package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/torob/certhub/pkg/netretry"
)

func TestServerExampleRetryConfigurationLoads(t *testing.T) {
	data, err := os.ReadFile("../../config/examples/server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(data, "config/examples/server.yaml", LoadOptions{Env: func(key string) (string, bool) {
		values := map[string]string{
			"CERTHUB_DATABASE_URL":   "postgres://user:pass@localhost/db",
			"CERTHUB_ENCRYPTION_KEY": validKey(),
		}
		value, ok := values[key]
		return value, ok
	}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutboundHTTP.Retry != netretry.DefaultPolicy() {
		t.Fatalf("example retry policy = %#v", cfg.OutboundHTTP.Retry)
	}
}

func TestDefaultOutboundRetryPolicy(t *testing.T) {
	cfg, err := normalize(rawConfig{Database: rawDatabase{URL: "postgres://user:pass@localhost/db"}, Encryption: rawEncryption{Key: validKey()}}, "test.yaml", func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutboundHTTP.Retry.MaxAttempts != 5 || cfg.OutboundHTTP.Retry.InitialBackoff != time.Second || cfg.OutboundHTTP.Retry.MaxBackoff != 8*time.Second {
		t.Fatalf("retry policy = %#v", cfg.OutboundHTTP.Retry)
	}
}

func TestCustomOutboundRetryPolicy(t *testing.T) {
	cfg, err := normalize(rawConfig{
		Database:   rawDatabase{URL: "postgres://user:pass@localhost/db"},
		Encryption: rawEncryption{Key: validKey()},
		OutboundHTTP: rawOutboundHTTP{Retry: rawRetryPolicy{
			MaxAttempts:           testInt(1),
			InitialBackoffSeconds: testInt(3),
			MaxBackoffSeconds:     testInt(9),
		}},
	}, "test.yaml", func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.OutboundHTTP.Retry; got != (netretry.Policy{MaxAttempts: 1, InitialBackoff: 3 * time.Second, MaxBackoff: 9 * time.Second}) {
		t.Fatalf("retry policy = %#v", got)
	}
}

func TestOutboundRetryPolicyRejectsInvalidAndOverflowingValues(t *testing.T) {
	tests := []struct {
		name  string
		retry rawRetryPolicy
	}{
		{name: "zero attempts", retry: rawRetryPolicy{MaxAttempts: testInt(0)}},
		{name: "too many attempts", retry: rawRetryPolicy{MaxAttempts: testInt(11)}},
		{name: "zero initial", retry: rawRetryPolicy{InitialBackoffSeconds: testInt(0)}},
		{name: "negative maximum", retry: rawRetryPolicy{MaxBackoffSeconds: testInt(-1)}},
		{name: "maximum below initial", retry: rawRetryPolicy{InitialBackoffSeconds: testInt(9), MaxBackoffSeconds: testInt(3)}},
		{name: "initial duration overflow", retry: rawRetryPolicy{InitialBackoffSeconds: testInt(18_446_744_075), MaxBackoffSeconds: testInt(18_446_744_075)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := normalize(rawConfig{
				Database:     rawDatabase{URL: "postgres://user:pass@localhost/db"},
				Encryption:   rawEncryption{Key: validKey()},
				OutboundHTTP: rawOutboundHTTP{Retry: tt.retry},
			}, "test.yaml", func(string) (string, bool) { return "", false })
			if err == nil {
				t.Fatal("invalid retry policy accepted")
			}
		})
	}
}

func testInt(value int) *int { return &value }

func TestOutboundHTTPTransportIgnoresAmbientProxyWhenDirect(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://ambient.example:8080")
	transport, err := NewOutboundHTTPTransport(OutboundHTTPConfig{Proxies: map[string]ProxyConfig{}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if transport.Proxy != nil {
		req := &http.Request{URL: mustURL(t, "https://api.example.com")}
		proxy, err := transport.Proxy(req)
		if err != nil {
			t.Fatal(err)
		}
		if proxy != nil {
			t.Fatalf("direct transport used ambient proxy: %s", proxy.Redacted())
		}
	}
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("transport disabled upstream TLS verification")
	}
}

func TestOutboundHTTPTransportUsesOnlyNamedProxy(t *testing.T) {
	transport, err := NewOutboundHTTPTransport(OutboundHTTPConfig{Proxies: map[string]ProxyConfig{
		"corp_proxy": {URL: SecretString("https://proxy.example:8443")},
	}}, "corp_proxy")
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{URL: mustURL(t, "https://api.cloudflare.com/client/v4/zones")}
	proxy, err := transport.Proxy(req)
	if err != nil {
		t.Fatal(err)
	}
	if proxy == nil || proxy.String() != "https://proxy.example:8443" {
		t.Fatalf("proxy = %v", proxy)
	}
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("transport disabled upstream TLS verification")
	}
}

func TestOutboundProxyURLReturnsNamedProxy(t *testing.T) {
	proxy, err := OutboundProxyURL(OutboundHTTPConfig{Proxies: map[string]ProxyConfig{
		"corp_proxy": {URL: SecretString("http://proxy.example:8080")},
	}}, "corp_proxy")
	if err != nil {
		t.Fatal(err)
	}
	if proxy.String() != "http://proxy.example:8080" {
		t.Fatalf("proxy = %s", proxy)
	}
}

func TestOutboundHTTPLoggerLogsFailureWithoutSensitiveRequestData(t *testing.T) {
	const (
		token       = "cth_uat_v1_SECRET_CANARY_TOKEN"
		querySecret = "query-secret-canary"
		bodySecret  = "body-secret-canary"
	)
	var logs bytes.Buffer
	logger := NewOutboundHTTPLogger(&logs)
	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/"+token+"?token="+querySecret, strings.NewReader(bodySecret))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Request-ID", token)
	responseBody := io.NopCloser(strings.NewReader(bodySecret))
	transport := &outboundHTTPLoggingTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			header := make(http.Header)
			header.Set("Retry-After", "7")
			header.Set("X-Request-ID", token)
			return &http.Response{StatusCode: http.StatusTooManyRequests, Header: header, Body: responseBody, Request: req}, nil
		}),
		logger:    logger,
		proxyName: "corp_proxy",
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != bodySecret {
		t.Fatalf("response body = %q", data)
	}
	for _, secret := range []string{token, querySecret, bodySecret, "Authorization", "Bearer"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("outbound log leaked %q: %s", secret, logs.String())
		}
	}
	events := decodeOutboundHTTPEvents(t, logs.String())
	if len(events) != 1 {
		t.Fatalf("events = %#v logs=%s", events, logs.String())
	}
	event := events[0]
	if event["event"] != "outbound_http_request_failed" || event["level"] != "warn" || event["method"] != http.MethodPost {
		t.Fatalf("event = %#v", event)
	}
	if event["destination"] != "https://api.example.com" || event["proxy"] != "corp_proxy" {
		t.Fatalf("event = %#v", event)
	}
	if event["status"] != float64(http.StatusTooManyRequests) || event["retryable"] != true || event["retry_after_seconds"] != float64(7) {
		t.Fatalf("event = %#v", event)
	}
	if event["request_id"] != securityRedactedForTest || event["response_request_id"] != securityRedactedForTest {
		t.Fatalf("request IDs were not redacted: %#v", event)
	}
	for _, field := range []string{"timestamp", "path", "latency_ms", "error"} {
		if _, ok := event[field]; !ok {
			t.Fatalf("event missing %s: %#v", field, event)
		}
	}
}

func TestOutboundHTTPLoggerLogsTransientTransportError(t *testing.T) {
	const token = "cth_app_v1_SECRET_CANARY_TOKEN"
	var logs bytes.Buffer
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://identity.example.com/.well-known/openid-configuration", nil)
	if err != nil {
		t.Fatal(err)
	}
	transportErr := fmt.Errorf("proxy http://proxy-user:proxy-password@proxy.example:8443 Authorization: Bearer %s: %w", token, io.ErrUnexpectedEOF)
	transport := &outboundHTTPLoggingTransport{
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, transportErr
		}),
		logger: NewOutboundHTTPLogger(&logs),
	}
	if _, err := transport.RoundTrip(req); err == nil {
		t.Fatal("transport error was lost")
	}
	for _, secret := range []string{token, "proxy-user", "proxy-password", "Bearer"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("transport log leaked %q: %s", secret, logs.String())
		}
	}
	events := decodeOutboundHTTPEvents(t, logs.String())
	if len(events) != 1 {
		t.Fatalf("events = %#v", events)
	}
	event := events[0]
	if event["level"] != "error" || event["status"] != float64(0) || event["proxy"] != "direct" || event["retryable"] != true {
		t.Fatalf("event = %#v", event)
	}
}

func TestOutboundHTTPLoggerLogsEveryFailedRetryAttempt(t *testing.T) {
	var logs bytes.Buffer
	calls := 0
	transport := &outboundHTTPLoggingTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			status := http.StatusServiceUnavailable
			if calls == 3 {
				status = http.StatusNoContent
			}
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		}),
		logger: NewOutboundHTTPLogger(&logs),
	}
	client := netretry.NewClient(&http.Client{Transport: transport}, netretry.Policy{
		MaxAttempts: 3, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond,
	})
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/retry", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if calls != 3 {
		t.Fatalf("calls = %d", calls)
	}
	events := decodeOutboundHTTPEvents(t, logs.String())
	if len(events) != 2 {
		t.Fatalf("events = %#v logs=%s", events, logs.String())
	}
	for _, event := range events {
		if event["status"] != float64(http.StatusServiceUnavailable) || event["retryable"] != true {
			t.Fatalf("event = %#v", event)
		}
	}
}

func TestOutboundHTTPLoggerIgnoresSuccessfulAndRedirectResponses(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var logs bytes.Buffer
			transport := &outboundHTTPLoggingTransport{
				base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
				}),
				logger: NewOutboundHTTPLogger(&logs),
			}
			req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/ok", nil)
			if _, err := transport.RoundTrip(req); err != nil {
				t.Fatal(err)
			}
			if logs.Len() != 0 {
				t.Fatalf("logs = %s", logs.String())
			}
		})
	}
}

func TestOutboundHTTPLoggerSerializesConcurrentFailures(t *testing.T) {
	const requests = 32
	var logs bytes.Buffer
	transport := &outboundHTTPLoggingTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusBadGateway, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		}),
		logger: NewOutboundHTTPLogger(&logs),
	}
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://api.example.com/failure/%d", i), nil)
			_, _ = transport.RoundTrip(req)
		}(i)
	}
	wg.Wait()
	if events := decodeOutboundHTTPEvents(t, logs.String()); len(events) != requests {
		t.Fatalf("event count = %d; want %d", len(events), requests)
	}
}

const securityRedactedForTest = "[redacted]"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func decodeOutboundHTTPEvents(t *testing.T, raw string) []map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	events := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode outbound HTTP log %q: %v", line, err)
		}
		events = append(events, event)
	}
	return events
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
