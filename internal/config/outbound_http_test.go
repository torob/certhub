package config

import (
	"net/http"
	"net/url"
	"os"
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

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
