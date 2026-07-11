package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/pkg/netretry"
)

type OutboundHTTPLogger struct {
	mu  sync.Mutex
	out io.Writer
}

type outboundHTTPFailureEvent struct {
	Timestamp         string  `json:"timestamp"`
	Level             string  `json:"level"`
	Event             string  `json:"event"`
	Method            string  `json:"method"`
	Destination       string  `json:"destination"`
	Path              string  `json:"path"`
	Status            int     `json:"status"`
	LatencyMS         float64 `json:"latency_ms"`
	RequestID         string  `json:"request_id"`
	ResponseRequestID string  `json:"response_request_id"`
	Proxy             string  `json:"proxy"`
	Retryable         bool    `json:"retryable"`
	RetryAfterSeconds float64 `json:"retry_after_seconds"`
	Error             string  `json:"error"`
}

type outboundHTTPLoggingTransport struct {
	base      http.RoundTripper
	logger    *OutboundHTTPLogger
	proxyName string
}

func NewOutboundHTTPLogger(out io.Writer) *OutboundHTTPLogger {
	if out == nil {
		return nil
	}
	return &OutboundHTTPLogger{out: out}
}

func NewOutboundHTTPClient(cfg OutboundHTTPConfig, proxyName string, logger *OutboundHTTPLogger) (*http.Client, error) {
	transport, err := NewOutboundHTTPTransport(cfg, proxyName)
	if err != nil {
		return nil, err
	}
	var roundTripper http.RoundTripper = transport
	if logger != nil {
		roundTripper = &outboundHTTPLoggingTransport{base: transport, logger: logger, proxyName: proxyName}
	}
	return &http.Client{Transport: roundTripper, Timeout: 30 * time.Second}, nil
}

func (t *outboundHTTPLoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	started := time.Now()
	resp, err := base.RoundTrip(req)
	if err != nil || resp != nil && resp.StatusCode >= http.StatusBadRequest {
		t.logger.writeFailure(req, resp, err, t.proxyName, time.Since(started))
	}
	return resp, err
}

func (l *OutboundHTTPLogger) writeFailure(req *http.Request, resp *http.Response, requestErr error, proxyName string, latency time.Duration) {
	if l == nil || l.out == nil || req == nil {
		return
	}
	now := time.Now().UTC()
	proxy := proxyName
	if proxy == "" {
		proxy = "direct"
	}
	status := 0
	level := "error"
	retryable := netretry.IsTransientForContext(req.Context(), requestErr)
	retryAfter := time.Duration(0)
	responseRequestID := ""
	errorMessage := ""
	if resp != nil {
		status = resp.StatusCode
		if status < http.StatusInternalServerError {
			level = "warn"
		}
		retryable = netretry.RetryableStatus(status)
		retryAfter = netretry.ParseRetryAfter(resp.Header.Get("Retry-After"), now)
		responseRequestID = resp.Header.Get("X-Request-ID")
		errorMessage = fmt.Sprintf("HTTP %d %s", status, http.StatusText(status))
	}
	if requestErr != nil {
		errorMessage = requestErr.Error()
	}
	destination, path := outboundRequestTarget(req.URL)
	event := outboundHTTPFailureEvent{
		Timestamp:         now.Format(time.RFC3339Nano),
		Level:             level,
		Event:             "outbound_http_request_failed",
		Method:            security.RedactString(req.Method),
		Destination:       destination,
		Path:              path,
		Status:            status,
		LatencyMS:         float64(latency.Microseconds()) / 1000,
		RequestID:         security.RedactString(req.Header.Get("X-Request-ID")),
		ResponseRequestID: security.RedactString(responseRequestID),
		Proxy:             security.RedactString(proxy),
		Retryable:         retryable,
		RetryAfterSeconds: retryAfter.Seconds(),
		Error:             security.RedactString(strings.TrimSpace(errorMessage)),
	}
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	data = append(data, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.out.Write(data)
}

func outboundRequestTarget(u *url.URL) (string, string) {
	if u == nil {
		return "", ""
	}
	destination := u.Scheme + "://" + u.Host
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return security.RedactString(destination), security.RedactString(path)
}

func NewOutboundHTTPTransport(cfg OutboundHTTPConfig, proxyName string) (*http.Transport, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if proxyName == "" {
		return transport, nil
	}
	proxyURL, err := OutboundProxyURL(cfg, proxyName)
	if err != nil {
		return nil, err
	}
	transport.Proxy = http.ProxyURL(proxyURL)
	return transport, nil
}

func OutboundProxyURL(cfg OutboundHTTPConfig, proxyName string) (*url.URL, error) {
	proxy, ok := cfg.Proxies[proxyName]
	if !ok {
		return nil, errors.New("outbound proxy is not configured")
	}
	proxyURL, err := url.Parse(string(proxy.URL))
	if err != nil {
		return nil, errors.New("outbound proxy is invalid")
	}
	return proxyURL, nil
}
