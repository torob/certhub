package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/torob/certhub/internal/config"
)

type staticReadiness []ReadinessCheck

func (s staticReadiness) CheckReadiness() []ReadinessCheck { return []ReadinessCheck(s) }

func testConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return mustLoadConfig(t, `
database:
  url: "postgres://certhub:secret@db.example/certhub"
encryption:
  key: "`+key+`"
http:
  require_https: false
`+extra, config.LoadOptions{})
}

func mustLoadConfig(t *testing.T, body string, opts config.LoadOptions) *config.Config {
	t.Helper()
	cfg, err := config.Load([]byte(body), "/safe/server.yaml", opts)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestHealthAndRequestID(t *testing.T) {
	handler := New(testConfig(t, ""), WithReadinessChecker(staticReadiness{
		{Name: "postgresql", Status: "ok"},
		{Name: "migrations", Status: "ok"},
		{Name: "encryption_key", Status: "ok"},
		{Name: "process_configuration", Status: "ok"},
	})).Handler()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-ID", "req-test-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Request-ID") != "req-test-1" {
		t.Fatalf("request id not propagated: %q", rec.Header().Get("X-Request-ID"))
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestReadyzFailureUsesErrorEnvelope(t *testing.T) {
	handler := New(testConfig(t, ""), WithReadinessChecker(staticReadiness{
		{Name: "postgresql", Status: "failed"},
		{Name: "migrations", Status: "ok"},
		{Name: "encryption_key", Status: "ok"},
		{Name: "process_configuration", Status: "ok"},
	})).Handler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	var body map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"]["code"] != "service_unavailable" {
		t.Fatalf("body = %#v", body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing no-store header")
	}
}

func TestMetricsEndpoint(t *testing.T) {
	handler := New(testConfig(t, "")).Handler()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("content type = %q", ct)
	}
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("metrics leaked unexpected secret-like string: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "certhub_http_requests_total") {
		t.Fatalf("metrics body = %s", rec.Body.String())
	}
}

func TestMetricsReadinessGaugeReflectsCheckerFailure(t *testing.T) {
	handler := New(testConfig(t, ""), WithReadinessChecker(staticReadiness{
		{Name: "postgresql", Status: "failed"},
		{Name: "migrations", Status: "ok"},
		{Name: "encryption_key", Status: "ok"},
		{Name: "process_configuration", Status: "ok"},
	})).Handler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "certhub_platform_ready 0\n") {
		t.Fatalf("metrics did not reflect failed readiness: %s", rec.Body.String())
	}
}

func TestStructuredRequestLogSanitizesCanaries(t *testing.T) {
	const canary = "cth_uat_v1_SECRET_CANARY_TOKEN"
	var logs bytes.Buffer
	handler := New(testConfig(t, ""), WithLogWriter(&logs)).Handler()
	req := httptest.NewRequest(http.MethodGet, "/v1/"+canary+"?token="+canary, nil)
	req.Header.Set("Authorization", "Bearer "+canary)
	req.Header.Set("X-Request-ID", canary)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(logs.String(), canary) || strings.Contains(logs.String(), "Authorization") || strings.Contains(logs.String(), "Bearer") {
		t.Fatalf("structured log leaked secret material: %s", logs.String())
	}
	events := decodeLogEvents(t, logs.String())
	if len(events) != 1 {
		t.Fatalf("events = %#v logs=%s", events, logs.String())
	}
	event := events[0]
	if event["event"] != "http_request" || event["method"] != http.MethodGet || event["path_template"] != "/v1/*" {
		t.Fatalf("event = %#v", event)
	}
	if event["status"] != float64(http.StatusNotFound) || event["error_code"] != "certificate_not_found" {
		t.Fatalf("event = %#v", event)
	}
	for _, field := range []string{"timestamp", "level", "latency_ms", "request_id", "correlation_id", "source_ip", "identity_type", "identity_id"} {
		if _, ok := event[field]; !ok {
			t.Fatalf("event missing %s: %#v", field, event)
		}
	}
	if event["source_ip"] != "192.0.2.1" {
		t.Fatalf("source_ip = %#v", event["source_ip"])
	}
}

func TestMalformedForwardedHeadersWriteSanitizedSecurityLog(t *testing.T) {
	const canary = "cth_uat_v1_SECRET_CANARY_TOKEN"
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := mustLoadConfig(t, `
database:
  url: "postgres://certhub:secret@db.example/certhub"
encryption:
  key: "`+key+`"
server:
  public_hostname: "certhub.example.com"
http:
  require_https: true
  trusted_proxy_cidrs: ["10.0.0.0/8"]
`, config.LoadOptions{})
	var logs bytes.Buffer
	handler := New(cfg, WithLogWriter(&logs)).Handler()
	req := httptest.NewRequest(http.MethodGet, "/applications?token="+canary, nil)
	req.RemoteAddr = "10.0.0.20:443"
	req.Host = "internal.invalid"
	req.Header.Set("Forwarded", `for=203.0.113.9;proto=https;host=certhub.example.com`)
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("Authorization", "Bearer "+canary)
	req.Header.Set("X-Request-ID", canary)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(logs.String(), canary) || strings.Contains(logs.String(), "Authorization") || strings.Contains(logs.String(), "Bearer") || strings.Contains(logs.String(), "Forwarded") {
		t.Fatalf("security log leaked header material: %s", logs.String())
	}
	events := decodeLogEvents(t, logs.String())
	if len(events) != 2 {
		t.Fatalf("events = %#v logs=%s", events, logs.String())
	}
	var foundSecurity bool
	for _, event := range events {
		if event["event"] == "security.forwarded_headers_rejected" {
			foundSecurity = true
			if event["level"] != "warn" || event["reason"] != "malformed_or_conflicting_forwarded_headers" || event["path_template"] != "/{frontend}" {
				t.Fatalf("security event = %#v", event)
			}
			if event["source_ip"] != "203.0.113.9" {
				t.Fatalf("security source_ip = %#v", event["source_ip"])
			}
		}
	}
	if !foundSecurity {
		t.Fatalf("missing security log event: %#v", events)
	}
}

func TestReservedBackendPrefixNeverFallsBackToSPA(t *testing.T) {
	handler := New(testConfig(t, "")).Handler()
	req := httptest.NewRequest(http.MethodGet, "/v1/not-implemented", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "<!doctype html>") {
		t.Fatalf("reserved backend path returned SPA shell")
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("content type = %q", rec.Header().Get("Content-Type"))
	}
}

func TestStaticSPAFallbackAndTraversalGuard(t *testing.T) {
	handler := New(testConfig(t, "")).Handler()
	for _, p := range []string{"/", "/applications/123"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<!doctype html>") {
			t.Fatalf("%s: status=%d body=%s", p, rec.Code, rec.Body.String())
		}
		if csp := rec.Header().Get("Content-Security-Policy"); strings.Contains(csp, "unsafe-inline") || csp == "" {
			t.Fatalf("%s: bad CSP %q", p, csp)
		}
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/%252e%252e/secret", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("traversal status = %d", rec.Code)
	}
}

func TestProductionStaticAssetsFromDist(t *testing.T) {
	repoRoot := findRepoRoot(t)
	distWeb := filepath.Join(repoRoot, "dist", "web")
	entries, err := os.ReadDir(filepath.Join(distWeb, "assets"))
	if err != nil {
		t.Skipf("production web build is required for static asset certification: %v", err)
	}
	var jsAsset, cssAsset string
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case strings.HasSuffix(name, ".js"):
			jsAsset = "/assets/" + name
		case strings.HasSuffix(name, ".css"):
			cssAsset = "/assets/" + name
		}
	}
	if jsAsset == "" || cssAsset == "" {
		t.Fatalf("dist assets missing js/css: %#v", entries)
	}
	handler := New(testConfig(t, ""), WithStaticFS(os.DirFS(distWeb))).Handler()

	for _, path := range []string{"/", "/applications/123"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d body=%s", path, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if strings.Contains(body, "Placeholder for generated production web assets") || !strings.Contains(body, "/assets/") {
			t.Fatalf("%s did not serve production shell: %s", path, body)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s Cache-Control = %q", path, rec.Header().Get("Cache-Control"))
		}
		if rec.Header().Get("Strict-Transport-Security") == "" || rec.Header().Get("Content-Security-Policy") == "" {
			t.Fatalf("%s missing security headers", path)
		}
	}

	for _, tc := range []struct {
		path string
		mime string
	}{
		{jsAsset, "text/javascript"},
		{cssAsset, "text/css"},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d", tc.path, rec.Code)
		}
		if !strings.Contains(rec.Header().Get("Content-Type"), tc.mime) {
			t.Fatalf("%s Content-Type = %q", tc.path, rec.Header().Get("Content-Type"))
		}
		if rec.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("%s Cache-Control = %q", tc.path, rec.Header().Get("Cache-Control"))
		}
		if strings.Contains(rec.Body.String(), "sourceMappingURL") {
			t.Fatalf("%s contains forbidden production asset reference", tc.path)
		}
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			t.Fatal("could not find repo root")
		}
		dir = next
	}
}

func TestHostAllowlistAndHTTPSRequirement(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg, err := config.Load([]byte(`
database:
  url: "postgres://certhub:secret@db.example/certhub"
encryption:
  key: "`+key+`"
server:
  public_hostname: "certhub.example.com"
http:
  require_https: true
  trusted_proxy_cidrs: ["192.0.2.0/24"]
`), "/safe/server.yaml", config.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	handler := New(cfg).Handler()

	badHost := httptest.NewRequest(http.MethodGet, "/applications", nil)
	badHost.Host = "evil.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, badHost)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad host status = %d", rec.Code)
	}

	plaintext := httptest.NewRequest(http.MethodGet, "/applications", nil)
	plaintext.Host = "certhub.example.com"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, plaintext)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("plaintext status = %d", rec.Code)
	}

	trusted := httptest.NewRequest(http.MethodGet, "/applications", nil)
	trusted.Host = "certhub.example.com"
	trusted.RemoteAddr = "192.0.2.10:1234"
	trusted.Header.Set("X-Forwarded-Proto", "https")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, trusted)
	if rec.Code != http.StatusOK {
		t.Fatalf("trusted proxy status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestOperationalEndpointsBypassHostAllowlist(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := mustLoadConfig(t, `
database:
  url: "postgres://certhub:secret@db.example/certhub"
encryption:
  key: "`+key+`"
server:
  public_hostname: "certhub.example.com"
http:
  require_https: true
`, config.LoadOptions{})
	handler := New(cfg, WithReadinessChecker(staticReadiness{
		{Name: "postgresql", Status: "ok"},
		{Name: "migrations", Status: "ok"},
		{Name: "encryption_key", Status: "ok"},
		{Name: "process_configuration", Status: "ok"},
	})).Handler()

	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Host = "probe.internal"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
			}
		})
	}

	body := &failOnReadBody{}
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", body)
	req.Body = body
	req.Host = "probe.internal"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("normal API status = %d body = %s", rec.Code, rec.Body.String())
	}
	if body.read {
		t.Fatalf("request body was read before Host rejection")
	}

	req = httptest.NewRequest(http.MethodGet, "/applications", nil)
	req.Host = "probe.internal"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("normal web status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestTrustedProxyRequestContextDerivation(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := mustLoadConfig(t, `
database:
  url: "postgres://certhub:secret@db.example/certhub"
encryption:
  key: "`+key+`"
http:
  require_https: true
  trusted_proxy_cidrs: ["10.0.0.0/8"]
`, config.LoadOptions{})
	server := New(cfg)

	req := httptest.NewRequest(http.MethodGet, "/v1/sync/certificates", nil)
	req.RemoteAddr = "10.0.0.20:443"
	req.Host = "internal.invalid"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.10")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "certhub.example.com:443")

	ctx := server.deriveRequestContext(req, "req-1")
	if ctx.SourceIP.String() != "203.0.113.9" {
		t.Fatalf("source ip = %s", ctx.SourceIP)
	}
	if ctx.EffectiveScheme != "https" {
		t.Fatalf("scheme = %q", ctx.EffectiveScheme)
	}
	if ctx.EffectiveHost != "certhub.example.com" {
		t.Fatalf("host = %q", ctx.EffectiveHost)
	}
	if !ctx.TrustedProxyPeer || ctx.ForwardedMalformed {
		t.Fatalf("context = %#v", ctx)
	}
}

func TestForwardedHeaderFromTrustedProxy(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := mustLoadConfig(t, `
database:
  url: "postgres://certhub:secret@db.example/certhub"
encryption:
  key: "`+key+`"
server:
  public_hostname: "certhub.example.com"
http:
  require_https: true
  trusted_proxy_cidrs: ["10.0.0.0/8", "192.0.2.0/24"]
`, config.LoadOptions{})
	handler := New(cfg).Handler()

	req := httptest.NewRequest(http.MethodGet, "/applications", nil)
	req.RemoteAddr = "10.0.0.20:443"
	req.Host = "internal.invalid"
	req.Header.Set("Forwarded", `for=203.0.113.9;proto=https;host="certhub.example.com:443"`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("trusted Forwarded status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestTrustedForwardedHeaderUsesRightmostElement(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := mustLoadConfig(t, `
database:
  url: "postgres://certhub:secret@db.example/certhub"
encryption:
  key: "`+key+`"
server:
  public_hostname: "certhub.example.com"
http:
  require_https: true
  trusted_proxy_cidrs: ["10.0.0.0/8"]
`, config.LoadOptions{})
	server := New(cfg)

	req := httptest.NewRequest(http.MethodGet, "/applications", nil)
	req.RemoteAddr = "10.0.0.20:443"
	req.Host = "internal.invalid"
	req.Header.Set("Forwarded", `for=198.51.100.10;proto=http;host=evil.example.com, for=203.0.113.9;proto=https;host="certhub.example.com:443"`)

	ctx := server.deriveRequestContext(req, "req-1")
	if ctx.SourceIP.String() != "203.0.113.9" || ctx.EffectiveScheme != "https" || ctx.EffectiveHost != "certhub.example.com" {
		t.Fatalf("rightmost Forwarded element was not used: %#v", ctx)
	}
	if ctx.ForwardedMalformed {
		t.Fatalf("context marked malformed: %#v", ctx)
	}

	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("trusted Forwarded status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestTrustedXForwardedProtoAndHostUseRightmostValues(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := mustLoadConfig(t, `
database:
  url: "postgres://certhub:secret@db.example/certhub"
encryption:
  key: "`+key+`"
server:
  public_hostname: "certhub.example.com"
http:
  require_https: true
  trusted_proxy_cidrs: ["10.0.0.0/8"]
`, config.LoadOptions{})
	server := New(cfg)

	req := httptest.NewRequest(http.MethodGet, "/applications", nil)
	req.RemoteAddr = "10.0.0.20:443"
	req.Host = "internal.invalid"
	req.Header.Set("X-Forwarded-Proto", "http, https")
	req.Header.Set("X-Forwarded-Host", "evil.example.com, certhub.example.com")

	ctx := server.deriveRequestContext(req, "req-1")
	if ctx.EffectiveScheme != "https" || ctx.EffectiveHost != "certhub.example.com" || ctx.ForwardedMalformed {
		t.Fatalf("rightmost X-Forwarded values were not used: %#v", ctx)
	}

	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("trusted X-Forwarded status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/applications", nil)
	req.RemoteAddr = "10.0.0.20:443"
	req.Host = "internal.invalid"
	req.Header.Set("X-Forwarded-Proto", "https, http")
	req.Header.Set("X-Forwarded-Host", "certhub.example.com, evil.example.com")
	ctx = server.deriveRequestContext(req, "req-2")
	if ctx.EffectiveScheme != "http" || ctx.EffectiveHost != "evil.example.com" {
		t.Fatalf("rightmost spoofed values were not authoritative: %#v", ctx)
	}
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("rightmost bad values status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestConflictingForwardedAndXForwardedHeadersRejected(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := mustLoadConfig(t, `
database:
  url: "postgres://certhub:secret@db.example/certhub"
encryption:
  key: "`+key+`"
server:
  public_hostname: "certhub.example.com"
http:
  require_https: true
  trusted_proxy_cidrs: ["10.0.0.0/8"]
`, config.LoadOptions{})
	server := New(cfg)

	req := httptest.NewRequest(http.MethodGet, "/applications", nil)
	req.RemoteAddr = "10.0.0.20:443"
	req.Host = "internal.invalid"
	req.Header.Set("Forwarded", `for=203.0.113.9;proto=https;host=certhub.example.com`)
	req.Header.Set("X-Forwarded-Proto", "http")

	ctx := server.deriveRequestContext(req, "req-1")
	if !ctx.ForwardedMalformed {
		t.Fatalf("conflicting headers were not marked malformed: %#v", ctx)
	}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("conflicting headers status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestUntrustedForwardedHeadersDoNotAffectHostSchemeOrSource(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := mustLoadConfig(t, `
database:
  url: "postgres://certhub:secret@db.example/certhub"
encryption:
  key: "`+key+`"
server:
  public_hostname: "certhub.example.com"
http:
  require_https: true
  trusted_proxy_cidrs: ["10.0.0.0/8"]
`, config.LoadOptions{})
	server := New(cfg)
	req := httptest.NewRequest(http.MethodGet, "/applications", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	req.Host = "evil.example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "certhub.example.com")
	req.Header.Set("Forwarded", `for=203.0.113.9;proto=https;host=certhub.example.com`)

	ctx := server.deriveRequestContext(req, "req-1")
	if ctx.SourceIP.String() != "198.51.100.10" || ctx.EffectiveScheme != "http" || ctx.EffectiveHost != "evil.example.com" {
		t.Fatalf("untrusted headers influenced context: %#v", ctx)
	}

	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("untrusted forwarded request status = %d body = %s", rec.Code, rec.Body.String())
	}
}

type failOnReadBody struct {
	read bool
}

func (b *failOnReadBody) Read([]byte) (int, error) {
	b.read = true
	return 0, errors.New("body must not be read")
}

func (b *failOnReadBody) Close() error { return nil }

var _ io.ReadCloser = (*failOnReadBody)(nil)

func decodeLogEvents(t *testing.T, data string) []map[string]any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(data))
	var events []map[string]any
	for {
		var event map[string]any
		if err := decoder.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		events = append(events, event)
	}
	return events
}

func TestPlaintextRejectionDoesNotReadBody(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := mustLoadConfig(t, `
database:
  url: "postgres://certhub:secret@db.example/certhub"
encryption:
  key: "`+key+`"
http:
  require_https: true
`, config.LoadOptions{})
	handler := New(cfg).Handler()
	body := &failOnReadBody{}
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", body)
	req.Body = body
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if body.read {
		t.Fatalf("request body was read before HTTPS rejection")
	}
}

func TestHTTPErrorReadinessAndMetricsRedactionCanary(t *testing.T) {
	const canary = "cth_uat_v1_SECRET_CANARY_TOKEN"
	handler := New(testConfig(t, ""), WithReadinessChecker(staticReadiness{
		{Name: "postgresql", Status: canary},
		{Name: canary, Status: "failed"},
	})).Handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if strings.Contains(rec.Body.String(), canary) {
		t.Fatalf("readyz leaked canary: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/not-implemented", nil)
	req.Header.Set("Authorization", "Bearer "+canary)
	handler.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), canary) {
		t.Fatalf("error leaked canary: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(rec.Body.String(), canary) {
		t.Fatalf("metrics leaked canary: %s", rec.Body.String())
	}
}
