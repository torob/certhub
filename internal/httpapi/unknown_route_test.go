package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appdomain "github.com/torob/certhub/internal/applications"
	auditdomain "github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/auth"
	certdomain "github.com/torob/certhub/internal/certificates"
	dnsdomain "github.com/torob/certhub/internal/dnsproviders"
	issuerdomain "github.com/torob/certhub/internal/issuers"
)

const testUnknownRouteID = "72345678-1234-4234-9234-123456789abc"

// assertUnknownRoute checks the response for a reserved backend path that no
// API route matches. The code must not be certificate_not_found, because
// Application clients treat that code as a missing certificate.
func assertUnknownRoute(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("content type = %q", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	var body struct {
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body = %s: %v", rec.Body.String(), err)
	}
	if len(body.Error) != 5 {
		t.Fatalf("error envelope = %#v", body.Error)
	}
	for _, field := range []struct {
		key   string
		value any
	}{
		{key: "code", value: "invalid_request"},
		{key: "message", value: "Unknown API route."},
		{key: "retryable", value: false},
		{key: "retry_after_seconds", value: nil},
	} {
		if got, ok := body.Error[field.key]; !ok || got != field.value {
			t.Fatalf("error.%s = %#v, want %#v", field.key, got, field.value)
		}
	}
	if details, ok := body.Error["details"].(map[string]any); !ok || len(details) != 0 {
		t.Fatalf("error.details = %#v", body.Error["details"])
	}
}

func TestUnknownBackendRouteIsNotCertificateNotFound(t *testing.T) {
	var logs bytes.Buffer
	handler := New(testConfig(t, ""), WithLogWriter(&logs)).Handler()
	for _, tc := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/v1"},
		{method: http.MethodGet, path: "/v1/not-implemented"},
		{method: http.MethodPost, path: "/v1/sync/certificate/tls-material"},
		{method: http.MethodPost, path: "/v1/sync"},
		{method: http.MethodPost, path: "/healthz"},
		{method: http.MethodGet, path: "/readyz/extra"},
		{method: http.MethodGet, path: "/metrics/extra"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			logs.Reset()
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
			req.Header.Set("Accept", "text/html")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assertUnknownRoute(t, rec)
			events := decodeLogEvents(t, logs.String())
			if len(events) != 1 {
				t.Fatalf("events = %#v", events)
			}
			if events[0]["status"] != float64(http.StatusNotFound) || events[0]["error_code"] != "invalid_request" || events[0]["level"] != "warn" {
				t.Fatalf("event = %#v", events[0])
			}
		})
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `certhub_http_requests_total{method="GET",path="/v1/*",status="404",error_code="invalid_request"} 2`) {
		t.Fatalf("metrics = %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `error_code="certificate_not_found"`) {
		t.Fatalf("unknown route counted as certificate_not_found: %s", rec.Body.String())
	}
}

// unknownRouteTestHandler serves every API area with an authenticated User.
// The domain services are empty because an unknown route must not reach them.
func unknownRouteTestHandler(t *testing.T) (http.Handler, string) {
	t.Helper()
	keys := testKeySet(t)
	user := fakeUser()
	token := auth.UserAccessTokenPrefix + strings.Repeat("U", 43)
	authSvc := auth.NewService(auth.ServiceConfig{
		AuthRepository: &identityFakeAuthRepo{session: auth.Session{
			ID:               "82345678-1234-4234-9234-123456789abc",
			UserID:           user.ID,
			AuthMethod:       auth.AuthMethodPassword,
			AccessTokenHash:  keys.HashToken(token),
			Status:           auth.SessionStatusActive,
			AccessExpiresAt:  time.Now().Add(time.Minute),
			SessionExpiresAt: time.Now().Add(time.Hour),
		}},
		UserRepository:  &identityFakeUserRepo{user: user},
		AuditRepository: identityFakeAudit{},
		KeySet:          keys,
		Config:          testConfig(t, "").Auth,
	})
	handler := New(testConfig(t, ""),
		WithIdentityServices(authSvc, nil),
		WithApplicationAccessServices(&appdomain.Service{}, &auditdomain.Service{}),
		WithIssuerService(&issuerdomain.Service{}),
		WithDNSProviderService(&dnsdomain.Service{}),
		WithCertificateService(&certdomain.Service{}),
	).Handler()
	return handler, token
}

func TestUnknownAreaRouteIsNotCertificateNotFound(t *testing.T) {
	handler, token := unknownRouteTestHandler(t)
	id := testUnknownRouteID
	for _, tc := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/v1/auth/login"},
		{method: http.MethodDelete, path: "/v1/auth/me"},
		{method: http.MethodGet, path: "/v1/applications/"},
		{method: http.MethodPut, path: "/v1/applications/" + id},
		{method: http.MethodGet, path: "/v1/applications/" + id + "/unknown"},
		{method: http.MethodGet, path: "/v1/applications/" + id + "/certificates"},
		{method: http.MethodPost, path: "/v1/audit-events"},
		{method: http.MethodGet, path: "/v1/certificates/" + id + "/tls-material"},
		{method: http.MethodGet, path: "/v1/certificates/" + id + "/a/b"},
		{method: http.MethodGet, path: "/v1/certificates/" + id + "/versions/" + id + "/unknown"},
		{method: http.MethodPut, path: "/v1/issuers/" + id},
		{method: http.MethodGet, path: "/v1/issuers/" + id + "/unknown"},
		{method: http.MethodPut, path: "/v1/dns-providers/" + id},
		{method: http.MethodGet, path: "/v1/dns-providers/" + id + "/unknown"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assertUnknownRoute(t, rec)
		})
	}
}

func TestUnknownAreaRouteStillAuthenticatesFirst(t *testing.T) {
	handler, _ := unknownRouteTestHandler(t)
	for _, p := range []string{
		"/v1/applications/" + testUnknownRouteID + "/unknown",
		"/v1/certificates/" + testUnknownRouteID + "/tls-material",
		"/v1/issuers/" + testUnknownRouteID + "/unknown",
		"/v1/dns-providers/" + testUnknownRouteID + "/unknown",
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		assertErrorCode(t, rec, http.StatusUnauthorized, "invalid_token")
	}
}

func TestMissingResourceKeepsCertificateNotFound(t *testing.T) {
	for name, write := range map[string]func(http.ResponseWriter) (int, string){
		"identity":     func(w http.ResponseWriter) (int, string) { return writeIdentityError(w, auth.ErrNotFound) },
		"application":  func(w http.ResponseWriter) (int, string) { return writeApplicationError(w, appdomain.ErrNotFound) },
		"audit":        func(w http.ResponseWriter) (int, string) { return writeAuditError(w, appdomain.ErrNotFound) },
		"certificate":  func(w http.ResponseWriter) (int, string) { return writeCertificateError(w, certdomain.ErrNotFound) },
		"issuer":       func(w http.ResponseWriter) (int, string) { return writeIssuerError(w, issuerdomain.ErrNotFound) },
		"dns provider": func(w http.ResponseWriter) (int, string) { return writeDNSProviderError(w, dnsdomain.ErrNotFound) },
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			status, code := write(rec)
			if status != http.StatusNotFound || code != "certificate_not_found" {
				t.Fatalf("status = %d code = %q", status, code)
			}
			assertErrorCode(t, rec, http.StatusNotFound, "certificate_not_found")
		})
	}
}
