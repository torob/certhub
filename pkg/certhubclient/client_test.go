package certhubclient

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	certerrors "github.com/torob/certhub/pkg/errors"
)

const validAppToken = ApplicationTokenPrefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestValidateApplicationTokenRejectsUserTokens(t *testing.T) {
	tests := []struct {
		name string
		in   string
		code string
	}{
		{name: "user access", in: UserAccessTokenPrefix + strings.Repeat("A", 43), code: certerrors.CodeApplicationTokenRequired},
		{name: "removed refresh prefix", in: "cth_urt_v1_" + strings.Repeat("A", 43), code: certerrors.CodeInvalidToken},
		{name: "malformed app", in: ApplicationTokenPrefix + "example_redacted", code: certerrors.CodeInvalidToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateApplicationToken(tt.in)
			if err == nil {
				t.Fatal("ValidateApplicationToken returned nil")
			}
			var apiErr *certerrors.APIError
			if !stderrors.As(err, &apiErr) {
				t.Fatalf("error type = %T; want *errors.APIError", err)
			}
			if apiErr.Envelope.Code != tt.code {
				t.Fatalf("code = %q; want %q", apiErr.Envelope.Code, tt.code)
			}
		})
	}
}

func TestGetTLSMaterialSendsCriteriaIfNoneMatchAndNoApplicationID(t *testing.T) {
	var got struct {
		Method        string
		Path          string
		Authorization string
		IfNoneMatch   string
		RequestID     string
		Body          map[string]any
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Method = r.Method
		got.Path = r.URL.Path
		got.Authorization = r.Header.Get("Authorization")
		got.IfNoneMatch = r.Header.Get("If-None-Match")
		got.RequestID = r.Header.Get("X-Request-ID")
		if err := json.NewDecoder(r.Body).Decode(&got.Body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("X-Request-ID", "req-server")
		w.Header().Set("ETag", `"cth-mat-v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"certificate_id":"cert-1",
			"application_id":"app-1",
			"domains":["api.example.com"],
			"key_type":"ecdsa-p256",
			"issuer_id":"issuer-1",
			"issuer_name":"letsencrypt",
			"version":3,
			"cert_pem":"CERT",
			"chain_pem":"CHAIN",
			"fullchain_pem":"FULLCHAIN",
			"private_key_pem":"KEY",
			"not_before":"2026-06-24T00:00:00Z",
			"not_after":"2026-09-22T00:00:00Z",
			"serial_number":"03aabb",
			"fingerprint_sha256":"abc123",
			"key_fingerprint_sha256":"def456",
			"material_etag":"\"cth-mat-v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\""
		}`))
	}))
	defer server.Close()

	client, err := New(server.URL, validAppToken)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mat, meta, err := client.GetTLSMaterial(context.Background(), CertificateCriteria{
		Domains: []string{"api.example.com"},
		KeyType: "ecdsa-p256",
		Issuer:  "letsencrypt",
	}, RequestOptions{
		IfNoneMatch: `"cth-mat-v1.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"`,
		RequestID:   "req-client",
	})
	if err != nil {
		t.Fatalf("GetTLSMaterial: %v", err)
	}
	if mat == nil || mat.CertificateID != "cert-1" {
		t.Fatalf("material = %#v; want cert-1", mat)
	}
	if meta.RequestID != "req-server" || meta.ETag == "" {
		t.Fatalf("meta = %#v; want request ID and ETag", meta)
	}
	if got.Method != http.MethodPost || got.Path != "/v1/sync/certificates/tls-material" {
		t.Fatalf("request = %s %s; want POST material path", got.Method, got.Path)
	}
	if got.Authorization != "Bearer "+validAppToken {
		t.Fatalf("Authorization = %q; want bearer app token", got.Authorization)
	}
	if got.IfNoneMatch == "" || got.RequestID != "req-client" {
		t.Fatalf("headers missing If-None-Match or request ID: %#v", got)
	}
	if _, ok := got.Body["application_id"]; ok {
		t.Fatalf("request body included application_id: %#v", got.Body)
	}
}

func TestGetTLSMaterialNoContentReturnsMetaWithoutBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", "req-204")
		w.Header().Set("ETag", `"cth-mat-v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := New(server.URL, validAppToken)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mat, meta, err := client.GetTLSMaterial(context.Background(), CertificateCriteria{Domains: []string{"api.example.com"}}, RequestOptions{})
	if err != nil {
		t.Fatalf("GetTLSMaterial: %v", err)
	}
	if mat != nil {
		t.Fatalf("material = %#v; want nil", mat)
	}
	if meta.StatusCode != http.StatusNoContent || meta.RequestID != "req-204" {
		t.Fatalf("meta = %#v; want 204 with request ID", meta)
	}
}

func TestEnsureCertificateAcceptsPendingAndCapturesRetryAfter(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sync/certificates" {
			t.Fatalf("path = %q; want ensure path", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("X-Request-ID", "req-202")
		w.Header().Set("Retry-After", "12")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{
			"certificate": {
				"id":"cert-1",
				"application_id":"app-1",
				"normalized_sans":["api.example.com"],
				"key_type":"ecdsa-p256",
				"issuer_id":"issuer-1",
				"issuer_name":"letsencrypt",
				"status":"pending",
				"created_at":"2026-06-24T00:00:00Z",
				"updated_at":"2026-06-24T00:00:00Z"
			}
		}`))
	}))
	defer server.Close()

	client, err := New(server.URL, validAppToken)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cert, meta, err := client.EnsureCertificate(context.Background(), CertificateCriteria{Domains: []string{"api.example.com"}}, RequestOptions{})
	if err != nil {
		t.Fatalf("EnsureCertificate: %v", err)
	}
	if cert.Certificate.Status != "pending" {
		t.Fatalf("status = %q; want pending", cert.Certificate.Status)
	}
	if _, ok := body["application_id"]; ok {
		t.Fatalf("request body included application_id: %#v", body)
	}
	if got, ok := meta.RetryAfterSeconds(); !ok || got != 12 {
		t.Fatalf("retry after = %d, %v; want 12, true", got, ok)
	}
}

func TestErrorEnvelopeCapturesRequestIDAndRetryAfter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", "req-error")
		w.Header().Set("Retry-After", "8")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{
			"error": {
				"code":"certificate_not_ready",
				"message":"Certificate is not ready.",
				"retryable":true,
				"retry_after_seconds":30,
				"details":{"certificate_id":"cert-1","status":"pending"}
			}
		}`))
	}))
	defer server.Close()

	client, err := New(server.URL, validAppToken)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, meta, err := client.GetTLSMaterial(context.Background(), CertificateCriteria{Domains: []string{"api.example.com"}}, RequestOptions{})
	if err == nil {
		t.Fatal("GetTLSMaterial returned nil error")
	}
	if meta.RequestID != "req-error" {
		t.Fatalf("meta request ID = %q; want req-error", meta.RequestID)
	}
	var apiErr *certerrors.APIError
	if !stderrors.As(err, &apiErr) {
		t.Fatalf("error type = %T; want *errors.APIError", err)
	}
	if apiErr.StatusCode != http.StatusConflict || apiErr.RequestID != "req-error" || apiErr.Envelope.Code != certerrors.CodeCertificateNotReady {
		t.Fatalf("api error = %#v", apiErr)
	}
	if got, ok := apiErr.RetryAfterSeconds(); !ok || got != 8 {
		t.Fatalf("retry after = %d, %v; want header value 8, true", got, ok)
	}
}

func TestRedirectAuthorizationOnlySameOrigin(t *testing.T) {
	var crossOriginAuth string
	crossOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		crossOriginAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer crossOrigin.Close()

	var sameOriginAuth string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sync/certificates/tls-material":
			http.Redirect(w, r, "/same-origin", http.StatusTemporaryRedirect)
		case "/same-origin":
			sameOriginAuth = r.Header.Get("Authorization")
			http.Redirect(w, r, crossOrigin.URL+"/cross-origin", http.StatusTemporaryRedirect)
		default:
			t.Fatalf("unexpected path %q on %s", r.URL.Path, server.URL)
		}
	}))
	defer server.Close()

	client, err := New(server.URL, validAppToken)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _, err = client.GetTLSMaterial(context.Background(), CertificateCriteria{Domains: []string{"api.example.com"}}, RequestOptions{})
	if err != nil {
		t.Fatalf("GetTLSMaterial: %v", err)
	}
	if sameOriginAuth != "Bearer "+validAppToken {
		t.Fatalf("same-origin Authorization = %q; want bearer token", sameOriginAuth)
	}
	if crossOriginAuth != "" {
		t.Fatalf("cross-origin Authorization = %q; want empty", crossOriginAuth)
	}
}

func TestRetryAfterDateHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", time.Now().UTC().Add(2*time.Second).Format(time.RFC1123))
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"certificate_not_ready","message":"pending","retryable":true,"details":{}}}`))
	}))
	defer server.Close()

	client, err := New(server.URL, validAppToken)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _, err = client.GetTLSMaterial(context.Background(), CertificateCriteria{Domains: []string{"api.example.com"}}, RequestOptions{})
	var apiErr *certerrors.APIError
	if !stderrors.As(err, &apiErr) {
		t.Fatalf("error type = %T; want *errors.APIError", err)
	}
	if got, ok := apiErr.RetryAfterSeconds(); !ok || got < 1 {
		t.Fatalf("retry after = %d, %v; want positive value", got, ok)
	}
}
