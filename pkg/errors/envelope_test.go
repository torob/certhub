package errors

import (
	"strings"
	"testing"
	"time"
)

func TestAPIErrorRetryAfterPrefersHeader(t *testing.T) {
	header := 7
	body := 30
	err := NewAPIError(409, "req-1", &header, Envelope{
		Code:              CodeCertificateNotReady,
		Message:           "pending",
		Retryable:         true,
		RetryAfterSeconds: &body,
	})

	got, ok := err.RetryAfterSeconds()
	if !ok || got != 7 {
		t.Fatalf("RetryAfterSeconds() = %d, %v; want 7, true", got, ok)
	}
	if text := err.Error(); !strings.Contains(text, "certificate_not_ready") || !strings.Contains(text, "request_id=req-1") {
		t.Fatalf("Error() missing code or request ID: %q", text)
	}
}

func TestOperatorAuthorizationErrorCodeConstants(t *testing.T) {
	tests := map[string]string{
		"application_source_ip_denied": CodeApplicationSourceIPDenied,
		"domain_not_authorized":        CodeDomainNotAuthorized,
	}
	for want, got := range tests {
		if got != want {
			t.Fatalf("constant = %q; want %q", got, want)
		}
	}
}

func TestParseRetryAfterSeconds(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	if got, ok := ParseRetryAfterSeconds("15", now); !ok || got != 15 {
		t.Fatalf("seconds Retry-After = %d, %v; want 15, true", got, ok)
	}
	if got, ok := ParseRetryAfterSeconds("Wed, 24 Jun 2026 12:00:05 GMT", now); !ok || got != 5 {
		t.Fatalf("date Retry-After = %d, %v; want 5, true", got, ok)
	}
	if _, ok := ParseRetryAfterSeconds("0", now); ok {
		t.Fatal("zero Retry-After parsed as valid")
	}
}
