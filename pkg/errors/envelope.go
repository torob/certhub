package errors

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	CodeInvalidRequest             = "invalid_request"
	CodeInvalidToken               = "invalid_token"
	CodeApplicationTokenRequired   = "application_token_required"
	CodeUserTokenRequired          = "user_token_required"
	CodeRefreshTokenNotAllowed     = "refresh_token_not_allowed"
	CodeApplicationSourceIPDenied  = "application_source_ip_denied"
	CodeDomainNotAuthorized        = "domain_not_authorized"
	CodeCertificateNotFound        = "certificate_not_found"
	CodeCertificateNotReady        = "certificate_not_ready"
	CodeCertificateExpired         = "certificate_expired"
	CodeCertificateIssuanceFailed  = "certificate_issuance_failed"
	CodeCertificateRevoked         = "certificate_revoked"
	CodeCertificateNoActiveVersion = "certificate_no_active_version"
	CodeIssuerNotConfigured        = "issuer_not_configured"
	CodeServiceUnavailable         = "service_unavailable"
	CodeIssuerUnavailable          = "issuer_unavailable"
	CodeDNSProviderUnavailable     = "dns_provider_unavailable"
	CodeDNSZoneDiscoveryFailed     = "dns_zone_discovery_failed"
	CodeRateLimited                = "rate_limited"
)

type Response struct {
	Error Envelope `json:"error"`
}

type Envelope struct {
	Code              string         `json:"code"`
	Message           string         `json:"message"`
	Retryable         bool           `json:"retryable"`
	RetryAfterSeconds *int           `json:"retry_after_seconds,omitempty"`
	Details           map[string]any `json:"details,omitempty"`
}

type APIError struct {
	StatusCode              int
	RequestID               string
	HeaderRetryAfterSeconds *int
	Envelope                Envelope
}

func (e *APIError) Error() string {
	if e == nil {
		return "<nil>"
	}
	var b strings.Builder
	if e.Envelope.Code != "" {
		b.WriteString(e.Envelope.Code)
	} else {
		b.WriteString("certhub_api_error")
	}
	if e.Envelope.Message != "" {
		b.WriteString(": ")
		b.WriteString(e.Envelope.Message)
	}
	if e.StatusCode > 0 {
		b.WriteString(" (status ")
		b.WriteString(strconv.Itoa(e.StatusCode))
		b.WriteString(")")
	}
	if e.RequestID != "" {
		b.WriteString(" request_id=")
		b.WriteString(e.RequestID)
	}
	return b.String()
}

func (e *APIError) RetryAfterSeconds() (int, bool) {
	if e == nil {
		return 0, false
	}
	if e.HeaderRetryAfterSeconds != nil {
		return *e.HeaderRetryAfterSeconds, true
	}
	if e.Envelope.RetryAfterSeconds != nil {
		return *e.Envelope.RetryAfterSeconds, true
	}
	return 0, false
}

func NewAPIError(statusCode int, requestID string, headerRetryAfterSeconds *int, envelope Envelope) *APIError {
	return &APIError{
		StatusCode:              statusCode,
		RequestID:               requestID,
		HeaderRetryAfterSeconds: headerRetryAfterSeconds,
		Envelope:                envelope,
	}
}

func NewLocal(code, message string) *APIError {
	return &APIError{
		Envelope: Envelope{
			Code:      code,
			Message:   message,
			Retryable: false,
			Details:   map[string]any{},
		},
	}
}

func ParseRetryAfterSeconds(value string, now time.Time) (int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	seconds, err := strconv.Atoi(value)
	if err == nil && seconds > 0 {
		return seconds, true
	}
	when, err := httpTime(value)
	if err != nil {
		return 0, false
	}
	delay := int(when.Sub(now).Seconds())
	if delay < 1 {
		delay = 1
	}
	return delay, true
}

func httpTime(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC1123, time.RFC1123Z, time.RFC850, time.ANSIC} {
		if t, err := time.Parse(layout, value); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid Retry-After value")
}
