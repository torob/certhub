package netretry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestDefaultPolicyAndValidationBoundaries(t *testing.T) {
	if got := DefaultPolicy(); got != (Policy{MaxAttempts: 5, InitialBackoff: time.Second, MaxBackoff: 8 * time.Second}) {
		t.Fatalf("default policy = %#v", got)
	}
	tests := []struct {
		name    string
		policy  Policy
		wantErr bool
	}{
		{name: "minimum", policy: Policy{MaxAttempts: 1, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond}},
		{name: "maximum attempts", policy: Policy{MaxAttempts: MaxAllowedAttempts, InitialBackoff: time.Second, MaxBackoff: time.Hour}},
		{name: "zero attempts", policy: Policy{MaxAttempts: 0, InitialBackoff: time.Second, MaxBackoff: time.Second}, wantErr: true},
		{name: "negative attempts", policy: Policy{MaxAttempts: -1, InitialBackoff: time.Second, MaxBackoff: time.Second}, wantErr: true},
		{name: "too many attempts", policy: Policy{MaxAttempts: MaxAllowedAttempts + 1, InitialBackoff: time.Second, MaxBackoff: time.Second}, wantErr: true},
		{name: "zero initial", policy: Policy{MaxAttempts: 2, MaxBackoff: time.Second}, wantErr: true},
		{name: "negative initial", policy: Policy{MaxAttempts: 2, InitialBackoff: -time.Second, MaxBackoff: time.Second}, wantErr: true},
		{name: "maximum below initial", policy: Policy{MaxAttempts: 2, InitialBackoff: 2 * time.Second, MaxBackoff: time.Second}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestBackoffBudgetAndBounds(t *testing.T) {
	p := Policy{MaxAttempts: 5, InitialBackoff: time.Second, MaxBackoff: 8 * time.Second}
	for retry, max := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second} {
		got := Backoff(p, retry+1, 0)
		if got < 0 || got > max {
			t.Fatalf("retry %d delay = %s; want [0,%s]", retry+1, got, max)
		}
	}
	if got := Backoff(p, 5, 0); got > 0 {
		t.Fatalf("exhausted delay = %s; want non-positive", got)
	}
}

func TestBackoffHonorsRetryAfterCapsAndZeroPolicy(t *testing.T) {
	p := Policy{MaxAttempts: 4, InitialBackoff: 4 * time.Second, MaxBackoff: 5 * time.Second}
	if got := Backoff(p, 1, 17*time.Second); got != 17*time.Second {
		t.Fatalf("Retry-After backoff = %s; want 17s", got)
	}
	if got := Backoff(p, 2, 0); got <= 0 || got > 5*time.Second {
		t.Fatalf("capped backoff = %s; want (0,5s]", got)
	}
	if got := Backoff(p, 0, 0); got >= 0 {
		t.Fatalf("retry zero backoff = %s; want negative", got)
	}
	if got := Backoff(Policy{}, 1, 0); got >= 0 {
		t.Fatalf("zero policy backoff = %s; want single-attempt exhaustion", got)
	}
}

func TestRetryableStatusMatrix(t *testing.T) {
	retryable := map[int]bool{
		http.StatusRequestTimeout:      true,
		http.StatusTooEarly:            true,
		http.StatusTooManyRequests:     true,
		http.StatusInternalServerError: true,
		http.StatusBadGateway:          true,
		http.StatusServiceUnavailable:  true,
		http.StatusGatewayTimeout:      true,
	}
	for _, status := range []int{200, 400, 401, 403, 404, 409, 408, 425, 429, 500, 501, 502, 503, 504} {
		if got := RetryableStatus(status); got != retryable[status] {
			t.Errorf("RetryableStatus(%d) = %v; want %v", status, got, retryable[status])
		}
	}
}

func TestClientRetriesStatusAndRebuildsRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	var builds atomic.Int32
	client := NewClient(doerFunc(func(req *http.Request) (*http.Response, error) {
		builds.Add(1)
		return server.Client().Do(req)
	}), Policy{MaxAttempts: 5, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if calls.Load() != 3 || builds.Load() != 3 || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("calls=%d builds=%d status=%d", calls.Load(), builds.Load(), resp.StatusCode)
	}
}

func TestClientRetriesEveryTransientStatusOnly(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 408, 409, 425, 429, 500, 501, 502, 503, 504} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			base := doerFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return response(req, status, "response"), nil
			})
			req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
			resp, err := NewClient(base, tinyPolicy(3)).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			wantCalls := 1
			if RetryableStatus(status) {
				wantCalls = 3
			}
			if calls != wantCalls || resp.StatusCode != status {
				t.Fatalf("calls=%d status=%d; want calls=%d status=%d", calls, resp.StatusCode, wantCalls, status)
			}
		})
	}
}

func TestClientLeavesFinalResponseReadable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("final body"))
	}))
	defer server.Close()
	client := NewClient(server.Client(), Policy{MaxAttempts: 1, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "final body" {
		t.Fatalf("body = %q", body)
	}
}

func TestClientRetriesOnlyExplicitlySafePostAndReplaysBody(t *testing.T) {
	var calls atomic.Int32
	var bodies []string
	base := doerFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		body, _ := io.ReadAll(req.Body)
		bodies = append(bodies, string(body))
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("retry")), Request: req}, nil
	})
	policy := Policy{MaxAttempts: 3, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond}
	req, _ := http.NewRequest(http.MethodPost, "https://example.com", strings.NewReader("payload"))
	resp, err := NewClient(base, policy).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if calls.Load() != 1 {
		t.Fatalf("unsafe POST attempts = %d; want 1", calls.Load())
	}

	calls.Store(0)
	bodies = nil
	req, _ = http.NewRequest(http.MethodPost, "https://example.com", strings.NewReader("payload"))
	resp, err = NewClient(base, policy, WithRetryableMethods(http.MethodPost)).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if calls.Load() != 3 || strings.Join(bodies, ",") != "payload,payload,payload" {
		t.Fatalf("attempts=%d bodies=%v", calls.Load(), bodies)
	}
}

func TestClientDoesNotReplayBodyWithoutGetBody(t *testing.T) {
	var calls atomic.Int32
	base := doerFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	})
	req, _ := http.NewRequest(http.MethodPost, "https://example.com", io.NopCloser(strings.NewReader("payload")))
	policy := Policy{MaxAttempts: 3, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond}
	resp, err := NewClient(base, policy, WithRetryableMethods(http.MethodPost)).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if calls.Load() != 1 {
		t.Fatalf("attempts = %d; want 1", calls.Load())
	}
}

func TestClientRetriesTransientTransportErrorAndStopsOnPermanentError(t *testing.T) {
	transientCalls := 0
	transient := doerFunc(func(req *http.Request) (*http.Response, error) {
		transientCalls++
		if transientCalls < 3 {
			return nil, io.ErrUnexpectedEOF
		}
		return response(req, http.StatusNoContent, ""), nil
	})
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	resp, err := NewClient(transient, tinyPolicy(4)).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if transientCalls != 3 {
		t.Fatalf("transient calls = %d; want 3", transientCalls)
	}

	permanentCalls := 0
	permanentErr := x509.UnknownAuthorityError{}
	permanent := doerFunc(func(*http.Request) (*http.Response, error) {
		permanentCalls++
		return nil, permanentErr
	})
	req, _ = http.NewRequest(http.MethodGet, "https://example.com", nil)
	if _, err := NewClient(permanent, tinyPolicy(4)).Do(req); !errors.As(err, &permanentErr) {
		t.Fatalf("permanent error = %v; want UnknownAuthorityError", err)
	}
	if permanentCalls != 1 {
		t.Fatalf("permanent calls = %d; want 1", permanentCalls)
	}
}

func TestClientClosesIntermediateResponseAndPreservesFinalBody(t *testing.T) {
	firstBody := &trackingBody{Reader: strings.NewReader("temporary")}
	calls := 0
	base := doerFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Body: firstBody, Request: req}, nil
		}
		return response(req, http.StatusOK, "final"), nil
	})
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	resp, err := NewClient(base, tinyPolicy(2)).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if !firstBody.closed || string(data) != "final" {
		t.Fatalf("intermediate closed=%v final=%q", firstBody.closed, data)
	}
}

func TestClientCancellationDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	base := doerFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		cancel()
		resp := response(req, http.StatusServiceUnavailable, "retry")
		resp.Header.Set("Retry-After", "3600")
		return resp, nil
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com", nil)
	if _, err := NewClient(base, tinyPolicy(3)).Do(req); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v; want context canceled", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d; want 1", calls)
	}
}

func TestClientRejectsInvalidInputsAndPolicy(t *testing.T) {
	client := NewClient(nil, DefaultPolicy())
	if _, err := client.Do(nil); err == nil {
		t.Fatal("nil request accepted")
	}
	var nilClient *Client
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if _, err := nilClient.Do(req); err == nil {
		t.Fatal("nil client accepted")
	}
	req, _ = http.NewRequest(http.MethodGet, "https://example.com", nil)
	if _, err := NewClient(doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid policy reached base client")
		return nil, nil
	}), Policy{MaxAttempts: 11, InitialBackoff: time.Second, MaxBackoff: time.Second}).Do(req); err == nil {
		t.Fatal("invalid policy accepted")
	}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

type trackingBody struct {
	io.Reader
	closed bool
}

func (b *trackingBody) Close() error {
	b.closed = true
	return nil
}

func response(req *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

func tinyPolicy(attempts int) Policy {
	return Policy{MaxAttempts: attempts, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond}
}

func TestWaitCancellation(t *testing.T) {
	if err := Wait(context.Background(), 0); err != nil {
		t.Fatalf("zero wait: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Wait(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait error = %v", err)
	}
}

func TestDoHelpersRetryStopExhaustAndHonorRetryAfter(t *testing.T) {
	calls := 0
	err := Do(context.Background(), tinyPolicy(4), func() (bool, error) {
		calls++
		if calls < 3 {
			return true, io.ErrUnexpectedEOF
		}
		return false, nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("eventual success: calls=%d err=%v", calls, err)
	}

	lastErr := errors.New("last")
	calls = 0
	err = Do(context.Background(), tinyPolicy(2), func() (bool, error) {
		calls++
		return true, lastErr
	})
	if !errors.Is(err, lastErr) || calls != 2 {
		t.Fatalf("exhaustion: calls=%d err=%v", calls, err)
	}

	calls = 0
	err = Do(context.Background(), tinyPolicy(3), func() (bool, error) {
		calls++
		return false, lastErr
	})
	if !errors.Is(err, lastErr) || calls != 1 {
		t.Fatalf("non-retryable: calls=%d err=%v", calls, err)
	}

	started := time.Now()
	calls = 0
	err = DoWithRetryAfter(context.Background(), tinyPolicy(2), func() (bool, time.Duration, error) {
		calls++
		if calls == 1 {
			return true, 2 * time.Millisecond, lastErr
		}
		return false, 0, nil
	})
	if err != nil || calls != 2 || time.Since(started) < 2*time.Millisecond {
		t.Fatalf("Retry-After: calls=%d elapsed=%s err=%v", calls, time.Since(started), err)
	}
}

func TestPerAttemptDeadlineIsRetryableButParentDeadlineIsNot(t *testing.T) {
	if !IsTransientForContext(context.Background(), context.DeadlineExceeded) {
		t.Fatal("per-attempt deadline was not retryable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if IsTransientForContext(ctx, context.DeadlineExceeded) {
		t.Fatal("exhausted parent context was retryable")
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestIsTransientClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil},
		{name: "EOF", err: io.EOF, want: true},
		{name: "unexpected EOF", err: io.ErrUnexpectedEOF, want: true},
		{name: "connection reset", err: syscall.ECONNRESET, want: true},
		{name: "connection refused", err: syscall.ECONNREFUSED, want: true},
		{name: "broken pipe", err: syscall.EPIPE, want: true},
		{name: "network timeout", err: timeoutError{}, want: true},
		{name: "URL wrapped timeout", err: &url.Error{Op: "Get", URL: "https://example.com", Err: timeoutError{}}, want: true},
		{name: "temporary DNS", err: &net.DNSError{Err: "temporary", IsTemporary: true}, want: true},
		{name: "DNS timeout", err: &net.DNSError{Err: "timeout", IsTimeout: true}, want: true},
		{name: "DNS not found", err: &net.DNSError{Err: "no such host", IsNotFound: true}},
		{name: "canceled", err: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded},
		{name: "unknown authority", err: x509.UnknownAuthorityError{}},
		{name: "hostname", err: x509.HostnameError{}},
		{name: "certificate invalid", err: x509.CertificateInvalidError{}},
		{name: "TLS record", err: tls.RecordHeaderError{}},
		{name: "ordinary", err: errors.New("ordinary")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTransient(tt.err); got != tt.want {
				t.Fatalf("IsTransient(%T) = %v; want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	if got := ParseRetryAfter("7", now); got != 7*time.Second {
		t.Fatalf("seconds = %s", got)
	}
	if got := ParseRetryAfter(now.Add(9*time.Second).Format(http.TimeFormat), now); got != 9*time.Second {
		t.Fatalf("date = %s", got)
	}
	for _, value := range []string{"", "0", "-1", "9227000000", "nonsense", now.Add(-time.Second).Format(http.TimeFormat)} {
		if got := ParseRetryAfter(value, now); got != 0 {
			t.Errorf("ParseRetryAfter(%q) = %s; want 0", value, got)
		}
	}
}

func FuzzParseRetryAfterNeverPanics(f *testing.F) {
	for _, seed := range []string{"", "0", "7", "-1", "Wed, 21 Oct 2015 07:28:00 GMT", strings.Repeat("9", 100)} {
		f.Add(seed)
	}
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, value string) {
		if got := ParseRetryAfter(value, now); got < 0 {
			t.Fatalf("negative delay %s for %q", got, value)
		}
	})
}

func FuzzValidPolicyBackoffInvariants(f *testing.F) {
	f.Add(int64(5), int64(time.Second), int64(8*time.Second), int64(1))
	f.Add(int64(1), int64(1), int64(1), int64(1))
	f.Fuzz(func(t *testing.T, attempts, initial, maximum, retry int64) {
		if attempts < 1 || attempts > MaxAllowedAttempts || initial <= 0 || maximum < initial {
			return
		}
		p := Policy{MaxAttempts: int(attempts), InitialBackoff: time.Duration(initial), MaxBackoff: time.Duration(maximum)}
		if err := p.Validate(); err != nil {
			return
		}
		got := Backoff(p, int(retry), 0)
		if retry < 1 || retry >= attempts {
			if got >= 0 {
				t.Fatalf("exhausted retry %d returned %s", retry, got)
			}
			return
		}
		if got <= 0 || got > p.MaxBackoff {
			t.Fatalf("retry %d returned %s outside (0,%s]", retry, got, p.MaxBackoff)
		}
	})
}
