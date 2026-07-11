package netretry

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

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

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestWaitCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Wait(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait error = %v", err)
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

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	if got := ParseRetryAfter("7", now); got != 7*time.Second {
		t.Fatalf("seconds = %s", got)
	}
	if got := ParseRetryAfter(now.Add(9*time.Second).Format(http.TimeFormat), now); got != 9*time.Second {
		t.Fatalf("date = %s", got)
	}
}
