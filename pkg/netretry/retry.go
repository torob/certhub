package netretry

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const MaxAllowedAttempts = 10

type Policy struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

type Client struct {
	base             Doer
	policy           Policy
	retryableMethods map[string]struct{}
}

type ClientOption func(*Client)

var _ Doer = (*Client)(nil)

// WithRetryableMethods adds methods which the caller knows are safe to replay.
// Safe/read-only HTTP methods are enabled by default.
func WithRetryableMethods(methods ...string) ClientOption {
	return func(c *Client) {
		for _, method := range methods {
			method = strings.ToUpper(strings.TrimSpace(method))
			if method != "" {
				c.retryableMethods[method] = struct{}{}
			}
		}
	}
}

func NewClient(base Doer, policy Policy, opts ...ClientOption) *Client {
	if base == nil {
		base = http.DefaultClient
	}
	c := &Client{
		base:   base,
		policy: policy,
		retryableMethods: map[string]struct{}{
			http.MethodGet:     {},
			http.MethodHead:    {},
			http.MethodOptions: {},
			http.MethodTrace:   {},
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func DefaultPolicy() Policy {
	return Policy{MaxAttempts: 5, InitialBackoff: time.Second, MaxBackoff: 8 * time.Second}
}

func (p Policy) Validate() error {
	if p.MaxAttempts < 1 || p.MaxAttempts > MaxAllowedAttempts {
		return errors.New("retry max attempts must be between 1 and 10")
	}
	if p.InitialBackoff <= 0 {
		return errors.New("retry initial backoff must be positive")
	}
	if p.MaxBackoff < p.InitialBackoff {
		return errors.New("retry maximum backoff must be at least the initial backoff")
	}
	return nil
}

func (p Policy) normalized() Policy {
	if p.MaxAttempts == 0 && p.InitialBackoff == 0 && p.MaxBackoff == 0 {
		// A zero policy is intentionally single-attempt. Production constructors
		// install DefaultPolicy explicitly; this keeps zero-value embedding safe.
		return Policy{MaxAttempts: 1, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond}
	}
	return p
}

// Backoff returns the jittered delay before retry number n, where n starts at 1.
// A non-positive result means the retry budget has been exhausted.
func Backoff(policy Policy, n int, retryAfter time.Duration) time.Duration {
	policy = policy.normalized()
	if n < 1 || n >= policy.MaxAttempts {
		return -1
	}
	if retryAfter > 0 {
		return retryAfter
	}
	delay := policy.InitialBackoff
	for i := 1; i < n && delay < policy.MaxBackoff; i++ {
		if delay > policy.MaxBackoff/2 {
			delay = policy.MaxBackoff
			break
		}
		delay *= 2
	}
	if delay > policy.MaxBackoff {
		delay = policy.MaxBackoff
	}
	return jitter(delay)
}

func Wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Do retries an operation when it reports a retryable error.
func Do(ctx context.Context, policy Policy, operation func() (retryable bool, err error)) error {
	return DoWithRetryAfter(ctx, policy, func() (bool, time.Duration, error) {
		retryable, err := operation()
		return retryable, 0, err
	})
}

func DoWithRetryAfter(ctx context.Context, policy Policy, operation func() (retryable bool, retryAfter time.Duration, err error)) error {
	policy = policy.normalized()
	if err := policy.Validate(); err != nil {
		return err
	}
	for attempt := 1; ; attempt++ {
		retryable, retryAfter, err := operation()
		if err == nil || !retryable {
			return err
		}
		delay := Backoff(policy, attempt, retryAfter)
		if delay <= 0 {
			return err
		}
		if err := Wait(ctx, delay); err != nil {
			return err
		}
	}
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("retry HTTP request is nil")
	}
	if c == nil {
		return nil, errors.New("retry HTTP client is nil")
	}
	policy := c.policy.normalized()
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	base := c.base
	if base == nil {
		base = http.DefaultClient
	}
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	if _, ok := c.retryableMethods[method]; !ok || !requestReplayable(req) {
		return base.Do(req)
	}
	ctx := req.Context()
	for attempt := 1; ; attempt++ {
		attemptReq, err := requestForAttempt(req, attempt)
		if err != nil {
			return nil, err
		}
		resp, err := base.Do(attemptReq)
		if err == nil && !RetryableStatus(resp.StatusCode) {
			return resp, nil
		}
		if err != nil && !IsTransientForContext(ctx, err) {
			return nil, err
		}
		retryAfter := time.Duration(0)
		if resp != nil {
			retryAfter = ParseRetryAfter(resp.Header.Get("Retry-After"), time.Now().UTC())
		}
		delay := Backoff(policy, attempt, retryAfter)
		if delay <= 0 {
			if resp != nil {
				return resp, nil
			}
			return nil, err
		}
		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
		}
		if waitErr := Wait(ctx, delay); waitErr != nil {
			return nil, waitErr
		}
	}
}

func requestReplayable(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

func requestForAttempt(req *http.Request, attempt int) (*http.Request, error) {
	if attempt == 1 {
		return req, nil
	}
	next := req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		next.Body = body
	}
	return next, nil
}

func RetryableStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func IsTransient(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var certInvalid x509.CertificateInvalidError
	var hostInvalid x509.HostnameError
	var unknownAuthority x509.UnknownAuthorityError
	var recordHeader tls.RecordHeaderError
	if errors.As(err, &certInvalid) || errors.As(err, &hostInvalid) || errors.As(err, &unknownAuthority) || errors.As(err, &recordHeader) {
		return false
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return IsTransient(urlErr.Err)
	}
	var netErr net.Error
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTimeout || dnsErr.IsTemporary
	}
	if errors.As(err, &netErr) {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE)
}

// IsTransientForContext distinguishes an individual http.Client timeout from
// exhaustion of the caller's overall operation context.
func IsTransientForContext(ctx context.Context, err error) bool {
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		return true
	}
	return IsTransient(err)
}

func ParseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds > 0 {
			if int64(seconds) > int64((time.Duration(1<<63-1))/time.Second) {
				return 0
			}
			return time.Duration(seconds) * time.Second
		}
		return 0
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	return when.Sub(now)
}

func jitter(max time.Duration) time.Duration {
	if max <= 1 {
		return max
	}
	var data [8]byte
	if _, err := rand.Read(data[:]); err != nil {
		return max
	}
	return time.Duration(binary.LittleEndian.Uint64(data[:])%uint64(max)) + 1
}
