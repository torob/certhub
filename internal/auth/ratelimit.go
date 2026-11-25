package auth

import (
	"context"
	"errors"
	"math"
	"runtime"
	"strings"
	"sync"
	"time"

	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/storage"
)

// Default login rate limits. Counters are kept in memory in each server
// process; they are not shared between replicas and reset on restart.
const (
	DefaultLoginEmailIPFailureLimit = 5
	DefaultLoginIPFailureLimit      = 50
	DefaultLoginFailureWindow       = 5 * time.Minute
	DefaultLoginRateLimitMaxKeys    = 100_000
	// maxDefaultPasswordVerifications caps concurrent Argon2id verifications.
	// Each verification uses 64 MiB, so the cap bounds that memory.
	maxDefaultPasswordVerifications = 4
)

// ErrRateLimited reports that too many failed password or TOTP verifications
// were made. Use errors.As with *RateLimitError to read the retry delay.
var ErrRateLimited = errors.New("rate limited")

type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string { return ErrRateLimited.Error() }

func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

// RetryAfterSeconds returns the delay rounded up to whole seconds, at least 1.
func (e *RateLimitError) RetryAfterSeconds() int {
	seconds := int(math.Ceil(e.RetryAfter.Seconds()))
	if seconds < 1 {
		return 1
	}
	return seconds
}

type LoginRateLimitConfig struct {
	// EmailIPFailureLimit is the number of failures allowed for one normalized
	// email plus source IP in one window.
	EmailIPFailureLimit int
	// IPFailureLimit is the number of failures allowed for one source IP in one window.
	IPFailureLimit int
	// Window is the fixed failure window. It starts at the first failure.
	Window time.Duration
	// MaxKeys caps the number of tracked keys.
	MaxKeys int
	// MaxConcurrentVerifications caps concurrent Argon2id password verifications.
	MaxConcurrentVerifications int
	// Now is the clock. Tests can replace it.
	Now func() time.Time
}

// LoginRateLimiter limits failed password and TOTP verifications by
// normalized email plus source IP and by source IP alone. It also limits the
// number of concurrent Argon2id verifications. It is safe for concurrent use.
type LoginRateLimiter struct {
	cfg     LoginRateLimitConfig
	mu      sync.Mutex
	entries map[string]*loginFailureEntry
	verify  chan struct{}
}

type loginFailureEntry struct {
	failures  int
	inflight  int
	windowEnd time.Time
	// lastUsed is the time of the last admitted attempt. Eviction uses it.
	lastUsed time.Time
}

func NewLoginRateLimiter(cfg LoginRateLimitConfig) *LoginRateLimiter {
	if cfg.EmailIPFailureLimit <= 0 {
		cfg.EmailIPFailureLimit = DefaultLoginEmailIPFailureLimit
	}
	if cfg.IPFailureLimit <= 0 {
		cfg.IPFailureLimit = DefaultLoginIPFailureLimit
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultLoginFailureWindow
	}
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = DefaultLoginRateLimitMaxKeys
	}
	if cfg.MaxConcurrentVerifications <= 0 {
		cfg.MaxConcurrentVerifications = min(runtime.GOMAXPROCS(0), maxDefaultPasswordVerifications)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &LoginRateLimiter{
		cfg:     cfg,
		entries: map[string]*loginFailureEntry{},
		verify:  make(chan struct{}, cfg.MaxConcurrentVerifications),
	}
}

// WithLoginRateLimiter replaces the default login rate limiter.
func WithLoginRateLimiter(limiter *LoginRateLimiter) ServiceOption {
	return func(s *Service) {
		if limiter != nil {
			s.loginLimiter = limiter
		}
	}
}

// loginAttempt is one admitted verification attempt. Exactly one of fail,
// succeed, or done must be called. It is safe to call them on a nil attempt.
type loginAttempt struct {
	limiter *LoginRateLimiter
	keys    []string
}

// begin admits one attempt for the email and source IP. It reserves the
// attempt against both keys, so parallel requests cannot pass the limit.
func (l *LoginRateLimiter) begin(email, sourceIP string) (*loginAttempt, error) {
	if l == nil {
		return nil, nil
	}
	keys := []string{loginEmailIPKey(email, sourceIP), loginIPKey(sourceIP)}
	limits := []int{l.cfg.EmailIPFailureLimit, l.cfg.IPFailureLimit}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.cfg.Now()
	var retryAfter time.Duration
	missing := 0
	for i, key := range keys {
		entry := l.entries[key]
		if entry == nil {
			missing++
			continue
		}
		if !now.Before(entry.windowEnd) {
			entry.failures = 0
		}
		if entry.failures+entry.inflight >= limits[i] {
			wait := entry.windowEnd.Sub(now)
			if entry.failures == 0 {
				// Only in-flight attempts fill the limit.
				wait = time.Second
			}
			retryAfter = max(retryAfter, wait)
		}
	}
	if retryAfter > 0 {
		return nil, &RateLimitError{RetryAfter: retryAfter}
	}
	// Reserve the existing keys first, so that making room cannot evict them.
	for _, key := range keys {
		if entry := l.entries[key]; entry != nil {
			entry.inflight++
			entry.lastUsed = now
		}
	}
	if missing > 0 && !l.makeRoomLocked(now, missing) {
		for _, key := range keys {
			if entry := l.entries[key]; entry != nil {
				entry.inflight--
			}
		}
		return nil, &RateLimitError{RetryAfter: time.Second}
	}
	for _, key := range keys {
		if l.entries[key] == nil {
			l.entries[key] = &loginFailureEntry{inflight: 1, lastUsed: now}
		}
	}
	return &loginAttempt{limiter: l, keys: keys}, nil
}

// fail records one failed password or TOTP verification.
func (a *loginAttempt) fail() {
	a.finish(func(entry *loginFailureEntry, now time.Time, window time.Duration, _ int) {
		if entry.failures == 0 || !now.Before(entry.windowEnd) {
			entry.failures = 0
			entry.windowEnd = now.Add(window)
		}
		entry.failures++
	})
}

// succeed clears the normalized email plus source IP failure counter.
func (a *loginAttempt) succeed() {
	a.finish(func(entry *loginFailureEntry, _ time.Time, _ time.Duration, index int) {
		if index == 0 {
			entry.failures = 0
		}
	})
}

// finishWith records the result of the attempt. Invalid credentials and
// invalid 2FA codes count as failures. A nil error clears the email plus
// source IP counter only when clearOnSuccess is true.
func (a *loginAttempt) finishWith(err error, clearOnSuccess bool) {
	switch {
	case errors.Is(err, ErrInvalidCredentials), errors.Is(err, ErrInvalid2FACode):
		a.fail()
	case err == nil && clearOnSuccess:
		a.succeed()
	default:
		a.done()
	}
}

// done releases the attempt without recording a result.
func (a *loginAttempt) done() {
	a.finish(func(*loginFailureEntry, time.Time, time.Duration, int) {})
}

func (a *loginAttempt) finish(update func(*loginFailureEntry, time.Time, time.Duration, int)) {
	if a == nil || a.limiter == nil {
		return
	}
	l := a.limiter
	a.limiter = nil
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.cfg.Now()
	for i, key := range a.keys {
		entry := l.entries[key]
		if entry == nil {
			continue
		}
		if entry.inflight > 0 {
			entry.inflight--
		}
		update(entry, now, l.cfg.Window, i)
		if entry.inflight == 0 && (entry.failures == 0 || !now.Before(entry.windowEnd)) {
			delete(l.entries, key)
		}
	}
}

// makeRoomLocked makes room for n new keys. It removes expired keys first.
// If the map is still full, it evicts the least recently used keys. It
// never evicts keys with in-flight attempts. It reports false if no room can
// be made.
func (l *LoginRateLimiter) makeRoomLocked(now time.Time, n int) bool {
	if len(l.entries)+n <= l.cfg.MaxKeys {
		return true
	}
	for key, entry := range l.entries {
		if entry.inflight == 0 && (entry.failures == 0 || !now.Before(entry.windowEnd)) {
			delete(l.entries, key)
		}
	}
	for len(l.entries)+n > l.cfg.MaxKeys {
		oldestKey := ""
		var oldest time.Time
		for key, entry := range l.entries {
			if entry.inflight > 0 {
				continue
			}
			if oldestKey == "" || entry.lastUsed.Before(oldest) {
				oldestKey, oldest = key, entry.lastUsed
			}
		}
		if oldestKey == "" {
			return false
		}
		delete(l.entries, oldestKey)
	}
	return true
}

// acquireVerification waits for an Argon2id verification slot. It returns
// the context error if the context ends first.
func (l *LoginRateLimiter) acquireVerification(ctx context.Context) (func(), error) {
	if l == nil {
		return func() {}, nil
	}
	select {
	case l.verify <- struct{}{}:
		return func() { <-l.verify }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func loginEmailIPKey(email, sourceIP string) string {
	normalized, err := storage.NormalizeEmail(strings.TrimSpace(email))
	if err != nil {
		normalized = strings.ToLower(strings.TrimSpace(email))
	}
	return "email_ip\x00" + normalized + "\x00" + sourceIP
}

func loginIPKey(sourceIP string) string {
	return "ip\x00" + sourceIP
}

// verifyPasswordWithSlot runs one Argon2id verification inside a concurrency slot.
// A non-nil error from the slot wait is returned as is; other errors and
// mismatches return match=false.
func (s *Service) verifyPasswordWithSlot(ctx context.Context, password, hash string) (match, needsRehash bool, err error) {
	release, err := s.loginLimiter.acquireVerification(ctx)
	if err != nil {
		return false, false, err
	}
	defer release()
	match, needsRehash, verifyErr := security.VerifyPassword(password, hash)
	if verifyErr != nil {
		return false, false, nil
	}
	return match, needsRehash, nil
}

// verifyDummyPasswordWithSlot spends the same Argon2id work as a real verification
// for unknown or unusable accounts. It returns only the slot wait error.
func (s *Service) verifyDummyPasswordWithSlot(ctx context.Context, password string) error {
	release, err := s.loginLimiter.acquireVerification(ctx)
	if err != nil {
		return err
	}
	defer release()
	_ = verifyDummyPassword(password)
	return nil
}
