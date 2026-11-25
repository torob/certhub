package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/users"
)

type fakeLoginClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeLoginClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeLoginClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newFakeLoginClock() *fakeLoginClock {
	return &fakeLoginClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

type lookupCountingRepo struct {
	*passwordFlowRepo
	lookups int
}

func (r *lookupCountingRepo) LookupByNormalizedEmail(ctx context.Context, email string) (users.User, error) {
	r.lookups++
	return r.passwordFlowRepo.LookupByNormalizedEmail(ctx, email)
}

func TestPasswordLoginRateLimitsUnknownAndKnownEmailBeforeLookup(t *testing.T) {
	ctx := context.Background()
	keys := passwordResetTestKeys(t)
	hash, err := security.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	user := users.User{ID: "12345678-1234-4234-9234-123456789abc", Email: "admin@example.com", DisplayName: "Admin", GlobalRole: users.GlobalRoleAdmin, Status: users.StatusActive, PasswordHash: &hash}
	for _, email := range []string{"nobody@example.com", user.Email} {
		t.Run(email, func(t *testing.T) {
			repo := &lookupCountingRepo{passwordFlowRepo: newPasswordFlowRepo(user)}
			svc := newPasswordFlowService(keys, repo.passwordFlowRepo, false)
			svc.userRepo = repo
			params := PasswordLoginParams{Email: email, Password: "wrong horse battery staple", Audit: AuditContext{SourceIP: "203.0.113.7"}}
			for i := 0; i < DefaultLoginEmailIPFailureLimit; i++ {
				if _, err := svc.PasswordLogin(ctx, params); !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("attempt %d: err = %v", i+1, err)
				}
			}
			lookups := repo.lookups
			_, err := svc.PasswordLogin(ctx, params)
			var limited *RateLimitError
			if !errors.Is(err, ErrRateLimited) || !errors.As(err, &limited) || limited.RetryAfterSeconds() < 1 {
				t.Fatalf("attempt over limit: err = %v", err)
			}
			if repo.lookups != lookups {
				t.Fatal("rate-limited login looked up the user")
			}
			// The correct password is also refused while the limit is active.
			params.Password = "correct horse battery staple"
			if _, err := svc.PasswordLogin(ctx, params); !errors.Is(err, ErrRateLimited) {
				t.Fatalf("correct password over limit: err = %v", err)
			}
		})
	}
}

func TestPasswordLoginTOTPFailuresAreRateLimitedAndSuccessClearsEmailKey(t *testing.T) {
	ctx := context.Background()
	keys := passwordResetTestKeys(t)
	hash, err := security.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	const totpSecret = "JBSWY3DPEHPK3PXP"
	userID := "12345678-1234-4234-9234-123456789abc"
	encrypted, err := keys.EncryptTOTPSecret(totpSecret, totpAAD(userID))
	if err != nil {
		t.Fatal(err)
	}
	user := users.User{ID: userID, Email: "admin@example.com", DisplayName: "Admin", GlobalRole: users.GlobalRoleAdmin, Status: users.StatusActive, PasswordHash: &hash, Password2FAEnabled: true, TOTPSecretEncrypted: &encrypted}
	clock := newFakeLoginClock()
	svc := NewService(newPasswordFlowService(keys, newPasswordFlowRepo(user), false).serviceConfigForTest(), WithLoginRateLimiter(NewLoginRateLimiter(LoginRateLimitConfig{EmailIPFailureLimit: 2, IPFailureLimit: 10, Window: time.Minute, Now: clock.Now})))
	params := PasswordLoginParams{Email: user.Email, Password: "correct horse battery staple", TOTPCode: wrongTOTPCode(totpSecret), Audit: AuditContext{SourceIP: "203.0.113.7"}}
	for i := 0; i < 2; i++ {
		if _, err := svc.PasswordLogin(ctx, params); !errors.Is(err, ErrInvalid2FACode) {
			t.Fatalf("attempt %d: err = %v", i+1, err)
		}
	}
	params.TOTPCode = GenerateTOTP(totpSecret, time.Now().UTC().Unix()/totpPeriodSeconds, totpDigits)
	_, err = svc.PasswordLogin(ctx, params)
	var limited *RateLimitError
	if !errors.As(err, &limited) || limited.RetryAfter != time.Minute {
		t.Fatalf("correct code over limit: err = %v", err)
	}

	clock.Advance(time.Minute)
	if result, err := svc.PasswordLogin(ctx, params); err != nil || result.Status != "completed" {
		t.Fatalf("login after window: status=%q err=%v", result.Status, err)
	}
	if entry := svc.loginLimiter.entries[loginEmailIPKey(user.Email, "203.0.113.7")]; entry != nil {
		t.Fatalf("successful login kept the email plus source IP counter: %+v", *entry)
	}
}

func TestPassword2FAVerificationEndpointsAreRateLimited(t *testing.T) {
	ctx := context.Background()
	keys := passwordResetTestKeys(t)
	hash, err := security.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	const totpSecret = "JBSWY3DPEHPK3PXP"
	userID := "12345678-1234-4234-9234-123456789abc"
	encrypted, err := keys.EncryptTOTPSecret(totpSecret, totpAAD(userID))
	if err != nil {
		t.Fatal(err)
	}
	auditCtx := AuditContext{SourceIP: "203.0.113.7"}
	limiterConfig := LoginRateLimitConfig{EmailIPFailureLimit: 2, IPFailureLimit: 10, Window: time.Minute}

	t.Run("disable with password", func(t *testing.T) {
		user := users.User{ID: userID, Email: "admin@example.com", Status: users.StatusActive, PasswordHash: &hash, Password2FAEnabled: true, TOTPSecretEncrypted: &encrypted}
		svc := NewService(newPasswordFlowService(keys, newPasswordFlowRepo(user), false).serviceConfigForTest(), WithLoginRateLimiter(NewLoginRateLimiter(limiterConfig)))
		current := AuthenticatedUser{User: user}
		for i := 0; i < 2; i++ {
			if err := svc.DisablePassword2FA(ctx, current, "wrong horse battery staple", "", auditCtx); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("attempt %d: err = %v", i+1, err)
			}
		}
		if err := svc.DisablePassword2FA(ctx, current, "correct horse battery staple", "", auditCtx); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("attempt over limit: err = %v", err)
		}
	})

	t.Run("disable with code", func(t *testing.T) {
		user := users.User{ID: userID, Email: "admin@example.com", Status: users.StatusActive, PasswordHash: &hash, Password2FAEnabled: true, TOTPSecretEncrypted: &encrypted}
		svc := NewService(newPasswordFlowService(keys, newPasswordFlowRepo(user), false).serviceConfigForTest(), WithLoginRateLimiter(NewLoginRateLimiter(limiterConfig)))
		current := AuthenticatedUser{User: user}
		for i := 0; i < 2; i++ {
			if err := svc.DisablePassword2FA(ctx, current, "", wrongTOTPCode(totpSecret), auditCtx); !errors.Is(err, ErrInvalid2FACode) {
				t.Fatalf("attempt %d: err = %v", i+1, err)
			}
		}
		if err := svc.DisablePassword2FA(ctx, current, "", wrongTOTPCode(totpSecret), auditCtx); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("attempt over limit: err = %v", err)
		}
	})

	t.Run("confirm setup", func(t *testing.T) {
		user := users.User{ID: userID, Email: "admin@example.com", Status: users.StatusActive, PasswordHash: &hash, PendingTOTPSecretEncrypted: &encrypted}
		svc := NewService(newPasswordFlowService(keys, newPasswordFlowRepo(user), false).serviceConfigForTest(), WithLoginRateLimiter(NewLoginRateLimiter(limiterConfig)))
		current := AuthenticatedUser{User: user}
		for i := 0; i < 2; i++ {
			if err := svc.ConfirmPassword2FA(ctx, current, wrongTOTPCode(totpSecret), auditCtx); !errors.Is(err, ErrInvalid2FACode) {
				t.Fatalf("attempt %d: err = %v", i+1, err)
			}
		}
		if err := svc.ConfirmPassword2FA(ctx, current, wrongTOTPCode(totpSecret), auditCtx); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("attempt over limit: err = %v", err)
		}
	})

	t.Run("required login setup confirm", func(t *testing.T) {
		user := users.User{ID: userID, Email: "admin@example.com", Status: users.StatusActive, PasswordHash: &hash}
		svc := NewService(newPasswordFlowService(keys, newPasswordFlowRepo(user), true).serviceConfigForTest(), WithLoginRateLimiter(NewLoginRateLimiter(limiterConfig)))
		start, err := svc.PasswordLogin(ctx, PasswordLoginParams{Email: user.Email, Password: "correct horse battery staple", Audit: auditCtx})
		if err != nil || start.Password2FAProvisioning == nil {
			t.Fatalf("start setup: %v", err)
		}
		secret := start.Password2FAProvisioning.Secret
		for i := 0; i < 2; i++ {
			if _, err := svc.ConfirmPassword2FALoginSetup(ctx, start.Password2FASetupToken, wrongTOTPCode(secret), auditCtx); !errors.Is(err, ErrInvalid2FACode) {
				t.Fatalf("attempt %d: err = %v", i+1, err)
			}
		}
		// A new password step must not clear the TOTP failure counter.
		if _, err := svc.PasswordLogin(ctx, PasswordLoginParams{Email: user.Email, Password: "correct horse battery staple", Audit: auditCtx}); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("password step over limit: err = %v", err)
		}
		code := GenerateTOTP(secret, time.Now().UTC().Unix()/totpPeriodSeconds, totpDigits)
		if _, err := svc.ConfirmPassword2FALoginSetup(ctx, start.Password2FASetupToken, code, auditCtx); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("attempt over limit: err = %v", err)
		}
	})
}

func TestLoginRateLimiterSourceIPLimitAcrossEmails(t *testing.T) {
	clock := newFakeLoginClock()
	limiter := NewLoginRateLimiter(LoginRateLimitConfig{EmailIPFailureLimit: 5, IPFailureLimit: 3, Window: time.Minute, Now: clock.Now})
	for i := 0; i < 3; i++ {
		attempt, err := limiter.begin(fmt.Sprintf("user%d@example.com", i), "203.0.113.7")
		if err != nil {
			t.Fatal(err)
		}
		attempt.fail()
		clock.Advance(10 * time.Second)
	}
	_, err := limiter.begin("other@example.com", "203.0.113.7")
	var limited *RateLimitError
	if !errors.As(err, &limited) || limited.RetryAfterSeconds() != 30 {
		t.Fatalf("source IP limit: err = %v", err)
	}
	if attempt, err := limiter.begin("other@example.com", "203.0.113.8"); err != nil {
		t.Fatalf("other source IP: %v", err)
	} else {
		attempt.done()
	}
	clock.Advance(30 * time.Second)
	if attempt, err := limiter.begin("other@example.com", "203.0.113.7"); err != nil {
		t.Fatalf("after window: %v", err)
	} else {
		attempt.done()
	}
}

func TestLoginRateLimiterReservesParallelAttempts(t *testing.T) {
	limiter := NewLoginRateLimiter(LoginRateLimitConfig{EmailIPFailureLimit: 3, IPFailureLimit: 100})
	var attempts []*loginAttempt
	for i := 0; i < 3; i++ {
		attempt, err := limiter.begin("admin@example.com", "203.0.113.7")
		if err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
		attempts = append(attempts, attempt)
	}
	if _, err := limiter.begin("admin@example.com", "203.0.113.7"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("in-flight attempts did not count: %v", err)
	}
	for _, attempt := range attempts {
		attempt.done()
	}
	if len(limiter.entries) != 0 {
		t.Fatalf("released attempts left %d keys", len(limiter.entries))
	}
}

func TestLoginRateLimiterBoundsKeys(t *testing.T) {
	clock := newFakeLoginClock()
	limiter := NewLoginRateLimiter(LoginRateLimitConfig{EmailIPFailureLimit: 5, IPFailureLimit: 1000, Window: 10 * time.Minute, MaxKeys: 10, Now: clock.Now})
	for i := 0; i < 100; i++ {
		attempt, err := limiter.begin(fmt.Sprintf("user%d@example.com", i), "203.0.113.7")
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		attempt.fail()
		if len(limiter.entries) > 10 {
			t.Fatalf("limiter tracks %d keys, cap is 10", len(limiter.entries))
		}
		clock.Advance(time.Second)
	}
	// Rotating emails must not evict the source IP counter of the attempts.
	if entry := limiter.entries[loginIPKey("203.0.113.7")]; entry == nil || entry.failures != 100 {
		t.Fatalf("source IP counter was evicted or reset: %+v", entry)
	}
	clock.Advance(10 * time.Minute)
	attempt, err := limiter.begin("late@example.com", "198.51.100.1")
	if err != nil {
		t.Fatal(err)
	}
	attempt.fail()
	if len(limiter.entries) != 2 {
		t.Fatalf("expired keys were not removed first: %d keys", len(limiter.entries))
	}
}

func TestLoginRateLimiterVerificationSlotsRespectCancellation(t *testing.T) {
	limiter := NewLoginRateLimiter(LoginRateLimitConfig{MaxConcurrentVerifications: 1})
	release, err := limiter.acquireVerification(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := limiter.acquireVerification(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second verification did not wait for a slot: %v", err)
	}
	release()
	release, err = limiter.acquireVerification(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestNewLoginRateLimiterDefaults(t *testing.T) {
	limiter := NewLoginRateLimiter(LoginRateLimitConfig{})
	if limiter.cfg.EmailIPFailureLimit != 5 || limiter.cfg.IPFailureLimit != 50 || limiter.cfg.Window != 5*time.Minute || limiter.cfg.MaxKeys != 100_000 {
		t.Fatalf("defaults = %+v", limiter.cfg)
	}
	if limiter.cfg.MaxConcurrentVerifications < 1 || limiter.cfg.MaxConcurrentVerifications > maxDefaultPasswordVerifications {
		t.Fatalf("verification slots = %d", limiter.cfg.MaxConcurrentVerifications)
	}
	if NewService(ServiceConfig{}).loginLimiter == nil {
		t.Fatal("NewService did not install a login rate limiter")
	}
}

func wrongTOTPCode(secret string) string {
	now := time.Now().UTC().Unix() / totpPeriodSeconds
	for i := 0; i < 1_000_000; i++ {
		code := fmt.Sprintf("%06d", i)
		if code != GenerateTOTP(secret, now-1, totpDigits) && code != GenerateTOTP(secret, now, totpDigits) && code != GenerateTOTP(secret, now+1, totpDigits) {
			return code
		}
	}
	panic("no wrong TOTP code")
}

func (s *Service) serviceConfigForTest() ServiceConfig {
	return ServiceConfig{
		AuthRepository:  s.authRepo,
		UserRepository:  s.userRepo,
		AuditRepository: s.auditRepo,
		KeySet:          s.keys,
		Config:          s.cfg,
	}
}
