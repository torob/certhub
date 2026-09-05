package auth

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/config"
	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/migrations"
	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
)

func TestLoginRecoveryWithPostgres(t *testing.T) {
	pool := securityTestPool(t)
	keys := passwordResetTestKeys(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, resetKind := range []string{"password", "2fa"} {
		for _, withSession := range []bool{false, true} {
			t.Run(resetKind+map[bool]string{false: "/no session", true: "/existing session"}[withSession], func(t *testing.T) {
				tx, err := pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				user := createSecurityTestUser(t, ctx, tx)
				svc := securityTestService(tx, keys)
				start, err := svc.PasswordLogin(ctx, PasswordLoginParams{Email: user.Email, Password: "correct horse battery staple"})
				if err != nil || start.Password2FAProvisioning == nil {
					t.Fatalf("start setup: %v", err)
				}
				handoffToken := OIDCHandoffPrefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				_, err = svc.authRepo.CreateOIDCHandoff(ctx, CreateOIDCHandoffParams{HandoffHash: keys.HashToken(handoffToken), UserID: user.ID, ExpiresAt: time.Now().Add(time.Minute)})
				if err != nil {
					t.Fatal(err)
				}
				var tokens Tokens
				if withSession {
					tokens, _, err = svc.createSession(ctx, user.ID, AuthMethodOIDC, AuditContext{})
					if err != nil {
						t.Fatal(err)
					}
				}
				resetSecurityTestUser(t, ctx, svc, user, resetKind)
				code := GenerateTOTP(start.Password2FAProvisioning.Secret, time.Now().Unix()/totpPeriodSeconds, totpDigits)
				result, err := svc.ConfirmPassword2FALoginSetup(ctx, start.Password2FASetupToken, code, AuditContext{})
				if !errors.Is(err, ErrInvalidToken) || result.Tokens.AccessToken != "" {
					t.Fatalf("setup survived recovery: %v", err)
				}
				result, err = svc.ExchangeOIDCHandoff(ctx, handoffToken, AuditContext{})
				if !errors.Is(err, ErrInvalidCredentials) || result.Tokens.AccessToken != "" {
					t.Fatalf("OIDC handoff survived recovery: %v", err)
				}
				if withSession {
					if _, err := svc.ValidateUserAccessToken(ctx, tokens.AccessToken); !errors.Is(err, ErrInvalidToken) {
						t.Fatalf("session survived recovery: %v", err)
					}
				}
				var count int
				if err := tx.QueryRow(ctx, "select count(*) from user_sessions where user_id = $1 and status = 'active'", user.ID).Scan(&count); err != nil || count != 0 {
					t.Fatalf("active sessions after recovery: count=%d err=%v", count, err)
				}
			})
		}
	}
}

func TestConcurrentLoginRecoveryWithPostgres(t *testing.T) {
	pool := securityTestPool(t)
	keys := passwordResetTestKeys(t)
	for _, loginKind := range []string{"password", "2fa setup", "OIDC handoff"} {
		t.Run(loginKind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			user := createSecurityTestUser(t, ctx, pool)
			svc := securityTestService(pool, keys)
			svc.tx = pool
			start, err := svc.PasswordLogin(ctx, PasswordLoginParams{Email: user.Email, Password: "correct horse battery staple"})
			if err != nil {
				t.Fatal(err)
			}
			handoffToken, err := randomPrefixedToken(OIDCHandoffPrefix)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.authRepo.CreateOIDCHandoff(ctx, CreateOIDCHandoffParams{HandoffHash: keys.HashToken(handoffToken), UserID: user.ID, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
				t.Fatal(err)
			}
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			inflight := securityTestService(tx, keys)
			reachedLock := make(chan struct{})
			resume := make(chan struct{})
			inflight.userRepo = &pausedSecurityUserRepo{Repository: users.NewRepository(tx), reached: reachedLock, resume: resume}
			result := make(chan error, 1)
			go func() {
				var err error
				switch loginKind {
				case "password":
					_, err = inflight.PasswordLogin(ctx, PasswordLoginParams{Email: user.Email, Password: "correct horse battery staple"})
				case "2fa setup":
					code := GenerateTOTP(start.Password2FAProvisioning.Secret, time.Now().Unix()/totpPeriodSeconds, totpDigits)
					_, err = inflight.ConfirmPassword2FALoginSetup(ctx, start.Password2FASetupToken, code, AuditContext{})
				case "OIDC handoff":
					_, err = inflight.ExchangeOIDCHandoff(ctx, handoffToken, AuditContext{})
				}
				result <- err
			}()
			select {
			case <-reachedLock:
			case <-ctx.Done():
				t.Fatal("login did not reach user lock")
			}
			resetSecurityTestUser(t, ctx, svc, user, "password")
			close(resume)
			select {
			case err := <-result:
				if !errors.Is(err, ErrInvalidToken) && !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("login using pre-reset credentials was not rejected: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("login did not finish after recovery")
			}
		})
	}
}

type pausedSecurityUserRepo struct {
	users.Repository
	reached chan struct{}
	resume  chan struct{}
}

func (r *pausedSecurityUserRepo) GetForUpdate(ctx context.Context, id string) (users.User, error) {
	close(r.reached)
	select {
	case <-r.resume:
		return r.Repository.GetForUpdate(ctx, id)
	case <-ctx.Done():
		return users.User{}, ctx.Err()
	}
}

func securityTestPool(t *testing.T) *storage.Pool {
	t.Helper()
	databaseURL := os.Getenv("CERTHUB_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CERTHUB_TEST_DATABASE_URL is not set")
	}
	db, err := migrations.OpenDB(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := migrations.NewRunner(migrations.DefaultDir).Up(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	pool, err := storage.Open(context.Background(), storage.Config{URL: databaseURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func securityTestService(db storage.DBTX, keys *security.KeySet) *Service {
	return NewService(ServiceConfig{
		AuthRepository: NewRepository(db), UserRepository: users.NewRepository(db), AuditRepository: audit.NewRepository(db), KeySet: keys,
		Config: config.AuthConfig{
			Password: config.PasswordConfig{Enabled: true, TwoFARequired: true},
			OIDC:     config.OIDCConfig{Enabled: true}, UserAccessTokenTTLSeconds: 300, UserSessionTTLSeconds: 3600,
		},
	})
}

func createSecurityTestUser(t *testing.T, ctx context.Context, db storage.DBTX) users.User {
	t.Helper()
	id, err := storage.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := security.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	user, err := users.NewRepository(db).Create(ctx, users.CreateUserParams{ID: id, Email: id + "@example.com", DisplayName: "Security test", GlobalRole: users.GlobalRoleAdmin, Status: users.StatusActive, PasswordHash: &hash})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func resetSecurityTestUser(t *testing.T, ctx context.Context, svc *Service, user users.User, kind string) {
	t.Helper()
	if kind == "2fa" {
		if _, err := svc.AdminResetPassword2FA(ctx, AuthenticatedUser{User: user}, user.ID, AuditContext{}); err != nil {
			t.Fatal(err)
		}
		return
	}
	reset, err := svc.AdminCreatePasswordResetLink(ctx, AuthenticatedUser{User: user}, user.ID, nil, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.CompletePasswordReset(ctx, reset.ResetURL, "replacement horse battery staple", AuditContext{}); err != nil {
		t.Fatal(err)
	}
}
