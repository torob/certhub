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

func TestRefreshUnknownTokenWithPostgresStorage(t *testing.T) {
	pool := securityTestPool(t)
	keys := passwordResetTestKeys(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	svc := securityTestService(pool, keys)
	svc.tx = pool
	unknownToken, err := randomPrefixedToken(UserAccessTokenPrefix)
	if err != nil {
		t.Fatal(err)
	}
	correlationID, err := storage.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.Refresh(ctx, unknownToken, AuditContext{CorrelationID: correlationID})
	if !errors.Is(err, ErrInvalidToken) || result.Tokens.AccessToken != "" {
		t.Fatalf("Refresh(unknown token) error = %v, want ErrInvalidToken", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `
select count(*) from audit_events
where correlation_id = $1
  and action = 'user_session_refreshed'
  and result = 'failure'
  and metadata->>'reason' = 'invalid_token'`, correlationID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("refresh failure audit events = %d err=%v, want 1", count, err)
	}
}

// TestPasswordLoginFailureAuditPersistsWithPostgres uses the production
// construction (ServiceConfig.Storage set), so each login runs in its own
// write transaction. A rejected login must still leave a committed
// user_login_failed audit event.
func TestPasswordLoginFailureAuditPersistsWithPostgres(t *testing.T) {
	pool := securityTestPool(t)
	keys := passwordResetTestKeys(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	newService := func(passwordEnabled bool, opts ...ServiceOption) *Service {
		return NewService(ServiceConfig{
			AuthRepository: NewRepository(pool), UserRepository: users.NewRepository(pool), AuditRepository: audit.NewRepository(pool), KeySet: keys, Storage: pool,
			Config: config.AuthConfig{
				Password:                  config.PasswordConfig{Enabled: passwordEnabled},
				UserAccessTokenTTLSeconds: 300, UserSessionTTLSeconds: 3600,
			},
		}, opts...)
	}
	active := createSecurityTestUser(t, ctx, pool)
	disabled := createSecurityTestUser(t, ctx, pool)
	if _, err := users.NewRepository(pool).Update(ctx, disabled.ID, users.UpdateUserParams{Status: storage.SetString(string(users.StatusDisabled))}); err != nil {
		t.Fatal(err)
	}
	withTOTP := createSecurityTestUser(t, ctx, pool)
	totpSecret, err := newTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	encryptedTOTP, err := keys.EncryptTOTPSecret(totpSecret, totpAAD(withTOTP.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.NewRepository(pool).Update(ctx, withTOTP.ID, users.UpdateUserParams{TOTPSecretEncrypted: storage.SetString(encryptedTOTP), Password2FAEnabled: storage.SetBool(true)}); err != nil {
		t.Fatal(err)
	}
	unknownID, err := storage.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	wrongTOTP := "000000"
	if VerifyTOTP(totpSecret, wrongTOTP, time.Now().UTC()) {
		wrongTOTP = "111111"
	}
	const password = "correct horse battery staple"
	tests := []struct {
		name            string
		passwordEnabled bool
		params          PasswordLoginParams
		wantErr         error
		wantTarget      *string
		wantReason      string
	}{
		{name: "wrong password", passwordEnabled: true, params: PasswordLoginParams{Email: active.Email, Password: "wrong horse battery staple"}, wantErr: ErrInvalidCredentials, wantTarget: &active.ID, wantReason: "invalid_credentials"},
		{name: "unknown email", passwordEnabled: true, params: PasswordLoginParams{Email: unknownID + "@example.com", Password: password}, wantErr: ErrInvalidCredentials, wantReason: "invalid_credentials"},
		{name: "disabled user", passwordEnabled: true, params: PasswordLoginParams{Email: disabled.Email, Password: password}, wantErr: ErrInvalidCredentials, wantTarget: &disabled.ID, wantReason: "invalid_credentials"},
		{name: "invalid 2fa code", passwordEnabled: true, params: PasswordLoginParams{Email: withTOTP.Email, Password: password, TOTPCode: wrongTOTP}, wantErr: ErrInvalid2FACode, wantTarget: &withTOTP.ID, wantReason: "invalid_2fa_code"},
		{name: "missing 2fa code", passwordEnabled: true, params: PasswordLoginParams{Email: withTOTP.Email, Password: password}, wantErr: ErrPassword2FARequired, wantTarget: &withTOTP.ID, wantReason: "password_2fa_required"},
		{name: "password auth disabled", passwordEnabled: false, params: PasswordLoginParams{Email: active.Email, Password: password}, wantErr: ErrPasswordAuthDisabled, wantReason: "password_auth_disabled"},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			correlationID, err := storage.NewUUID()
			if err != nil {
				t.Fatal(err)
			}
			tc.params.Audit = AuditContext{CorrelationID: correlationID, SourceIP: "192.0.2." + string(rune('1'+i))}
			_, err = newService(tc.passwordEnabled).PasswordLogin(ctx, tc.params)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("login error = %v, want %v", err, tc.wantErr)
			}
			assertLoginFailedAudit(t, ctx, pool, correlationID, tc.wantTarget, tc.wantReason)
		})
	}
	t.Run("rate limited", func(t *testing.T) {
		svc := newService(true, WithLoginRateLimiter(NewLoginRateLimiter(LoginRateLimitConfig{EmailIPFailureLimit: 1, IPFailureLimit: 10, Window: time.Minute})))
		first, err := storage.NewUUID()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.PasswordLogin(ctx, PasswordLoginParams{Email: active.Email, Password: "wrong horse battery staple", Audit: AuditContext{CorrelationID: first, SourceIP: "198.51.100.1"}}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("first login error = %v", err)
		}
		limited, err := storage.NewUUID()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.PasswordLogin(ctx, PasswordLoginParams{Email: active.Email, Password: password, Audit: AuditContext{CorrelationID: limited, SourceIP: "198.51.100.1"}}); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("second login error = %v, want rate limited", err)
		}
		// The rate-limited event must not name the User: it must not reveal
		// whether the email exists.
		assertLoginFailedAudit(t, ctx, pool, limited, nil, "rate_limited")
	})
}

func assertLoginFailedAudit(t *testing.T, ctx context.Context, pool *storage.Pool, correlationID string, wantTarget *string, wantReason string) {
	t.Helper()
	rows, err := pool.Query(ctx, "select action, identity_type, result, target_id::text, metadata->>'method', metadata->>'reason' from audit_events where correlation_id = $1", correlationID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		var action, identityType, result, method, reason string
		var targetID *string
		if err := rows.Scan(&action, &identityType, &result, &targetID, &method, &reason); err != nil {
			t.Fatal(err)
		}
		if action != "user_login_failed" || identityType != string(audit.IdentityTypeSystem) || result != string(audit.ResultFailure) || method != string(AuthMethodPassword) || reason != wantReason {
			t.Fatalf("audit event = action %q identity %q result %q method %q reason %q, want user_login_failed/system/failure/password/%s", action, identityType, result, method, reason, wantReason)
		}
		if (targetID == nil) != (wantTarget == nil) || (targetID != nil && *targetID != *wantTarget) {
			t.Fatalf("audit target = %v, want %v", targetID, wantTarget)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("user_login_failed audit events for correlation %s = %d, want 1", correlationID, count)
	}
}
