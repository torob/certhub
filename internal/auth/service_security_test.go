package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
)

func TestPasswordLoginSetupCannotReplaceEstablishedCredentials(t *testing.T) {
	for _, change := range []string{"password reset", "2fa reset", "2fa enabled", "password login disabled", "password removed"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			keys := passwordResetTestKeys(t)
			hash, err := security.HashPassword("correct horse battery staple")
			if err != nil {
				t.Fatal(err)
			}
			user := users.User{ID: "12345678-1234-4234-9234-123456789abc", Email: "admin@example.com", DisplayName: "Admin", GlobalRole: users.GlobalRoleAdmin, Status: users.StatusActive, PasswordHash: &hash}
			repo := newPasswordFlowRepo(user)
			svc := newPasswordFlowService(keys, repo, true)
			start, err := svc.PasswordLogin(ctx, PasswordLoginParams{Email: user.Email, Password: "correct horse battery staple"})
			if err != nil || start.Password2FAProvisioning == nil {
				t.Fatalf("start setup: %v", err)
			}
			switch change {
			case "password reset":
				reset, err := svc.AdminCreatePasswordResetLink(ctx, AuthenticatedUser{User: user}, user.ID, nil, AuditContext{})
				if err != nil {
					t.Fatal(err)
				}
				if err := svc.CompletePasswordReset(ctx, reset.ResetURL, "replacement horse battery staple", AuditContext{}); err != nil {
					t.Fatal(err)
				}
			case "2fa reset":
				if _, err := svc.AdminResetPassword2FA(ctx, AuthenticatedUser{User: user}, user.ID, AuditContext{}); err != nil {
					t.Fatal(err)
				}
			case "2fa enabled":
				secret, err := keys.EncryptTOTPSecret("JBSWY3DPEHPK3PXP", totpAAD(user.ID))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := repo.Update(ctx, user.ID, users.UpdateUserParams{Password2FAEnabled: storage.SetBool(true), TOTPSecretEncrypted: storage.SetString(secret)}); err != nil {
					t.Fatal(err)
				}
			case "password login disabled":
				svc.cfg.Password.Enabled = false
			case "password removed":
				if _, err := repo.Update(ctx, user.ID, users.UpdateUserParams{PasswordHash: storage.ClearString()}); err != nil {
					t.Fatal(err)
				}
			}
			before := repo.users[user.ID]
			code := GenerateTOTP(start.Password2FAProvisioning.Secret, time.Now().UTC().Unix()/totpPeriodSeconds, totpDigits)
			result, err := svc.ConfirmPassword2FALoginSetup(ctx, start.Password2FASetupToken, code, AuditContext{})
			if err == nil || result.Tokens.AccessToken != "" || len(repo.createdSessions) != 0 {
				t.Fatal("stale setup granted a new session with certificate access")
			}
			if !errors.Is(err, ErrInvalidToken) && !errors.Is(err, ErrPasswordAuthDisabled) {
				t.Fatalf("unexpected rejection: %v", err)
			}
			after := repo.users[user.ID]
			if before.TOTPSecretEncrypted != after.TOTPSecretEncrypted || before.Password2FAEnabled != after.Password2FAEnabled {
				t.Fatal("rejected setup changed the user's second factor")
			}
		})
	}
}
