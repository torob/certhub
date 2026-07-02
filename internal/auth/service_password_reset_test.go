package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/config"
	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
)

func TestPasswordLoginMissingForced2FARequiresSetupWithoutSession(t *testing.T) {
	keys := passwordResetTestKeys(t)
	hash, err := security.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	repo := newPasswordFlowRepo(users.User{
		ID:           "12345678-1234-4234-9234-123456789abc",
		Email:        "user@example.com",
		DisplayName:  "User",
		PasswordHash: &hash,
		GlobalRole:   users.GlobalRoleUser,
		Status:       users.StatusActive,
	})
	service := newPasswordFlowService(keys, repo, true)

	result, err := service.PasswordLogin(context.Background(), PasswordLoginParams{
		Email:    "user@example.com",
		Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "password_2fa_setup_required" || !strings.HasPrefix(result.Password2FASetupToken, Password2FASetupPrefix) || result.Password2FAProvisioning == nil {
		t.Fatalf("unexpected login result: %#v", result)
	}
	if len(repo.createdSessions) != 0 {
		t.Fatalf("created session before 2FA setup: %#v", repo.createdSessions)
	}
	if len(repo.setups) != 1 {
		t.Fatalf("setup tokens = %d", len(repo.setups))
	}
}

func TestPassword2FALoginSetupRejectsWrongCodeThenCreatesSession(t *testing.T) {
	keys := passwordResetTestKeys(t)
	hash, err := security.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	repo := newPasswordFlowRepo(users.User{
		ID:           "12345678-1234-4234-9234-123456789abc",
		Email:        "user@example.com",
		DisplayName:  "User",
		PasswordHash: &hash,
		GlobalRole:   users.GlobalRoleUser,
		Status:       users.StatusActive,
	})
	service := newPasswordFlowService(keys, repo, true)
	start, err := service.PasswordLogin(context.Background(), PasswordLoginParams{Email: "user@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.ConfirmPassword2FALoginSetup(context.Background(), start.Password2FASetupToken, "000000", AuditContext{})
	if !errors.Is(err, ErrInvalid2FACode) {
		t.Fatalf("wrong code err = %v", err)
	}
	if repo.setupByHash[keys.HashToken(start.Password2FASetupToken)].Status != OneTimeTokenStatusActive {
		t.Fatalf("wrong code consumed setup token")
	}

	code := GenerateTOTP(start.Password2FAProvisioning.Secret, time.Now().UTC().Unix()/totpPeriodSeconds, totpDigits)
	done, err := service.ConfirmPassword2FALoginSetup(context.Background(), start.Password2FASetupToken, code, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != "completed" || done.Tokens.AccessToken == "" || len(repo.createdSessions) != 1 {
		t.Fatalf("setup completion did not create a session: %#v", done)
	}
	updated := repo.users["12345678-1234-4234-9234-123456789abc"]
	if !updated.Password2FAEnabled || updated.TOTPSecretEncrypted == nil {
		t.Fatalf("2FA was not enabled on user: %#v", updated)
	}
	if repo.setupByHash[keys.HashToken(start.Password2FASetupToken)].Status != OneTimeTokenStatusConsumed {
		t.Fatalf("setup token was not consumed")
	}
}

func TestPasswordResetLinksAreOneTimeSupersedingAndRevokeSessions(t *testing.T) {
	keys := passwordResetTestKeys(t)
	oldHash, err := security.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	encryptedTOTP, err := keys.EncryptTOTPSecret("JBSWY3DPEHPK3PXP", totpAAD("22345678-1234-4234-9234-123456789abc"))
	if err != nil {
		t.Fatal(err)
	}
	admin := users.User{
		ID:          "12345678-1234-4234-9234-123456789abc",
		Email:       "admin@example.com",
		DisplayName: "Admin",
		GlobalRole:  users.GlobalRoleAdmin,
		Status:      users.StatusActive,
	}
	target := users.User{
		ID:                  "22345678-1234-4234-9234-123456789abc",
		Email:               "user@example.com",
		DisplayName:         "User",
		PasswordHash:        &oldHash,
		Password2FAEnabled:  true,
		TOTPSecretEncrypted: &encryptedTOTP,
		GlobalRole:          users.GlobalRoleUser,
		Status:              users.StatusActive,
	}
	repo := newPasswordFlowRepo(admin, target)
	repo.sessions["32345678-1234-4234-9234-123456789abc"] = Session{
		ID:               "32345678-1234-4234-9234-123456789abc",
		UserID:           target.ID,
		Status:           SessionStatusActive,
		AccessExpiresAt:  time.Now().Add(time.Minute),
		RefreshExpiresAt: time.Now().Add(time.Hour),
	}
	service := newPasswordFlowService(keys, repo, true)
	current := AuthenticatedUser{User: admin}

	first, err := service.AdminCreatePasswordResetLink(context.Background(), current, target.ID, func(token string) string {
		return "https://certhub.example.com/reset-password?token=" + token
	}, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.AdminCreatePasswordResetLink(context.Background(), current, target.ID, nil, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if first.ResetURL == second.ResetURL || strings.Contains(repo.latestResetHash, PasswordResetPrefix) {
		t.Fatalf("reset tokens were not one-time hashed values")
	}
	if _, err := service.PreviewPasswordReset(context.Background(), strings.TrimPrefix(first.ResetURL, "https://certhub.example.com/reset-password?token=")); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("superseded reset preview err = %v", err)
	}
	preview, err := service.PreviewPasswordReset(context.Background(), second.ResetURL)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Email != target.Email {
		t.Fatalf("preview email = %q", preview.Email)
	}

	if err := service.CompletePasswordReset(context.Background(), second.ResetURL, "new correct horse battery staple", AuditContext{}); err != nil {
		t.Fatal(err)
	}
	updated := repo.users[target.ID]
	if updated.PasswordHash == nil || *updated.PasswordHash == oldHash || !updated.Password2FAEnabled || updated.TOTPSecretEncrypted == nil {
		t.Fatalf("password reset mutated unexpected user fields: %#v", updated)
	}
	if repo.sessions["32345678-1234-4234-9234-123456789abc"].Status != SessionStatusRevoked {
		t.Fatalf("active session was not revoked")
	}
	if _, err := service.PreviewPasswordReset(context.Background(), second.ResetURL); !errors.Is(err, ErrInvalidPasswordReset) {
		t.Fatalf("consumed reset preview err = %v", err)
	}
}

func TestAdminResetPassword2FADisablesAndRevokesSessions(t *testing.T) {
	keys := passwordResetTestKeys(t)
	encryptedTOTP, err := keys.EncryptTOTPSecret("JBSWY3DPEHPK3PXP", totpAAD("22345678-1234-4234-9234-123456789abc"))
	if err != nil {
		t.Fatal(err)
	}
	admin := users.User{ID: "12345678-1234-4234-9234-123456789abc", Email: "admin@example.com", DisplayName: "Admin", GlobalRole: users.GlobalRoleAdmin, Status: users.StatusActive}
	target := users.User{
		ID:                  "22345678-1234-4234-9234-123456789abc",
		Email:               "user@example.com",
		DisplayName:         "User",
		Password2FAEnabled:  true,
		TOTPSecretEncrypted: &encryptedTOTP,
		GlobalRole:          users.GlobalRoleUser,
		Status:              users.StatusActive,
	}
	repo := newPasswordFlowRepo(admin, target)
	repo.sessions["32345678-1234-4234-9234-123456789abc"] = Session{ID: "32345678-1234-4234-9234-123456789abc", UserID: target.ID, Status: SessionStatusActive}
	service := newPasswordFlowService(keys, repo, true)

	updated, err := service.AdminResetPassword2FA(context.Background(), AuthenticatedUser{User: admin}, target.ID, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Password2FAEnabled || updated.TOTPSecretEncrypted != nil || repo.sessions["32345678-1234-4234-9234-123456789abc"].Status != SessionStatusRevoked {
		t.Fatalf("2FA reset failed: user=%#v session=%#v", updated, repo.sessions["32345678-1234-4234-9234-123456789abc"])
	}
	if _, err := service.AdminResetPassword2FA(context.Background(), AuthenticatedUser{User: admin}, target.ID, AuditContext{}); err != nil {
		t.Fatalf("idempotent reset err = %v", err)
	}
}

func passwordResetTestKeys(t *testing.T) *security.KeySet {
	t.Helper()
	keys, err := security.NewKeySet(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func newPasswordFlowService(keys *security.KeySet, repo *passwordFlowRepo, twoFARequired bool) *Service {
	return NewService(ServiceConfig{
		AuthRepository:  repo,
		UserRepository:  repo,
		AuditRepository: repo,
		KeySet:          keys,
		Config: config.AuthConfig{
			Password:                   config.PasswordConfig{Enabled: true, TwoFARequired: twoFARequired},
			UserAccessTokenTTLSeconds:  300,
			UserRefreshTokenTTLSeconds: 3600,
			PasswordResetTTLSeconds:    3600,
		},
	})
}

type passwordFlowRepo struct {
	users           map[string]users.User
	userByEmail     map[string]string
	resets          []PasswordResetToken
	resetByHash     map[string]PasswordResetToken
	setups          []Password2FALoginSetup
	setupByHash     map[string]Password2FALoginSetup
	sessions        map[string]Session
	createdSessions []CreateSessionParams
	audits          []audit.AppendEventParams
	latestResetHash string
}

func newPasswordFlowRepo(values ...users.User) *passwordFlowRepo {
	repo := &passwordFlowRepo{
		users:       map[string]users.User{},
		userByEmail: map[string]string{},
		resetByHash: map[string]PasswordResetToken{},
		setupByHash: map[string]Password2FALoginSetup{},
		sessions:    map[string]Session{},
	}
	for _, user := range values {
		repo.users[user.ID] = user
		repo.userByEmail[user.Email] = user.ID
	}
	return repo
}

func (r *passwordFlowRepo) CreateSession(_ context.Context, params CreateSessionParams) (Session, error) {
	id := "42345678-1234-4234-9234-123456789abc"
	if len(r.createdSessions) > 0 {
		id = "52345678-1234-4234-9234-123456789abc"
	}
	session := Session{
		ID:               id,
		UserID:           params.UserID,
		AuthMethod:       params.AuthMethod,
		AccessTokenHash:  params.AccessTokenHash,
		RefreshTokenHash: params.RefreshTokenHash,
		Status:           SessionStatusActive,
		AccessExpiresAt:  params.AccessExpiresAt,
		RefreshExpiresAt: params.RefreshExpiresAt,
	}
	r.createdSessions = append(r.createdSessions, params)
	r.sessions[id] = session
	return session, nil
}

func (r *passwordFlowRepo) GetSessionByAccessTokenHash(context.Context, string) (Session, error) {
	return Session{}, storage.ErrNoRows
}

func (r *passwordFlowRepo) MarkSessionUsed(context.Context, string) error { return nil }

func (r *passwordFlowRepo) RevokeSession(_ context.Context, sessionID string, reason SessionRevokedReason) (bool, error) {
	session, ok := r.sessions[sessionID]
	if !ok || session.Status != SessionStatusActive {
		return false, nil
	}
	session.Status = SessionStatusRevoked
	session.RevokedReason = &reason
	r.sessions[sessionID] = session
	return true, nil
}

func (r *passwordFlowRepo) RevokeUserSessions(_ context.Context, userID string, reason SessionRevokedReason) (int64, error) {
	var count int64
	for id, session := range r.sessions {
		if session.UserID != userID || session.Status != SessionStatusActive {
			continue
		}
		session.Status = SessionStatusRevoked
		session.RevokedReason = &reason
		r.sessions[id] = session
		count++
	}
	return count, nil
}

func (r *passwordFlowRepo) RotateRefreshToken(context.Context, RotateRefreshTokenParams) (Session, error) {
	return Session{}, errors.New("not implemented")
}

func (r *passwordFlowRepo) CreateOIDCState(context.Context, CreateOIDCStateParams) (OIDCLoginState, error) {
	return OIDCLoginState{}, errors.New("not implemented")
}

func (r *passwordFlowRepo) ConsumeOIDCState(context.Context, string) (OIDCLoginState, error) {
	return OIDCLoginState{}, errors.New("not implemented")
}

func (r *passwordFlowRepo) CreateOIDCHandoff(context.Context, CreateOIDCHandoffParams) (OIDCLoginHandoff, error) {
	return OIDCLoginHandoff{}, errors.New("not implemented")
}

func (r *passwordFlowRepo) ConsumeOIDCHandoff(context.Context, string) (OIDCLoginHandoff, error) {
	return OIDCLoginHandoff{}, errors.New("not implemented")
}

func (r *passwordFlowRepo) CreatePasswordReset(_ context.Context, params CreatePasswordResetParams) (PasswordResetToken, error) {
	for hash, reset := range r.resetByHash {
		if reset.UserID == params.UserID && reset.Status == OneTimeTokenStatusActive {
			reset.Status = OneTimeTokenStatusSuperseded
			r.resetByHash[hash] = reset
		}
	}
	token := PasswordResetToken{
		ID:              "62345678-1234-4234-9234-123456789abc",
		UserID:          params.UserID,
		TokenHash:       params.TokenHash,
		Status:          OneTimeTokenStatusActive,
		CreatedByUserID: params.CreatedByUserID,
		CreatedAt:       time.Now().UTC(),
		ExpiresAt:       params.ExpiresAt,
	}
	r.latestResetHash = params.TokenHash
	r.resets = append(r.resets, token)
	r.resetByHash[params.TokenHash] = token
	return token, nil
}

func (r *passwordFlowRepo) GetActivePasswordResetByHash(_ context.Context, tokenHash string) (PasswordResetToken, error) {
	reset, ok := r.resetByHash[tokenHash]
	if !ok || reset.Status != OneTimeTokenStatusActive || !reset.ExpiresAt.After(time.Now().UTC()) {
		return PasswordResetToken{}, storage.ErrNoRows
	}
	return reset, nil
}

func (r *passwordFlowRepo) ConsumePasswordReset(_ context.Context, tokenHash string) (PasswordResetToken, error) {
	reset, ok := r.resetByHash[tokenHash]
	if !ok || reset.Status != OneTimeTokenStatusActive || !reset.ExpiresAt.After(time.Now().UTC()) {
		return PasswordResetToken{}, storage.ErrNoRows
	}
	reset.Status = OneTimeTokenStatusConsumed
	now := time.Now().UTC()
	reset.ConsumedAt = &now
	r.resetByHash[tokenHash] = reset
	return reset, nil
}

func (r *passwordFlowRepo) CreatePassword2FASetup(_ context.Context, params CreatePassword2FASetupParams) (Password2FALoginSetup, error) {
	for hash, setup := range r.setupByHash {
		if setup.UserID == params.UserID && setup.Status == OneTimeTokenStatusActive {
			setup.Status = OneTimeTokenStatusSuperseded
			r.setupByHash[hash] = setup
		}
	}
	setup := Password2FALoginSetup{
		ID:                         "72345678-1234-4234-9234-123456789abc",
		SetupHash:                  params.SetupHash,
		UserID:                     params.UserID,
		PendingTOTPSecretEncrypted: params.PendingTOTPSecretEncrypted,
		Status:                     OneTimeTokenStatusActive,
		CreatedAt:                  time.Now().UTC(),
		ExpiresAt:                  params.ExpiresAt,
	}
	r.setups = append(r.setups, setup)
	r.setupByHash[params.SetupHash] = setup
	return setup, nil
}

func (r *passwordFlowRepo) GetActivePassword2FASetupByHash(_ context.Context, setupHash string) (Password2FALoginSetup, error) {
	setup, ok := r.setupByHash[setupHash]
	if !ok || setup.Status != OneTimeTokenStatusActive || !setup.ExpiresAt.After(time.Now().UTC()) {
		return Password2FALoginSetup{}, storage.ErrNoRows
	}
	return setup, nil
}

func (r *passwordFlowRepo) ConsumePassword2FASetup(_ context.Context, setupHash string) (Password2FALoginSetup, error) {
	setup, ok := r.setupByHash[setupHash]
	if !ok || setup.Status != OneTimeTokenStatusActive || !setup.ExpiresAt.After(time.Now().UTC()) {
		return Password2FALoginSetup{}, storage.ErrNoRows
	}
	setup.Status = OneTimeTokenStatusConsumed
	now := time.Now().UTC()
	setup.ConsumedAt = &now
	r.setupByHash[setupHash] = setup
	return setup, nil
}

func (r *passwordFlowRepo) Get(_ context.Context, userID string) (users.User, error) {
	user, ok := r.users[userID]
	if !ok {
		return users.User{}, storage.ErrNoRows
	}
	return user, nil
}

func (r *passwordFlowRepo) LookupByNormalizedEmail(_ context.Context, email string) (users.User, error) {
	id, ok := r.userByEmail[email]
	if !ok {
		return users.User{}, storage.ErrNoRows
	}
	return r.users[id], nil
}

func (r *passwordFlowRepo) LookupByOIDC(context.Context, string, string) (users.User, error) {
	return users.User{}, storage.ErrNoRows
}

func (r *passwordFlowRepo) Update(_ context.Context, userID string, params users.UpdateUserParams) (users.User, error) {
	user, ok := r.users[userID]
	if !ok {
		return users.User{}, storage.ErrNoRows
	}
	if params.PasswordHash.Set {
		user.PasswordHash = params.PasswordHash.Value
	}
	if params.Password2FAEnabled.Set {
		user.Password2FAEnabled = params.Password2FAEnabled.Value
	}
	if params.TOTPSecretEncrypted.Set {
		user.TOTPSecretEncrypted = params.TOTPSecretEncrypted.Value
	}
	if params.PendingTOTPSecretEncrypted.Set {
		user.PendingTOTPSecretEncrypted = params.PendingTOTPSecretEncrypted.Value
	}
	if params.LastLoginAt.Set {
		user.LastLoginAt = params.LastLoginAt.Value
	}
	r.users[userID] = user
	return user, nil
}

func (r *passwordFlowRepo) Append(_ context.Context, params audit.AppendEventParams) (audit.Event, error) {
	r.audits = append(r.audits, params)
	return audit.Event{Action: params.Action, Metadata: params.Metadata}, nil
}
