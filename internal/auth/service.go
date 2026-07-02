package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/torob/certhub/internal/audit"
	"github.com/torob/certhub/internal/config"
	security "github.com/torob/certhub/internal/crypto"
	"github.com/torob/certhub/internal/storage"
	"github.com/torob/certhub/internal/users"
)

const (
	UserAccessTokenPrefix  = "cth_uat_v1_"
	UserRefreshTokenPrefix = "cth_urt_v1_"
	OIDCHandoffPrefix      = "cth_oidc_handoff_"
	PasswordResetPrefix    = "cth_pwd_reset_v1_"
	Password2FASetupPrefix = "cth_pwd_2fa_setup_v1_"

	oidcStatePrefix         = "cth_oidc_state_"
	tokenSecretBytes        = 32
	oidcStateSecretBytes    = 32
	oidcHandoffTTL          = 5 * time.Minute
	oidcLoginStateTTL       = 10 * time.Minute
	password2FASetupTTL     = 10 * time.Minute
	defaultPasswordResetTTL = time.Hour
	totpIssuer              = "Certhub"
	totpDigits              = 6
	totpPeriodSeconds       = 30
	totpAllowedSkewWindow   = 1
)

var (
	ErrInvalidCredentials         = errors.New("invalid credentials")
	ErrPasswordAuthDisabled       = errors.New("password auth disabled")
	ErrPassword2FARequired        = errors.New("password 2fa required")
	ErrInvalid2FACode             = errors.New("invalid 2fa code")
	ErrInvalidToken               = errors.New("invalid token")
	ErrRefreshTokenNotAllowed     = errors.New("refresh token not allowed")
	ErrUserTokenRequired          = errors.New("user token required")
	ErrInvalidRefreshToken        = errors.New("invalid refresh token")
	ErrSessionExpired             = errors.New("session expired")
	ErrConflict                   = errors.New("conflict")
	ErrNotFound                   = errors.New("not found")
	ErrForbidden                  = errors.New("forbidden")
	ErrInvalidRequest             = errors.New("invalid request")
	ErrUserDisabled               = errors.New("user disabled")
	ErrOIDCDisabled               = errors.New("oidc disabled")
	ErrOIDCValidationFailed       = errors.New("oidc validation failed")
	ErrOIDCUserNotProvisioned     = errors.New("oidc user not provisioned")
	ErrIdentityServiceUnavailable = errors.New("identity service unavailable")
	ErrInvalidPasswordReset       = errors.New("invalid password reset")
)

type SessionRepository interface {
	CreateSession(context.Context, CreateSessionParams) (Session, error)
	GetSessionByAccessTokenHash(context.Context, string) (Session, error)
	MarkSessionUsed(context.Context, string) error
	RevokeSession(context.Context, string, SessionRevokedReason) (bool, error)
	RevokeUserSessions(context.Context, string, SessionRevokedReason) (int64, error)
	RotateRefreshToken(context.Context, RotateRefreshTokenParams) (Session, error)
	CreateOIDCState(context.Context, CreateOIDCStateParams) (OIDCLoginState, error)
	ConsumeOIDCState(context.Context, string) (OIDCLoginState, error)
	CreateOIDCHandoff(context.Context, CreateOIDCHandoffParams) (OIDCLoginHandoff, error)
	ConsumeOIDCHandoff(context.Context, string) (OIDCLoginHandoff, error)
	CreatePasswordReset(context.Context, CreatePasswordResetParams) (PasswordResetToken, error)
	GetActivePasswordResetByHash(context.Context, string) (PasswordResetToken, error)
	ConsumePasswordReset(context.Context, string) (PasswordResetToken, error)
	CreatePassword2FASetup(context.Context, CreatePassword2FASetupParams) (Password2FALoginSetup, error)
	GetActivePassword2FASetupByHash(context.Context, string) (Password2FALoginSetup, error)
	ConsumePassword2FASetup(context.Context, string) (Password2FALoginSetup, error)
}

type UserRepository interface {
	Get(context.Context, string) (users.User, error)
	LookupByNormalizedEmail(context.Context, string) (users.User, error)
	LookupByOIDC(context.Context, string, string) (users.User, error)
	Update(context.Context, string, users.UpdateUserParams) (users.User, error)
}

type AuditRepository interface {
	Append(context.Context, audit.AppendEventParams) (audit.Event, error)
}

type Service struct {
	authRepo  SessionRepository
	userRepo  UserRepository
	auditRepo AuditRepository
	keys      *security.KeySet
	cfg       config.AuthConfig
	tx        storage.Beginner
	http      *http.Client
}

type ServiceConfig struct {
	AuthRepository  SessionRepository
	UserRepository  UserRepository
	AuditRepository AuditRepository
	KeySet          *security.KeySet
	Config          config.AuthConfig
	Storage         storage.Beginner
	HTTPClient      *http.Client
}

type AuditContext struct {
	CorrelationID string
	SourceIP      string
	UserAgent     string
}

type AuthenticatedUser struct {
	User    users.User
	Session Session
}

type Tokens struct {
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
}

type LoginResult struct {
	Status                  string
	User                    users.User
	Tokens                  Tokens
	Password2FASetupToken   string
	Password2FAProvisioning *TOTPProvisioning
}

type PasswordLoginParams struct {
	Email    string
	Password string
	TOTPCode string
	Audit    AuditContext
}

type RefreshResult struct {
	Tokens Tokens
}

type TOTPProvisioning struct {
	Issuer          string
	AccountLabel    string
	Secret          string
	ProvisioningURI string
}

type OIDCLoginStart struct {
	AuthorizationURL string
}

type OIDCCallbackResult struct {
	RedirectURL string
}

type PasswordResetLinkResult struct {
	Email     string
	ExpiresAt time.Time
	ResetURL  string
}

type PasswordResetPreviewResult struct {
	Email     string
	ExpiresAt time.Time
}

type ServiceOption func(*Service)

func NewService(cfg ServiceConfig, opts ...ServiceOption) *Service {
	s := &Service{
		authRepo:  cfg.AuthRepository,
		userRepo:  cfg.UserRepository,
		auditRepo: cfg.AuditRepository,
		keys:      cfg.KeySet,
		cfg:       cfg.Config,
		tx:        cfg.Storage,
		http:      cfg.HTTPClient,
	}
	if s.http == nil {
		s.http = http.DefaultClient
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Service) PasswordLogin(ctx context.Context, params PasswordLoginParams) (LoginResult, error) {
	var result LoginResult
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		var err error
		result, err = txsvc.passwordLogin(ctx, params)
		return err
	})
	return result, err
}

func (s *Service) passwordLogin(ctx context.Context, params PasswordLoginParams) (LoginResult, error) {
	if err := s.ready(); err != nil {
		return LoginResult{}, err
	}
	if !s.cfg.Password.Enabled {
		_ = s.auditSystemFailure(ctx, "user_login_failed", "user", nil, params.Audit, map[string]any{"method": string(AuthMethodPassword), "reason": "password_auth_disabled"})
		return LoginResult{}, ErrPasswordAuthDisabled
	}
	user, lookupErr := s.userRepo.LookupByNormalizedEmail(ctx, params.Email)
	if lookupErr != nil {
		_ = verifyDummyPassword(params.Password)
		_ = s.auditSystemFailure(ctx, "user_login_failed", "user", nil, params.Audit, map[string]any{"method": string(AuthMethodPassword), "reason": "invalid_credentials"})
		return LoginResult{}, ErrInvalidCredentials
	}
	targetID := &user.ID
	if user.Status != users.StatusActive || user.PasswordHash == nil {
		_ = verifyDummyPassword(params.Password)
		_ = s.auditSystemFailure(ctx, "user_login_failed", "user", targetID, params.Audit, map[string]any{"method": string(AuthMethodPassword), "reason": "invalid_credentials"})
		return LoginResult{}, ErrInvalidCredentials
	}
	match, needsRehash, err := security.VerifyPassword(params.Password, *user.PasswordHash)
	if err != nil || !match {
		_ = s.auditSystemFailure(ctx, "user_login_failed", "user", targetID, params.Audit, map[string]any{"method": string(AuthMethodPassword), "reason": "invalid_credentials"})
		return LoginResult{}, ErrInvalidCredentials
	}
	if s.cfg.Password.TwoFARequired && (!user.Password2FAEnabled || user.TOTPSecretEncrypted == nil) {
		result, err := s.startPassword2FARequiredLoginSetup(ctx, user, params.Audit)
		if err != nil {
			return LoginResult{}, err
		}
		if needsRehash {
			hash, err := security.HashPassword(params.Password)
			if err != nil {
				return LoginResult{}, err
			}
			if _, err := s.userRepo.Update(ctx, user.ID, users.UpdateUserParams{PasswordHash: storage.SetString(hash)}); err != nil {
				return LoginResult{}, err
			}
		}
		return result, nil
	}
	if err := s.verifyPasswordTOTP(user, params.TOTPCode); err != nil {
		reason := "invalid_2fa_code"
		if errors.Is(err, ErrPassword2FARequired) {
			reason = "password_2fa_required"
		}
		_ = s.auditSystemFailure(ctx, "user_login_failed", "user", targetID, params.Audit, map[string]any{"method": string(AuthMethodPassword), "reason": reason})
		return LoginResult{}, err
	}
	tokens, session, err := s.createSession(ctx, user.ID, AuthMethodPassword, params.Audit)
	if err != nil {
		return LoginResult{}, err
	}
	update := users.UpdateUserParams{LastLoginAt: storage.SetTime(time.Now().UTC())}
	if needsRehash {
		hash, err := security.HashPassword(params.Password)
		if err != nil {
			return LoginResult{}, err
		}
		update.PasswordHash = storage.SetString(hash)
	}
	updated, err := s.userRepo.Update(ctx, user.ID, update)
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.auditUserEvent(ctx, updated.ID, "user_session_created", "user_session", &session.ID, params.Audit, audit.ResultSuccess, map[string]any{"method": string(AuthMethodPassword)}); err != nil {
		return LoginResult{}, err
	}
	if err := s.auditUserEvent(ctx, updated.ID, "user_login_succeeded", "user", &updated.ID, params.Audit, audit.ResultSuccess, map[string]any{"method": string(AuthMethodPassword)}); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Status: "completed", User: updated, Tokens: tokens}, nil
}

func (s *Service) ValidateUserAccessToken(ctx context.Context, token string) (AuthenticatedUser, error) {
	if err := s.ready(); err != nil {
		return AuthenticatedUser{}, err
	}
	if err := validatePresentedUserAccessToken(token); err != nil {
		return AuthenticatedUser{}, err
	}
	session, err := s.authRepo.GetSessionByAccessTokenHash(ctx, s.keys.HashToken(token))
	if err != nil {
		return AuthenticatedUser{}, ErrInvalidToken
	}
	if session.Status != SessionStatusActive || !session.AccessExpiresAt.After(time.Now().UTC()) {
		return AuthenticatedUser{}, ErrInvalidToken
	}
	user, err := s.userRepo.Get(ctx, session.UserID)
	if err != nil {
		return AuthenticatedUser{}, ErrInvalidToken
	}
	if user.Status != users.StatusActive {
		return AuthenticatedUser{}, ErrUserDisabled
	}
	if err := s.authRepo.MarkSessionUsed(ctx, session.ID); err != nil {
		return AuthenticatedUser{}, err
	}
	return AuthenticatedUser{User: user, Session: session}, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken string, auditCtx AuditContext) (RefreshResult, error) {
	if err := s.ready(); err != nil {
		return RefreshResult{}, err
	}
	if err := validatePresentedRefreshToken(refreshToken); err != nil {
		_ = s.auditSystemFailure(ctx, "user_session_refreshed", "user_session", nil, auditCtx, map[string]any{"reason": "invalid_refresh_token"})
		return RefreshResult{}, ErrInvalidRefreshToken
	}
	accessToken, err := randomPrefixedToken(UserAccessTokenPrefix)
	if err != nil {
		return RefreshResult{}, err
	}
	newRefreshToken, err := randomPrefixedToken(UserRefreshTokenPrefix)
	if err != nil {
		return RefreshResult{}, err
	}
	now := time.Now().UTC()
	accessExpiresAt := now.Add(time.Duration(s.cfg.UserAccessTokenTTLSeconds) * time.Second)
	refreshExpiresAt := now.Add(time.Duration(s.cfg.UserRefreshTokenTTLSeconds) * time.Second)
	params := RotateRefreshTokenParams{
		CurrentRefreshTokenHash: s.keys.HashToken(refreshToken),
		NewAccessTokenHash:      s.keys.HashToken(accessToken),
		NewRefreshTokenHash:     s.keys.HashToken(newRefreshToken),
		AccessExpiresAt:         accessExpiresAt,
		RefreshExpiresAt:        refreshExpiresAt,
	}
	if s.tx != nil {
		return s.refreshWithTx(ctx, params, accessToken, newRefreshToken, accessExpiresAt, refreshExpiresAt, auditCtx)
	}
	session, err := s.authRepo.RotateRefreshToken(ctx, params)
	if err != nil {
		reason := "invalid_refresh_token"
		if errors.Is(err, ErrRefreshTokenExpired) {
			reason = "session_expired"
		}
		if errors.Is(err, ErrRefreshTokenReused) {
			reason = "refresh_reuse"
		}
		_ = s.auditSystemFailure(ctx, "user_session_refreshed", "user_session", nil, auditCtx, map[string]any{"reason": reason})
		if errors.Is(err, ErrRefreshTokenExpired) {
			return RefreshResult{}, ErrSessionExpired
		}
		return RefreshResult{}, ErrInvalidRefreshToken
	}
	user, err := s.userRepo.Get(ctx, session.UserID)
	if err != nil || user.Status != users.StatusActive {
		return RefreshResult{}, ErrInvalidRefreshToken
	}
	if err := s.auditUserEvent(ctx, user.ID, "user_session_refreshed", "user_session", &session.ID, auditCtx, audit.ResultSuccess, map[string]any{}); err != nil {
		return RefreshResult{}, err
	}
	return RefreshResult{Tokens: Tokens{
		AccessToken:      accessToken,
		AccessExpiresAt:  accessExpiresAt,
		RefreshToken:     newRefreshToken,
		RefreshExpiresAt: refreshExpiresAt,
	}}, nil
}

func (s *Service) Logout(ctx context.Context, current AuthenticatedUser, auditCtx AuditContext) error {
	return s.withWriteTx(ctx, func(txsvc *Service) error {
		return txsvc.logout(ctx, current, auditCtx)
	})
}

func (s *Service) logout(ctx context.Context, current AuthenticatedUser, auditCtx AuditContext) error {
	if err := s.ready(); err != nil {
		return err
	}
	revoked, err := s.authRepo.RevokeSession(ctx, current.Session.ID, SessionRevokedLogout)
	if err != nil {
		return err
	}
	if !revoked {
		return ErrInvalidToken
	}
	return s.auditUserEvent(ctx, current.User.ID, "user_session_revoked", "user_session", &current.Session.ID, auditCtx, audit.ResultSuccess, map[string]any{"reason": string(SessionRevokedLogout)})
}

func (s *Service) SetupPassword2FA(ctx context.Context, current AuthenticatedUser, auditCtx AuditContext) (TOTPProvisioning, error) {
	var result TOTPProvisioning
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		var err error
		result, err = txsvc.setupPassword2FA(ctx, current, auditCtx)
		return err
	})
	return result, err
}

func (s *Service) setupPassword2FA(ctx context.Context, current AuthenticatedUser, auditCtx AuditContext) (TOTPProvisioning, error) {
	if err := s.ready(); err != nil {
		return TOTPProvisioning{}, err
	}
	if current.User.Password2FAEnabled || current.User.TOTPSecretEncrypted != nil || current.User.PendingTOTPSecretEncrypted != nil {
		return TOTPProvisioning{}, ErrConflict
	}
	provisioning, encrypted, err := s.newTOTPProvisioning(current.User.ID, current.User.Email)
	if err != nil {
		return TOTPProvisioning{}, err
	}
	_, err = s.userRepo.Update(ctx, current.User.ID, users.UpdateUserParams{
		PendingTOTPSecretEncrypted: storage.SetString(encrypted),
	})
	if err != nil {
		return TOTPProvisioning{}, err
	}
	if err := s.auditUserEvent(ctx, current.User.ID, "password_2fa_setup_started", "user", &current.User.ID, auditCtx, audit.ResultSuccess, map[string]any{}); err != nil {
		return TOTPProvisioning{}, err
	}
	return provisioning, nil
}

func (s *Service) ConfirmPassword2FA(ctx context.Context, current AuthenticatedUser, code string, auditCtx AuditContext) error {
	return s.withWriteTx(ctx, func(txsvc *Service) error {
		return txsvc.confirmPassword2FA(ctx, current, code, auditCtx)
	})
}

func (s *Service) confirmPassword2FA(ctx context.Context, current AuthenticatedUser, code string, auditCtx AuditContext) error {
	if err := s.ready(); err != nil {
		return err
	}
	if current.User.PendingTOTPSecretEncrypted == nil {
		return ErrNotFound
	}
	secret, err := s.keys.DecryptTOTPSecret(*current.User.PendingTOTPSecretEncrypted, totpAAD(current.User.ID))
	if err != nil {
		return err
	}
	if !VerifyTOTP(secret, code, time.Now().UTC()) {
		return ErrInvalid2FACode
	}
	_, err = s.userRepo.Update(ctx, current.User.ID, users.UpdateUserParams{
		TOTPSecretEncrypted:        storage.SetString(*current.User.PendingTOTPSecretEncrypted),
		PendingTOTPSecretEncrypted: storage.ClearString(),
		Password2FAEnabled:         storage.SetBool(true),
	})
	if err != nil {
		return err
	}
	return s.auditUserEvent(ctx, current.User.ID, "password_2fa_enabled", "user", &current.User.ID, auditCtx, audit.ResultSuccess, map[string]any{})
}

func (s *Service) DisablePassword2FA(ctx context.Context, current AuthenticatedUser, password, code string, auditCtx AuditContext) error {
	return s.withWriteTx(ctx, func(txsvc *Service) error {
		return txsvc.disablePassword2FA(ctx, current, password, code, auditCtx)
	})
}

func (s *Service) disablePassword2FA(ctx context.Context, current AuthenticatedUser, password, code string, auditCtx AuditContext) error {
	if err := s.ready(); err != nil {
		return err
	}
	if s.cfg.Password.TwoFARequired && current.User.PasswordHash != nil {
		return ErrPassword2FARequired
	}
	if current.User.TOTPSecretEncrypted == nil || !current.User.Password2FAEnabled {
		return ErrNotFound
	}
	if code != "" {
		secret, err := s.keys.DecryptTOTPSecret(*current.User.TOTPSecretEncrypted, totpAAD(current.User.ID))
		if err != nil {
			return err
		}
		if !VerifyTOTP(secret, code, time.Now().UTC()) {
			return ErrInvalid2FACode
		}
	} else if password != "" && current.User.PasswordHash != nil {
		match, _, err := security.VerifyPassword(password, *current.User.PasswordHash)
		if err != nil || !match {
			return ErrInvalidCredentials
		}
	} else {
		return ErrInvalidCredentials
	}
	_, err := s.userRepo.Update(ctx, current.User.ID, users.UpdateUserParams{
		Password2FAEnabled:         storage.SetBool(false),
		TOTPSecretEncrypted:        storage.ClearString(),
		PendingTOTPSecretEncrypted: storage.ClearString(),
	})
	if err != nil {
		return err
	}
	return s.auditUserEvent(ctx, current.User.ID, "password_2fa_disabled", "user", &current.User.ID, auditCtx, audit.ResultSuccess, map[string]any{})
}

func (s *Service) AdminCreatePasswordResetLink(ctx context.Context, current AuthenticatedUser, userID string, resetURL func(string) string, auditCtx AuditContext) (PasswordResetLinkResult, error) {
	var result PasswordResetLinkResult
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		var err error
		result, err = txsvc.adminCreatePasswordResetLink(ctx, current, userID, resetURL, auditCtx)
		return err
	})
	return result, err
}

func (s *Service) adminCreatePasswordResetLink(ctx context.Context, current AuthenticatedUser, userID string, resetURL func(string) string, auditCtx AuditContext) (PasswordResetLinkResult, error) {
	if err := s.ready(); err != nil {
		return PasswordResetLinkResult{}, err
	}
	if current.User.GlobalRole != users.GlobalRoleAdmin {
		return PasswordResetLinkResult{}, ErrForbidden
	}
	target, err := s.userRepo.Get(ctx, userID)
	if err != nil {
		return PasswordResetLinkResult{}, ErrNotFound
	}
	token, err := randomPrefixedToken(PasswordResetPrefix)
	if err != nil {
		return PasswordResetLinkResult{}, err
	}
	expiresAt := time.Now().UTC().Add(s.passwordResetTTL())
	reset, err := s.authRepo.CreatePasswordReset(ctx, CreatePasswordResetParams{
		UserID:          target.ID,
		TokenHash:       s.keys.HashToken(token),
		CreatedByUserID: current.User.ID,
		ExpiresAt:       expiresAt,
	})
	if err != nil {
		return PasswordResetLinkResult{}, err
	}
	if err := s.auditUserEvent(ctx, current.User.ID, "password_reset_link_created", "user", &target.ID, auditCtx, audit.ResultSuccess, map[string]any{"email": target.Email}); err != nil {
		return PasswordResetLinkResult{}, err
	}
	rawURL := token
	if resetURL != nil {
		rawURL = resetURL(token)
	}
	return PasswordResetLinkResult{Email: target.Email, ExpiresAt: reset.ExpiresAt, ResetURL: rawURL}, nil
}

func (s *Service) PreviewPasswordReset(ctx context.Context, token string) (PasswordResetPreviewResult, error) {
	if err := s.ready(); err != nil {
		return PasswordResetPreviewResult{}, err
	}
	if err := validatePresentedPasswordResetToken(token); err != nil {
		return PasswordResetPreviewResult{}, ErrInvalidPasswordReset
	}
	reset, err := s.authRepo.GetActivePasswordResetByHash(ctx, s.keys.HashToken(token))
	if err != nil {
		return PasswordResetPreviewResult{}, ErrInvalidPasswordReset
	}
	user, err := s.userRepo.Get(ctx, reset.UserID)
	if err != nil {
		return PasswordResetPreviewResult{}, ErrInvalidPasswordReset
	}
	return PasswordResetPreviewResult{Email: user.Email, ExpiresAt: reset.ExpiresAt}, nil
}

func (s *Service) CompletePasswordReset(ctx context.Context, token, password string, auditCtx AuditContext) error {
	return s.withWriteTx(ctx, func(txsvc *Service) error {
		return txsvc.completePasswordReset(ctx, token, password, auditCtx)
	})
}

func (s *Service) completePasswordReset(ctx context.Context, token, password string, auditCtx AuditContext) error {
	if err := s.ready(); err != nil {
		return err
	}
	if err := validatePresentedPasswordResetToken(token); err != nil {
		return ErrInvalidPasswordReset
	}
	tokenHash := s.keys.HashToken(token)
	reset, err := s.authRepo.GetActivePasswordResetByHash(ctx, tokenHash)
	if err != nil {
		return ErrInvalidPasswordReset
	}
	user, err := s.userRepo.Get(ctx, reset.UserID)
	if err != nil {
		return ErrInvalidPasswordReset
	}
	if err := security.ValidatePasswordPolicy(password, user.Email); err != nil {
		return ErrInvalidRequest
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return err
	}
	consumed, err := s.authRepo.ConsumePasswordReset(ctx, tokenHash)
	if err != nil || consumed.ID != reset.ID {
		return ErrInvalidPasswordReset
	}
	updated, err := s.userRepo.Update(ctx, user.ID, users.UpdateUserParams{PasswordHash: storage.SetString(hash)})
	if err != nil {
		return err
	}
	if _, err := s.authRepo.RevokeUserSessions(ctx, updated.ID, SessionRevokedPasswordReset); err != nil {
		return err
	}
	return s.auditUserEvent(ctx, updated.ID, "password_reset_completed", "user", &updated.ID, auditCtx, audit.ResultSuccess, map[string]any{})
}

func (s *Service) AdminResetPassword2FA(ctx context.Context, current AuthenticatedUser, userID string, auditCtx AuditContext) (users.User, error) {
	var result users.User
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		var err error
		result, err = txsvc.adminResetPassword2FA(ctx, current, userID, auditCtx)
		return err
	})
	return result, err
}

func (s *Service) adminResetPassword2FA(ctx context.Context, current AuthenticatedUser, userID string, auditCtx AuditContext) (users.User, error) {
	if err := s.ready(); err != nil {
		return users.User{}, err
	}
	if current.User.GlobalRole != users.GlobalRoleAdmin {
		return users.User{}, ErrForbidden
	}
	target, err := s.userRepo.Get(ctx, userID)
	if err != nil {
		return users.User{}, ErrNotFound
	}
	updated, err := s.userRepo.Update(ctx, target.ID, users.UpdateUserParams{
		Password2FAEnabled:         storage.SetBool(false),
		TOTPSecretEncrypted:        storage.ClearString(),
		PendingTOTPSecretEncrypted: storage.ClearString(),
	})
	if err != nil {
		return users.User{}, err
	}
	if _, err := s.authRepo.RevokeUserSessions(ctx, updated.ID, SessionRevokedPassword2FAReset); err != nil {
		return users.User{}, err
	}
	if err := s.auditUserEvent(ctx, current.User.ID, "password_2fa_reset", "user", &updated.ID, auditCtx, audit.ResultSuccess, map[string]any{}); err != nil {
		return users.User{}, err
	}
	return updated, nil
}

func (s *Service) ConfirmPassword2FALoginSetup(ctx context.Context, setupToken, code string, auditCtx AuditContext) (LoginResult, error) {
	var result LoginResult
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		var err error
		result, err = txsvc.confirmPassword2FALoginSetup(ctx, setupToken, code, auditCtx)
		return err
	})
	return result, err
}

func (s *Service) confirmPassword2FALoginSetup(ctx context.Context, setupToken, code string, auditCtx AuditContext) (LoginResult, error) {
	if err := s.ready(); err != nil {
		return LoginResult{}, err
	}
	if err := validatePresentedPassword2FASetupToken(setupToken); err != nil {
		return LoginResult{}, ErrInvalidToken
	}
	setupHash := s.keys.HashToken(setupToken)
	setup, err := s.authRepo.GetActivePassword2FASetupByHash(ctx, setupHash)
	if err != nil {
		return LoginResult{}, ErrInvalidToken
	}
	user, err := s.userRepo.Get(ctx, setup.UserID)
	if err != nil || user.Status != users.StatusActive {
		return LoginResult{}, ErrUserDisabled
	}
	secret, err := s.keys.DecryptTOTPSecret(setup.PendingTOTPSecretEncrypted, totpAAD(user.ID))
	if err != nil {
		return LoginResult{}, err
	}
	if !VerifyTOTP(secret, code, time.Now().UTC()) {
		return LoginResult{}, ErrInvalid2FACode
	}
	if _, err := s.authRepo.ConsumePassword2FASetup(ctx, setupHash); err != nil {
		return LoginResult{}, ErrInvalidToken
	}
	tokens, session, err := s.createSession(ctx, user.ID, AuthMethodPassword, auditCtx)
	if err != nil {
		return LoginResult{}, err
	}
	updated, err := s.userRepo.Update(ctx, user.ID, users.UpdateUserParams{
		TOTPSecretEncrypted:        storage.SetString(setup.PendingTOTPSecretEncrypted),
		PendingTOTPSecretEncrypted: storage.ClearString(),
		Password2FAEnabled:         storage.SetBool(true),
		LastLoginAt:                storage.SetTime(time.Now().UTC()),
	})
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.auditUserEvent(ctx, updated.ID, "password_2fa_login_setup_completed", "user", &updated.ID, auditCtx, audit.ResultSuccess, map[string]any{}); err != nil {
		return LoginResult{}, err
	}
	if err := s.auditUserEvent(ctx, updated.ID, "user_session_created", "user_session", &session.ID, auditCtx, audit.ResultSuccess, map[string]any{"method": string(AuthMethodPassword)}); err != nil {
		return LoginResult{}, err
	}
	if err := s.auditUserEvent(ctx, updated.ID, "user_login_succeeded", "user", &updated.ID, auditCtx, audit.ResultSuccess, map[string]any{"method": string(AuthMethodPassword), "phase": "password_2fa_setup"}); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Status: "completed", User: updated, Tokens: tokens}, nil
}

func (s *Service) StartOIDCLogin(ctx context.Context, returnURL string, auditCtx AuditContext) (OIDCLoginStart, error) {
	if err := s.ready(); err != nil {
		return OIDCLoginStart{}, err
	}
	if !s.cfg.OIDC.Enabled {
		return OIDCLoginStart{}, ErrOIDCDisabled
	}
	frontendReturnURL, err := s.normalizeReturnURL(returnURL)
	if err != nil {
		return OIDCLoginStart{}, err
	}
	discovery, err := s.fetchOIDCDiscovery(ctx)
	if err != nil {
		return OIDCLoginStart{}, err
	}
	state, err := randomPrefixedBytes(oidcStatePrefix, oidcStateSecretBytes)
	if err != nil {
		return OIDCLoginStart{}, err
	}
	nonce, err := randomBase64URL(tokenSecretBytes)
	if err != nil {
		return OIDCLoginStart{}, err
	}
	codeVerifier, err := randomBase64URL(tokenSecretBytes)
	if err != nil {
		return OIDCLoginStart{}, err
	}
	stateID, err := storage.NewUUID()
	if err != nil {
		return OIDCLoginStart{}, err
	}
	encryptedVerifier, err := s.keys.SealDatabaseValue([]byte(codeVerifier), oidcVerifierAAD(stateID))
	if err != nil {
		return OIDCLoginStart{}, err
	}
	expiresAt := time.Now().UTC().Add(oidcLoginStateTTL)
	_, err = s.authRepo.CreateOIDCState(ctx, CreateOIDCStateParams{
		ID:                    stateID,
		StateHash:             s.keys.HashOIDCState(state),
		Nonce:                 nonce,
		CodeVerifierEncrypted: encryptedVerifier,
		ProviderCallbackURL:   s.cfg.OIDC.RedirectURL,
		FrontendReturnURL:     frontendReturnURL,
		ExpiresAt:             expiresAt,
		SourceIP:              optionalString(auditCtx.SourceIP),
		UserAgent:             optionalString(auditCtx.UserAgent),
	})
	if err != nil {
		return OIDCLoginStart{}, err
	}
	return OIDCLoginStart{AuthorizationURL: s.authorizationURL(discovery.AuthorizationEndpoint, state, nonce, codeVerifier)}, nil
}

func (s *Service) CompleteOIDCCallback(ctx context.Context, code, state string, auditCtx AuditContext) (OIDCCallbackResult, error) {
	if err := s.ready(); err != nil {
		return OIDCCallbackResult{}, err
	}
	if !s.cfg.OIDC.Enabled {
		return OIDCCallbackResult{}, ErrOIDCDisabled
	}
	if code == "" || state == "" {
		return OIDCCallbackResult{}, ErrOIDCValidationFailed
	}
	handoffID, err := randomPrefixedToken(OIDCHandoffPrefix)
	if err != nil {
		return OIDCCallbackResult{}, err
	}
	var frontendReturnURL *string
	if err := s.withWriteTx(ctx, func(txsvc *Service) error {
		loginState, err := txsvc.authRepo.ConsumeOIDCState(ctx, txsvc.keys.HashOIDCState(state))
		if err != nil {
			_ = s.auditSystemFailure(ctx, "user_login_failed", "user", nil, auditCtx, map[string]any{"method": string(AuthMethodOIDC), "reason": "invalid_oidc_state"})
			return ErrOIDCValidationFailed
		}
		verifier, err := txsvc.keys.OpenDatabaseValue(loginState.CodeVerifierEncrypted, oidcVerifierAAD(loginState.ID))
		if err != nil {
			_ = s.auditSystemFailure(ctx, "user_login_failed", "user", nil, auditCtx, map[string]any{"method": string(AuthMethodOIDC), "reason": "invalid_code_verifier"})
			return ErrOIDCValidationFailed
		}
		claims, err := txsvc.validateOIDCCode(ctx, code, string(verifier), loginState.Nonce)
		if err != nil {
			_ = s.auditSystemFailure(ctx, "user_login_failed", "user", nil, auditCtx, map[string]any{"method": string(AuthMethodOIDC), "reason": "oidc_validation_failed"})
			return ErrOIDCValidationFailed
		}
		user, linked, err := txsvc.resolveOIDCUser(ctx, claims)
		if err != nil {
			reason := "user_not_provisioned"
			if errors.Is(err, ErrOIDCValidationFailed) {
				reason = "oidc_email_mismatch"
			}
			var targetID *string
			if user.ID != "" {
				targetID = &user.ID
			}
			_ = s.auditSystemFailure(ctx, "user_login_failed", "user", targetID, auditCtx, map[string]any{"method": string(AuthMethodOIDC), "reason": reason})
			return err
		}
		if linked {
			if err := txsvc.auditUserEvent(ctx, user.ID, "user_updated", "user", &user.ID, auditCtx, audit.ResultSuccess, map[string]any{"oidc_linked": true}); err != nil {
				return err
			}
		}
		if user.Status != users.StatusActive {
			_ = s.auditSystemFailure(ctx, "user_login_failed", "user", &user.ID, auditCtx, map[string]any{"method": string(AuthMethodOIDC), "reason": "user_not_provisioned"})
			return ErrOIDCUserNotProvisioned
		}
		if _, err := txsvc.authRepo.CreateOIDCHandoff(ctx, CreateOIDCHandoffParams{
			HandoffHash:       txsvc.keys.HashToken(handoffID),
			UserID:            user.ID,
			OIDCLoginStateID:  &loginState.ID,
			FrontendReturnURL: loginState.FrontendReturnURL,
			ExpiresAt:         time.Now().UTC().Add(oidcHandoffTTL),
			SourceIP:          optionalString(auditCtx.SourceIP),
			UserAgent:         optionalString(auditCtx.UserAgent),
		}); err != nil {
			return err
		}
		if err := txsvc.auditUserEvent(ctx, user.ID, "user_login_succeeded", "user", &user.ID, auditCtx, audit.ResultSuccess, map[string]any{"method": string(AuthMethodOIDC), "phase": "callback"}); err != nil {
			return err
		}
		frontendReturnURL = loginState.FrontendReturnURL
		return nil
	}); err != nil {
		return OIDCCallbackResult{}, err
	}
	redirectURL, err := appendHandoffID(s.callbackReturnURL(frontendReturnURL), handoffID)
	if err != nil {
		return OIDCCallbackResult{}, err
	}
	return OIDCCallbackResult{RedirectURL: redirectURL}, nil
}

func (s *Service) ExchangeOIDCHandoff(ctx context.Context, handoffID string, auditCtx AuditContext) (LoginResult, error) {
	var result LoginResult
	err := s.withWriteTx(ctx, func(txsvc *Service) error {
		var err error
		result, err = txsvc.exchangeOIDCHandoff(ctx, handoffID, auditCtx)
		return err
	})
	if err != nil && s.tx != nil && errors.Is(err, ErrInvalidCredentials) {
		_ = s.auditSystemFailure(ctx, "user_login_failed", "user", nil, auditCtx, map[string]any{"method": string(AuthMethodOIDC), "reason": "invalid_handoff"})
	}
	return result, err
}

func (s *Service) exchangeOIDCHandoff(ctx context.Context, handoffID string, auditCtx AuditContext) (LoginResult, error) {
	if err := s.ready(); err != nil {
		return LoginResult{}, err
	}
	if !s.cfg.OIDC.Enabled {
		return LoginResult{}, ErrOIDCDisabled
	}
	if !strings.HasPrefix(handoffID, OIDCHandoffPrefix) {
		return LoginResult{}, ErrInvalidCredentials
	}
	handoff, err := s.authRepo.ConsumeOIDCHandoff(ctx, s.keys.HashToken(handoffID))
	if err != nil {
		_ = s.auditSystemFailure(ctx, "user_login_failed", "user", nil, auditCtx, map[string]any{"method": string(AuthMethodOIDC), "reason": "invalid_handoff"})
		return LoginResult{}, ErrInvalidCredentials
	}
	user, err := s.userRepo.Get(ctx, handoff.UserID)
	if err != nil || user.Status != users.StatusActive {
		return LoginResult{}, ErrUserDisabled
	}
	tokens, session, err := s.createSession(ctx, user.ID, AuthMethodOIDC, auditCtx)
	if err != nil {
		return LoginResult{}, err
	}
	updated, err := s.userRepo.Update(ctx, user.ID, users.UpdateUserParams{LastLoginAt: storage.SetTime(time.Now().UTC())})
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.auditUserEvent(ctx, updated.ID, "user_session_created", "user_session", &session.ID, auditCtx, audit.ResultSuccess, map[string]any{"method": string(AuthMethodOIDC)}); err != nil {
		return LoginResult{}, err
	}
	if err := s.auditUserEvent(ctx, updated.ID, "user_login_succeeded", "user", &updated.ID, auditCtx, audit.ResultSuccess, map[string]any{"method": string(AuthMethodOIDC), "phase": "handoff"}); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Status: "completed", User: updated, Tokens: tokens}, nil
}

func (s *Service) resolveOIDCUser(ctx context.Context, claims oidcClaims) (users.User, bool, error) {
	issuer := claims.Issuer
	user, err := s.userRepo.LookupByOIDC(ctx, issuer, claims.Subject)
	if err == nil {
		if claims.Email != "" && !strings.EqualFold(claims.Email, user.Email) {
			return user, false, ErrOIDCValidationFailed
		}
		return user, false, nil
	}
	if !errors.Is(err, storage.ErrNoRows) {
		return users.User{}, false, err
	}
	if claims.Email == "" || !claims.EmailVerified {
		return users.User{}, false, ErrOIDCUserNotProvisioned
	}
	user, err = s.userRepo.LookupByNormalizedEmail(ctx, claims.Email)
	if err != nil || user.Status != users.StatusActive {
		return users.User{}, false, ErrOIDCUserNotProvisioned
	}
	if user.OIDCIssuer != nil || user.OIDCSubject != nil {
		return user, false, ErrOIDCUserNotProvisioned
	}
	updated, err := s.userRepo.Update(ctx, user.ID, users.UpdateUserParams{
		OIDCIssuer:  storage.SetString(issuer),
		OIDCSubject: storage.SetString(claims.Subject),
	})
	if err != nil {
		return user, false, ErrOIDCUserNotProvisioned
	}
	return updated, true, nil
}

func (s *Service) createSession(ctx context.Context, userID string, method AuthMethod, auditCtx AuditContext) (Tokens, Session, error) {
	accessToken, err := randomPrefixedToken(UserAccessTokenPrefix)
	if err != nil {
		return Tokens{}, Session{}, err
	}
	refreshToken, err := randomPrefixedToken(UserRefreshTokenPrefix)
	if err != nil {
		return Tokens{}, Session{}, err
	}
	now := time.Now().UTC()
	tokens := Tokens{
		AccessToken:      accessToken,
		AccessExpiresAt:  now.Add(time.Duration(s.cfg.UserAccessTokenTTLSeconds) * time.Second),
		RefreshToken:     refreshToken,
		RefreshExpiresAt: now.Add(time.Duration(s.cfg.UserRefreshTokenTTLSeconds) * time.Second),
	}
	session, err := s.authRepo.CreateSession(ctx, CreateSessionParams{
		UserID:                userID,
		AuthMethod:            method,
		AccessTokenHash:       s.keys.HashToken(accessToken),
		RefreshTokenHash:      s.keys.HashToken(refreshToken),
		AccessExpiresAt:       tokens.AccessExpiresAt,
		RefreshExpiresAt:      tokens.RefreshExpiresAt,
		UserAgent:             optionalString(auditCtx.UserAgent),
		SourceIP:              optionalString(auditCtx.SourceIP),
		RefreshTokenIssuedAt:  now,
		RefreshTokenExpiresAt: tokens.RefreshExpiresAt,
	})
	if err != nil {
		return Tokens{}, Session{}, err
	}
	return tokens, session, nil
}

func (s *Service) startPassword2FARequiredLoginSetup(ctx context.Context, user users.User, auditCtx AuditContext) (LoginResult, error) {
	setupToken, err := randomPrefixedToken(Password2FASetupPrefix)
	if err != nil {
		return LoginResult{}, err
	}
	provisioning, encrypted, err := s.newTOTPProvisioning(user.ID, user.Email)
	if err != nil {
		return LoginResult{}, err
	}
	setup, err := s.authRepo.CreatePassword2FASetup(ctx, CreatePassword2FASetupParams{
		SetupHash:                  s.keys.HashToken(setupToken),
		UserID:                     user.ID,
		PendingTOTPSecretEncrypted: encrypted,
		ExpiresAt:                  time.Now().UTC().Add(password2FASetupTTL),
		SourceIP:                   optionalString(auditCtx.SourceIP),
		UserAgent:                  optionalString(auditCtx.UserAgent),
	})
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.auditUserEvent(ctx, user.ID, "password_2fa_login_setup_started", "user", &user.ID, auditCtx, audit.ResultSuccess, map[string]any{"expires_at": setup.ExpiresAt}); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		Status:                  "password_2fa_setup_required",
		User:                    user,
		Password2FASetupToken:   setupToken,
		Password2FAProvisioning: &provisioning,
	}, nil
}

func (s *Service) verifyPasswordTOTP(user users.User, code string) error {
	if !user.Password2FAEnabled && !s.cfg.Password.TwoFARequired {
		return nil
	}
	if user.TOTPSecretEncrypted == nil {
		return ErrPassword2FARequired
	}
	if code == "" {
		return ErrPassword2FARequired
	}
	secret, err := s.keys.DecryptTOTPSecret(*user.TOTPSecretEncrypted, totpAAD(user.ID))
	if err != nil {
		return err
	}
	if !VerifyTOTP(secret, code, time.Now().UTC()) {
		return ErrInvalid2FACode
	}
	return nil
}

func (s *Service) newTOTPProvisioning(userID, email string) (TOTPProvisioning, string, error) {
	secret, err := newTOTPSecret()
	if err != nil {
		return TOTPProvisioning{}, "", err
	}
	encrypted, err := s.keys.EncryptTOTPSecret(secret, totpAAD(userID))
	if err != nil {
		return TOTPProvisioning{}, "", err
	}
	provisioning := TOTPProvisioning{
		Issuer:          totpIssuer,
		AccountLabel:    email,
		Secret:          secret,
		ProvisioningURI: provisioningURI(totpIssuer, email, secret),
	}
	return provisioning, encrypted, nil
}

func (s *Service) ready() error {
	if s == nil || s.authRepo == nil || s.userRepo == nil || s.auditRepo == nil || s.keys == nil {
		return ErrIdentityServiceUnavailable
	}
	if s.cfg.UserAccessTokenTTLSeconds <= 0 || s.cfg.UserRefreshTokenTTLSeconds <= s.cfg.UserAccessTokenTTLSeconds {
		return ErrIdentityServiceUnavailable
	}
	return nil
}

func (s *Service) passwordResetTTL() time.Duration {
	if s.cfg.PasswordResetTTLSeconds <= 0 {
		return defaultPasswordResetTTL
	}
	return time.Duration(s.cfg.PasswordResetTTLSeconds) * time.Second
}

func (s *Service) normalizeReturnURL(raw string) (*string, error) {
	if raw == "" {
		return nil, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, ErrForbidden
	}
	for _, allowed := range s.cfg.OIDC.AllowedReturnURLs {
		if raw == allowed {
			return &raw, nil
		}
	}
	if len(s.cfg.OIDC.AllowedReturnURLs) == 0 {
		redirect, err := url.Parse(s.cfg.OIDC.RedirectURL)
		if err != nil {
			return nil, ErrForbidden
		}
		if parsed.Scheme == redirect.Scheme && parsed.Host == redirect.Host {
			return &raw, nil
		}
	}
	return nil, ErrForbidden
}

func (s *Service) callbackReturnURL(stored *string) string {
	if stored != nil && *stored != "" {
		return *stored
	}
	if len(s.cfg.OIDC.AllowedReturnURLs) > 0 {
		return s.cfg.OIDC.AllowedReturnURLs[0]
	}
	return s.cfg.OIDC.RedirectURL
}

func (s *Service) authorizationURL(authorizationEndpoint, state, nonce, codeVerifier string) string {
	u, err := url.Parse(authorizationEndpoint)
	if err != nil {
		return authorizationEndpoint
	}
	u.RawQuery = ""
	u.Fragment = ""
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", s.cfg.OIDC.ClientID)
	q.Set("redirect_uri", s.cfg.OIDC.RedirectURL)
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("nonce", nonce)
	sum := sha256.Sum256([]byte(codeVerifier))
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *Service) refreshWithTx(ctx context.Context, params RotateRefreshTokenParams, accessToken, refreshToken string, accessExpiresAt, refreshExpiresAt time.Time, auditCtx AuditContext) (result RefreshResult, err error) {
	tx, err := s.tx.Begin(ctx)
	if err != nil {
		return RefreshResult{}, err
	}
	commit := false
	defer func() {
		if !commit {
			rollbackTx(ctx, tx)
		}
	}()
	txAuth := NewRepository(tx)
	session, err := txAuth.RotateRefreshToken(ctx, params)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenReused) || errors.Is(err, ErrRefreshTokenExpired) {
			if commitErr := tx.Commit(ctx); commitErr != nil {
				return RefreshResult{}, commitErr
			}
			commit = true
			reason := "invalid_refresh_token"
			if errors.Is(err, ErrRefreshTokenExpired) {
				reason = "session_expired"
			}
			if errors.Is(err, ErrRefreshTokenReused) {
				reason = "refresh_reuse"
			}
			_ = s.auditSystemFailure(ctx, "user_session_refreshed", "user_session", nil, auditCtx, map[string]any{"reason": reason})
			if errors.Is(err, ErrRefreshTokenExpired) {
				return RefreshResult{}, ErrSessionExpired
			}
			return RefreshResult{}, ErrInvalidRefreshToken
		}
		return RefreshResult{}, err
	}
	txUsers := users.NewRepository(tx)
	user, err := txUsers.Get(ctx, session.UserID)
	if err != nil || user.Status != users.StatusActive {
		return RefreshResult{}, ErrInvalidRefreshToken
	}
	txAudit := audit.NewRepository(tx)
	txsvc := *s
	txsvc.authRepo = txAuth
	txsvc.userRepo = txUsers
	txsvc.auditRepo = txAudit
	txsvc.tx = nil
	if err := txsvc.auditUserEvent(ctx, user.ID, "user_session_refreshed", "user_session", &session.ID, auditCtx, audit.ResultSuccess, map[string]any{}); err != nil {
		return RefreshResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RefreshResult{}, err
	}
	commit = true
	return RefreshResult{Tokens: Tokens{
		AccessToken:      accessToken,
		AccessExpiresAt:  accessExpiresAt,
		RefreshToken:     refreshToken,
		RefreshExpiresAt: refreshExpiresAt,
	}}, nil
}

func (s *Service) withWriteTx(ctx context.Context, fn func(*Service) error) error {
	if s.tx == nil {
		return fn(s)
	}
	return storage.WithTx(ctx, s.tx, func(ctx context.Context, tx storage.Tx) error {
		txsvc := *s
		txsvc.authRepo = NewRepository(tx)
		txsvc.userRepo = users.NewRepository(tx)
		txsvc.auditRepo = audit.NewRepository(tx)
		txsvc.tx = nil
		return fn(&txsvc)
	})
}

func rollbackTx(ctx context.Context, tx storage.Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	if rollbackCtx.Err() != nil {
		cancel()
		rollbackCtx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	}
	defer cancel()
	_ = tx.Rollback(rollbackCtx)
}

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type oidcTokenResponse struct {
	IDToken string `json:"id_token"`
}

type oidcJWTHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

type oidcClaims struct {
	Issuer        string          `json:"iss"`
	Subject       string          `json:"sub"`
	Audience      json.RawMessage `json:"aud"`
	Expiry        int64           `json:"exp"`
	NotBefore     int64           `json:"nbf"`
	IssuedAt      int64           `json:"iat"`
	Nonce         string          `json:"nonce"`
	Email         string          `json:"email"`
	EmailVerified bool            `json:"email_verified"`
}

type oidcJWKS struct {
	Keys []oidcJWK `json:"keys"`
}

type oidcJWK struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

func (s *Service) validateOIDCCode(ctx context.Context, code, codeVerifier, nonce string) (oidcClaims, error) {
	discovery, err := s.fetchOIDCDiscovery(ctx)
	if err != nil {
		return oidcClaims{}, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.cfg.OIDC.RedirectURL)
	form.Set("client_id", s.cfg.OIDC.ClientID)
	form.Set("code_verifier", codeVerifier)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, discovery.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return oidcClaims{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return oidcClaims{}, ErrOIDCValidationFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return oidcClaims{}, ErrOIDCValidationFailed
	}
	var tokenResponse oidcTokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tokenResponse); err != nil || tokenResponse.IDToken == "" {
		return oidcClaims{}, ErrOIDCValidationFailed
	}
	claims, err := s.validateIDToken(ctx, tokenResponse.IDToken, discovery, nonce)
	if err != nil {
		return oidcClaims{}, err
	}
	return claims, nil
}

func (s *Service) fetchOIDCDiscovery(ctx context.Context) (oidcDiscovery, error) {
	u := strings.TrimRight(s.cfg.OIDC.IssuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return oidcDiscovery{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return oidcDiscovery{}, ErrOIDCValidationFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return oidcDiscovery{}, ErrOIDCValidationFailed
	}
	var discovery oidcDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&discovery); err != nil {
		return oidcDiscovery{}, ErrOIDCValidationFailed
	}
	if discovery.Issuer != strings.TrimRight(s.cfg.OIDC.IssuerURL, "/") || discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" || discovery.JWKSURI == "" {
		return oidcDiscovery{}, ErrOIDCValidationFailed
	}
	if !isCleanHTTPSURL(discovery.AuthorizationEndpoint) || !isCleanHTTPSURL(discovery.TokenEndpoint) || !isCleanHTTPSURL(discovery.JWKSURI) {
		return oidcDiscovery{}, ErrOIDCValidationFailed
	}
	return discovery, nil
}

func (s *Service) validateIDToken(ctx context.Context, raw string, discovery oidcDiscovery, nonce string) (oidcClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return oidcClaims{}, ErrOIDCValidationFailed
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return oidcClaims{}, ErrOIDCValidationFailed
	}
	var header oidcJWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return oidcClaims{}, ErrOIDCValidationFailed
	}
	if header.Algorithm != "RS256" || header.KeyID == "" {
		return oidcClaims{}, ErrOIDCValidationFailed
	}
	key, err := s.fetchRS256Key(ctx, discovery.JWKSURI, header.KeyID)
	if err != nil {
		return oidcClaims{}, err
	}
	signed := []byte(parts[0] + "." + parts[1])
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return oidcClaims{}, ErrOIDCValidationFailed
	}
	digest := sha256.Sum256(signed)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return oidcClaims{}, ErrOIDCValidationFailed
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return oidcClaims{}, ErrOIDCValidationFailed
	}
	var claims oidcClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return oidcClaims{}, ErrOIDCValidationFailed
	}
	now := time.Now().UTC().Unix()
	if claims.Issuer != discovery.Issuer || claims.Subject == "" || claims.Nonce != nonce || claims.Expiry <= now {
		return oidcClaims{}, ErrOIDCValidationFailed
	}
	if claims.NotBefore != 0 && claims.NotBefore > now+60 {
		return oidcClaims{}, ErrOIDCValidationFailed
	}
	if claims.IssuedAt != 0 && claims.IssuedAt > now+60 {
		return oidcClaims{}, ErrOIDCValidationFailed
	}
	if !claimsHasAudience(claims.Audience, s.cfg.OIDC.ClientID) {
		return oidcClaims{}, ErrOIDCValidationFailed
	}
	return claims, nil
}

func (s *Service) fetchRS256Key(ctx context.Context, jwksURI, keyID string) (*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, ErrOIDCValidationFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, ErrOIDCValidationFailed
	}
	var jwks oidcJWKS
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&jwks); err != nil {
		return nil, ErrOIDCValidationFailed
	}
	for _, key := range jwks.Keys {
		if key.KeyID != keyID || key.KeyType != "RSA" || (key.Use != "" && key.Use != "sig") || (key.Algorithm != "" && key.Algorithm != "RS256") {
			continue
		}
		return rsaPublicKeyFromJWK(key)
	}
	return nil, ErrOIDCValidationFailed
}

func rsaPublicKeyFromJWK(key oidcJWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.Modulus)
	if err != nil || len(nBytes) == 0 {
		return nil, ErrOIDCValidationFailed
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.Exponent)
	if err != nil || len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, ErrOIDCValidationFailed
	}
	var exponent int
	for _, b := range eBytes {
		exponent = exponent<<8 + int(b)
	}
	if exponent < 3 {
		return nil, ErrOIDCValidationFailed
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: exponent}, nil
}

func claimsHasAudience(raw json.RawMessage, clientID string) bool {
	var audience string
	if err := json.Unmarshal(raw, &audience); err == nil {
		return audience == clientID
	}
	var audiences []string
	if err := json.Unmarshal(raw, &audiences); err != nil {
		return false
	}
	for _, value := range audiences {
		if value == clientID {
			return true
		}
	}
	return false
}

func isHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

func isCleanHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

func (s *Service) auditUserEvent(ctx context.Context, userID, action, targetType string, targetID *string, auditCtx AuditContext, result audit.Result, metadata map[string]any) error {
	_, err := s.auditRepo.Append(ctx, audit.AppendEventParams{
		IdentityType:  audit.IdentityTypeUser,
		IdentityID:    &userID,
		Action:        action,
		TargetType:    targetType,
		TargetID:      targetID,
		Result:        result,
		CorrelationID: optionalString(auditCtx.CorrelationID),
		SourceIP:      optionalString(auditCtx.SourceIP),
		Metadata:      metadataJSON(metadata),
	})
	return err
}

func (s *Service) auditSystemFailure(ctx context.Context, action, targetType string, targetID *string, auditCtx AuditContext, metadata map[string]any) error {
	_, err := s.auditRepo.Append(ctx, audit.AppendEventParams{
		IdentityType:  audit.IdentityTypeSystem,
		Action:        action,
		TargetType:    targetType,
		TargetID:      targetID,
		Result:        audit.ResultFailure,
		CorrelationID: optionalString(auditCtx.CorrelationID),
		SourceIP:      optionalString(auditCtx.SourceIP),
		Metadata:      metadataJSON(metadata),
	})
	return err
}

func metadataJSON(metadata map[string]any) json.RawMessage {
	if metadata == nil {
		return json.RawMessage(`{}`)
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return data
}

func validatePresentedUserAccessToken(token string) error {
	switch {
	case strings.HasPrefix(token, UserAccessTokenPrefix):
		if len(token) != len(UserAccessTokenPrefix)+43 {
			return ErrInvalidToken
		}
		return nil
	case strings.HasPrefix(token, UserRefreshTokenPrefix):
		return ErrRefreshTokenNotAllowed
	case strings.HasPrefix(token, "cth_app_v1_"):
		return ErrUserTokenRequired
	default:
		return ErrInvalidToken
	}
}

func validatePresentedRefreshToken(token string) error {
	if !strings.HasPrefix(token, UserRefreshTokenPrefix) || len(token) != len(UserRefreshTokenPrefix)+43 {
		return ErrInvalidRefreshToken
	}
	return nil
}

func validatePresentedPasswordResetToken(token string) error {
	if !strings.HasPrefix(token, PasswordResetPrefix) || len(token) != len(PasswordResetPrefix)+43 {
		return ErrInvalidPasswordReset
	}
	return nil
}

func validatePresentedPassword2FASetupToken(token string) error {
	if !strings.HasPrefix(token, Password2FASetupPrefix) || len(token) != len(Password2FASetupPrefix)+43 {
		return ErrInvalidToken
	}
	return nil
}

func randomPrefixedToken(prefix string) (string, error) {
	secret, err := randomBase64URL(tokenSecretBytes)
	if err != nil {
		return "", err
	}
	return prefix + secret, nil
}

func randomPrefixedBytes(prefix string, n int) (string, error) {
	secret, err := randomBase64URL(n)
	if err != nil {
		return "", err
	}
	return prefix + secret, nil
}

func randomBase64URL(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func totpAAD(userID string) string {
	return "user:" + userID + ":totp_secret"
}

func oidcVerifierAAD(stateID string) string {
	return "oidc_login_state:" + stateID + ":code_verifier"
}

func appendHandoffID(rawURL, handoffID string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("handoff_id", handoffID)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

var dummyPassword struct {
	once sync.Once
	hash string
}

func verifyDummyPassword(password string) error {
	dummyPassword.once.Do(func() {
		hash, err := security.HashPassword("certhub-dummy-password-for-enumeration-resistance")
		if err != nil {
			return
		}
		dummyPassword.hash = hash
	})
	if dummyPassword.hash == "" {
		return nil
	}
	_, _, err := security.VerifyPassword(password, dummyPassword.hash)
	return err
}

func newTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}
