package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/torob/certhub/internal/storage"
)

const rollbackTimeout = 5 * time.Second

var (
	ErrRefreshTokenReused  = errors.New("refresh token was already used")
	ErrRefreshTokenExpired = errors.New("refresh token expired")
	ErrSessionInactive     = errors.New("session is not active")
)

type AuthMethod string

const (
	AuthMethodPassword AuthMethod = "password"
	AuthMethodOIDC     AuthMethod = "oidc"
)

type SessionStatus string

const (
	SessionStatusActive  SessionStatus = "active"
	SessionStatusRevoked SessionStatus = "revoked"
)

type SessionRevokedReason string

const (
	SessionRevokedLogout           SessionRevokedReason = "logout"
	SessionRevokedDisabledUser     SessionRevokedReason = "disabled_user"
	SessionRevokedRefreshReuse     SessionRevokedReason = "refresh_reuse"
	SessionRevokedAdminAction      SessionRevokedReason = "admin_action"
	SessionRevokedExpired          SessionRevokedReason = "expired"
	SessionRevokedPasswordReset    SessionRevokedReason = "password_reset"
	SessionRevokedPassword2FAReset SessionRevokedReason = "password_2fa_reset"
)

type RefreshTokenStatus string

const (
	RefreshTokenStatusActive  RefreshTokenStatus = "active"
	RefreshTokenStatusRotated RefreshTokenStatus = "rotated"
	RefreshTokenStatusRevoked RefreshTokenStatus = "revoked"
	RefreshTokenStatusReused  RefreshTokenStatus = "reused"
	RefreshTokenStatusExpired RefreshTokenStatus = "expired"
)

type HandoffStatus string

const (
	HandoffStatusActive   HandoffStatus = "active"
	HandoffStatusConsumed HandoffStatus = "consumed"
	HandoffStatusExpired  HandoffStatus = "expired"
)

type OneTimeTokenStatus string

const (
	OneTimeTokenStatusActive     OneTimeTokenStatus = "active"
	OneTimeTokenStatusConsumed   OneTimeTokenStatus = "consumed"
	OneTimeTokenStatusExpired    OneTimeTokenStatus = "expired"
	OneTimeTokenStatusSuperseded OneTimeTokenStatus = "superseded"
)

type Session struct {
	ID               string
	UserID           string
	AuthMethod       AuthMethod
	AccessTokenHash  string
	RefreshTokenHash string
	Status           SessionStatus
	CreatedAt        time.Time
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	LastRefreshedAt  *time.Time
	LastUsedAt       *time.Time
	RevokedAt        *time.Time
	RevokedReason    *SessionRevokedReason
	UserAgent        *string
	SourceIP         *string
}

type RefreshToken struct {
	ID               string
	UserSessionID    string
	RefreshTokenHash string
	Status           RefreshTokenStatus
	IssuedAt         time.Time
	ExpiresAt        time.Time
	RotatedAt        *time.Time
	LastSeenAt       *time.Time
}

type OIDCLoginState struct {
	ID                    string
	StateHash             string
	Nonce                 string
	CodeVerifierEncrypted string
	ProviderCallbackURL   string
	FrontendReturnURL     *string
	ExpiresAt             time.Time
	ConsumedAt            *time.Time
	CreatedAt             time.Time
	SourceIP              *string
	UserAgent             *string
}

type OIDCLoginHandoff struct {
	ID                string
	HandoffHash       string
	UserID            string
	OIDCLoginStateID  *string
	FrontendReturnURL *string
	Status            HandoffStatus
	CreatedAt         time.Time
	ExpiresAt         time.Time
	ConsumedAt        *time.Time
	SourceIP          *string
	UserAgent         *string
}

type PasswordResetToken struct {
	ID              string
	UserID          string
	TokenHash       string
	Status          OneTimeTokenStatus
	CreatedByUserID string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	ConsumedAt      *time.Time
}

type Password2FALoginSetup struct {
	ID                         string
	SetupHash                  string
	UserID                     string
	PendingTOTPSecretEncrypted string
	Status                     OneTimeTokenStatus
	CreatedAt                  time.Time
	ExpiresAt                  time.Time
	ConsumedAt                 *time.Time
	SourceIP                   *string
	UserAgent                  *string
}

type Repository struct {
	db storage.DBTX
}

func NewRepository(db storage.DBTX) Repository {
	return Repository{db: db}
}

type CreateSessionParams struct {
	ID                    string
	RefreshHistoryID      string
	UserID                string
	AuthMethod            AuthMethod
	AccessTokenHash       string
	RefreshTokenHash      string
	AccessExpiresAt       time.Time
	RefreshExpiresAt      time.Time
	UserAgent             *string
	SourceIP              *string
	RefreshTokenIssuedAt  time.Time
	RefreshTokenExpiresAt time.Time
}

type RotateRefreshTokenParams struct {
	CurrentRefreshTokenHash string
	NewAccessTokenHash      string
	NewRefreshTokenHash     string
	AccessExpiresAt         time.Time
	RefreshExpiresAt        time.Time
}

type CreateOIDCStateParams struct {
	ID                    string
	StateHash             string
	Nonce                 string
	CodeVerifierEncrypted string
	ProviderCallbackURL   string
	FrontendReturnURL     *string
	ExpiresAt             time.Time
	SourceIP              *string
	UserAgent             *string
}

type CreateOIDCHandoffParams struct {
	ID                string
	HandoffHash       string
	UserID            string
	OIDCLoginStateID  *string
	FrontendReturnURL *string
	ExpiresAt         time.Time
	SourceIP          *string
	UserAgent         *string
}

type CreatePasswordResetParams struct {
	ID              string
	UserID          string
	TokenHash       string
	CreatedByUserID string
	ExpiresAt       time.Time
}

type CreatePassword2FASetupParams struct {
	ID                         string
	SetupHash                  string
	UserID                     string
	PendingTOTPSecretEncrypted string
	ExpiresAt                  time.Time
	SourceIP                   *string
	UserAgent                  *string
}

func (r Repository) CreateSession(ctx context.Context, params CreateSessionParams) (Session, error) {
	beginner, ok := r.db.(storage.Beginner)
	if !ok {
		return CreateSessionTx(ctx, r.db, params)
	}
	var session Session
	err := storage.WithTx(ctx, beginner, func(ctx context.Context, tx storage.Tx) error {
		var err error
		session, err = CreateSessionTx(ctx, tx, params)
		return err
	})
	if err != nil {
		return Session{}, err
	}
	return session, nil
}

func CreateSessionTx(ctx context.Context, db storage.DBTX, params CreateSessionParams) (Session, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return Session{}, err
		}
		params.ID = id
	}
	if params.RefreshHistoryID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return Session{}, err
		}
		params.RefreshHistoryID = id
	}
	if params.RefreshTokenIssuedAt.IsZero() {
		params.RefreshTokenIssuedAt = time.Now().UTC()
	}
	if params.RefreshTokenExpiresAt.IsZero() {
		params.RefreshTokenExpiresAt = params.RefreshExpiresAt
	}
	if err := validateCreateSession(params); err != nil {
		return Session{}, err
	}
	session, err := scanSession(db.QueryRow(ctx, `
insert into user_sessions (
    id, user_id, auth_method, access_token_hash, refresh_token_hash,
    access_expires_at, refresh_expires_at, user_agent, source_ip
) values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
returning id, user_id, auth_method, access_token_hash, refresh_token_hash,
    status, created_at, access_expires_at, refresh_expires_at,
    last_refreshed_at, last_used_at, revoked_at, revoked_reason, user_agent, source_ip`,
		params.ID, params.UserID, string(params.AuthMethod), params.AccessTokenHash, params.RefreshTokenHash,
		params.AccessExpiresAt, params.RefreshExpiresAt, params.UserAgent, params.SourceIP))
	if err != nil {
		return Session{}, fmt.Errorf("create user session: %w", err)
	}
	_, err = db.Exec(ctx, `
insert into user_session_refresh_tokens (
    id, user_session_id, refresh_token_hash, status, issued_at, expires_at
) values ($1, $2, $3, 'active', $4, $5)`,
		params.RefreshHistoryID, params.ID, params.RefreshTokenHash, params.RefreshTokenIssuedAt, params.RefreshTokenExpiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("create refresh token history: %w", err)
	}
	return session, nil
}

func (r Repository) GetSessionByAccessTokenHash(ctx context.Context, accessTokenHash string) (Session, error) {
	if err := storage.ValidateTokenHash(accessTokenHash, "access_token_hash"); err != nil {
		return Session{}, err
	}
	session, err := scanSession(r.db.QueryRow(ctx, sessionSelectSQL()+` where access_token_hash = $1`, accessTokenHash))
	if err != nil {
		return Session{}, fmt.Errorf("get user session: %w", err)
	}
	return session, nil
}

func (r Repository) MarkSessionUsed(ctx context.Context, sessionID string) error {
	if err := storage.ValidateUUID(sessionID, "session_id"); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx, `
update user_sessions
set last_used_at = now()
where id = $1
  and status = 'active'`, sessionID)
	if err != nil {
		return fmt.Errorf("mark user session used: %w", err)
	}
	return nil
}

func (r Repository) RevokeSession(ctx context.Context, sessionID string, reason SessionRevokedReason) (bool, error) {
	if err := storage.ValidateUUID(sessionID, "session_id"); err != nil {
		return false, err
	}
	if err := validateRevokedReason(reason); err != nil {
		return false, err
	}
	tag, err := r.db.Exec(ctx, `
update user_sessions
set status = 'revoked',
    revoked_at = coalesce(revoked_at, now()),
    revoked_reason = coalesce(revoked_reason, $2)
where id = $1
  and status = 'active'`, sessionID, string(reason))
	if err != nil {
		return false, fmt.Errorf("revoke user session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	_, err = r.db.Exec(ctx, `
update user_session_refresh_tokens
set status = case when status = 'active' then 'revoked' else status end,
    last_seen_at = coalesce(last_seen_at, now())
where user_session_id = $1
  and status = 'active'`, sessionID)
	if err != nil {
		return false, fmt.Errorf("revoke refresh token history: %w", err)
	}
	return true, nil
}

func (r Repository) RevokeUserSessions(ctx context.Context, userID string, reason SessionRevokedReason) (int64, error) {
	if err := storage.ValidateUUID(userID, "user_id"); err != nil {
		return 0, err
	}
	if err := validateRevokedReason(reason); err != nil {
		return 0, err
	}
	rows, err := r.db.Query(ctx, `
update user_sessions
set status = 'revoked',
    revoked_at = coalesce(revoked_at, now()),
    revoked_reason = coalesce(revoked_reason, $2)
where user_id = $1
  and status = 'active'
returning id`, userID, string(reason))
	if err != nil {
		return 0, fmt.Errorf("revoke user sessions: %w", err)
	}
	defer rows.Close()
	var sessionIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, fmt.Errorf("revoke user sessions: %w", err)
		}
		sessionIDs = append(sessionIDs, id)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("revoke user sessions: %w", err)
	}
	if len(sessionIDs) == 0 {
		return 0, nil
	}
	for _, id := range sessionIDs {
		if _, err := r.db.Exec(ctx, `
update user_session_refresh_tokens
set status = case when status = 'active' then 'revoked' else status end,
    last_seen_at = coalesce(last_seen_at, now())
where user_session_id = $1
  and status = 'active'`, id); err != nil {
			return 0, fmt.Errorf("revoke user refresh token history: %w", err)
		}
	}
	return int64(len(sessionIDs)), nil
}

func (r Repository) CreatePasswordReset(ctx context.Context, params CreatePasswordResetParams) (PasswordResetToken, error) {
	beginner, ok := r.db.(storage.Beginner)
	if !ok {
		return CreatePasswordResetTx(ctx, r.db, params)
	}
	var token PasswordResetToken
	err := storage.WithTx(ctx, beginner, func(ctx context.Context, tx storage.Tx) error {
		var err error
		token, err = CreatePasswordResetTx(ctx, tx, params)
		return err
	})
	return token, err
}

func CreatePasswordResetTx(ctx context.Context, db storage.DBTX, params CreatePasswordResetParams) (PasswordResetToken, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return PasswordResetToken{}, err
		}
		params.ID = id
	}
	if err := validateCreatePasswordReset(params); err != nil {
		return PasswordResetToken{}, err
	}
	if _, err := db.Exec(ctx, `
update user_password_reset_tokens
set status = 'superseded'
where user_id = $1
  and status = 'active'`, params.UserID); err != nil {
		return PasswordResetToken{}, fmt.Errorf("supersede password reset tokens: %w", err)
	}
	token, err := scanPasswordReset(db.QueryRow(ctx, `
insert into user_password_reset_tokens (
    id, user_id, token_hash, created_by_user_id, expires_at
) values ($1, $2, $3, $4, $5)
returning id, user_id, token_hash, status, created_by_user_id, created_at, expires_at, consumed_at`,
		params.ID, params.UserID, params.TokenHash, params.CreatedByUserID, params.ExpiresAt))
	if err != nil {
		return PasswordResetToken{}, fmt.Errorf("create password reset token: %w", err)
	}
	return token, nil
}

func (r Repository) GetActivePasswordResetByHash(ctx context.Context, tokenHash string) (PasswordResetToken, error) {
	if err := storage.ValidateTokenHash(tokenHash, "token_hash"); err != nil {
		return PasswordResetToken{}, err
	}
	token, err := scanPasswordReset(r.db.QueryRow(ctx, passwordResetSelectSQL()+`
where token_hash = $1
  and status = 'active'
  and expires_at > now()`, tokenHash))
	if err != nil {
		return PasswordResetToken{}, fmt.Errorf("get password reset token: %w", err)
	}
	return token, nil
}

func (r Repository) ConsumePasswordReset(ctx context.Context, tokenHash string) (PasswordResetToken, error) {
	if err := storage.ValidateTokenHash(tokenHash, "token_hash"); err != nil {
		return PasswordResetToken{}, err
	}
	token, err := scanPasswordReset(r.db.QueryRow(ctx, `
update user_password_reset_tokens
set status = 'consumed',
    consumed_at = now()
where token_hash = $1
  and status = 'active'
  and expires_at > now()
returning id, user_id, token_hash, status, created_by_user_id, created_at, expires_at, consumed_at`, tokenHash))
	if err != nil {
		return PasswordResetToken{}, fmt.Errorf("consume password reset token: %w", err)
	}
	return token, nil
}

func (r Repository) CreatePassword2FASetup(ctx context.Context, params CreatePassword2FASetupParams) (Password2FALoginSetup, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return Password2FALoginSetup{}, err
		}
		params.ID = id
	}
	if err := validateCreatePassword2FASetup(params); err != nil {
		return Password2FALoginSetup{}, err
	}
	if _, err := r.db.Exec(ctx, `
update password_2fa_login_setups
set status = 'superseded'
where user_id = $1
  and status = 'active'`, params.UserID); err != nil {
		return Password2FALoginSetup{}, fmt.Errorf("supersede password 2fa login setup tokens: %w", err)
	}
	setup, err := scanPassword2FASetup(r.db.QueryRow(ctx, `
insert into password_2fa_login_setups (
    id, setup_hash, user_id, pending_totp_secret_encrypted,
    expires_at, source_ip, user_agent
) values ($1, $2, $3, $4, $5, $6, $7)
returning id, setup_hash, user_id, pending_totp_secret_encrypted,
    status, created_at, expires_at, consumed_at, source_ip, user_agent`,
		params.ID, params.SetupHash, params.UserID, params.PendingTOTPSecretEncrypted,
		params.ExpiresAt, params.SourceIP, params.UserAgent))
	if err != nil {
		return Password2FALoginSetup{}, fmt.Errorf("create password 2fa login setup: %w", err)
	}
	return setup, nil
}

func (r Repository) GetActivePassword2FASetupByHash(ctx context.Context, setupHash string) (Password2FALoginSetup, error) {
	if err := storage.ValidateTokenHash(setupHash, "setup_hash"); err != nil {
		return Password2FALoginSetup{}, err
	}
	setup, err := scanPassword2FASetup(r.db.QueryRow(ctx, password2FASetupSelectSQL()+`
where setup_hash = $1
  and status = 'active'
  and expires_at > now()
for update`, setupHash))
	if err != nil {
		return Password2FALoginSetup{}, fmt.Errorf("get password 2fa login setup: %w", err)
	}
	return setup, nil
}

func (r Repository) ConsumePassword2FASetup(ctx context.Context, setupHash string) (Password2FALoginSetup, error) {
	if err := storage.ValidateTokenHash(setupHash, "setup_hash"); err != nil {
		return Password2FALoginSetup{}, err
	}
	setup, err := scanPassword2FASetup(r.db.QueryRow(ctx, `
update password_2fa_login_setups
set status = 'consumed',
    consumed_at = now()
where setup_hash = $1
  and status = 'active'
  and expires_at > now()
returning id, setup_hash, user_id, pending_totp_secret_encrypted,
    status, created_at, expires_at, consumed_at, source_ip, user_agent`, setupHash))
	if err != nil {
		return Password2FALoginSetup{}, fmt.Errorf("consume password 2fa login setup: %w", err)
	}
	return setup, nil
}

func (r Repository) RotateRefreshToken(ctx context.Context, params RotateRefreshTokenParams) (Session, error) {
	beginner, ok := r.db.(storage.Beginner)
	if !ok {
		return RotateRefreshTokenTx(ctx, r.db, params)
	}
	tx, err := beginner.Begin(ctx)
	if err != nil {
		return Session{}, err
	}
	session, err := RotateRefreshTokenTx(ctx, tx, params)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenReused) || errors.Is(err, ErrRefreshTokenExpired) {
			if commitErr := tx.Commit(ctx); commitErr != nil {
				return Session{}, commitErr
			}
			return Session{}, err
		}
		rollbackWithFreshContext(ctx, tx)
		return Session{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Session{}, err
	}
	return session, nil
}

func RotateRefreshTokenTx(ctx context.Context, db storage.DBTX, params RotateRefreshTokenParams) (Session, error) {
	if err := validateRotateRefresh(params); err != nil {
		return Session{}, err
	}
	refresh, err := scanRefreshToken(db.QueryRow(ctx, refreshTokenSelectSQL()+` where refresh_token_hash = $1 for update`, params.CurrentRefreshTokenHash))
	if err != nil {
		return Session{}, fmt.Errorf("lookup refresh token: %w", err)
	}
	if refresh.Status != RefreshTokenStatusActive {
		if err := markRefreshReuse(ctx, db, refresh.UserSessionID, refresh.ID); err != nil {
			return Session{}, fmt.Errorf("mark refresh token reuse: %w", err)
		}
		return Session{}, ErrRefreshTokenReused
	}
	now := time.Now().UTC()
	if !refresh.ExpiresAt.After(now) {
		_, _ = db.Exec(ctx, `
update user_session_refresh_tokens
set status = 'expired',
    last_seen_at = now()
where id = $1
  and status = 'active'`, refresh.ID)
		return Session{}, ErrRefreshTokenExpired
	}
	session, err := scanSession(db.QueryRow(ctx, sessionSelectSQL()+` where id = $1 for update`, refresh.UserSessionID))
	if err != nil {
		return Session{}, fmt.Errorf("lock user session: %w", err)
	}
	if session.Status != SessionStatusActive || session.RefreshTokenHash != params.CurrentRefreshTokenHash {
		if err := markRefreshReuse(ctx, db, refresh.UserSessionID, refresh.ID); err != nil {
			return Session{}, fmt.Errorf("mark refresh token reuse: %w", err)
		}
		return Session{}, ErrRefreshTokenReused
	}
	if !session.RefreshExpiresAt.After(now) {
		_, _ = db.Exec(ctx, `
update user_session_refresh_tokens
set status = 'expired',
    last_seen_at = now()
where id = $1
  and status = 'active'`, refresh.ID)
		return Session{}, ErrRefreshTokenExpired
	}
	if _, err := db.Exec(ctx, `
update user_session_refresh_tokens
set status = 'rotated',
    rotated_at = now(),
    last_seen_at = now()
where id = $1
  and status = 'active'`, refresh.ID); err != nil {
		return Session{}, fmt.Errorf("rotate old refresh token: %w", err)
	}
	newRefreshID, err := storage.NewUUID()
	if err != nil {
		return Session{}, err
	}
	if _, err := db.Exec(ctx, `
insert into user_session_refresh_tokens (
    id, user_session_id, refresh_token_hash, status, issued_at, expires_at
) values ($1, $2, $3, 'active', now(), $4)`,
		newRefreshID, refresh.UserSessionID, params.NewRefreshTokenHash, params.RefreshExpiresAt); err != nil {
		return Session{}, fmt.Errorf("insert new refresh token: %w", err)
	}
	rotated, err := scanSession(db.QueryRow(ctx, `
update user_sessions
set access_token_hash = $2,
    refresh_token_hash = $3,
    access_expires_at = $4,
    refresh_expires_at = $5,
    last_refreshed_at = now()
where id = $1
  and status = 'active'
returning id, user_id, auth_method, access_token_hash, refresh_token_hash,
    status, created_at, access_expires_at, refresh_expires_at,
    last_refreshed_at, last_used_at, revoked_at, revoked_reason, user_agent, source_ip`,
		refresh.UserSessionID, params.NewAccessTokenHash, params.NewRefreshTokenHash,
		params.AccessExpiresAt, params.RefreshExpiresAt))
	if err != nil {
		return Session{}, fmt.Errorf("update user session refresh token: %w", err)
	}
	return rotated, nil
}

func (r Repository) CreateOIDCState(ctx context.Context, params CreateOIDCStateParams) (OIDCLoginState, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return OIDCLoginState{}, err
		}
		params.ID = id
	}
	if err := validateCreateOIDCState(params); err != nil {
		return OIDCLoginState{}, err
	}
	state, err := scanOIDCState(r.db.QueryRow(ctx, `
insert into oidc_login_states (
    id, state_hash, nonce, code_verifier_encrypted,
    provider_callback_url, frontend_return_url, expires_at, source_ip, user_agent
) values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
returning id, state_hash, nonce, code_verifier_encrypted,
    provider_callback_url, frontend_return_url, expires_at,
    consumed_at, created_at, source_ip, user_agent`,
		params.ID, params.StateHash, params.Nonce, params.CodeVerifierEncrypted,
		params.ProviderCallbackURL, params.FrontendReturnURL, params.ExpiresAt, params.SourceIP, params.UserAgent))
	if err != nil {
		return OIDCLoginState{}, fmt.Errorf("create oidc login state: %w", err)
	}
	return state, nil
}

func (r Repository) ConsumeOIDCState(ctx context.Context, stateHash string) (OIDCLoginState, error) {
	if err := storage.ValidateTokenHash(stateHash, "state_hash"); err != nil {
		return OIDCLoginState{}, err
	}
	state, err := scanOIDCState(r.db.QueryRow(ctx, `
update oidc_login_states
set consumed_at = now()
where state_hash = $1
  and consumed_at is null
  and expires_at > now()
returning id, state_hash, nonce, code_verifier_encrypted,
    provider_callback_url, frontend_return_url, expires_at,
    consumed_at, created_at, source_ip, user_agent`, stateHash))
	if err != nil {
		return OIDCLoginState{}, fmt.Errorf("consume oidc login state: %w", err)
	}
	return state, nil
}

func (r Repository) CreateOIDCHandoff(ctx context.Context, params CreateOIDCHandoffParams) (OIDCLoginHandoff, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return OIDCLoginHandoff{}, err
		}
		params.ID = id
	}
	if err := validateCreateOIDCHandoff(params); err != nil {
		return OIDCLoginHandoff{}, err
	}
	handoff, err := scanOIDCHandoff(r.db.QueryRow(ctx, `
insert into oidc_login_handoffs (
    id, handoff_hash, user_id, oidc_login_state_id,
    frontend_return_url, expires_at, source_ip, user_agent
) values ($1, $2, $3, $4, $5, $6, $7, $8)
returning id, handoff_hash, user_id, oidc_login_state_id,
    frontend_return_url, status, created_at, expires_at,
    consumed_at, source_ip, user_agent`,
		params.ID, params.HandoffHash, params.UserID, params.OIDCLoginStateID,
		params.FrontendReturnURL, params.ExpiresAt, params.SourceIP, params.UserAgent))
	if err != nil {
		return OIDCLoginHandoff{}, fmt.Errorf("create oidc login handoff: %w", err)
	}
	return handoff, nil
}

func (r Repository) ConsumeOIDCHandoff(ctx context.Context, handoffHash string) (OIDCLoginHandoff, error) {
	if err := storage.ValidateTokenHash(handoffHash, "handoff_hash"); err != nil {
		return OIDCLoginHandoff{}, err
	}
	handoff, err := scanOIDCHandoff(r.db.QueryRow(ctx, `
update oidc_login_handoffs
set status = 'consumed',
    consumed_at = now()
where handoff_hash = $1
  and status = 'active'
  and expires_at > now()
returning id, handoff_hash, user_id, oidc_login_state_id,
    frontend_return_url, status, created_at, expires_at,
    consumed_at, source_ip, user_agent`, handoffHash))
	if err != nil {
		return OIDCLoginHandoff{}, fmt.Errorf("consume oidc login handoff: %w", err)
	}
	return handoff, nil
}

func sessionSelectSQL() string {
	return `select id, user_id, auth_method, access_token_hash, refresh_token_hash,
    status, created_at, access_expires_at, refresh_expires_at,
    last_refreshed_at, last_used_at, revoked_at, revoked_reason, user_agent, source_ip
from user_sessions`
}

func refreshTokenSelectSQL() string {
	return `select id, user_session_id, refresh_token_hash, status,
    issued_at, expires_at, rotated_at, last_seen_at
from user_session_refresh_tokens`
}

func passwordResetSelectSQL() string {
	return `select id, user_id, token_hash, status, created_by_user_id,
    created_at, expires_at, consumed_at
from user_password_reset_tokens `
}

func password2FASetupSelectSQL() string {
	return `select id, setup_hash, user_id, pending_totp_secret_encrypted,
    status, created_at, expires_at, consumed_at, source_ip, user_agent
from password_2fa_login_setups `
}

func scanSession(row scanner) (Session, error) {
	var session Session
	var authMethod, status string
	var lastRefreshedAt, lastUsedAt, revokedAt sql.NullTime
	var revokedReason, userAgent, sourceIP sql.NullString
	if err := row.Scan(
		&session.ID,
		&session.UserID,
		&authMethod,
		&session.AccessTokenHash,
		&session.RefreshTokenHash,
		&status,
		&session.CreatedAt,
		&session.AccessExpiresAt,
		&session.RefreshExpiresAt,
		&lastRefreshedAt,
		&lastUsedAt,
		&revokedAt,
		&revokedReason,
		&userAgent,
		&sourceIP,
	); err != nil {
		return Session{}, err
	}
	session.AuthMethod = AuthMethod(authMethod)
	session.Status = SessionStatus(status)
	session.LastRefreshedAt = timePtr(lastRefreshedAt)
	session.LastUsedAt = timePtr(lastUsedAt)
	session.RevokedAt = timePtr(revokedAt)
	if revokedReason.Valid {
		reason := SessionRevokedReason(revokedReason.String)
		session.RevokedReason = &reason
	}
	session.UserAgent = stringPtr(userAgent)
	session.SourceIP = stringPtr(sourceIP)
	return session, nil
}

func scanRefreshToken(row scanner) (RefreshToken, error) {
	var token RefreshToken
	var status string
	var rotatedAt, lastSeenAt sql.NullTime
	if err := row.Scan(
		&token.ID,
		&token.UserSessionID,
		&token.RefreshTokenHash,
		&status,
		&token.IssuedAt,
		&token.ExpiresAt,
		&rotatedAt,
		&lastSeenAt,
	); err != nil {
		return RefreshToken{}, err
	}
	token.Status = RefreshTokenStatus(status)
	token.RotatedAt = timePtr(rotatedAt)
	token.LastSeenAt = timePtr(lastSeenAt)
	return token, nil
}

func scanOIDCState(row scanner) (OIDCLoginState, error) {
	var state OIDCLoginState
	var frontendReturnURL, sourceIP, userAgent sql.NullString
	var consumedAt sql.NullTime
	if err := row.Scan(
		&state.ID,
		&state.StateHash,
		&state.Nonce,
		&state.CodeVerifierEncrypted,
		&state.ProviderCallbackURL,
		&frontendReturnURL,
		&state.ExpiresAt,
		&consumedAt,
		&state.CreatedAt,
		&sourceIP,
		&userAgent,
	); err != nil {
		return OIDCLoginState{}, err
	}
	state.FrontendReturnURL = stringPtr(frontendReturnURL)
	state.ConsumedAt = timePtr(consumedAt)
	state.SourceIP = stringPtr(sourceIP)
	state.UserAgent = stringPtr(userAgent)
	return state, nil
}

func scanOIDCHandoff(row scanner) (OIDCLoginHandoff, error) {
	var handoff OIDCLoginHandoff
	var stateID, frontendReturnURL, sourceIP, userAgent sql.NullString
	var status string
	var consumedAt sql.NullTime
	if err := row.Scan(
		&handoff.ID,
		&handoff.HandoffHash,
		&handoff.UserID,
		&stateID,
		&frontendReturnURL,
		&status,
		&handoff.CreatedAt,
		&handoff.ExpiresAt,
		&consumedAt,
		&sourceIP,
		&userAgent,
	); err != nil {
		return OIDCLoginHandoff{}, err
	}
	handoff.OIDCLoginStateID = stringPtr(stateID)
	handoff.FrontendReturnURL = stringPtr(frontendReturnURL)
	handoff.Status = HandoffStatus(status)
	handoff.ConsumedAt = timePtr(consumedAt)
	handoff.SourceIP = stringPtr(sourceIP)
	handoff.UserAgent = stringPtr(userAgent)
	return handoff, nil
}

func scanPasswordReset(row scanner) (PasswordResetToken, error) {
	var token PasswordResetToken
	var status string
	var consumedAt sql.NullTime
	if err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&status,
		&token.CreatedByUserID,
		&token.CreatedAt,
		&token.ExpiresAt,
		&consumedAt,
	); err != nil {
		return PasswordResetToken{}, err
	}
	token.Status = OneTimeTokenStatus(status)
	token.ConsumedAt = timePtr(consumedAt)
	return token, nil
}

func scanPassword2FASetup(row scanner) (Password2FALoginSetup, error) {
	var setup Password2FALoginSetup
	var status string
	var consumedAt sql.NullTime
	var sourceIP, userAgent sql.NullString
	if err := row.Scan(
		&setup.ID,
		&setup.SetupHash,
		&setup.UserID,
		&setup.PendingTOTPSecretEncrypted,
		&status,
		&setup.CreatedAt,
		&setup.ExpiresAt,
		&consumedAt,
		&sourceIP,
		&userAgent,
	); err != nil {
		return Password2FALoginSetup{}, err
	}
	setup.Status = OneTimeTokenStatus(status)
	setup.ConsumedAt = timePtr(consumedAt)
	setup.SourceIP = stringPtr(sourceIP)
	setup.UserAgent = stringPtr(userAgent)
	return setup, nil
}

type scanner interface {
	Scan(...any) error
}

func markRefreshReuse(ctx context.Context, db storage.DBTX, sessionID, refreshTokenID string) error {
	if _, err := db.Exec(ctx, `
update user_session_refresh_tokens
set status = 'reused',
    last_seen_at = now()
where id = $1`, refreshTokenID); err != nil {
		return err
	}
	if _, err := db.Exec(ctx, `
update user_session_refresh_tokens
set status = 'revoked',
    last_seen_at = coalesce(last_seen_at, now())
where user_session_id = $1
  and id <> $2
  and status = 'active'`, sessionID, refreshTokenID); err != nil {
		return err
	}
	_, err := db.Exec(ctx, `
update user_sessions
set status = 'revoked',
    revoked_at = coalesce(revoked_at, now()),
    revoked_reason = coalesce(revoked_reason, 'refresh_reuse')
where id = $1
  and status = 'active'`, sessionID)
	return err
}

func validateCreateSession(params CreateSessionParams) error {
	if err := storage.ValidateUUID(params.ID, "session_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.RefreshHistoryID, "refresh_history_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.UserID, "user_id"); err != nil {
		return err
	}
	if err := validateAuthMethod(params.AuthMethod); err != nil {
		return err
	}
	if err := storage.ValidateTokenHash(params.AccessTokenHash, "access_token_hash"); err != nil {
		return err
	}
	if err := storage.ValidateTokenHash(params.RefreshTokenHash, "refresh_token_hash"); err != nil {
		return err
	}
	if params.AccessExpiresAt.IsZero() || params.RefreshExpiresAt.IsZero() || !params.RefreshExpiresAt.After(params.AccessExpiresAt) {
		return errors.New("refresh_expires_at must be after access_expires_at")
	}
	if !params.RefreshTokenExpiresAt.After(params.RefreshTokenIssuedAt) {
		return errors.New("refresh token history expiry must be after issued_at")
	}
	if err := storage.ValidateOptionalHumanString(params.UserAgent, "user_agent", 1024); err != nil {
		return err
	}
	if err := storage.ValidateOptionalHumanString(params.SourceIP, "source_ip", 128); err != nil {
		return err
	}
	return nil
}

func validateRotateRefresh(params RotateRefreshTokenParams) error {
	if err := storage.ValidateTokenHash(params.CurrentRefreshTokenHash, "refresh_token_hash"); err != nil {
		return err
	}
	if err := storage.ValidateTokenHash(params.NewAccessTokenHash, "access_token_hash"); err != nil {
		return err
	}
	if err := storage.ValidateTokenHash(params.NewRefreshTokenHash, "new_refresh_token_hash"); err != nil {
		return err
	}
	if params.AccessExpiresAt.IsZero() || params.RefreshExpiresAt.IsZero() || !params.RefreshExpiresAt.After(params.AccessExpiresAt) {
		return errors.New("refresh_expires_at must be after access_expires_at")
	}
	return nil
}

func validateCreateOIDCState(params CreateOIDCStateParams) error {
	if err := storage.ValidateUUID(params.ID, "oidc_login_state_id"); err != nil {
		return err
	}
	if err := storage.ValidateTokenHash(params.StateHash, "state_hash"); err != nil {
		return err
	}
	if err := storage.ValidateHumanString(params.Nonce, "nonce", 22, 256); err != nil {
		return err
	}
	if err := storage.ValidateEncryptedEnvelope(&params.CodeVerifierEncrypted, "code_verifier_encrypted"); err != nil {
		return err
	}
	if err := storage.ValidateHTTPSURL(&params.ProviderCallbackURL, "provider_callback_url"); err != nil {
		return err
	}
	if err := storage.ValidateHTTPSURL(params.FrontendReturnURL, "frontend_return_url"); err != nil {
		return err
	}
	if params.ExpiresAt.IsZero() {
		return errors.New("expires_at is required")
	}
	if err := storage.ValidateOptionalHumanString(params.SourceIP, "source_ip", 128); err != nil {
		return err
	}
	return storage.ValidateOptionalHumanString(params.UserAgent, "user_agent", 1024)
}

func validateCreateOIDCHandoff(params CreateOIDCHandoffParams) error {
	if err := storage.ValidateUUID(params.ID, "oidc_login_handoff_id"); err != nil {
		return err
	}
	if err := storage.ValidateTokenHash(params.HandoffHash, "handoff_hash"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.UserID, "user_id"); err != nil {
		return err
	}
	if params.OIDCLoginStateID != nil {
		if err := storage.ValidateUUID(*params.OIDCLoginStateID, "oidc_login_state_id"); err != nil {
			return err
		}
	}
	if err := storage.ValidateHTTPSURL(params.FrontendReturnURL, "frontend_return_url"); err != nil {
		return err
	}
	if params.ExpiresAt.IsZero() {
		return errors.New("expires_at is required")
	}
	if err := storage.ValidateOptionalHumanString(params.SourceIP, "source_ip", 128); err != nil {
		return err
	}
	return storage.ValidateOptionalHumanString(params.UserAgent, "user_agent", 1024)
}

func validateCreatePasswordReset(params CreatePasswordResetParams) error {
	if err := storage.ValidateUUID(params.ID, "password_reset_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.UserID, "user_id"); err != nil {
		return err
	}
	if err := storage.ValidateTokenHash(params.TokenHash, "token_hash"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.CreatedByUserID, "created_by_user_id"); err != nil {
		return err
	}
	if params.ExpiresAt.IsZero() || !params.ExpiresAt.After(time.Now().UTC()) {
		return errors.New("expires_at must be in the future")
	}
	return nil
}

func validateCreatePassword2FASetup(params CreatePassword2FASetupParams) error {
	if err := storage.ValidateUUID(params.ID, "password_2fa_setup_id"); err != nil {
		return err
	}
	if err := storage.ValidateTokenHash(params.SetupHash, "setup_hash"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.UserID, "user_id"); err != nil {
		return err
	}
	if err := storage.ValidateEncryptedEnvelope(&params.PendingTOTPSecretEncrypted, "pending_totp_secret_encrypted"); err != nil {
		return err
	}
	if params.ExpiresAt.IsZero() || !params.ExpiresAt.After(time.Now().UTC()) {
		return errors.New("expires_at must be in the future")
	}
	if err := storage.ValidateOptionalHumanString(params.SourceIP, "source_ip", 128); err != nil {
		return err
	}
	return storage.ValidateOptionalHumanString(params.UserAgent, "user_agent", 1024)
}

func validateAuthMethod(method AuthMethod) error {
	switch method {
	case AuthMethodPassword, AuthMethodOIDC:
		return nil
	default:
		return errors.New("auth_method is invalid")
	}
}

func validateRevokedReason(reason SessionRevokedReason) error {
	switch reason {
	case SessionRevokedLogout, SessionRevokedDisabledUser, SessionRevokedRefreshReuse, SessionRevokedAdminAction, SessionRevokedExpired, SessionRevokedPasswordReset, SessionRevokedPassword2FAReset:
		return nil
	default:
		return errors.New("revoked_reason is invalid")
	}
}

func timePtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	return &value.Time
}

func stringPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}

func rollbackWithFreshContext(ctx context.Context, tx storage.Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	if rollbackCtx.Err() != nil {
		cancel()
		rollbackCtx, cancel = context.WithTimeout(context.Background(), rollbackTimeout)
	}
	defer cancel()
	_ = tx.Rollback(rollbackCtx)
}
