package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"certhub/internal/storage"
)

type GlobalRole string

const (
	GlobalRoleUser  GlobalRole = "user"
	GlobalRoleAdmin GlobalRole = "admin"
)

type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

type User struct {
	ID                         string
	Email                      string
	DisplayName                string
	PasswordHash               *string
	Password2FAEnabled         bool
	TOTPSecretEncrypted        *string
	PendingTOTPSecretEncrypted *string
	OIDCIssuer                 *string
	OIDCSubject                *string
	GlobalRole                 GlobalRole
	Status                     Status
	CreatedAt                  time.Time
	UpdatedAt                  time.Time
	LastLoginAt                *time.Time
	ApplicationGrantCount      int64
}

type Repository struct {
	db storage.DBTX
}

func NewRepository(db storage.DBTX) Repository {
	return Repository{db: db}
}

type CreateUserParams struct {
	ID                         string
	Email                      string
	DisplayName                string
	PasswordHash               *string
	Password2FAEnabled         bool
	TOTPSecretEncrypted        *string
	PendingTOTPSecretEncrypted *string
	OIDCIssuer                 *string
	OIDCSubject                *string
	GlobalRole                 GlobalRole
	Status                     Status
}

type UpdateUserParams struct {
	DisplayName                storage.OptionalString
	PasswordHash               storage.OptionalString
	Password2FAEnabled         storage.OptionalBool
	TOTPSecretEncrypted        storage.OptionalString
	PendingTOTPSecretEncrypted storage.OptionalString
	OIDCIssuer                 storage.OptionalString
	OIDCSubject                storage.OptionalString
	GlobalRole                 storage.OptionalString
	Status                     storage.OptionalString
	LastLoginAt                storage.OptionalTime
}

type ListUsersParams struct {
	storage.ListOptions
	Status     *Status
	GlobalRole *GlobalRole
	Search     string
}

func (r Repository) Create(ctx context.Context, params CreateUserParams) (User, error) {
	if r.db == nil {
		return User{}, errors.New("users repository storage is required")
	}
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return User{}, err
		}
		params.ID = id
	}
	if err := validateCreateUser(&params); err != nil {
		return User{}, err
	}
	var user User
	row := r.db.QueryRow(ctx, `
insert into users (
    id, email, display_name, password_hash, password_2fa_enabled,
    totp_secret_encrypted, pending_totp_secret_encrypted,
    oidc_issuer, oidc_subject, global_role, status
) values (
    $1, $2, $3, $4, $5,
    $6, $7,
    $8, $9, $10, $11
)
returning id, email, display_name, password_hash, password_2fa_enabled,
    totp_secret_encrypted, pending_totp_secret_encrypted,
    oidc_issuer, oidc_subject, global_role, status,
    created_at, updated_at, last_login_at, 0::bigint`, params.ID, params.Email, params.DisplayName, params.PasswordHash,
		params.Password2FAEnabled, params.TOTPSecretEncrypted, params.PendingTOTPSecretEncrypted, params.OIDCIssuer,
		params.OIDCSubject, string(params.GlobalRole), string(params.Status))
	user, err := scanUser(row)
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func (r Repository) Get(ctx context.Context, id string) (User, error) {
	if err := storage.ValidateUUID(id, "user_id"); err != nil {
		return User{}, err
	}
	return r.getWhere(ctx, "u.id = $1", id)
}

func (r Repository) LookupByNormalizedEmail(ctx context.Context, email string) (User, error) {
	normalized, err := storage.NormalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	return r.getWhere(ctx, "u.email = $1", normalized)
}

func (r Repository) LookupActiveByNormalizedEmail(ctx context.Context, email string) (User, error) {
	normalized, err := storage.NormalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	return r.getWhere(ctx, "u.email = $1 and u.status = 'active'", normalized)
}

func (r Repository) LookupByOIDC(ctx context.Context, issuer, subject string) (User, error) {
	if err := storage.ValidateHTTPSURL(&issuer, "oidc_issuer"); err != nil {
		return User{}, err
	}
	if err := storage.ValidateHumanString(subject, "oidc_subject", 1, 255); err != nil {
		return User{}, err
	}
	return r.getWhere(ctx, "u.oidc_issuer = $1 and u.oidc_subject = $2", issuer, subject)
}

func (r Repository) List(ctx context.Context, params ListUsersParams) ([]User, error) {
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return nil, err
	}
	var args []any
	var where []string
	if params.Status != nil {
		if err := validateStatus(*params.Status); err != nil {
			return nil, err
		}
		args = append(args, string(*params.Status))
		where = append(where, fmt.Sprintf("u.status = $%d", len(args)))
	}
	if params.GlobalRole != nil {
		if err := validateGlobalRole(*params.GlobalRole); err != nil {
			return nil, err
		}
		args = append(args, string(*params.GlobalRole))
		where = append(where, fmt.Sprintf("u.global_role = $%d", len(args)))
	}
	if params.Search != "" {
		if err := storage.ValidateHumanString(params.Search, "search", 1, 254); err != nil {
			return nil, err
		}
		args = append(args, "%"+strings.ToLower(params.Search)+"%")
		where = append(where, fmt.Sprintf("(u.email like $%d or lower(u.display_name) like $%d)", len(args), len(args)))
	}
	args = append(args, opts.Limit, opts.Offset)
	limitParam := len(args) - 1
	offsetParam := len(args)
	query := baseUserSelect()
	if len(where) > 0 {
		query += " where " + strings.Join(where, " and ")
	}
	query += fmt.Sprintf(" group by u.id order by u.created_at desc, u.id desc limit $%d offset $%d", limitParam, offsetParam)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("list users: %w", err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

func (r Repository) Count(ctx context.Context, params ListUsersParams) (int64, error) {
	if _, err := storage.NormalizeListOptions(params.ListOptions); err != nil {
		return 0, err
	}
	var args []any
	var where []string
	if params.Status != nil {
		if err := validateStatus(*params.Status); err != nil {
			return 0, err
		}
		args = append(args, string(*params.Status))
		where = append(where, fmt.Sprintf("u.status = $%d", len(args)))
	}
	if params.GlobalRole != nil {
		if err := validateGlobalRole(*params.GlobalRole); err != nil {
			return 0, err
		}
		args = append(args, string(*params.GlobalRole))
		where = append(where, fmt.Sprintf("u.global_role = $%d", len(args)))
	}
	if params.Search != "" {
		if err := storage.ValidateHumanString(params.Search, "search", 1, 254); err != nil {
			return 0, err
		}
		args = append(args, "%"+strings.ToLower(params.Search)+"%")
		where = append(where, fmt.Sprintf("(u.email like $%d or lower(u.display_name) like $%d)", len(args), len(args)))
	}
	query := `select count(*)::bigint from users u`
	if len(where) > 0 {
		query += " where " + strings.Join(where, " and ")
	}
	var total int64
	if err := r.db.QueryRow(ctx, query, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return total, nil
}

func (r Repository) Update(ctx context.Context, id string, params UpdateUserParams) (User, error) {
	if err := storage.ValidateUUID(id, "user_id"); err != nil {
		return User{}, err
	}
	if err := validateUpdateUser(params); err != nil {
		return User{}, err
	}
	var sets []string
	args := []any{}
	add := func(column string, value any) {
		args = append(args, value)
		sets = append(sets, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	if params.DisplayName.Set {
		add("display_name", valueOrNil(params.DisplayName.Value))
	}
	if params.PasswordHash.Set {
		add("password_hash", valueOrNil(params.PasswordHash.Value))
	}
	if params.Password2FAEnabled.Set {
		add("password_2fa_enabled", params.Password2FAEnabled.Value)
	}
	if params.TOTPSecretEncrypted.Set {
		add("totp_secret_encrypted", valueOrNil(params.TOTPSecretEncrypted.Value))
	}
	if params.PendingTOTPSecretEncrypted.Set {
		add("pending_totp_secret_encrypted", valueOrNil(params.PendingTOTPSecretEncrypted.Value))
	}
	if params.OIDCIssuer.Set {
		add("oidc_issuer", valueOrNil(params.OIDCIssuer.Value))
	}
	if params.OIDCSubject.Set {
		add("oidc_subject", valueOrNil(params.OIDCSubject.Value))
	}
	if params.GlobalRole.Set {
		add("global_role", valueOrNil(params.GlobalRole.Value))
	}
	if params.Status.Set {
		add("status", valueOrNil(params.Status.Value))
	}
	if params.LastLoginAt.Set {
		add("last_login_at", params.LastLoginAt.Value)
	}
	if len(sets) == 0 {
		return r.Get(ctx, id)
	}
	sets = append(sets, "updated_at = now()")
	args = append(args, id)
	query := fmt.Sprintf(`
update users
set %s
where id = $%d
returning id, email, display_name, password_hash, password_2fa_enabled,
    totp_secret_encrypted, pending_totp_secret_encrypted,
    oidc_issuer, oidc_subject, global_role, status,
    created_at, updated_at, last_login_at,
    (select count(*) from application_user_grants where user_id = users.id)::bigint`, strings.Join(sets, ", "), len(args))
	user, err := scanUser(r.db.QueryRow(ctx, query, args...))
	if err != nil {
		return User{}, fmt.Errorf("update user: %w", err)
	}
	return user, nil
}

func (r Repository) getWhere(ctx context.Context, predicate string, args ...any) (User, error) {
	if r.db == nil {
		return User{}, errors.New("users repository storage is required")
	}
	query := baseUserSelect() + " where " + predicate + " group by u.id"
	user, err := scanUser(r.db.QueryRow(ctx, query, args...))
	if err != nil {
		return User{}, fmt.Errorf("get user: %w", err)
	}
	return user, nil
}

func baseUserSelect() string {
	return `select u.id, u.email, u.display_name, u.password_hash, u.password_2fa_enabled,
    u.totp_secret_encrypted, u.pending_totp_secret_encrypted,
    u.oidc_issuer, u.oidc_subject, u.global_role, u.status,
    u.created_at, u.updated_at, u.last_login_at,
    count(g.id)::bigint
from users u
left join application_user_grants g on g.user_id = u.id`
}

type scanner interface {
	Scan(...any) error
}

func scanUser(row scanner) (User, error) {
	var user User
	var passwordHash, totpSecret, pendingTOTPSecret, oidcIssuer, oidcSubject sql.NullString
	var lastLoginAt sql.NullTime
	var globalRole, status string
	if err := row.Scan(
		&user.ID,
		&user.Email,
		&user.DisplayName,
		&passwordHash,
		&user.Password2FAEnabled,
		&totpSecret,
		&pendingTOTPSecret,
		&oidcIssuer,
		&oidcSubject,
		&globalRole,
		&status,
		&user.CreatedAt,
		&user.UpdatedAt,
		&lastLoginAt,
		&user.ApplicationGrantCount,
	); err != nil {
		return User{}, err
	}
	user.PasswordHash = ptrFromNullString(passwordHash)
	user.TOTPSecretEncrypted = ptrFromNullString(totpSecret)
	user.PendingTOTPSecretEncrypted = ptrFromNullString(pendingTOTPSecret)
	user.OIDCIssuer = ptrFromNullString(oidcIssuer)
	user.OIDCSubject = ptrFromNullString(oidcSubject)
	if lastLoginAt.Valid {
		user.LastLoginAt = &lastLoginAt.Time
	}
	user.GlobalRole = GlobalRole(globalRole)
	user.Status = Status(status)
	return user, nil
}

func ptrFromNullString(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}

func validateCreateUser(params *CreateUserParams) error {
	if err := storage.ValidateUUID(params.ID, "user_id"); err != nil {
		return err
	}
	normalized, err := storage.NormalizeEmail(params.Email)
	if err != nil {
		return err
	}
	params.Email = normalized
	if err := storage.ValidateHumanString(params.DisplayName, "display_name", 1, 255); err != nil {
		return err
	}
	if params.GlobalRole == "" {
		params.GlobalRole = GlobalRoleUser
	}
	if err := validateGlobalRole(params.GlobalRole); err != nil {
		return err
	}
	if params.Status == "" {
		params.Status = StatusActive
	}
	if err := validateStatus(params.Status); err != nil {
		return err
	}
	if params.PasswordHash != nil {
		if err := storage.ValidateHumanString(*params.PasswordHash, "password_hash", 1, 4096); err != nil {
			return err
		}
	}
	if err := storage.ValidateEncryptedEnvelope(params.TOTPSecretEncrypted, "totp_secret_encrypted"); err != nil {
		return err
	}
	if err := storage.ValidateEncryptedEnvelope(params.PendingTOTPSecretEncrypted, "pending_totp_secret_encrypted"); err != nil {
		return err
	}
	if params.Password2FAEnabled && params.TOTPSecretEncrypted == nil {
		return errors.New("totp_secret_encrypted is required when password 2FA is enabled")
	}
	if (params.OIDCIssuer == nil) != (params.OIDCSubject == nil) {
		return errors.New("oidc_issuer and oidc_subject must be set together")
	}
	if err := storage.ValidateHTTPSURL(params.OIDCIssuer, "oidc_issuer"); err != nil {
		return err
	}
	if params.OIDCSubject != nil {
		if err := storage.ValidateHumanString(*params.OIDCSubject, "oidc_subject", 1, 255); err != nil {
			return err
		}
	}
	return nil
}

func validateUpdateUser(params UpdateUserParams) error {
	if params.DisplayName.Set && params.DisplayName.Value == nil {
		return errors.New("display_name cannot be null")
	}
	if params.DisplayName.Set && params.DisplayName.Value != nil {
		if err := storage.ValidateHumanString(*params.DisplayName.Value, "display_name", 1, 255); err != nil {
			return err
		}
	}
	if params.PasswordHash.Set && params.PasswordHash.Value != nil {
		if err := storage.ValidateHumanString(*params.PasswordHash.Value, "password_hash", 1, 4096); err != nil {
			return err
		}
	}
	if err := storage.ValidateEncryptedEnvelope(params.TOTPSecretEncrypted.Value, "totp_secret_encrypted"); params.TOTPSecretEncrypted.Set && err != nil {
		return err
	}
	if err := storage.ValidateEncryptedEnvelope(params.PendingTOTPSecretEncrypted.Value, "pending_totp_secret_encrypted"); params.PendingTOTPSecretEncrypted.Set && err != nil {
		return err
	}
	if params.OIDCIssuer.Set != params.OIDCSubject.Set {
		return errors.New("oidc_issuer and oidc_subject must be updated together")
	}
	if params.OIDCIssuer.Set {
		if (params.OIDCIssuer.Value == nil) != (params.OIDCSubject.Value == nil) {
			return errors.New("oidc_issuer and oidc_subject must both be null or non-null")
		}
		if err := storage.ValidateHTTPSURL(params.OIDCIssuer.Value, "oidc_issuer"); err != nil {
			return err
		}
		if params.OIDCSubject.Value != nil {
			if err := storage.ValidateHumanString(*params.OIDCSubject.Value, "oidc_subject", 1, 255); err != nil {
				return err
			}
		}
	}
	if params.GlobalRole.Set && params.GlobalRole.Value == nil {
		return errors.New("global_role cannot be null")
	}
	if params.GlobalRole.Set && params.GlobalRole.Value != nil {
		if err := validateGlobalRole(GlobalRole(*params.GlobalRole.Value)); err != nil {
			return err
		}
	}
	if params.Status.Set && params.Status.Value == nil {
		return errors.New("status cannot be null")
	}
	if params.Status.Set && params.Status.Value != nil {
		if err := validateStatus(Status(*params.Status.Value)); err != nil {
			return err
		}
	}
	return nil
}

func validateGlobalRole(role GlobalRole) error {
	switch role {
	case GlobalRoleUser, GlobalRoleAdmin:
		return nil
	default:
		return errors.New("global_role is invalid")
	}
}

func validateStatus(status Status) error {
	switch status {
	case StatusActive, StatusDisabled:
		return nil
	default:
		return errors.New("status is invalid")
	}
}

func valueOrNil(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
