package applications

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/torob/certhub/internal/storage"
)

type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

type SystemKind string

const SystemKindCerthubServer SystemKind = "certhub_server"

type TokenStatus string

const (
	TokenStatusActive  TokenStatus = "active"
	TokenStatusRevoked TokenStatus = "revoked"
)

type GrantRole string

const (
	GrantRoleViewer            GrantRole = "viewer"
	GrantRoleCertificateReader GrantRole = "certificate_reader"
	GrantRoleManager           GrantRole = "manager"
)

type DomainScopeKind string

const (
	DomainScopeKindExact    DomainScopeKind = "exact"
	DomainScopeKindWildcard DomainScopeKind = "wildcard"
)

type Application struct {
	ID                     string
	Name                   string
	DisplayName            string
	Status                 Status
	SystemKind             *SystemKind
	Description            *string
	TrustedSourceCIDRs     []string
	CreatedAt              time.Time
	UpdatedAt              time.Time
	DomainScopeCount       int64
	TokenCount             int64
	UserGrantCount         int64
	CertificateCount       int64
	TrustedSourceCIDRCount int64
}

type ApplicationToken struct {
	ID            string
	ApplicationID string
	Name          string
	TokenHash     string
	Status        TokenStatus
	CreatedAt     time.Time
	ExpiresAt     *time.Time
	LastUsedAt    *time.Time
	RevokedAt     *time.Time
}

type TokenIdentity struct {
	Token       ApplicationToken
	Application Application
}

type DomainScope struct {
	ID              string
	ApplicationID   string
	Value           string
	Kind            DomainScopeKind
	CreatedAt       time.Time
	CreatedByUserID *string
}

type UserGrant struct {
	ID              string
	ApplicationID   string
	UserID          string
	Role            GrantRole
	CreatedAt       time.Time
	CreatedByUserID *string
}

type Repository struct {
	db storage.DBTX
}

func NewRepository(db storage.DBTX) Repository {
	return Repository{db: db}
}

type CreateApplicationParams struct {
	ID                 string
	Name               string
	DisplayName        string
	Status             Status
	SystemKind         *SystemKind
	Description        *string
	TrustedSourceCIDRs []string
}

type UpdateApplicationParams struct {
	DisplayName        storage.OptionalString
	Status             storage.OptionalString
	Description        storage.OptionalString
	TrustedSourceCIDRs *[]string
}

type ListApplicationsParams struct {
	storage.ListOptions
	Status *Status
	Search string
}

type ListTokensParams struct {
	storage.ListOptions
	Status *TokenStatus
}

type CreateTokenParams struct {
	ID            string
	ApplicationID string
	Name          string
	TokenHash     string
	ExpiresAt     *time.Time
}

type RotateTokenParams struct {
	ApplicationID string
	TokenID       string
	TokenHash     string
	ExpiresAt     *time.Time
}

type AddDomainScopeParams struct {
	ID              string
	ApplicationID   string
	Value           string
	CreatedByUserID *string
}

type UpsertGrantParams struct {
	ID              string
	ApplicationID   string
	UserID          string
	Role            GrantRole
	CreatedByUserID *string
}

func (r Repository) Create(ctx context.Context, params CreateApplicationParams) (Application, error) {
	if r.db == nil {
		return Application{}, errors.New("applications repository storage is required")
	}
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return Application{}, err
		}
		params.ID = id
	}
	if err := validateCreateApplication(&params); err != nil {
		return Application{}, err
	}
	app, err := scanApplication(r.db.QueryRow(ctx, `
insert into applications (
    id, name, display_name, status, system_kind, description, trusted_source_cidrs
) values ($1, $2, $3, $4, $5, $6, $7::cidr[])
returning `+applicationReturningSQL(),
		params.ID, params.Name, params.DisplayName, string(params.Status),
		systemKindValue(params.SystemKind), params.Description, params.TrustedSourceCIDRs))
	if err != nil {
		return Application{}, fmt.Errorf("create application: %w", err)
	}
	return app, nil
}

func (r Repository) EnsureSystemApplication(ctx context.Context, params CreateApplicationParams) (Application, error) {
	kind := SystemKindCerthubServer
	params.Name = string(SystemKindCerthubServer)
	params.SystemKind = &kind
	params.Status = StatusActive
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return Application{}, err
		}
		params.ID = id
	}
	if err := validateCreateApplication(&params); err != nil {
		return Application{}, err
	}
	app, err := scanApplication(r.db.QueryRow(ctx, `
insert into applications (
    id, name, display_name, status, system_kind, description, trusted_source_cidrs
) values ($1, $2, $3, 'active', 'certhub_server', $4, $5::cidr[])
on conflict (name) do update
set display_name = excluded.display_name,
    status = 'active',
    system_kind = 'certhub_server',
    description = excluded.description,
    trusted_source_cidrs = excluded.trusted_source_cidrs,
    updated_at = now()
where applications.name = 'certhub_server'
returning `+applicationReturningSQL(),
		params.ID, params.Name, params.DisplayName, params.Description, params.TrustedSourceCIDRs))
	if err != nil {
		return Application{}, fmt.Errorf("ensure system application: %w", err)
	}
	return app, nil
}

func (r Repository) Get(ctx context.Context, id string) (Application, error) {
	if err := storage.ValidateUUID(id, "application_id"); err != nil {
		return Application{}, err
	}
	return r.getWhere(ctx, "a.id = $1", id)
}

func (r Repository) GetByName(ctx context.Context, name string) (Application, error) {
	if err := storage.ValidateMachineName(name, "application_name"); err != nil {
		return Application{}, err
	}
	return r.getWhere(ctx, "a.name = $1", name)
}

func (r Repository) List(ctx context.Context, params ListApplicationsParams) ([]Application, error) {
	query, args, err := r.listApplicationsQuery(params, "")
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	defer rows.Close()
	var apps []Application
	for rows.Next() {
		app, err := scanApplication(rows)
		if err != nil {
			return nil, fmt.Errorf("list applications: %w", err)
		}
		apps = append(apps, app)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	return apps, nil
}

func (r Repository) Count(ctx context.Context, params ListApplicationsParams) (int64, error) {
	query, args, err := r.countApplicationsQuery(params, "")
	if err != nil {
		return 0, err
	}
	var total int64
	if err := r.db.QueryRow(ctx, query, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("count applications: %w", err)
	}
	return total, nil
}

func (r Repository) ListVisible(ctx context.Context, userID string, params ListApplicationsParams) ([]Application, error) {
	if err := storage.ValidateUUID(userID, "user_id"); err != nil {
		return nil, err
	}
	query, args, err := r.listApplicationsQuery(params, userID)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list visible applications: %w", err)
	}
	defer rows.Close()
	var apps []Application
	for rows.Next() {
		app, err := scanApplication(rows)
		if err != nil {
			return nil, fmt.Errorf("list visible applications: %w", err)
		}
		apps = append(apps, app)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list visible applications: %w", err)
	}
	return apps, nil
}

func (r Repository) CountVisible(ctx context.Context, userID string, params ListApplicationsParams) (int64, error) {
	if err := storage.ValidateUUID(userID, "user_id"); err != nil {
		return 0, err
	}
	query, args, err := r.countApplicationsQuery(params, userID)
	if err != nil {
		return 0, err
	}
	var total int64
	if err := r.db.QueryRow(ctx, query, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("count visible applications: %w", err)
	}
	return total, nil
}

func (r Repository) ListAccessibleApplicationIDs(ctx context.Context, userID string) ([]string, error) {
	if err := storage.ValidateUUID(userID, "user_id"); err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `
select application_id::text
from application_user_grants
where user_id = $1
order by application_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list accessible application ids: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("list accessible application ids: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list accessible application ids: %w", err)
	}
	return ids, nil
}

func (r Repository) listApplicationsQuery(params ListApplicationsParams, visibleUserID string) (string, []any, error) {
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return "", nil, err
	}
	var args []any
	var where []string
	join := ""
	if visibleUserID != "" {
		args = append(args, visibleUserID)
		join = fmt.Sprintf(" join application_user_grants visible_grants on visible_grants.application_id = a.id and visible_grants.user_id = $%d", len(args))
	}
	if params.Status != nil {
		if err := validateStatus(*params.Status); err != nil {
			return "", nil, err
		}
		args = append(args, string(*params.Status))
		where = append(where, fmt.Sprintf("a.status = $%d", len(args)))
	}
	if params.Search != "" {
		if err := storage.ValidateHumanString(params.Search, "search", 1, 255); err != nil {
			return "", nil, err
		}
		args = append(args, "%"+strings.ToLower(params.Search)+"%")
		where = append(where, fmt.Sprintf("(a.name like $%d or lower(a.display_name) like $%d)", len(args), len(args)))
	}
	args = append(args, opts.Limit, opts.Offset)
	query := `select ` + applicationSelectColumnsSQL() + ` from applications a` + join
	if len(where) > 0 {
		query += " where " + strings.Join(where, " and ")
	}
	query += fmt.Sprintf(" order by a.created_at desc, a.id desc limit $%d offset $%d", len(args)-1, len(args))
	return query, args, nil
}

func (r Repository) countApplicationsQuery(params ListApplicationsParams, visibleUserID string) (string, []any, error) {
	if _, err := storage.NormalizeListOptions(params.ListOptions); err != nil {
		return "", nil, err
	}
	var args []any
	var where []string
	join := ""
	if visibleUserID != "" {
		args = append(args, visibleUserID)
		join = fmt.Sprintf(" join application_user_grants visible_grants on visible_grants.application_id = a.id and visible_grants.user_id = $%d", len(args))
	}
	if params.Status != nil {
		if err := validateStatus(*params.Status); err != nil {
			return "", nil, err
		}
		args = append(args, string(*params.Status))
		where = append(where, fmt.Sprintf("a.status = $%d", len(args)))
	}
	if params.Search != "" {
		if err := storage.ValidateHumanString(params.Search, "search", 1, 255); err != nil {
			return "", nil, err
		}
		args = append(args, "%"+strings.ToLower(params.Search)+"%")
		where = append(where, fmt.Sprintf("(a.name like $%d or lower(a.display_name) like $%d)", len(args), len(args)))
	}
	query := `select count(*)::bigint from applications a` + join
	if len(where) > 0 {
		query += " where " + strings.Join(where, " and ")
	}
	return query, args, nil
}

func (r Repository) Update(ctx context.Context, id string, params UpdateApplicationParams) (Application, error) {
	if err := storage.ValidateUUID(id, "application_id"); err != nil {
		return Application{}, err
	}
	if err := validateUpdateApplication(&params); err != nil {
		return Application{}, err
	}
	var sets []string
	var args []any
	add := func(column string, value any) {
		args = append(args, value)
		sets = append(sets, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	if params.DisplayName.Set {
		add("display_name", valueOrNil(params.DisplayName.Value))
	}
	if params.Status.Set {
		add("status", valueOrNil(params.Status.Value))
	}
	if params.Description.Set {
		add("description", valueOrNil(params.Description.Value))
	}
	if params.TrustedSourceCIDRs != nil {
		add("trusted_source_cidrs", *params.TrustedSourceCIDRs)
		sets[len(sets)-1] += "::cidr[]"
	}
	if len(sets) == 0 {
		return r.Get(ctx, id)
	}
	sets = append(sets, "updated_at = now()")
	args = append(args, id)
	app, err := scanApplication(r.db.QueryRow(ctx, fmt.Sprintf(`
update applications
set %s
where id = $%d
returning `+applicationReturningSQL(), strings.Join(sets, ", "), len(args)), args...))
	if err != nil {
		return Application{}, fmt.Errorf("update application: %w", err)
	}
	return app, nil
}

func (r Repository) CreateToken(ctx context.Context, params CreateTokenParams) (ApplicationToken, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return ApplicationToken{}, err
		}
		params.ID = id
	}
	if err := validateCreateToken(params); err != nil {
		return ApplicationToken{}, err
	}
	token, err := scanToken(r.db.QueryRow(ctx, `
insert into application_tokens (id, application_id, name, token_hash, expires_at)
values ($1, $2, $3, $4, $5)
returning `+tokenReturningSQL(),
		params.ID, params.ApplicationID, params.Name, params.TokenHash, params.ExpiresAt))
	if err != nil {
		return ApplicationToken{}, fmt.Errorf("create application token: %w", err)
	}
	return token, nil
}

func (r Repository) LookupTokenByHash(ctx context.Context, tokenHash string) (TokenIdentity, error) {
	if err := storage.ValidateTokenHash(tokenHash, "token_hash"); err != nil {
		return TokenIdentity{}, err
	}
	row := r.db.QueryRow(ctx, `
select `+prefixedTokenColumnsSQL("t")+`, `+applicationSelectColumnsSQL()+`
from application_tokens t
join applications a on a.id = t.application_id
where t.token_hash = $1`, tokenHash)
	token, app, err := scanTokenIdentity(row)
	if err != nil {
		return TokenIdentity{}, fmt.Errorf("lookup application token: %w", err)
	}
	return TokenIdentity{Token: token, Application: app}, nil
}

func (r Repository) MarkTokenUsed(ctx context.Context, tokenID string) error {
	if err := storage.ValidateUUID(tokenID, "token_id"); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx, `
update application_tokens
set last_used_at = now()
where id = $1
  and status = 'active'`, tokenID)
	if err != nil {
		return fmt.Errorf("mark application token used: %w", err)
	}
	return nil
}

func (r Repository) RotateToken(ctx context.Context, params RotateTokenParams) (ApplicationToken, error) {
	if err := validateRotateToken(params); err != nil {
		return ApplicationToken{}, err
	}
	token, err := scanToken(r.db.QueryRow(ctx, `
update application_tokens
set token_hash = $3,
    expires_at = $4,
    last_used_at = null
where application_id = $1
  and id = $2
  and status = 'active'
returning `+tokenReturningSQL(), params.ApplicationID, params.TokenID, params.TokenHash, params.ExpiresAt))
	if err != nil {
		return ApplicationToken{}, fmt.Errorf("rotate application token: %w", err)
	}
	return token, nil
}

func (r Repository) ListTokens(ctx context.Context, applicationID string, params ListTokensParams) ([]ApplicationToken, error) {
	if err := storage.ValidateUUID(applicationID, "application_id"); err != nil {
		return nil, err
	}
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return nil, err
	}
	var args []any
	var where []string
	args = append(args, applicationID)
	where = append(where, fmt.Sprintf("application_id = $%d", len(args)))
	if params.Status != nil {
		if err := validateTokenStatus(*params.Status); err != nil {
			return nil, err
		}
		args = append(args, string(*params.Status))
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	args = append(args, opts.Limit, opts.Offset)
	query := `
select ` + tokenReturningSQL() + `
from application_tokens
where ` + strings.Join(where, " and ") + fmt.Sprintf(`
order by created_at desc, id desc
limit $%d offset $%d`, len(args)-1, len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list application tokens: %w", err)
	}
	defer rows.Close()
	var tokens []ApplicationToken
	for rows.Next() {
		token, err := scanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("list application tokens: %w", err)
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list application tokens: %w", err)
	}
	return tokens, nil
}

func (r Repository) CountTokens(ctx context.Context, applicationID string, params ListTokensParams) (int64, error) {
	if err := storage.ValidateUUID(applicationID, "application_id"); err != nil {
		return 0, err
	}
	if _, err := storage.NormalizeListOptions(params.ListOptions); err != nil {
		return 0, err
	}
	var args []any
	var where []string
	args = append(args, applicationID)
	where = append(where, fmt.Sprintf("application_id = $%d", len(args)))
	if params.Status != nil {
		if err := validateTokenStatus(*params.Status); err != nil {
			return 0, err
		}
		args = append(args, string(*params.Status))
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	var total int64
	if err := r.db.QueryRow(ctx, `select count(*)::bigint from application_tokens where `+strings.Join(where, " and "), args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("count application tokens: %w", err)
	}
	return total, nil
}

func (r Repository) RevokeToken(ctx context.Context, applicationID, tokenID string) (bool, error) {
	if err := storage.ValidateUUID(applicationID, "application_id"); err != nil {
		return false, err
	}
	if err := storage.ValidateUUID(tokenID, "token_id"); err != nil {
		return false, err
	}
	tag, err := r.db.Exec(ctx, `
update application_tokens
set status = 'revoked',
    revoked_at = coalesce(revoked_at, now())
where application_id = $1
  and id = $2`, applicationID, tokenID)
	if err != nil {
		return false, fmt.Errorf("revoke application token: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r Repository) AddDomainScope(ctx context.Context, params AddDomainScopeParams) (DomainScope, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return DomainScope{}, err
		}
		params.ID = id
	}
	if err := validateAddDomainScope(&params); err != nil {
		return DomainScope{}, err
	}
	scope, err := scanDomainScope(r.db.QueryRow(ctx, `
insert into application_domain_scopes (id, application_id, value, created_by_user_id)
values ($1, $2, $3, $4)
returning id, application_id, value, created_at, created_by_user_id`,
		params.ID, params.ApplicationID, params.Value, params.CreatedByUserID))
	if err != nil {
		return DomainScope{}, fmt.Errorf("add application domain scope: %w", err)
	}
	return scope, nil
}

func (r Repository) ReplaceSystemDomainScopes(ctx context.Context, applicationID, value string) ([]DomainScope, error) {
	if err := storage.ValidateUUID(applicationID, "application_id"); err != nil {
		return nil, err
	}
	normalized, err := storage.NormalizeDomainScopeValue(value)
	if err != nil {
		return nil, err
	}
	id, err := storage.NewUUID()
	if err != nil {
		return nil, err
	}
	if _, err := r.db.Exec(ctx, `
delete from application_domain_scopes s
using applications a
where s.application_id = $1
  and a.id = s.application_id
  and a.system_kind = 'certhub_server'
  and s.value <> $2`, applicationID, normalized); err != nil {
		return nil, fmt.Errorf("replace system application domain scopes: %w", err)
	}
	if _, err := r.db.Exec(ctx, `
insert into application_domain_scopes (id, application_id, value, created_by_user_id)
select $3, a.id, $2, null
from applications a
where a.id = $1
  and a.system_kind = 'certhub_server'
on conflict (application_id, value) do nothing`, applicationID, normalized, id); err != nil {
		return nil, fmt.Errorf("replace system application domain scopes: %w", err)
	}
	return r.ListDomainScopes(ctx, applicationID, storage.ListOptions{Limit: storage.MaxListLimit})
}

func (r Repository) ListDomainScopes(ctx context.Context, applicationID string, opts storage.ListOptions) ([]DomainScope, error) {
	if err := storage.ValidateUUID(applicationID, "application_id"); err != nil {
		return nil, err
	}
	opts, err := storage.NormalizeListOptions(opts)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `
select id, application_id, value, created_at, created_by_user_id
from application_domain_scopes
where application_id = $1
order by value asc, id asc
limit $2 offset $3`, applicationID, opts.Limit, opts.Offset)
	if err != nil {
		return nil, fmt.Errorf("list application domain scopes: %w", err)
	}
	defer rows.Close()
	var scopes []DomainScope
	for rows.Next() {
		scope, err := scanDomainScope(rows)
		if err != nil {
			return nil, fmt.Errorf("list application domain scopes: %w", err)
		}
		scopes = append(scopes, scope)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list application domain scopes: %w", err)
	}
	return scopes, nil
}

func (r Repository) CountDomainScopes(ctx context.Context, applicationID string, opts storage.ListOptions) (int64, error) {
	if err := storage.ValidateUUID(applicationID, "application_id"); err != nil {
		return 0, err
	}
	if _, err := storage.NormalizeListOptions(opts); err != nil {
		return 0, err
	}
	var total int64
	if err := r.db.QueryRow(ctx, `
select count(*)::bigint
from application_domain_scopes
where application_id = $1`, applicationID).Scan(&total); err != nil {
		return 0, fmt.Errorf("count application domain scopes: %w", err)
	}
	return total, nil
}

func (r Repository) DeleteDomainScope(ctx context.Context, applicationID, scopeID string) (bool, error) {
	if err := storage.ValidateUUID(applicationID, "application_id"); err != nil {
		return false, err
	}
	if err := storage.ValidateUUID(scopeID, "scope_id"); err != nil {
		return false, err
	}
	tag, err := r.db.Exec(ctx, `
delete from application_domain_scopes
where application_id = $1
  and id = $2`, applicationID, scopeID)
	if err != nil {
		return false, fmt.Errorf("delete application domain scope: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r Repository) UpsertGrant(ctx context.Context, params UpsertGrantParams) (UserGrant, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return UserGrant{}, err
		}
		params.ID = id
	}
	if err := validateUpsertGrant(params); err != nil {
		return UserGrant{}, err
	}
	grant, err := scanGrant(r.db.QueryRow(ctx, `
insert into application_user_grants (id, application_id, user_id, role, created_by_user_id)
values ($1, $2, $3, $4, $5)
on conflict (application_id, user_id) do update
set role = excluded.role,
    created_by_user_id = excluded.created_by_user_id
returning id, application_id, user_id, role, created_at, created_by_user_id`,
		params.ID, params.ApplicationID, params.UserID, string(params.Role), params.CreatedByUserID))
	if err != nil {
		return UserGrant{}, fmt.Errorf("upsert application user grant: %w", err)
	}
	return grant, nil
}

func (r Repository) ListGrants(ctx context.Context, applicationID string, opts storage.ListOptions) ([]UserGrant, error) {
	if err := storage.ValidateUUID(applicationID, "application_id"); err != nil {
		return nil, err
	}
	opts, err := storage.NormalizeListOptions(opts)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `
select id, application_id, user_id, role, created_at, created_by_user_id
from application_user_grants
where application_id = $1
order by created_at desc, id desc
limit $2 offset $3`, applicationID, opts.Limit, opts.Offset)
	if err != nil {
		return nil, fmt.Errorf("list application user grants: %w", err)
	}
	defer rows.Close()
	var grants []UserGrant
	for rows.Next() {
		grant, err := scanGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("list application user grants: %w", err)
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list application user grants: %w", err)
	}
	return grants, nil
}

func (r Repository) CountGrants(ctx context.Context, applicationID string, opts storage.ListOptions) (int64, error) {
	if err := storage.ValidateUUID(applicationID, "application_id"); err != nil {
		return 0, err
	}
	if _, err := storage.NormalizeListOptions(opts); err != nil {
		return 0, err
	}
	var total int64
	if err := r.db.QueryRow(ctx, `
select count(*)::bigint
from application_user_grants
where application_id = $1`, applicationID).Scan(&total); err != nil {
		return 0, fmt.Errorf("count application user grants: %w", err)
	}
	return total, nil
}

func (r Repository) GetGrant(ctx context.Context, applicationID, userID string) (UserGrant, error) {
	if err := storage.ValidateUUID(applicationID, "application_id"); err != nil {
		return UserGrant{}, err
	}
	if err := storage.ValidateUUID(userID, "user_id"); err != nil {
		return UserGrant{}, err
	}
	grant, err := scanGrant(r.db.QueryRow(ctx, `
select id, application_id, user_id, role, created_at, created_by_user_id
from application_user_grants
where application_id = $1
  and user_id = $2`, applicationID, userID))
	if err != nil {
		return UserGrant{}, fmt.Errorf("get application user grant: %w", err)
	}
	return grant, nil
}

func (r Repository) DeleteGrant(ctx context.Context, applicationID, userID string) (bool, error) {
	if err := storage.ValidateUUID(applicationID, "application_id"); err != nil {
		return false, err
	}
	if err := storage.ValidateUUID(userID, "user_id"); err != nil {
		return false, err
	}
	tag, err := r.db.Exec(ctx, `
delete from application_user_grants
where application_id = $1
  and user_id = $2`, applicationID, userID)
	if err != nil {
		return false, fmt.Errorf("delete application user grant: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r Repository) getWhere(ctx context.Context, predicate string, args ...any) (Application, error) {
	app, err := scanApplication(r.db.QueryRow(ctx, `select `+applicationSelectColumnsSQL()+` from applications a where `+predicate, args...))
	if err != nil {
		return Application{}, fmt.Errorf("get application: %w", err)
	}
	return app, nil
}

func applicationSelectColumnsSQL() string {
	return `a.id, a.name, a.display_name, a.status, a.system_kind, a.description,
    array(select cidr_value::text from unnest(a.trusted_source_cidrs) as cidr_value),
    a.created_at, a.updated_at,
    (select count(*) from application_domain_scopes where application_id = a.id)::bigint,
    (select count(*) from application_tokens where application_id = a.id)::bigint,
    (select count(*) from application_user_grants where application_id = a.id)::bigint,
    (select count(*) from certificates where application_id = a.id and deleted_at is null)::bigint,
    cardinality(a.trusted_source_cidrs)::bigint`
}

func applicationReturningSQL() string {
	return `id, name, display_name, status, system_kind, description,
    array(select cidr_value::text from unnest(trusted_source_cidrs) as cidr_value),
    created_at, updated_at,
    (select count(*) from application_domain_scopes where application_id = applications.id)::bigint,
    (select count(*) from application_tokens where application_id = applications.id)::bigint,
    (select count(*) from application_user_grants where application_id = applications.id)::bigint,
    (select count(*) from certificates where application_id = applications.id and deleted_at is null)::bigint,
    cardinality(trusted_source_cidrs)::bigint`
}

func tokenReturningSQL() string {
	return `id, application_id, name, token_hash, status, created_at, expires_at, last_used_at, revoked_at`
}

func prefixedTokenColumnsSQL(prefix string) string {
	return prefix + `.id, ` + prefix + `.application_id, ` + prefix + `.name, ` + prefix + `.token_hash, ` +
		prefix + `.status, ` + prefix + `.created_at, ` + prefix + `.expires_at, ` + prefix + `.last_used_at, ` + prefix + `.revoked_at`
}

type scanner interface {
	Scan(...any) error
}

func scanApplication(row scanner) (Application, error) {
	var app Application
	var status string
	var systemKind, description sql.NullString
	if err := row.Scan(
		&app.ID,
		&app.Name,
		&app.DisplayName,
		&status,
		&systemKind,
		&description,
		&app.TrustedSourceCIDRs,
		&app.CreatedAt,
		&app.UpdatedAt,
		&app.DomainScopeCount,
		&app.TokenCount,
		&app.UserGrantCount,
		&app.CertificateCount,
		&app.TrustedSourceCIDRCount,
	); err != nil {
		return Application{}, err
	}
	app.Status = Status(status)
	if systemKind.Valid {
		kind := SystemKind(systemKind.String)
		app.SystemKind = &kind
	}
	app.Description = stringPtr(description)
	if app.TrustedSourceCIDRs == nil {
		app.TrustedSourceCIDRs = []string{}
	}
	return app, nil
}

func scanToken(row scanner) (ApplicationToken, error) {
	var token ApplicationToken
	var status string
	var expiresAt, lastUsedAt, revokedAt sql.NullTime
	if err := row.Scan(
		&token.ID,
		&token.ApplicationID,
		&token.Name,
		&token.TokenHash,
		&status,
		&token.CreatedAt,
		&expiresAt,
		&lastUsedAt,
		&revokedAt,
	); err != nil {
		return ApplicationToken{}, err
	}
	token.Status = TokenStatus(status)
	token.ExpiresAt = timePtr(expiresAt)
	token.LastUsedAt = timePtr(lastUsedAt)
	token.RevokedAt = timePtr(revokedAt)
	return token, nil
}

func scanTokenIdentity(row scanner) (ApplicationToken, Application, error) {
	var token ApplicationToken
	var app Application
	var tokenStatus, appStatus string
	var expiresAt, lastUsedAt, revokedAt sql.NullTime
	var systemKind, description sql.NullString
	if err := row.Scan(
		&token.ID,
		&token.ApplicationID,
		&token.Name,
		&token.TokenHash,
		&tokenStatus,
		&token.CreatedAt,
		&expiresAt,
		&lastUsedAt,
		&revokedAt,
		&app.ID,
		&app.Name,
		&app.DisplayName,
		&appStatus,
		&systemKind,
		&description,
		&app.TrustedSourceCIDRs,
		&app.CreatedAt,
		&app.UpdatedAt,
		&app.DomainScopeCount,
		&app.TokenCount,
		&app.UserGrantCount,
		&app.CertificateCount,
		&app.TrustedSourceCIDRCount,
	); err != nil {
		return ApplicationToken{}, Application{}, err
	}
	token.Status = TokenStatus(tokenStatus)
	token.ExpiresAt = timePtr(expiresAt)
	token.LastUsedAt = timePtr(lastUsedAt)
	token.RevokedAt = timePtr(revokedAt)
	app.Status = Status(appStatus)
	if systemKind.Valid {
		kind := SystemKind(systemKind.String)
		app.SystemKind = &kind
	}
	app.Description = stringPtr(description)
	if app.TrustedSourceCIDRs == nil {
		app.TrustedSourceCIDRs = []string{}
	}
	return token, app, nil
}

func scanDomainScope(row scanner) (DomainScope, error) {
	var scope DomainScope
	var createdBy sql.NullString
	if err := row.Scan(&scope.ID, &scope.ApplicationID, &scope.Value, &scope.CreatedAt, &createdBy); err != nil {
		return DomainScope{}, err
	}
	scope.CreatedByUserID = stringPtr(createdBy)
	if strings.HasPrefix(scope.Value, "*.") {
		scope.Kind = DomainScopeKindWildcard
	} else {
		scope.Kind = DomainScopeKindExact
	}
	return scope, nil
}

func scanGrant(row scanner) (UserGrant, error) {
	var grant UserGrant
	var role string
	var createdBy sql.NullString
	if err := row.Scan(&grant.ID, &grant.ApplicationID, &grant.UserID, &role, &grant.CreatedAt, &createdBy); err != nil {
		return UserGrant{}, err
	}
	grant.Role = GrantRole(role)
	grant.CreatedByUserID = stringPtr(createdBy)
	return grant, nil
}

func validateCreateApplication(params *CreateApplicationParams) error {
	if err := storage.ValidateUUID(params.ID, "application_id"); err != nil {
		return err
	}
	if err := storage.ValidateMachineName(params.Name, "application_name"); err != nil {
		return err
	}
	if err := storage.ValidateHumanString(params.DisplayName, "display_name", 1, 255); err != nil {
		return err
	}
	if params.Status == "" {
		params.Status = StatusActive
	}
	if err := validateStatus(params.Status); err != nil {
		return err
	}
	if params.SystemKind != nil {
		if *params.SystemKind != SystemKindCerthubServer {
			return errors.New("system_kind is invalid")
		}
		if params.Name != string(SystemKindCerthubServer) {
			return errors.New("certhub_server system_kind requires certhub_server name")
		}
	}
	if params.Name == string(SystemKindCerthubServer) && (params.SystemKind == nil || *params.SystemKind != SystemKindCerthubServer) {
		return errors.New("certhub_server application name is reserved")
	}
	if err := storage.ValidateOptionalHumanString(params.Description, "description", 2048); err != nil {
		return err
	}
	cidrs, err := storage.NormalizeTrustedSourceCIDRs(params.TrustedSourceCIDRs)
	if err != nil {
		return err
	}
	params.TrustedSourceCIDRs = cidrs
	return nil
}

func validateUpdateApplication(params *UpdateApplicationParams) error {
	if params.DisplayName.Set && params.DisplayName.Value == nil {
		return errors.New("display_name cannot be null")
	}
	if params.DisplayName.Set {
		if err := storage.ValidateHumanString(*params.DisplayName.Value, "display_name", 1, 255); err != nil {
			return err
		}
	}
	if params.Status.Set && params.Status.Value == nil {
		return errors.New("status cannot be null")
	}
	if params.Status.Set {
		if err := validateStatus(Status(*params.Status.Value)); err != nil {
			return err
		}
	}
	if params.Description.Set {
		if err := storage.ValidateOptionalHumanString(params.Description.Value, "description", 2048); err != nil {
			return err
		}
	}
	if params.TrustedSourceCIDRs != nil {
		cidrs, err := storage.NormalizeTrustedSourceCIDRs(*params.TrustedSourceCIDRs)
		if err != nil {
			return err
		}
		*params.TrustedSourceCIDRs = cidrs
	}
	return nil
}

func validateCreateToken(params CreateTokenParams) error {
	if err := storage.ValidateUUID(params.ID, "token_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.ApplicationID, "application_id"); err != nil {
		return err
	}
	if err := storage.ValidateHumanString(params.Name, "token_name", 1, 128); err != nil {
		return err
	}
	return storage.ValidateTokenHash(params.TokenHash, "token_hash")
}

func validateRotateToken(params RotateTokenParams) error {
	if err := storage.ValidateUUID(params.ApplicationID, "application_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.TokenID, "token_id"); err != nil {
		return err
	}
	return storage.ValidateTokenHash(params.TokenHash, "token_hash")
}

func validateAddDomainScope(params *AddDomainScopeParams) error {
	if err := storage.ValidateUUID(params.ID, "scope_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.ApplicationID, "application_id"); err != nil {
		return err
	}
	value, err := storage.NormalizeDomainScopeValue(params.Value)
	if err != nil {
		return err
	}
	params.Value = value
	if params.CreatedByUserID != nil {
		return storage.ValidateUUID(*params.CreatedByUserID, "created_by_user_id")
	}
	return nil
}

func validateUpsertGrant(params UpsertGrantParams) error {
	if err := storage.ValidateUUID(params.ID, "grant_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.ApplicationID, "application_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.UserID, "user_id"); err != nil {
		return err
	}
	if err := validateGrantRole(params.Role); err != nil {
		return err
	}
	if params.CreatedByUserID != nil {
		return storage.ValidateUUID(*params.CreatedByUserID, "created_by_user_id")
	}
	return nil
}

func validateStatus(status Status) error {
	switch status {
	case StatusActive, StatusDisabled:
		return nil
	default:
		return errors.New("status is invalid")
	}
}

func validateGrantRole(role GrantRole) error {
	switch role {
	case GrantRoleViewer, GrantRoleCertificateReader, GrantRoleManager:
		return nil
	default:
		return errors.New("grant role is invalid")
	}
}

func validateTokenStatus(status TokenStatus) error {
	switch status {
	case TokenStatusActive, TokenStatusRevoked:
		return nil
	default:
		return errors.New("token status is invalid")
	}
}

func systemKindValue(kind *SystemKind) any {
	if kind == nil {
		return nil
	}
	return string(*kind)
}

func valueOrNil(value *string) any {
	if value == nil {
		return nil
	}
	return *value
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
