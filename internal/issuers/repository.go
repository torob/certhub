package issuers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/torob/certhub/internal/storage"
)

type Type string

const TypeACME Type = "acme"

type Environment string

const (
	EnvironmentProduction Environment = "production"
	EnvironmentStaging    Environment = "staging"
)

type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

type ACMEAccountStatus string

const (
	ACMEAccountStatusActive   ACMEAccountStatus = "active"
	ACMEAccountStatusDisabled ACMEAccountStatus = "disabled"
)

type Issuer struct {
	ID                   string
	Name                 string
	Type                 Type
	DirectoryURL         string
	Environment          Environment
	IsDefault            bool
	Status               Status
	RenewalWindowSeconds int
	ContactEmail         string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	ACMEAccountCount     int64
	ActiveACMEAccount    bool
}

type ACMEAccount struct {
	ID                     string
	IssuerID               string
	Email                  string
	AccountURL             string
	PrivateKeyPEMEncrypted string
	Status                 ACMEAccountStatus
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

type Repository struct {
	db storage.DBTX
}

func NewRepository(db storage.DBTX) Repository {
	return Repository{db: db}
}

type CreateIssuerParams struct {
	ID                   string
	Name                 string
	Type                 Type
	DirectoryURL         string
	Environment          Environment
	IsDefault            bool
	Status               Status
	RenewalWindowSeconds int
	ContactEmail         string
}

type UpdateIssuerParams struct {
	IsDefault            storage.OptionalBool
	Status               storage.OptionalString
	RenewalWindowSeconds storage.OptionalInt
	ContactEmail         storage.OptionalString
}

type ListIssuersParams struct {
	storage.ListOptions
	Status      *Status
	Environment *Environment
	Search      string
}

type CreateACMEAccountParams struct {
	ID                     string
	IssuerID               string
	Email                  string
	AccountURL             string
	PrivateKeyPEMEncrypted string
	Status                 ACMEAccountStatus
}

type ListACMEAccountsParams struct {
	storage.ListOptions
	Status *ACMEAccountStatus
}

func (r Repository) Create(ctx context.Context, params CreateIssuerParams) (Issuer, error) {
	if r.db == nil {
		return Issuer{}, errors.New("issuers repository storage is required")
	}
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return Issuer{}, err
		}
		params.ID = id
	}
	if err := validateCreateIssuer(&params); err != nil {
		return Issuer{}, err
	}
	issuer, err := scanIssuer(r.db.QueryRow(ctx, `
insert into issuers (
    id, name, type, directory_url, environment, is_default,
    status, renewal_window_seconds, contact_email
) values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
returning `+issuerReturningSQL(),
		params.ID, params.Name, string(params.Type), params.DirectoryURL, string(params.Environment),
		params.IsDefault, string(params.Status), params.RenewalWindowSeconds, params.ContactEmail))
	if err != nil {
		return Issuer{}, fmt.Errorf("create issuer: %w", err)
	}
	return issuer, nil
}

func (r Repository) Get(ctx context.Context, id string) (Issuer, error) {
	if err := storage.ValidateUUID(id, "issuer_id"); err != nil {
		return Issuer{}, err
	}
	return r.getWhere(ctx, "i.id = $1", id)
}

func (r Repository) GetByName(ctx context.Context, name string) (Issuer, error) {
	if err := storage.ValidateMachineName(name, "issuer_name"); err != nil {
		return Issuer{}, err
	}
	return r.getWhere(ctx, "i.name = $1", name)
}

func (r Repository) GetActiveDefault(ctx context.Context) (Issuer, error) {
	return r.getWhere(ctx, "i.status = 'active' and i.is_default")
}

func (r Repository) List(ctx context.Context, params ListIssuersParams) ([]Issuer, error) {
	query, args, err := r.listQuery(params)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list issuers: %w", err)
	}
	defer rows.Close()
	var issuers []Issuer
	for rows.Next() {
		issuer, err := scanIssuer(rows)
		if err != nil {
			return nil, fmt.Errorf("list issuers: %w", err)
		}
		issuers = append(issuers, issuer)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list issuers: %w", err)
	}
	return issuers, nil
}

func (r Repository) Count(ctx context.Context, params ListIssuersParams) (int64, error) {
	query, args, err := r.countQuery(params)
	if err != nil {
		return 0, err
	}
	var total int64
	if err := r.db.QueryRow(ctx, query, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("count issuers: %w", err)
	}
	return total, nil
}

func (r Repository) Update(ctx context.Context, id string, params UpdateIssuerParams) (Issuer, error) {
	if err := storage.ValidateUUID(id, "issuer_id"); err != nil {
		return Issuer{}, err
	}
	if err := validateUpdateIssuer(&params); err != nil {
		return Issuer{}, err
	}
	var sets []string
	var args []any
	add := func(column string, value any) {
		args = append(args, value)
		sets = append(sets, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	if params.IsDefault.Set {
		add("is_default", params.IsDefault.Value)
	}
	if params.Status.Set {
		add("status", *params.Status.Value)
	}
	if params.RenewalWindowSeconds.Set {
		add("renewal_window_seconds", params.RenewalWindowSeconds.Value)
	}
	if params.ContactEmail.Set {
		add("contact_email", *params.ContactEmail.Value)
	}
	if len(sets) == 0 {
		return r.Get(ctx, id)
	}
	if params.Status.Set && Status(*params.Status.Value) == StatusActive {
		if _, err := r.GetActiveACMEAccount(ctx, id); err != nil {
			if errors.Is(err, storage.ErrNoRows) {
				return Issuer{}, errors.New("active issuers require an active ACME account")
			}
			return Issuer{}, err
		}
	}
	sets = append(sets, "updated_at = now()")
	args = append(args, id)
	issuer, err := scanIssuer(r.db.QueryRow(ctx, fmt.Sprintf(`
update issuers
set %s
where id = $%d
returning `+issuerReturningSQL(), strings.Join(sets, ", "), len(args)), args...))
	if err != nil {
		return Issuer{}, fmt.Errorf("update issuer: %w", err)
	}
	return issuer, nil
}

func (r Repository) CreateACMEAccount(ctx context.Context, params CreateACMEAccountParams) (ACMEAccount, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return ACMEAccount{}, err
		}
		params.ID = id
	}
	if err := validateCreateACMEAccount(&params); err != nil {
		return ACMEAccount{}, err
	}
	account, err := scanACMEAccount(r.db.QueryRow(ctx, `
insert into acme_accounts (id, issuer_id, email, account_url, private_key_pem, status)
values ($1, $2, $3, $4, $5, $6)
returning `+acmeAccountReturningSQL(),
		params.ID, params.IssuerID, params.Email, params.AccountURL, params.PrivateKeyPEMEncrypted, string(params.Status)))
	if err != nil {
		return ACMEAccount{}, fmt.Errorf("create acme account: %w", err)
	}
	return account, nil
}

func (r Repository) EnsureACMEAccount(ctx context.Context, params CreateACMEAccountParams) (ACMEAccount, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return ACMEAccount{}, err
		}
		params.ID = id
	}
	if err := validateCreateACMEAccount(&params); err != nil {
		return ACMEAccount{}, err
	}
	account, err := scanACMEAccount(r.db.QueryRow(ctx, `
insert into acme_accounts (id, issuer_id, email, account_url, private_key_pem, status)
values ($1, $2, $3, $4, $5, $6)
on conflict (account_url) do update
set updated_at = acme_accounts.updated_at
returning `+acmeAccountReturningSQL(),
		params.ID, params.IssuerID, params.Email, params.AccountURL, params.PrivateKeyPEMEncrypted, string(params.Status)))
	if err != nil {
		return ACMEAccount{}, fmt.Errorf("ensure acme account: %w", err)
	}
	return account, nil
}

func (r Repository) GetActiveACMEAccount(ctx context.Context, issuerID string) (ACMEAccount, error) {
	if err := storage.ValidateUUID(issuerID, "issuer_id"); err != nil {
		return ACMEAccount{}, err
	}
	account, err := scanACMEAccount(r.db.QueryRow(ctx, `
select `+acmeAccountReturningSQL()+`
from acme_accounts
where issuer_id = $1
  and status = 'active'`, issuerID))
	if err != nil {
		return ACMEAccount{}, fmt.Errorf("get active acme account: %w", err)
	}
	return account, nil
}

func (r Repository) ListACMEAccounts(ctx context.Context, issuerID string, params ListACMEAccountsParams) ([]ACMEAccount, error) {
	if err := storage.ValidateUUID(issuerID, "issuer_id"); err != nil {
		return nil, err
	}
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return nil, err
	}
	var args []any
	var where []string
	args = append(args, issuerID)
	where = append(where, fmt.Sprintf("issuer_id = $%d", len(args)))
	if params.Status != nil {
		if err := validateACMEAccountStatus(*params.Status); err != nil {
			return nil, err
		}
		args = append(args, string(*params.Status))
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	args = append(args, opts.Limit, opts.Offset)
	rows, err := r.db.Query(ctx, `
select `+acmeAccountReturningSQL()+`
from acme_accounts
where `+strings.Join(where, " and ")+fmt.Sprintf(`
order by created_at desc, id desc
limit $%d offset $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list acme accounts: %w", err)
	}
	defer rows.Close()
	var accounts []ACMEAccount
	for rows.Next() {
		account, err := scanACMEAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("list acme accounts: %w", err)
		}
		accounts = append(accounts, account)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list acme accounts: %w", err)
	}
	return accounts, nil
}

func (r Repository) UpdateACMEAccountStatus(ctx context.Context, accountID string, status ACMEAccountStatus) (ACMEAccount, error) {
	if err := storage.ValidateUUID(accountID, "acme_account_id"); err != nil {
		return ACMEAccount{}, err
	}
	if err := validateACMEAccountStatus(status); err != nil {
		return ACMEAccount{}, err
	}
	account, err := scanACMEAccount(r.db.QueryRow(ctx, `
update acme_accounts
set status = $1,
    updated_at = now()
where id = $2
returning `+acmeAccountReturningSQL(), string(status), accountID))
	if err != nil {
		return ACMEAccount{}, fmt.Errorf("update acme account status: %w", err)
	}
	return account, nil
}

func (r Repository) getWhere(ctx context.Context, predicate string, args ...any) (Issuer, error) {
	issuer, err := scanIssuer(r.db.QueryRow(ctx, `select `+issuerSelectColumnsSQL()+` from issuers i where `+predicate, args...))
	if err != nil {
		return Issuer{}, fmt.Errorf("get issuer: %w", err)
	}
	return issuer, nil
}

func (r Repository) listQuery(params ListIssuersParams) (string, []any, error) {
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return "", nil, err
	}
	var args []any
	var where []string
	if params.Status != nil {
		if err := validateStatus(*params.Status); err != nil {
			return "", nil, err
		}
		args = append(args, string(*params.Status))
		where = append(where, fmt.Sprintf("i.status = $%d", len(args)))
	}
	if params.Environment != nil {
		if err := validateEnvironment(*params.Environment); err != nil {
			return "", nil, err
		}
		args = append(args, string(*params.Environment))
		where = append(where, fmt.Sprintf("i.environment = $%d", len(args)))
	}
	if params.Search != "" {
		if err := storage.ValidateHumanString(params.Search, "search", 1, 255); err != nil {
			return "", nil, err
		}
		args = append(args, "%"+strings.ToLower(params.Search)+"%")
		where = append(where, fmt.Sprintf("(i.name like $%d or lower(i.contact_email) like $%d)", len(args), len(args)))
	}
	args = append(args, opts.Limit, opts.Offset)
	query := `select ` + issuerSelectColumnsSQL() + ` from issuers i`
	if len(where) > 0 {
		query += " where " + strings.Join(where, " and ")
	}
	query += fmt.Sprintf(" order by i.created_at desc, i.id desc limit $%d offset $%d", len(args)-1, len(args))
	return query, args, nil
}

func (r Repository) countQuery(params ListIssuersParams) (string, []any, error) {
	if _, err := storage.NormalizeListOptions(params.ListOptions); err != nil {
		return "", nil, err
	}
	var args []any
	var where []string
	if params.Status != nil {
		if err := validateStatus(*params.Status); err != nil {
			return "", nil, err
		}
		args = append(args, string(*params.Status))
		where = append(where, fmt.Sprintf("i.status = $%d", len(args)))
	}
	if params.Environment != nil {
		if err := validateEnvironment(*params.Environment); err != nil {
			return "", nil, err
		}
		args = append(args, string(*params.Environment))
		where = append(where, fmt.Sprintf("i.environment = $%d", len(args)))
	}
	if params.Search != "" {
		if err := storage.ValidateHumanString(params.Search, "search", 1, 255); err != nil {
			return "", nil, err
		}
		args = append(args, "%"+strings.ToLower(params.Search)+"%")
		where = append(where, fmt.Sprintf("(i.name like $%d or lower(i.contact_email) like $%d)", len(args), len(args)))
	}
	query := `select count(*)::bigint from issuers i`
	if len(where) > 0 {
		query += " where " + strings.Join(where, " and ")
	}
	return query, args, nil
}

func issuerSelectColumnsSQL() string {
	return `i.id, i.name, i.type, i.directory_url, i.environment, i.is_default, i.status,
    i.renewal_window_seconds, i.contact_email, i.created_at, i.updated_at,
    (select count(*) from acme_accounts where issuer_id = i.id)::bigint,
    exists(select 1 from acme_accounts where issuer_id = i.id and status = 'active')`
}

func issuerReturningSQL() string {
	return `id, name, type, directory_url, environment, is_default, status,
    renewal_window_seconds, contact_email, created_at, updated_at,
    (select count(*) from acme_accounts where issuer_id = issuers.id)::bigint,
    exists(select 1 from acme_accounts where issuer_id = issuers.id and status = 'active')`
}

func acmeAccountReturningSQL() string {
	return `id, issuer_id, email, account_url, private_key_pem, status, created_at, updated_at`
}

type scanner interface {
	Scan(...any) error
}

func scanIssuer(row scanner) (Issuer, error) {
	var issuer Issuer
	var typ, environment, status string
	if err := row.Scan(
		&issuer.ID,
		&issuer.Name,
		&typ,
		&issuer.DirectoryURL,
		&environment,
		&issuer.IsDefault,
		&status,
		&issuer.RenewalWindowSeconds,
		&issuer.ContactEmail,
		&issuer.CreatedAt,
		&issuer.UpdatedAt,
		&issuer.ACMEAccountCount,
		&issuer.ActiveACMEAccount,
	); err != nil {
		return Issuer{}, err
	}
	issuer.Type = Type(typ)
	issuer.Environment = Environment(environment)
	issuer.Status = Status(status)
	return issuer, nil
}

func scanACMEAccount(row scanner) (ACMEAccount, error) {
	var account ACMEAccount
	var status string
	if err := row.Scan(
		&account.ID,
		&account.IssuerID,
		&account.Email,
		&account.AccountURL,
		&account.PrivateKeyPEMEncrypted,
		&status,
		&account.CreatedAt,
		&account.UpdatedAt,
	); err != nil {
		return ACMEAccount{}, err
	}
	account.Status = ACMEAccountStatus(status)
	return account, nil
}

func validateCreateIssuer(params *CreateIssuerParams) error {
	if err := storage.ValidateUUID(params.ID, "issuer_id"); err != nil {
		return err
	}
	if err := storage.ValidateMachineName(params.Name, "issuer_name"); err != nil {
		return err
	}
	if params.Type == "" {
		params.Type = TypeACME
	}
	if params.Type != TypeACME {
		return errors.New("issuer type is invalid")
	}
	if params.DirectoryURL == "" {
		return errors.New("directory_url is required")
	}
	if err := storage.ValidatePublicHTTPSURL(&params.DirectoryURL, "directory_url"); err != nil {
		return err
	}
	if err := validateEnvironment(params.Environment); err != nil {
		return err
	}
	if params.Status == "" {
		params.Status = StatusDisabled
	}
	if err := validateStatus(params.Status); err != nil {
		return err
	}
	if params.Status == StatusActive {
		return errors.New("active issuer creation requires an active ACME account; create disabled, add account, then activate")
	}
	if params.RenewalWindowSeconds == 0 {
		params.RenewalWindowSeconds = 2592000
	}
	if params.RenewalWindowSeconds < 86400 {
		return errors.New("renewal_window_seconds must be at least 86400")
	}
	email, err := storage.NormalizeEmail(params.ContactEmail)
	if err != nil {
		return err
	}
	params.ContactEmail = email
	return nil
}

func validateUpdateIssuer(params *UpdateIssuerParams) error {
	if params.Status.Set {
		if params.Status.Value == nil {
			return errors.New("status cannot be null")
		}
		if err := validateStatus(Status(*params.Status.Value)); err != nil {
			return err
		}
	}
	if params.RenewalWindowSeconds.Set && params.RenewalWindowSeconds.Value < 86400 {
		return errors.New("renewal_window_seconds must be at least 86400")
	}
	if params.ContactEmail.Set {
		if params.ContactEmail.Value == nil {
			return errors.New("contact_email cannot be null")
		}
		email, err := storage.NormalizeEmail(*params.ContactEmail.Value)
		if err != nil {
			return err
		}
		*params.ContactEmail.Value = email
	}
	return nil
}

func validateCreateACMEAccount(params *CreateACMEAccountParams) error {
	if err := storage.ValidateUUID(params.ID, "acme_account_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.IssuerID, "issuer_id"); err != nil {
		return err
	}
	email, err := storage.NormalizeEmail(params.Email)
	if err != nil {
		return err
	}
	params.Email = email
	if params.AccountURL == "" {
		return errors.New("account_url is required")
	}
	if err := storage.ValidatePublicHTTPSURL(&params.AccountURL, "account_url"); err != nil {
		return err
	}
	if err := storage.ValidateEncryptedEnvelope(&params.PrivateKeyPEMEncrypted, "private_key_pem"); err != nil {
		return err
	}
	if params.Status == "" {
		params.Status = ACMEAccountStatusActive
	}
	return validateACMEAccountStatus(params.Status)
}

func validateEnvironment(environment Environment) error {
	switch environment {
	case EnvironmentProduction, EnvironmentStaging:
		return nil
	default:
		return errors.New("issuer environment is invalid")
	}
}

func validateStatus(status Status) error {
	switch status {
	case StatusActive, StatusDisabled:
		return nil
	default:
		return errors.New("issuer status is invalid")
	}
}

func validateACMEAccountStatus(status ACMEAccountStatus) error {
	switch status {
	case ACMEAccountStatusActive, ACMEAccountStatusDisabled:
		return nil
	default:
		return errors.New("acme account status is invalid")
	}
}

func stringPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}
