package dnsproviders

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"certhub/internal/storage"
)

type ProviderType string

const (
	ProviderTypeCloudflare ProviderType = "cloudflare"
	ProviderTypeArvanCloud ProviderType = "arvancloud"
)

type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

type ZoneMode string

const (
	ZoneModeAuto   ZoneMode = "auto"
	ZoneModeManual ZoneMode = "manual"
)

type RefreshStatus string

const (
	RefreshStatusIdle      RefreshStatus = "idle"
	RefreshStatusPending   RefreshStatus = "pending"
	RefreshStatusRunning   RefreshStatus = "running"
	RefreshStatusSucceeded RefreshStatus = "succeeded"
	RefreshStatusFailed    RefreshStatus = "failed"
)

type RefreshJobStatus string

const (
	RefreshJobStatusPending   RefreshJobStatus = "pending"
	RefreshJobStatusRunning   RefreshJobStatus = "running"
	RefreshJobStatusSucceeded RefreshJobStatus = "succeeded"
	RefreshJobStatusFailed    RefreshJobStatus = "failed"
	RefreshJobStatusCanceled  RefreshJobStatus = "canceled"
)

const FailureCodeZoneConflict = "dns_provider_zone_conflict"

type Provider struct {
	ID                        string
	Name                      string
	Type                      ProviderType
	ZoneMode                  ZoneMode
	LastZoneRefreshAt         *time.Time
	ZoneRefreshStatus         RefreshStatus
	ZoneRefreshFailureCode    *string
	ZoneRefreshFailureMessage *string
	Status                    Status
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
	ZoneCount                 int64
}

type Zone struct {
	ID            string
	DNSProviderID string
	ZoneName      string
	CreatedAt     time.Time
}

type ZoneMatch struct {
	Zone     Zone
	Provider Provider
}

type RefreshJob struct {
	ID                    string
	DNSProviderID         string
	Status                RefreshJobStatus
	LockedBy              *string
	LockedUntil           *time.Time
	StartedAt             *time.Time
	CompletedAt           *time.Time
	DiscoveredZoneCount   *int
	FailureCode           *string
	FailureMessage        *string
	ConflictZoneName      *string
	ConflictDNSProviderID *string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

type Repository struct {
	db storage.DBTX
}

func NewRepository(db storage.DBTX) Repository {
	return Repository{db: db}
}

type CreateProviderParams struct {
	ID                   string
	Name                 string
	Type                 ProviderType
	CredentialsEncrypted string
	ZoneMode             ZoneMode
	Status               Status
}

type UpdateProviderParams struct {
	ZoneMode storage.OptionalString
	Status   storage.OptionalString
}

type ListProvidersParams struct {
	storage.ListOptions
	Type     *ProviderType
	ZoneMode *ZoneMode
	Status   *Status
	Search   string
}

type AddZoneParams struct {
	ID            string
	DNSProviderID string
	ZoneName      string
}

type EnsureRefreshJobParams struct {
	ID            string
	DNSProviderID string
}

type ClaimRefreshJobParams struct {
	WorkerID    string
	LockedUntil time.Time
}

type CompleteRefreshJobParams struct {
	JobID         string
	DNSProviderID string
	WorkerID      string
	ZoneNames     []string
}

type FailRefreshJobParams struct {
	JobID          string
	DNSProviderID  string
	WorkerID       string
	FailureCode    string
	FailureMessage *string
}

func (r Repository) Create(ctx context.Context, params CreateProviderParams) (Provider, error) {
	if r.db == nil {
		return Provider{}, errors.New("dns providers repository storage is required")
	}
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return Provider{}, err
		}
		params.ID = id
	}
	if err := validateCreateProvider(&params); err != nil {
		return Provider{}, err
	}
	provider, err := scanProvider(r.db.QueryRow(ctx, `
insert into dns_providers (id, name, type, credentials_encrypted, zone_mode, status)
values ($1, $2, $3, $4, $5, $6)
returning `+providerReturningSQL(),
		params.ID, params.Name, string(params.Type), params.CredentialsEncrypted, string(params.ZoneMode), string(params.Status)))
	if err != nil {
		return Provider{}, fmt.Errorf("create dns provider: %w", err)
	}
	return provider, nil
}

func (r Repository) Get(ctx context.Context, id string) (Provider, error) {
	if err := storage.ValidateUUID(id, "dns_provider_id"); err != nil {
		return Provider{}, err
	}
	return r.getWhere(ctx, "p.id = $1", id)
}

func (r Repository) GetByName(ctx context.Context, name string) (Provider, error) {
	if err := storage.ValidateMachineName(name, "dns_provider_name"); err != nil {
		return Provider{}, err
	}
	return r.getWhere(ctx, "p.name = $1", name)
}

func (r Repository) List(ctx context.Context, params ListProvidersParams) ([]Provider, error) {
	query, args, err := r.listProvidersQuery(params)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list dns providers: %w", err)
	}
	defer rows.Close()
	var providers []Provider
	for rows.Next() {
		provider, err := scanProvider(rows)
		if err != nil {
			return nil, fmt.Errorf("list dns providers: %w", err)
		}
		providers = append(providers, provider)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list dns providers: %w", err)
	}
	return providers, nil
}

func (r Repository) Count(ctx context.Context, params ListProvidersParams) (int64, error) {
	query, args, err := r.countProvidersQuery(params)
	if err != nil {
		return 0, err
	}
	var total int64
	if err := r.db.QueryRow(ctx, query, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("count dns providers: %w", err)
	}
	return total, nil
}

func (r Repository) Update(ctx context.Context, id string, params UpdateProviderParams) (Provider, error) {
	if err := storage.ValidateUUID(id, "dns_provider_id"); err != nil {
		return Provider{}, err
	}
	if err := validateUpdateProvider(&params); err != nil {
		return Provider{}, err
	}
	var sets []string
	var args []any
	add := func(column string, value any) {
		args = append(args, value)
		sets = append(sets, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	if params.ZoneMode.Set {
		add("zone_mode", *params.ZoneMode.Value)
	}
	if params.Status.Set {
		add("status", *params.Status.Value)
	}
	if len(sets) == 0 {
		return r.Get(ctx, id)
	}
	sets = append(sets, "updated_at = now()")
	args = append(args, id)
	provider, err := scanProvider(r.db.QueryRow(ctx, fmt.Sprintf(`
update dns_providers
set %s
where id = $%d
returning `+providerReturningSQL(), strings.Join(sets, ", "), len(args)), args...))
	if err != nil {
		return Provider{}, fmt.Errorf("update dns provider: %w", err)
	}
	return provider, nil
}

func (r Repository) ReplaceCredentials(ctx context.Context, id, credentialsEncrypted string) (Provider, error) {
	if err := storage.ValidateUUID(id, "dns_provider_id"); err != nil {
		return Provider{}, err
	}
	if err := storage.ValidateEncryptedEnvelope(&credentialsEncrypted, "credentials_encrypted"); err != nil {
		return Provider{}, err
	}
	provider, err := scanProvider(r.db.QueryRow(ctx, `
update dns_providers
set credentials_encrypted = $1,
    updated_at = now()
where id = $2
returning `+providerReturningSQL(), credentialsEncrypted, id))
	if err != nil {
		return Provider{}, fmt.Errorf("replace dns provider credentials: %w", err)
	}
	return provider, nil
}

func (r Repository) GetCredentialsEncrypted(ctx context.Context, id string) (string, error) {
	if err := storage.ValidateUUID(id, "dns_provider_id"); err != nil {
		return "", err
	}
	var credentials string
	if err := r.db.QueryRow(ctx, `
select credentials_encrypted
from dns_providers
where id = $1`, id).Scan(&credentials); err != nil {
		return "", fmt.Errorf("get dns provider credentials: %w", err)
	}
	return credentials, nil
}

func (r Repository) AddZone(ctx context.Context, params AddZoneParams) (Zone, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return Zone{}, err
		}
		params.ID = id
	}
	if err := validateAddZone(&params); err != nil {
		return Zone{}, err
	}
	zone, err := scanZone(r.db.QueryRow(ctx, `
insert into dns_provider_zones (id, dns_provider_id, zone_name)
select $1, p.id, $2
from dns_providers p
where p.id = $3
  and p.zone_mode = 'manual'
returning id, dns_provider_id, zone_name, created_at`,
		params.ID, params.ZoneName, params.DNSProviderID))
	if err != nil {
		return Zone{}, fmt.Errorf("add dns provider zone: %w", err)
	}
	return zone, nil
}

func (r Repository) DeleteZone(ctx context.Context, dnsProviderID, zoneID string) (bool, error) {
	if err := storage.ValidateUUID(dnsProviderID, "dns_provider_id"); err != nil {
		return false, err
	}
	if err := storage.ValidateUUID(zoneID, "zone_id"); err != nil {
		return false, err
	}
	tag, err := r.db.Exec(ctx, `
delete from dns_provider_zones z
using dns_providers p
where z.dns_provider_id = p.id
  and z.dns_provider_id = $1
  and z.id = $2
  and p.zone_mode = 'manual'`, dnsProviderID, zoneID)
	if err != nil {
		return false, fmt.Errorf("delete dns provider zone: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r Repository) ListZones(ctx context.Context, dnsProviderID string, opts storage.ListOptions) ([]Zone, error) {
	if err := storage.ValidateUUID(dnsProviderID, "dns_provider_id"); err != nil {
		return nil, err
	}
	opts, err := storage.NormalizeListOptions(opts)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `
select id, dns_provider_id, zone_name, created_at
from dns_provider_zones
where dns_provider_id = $1
order by zone_name asc, id asc
limit $2 offset $3`, dnsProviderID, opts.Limit, opts.Offset)
	if err != nil {
		return nil, fmt.Errorf("list dns provider zones: %w", err)
	}
	defer rows.Close()
	var zones []Zone
	for rows.Next() {
		zone, err := scanZone(rows)
		if err != nil {
			return nil, fmt.Errorf("list dns provider zones: %w", err)
		}
		zones = append(zones, zone)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list dns provider zones: %w", err)
	}
	return zones, nil
}

func (r Repository) CountZones(ctx context.Context, dnsProviderID string) (int64, error) {
	if err := storage.ValidateUUID(dnsProviderID, "dns_provider_id"); err != nil {
		return 0, err
	}
	var total int64
	if err := r.db.QueryRow(ctx, `
select count(*)
from dns_provider_zones
where dns_provider_id = $1`, dnsProviderID).Scan(&total); err != nil {
		return 0, fmt.Errorf("count dns provider zones: %w", err)
	}
	return total, nil
}

func (r Repository) FindZoneForDNSName(ctx context.Context, dnsName string) (ZoneMatch, error) {
	normalized, err := storage.NormalizeDNSName(dnsName)
	if err != nil {
		return ZoneMatch{}, err
	}
	row := r.db.QueryRow(ctx, `
select z.id, z.dns_provider_id, z.zone_name, z.created_at, `+providerSelectColumnsSQL()+`
from dns_provider_zones z
join dns_providers p on p.id = z.dns_provider_id
where p.status = 'active'
  and ($1 = z.zone_name or $1 like '%.' || z.zone_name)
order by length(z.zone_name) desc, z.zone_name asc
limit 1`, normalized)
	zone, provider, err := scanZoneMatch(row)
	if err != nil {
		return ZoneMatch{}, fmt.Errorf("find dns provider zone: %w", err)
	}
	return ZoneMatch{Zone: zone, Provider: provider}, nil
}

func (r Repository) EnsureRefreshJob(ctx context.Context, params EnsureRefreshJobParams) (RefreshJob, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return RefreshJob{}, err
		}
		params.ID = id
	}
	if err := validateEnsureRefreshJob(&params); err != nil {
		return RefreshJob{}, err
	}
	job, err := scanRefreshJob(r.db.QueryRow(ctx, `
with job as (
    insert into dns_provider_zone_refresh_jobs (id, dns_provider_id, status)
    values ($1, $2, 'pending')
    on conflict (dns_provider_id) where status in ('pending', 'running') do update
    set updated_at = dns_provider_zone_refresh_jobs.updated_at
    returning `+refreshJobReturningSQL()+`
), provider_update as (
    update dns_providers
    set zone_refresh_status = case when (select status from job) = 'running' then 'running' else 'pending' end,
        zone_refresh_failure_code = null,
        zone_refresh_failure_message = null,
        updated_at = now()
    where id = $2
    returning 1
)
select * from job`, params.ID, params.DNSProviderID))
	if err != nil {
		return RefreshJob{}, fmt.Errorf("ensure dns provider zone refresh job: %w", err)
	}
	return job, nil
}

func (r Repository) ClaimNextRefreshJob(ctx context.Context, params ClaimRefreshJobParams) (RefreshJob, error) {
	if err := validateClaimRefreshJob(params); err != nil {
		return RefreshJob{}, err
	}
	job, err := scanRefreshJob(r.db.QueryRow(ctx, `
with candidate as (
    select id
    from dns_provider_zone_refresh_jobs
    where status = 'pending'
       or (status = 'running' and locked_until <= now())
    order by created_at asc, id asc
    for update skip locked
    limit 1
), job as (
    update dns_provider_zone_refresh_jobs j
    set status = 'running',
        locked_by = $1,
        locked_until = $2,
        started_at = coalesce(j.started_at, now()),
        completed_at = null,
        updated_at = now()
    from candidate
    where j.id = candidate.id
    returning `+prefixedRefreshJobColumnsSQL("j")+`
), provider_update as (
    update dns_providers
    set zone_refresh_status = 'running',
        zone_refresh_failure_code = null,
        zone_refresh_failure_message = null,
        updated_at = now()
    where id = (select dns_provider_id from job)
    returning 1
)
select * from job`, params.WorkerID, params.LockedUntil))
	if err != nil {
		return RefreshJob{}, fmt.Errorf("claim dns provider zone refresh job: %w", err)
	}
	return job, nil
}

func (r Repository) CompleteRefreshJobSuccess(ctx context.Context, params CompleteRefreshJobParams) (RefreshJob, error) {
	if err := validateCompleteRefreshJob(&params); err != nil {
		return RefreshJob{}, err
	}
	zoneIDs := make([]string, 0, len(params.ZoneNames))
	for range params.ZoneNames {
		id, err := storage.NewUUID()
		if err != nil {
			return RefreshJob{}, err
		}
		zoneIDs = append(zoneIDs, id)
	}
	job, err := scanRefreshJob(r.db.QueryRow(ctx, `
with job_claim as (
    select id, dns_provider_id
    from dns_provider_zone_refresh_jobs
    where id = $1
      and dns_provider_id = $2
      and status = 'running'
      and locked_by = $5
      and locked_until > now()
    for update
), input(id, zone_name) as (
    select * from unnest($3::uuid[], $4::text[])
), conflict as (
    select input.zone_name, z.dns_provider_id
    from input
    join dns_provider_zones z on z.zone_name = input.zone_name
    where z.dns_provider_id <> $2
      and exists (select 1 from job_claim)
    order by length(input.zone_name) desc, input.zone_name asc
    limit 1
), deleted as (
    delete from dns_provider_zones
    where dns_provider_id = $2
      and exists (select 1 from job_claim)
      and not exists (select 1 from conflict)
      and not exists (select 1 from input where input.zone_name = dns_provider_zones.zone_name)
    returning 1
), inserted as (
    insert into dns_provider_zones (id, dns_provider_id, zone_name)
    select input.id, $2, input.zone_name
    from input
    where exists (select 1 from job_claim)
      and not exists (select 1 from conflict)
      and not exists (
          select 1
          from dns_provider_zones z
          where z.dns_provider_id = $2
            and z.zone_name = input.zone_name
      )
    returning 1
	), job as (
    update dns_provider_zone_refresh_jobs j
    set status = case when exists (select 1 from conflict) then 'failed' else 'succeeded' end,
        locked_by = null,
        locked_until = null,
        completed_at = now(),
        discovered_zone_count = case when exists (select 1 from conflict) then null else cardinality($4::text[]) end,
        failure_code = case when exists (select 1 from conflict) then 'dns_provider_zone_conflict' else null end,
        failure_message = case when exists (select 1 from conflict) then 'zone is owned by another DNS provider' else null end,
        conflict_zone_name = (select zone_name from conflict),
        conflict_dns_provider_id = (select dns_provider_id from conflict),
        updated_at = now()
    where j.id = $1
      and j.dns_provider_id = $2
      and exists (select 1 from job_claim)
    returning `+prefixedRefreshJobColumnsSQL("j")+`
), provider_update as (
    update dns_providers
    set last_zone_refresh_at = case when (select status from job) = 'succeeded' then now() else last_zone_refresh_at end,
        zone_refresh_status = case when (select status from job) = 'succeeded' then 'succeeded' else 'failed' end,
        zone_refresh_failure_code = case when (select status from job) = 'failed' then (select failure_code from job) else null end,
        zone_refresh_failure_message = case when (select status from job) = 'failed' then (select failure_message from job) else null end,
        updated_at = now()
    where id = $2
      and exists (select 1 from job)
    returning 1
)
select * from job`, params.JobID, params.DNSProviderID, zoneIDs, params.ZoneNames, params.WorkerID))
	if err != nil {
		return RefreshJob{}, fmt.Errorf("complete dns provider zone refresh job: %w", err)
	}
	return job, nil
}

func (r Repository) FailRefreshJob(ctx context.Context, params FailRefreshJobParams) (RefreshJob, error) {
	if err := validateFailRefreshJob(&params); err != nil {
		return RefreshJob{}, err
	}
	job, err := scanRefreshJob(r.db.QueryRow(ctx, `
with job as (
    update dns_provider_zone_refresh_jobs j
    set status = 'failed',
        locked_by = null,
        locked_until = null,
        completed_at = now(),
        discovered_zone_count = null,
        failure_code = $3,
        failure_message = $4,
        conflict_zone_name = null,
        conflict_dns_provider_id = null,
        updated_at = now()
    where j.id = $1
      and j.dns_provider_id = $2
      and j.status = 'running'
      and j.locked_by = $5
      and j.locked_until > now()
    returning `+prefixedRefreshJobColumnsSQL("j")+`
), provider_update as (
    update dns_providers
    set zone_refresh_status = 'failed',
        zone_refresh_failure_code = $3,
        zone_refresh_failure_message = $4,
        updated_at = now()
    where id = $2
      and exists (select 1 from job)
    returning 1
)
select * from job`, params.JobID, params.DNSProviderID, params.FailureCode, params.FailureMessage, params.WorkerID))
	if err != nil {
		return RefreshJob{}, fmt.Errorf("fail dns provider zone refresh job: %w", err)
	}
	return job, nil
}

func (r Repository) GetRefreshJob(ctx context.Context, id string) (RefreshJob, error) {
	if err := storage.ValidateUUID(id, "zone_refresh_job_id"); err != nil {
		return RefreshJob{}, err
	}
	job, err := scanRefreshJob(r.db.QueryRow(ctx, `
select `+refreshJobReturningSQL()+`
from dns_provider_zone_refresh_jobs
where id = $1`, id))
	if err != nil {
		return RefreshJob{}, fmt.Errorf("get dns provider zone refresh job: %w", err)
	}
	return job, nil
}

func (r Repository) getWhere(ctx context.Context, predicate string, args ...any) (Provider, error) {
	provider, err := scanProvider(r.db.QueryRow(ctx, `select `+providerSelectColumnsSQL()+` from dns_providers p where `+predicate, args...))
	if err != nil {
		return Provider{}, fmt.Errorf("get dns provider: %w", err)
	}
	return provider, nil
}

func (r Repository) listProvidersQuery(params ListProvidersParams) (string, []any, error) {
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return "", nil, err
	}
	var args []any
	var where []string
	if params.Type != nil {
		if err := validateProviderType(*params.Type); err != nil {
			return "", nil, err
		}
		args = append(args, string(*params.Type))
		where = append(where, fmt.Sprintf("p.type = $%d", len(args)))
	}
	if params.ZoneMode != nil {
		if err := validateZoneMode(*params.ZoneMode); err != nil {
			return "", nil, err
		}
		args = append(args, string(*params.ZoneMode))
		where = append(where, fmt.Sprintf("p.zone_mode = $%d", len(args)))
	}
	if params.Status != nil {
		if err := validateStatus(*params.Status); err != nil {
			return "", nil, err
		}
		args = append(args, string(*params.Status))
		where = append(where, fmt.Sprintf("p.status = $%d", len(args)))
	}
	if params.Search != "" {
		if err := storage.ValidateHumanString(params.Search, "search", 1, 255); err != nil {
			return "", nil, err
		}
		args = append(args, "%"+strings.ToLower(params.Search)+"%")
		where = append(where, fmt.Sprintf("p.name like $%d", len(args)))
	}
	args = append(args, opts.Limit, opts.Offset)
	query := `select ` + providerSelectColumnsSQL() + ` from dns_providers p`
	if len(where) > 0 {
		query += " where " + strings.Join(where, " and ")
	}
	query += fmt.Sprintf(" order by p.created_at desc, p.id desc limit $%d offset $%d", len(args)-1, len(args))
	return query, args, nil
}

func (r Repository) countProvidersQuery(params ListProvidersParams) (string, []any, error) {
	if _, err := storage.NormalizeListOptions(params.ListOptions); err != nil {
		return "", nil, err
	}
	var args []any
	var where []string
	if params.Type != nil {
		if err := validateProviderType(*params.Type); err != nil {
			return "", nil, err
		}
		args = append(args, string(*params.Type))
		where = append(where, fmt.Sprintf("p.type = $%d", len(args)))
	}
	if params.ZoneMode != nil {
		if err := validateZoneMode(*params.ZoneMode); err != nil {
			return "", nil, err
		}
		args = append(args, string(*params.ZoneMode))
		where = append(where, fmt.Sprintf("p.zone_mode = $%d", len(args)))
	}
	if params.Status != nil {
		if err := validateStatus(*params.Status); err != nil {
			return "", nil, err
		}
		args = append(args, string(*params.Status))
		where = append(where, fmt.Sprintf("p.status = $%d", len(args)))
	}
	if params.Search != "" {
		if err := storage.ValidateHumanString(params.Search, "search", 1, 255); err != nil {
			return "", nil, err
		}
		args = append(args, "%"+strings.ToLower(params.Search)+"%")
		where = append(where, fmt.Sprintf("p.name like $%d", len(args)))
	}
	query := `select count(*)::bigint from dns_providers p`
	if len(where) > 0 {
		query += " where " + strings.Join(where, " and ")
	}
	return query, args, nil
}

func providerSelectColumnsSQL() string {
	return `p.id, p.name, p.type, p.zone_mode, p.last_zone_refresh_at, p.zone_refresh_status,
    p.zone_refresh_failure_code, p.zone_refresh_failure_message, p.status, p.created_at, p.updated_at,
    (select count(*) from dns_provider_zones where dns_provider_id = p.id)::bigint`
}

func providerReturningSQL() string {
	return `id, name, type, zone_mode, last_zone_refresh_at, zone_refresh_status,
    zone_refresh_failure_code, zone_refresh_failure_message, status, created_at, updated_at,
    (select count(*) from dns_provider_zones where dns_provider_id = dns_providers.id)::bigint`
}

func refreshJobReturningSQL() string {
	return `id, dns_provider_id, status, locked_by, locked_until, started_at, completed_at,
    discovered_zone_count, failure_code, failure_message, conflict_zone_name, conflict_dns_provider_id,
    created_at, updated_at`
}

func prefixedRefreshJobColumnsSQL(prefix string) string {
	return prefix + `.id, ` + prefix + `.dns_provider_id, ` + prefix + `.status, ` + prefix + `.locked_by, ` +
		prefix + `.locked_until, ` + prefix + `.started_at, ` + prefix + `.completed_at, ` +
		prefix + `.discovered_zone_count, ` + prefix + `.failure_code, ` + prefix + `.failure_message, ` +
		prefix + `.conflict_zone_name, ` + prefix + `.conflict_dns_provider_id, ` + prefix + `.created_at, ` + prefix + `.updated_at`
}

type scanner interface {
	Scan(...any) error
}

func scanProvider(row scanner) (Provider, error) {
	var provider Provider
	var providerType, zoneMode, refreshStatus, status string
	var lastRefresh sql.NullTime
	var failureCode, failureMessage sql.NullString
	if err := row.Scan(
		&provider.ID,
		&provider.Name,
		&providerType,
		&zoneMode,
		&lastRefresh,
		&refreshStatus,
		&failureCode,
		&failureMessage,
		&status,
		&provider.CreatedAt,
		&provider.UpdatedAt,
		&provider.ZoneCount,
	); err != nil {
		return Provider{}, err
	}
	provider.Type = ProviderType(providerType)
	provider.ZoneMode = ZoneMode(zoneMode)
	provider.LastZoneRefreshAt = timePtr(lastRefresh)
	provider.ZoneRefreshStatus = RefreshStatus(refreshStatus)
	provider.ZoneRefreshFailureCode = stringPtr(failureCode)
	provider.ZoneRefreshFailureMessage = stringPtr(failureMessage)
	provider.Status = Status(status)
	return provider, nil
}

func scanZone(row scanner) (Zone, error) {
	var zone Zone
	if err := row.Scan(&zone.ID, &zone.DNSProviderID, &zone.ZoneName, &zone.CreatedAt); err != nil {
		return Zone{}, err
	}
	return zone, nil
}

func scanZoneMatch(row scanner) (Zone, Provider, error) {
	var zone Zone
	var provider Provider
	var providerType, zoneMode, refreshStatus, status string
	var lastRefresh sql.NullTime
	var failureCode, failureMessage sql.NullString
	if err := row.Scan(
		&zone.ID,
		&zone.DNSProviderID,
		&zone.ZoneName,
		&zone.CreatedAt,
		&provider.ID,
		&provider.Name,
		&providerType,
		&zoneMode,
		&lastRefresh,
		&refreshStatus,
		&failureCode,
		&failureMessage,
		&status,
		&provider.CreatedAt,
		&provider.UpdatedAt,
		&provider.ZoneCount,
	); err != nil {
		return Zone{}, Provider{}, err
	}
	provider.Type = ProviderType(providerType)
	provider.ZoneMode = ZoneMode(zoneMode)
	provider.LastZoneRefreshAt = timePtr(lastRefresh)
	provider.ZoneRefreshStatus = RefreshStatus(refreshStatus)
	provider.ZoneRefreshFailureCode = stringPtr(failureCode)
	provider.ZoneRefreshFailureMessage = stringPtr(failureMessage)
	provider.Status = Status(status)
	return zone, provider, nil
}

func scanRefreshJob(row scanner) (RefreshJob, error) {
	var job RefreshJob
	var status string
	var lockedBy, failureCode, failureMessage, conflictZoneName, conflictDNSProviderID sql.NullString
	var lockedUntil, startedAt, completedAt sql.NullTime
	var discoveredZoneCount sql.NullInt32
	if err := row.Scan(
		&job.ID,
		&job.DNSProviderID,
		&status,
		&lockedBy,
		&lockedUntil,
		&startedAt,
		&completedAt,
		&discoveredZoneCount,
		&failureCode,
		&failureMessage,
		&conflictZoneName,
		&conflictDNSProviderID,
		&job.CreatedAt,
		&job.UpdatedAt,
	); err != nil {
		return RefreshJob{}, err
	}
	job.Status = RefreshJobStatus(status)
	job.LockedBy = stringPtr(lockedBy)
	job.LockedUntil = timePtr(lockedUntil)
	job.StartedAt = timePtr(startedAt)
	job.CompletedAt = timePtr(completedAt)
	if discoveredZoneCount.Valid {
		value := int(discoveredZoneCount.Int32)
		job.DiscoveredZoneCount = &value
	}
	job.FailureCode = stringPtr(failureCode)
	job.FailureMessage = stringPtr(failureMessage)
	job.ConflictZoneName = stringPtr(conflictZoneName)
	job.ConflictDNSProviderID = stringPtr(conflictDNSProviderID)
	return job, nil
}

func validateCreateProvider(params *CreateProviderParams) error {
	if err := storage.ValidateUUID(params.ID, "dns_provider_id"); err != nil {
		return err
	}
	if err := storage.ValidateMachineName(params.Name, "dns_provider_name"); err != nil {
		return err
	}
	if err := validateProviderType(params.Type); err != nil {
		return err
	}
	if err := storage.ValidateEncryptedEnvelope(&params.CredentialsEncrypted, "credentials_encrypted"); err != nil {
		return err
	}
	if params.ZoneMode == "" {
		params.ZoneMode = ZoneModeManual
	}
	if err := validateZoneMode(params.ZoneMode); err != nil {
		return err
	}
	if params.Status == "" {
		params.Status = StatusActive
	}
	return validateStatus(params.Status)
}

func validateUpdateProvider(params *UpdateProviderParams) error {
	if params.ZoneMode.Set {
		if params.ZoneMode.Value == nil {
			return errors.New("zone_mode cannot be null")
		}
		if err := validateZoneMode(ZoneMode(*params.ZoneMode.Value)); err != nil {
			return err
		}
	}
	if params.Status.Set {
		if params.Status.Value == nil {
			return errors.New("status cannot be null")
		}
		if err := validateStatus(Status(*params.Status.Value)); err != nil {
			return err
		}
	}
	return nil
}

func validateAddZone(params *AddZoneParams) error {
	if err := storage.ValidateUUID(params.ID, "zone_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.DNSProviderID, "dns_provider_id"); err != nil {
		return err
	}
	zoneName, err := storage.NormalizeDNSName(params.ZoneName)
	if err != nil {
		return err
	}
	params.ZoneName = zoneName
	return nil
}

func validateEnsureRefreshJob(params *EnsureRefreshJobParams) error {
	if err := storage.ValidateUUID(params.ID, "zone_refresh_job_id"); err != nil {
		return err
	}
	return storage.ValidateUUID(params.DNSProviderID, "dns_provider_id")
}

func validateClaimRefreshJob(params ClaimRefreshJobParams) error {
	if err := storage.ValidateHumanString(params.WorkerID, "locked_by", 1, 255); err != nil {
		return err
	}
	if params.LockedUntil.IsZero() || !params.LockedUntil.After(time.Now()) {
		return errors.New("locked_until must be in the future")
	}
	return nil
}

func validateCompleteRefreshJob(params *CompleteRefreshJobParams) error {
	if err := storage.ValidateUUID(params.JobID, "zone_refresh_job_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.DNSProviderID, "dns_provider_id"); err != nil {
		return err
	}
	if err := storage.ValidateHumanString(params.WorkerID, "locked_by", 1, 255); err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for i, zoneName := range params.ZoneNames {
		normalized, err := storage.NormalizeDNSName(zoneName)
		if err != nil {
			return err
		}
		if _, ok := seen[normalized]; ok {
			return errors.New("zone_names contains duplicate zones")
		}
		seen[normalized] = struct{}{}
		params.ZoneNames[i] = normalized
	}
	return nil
}

func validateFailRefreshJob(params *FailRefreshJobParams) error {
	if err := storage.ValidateUUID(params.JobID, "zone_refresh_job_id"); err != nil {
		return err
	}
	if err := storage.ValidateUUID(params.DNSProviderID, "dns_provider_id"); err != nil {
		return err
	}
	if err := storage.ValidateHumanString(params.WorkerID, "locked_by", 1, 255); err != nil {
		return err
	}
	if err := validateFailureCode(params.FailureCode); err != nil {
		return err
	}
	return storage.ValidateOptionalHumanString(params.FailureMessage, "failure_message", 2048)
}

func validateProviderType(providerType ProviderType) error {
	switch providerType {
	case ProviderTypeCloudflare, ProviderTypeArvanCloud:
		return nil
	default:
		return errors.New("dns provider type is invalid")
	}
}

func validateZoneMode(mode ZoneMode) error {
	switch mode {
	case ZoneModeAuto, ZoneModeManual:
		return nil
	default:
		return errors.New("zone_mode is invalid")
	}
}

func validateStatus(status Status) error {
	switch status {
	case StatusActive, StatusDisabled:
		return nil
	default:
		return errors.New("dns provider status is invalid")
	}
}

func validateFailureCode(code string) error {
	if err := storage.ValidateMachineName(code, "failure_code"); err != nil {
		return err
	}
	return nil
}

func stringPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}

func timePtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	return &value.Time
}
