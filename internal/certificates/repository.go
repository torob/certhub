package certificates

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/torob/certhub/internal/storage"
)

type Repository struct {
	db storage.DBTX
}

func NewRepository(db storage.DBTX) Repository {
	return Repository{db: db}
}

type CreateOrReuseCertificateParams struct {
	ID             string
	ApplicationID  string
	IssuerID       string
	NormalizedSANs []string
	KeyType        KeyType
	Status         Status
}

type ListCertificatesParams struct {
	storage.ListOptions
	ApplicationID  *string
	ApplicationIDs []string
	IssuerID       *string
	Status         *Status
	Enabled        *bool
	KeyType        *KeyType
	NormalizedSANs []string
	ExpiresBefore  *time.Time
	IncludeDeleted bool
}

type ListVersionsParams struct {
	storage.ListOptions
	CertificateID string
}

type RenewalCandidate struct {
	CertificateID    string
	ApplicationID    string
	NormalizedSANs   []string
	ActiveVersion    CertificateVersion
	RenewalNotBefore time.Time
}

type CreateIssuingVersionParams struct {
	ID            string
	CertificateID string
	Reason        IssuanceReason
}

type StoreMaterialParams struct {
	JobID                  string
	WorkerID               string
	CertificateVersionID   string
	CertPEM                string
	ChainPEM               string
	FullchainPEM           string
	PrivateKeyPEMEncrypted string
	NotBefore              time.Time
	NotAfter               time.Time
	SerialNumber           string
	FingerprintSHA256      string
	KeyFingerprintSHA256   string
	MaterialETag           string
	ACMEOrderURL           *string
	CertificateURL         *string
}

type PrepareIssuingVersionParams struct {
	CertificateVersionID   string
	PrivateKeyPEMEncrypted string
	KeyFingerprintSHA256   string
	ACMEOrderURL           string
}

type EnsureIssuanceJobParams struct {
	ID                   string
	CertificateID        string
	CertificateVersionID *string
	Reason               JobReason
	NextRunAt            time.Time
}

type AttachIssuingVersionToJobParams struct {
	JobID                string
	WorkerID             string
	CertificateVersionID string
}

type UpdateCertificateIssuanceStatusParams struct {
	CertificateID string
	Status        Status
}

type RevokeCertificateVersionParams struct {
	CertificateID        string
	CertificateVersionID string
	Reason               RevocationReason
	RevokedByUserID      string
}

type DeleteCertificateParams struct {
	ID    string
	Force bool
}

type UpdateCertificateEnabledParams struct {
	ID      string
	Enabled bool
}

type ClaimIssuanceJobParams struct {
	WorkerID    string
	LockedUntil time.Time
}

type SucceedIssuanceJobParams struct {
	JobID    string
	WorkerID string
}

type FailIssuanceJobParams struct {
	JobID          string
	WorkerID       string
	FailureCode    string
	FailureMessage *string
	Retryable      bool
	MaxAttempts    int
	RetryAfter     time.Duration
}

type MarkACMERevocationParams struct {
	CertificateVersionID string
	FailureCode          string
	FailureMessage       *string
}

type RecordDNSChallengeParams struct {
	ID                      string
	IssuanceJobID           string
	CertificateID           string
	CertificateVersionID    string
	DNSProviderID           string
	DNSProviderZoneID       string
	AuthorizationIdentifier string
	RecordName              string
	TXTValueEncrypted       string
	Status                  DNSChallengeStatus
}

type ListDNSChallengesParams struct {
	storage.ListOptions
	IssuanceJobID        *string
	CertificateID        *string
	CertificateVersionID *string
	Status               *DNSChallengeStatus
}

type MarkDNSChallengeCleanupParams struct {
	ID             string
	Status         DNSChallengeStatus
	FailureCode    string
	FailureMessage *string
}

type MarkDNSChallengePresentedParams struct {
	ID string
}

type RecordEventParams struct {
	ID                   string
	CertificateID        string
	CertificateVersionID *string
	IssuanceJobID        *string
	EventType            string
	Result               EventResult
	CorrelationID        *string
	Message              *string
	Metadata             json.RawMessage
}

type ListEventsParams struct {
	storage.ListOptions
	CertificateID        string
	CertificateVersionID *string
	IssuanceJobID        *string
	EventType            *string
	Result               *EventResult
}

func (r Repository) CreateOrReuse(ctx context.Context, params CreateOrReuseCertificateParams) (Certificate, error) {
	if r.db == nil {
		return Certificate{}, errors.New("certificates repository storage is required")
	}
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return Certificate{}, err
		}
		params.ID = id
	}
	if err := validateCreateOrReuse(&params); err != nil {
		return Certificate{}, err
	}
	cert, err := scanCertificate(r.db.QueryRow(ctx, `
insert into certificates (id, application_id, issuer_id, normalized_sans, key_type, status)
values ($1, $2, $3, $4::text[], $5, $6)
on conflict (application_id, normalized_sans, key_type, issuer_id) where deleted_at is null do update
set updated_at = certificates.updated_at
returning `+certificateReturningSQL(),
		params.ID, params.ApplicationID, params.IssuerID, params.NormalizedSANs, string(params.KeyType), string(params.Status)))
	if err != nil {
		return Certificate{}, fmt.Errorf("create or reuse certificate: %w", err)
	}
	return cert, nil
}

func (r Repository) Get(ctx context.Context, id string) (Certificate, error) {
	if err := storage.ValidateUUID(id, "certificate_id"); err != nil {
		return Certificate{}, err
	}
	cert, err := scanCertificate(r.db.QueryRow(ctx, `
select `+certificateSelectSQL("c")+`
from certificates c
where c.id = $1`, id))
	if err != nil {
		return Certificate{}, fmt.Errorf("get certificate: %w", err)
	}
	return cert, nil
}

func (r Repository) UpdateEnabled(ctx context.Context, params UpdateCertificateEnabledParams) (Certificate, bool, error) {
	if err := storage.ValidateUUID(params.ID, "certificate_id"); err != nil {
		return Certificate{}, false, err
	}
	cert, err := scanCertificate(r.db.QueryRow(ctx, `
update certificates
set enabled = $2,
    updated_at = now()
where id = $1
  and deleted_at is null
  and enabled is distinct from $2
returning `+certificateReturningSQL(), params.ID, params.Enabled))
	if errors.Is(err, storage.ErrNoRows) {
		current, getErr := r.Get(ctx, params.ID)
		return current, false, getErr
	}
	if err != nil {
		return Certificate{}, false, fmt.Errorf("update certificate enabled state: %w", err)
	}
	return cert, true, nil
}

func (r Repository) List(ctx context.Context, params ListCertificatesParams) ([]Certificate, error) {
	query, args, err := r.listQuery(params, false)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	defer rows.Close()
	var certs []Certificate
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("list certificates: %w", err)
		}
		certs = append(certs, cert)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	return certs, nil
}

func (r Repository) Count(ctx context.Context, params ListCertificatesParams) (int64, error) {
	query, args, err := r.listQuery(params, true)
	if err != nil {
		return 0, err
	}
	var total int64
	if err := r.db.QueryRow(ctx, query, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("count certificates: %w", err)
	}
	return total, nil
}

func (r Repository) ListRenewalCandidates(ctx context.Context, limit int) ([]RenewalCandidate, error) {
	if limit <= 0 {
		return nil, errors.New("limit must be positive")
	}
	if limit > storage.MaxListLimit {
		limit = storage.MaxListLimit
	}
	rows, err := r.db.Query(ctx, `
with latest as (
    select distinct on (v.certificate_id) `+certificateVersionSelectSQL("v")+`
    from certificate_versions v
    where v.status = 'valid'
      and v.cert_pem is not null
      and v.chain_pem is not null
      and v.fullchain_pem is not null
      and v.private_key_pem is not null
      and v.material_etag is not null
      and v.not_before <= now()
      and v.not_after > now()
    order by v.certificate_id, v.version desc
)
select `+certificateVersionSelectSQL("latest")+`,
       latest.not_after - (i.renewal_window_seconds * interval '1 second') as renewal_not_before,
       c.application_id,
       c.normalized_sans
from certificates c
join latest on latest.certificate_id = c.id
join issuers i on i.id = c.issuer_id
where c.deleted_at is null
  and c.status <> 'deleted'
  and c.enabled
  and i.status = 'active'
  and latest.not_after <= now() + (i.renewal_window_seconds * interval '1 second')
  and not exists (
      select 1
      from certificate_versions issuing
      where issuing.certificate_id = c.id
        and issuing.status = 'issuing'
        and issuing.reason = 'renewal'
  )
order by latest.not_after asc, latest.certificate_id asc
limit $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list renewal candidates: %w", err)
	}
	defer rows.Close()
	var candidates []RenewalCandidate
	for rows.Next() {
		candidate, err := scanRenewalCandidate(rows)
		if err != nil {
			return nil, fmt.Errorf("list renewal candidates: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list renewal candidates: %w", err)
	}
	return candidates, nil
}

func (r Repository) LatestValidVersion(ctx context.Context, certificateID string) (CertificateVersion, error) {
	if err := storage.ValidateUUID(certificateID, "certificate_id"); err != nil {
		return CertificateVersion{}, err
	}
	version, err := scanCertificateVersion(r.db.QueryRow(ctx, `
select `+certificateVersionSelectSQL("v")+`
from certificate_versions v
where v.certificate_id = $1
  and v.status = 'valid'
order by v.version desc
limit 1`, certificateID))
	if err != nil {
		return CertificateVersion{}, fmt.Errorf("get latest valid certificate version: %w", err)
	}
	return version, nil
}

func (r Repository) ListVersions(ctx context.Context, params ListVersionsParams) ([]CertificateVersion, error) {
	if err := storage.ValidateUUID(params.CertificateID, "certificate_id"); err != nil {
		return nil, err
	}
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `
select `+certificateVersionSelectSQL("v")+`
from certificate_versions v
where v.certificate_id = $1
order by v.version desc
limit $2 offset $3`, params.CertificateID, opts.Limit, opts.Offset)
	if err != nil {
		return nil, fmt.Errorf("list certificate versions: %w", err)
	}
	defer rows.Close()
	var versions []CertificateVersion
	for rows.Next() {
		version, err := scanCertificateVersion(rows)
		if err != nil {
			return nil, fmt.Errorf("list certificate versions: %w", err)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list certificate versions: %w", err)
	}
	return versions, nil
}

func (r Repository) CountVersions(ctx context.Context, certificateID string) (int64, error) {
	if err := storage.ValidateUUID(certificateID, "certificate_id"); err != nil {
		return 0, err
	}
	var total int64
	if err := r.db.QueryRow(ctx, `select count(*)::bigint from certificate_versions where certificate_id = $1`, certificateID).Scan(&total); err != nil {
		return 0, fmt.Errorf("count certificate versions: %w", err)
	}
	return total, nil
}

func (r Repository) GetLatestValidMaterial(ctx context.Context, certificateID string) (CertificateVersion, error) {
	if err := storage.ValidateUUID(certificateID, "certificate_id"); err != nil {
		return CertificateVersion{}, err
	}
	version, err := scanCertificateVersion(r.db.QueryRow(ctx, `
select `+certificateVersionSelectSQL("v")+`
from certificate_versions v
join certificates c on c.id = v.certificate_id
where v.certificate_id = $1
  and v.status = 'valid'
  and v.cert_pem is not null
  and v.chain_pem is not null
  and v.fullchain_pem is not null
  and v.private_key_pem is not null
	  and v.material_etag is not null
	  and v.not_before <= now()
	  and v.not_after > now()
	  and c.status not in ('failed', 'deleted')
	order by v.version desc
	limit 1`, certificateID))
	if err != nil {
		return CertificateVersion{}, fmt.Errorf("get latest valid certificate material: %w", err)
	}
	return version, nil
}

func (r Repository) GetVersion(ctx context.Context, id string) (CertificateVersion, error) {
	if err := storage.ValidateUUID(id, "certificate_version_id"); err != nil {
		return CertificateVersion{}, err
	}
	version, err := scanCertificateVersion(r.db.QueryRow(ctx, `
select `+certificateVersionSelectSQL("v")+`
from certificate_versions v
where v.id = $1`, id))
	if err != nil {
		return CertificateVersion{}, fmt.Errorf("get certificate version: %w", err)
	}
	return version, nil
}

func (r Repository) CreateIssuingVersion(ctx context.Context, params CreateIssuingVersionParams) (CertificateVersion, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return CertificateVersion{}, err
		}
		params.ID = id
	}
	if err := validateCreateIssuingVersion(&params); err != nil {
		return CertificateVersion{}, err
	}
	parentStatus := statusForIssuanceReason(params.Reason)
	version, err := scanCertificateVersion(r.db.QueryRow(ctx, `
with locked_certificate as (
    select id
    from certificates
    where id = $2
      and status <> 'deleted'
      and enabled
    for update
), existing as (
    select `+certificateVersionSelectSQL("v")+`
    from certificate_versions v
    where v.certificate_id = $2
      and v.status = 'issuing'
), inserted as (
    insert into certificate_versions (id, certificate_id, version, status, reason, started_at)
    select $1, $2, coalesce((select max(version) from certificate_versions where certificate_id = $2), 0) + 1,
           'issuing', $3, now()
    where exists (select 1 from locked_certificate)
      and not exists (select 1 from existing)
    returning `+certificateVersionReturningSQL()+`
), parent_update as (
    update certificates
    set status = $4,
        failure_code = null,
        failure_message = null,
        revocation_reason = null,
        revoked_at = null,
        revoked_by_user_id = null,
        updated_at = now()
    where id = $2
      and exists (select 1 from inserted)
    returning 1
)
select * from inserted
union all
select * from existing
limit 1`, params.ID, params.CertificateID, string(params.Reason), string(parentStatus)))
	if err != nil {
		return CertificateVersion{}, fmt.Errorf("create issuing certificate version: %w", err)
	}
	return version, nil
}

func (r Repository) PrepareIssuingVersion(ctx context.Context, params PrepareIssuingVersionParams) (CertificateVersion, error) {
	if err := validatePrepareIssuingVersion(&params); err != nil {
		return CertificateVersion{}, err
	}
	version, err := scanCertificateVersion(r.db.QueryRow(ctx, `
update certificate_versions v
set private_key_pem = coalesce(v.private_key_pem, $2),
    key_fingerprint_sha256 = coalesce(v.key_fingerprint_sha256, $3),
    acme_order_url = coalesce(v.acme_order_url, $4),
    updated_at = now()
where v.id = $1
  and v.status = 'issuing'
returning `+certificateVersionSelectSQL("v"), params.CertificateVersionID, params.PrivateKeyPEMEncrypted, params.KeyFingerprintSHA256, params.ACMEOrderURL))
	if err != nil {
		return CertificateVersion{}, fmt.Errorf("prepare issuing certificate version: %w", err)
	}
	return version, nil
}

func (r Repository) StoreMaterial(ctx context.Context, params StoreMaterialParams) (CertificateVersion, error) {
	if err := validateStoreMaterial(&params); err != nil {
		return CertificateVersion{}, err
	}
	version, err := scanCertificateVersion(r.db.QueryRow(ctx, `
with updated as (
    update certificate_versions
    set status = 'valid',
        cert_pem = $2,
        chain_pem = $3,
        fullchain_pem = $4,
        private_key_pem = $5,
        not_before = $6,
        not_after = $7,
        serial_number = $8,
        fingerprint_sha256 = $9,
        key_fingerprint_sha256 = $10,
        material_etag = $11,
        acme_order_url = $12,
        certificate_url = $13,
        completed_at = now(),
        issued_at = now(),
        failure_code = null,
        failure_message = null,
        updated_at = now()
    where id = $1
      and status = 'issuing'
      and (
          $14 = ''
          or exists (
              select 1
              from certificate_issuance_jobs j
              where j.id = nullif($14, '')::uuid
                and j.certificate_version_id = certificate_versions.id
                and j.status = 'running'
                and j.locked_by = $15
                and j.locked_until > now()
          )
      )
    returning `+certificateVersionReturningSQL()+`
), parent_update as (
    update certificates
    set status = 'ready',
        failure_code = null,
        failure_message = null,
        updated_at = now()
    where id = (select certificate_id from updated)
    returning 1
), existing as (
    select `+certificateVersionSelectSQL("v")+`
    from certificate_versions v
    where v.id = $1
      and not exists (select 1 from updated)
)
select * from updated
union all
select * from existing
limit 1`, params.CertificateVersionID, params.CertPEM, params.ChainPEM, params.FullchainPEM,
		params.PrivateKeyPEMEncrypted, params.NotBefore, params.NotAfter, params.SerialNumber,
		params.FingerprintSHA256, params.KeyFingerprintSHA256, params.MaterialETag,
		params.ACMEOrderURL, params.CertificateURL, params.JobID, params.WorkerID))
	if err != nil {
		return CertificateVersion{}, fmt.Errorf("store certificate material: %w", err)
	}
	return version, nil
}

func (r Repository) UpdateCertificateIssuanceStatus(ctx context.Context, params UpdateCertificateIssuanceStatusParams) (Certificate, error) {
	if err := validateUpdateCertificateIssuanceStatus(params); err != nil {
		return Certificate{}, err
	}
	cert, err := scanCertificate(r.db.QueryRow(ctx, `
update certificates
set status = $2,
    updated_at = now()
where id = $1
  and status not in ('ready', 'revoked', 'failed', 'deleted')
returning `+certificateReturningSQL(), params.CertificateID, string(params.Status)))
	if err != nil {
		return Certificate{}, fmt.Errorf("update certificate issuance status: %w", err)
	}
	return cert, nil
}

func (r Repository) EnsureIssuanceJob(ctx context.Context, params EnsureIssuanceJobParams) (IssuanceJob, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return IssuanceJob{}, err
		}
		params.ID = id
	}
	if err := validateEnsureJob(&params); err != nil {
		return IssuanceJob{}, err
	}
	if params.CertificateVersionID == nil {
		job, err := scanIssuanceJob(r.db.QueryRow(ctx, `
insert into certificate_issuance_jobs (
    id, certificate_id, certificate_version_id, reason, status, next_run_at
) values (
    $1, $2, null, $3, 'pending', $4
)
on conflict (certificate_id, reason) where certificate_version_id is null and status in ('pending', 'running') do update
set updated_at = certificate_issuance_jobs.updated_at
returning `+issuanceJobReturningSQL(), params.ID, params.CertificateID, string(params.Reason), params.NextRunAt))
		if err != nil {
			return IssuanceJob{}, fmt.Errorf("ensure certificate issuance job: %w", err)
		}
		return job, nil
	}
	job, err := scanIssuanceJob(r.db.QueryRow(ctx, `
with job as (
    insert into certificate_issuance_jobs (
        id, certificate_id, certificate_version_id, reason, status, next_run_at
    ) values (
        $1, $2, $3, $4, 'pending', $5
    )
    on conflict (certificate_version_id) where certificate_version_id is not null and status in ('pending', 'running') do update
    set updated_at = certificate_issuance_jobs.updated_at
    returning `+issuanceJobReturningSQL()+`
)
select * from job`, params.ID, params.CertificateID, params.CertificateVersionID, string(params.Reason), params.NextRunAt))
	if err != nil {
		return IssuanceJob{}, fmt.Errorf("ensure certificate issuance job: %w", err)
	}
	return job, nil
}

func (r Repository) AttachIssuingVersionToJob(ctx context.Context, params AttachIssuingVersionToJobParams) (IssuanceJob, error) {
	if err := validateAttachIssuingVersionToJob(params); err != nil {
		return IssuanceJob{}, err
	}
	job, err := scanIssuanceJob(r.db.QueryRow(ctx, `
update certificate_issuance_jobs j
set certificate_version_id = coalesce(j.certificate_version_id, $3),
    updated_at = now()
where j.id = $1
  and j.status = 'running'
  and j.locked_by = $2
  and j.locked_until > now()
returning `+prefixedIssuanceJobColumnsSQL("j"), params.JobID, params.WorkerID, params.CertificateVersionID))
	if err != nil {
		return IssuanceJob{}, fmt.Errorf("attach issuing version to certificate issuance job: %w", err)
	}
	return job, nil
}

func (r Repository) RevokeCertificateVersion(ctx context.Context, params RevokeCertificateVersionParams) (CertificateVersion, error) {
	if err := validateRevokeCertificateVersion(params); err != nil {
		return CertificateVersion{}, err
	}
	version, err := scanCertificateVersion(r.db.QueryRow(ctx, `
with target as (
    select `+certificateVersionSelectSQL("v")+`
    from certificate_versions v
    join certificates c on c.id = v.certificate_id
    where v.id = $2
      and v.certificate_id = $1
      and c.status <> 'deleted'
      and v.status in ('valid', 'revoked')
      and v.cert_pem is not null
      and v.chain_pem is not null
      and v.fullchain_pem is not null
      and v.private_key_pem is not null
      and v.material_etag is not null
    for update of v
), updated as (
    update certificate_versions v
    set status = 'revoked',
        revocation_reason = coalesce(v.revocation_reason, $3),
        revoked_at = coalesce(v.revoked_at, now()),
        revoked_by_user_id = coalesce(v.revoked_by_user_id, $4),
        acme_revocation_status = case
            when v.acme_revocation_status = 'succeeded' then v.acme_revocation_status
            else coalesce(v.acme_revocation_status, 'pending')
        end,
        completed_at = coalesce(v.completed_at, now()),
        updated_at = now()
    where v.id = $2
      and exists (select 1 from target)
      and v.status = 'valid'
    returning `+certificateVersionSelectSQL("v")+`
), parent_update as (
    update certificates c
    set status = case
            when exists (
                select 1
                from certificate_versions active
                where active.certificate_id = c.id
                  and active.status = 'valid'
                  and active.cert_pem is not null
                  and active.chain_pem is not null
                  and active.fullchain_pem is not null
                  and active.private_key_pem is not null
                  and active.material_etag is not null
                  and active.not_before <= now()
                  and active.not_after > now()
            ) then 'ready'
            else c.status
        end,
        updated_at = now()
    where c.id = $1
      and exists (select 1 from updated)
    returning 1
)
select * from updated
union all
select * from target where not exists (select 1 from updated)
limit 1`, params.CertificateID, params.CertificateVersionID, string(params.Reason), params.RevokedByUserID))
	if err != nil {
		return CertificateVersion{}, fmt.Errorf("revoke certificate version: %w", err)
	}
	return version, nil
}

func (r Repository) DeleteCertificate(ctx context.Context, params DeleteCertificateParams) (Certificate, error) {
	if err := storage.ValidateUUID(params.ID, "certificate_id"); err != nil {
		return Certificate{}, err
	}
	cert, err := scanCertificate(r.db.QueryRow(ctx, `
select `+certificateSelectSQL("c")+`
from certificates c
where c.id = $1
for update`, params.ID))
	if err != nil {
		return Certificate{}, fmt.Errorf("lock certificate for deletion: %w", err)
	}
	var activeJobs, issuingVersions, uncleanChallenges, validVersions int64
	if err := r.db.QueryRow(ctx, `
select
    (select count(*) from certificate_issuance_jobs where certificate_id = $1 and status in ('pending', 'running')),
    (select count(*) from certificate_versions where certificate_id = $1 and status = 'issuing'),
    (select count(*) from dns_challenge_records where certificate_id = $1 and status <> 'cleaned'),
    (select count(*) from certificate_versions where certificate_id = $1 and status = 'valid')`, params.ID).
		Scan(&activeJobs, &issuingVersions, &uncleanChallenges, &validVersions); err != nil {
		return Certificate{}, fmt.Errorf("inspect certificate deletion blockers: %w", err)
	}
	if activeJobs > 0 || issuingVersions > 0 || uncleanChallenges > 0 {
		return Certificate{}, CertificateBusyError{ActiveJobs: activeJobs, IssuingVersions: issuingVersions, UncleanChallenges: uncleanChallenges}
	}
	if validVersions > 0 && !params.Force {
		return Certificate{}, CertificateHasValidVersionsError{Count: validVersions}
	}
	result, err := r.db.Exec(ctx, `delete from certificates where id = $1`, params.ID)
	if err != nil {
		return Certificate{}, fmt.Errorf("delete certificate: %w", err)
	}
	if result.RowsAffected() == 0 {
		return Certificate{}, storage.ErrNoRows
	}
	return cert, nil
}

func (r Repository) MarkACMERevocationSucceeded(ctx context.Context, params MarkACMERevocationParams) (CertificateVersion, error) {
	if err := storage.ValidateUUID(params.CertificateVersionID, "certificate_version_id"); err != nil {
		return CertificateVersion{}, err
	}
	version, err := scanCertificateVersion(r.db.QueryRow(ctx, `
update certificate_versions v
set acme_revocation_status = 'succeeded',
    acme_revocation_attempts = acme_revocation_attempts + 1,
    acme_revoked_at = now(),
    acme_revocation_failure_code = null,
    acme_revocation_failure_message = null,
    updated_at = now()
where v.id = $1
returning `+certificateVersionSelectSQL("v"), params.CertificateVersionID))
	if err != nil {
		return CertificateVersion{}, fmt.Errorf("mark acme revocation succeeded: %w", err)
	}
	return version, nil
}

func (r Repository) MarkACMERevocationFailed(ctx context.Context, params MarkACMERevocationParams) (CertificateVersion, error) {
	if err := storage.ValidateUUID(params.CertificateVersionID, "certificate_version_id"); err != nil {
		return CertificateVersion{}, err
	}
	if err := validateFailureCode(params.FailureCode); err != nil {
		return CertificateVersion{}, err
	}
	if err := storage.ValidateOptionalHumanString(params.FailureMessage, "acme_revocation_failure_message", 2048); err != nil {
		return CertificateVersion{}, err
	}
	version, err := scanCertificateVersion(r.db.QueryRow(ctx, `
update certificate_versions v
set acme_revocation_status = 'failed',
    acme_revocation_attempts = acme_revocation_attempts + 1,
    acme_revocation_failure_code = $2,
    acme_revocation_failure_message = $3,
    updated_at = now()
where v.id = $1
returning `+certificateVersionSelectSQL("v"), params.CertificateVersionID, params.FailureCode, params.FailureMessage))
	if err != nil {
		return CertificateVersion{}, fmt.Errorf("mark acme revocation failed: %w", err)
	}
	return version, nil
}

func (r Repository) ClaimNextIssuanceJob(ctx context.Context, params ClaimIssuanceJobParams) (IssuanceJob, error) {
	if err := validateClaimJob(params); err != nil {
		return IssuanceJob{}, err
	}
	job, err := scanIssuanceJob(r.db.QueryRow(ctx, `
with candidate as (
    select id
    from certificate_issuance_jobs
    where (status = 'pending' and next_run_at <= now())
       or (status = 'running' and locked_until <= now())
    order by next_run_at asc, created_at asc, id asc
    for update skip locked
    limit 1
), job as (
    update certificate_issuance_jobs j
    set status = 'running',
        attempt = case when j.status = 'running' then j.attempt + 1 else j.attempt end,
        locked_by = $1,
        locked_until = $2,
        started_at = coalesce(j.started_at, now()),
        completed_at = null,
        updated_at = now()
    from candidate
    where j.id = candidate.id
    returning `+prefixedIssuanceJobColumnsSQL("j")+`
)
select * from job`, params.WorkerID, params.LockedUntil))
	if err != nil {
		return IssuanceJob{}, fmt.Errorf("claim certificate issuance job: %w", err)
	}
	return job, nil
}

func (r Repository) SucceedIssuanceJob(ctx context.Context, params SucceedIssuanceJobParams) (IssuanceJob, error) {
	if err := validateSucceedJob(params); err != nil {
		return IssuanceJob{}, err
	}
	job, err := scanIssuanceJob(r.db.QueryRow(ctx, `
with job as (
    update certificate_issuance_jobs j
    set status = 'succeeded',
        locked_by = null,
        locked_until = null,
        completed_at = coalesce(j.completed_at, now()),
        failure_code = null,
        failure_message = null,
        updated_at = now()
    where j.id = $1
      and (
          (j.status = 'running' and j.locked_by = $2 and j.locked_until > now())
          or j.status = 'succeeded'
      )
    returning `+prefixedIssuanceJobColumnsSQL("j")+`
)
select * from job`, params.JobID, params.WorkerID))
	if err != nil {
		return IssuanceJob{}, fmt.Errorf("succeed certificate issuance job: %w", err)
	}
	return job, nil
}

func (r Repository) FailIssuanceJob(ctx context.Context, params FailIssuanceJobParams) (IssuanceJob, error) {
	if err := validateFailJob(&params); err != nil {
		return IssuanceJob{}, err
	}
	retryAfter := params.RetryAfter
	if retryAfter <= 0 {
		retryAfter = time.Minute
	}
	nextRunAt := time.Now().UTC().Add(retryAfter)
	job, err := scanIssuanceJob(r.db.QueryRow(ctx, `
with job as (
    update certificate_issuance_jobs j
    set status = case when $5 and ($6 = 0 or j.attempt < $6) then 'pending' else 'failed' end,
        attempt = case when $5 and ($6 = 0 or j.attempt < $6) then j.attempt + 1 else j.attempt end,
        locked_by = null,
        locked_until = null,
        next_run_at = case when $5 and ($6 = 0 or j.attempt < $6) then $7 else j.next_run_at end,
        completed_at = case when $5 and ($6 = 0 or j.attempt < $6) then null else coalesce(j.completed_at, now()) end,
        failure_code = case when $5 and ($6 = 0 or j.attempt < $6) then null else $3 end,
        failure_message = case when $5 and ($6 = 0 or j.attempt < $6) then null else $4 end,
        updated_at = now()
    where j.id = $1
      and (
          (j.status = 'running' and j.locked_by = $2 and j.locked_until > now())
          or j.status = 'failed'
      )
    returning `+prefixedIssuanceJobColumnsSQL("j")+`
), version_update as (
    update certificate_versions
    set status = 'failed',
        completed_at = coalesce(completed_at, now()),
        failure_code = $3,
        failure_message = $4,
        updated_at = now()
    where id = (select certificate_version_id from job)
      and status = 'issuing'
      and (select status from job) = 'failed'
    returning certificate_id
), cert_update as (
    update certificates c
    set status = case when valid_material.exists then 'ready' else 'failed' end,
        failure_code = case when valid_material.exists then null else $3 end,
        failure_message = case when valid_material.exists then null else $4 end,
        updated_at = now()
    from (
        select exists (
            select 1
            from certificate_versions v
            where v.certificate_id = (select certificate_id from version_update)
              and v.status = 'valid'
              and v.cert_pem is not null
              and v.chain_pem is not null
              and v.fullchain_pem is not null
              and v.private_key_pem is not null
              and v.material_etag is not null
              and v.not_before <= now()
              and v.not_after > now()
        ) as exists
    ) valid_material
    where c.id = (select certificate_id from version_update)
    returning 1
)
select * from job`, params.JobID, params.WorkerID, params.FailureCode, params.FailureMessage, params.Retryable, params.MaxAttempts, nextRunAt))
	if err != nil {
		return IssuanceJob{}, fmt.Errorf("fail certificate issuance job: %w", err)
	}
	return job, nil
}

func (r Repository) RecordDNSChallenge(ctx context.Context, params RecordDNSChallengeParams) (DNSChallengeRecord, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return DNSChallengeRecord{}, err
		}
		params.ID = id
	}
	if err := validateRecordDNSChallenge(&params); err != nil {
		return DNSChallengeRecord{}, err
	}
	record, err := scanDNSChallenge(r.db.QueryRow(ctx, `
insert into dns_challenge_records (
    id, issuance_job_id, certificate_id, certificate_version_id, dns_provider_id, dns_provider_zone_id,
    authorization_identifier, record_name, txt_value_encrypted, status,
    presented_at, validated_at
) values (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10,
    case when $10 in ('presented', 'validated', 'cleanup_pending') then now() else null end,
    case when $10 in ('validated', 'cleanup_pending') then now() else null end
)
on conflict (issuance_job_id, record_name, txt_value_encrypted) do update
set updated_at = dns_challenge_records.updated_at
returning `+dnsChallengeReturningSQL(),
		params.ID, params.IssuanceJobID, params.CertificateID, params.CertificateVersionID,
		params.DNSProviderID, params.DNSProviderZoneID, params.AuthorizationIdentifier,
		params.RecordName, params.TXTValueEncrypted, string(params.Status)))
	if err != nil {
		return DNSChallengeRecord{}, fmt.Errorf("record dns challenge: %w", err)
	}
	return record, nil
}

func (r Repository) MarkDNSChallengePresented(ctx context.Context, params MarkDNSChallengePresentedParams) (DNSChallengeRecord, error) {
	if err := storage.ValidateUUID(params.ID, "dns_challenge_record_id"); err != nil {
		return DNSChallengeRecord{}, err
	}
	record, err := scanDNSChallenge(r.db.QueryRow(ctx, `
update dns_challenge_records
set status = case when status in ('pending', 'cleaned', 'cleanup_failed') then 'presented' else status end,
    presented_at = case when status in ('pending', 'cleaned', 'cleanup_failed') then now() else coalesce(presented_at, now()) end,
    validated_at = case when status in ('cleaned', 'cleanup_failed') then null else validated_at end,
    cleaned_at = case when status in ('cleaned', 'cleanup_failed') then null else cleaned_at end,
    failure_code = case when status = 'cleanup_failed' then null else failure_code end,
    failure_message = case when status = 'cleanup_failed' then null else failure_message end,
    updated_at = now()
where id = $1
returning `+dnsChallengeReturningSQL(), params.ID))
	if err != nil {
		return DNSChallengeRecord{}, fmt.Errorf("mark dns challenge presented: %w", err)
	}
	return record, nil
}

func (r Repository) ListDNSChallenges(ctx context.Context, params ListDNSChallengesParams) ([]DNSChallengeRecord, error) {
	query, args, err := r.listDNSChallengesQuery(params)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list dns challenges: %w", err)
	}
	defer rows.Close()
	var records []DNSChallengeRecord
	for rows.Next() {
		record, err := scanDNSChallenge(rows)
		if err != nil {
			return nil, fmt.Errorf("list dns challenges: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list dns challenges: %w", err)
	}
	return records, nil
}

func (r Repository) MarkDNSChallengeCleanup(ctx context.Context, params MarkDNSChallengeCleanupParams) (DNSChallengeRecord, error) {
	if err := validateMarkDNSChallengeCleanup(&params); err != nil {
		return DNSChallengeRecord{}, err
	}
	record, err := scanDNSChallenge(r.db.QueryRow(ctx, `
update dns_challenge_records
set status = $2,
    presented_at = case when $2 in ('cleanup_pending', 'cleanup_failed', 'cleaned') then coalesce(presented_at, now()) else presented_at end,
    validated_at = case when $2 in ('cleanup_pending', 'cleanup_failed', 'cleaned') then coalesce(validated_at, now()) else validated_at end,
    cleaned_at = case when $2 = 'cleaned' then now() else null end,
    failure_code = case when $2 = 'cleanup_failed' then $3 else null end,
    failure_message = case when $2 = 'cleanup_failed' then $4 else null end,
    updated_at = now()
where id = $1
returning `+dnsChallengeReturningSQL(), params.ID, string(params.Status), params.FailureCode, params.FailureMessage))
	if err != nil {
		return DNSChallengeRecord{}, fmt.Errorf("mark dns challenge cleanup: %w", err)
	}
	return record, nil
}

func (r Repository) RecordEvent(ctx context.Context, params RecordEventParams) (Event, error) {
	if params.ID == "" {
		id, err := storage.NewUUID()
		if err != nil {
			return Event{}, err
		}
		params.ID = id
	}
	if err := validateRecordEvent(&params); err != nil {
		return Event{}, err
	}
	event, err := scanEvent(r.db.QueryRow(ctx, `
insert into certificate_events (
    id, certificate_id, certificate_version_id, issuance_job_id,
    event_type, result, correlation_id, message, metadata
) values (
    $1, $2, $3, $4,
    $5, $6, $7, $8, $9
)
returning `+eventReturningSQL(),
		params.ID, params.CertificateID, params.CertificateVersionID, params.IssuanceJobID,
		params.EventType, string(params.Result), params.CorrelationID, params.Message, []byte(params.Metadata)))
	if err != nil {
		return Event{}, fmt.Errorf("record certificate event: %w", err)
	}
	return event, nil
}

func (r Repository) ListEvents(ctx context.Context, params ListEventsParams) ([]Event, error) {
	query, args, err := r.listEventsQuery(params, false)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list certificate events: %w", err)
	}
	defer rows.Close()
	var events []Event
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("list certificate events: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list certificate events: %w", err)
	}
	return events, nil
}

func (r Repository) CountEvents(ctx context.Context, params ListEventsParams) (int64, error) {
	query, args, err := r.listEventsQuery(params, true)
	if err != nil {
		return 0, err
	}
	var total int64
	if err := r.db.QueryRow(ctx, query, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("count certificate events: %w", err)
	}
	return total, nil
}

func (r Repository) listQuery(params ListCertificatesParams, count bool) (string, []any, error) {
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return "", nil, err
	}
	if err := validateList(&params); err != nil {
		return "", nil, err
	}
	var args []any
	var where []string
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if params.ApplicationID != nil {
		add("c.application_id = $%d", *params.ApplicationID)
	}
	if len(params.ApplicationIDs) > 0 {
		placeholders := make([]string, 0, len(params.ApplicationIDs))
		for _, id := range params.ApplicationIDs {
			args = append(args, id)
			placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
		}
		where = append(where, "c.application_id in ("+strings.Join(placeholders, ", ")+")")
	}
	if params.IssuerID != nil {
		add("c.issuer_id = $%d", *params.IssuerID)
	}
	if params.Status != nil {
		add("c.status = $%d", string(*params.Status))
	}
	if params.Enabled != nil {
		add("c.enabled = $%d", *params.Enabled)
	}
	if params.KeyType != nil {
		add("c.key_type = $%d", string(*params.KeyType))
	}
	if len(params.NormalizedSANs) > 0 {
		add("c.normalized_sans = $%d::text[]", params.NormalizedSANs)
	}
	if params.ExpiresBefore != nil {
		add(`coalesce((
			select v.not_after <= $%d
			from certificate_versions v
			where v.certificate_id = c.id
			  and v.status = 'valid'
			order by v.version desc
			limit 1
		), false)`, *params.ExpiresBefore)
	}
	if !params.IncludeDeleted {
		where = append(where, "c.deleted_at is null")
	}
	if count {
		query := "select count(*)::bigint from certificates c"
		if len(where) > 0 {
			query += " where " + strings.Join(where, " and ")
		}
		return query, args, nil
	}
	args = append(args, opts.Limit, opts.Offset)
	query := "select " + certificateSelectSQL("c") + " from certificates c"
	if len(where) > 0 {
		query += " where " + strings.Join(where, " and ")
	}
	query += fmt.Sprintf(" order by c.created_at desc, c.id desc limit $%d offset $%d", len(args)-1, len(args))
	return query, args, nil
}

func (r Repository) listDNSChallengesQuery(params ListDNSChallengesParams) (string, []any, error) {
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return "", nil, err
	}
	var args []any
	var where []string
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	for field, value := range map[string]*string{
		"issuance_job_id":        params.IssuanceJobID,
		"certificate_id":         params.CertificateID,
		"certificate_version_id": params.CertificateVersionID,
	} {
		if value != nil {
			if err := storage.ValidateUUID(*value, field); err != nil {
				return "", nil, err
			}
		}
	}
	if params.Status != nil {
		if err := validateDNSChallengeStatus(*params.Status); err != nil {
			return "", nil, err
		}
	}
	if params.IssuanceJobID != nil {
		add("issuance_job_id = $%d", *params.IssuanceJobID)
	}
	if params.CertificateID != nil {
		add("certificate_id = $%d", *params.CertificateID)
	}
	if params.CertificateVersionID != nil {
		add("certificate_version_id = $%d", *params.CertificateVersionID)
	}
	if params.Status != nil {
		add("status = $%d", string(*params.Status))
	}
	args = append(args, opts.Limit, opts.Offset)
	query := "select " + dnsChallengeReturningSQL() + " from dns_challenge_records"
	if len(where) > 0 {
		query += " where " + strings.Join(where, " and ")
	}
	query += fmt.Sprintf(" order by created_at desc, id desc limit $%d offset $%d", len(args)-1, len(args))
	return query, args, nil
}

func (r Repository) listEventsQuery(params ListEventsParams, count bool) (string, []any, error) {
	opts, err := storage.NormalizeListOptions(params.ListOptions)
	if err != nil {
		return "", nil, err
	}
	if err := storage.ValidateUUID(params.CertificateID, "certificate_id"); err != nil {
		return "", nil, err
	}
	var args []any
	var where []string
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	add("certificate_id = $%d", params.CertificateID)
	if params.CertificateVersionID != nil {
		if err := storage.ValidateUUID(*params.CertificateVersionID, "certificate_version_id"); err != nil {
			return "", nil, err
		}
		add("certificate_version_id = $%d", *params.CertificateVersionID)
	}
	if params.IssuanceJobID != nil {
		if err := storage.ValidateUUID(*params.IssuanceJobID, "issuance_job_id"); err != nil {
			return "", nil, err
		}
		add("issuance_job_id = $%d", *params.IssuanceJobID)
	}
	if params.EventType != nil {
		if !eventTypeRE.MatchString(*params.EventType) {
			return "", nil, errors.New("event_type is invalid")
		}
		add("event_type = $%d", *params.EventType)
	}
	if params.Result != nil {
		if *params.Result != EventResultSuccess && *params.Result != EventResultFailure {
			return "", nil, errors.New("event result is invalid")
		}
		add("result = $%d", string(*params.Result))
	}
	if count {
		return "select count(*)::bigint from certificate_events where " + strings.Join(where, " and "), args, nil
	}
	args = append(args, opts.Limit, opts.Offset)
	query := "select " + eventReturningSQL() + " from certificate_events where " + strings.Join(where, " and ")
	query += fmt.Sprintf(" order by created_at asc, id asc limit $%d offset $%d", len(args)-1, len(args))
	return query, args, nil
}

func certificateSelectSQL(prefix string) string {
	return prefix + `.id, ` + prefix + `.enabled, ` + prefix + `.normalized_sans, ` + prefix + `.key_type, ` + prefix + `.issuer_id, ` +
		`(select i.name from issuers i where i.id = ` + prefix + `.issuer_id), ` +
		prefix + `.application_id, ` + prefix + `.status, ` + prefix + `.failure_code, ` + prefix + `.failure_message, ` +
		prefix + `.revocation_reason, ` + prefix + `.revoked_at, ` + prefix + `.revoked_by_user_id, ` +
		prefix + `.created_at, ` + prefix + `.updated_at, ` + prefix + `.deleted_at, ` +
		`(select count(*) from certificate_versions where certificate_id = ` + prefix + `.id)::bigint, ` +
		`exists (select 1 from certificate_versions v where v.certificate_id = ` + prefix + `.id and v.status = 'valid' and v.cert_pem is not null and v.chain_pem is not null and v.fullchain_pem is not null and v.private_key_pem is not null and v.material_etag is not null and v.not_before <= now() and v.not_after > now() and ` + prefix + `.status not in ('failed', 'deleted')), ` +
		`exists (select 1 from certificate_versions v where v.certificate_id = ` + prefix + `.id and v.status = 'issuing')`
}

func certificateReturningSQL() string {
	return `id, enabled, normalized_sans, key_type, issuer_id, (select i.name from issuers i where i.id = certificates.issuer_id), application_id, status, failure_code, failure_message,
    revocation_reason, revoked_at, revoked_by_user_id, created_at, updated_at, deleted_at,
    (select count(*) from certificate_versions where certificate_id = certificates.id)::bigint,
    exists (select 1 from certificate_versions v where v.certificate_id = certificates.id and v.status = 'valid' and v.cert_pem is not null and v.chain_pem is not null and v.fullchain_pem is not null and v.private_key_pem is not null and v.material_etag is not null and v.not_before <= now() and v.not_after > now() and certificates.status not in ('failed', 'deleted')),
    exists (select 1 from certificate_versions v where v.certificate_id = certificates.id and v.status = 'issuing')`
}

func certificateVersionSelectSQL(prefix string) string {
	return prefix + `.id, ` + prefix + `.certificate_id, ` + prefix + `.version, ` + prefix + `.status, ` +
		prefix + `.reason, ` + prefix + `.cert_pem, ` + prefix + `.chain_pem, ` + prefix + `.fullchain_pem, ` +
		prefix + `.private_key_pem, ` + prefix + `.not_before, ` + prefix + `.not_after, ` +
		prefix + `.serial_number, ` + prefix + `.fingerprint_sha256, ` + prefix + `.key_fingerprint_sha256, ` +
		prefix + `.material_etag, ` + prefix + `.acme_order_url, ` + prefix + `.certificate_url, ` +
		prefix + `.revocation_reason, ` + prefix + `.revoked_at, ` + prefix + `.revoked_by_user_id, ` +
		prefix + `.acme_revocation_status, ` + prefix + `.acme_revocation_attempts, ` + prefix + `.acme_revoked_at, ` +
		prefix + `.acme_revocation_failure_code, ` + prefix + `.acme_revocation_failure_message, ` +
		prefix + `.created_at, ` + prefix + `.updated_at, ` + prefix + `.started_at, ` + prefix + `.completed_at, ` +
		prefix + `.issued_at, ` + prefix + `.failure_code, ` + prefix + `.failure_message`
}

func certificateVersionReturningSQL() string {
	return `id, certificate_id, version, status, reason, cert_pem, chain_pem, fullchain_pem,
	    private_key_pem, not_before, not_after, serial_number, fingerprint_sha256, key_fingerprint_sha256,
	    material_etag, acme_order_url, certificate_url, revocation_reason, revoked_at, revoked_by_user_id,
	    acme_revocation_status, acme_revocation_attempts,
	    acme_revoked_at, acme_revocation_failure_code, acme_revocation_failure_message,
	    created_at, updated_at, started_at, completed_at, issued_at, failure_code, failure_message`
}

func issuanceJobReturningSQL() string {
	return `id, certificate_id, certificate_version_id, reason, status, attempt, locked_by, locked_until,
    next_run_at, started_at, completed_at, failure_code, failure_message, created_at, updated_at`
}

func prefixedIssuanceJobColumnsSQL(prefix string) string {
	return prefix + `.id, ` + prefix + `.certificate_id, ` + prefix + `.certificate_version_id, ` +
		prefix + `.reason, ` + prefix + `.status, ` + prefix + `.attempt, ` + prefix + `.locked_by, ` +
		prefix + `.locked_until, ` + prefix + `.next_run_at, ` + prefix + `.started_at, ` + prefix + `.completed_at, ` +
		prefix + `.failure_code, ` + prefix + `.failure_message, ` + prefix + `.created_at, ` + prefix + `.updated_at`
}

func dnsChallengeReturningSQL() string {
	return `id, issuance_job_id, certificate_id, certificate_version_id, dns_provider_id, dns_provider_zone_id,
    authorization_identifier, record_name, txt_value_encrypted, status, presented_at, validated_at,
    cleaned_at, failure_code, failure_message, created_at, updated_at`
}

func eventReturningSQL() string {
	return `id, certificate_id, certificate_version_id, issuance_job_id, event_type, result,
    correlation_id, message, metadata, created_at`
}

type scanner interface {
	Scan(...any) error
}

func scanCertificate(row scanner) (Certificate, error) {
	var cert Certificate
	var keyType, status string
	var issuerName, failureCode, failureMessage, revocationReason, revokedByUserID sql.NullString
	var revokedAt, deletedAt sql.NullTime
	if err := row.Scan(
		&cert.ID,
		&cert.Enabled,
		&cert.NormalizedSANs,
		&keyType,
		&cert.IssuerID,
		&issuerName,
		&cert.ApplicationID,
		&status,
		&failureCode,
		&failureMessage,
		&revocationReason,
		&revokedAt,
		&revokedByUserID,
		&cert.CreatedAt,
		&cert.UpdatedAt,
		&deletedAt,
		&cert.VersionCount,
		&cert.HasActiveValidVersion,
		&cert.HasIssuingVersion,
	); err != nil {
		return Certificate{}, err
	}
	cert.KeyType = KeyType(keyType)
	cert.Status = Status(status)
	if issuerName.Valid {
		cert.IssuerName = issuerName.String
	}
	cert.FailureCode = stringPtr(failureCode)
	cert.FailureMessage = stringPtr(failureMessage)
	if revocationReason.Valid {
		value := RevocationReason(revocationReason.String)
		cert.RevocationReason = &value
	}
	cert.RevokedAt = timePtr(revokedAt)
	cert.RevokedByUserID = stringPtr(revokedByUserID)
	cert.DeletedAt = timePtr(deletedAt)
	return cert, nil
}

func scanCertificateVersion(row scanner) (CertificateVersion, error) {
	return scanCertificateVersionWith(row)
}

func scanCertificateVersionWith(row scanner, extraDestinations ...any) (CertificateVersion, error) {
	var version CertificateVersion
	var status, reason string
	var certPEM, chainPEM, fullchainPEM, privateKeyPEM sql.NullString
	var serialNumber, fingerprint, keyFingerprint, etag sql.NullString
	var acmeOrderURL, certificateURL, acmeRevocationStatus sql.NullString
	var revocationReason, revokedByUserID sql.NullString
	var revocationFailureCode, revocationFailureMessage sql.NullString
	var failureCode, failureMessage sql.NullString
	var notBefore, notAfter, revokedAt, acmeRevokedAt, startedAt, completedAt, issuedAt sql.NullTime
	destinations := []any{
		&version.ID,
		&version.CertificateID,
		&version.Version,
		&status,
		&reason,
		&certPEM,
		&chainPEM,
		&fullchainPEM,
		&privateKeyPEM,
		&notBefore,
		&notAfter,
		&serialNumber,
		&fingerprint,
		&keyFingerprint,
		&etag,
		&acmeOrderURL,
		&certificateURL,
		&revocationReason,
		&revokedAt,
		&revokedByUserID,
		&acmeRevocationStatus,
		&version.ACMERevocationAttempts,
		&acmeRevokedAt,
		&revocationFailureCode,
		&revocationFailureMessage,
		&version.CreatedAt,
		&version.UpdatedAt,
		&startedAt,
		&completedAt,
		&issuedAt,
		&failureCode,
		&failureMessage,
	}
	destinations = append(destinations, extraDestinations...)
	if err := row.Scan(destinations...); err != nil {
		return CertificateVersion{}, err
	}
	version.Status = VersionStatus(status)
	version.Reason = IssuanceReason(reason)
	version.CertPEM = stringPtr(certPEM)
	version.ChainPEM = stringPtr(chainPEM)
	version.FullchainPEM = stringPtr(fullchainPEM)
	version.PrivateKeyPEMEncrypted = stringPtr(privateKeyPEM)
	version.NotBefore = timePtr(notBefore)
	version.NotAfter = timePtr(notAfter)
	version.SerialNumber = stringPtr(serialNumber)
	version.FingerprintSHA256 = stringPtr(fingerprint)
	version.KeyFingerprintSHA256 = stringPtr(keyFingerprint)
	version.MaterialETag = stringPtr(etag)
	version.ACMEOrderURL = stringPtr(acmeOrderURL)
	version.CertificateURL = stringPtr(certificateURL)
	if revocationReason.Valid {
		value := RevocationReason(revocationReason.String)
		version.RevocationReason = &value
	}
	version.RevokedAt = timePtr(revokedAt)
	version.RevokedByUserID = stringPtr(revokedByUserID)
	if acmeRevocationStatus.Valid {
		value := ACMERemoteRevocationStatus(acmeRevocationStatus.String)
		version.ACMERevocationStatus = &value
	}
	version.ACMERevokedAt = timePtr(acmeRevokedAt)
	version.ACMERevocationFailureCode = stringPtr(revocationFailureCode)
	version.ACMERevocationFailureMessage = stringPtr(revocationFailureMessage)
	version.StartedAt = timePtr(startedAt)
	version.CompletedAt = timePtr(completedAt)
	version.IssuedAt = timePtr(issuedAt)
	version.FailureCode = stringPtr(failureCode)
	version.FailureMessage = stringPtr(failureMessage)
	return version, nil
}

func scanRenewalCandidate(row scanner) (RenewalCandidate, error) {
	var renewalNotBefore time.Time
	var applicationID string
	var normalizedSANs []string
	version, err := scanCertificateVersionWith(row, &renewalNotBefore, &applicationID, &normalizedSANs)
	if err != nil {
		return RenewalCandidate{}, err
	}
	return RenewalCandidate{CertificateID: version.CertificateID, ApplicationID: applicationID, NormalizedSANs: normalizedSANs, ActiveVersion: version, RenewalNotBefore: renewalNotBefore}, nil
}

func scanIssuanceJob(row scanner) (IssuanceJob, error) {
	var job IssuanceJob
	var certificateVersionID, lockedBy, failureCode, failureMessage sql.NullString
	var reason, status string
	var lockedUntil, startedAt, completedAt sql.NullTime
	if err := row.Scan(
		&job.ID,
		&job.CertificateID,
		&certificateVersionID,
		&reason,
		&status,
		&job.Attempt,
		&lockedBy,
		&lockedUntil,
		&job.NextRunAt,
		&startedAt,
		&completedAt,
		&failureCode,
		&failureMessage,
		&job.CreatedAt,
		&job.UpdatedAt,
	); err != nil {
		return IssuanceJob{}, err
	}
	job.CertificateVersionID = stringPtr(certificateVersionID)
	job.Reason = JobReason(reason)
	job.Status = JobStatus(status)
	job.LockedBy = stringPtr(lockedBy)
	job.LockedUntil = timePtr(lockedUntil)
	job.StartedAt = timePtr(startedAt)
	job.CompletedAt = timePtr(completedAt)
	job.FailureCode = stringPtr(failureCode)
	job.FailureMessage = stringPtr(failureMessage)
	return job, nil
}

func scanDNSChallenge(row scanner) (DNSChallengeRecord, error) {
	var record DNSChallengeRecord
	var status string
	var presentedAt, validatedAt, cleanedAt sql.NullTime
	var failureCode, failureMessage sql.NullString
	if err := row.Scan(
		&record.ID,
		&record.IssuanceJobID,
		&record.CertificateID,
		&record.CertificateVersionID,
		&record.DNSProviderID,
		&record.DNSProviderZoneID,
		&record.AuthorizationIdentifier,
		&record.RecordName,
		&record.TXTValueEncrypted,
		&status,
		&presentedAt,
		&validatedAt,
		&cleanedAt,
		&failureCode,
		&failureMessage,
		&record.CreatedAt,
		&record.UpdatedAt,
	); err != nil {
		return DNSChallengeRecord{}, err
	}
	record.Status = DNSChallengeStatus(status)
	record.PresentedAt = timePtr(presentedAt)
	record.ValidatedAt = timePtr(validatedAt)
	record.CleanedAt = timePtr(cleanedAt)
	record.FailureCode = stringPtr(failureCode)
	record.FailureMessage = stringPtr(failureMessage)
	return record, nil
}

func scanEvent(row scanner) (Event, error) {
	var event Event
	var certificateVersionID, issuanceJobID, correlationID, message sql.NullString
	var result string
	var metadata []byte
	if err := row.Scan(
		&event.ID,
		&event.CertificateID,
		&certificateVersionID,
		&issuanceJobID,
		&event.EventType,
		&result,
		&correlationID,
		&message,
		&metadata,
		&event.CreatedAt,
	); err != nil {
		return Event{}, err
	}
	event.CertificateVersionID = stringPtr(certificateVersionID)
	event.IssuanceJobID = stringPtr(issuanceJobID)
	event.Result = EventResult(result)
	event.CorrelationID = stringPtr(correlationID)
	event.Message = stringPtr(message)
	event.Metadata = append(json.RawMessage(nil), metadata...)
	return event, nil
}

func statusForIssuanceReason(reason IssuanceReason) Status {
	switch reason {
	case IssuanceReasonRenewal:
		return StatusRenewing
	case IssuanceReasonKeyRotation:
		return StatusRotatingKey
	case IssuanceReasonReissue:
		return StatusIssuing
	default:
		return StatusIssuing
	}
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
