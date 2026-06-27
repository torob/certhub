-- +goose Up
-- +goose StatementBegin
create function certhub_certificate_sans_valid(sans text[])
returns boolean
language sql
immutable
as $$
    select coalesce(cardinality(sans), 0) > 0
       and coalesce(cardinality(sans), 0) <= 100
       and sans = (
           select array_agg(distinct san order by san)
           from unnest(sans) as san
       )
       and not exists (
           select 1
           from unnest(sans) as san
           where san is null
              or length(san) > 253
              or san !~ '^(\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
       )
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create function certhub_reject_certificate_version_regression()
returns trigger
language plpgsql
as $$
begin
    if exists (
        select 1
        from certificate_versions
        where certificate_id = new.certificate_id
          and version >= new.version
    ) then
        raise exception 'certificate version numbers must increase';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create function certhub_enforce_system_application_certificate_limit()
returns trigger
language plpgsql
as $$
begin
    if new.deleted_at is null
        and exists (
            select 1
            from applications
            where id = new.application_id
              and system_kind = 'certhub_server'
        )
        and exists (
            select 1
            from certificates
            where application_id = new.application_id
              and deleted_at is null
              and id <> new.id
        ) then
        raise exception 'certhub_server application may have at most one active certificate';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create function certhub_enforce_certificate_version_overlap()
returns trigger
language plpgsql
as $$
declare
    active_valid_count integer;
begin
    if new.status = 'valid' and new.not_after > now() then
        select count(*) into active_valid_count
        from certificate_versions
        where certificate_id = new.certificate_id
          and status = 'valid'
          and not_after > now()
          and id <> new.id;

        if active_valid_count >= 2 then
            raise exception 'too many active valid certificate versions';
        end if;
    end if;
    return new;
end;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create function certhub_reject_certificate_event_mutation()
returns trigger
language plpgsql
as $$
begin
    raise exception 'certificate_events are append-only';
end;
$$;
-- +goose StatementEnd

create table certificates (
    id uuid primary key,
    normalized_sans text[] not null,
    key_type text not null,
    issuer_id uuid not null references issuers(id),
    application_id uuid not null references applications(id),
    status text not null default 'pending',
    failure_code text,
    failure_message text,
    revocation_reason text,
    revoked_at timestamptz,
    revoked_by_user_id uuid references users(id),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz,
    constraint certificates_sans_valid check (certhub_certificate_sans_valid(normalized_sans)),
    constraint certificates_key_type_valid check (key_type in ('rsa-2048', 'rsa-3072', 'rsa-4096', 'ecdsa-p256', 'ecdsa-p384')),
    constraint certificates_status_valid check (status in ('pending', 'validating_dns', 'issuing', 'ready', 'renewing', 'rotating_key', 'expired', 'revoked', 'failed', 'deleted')),
    constraint certificates_failure_code_format check (
        failure_code is null or (length(failure_code) between 1 and 128 and failure_code ~ '^[a-z][a-z0-9_]{0,127}$')
    ),
    constraint certificates_failure_message_format check (
        failure_message is null or (length(failure_message) <= 2048 and failure_message !~ '[[:cntrl:]]')
    ),
    constraint certificates_failure_state check (
        (status = 'failed' and failure_code is not null)
        or (status <> 'failed' and failure_code is null and failure_message is null)
    ),
    constraint certificates_revocation_reason_valid check (
        revocation_reason is null or revocation_reason in ('key_compromise', 'superseded', 'cessation_of_operation', 'unspecified')
    ),
    constraint certificates_revoked_state check (
        (status = 'revoked' and revocation_reason is not null and revoked_at is not null)
        or (status <> 'revoked' and revocation_reason is null and revoked_at is null and revoked_by_user_id is null)
    ),
    constraint certificates_deleted_state check (
        (status = 'deleted' and deleted_at is not null)
        or (status <> 'deleted' and deleted_at is null)
    ),
    constraint certificates_updated_at_after_created check (updated_at >= created_at)
);

create unique index uniq_active_certificate_identity_per_application
on certificates (application_id, normalized_sans, key_type, issuer_id)
where deleted_at is null;
create trigger certificates_system_application_limit
before insert or update of application_id, deleted_at on certificates
for each row execute function certhub_enforce_system_application_certificate_limit();
create index certificates_application_id_idx on certificates (application_id);
create index certificates_issuer_id_idx on certificates (issuer_id);
create index certificates_status_idx on certificates (status);
create index certificates_sans_gin_idx on certificates using gin (normalized_sans);

alter table audit_events
add constraint audit_events_scope_certificate_id_fkey
foreign key (scope_certificate_id) references certificates(id);

create table certificate_versions (
    id uuid primary key,
    certificate_id uuid not null references certificates(id),
    version integer not null,
    status text not null default 'issuing',
    reason text not null,
    cert_pem text,
    chain_pem text,
    fullchain_pem text,
    private_key_pem text,
    not_before timestamptz,
    not_after timestamptz,
    serial_number text,
    fingerprint_sha256 text,
    key_fingerprint_sha256 text,
    material_etag text,
    acme_order_url text,
    certificate_url text,
    acme_revocation_status text,
    acme_revocation_attempts integer not null default 0,
    acme_revoked_at timestamptz,
    acme_revocation_failure_code text,
    acme_revocation_failure_message text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    started_at timestamptz,
    completed_at timestamptz,
    issued_at timestamptz,
    failure_code text,
    failure_message text,
    constraint certificate_versions_version_positive check (version > 0),
    constraint certificate_versions_status_valid check (status in ('issuing', 'valid', 'failed', 'revoked')),
    constraint certificate_versions_reason_valid check (reason in ('initial_issue', 'renewal', 'key_rotation')),
    constraint certificate_versions_material_state check (
        (status in ('valid', 'revoked')
            and cert_pem is not null
            and chain_pem is not null
            and fullchain_pem is not null
            and private_key_pem is not null
            and not_before is not null
            and not_after is not null
            and serial_number is not null
            and fingerprint_sha256 is not null
            and key_fingerprint_sha256 is not null
            and material_etag is not null
            and issued_at is not null)
        or status in ('issuing', 'failed')
    ),
    constraint certificate_versions_validity_window check (
        (not_before is null and not_after is null) or (not_before is not null and not_after is not null and not_after > not_before)
    ),
    constraint certificate_versions_private_key_envelope_format check (
        private_key_pem is null or (length(private_key_pem) between 1 and 8192 and left(private_key_pem, 1) = '{')
    ),
    constraint certificate_versions_fingerprint_format check (
        fingerprint_sha256 is null or fingerprint_sha256 ~ '^[a-f0-9]{64}$'
    ),
    constraint certificate_versions_key_fingerprint_format check (
        key_fingerprint_sha256 is null or key_fingerprint_sha256 ~ '^[a-f0-9]{64}$'
    ),
    constraint certificate_versions_material_etag_format check (
        material_etag is null or material_etag ~ '^"cth-mat-v1\.[A-Za-z0-9_-]{43}"$'
    ),
    constraint certificate_versions_url_format check (
        (acme_order_url is null or (length(acme_order_url) <= 2048 and acme_order_url ~ '^https://[^[:space:]@#]+' and acme_order_url !~ '[[:cntrl:]]'))
        and (certificate_url is null or (length(certificate_url) <= 2048 and certificate_url ~ '^https://[^[:space:]@#]+' and certificate_url !~ '[[:cntrl:]]'))
    ),
    constraint certificate_versions_revocation_status_valid check (
        acme_revocation_status is null or acme_revocation_status in ('pending', 'succeeded', 'failed', 'not_required')
    ),
    constraint certificate_versions_revocation_attempts_valid check (acme_revocation_attempts >= 0),
    constraint certificate_versions_revocation_failure_code_format check (
        acme_revocation_failure_code is null or (length(acme_revocation_failure_code) between 1 and 128 and acme_revocation_failure_code ~ '^[a-z][a-z0-9_]{0,127}$')
    ),
    constraint certificate_versions_revocation_failure_message_format check (
        acme_revocation_failure_message is null or (length(acme_revocation_failure_message) <= 2048 and acme_revocation_failure_message !~ '[[:cntrl:]]')
    ),
    constraint certificate_versions_issuing_started check (status <> 'issuing' or started_at is not null),
    constraint certificate_versions_terminal_completed check (
        (status in ('valid', 'failed', 'revoked') and completed_at is not null)
        or (status = 'issuing' and completed_at is null)
    ),
    constraint certificate_versions_failure_code_format check (
        failure_code is null or (length(failure_code) between 1 and 128 and failure_code ~ '^[a-z][a-z0-9_]{0,127}$')
    ),
    constraint certificate_versions_failure_message_format check (
        failure_message is null or (length(failure_message) <= 2048 and failure_message !~ '[[:cntrl:]]')
    ),
    constraint certificate_versions_failure_state check (
        (status = 'failed' and failure_code is not null)
        or (status <> 'failed' and failure_code is null and failure_message is null)
    ),
    constraint certificate_versions_updated_at_after_created check (updated_at >= created_at)
);

create trigger certificate_versions_monotonic
before insert on certificate_versions
for each row execute function certhub_reject_certificate_version_regression();

create trigger certificate_versions_valid_overlap
before insert or update of status, not_after on certificate_versions
for each row execute function certhub_enforce_certificate_version_overlap();

create unique index certificate_versions_certificate_version_unique on certificate_versions (certificate_id, version);
create unique index certificate_versions_one_issuing_per_certificate_idx
on certificate_versions (certificate_id)
where status = 'issuing';
create index certificate_versions_certificate_id_idx on certificate_versions (certificate_id);
create index certificate_versions_material_etag_idx on certificate_versions (material_etag)
where material_etag is not null;
create index certificate_versions_latest_valid_idx
on certificate_versions (certificate_id, version desc)
where status = 'valid';

create table certificate_issuance_jobs (
    id uuid primary key,
    certificate_id uuid not null references certificates(id),
    certificate_version_id uuid references certificate_versions(id),
    reason text not null,
    status text not null default 'pending',
    attempt integer not null default 1,
    locked_by text,
    locked_until timestamptz,
    next_run_at timestamptz not null default now(),
    started_at timestamptz,
    completed_at timestamptz,
    failure_code text,
    failure_message text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint certificate_issuance_jobs_reason_valid check (reason in ('initial_issue', 'renewal', 'key_rotation', 'revocation_retry', 'dns_cleanup')),
    constraint certificate_issuance_jobs_status_valid check (status in ('pending', 'running', 'succeeded', 'failed', 'canceled')),
    constraint certificate_issuance_jobs_attempt_positive check (attempt > 0),
    constraint certificate_issuance_jobs_locked_by_format check (
        locked_by is null or (length(locked_by) between 1 and 255 and locked_by !~ '[[:cntrl:]]')
    ),
    constraint certificate_issuance_jobs_lock_pair check (
        (locked_by is null and locked_until is null) or (locked_by is not null and locked_until is not null)
    ),
    constraint certificate_issuance_jobs_running_state check (status <> 'running' or (locked_by is not null and locked_until is not null and started_at is not null)),
    constraint certificate_issuance_jobs_completed_state check (
        (status in ('succeeded', 'failed', 'canceled') and completed_at is not null)
        or (status in ('pending', 'running') and completed_at is null)
    ),
    constraint certificate_issuance_jobs_failure_code_format check (
        failure_code is null or (length(failure_code) between 1 and 128 and failure_code ~ '^[a-z][a-z0-9_]{0,127}$')
    ),
    constraint certificate_issuance_jobs_failure_message_format check (
        failure_message is null or (length(failure_message) <= 2048 and failure_message !~ '[[:cntrl:]]')
    ),
    constraint certificate_issuance_jobs_failure_state check (
        (status = 'failed' and failure_code is not null)
        or (status <> 'failed' and failure_code is null and failure_message is null)
    ),
    constraint certificate_issuance_jobs_updated_at_after_created check (updated_at >= created_at)
);

create unique index certificate_issuance_jobs_active_version_idx
on certificate_issuance_jobs (certificate_version_id)
where certificate_version_id is not null and status in ('pending', 'running');
create unique index certificate_issuance_jobs_active_null_version_idx
on certificate_issuance_jobs (certificate_id, reason)
where certificate_version_id is null and status in ('pending', 'running');
create index certificate_issuance_jobs_claim_idx
on certificate_issuance_jobs (next_run_at, created_at, id)
where status in ('pending', 'running');
create index certificate_issuance_jobs_certificate_id_idx on certificate_issuance_jobs (certificate_id);
create index certificate_issuance_jobs_certificate_version_id_idx on certificate_issuance_jobs (certificate_version_id)
where certificate_version_id is not null;

create table dns_challenge_records (
    id uuid primary key,
    issuance_job_id uuid not null references certificate_issuance_jobs(id),
    certificate_id uuid not null references certificates(id),
    certificate_version_id uuid not null references certificate_versions(id),
    dns_provider_id uuid not null references dns_providers(id),
    dns_provider_zone_id uuid not null references dns_provider_zones(id),
    authorization_identifier text not null,
    record_name text not null,
    txt_value_encrypted text not null,
    status text not null default 'pending',
    presented_at timestamptz,
    validated_at timestamptz,
    cleaned_at timestamptz,
    failure_code text,
    failure_message text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint dns_challenge_records_authorization_identifier_format check (
        authorization_identifier ~ '^(\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
    ),
    constraint dns_challenge_records_record_name_format check (
        record_name ~ '^_acme-challenge(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
    ),
    constraint dns_challenge_records_txt_envelope_format check (
        length(txt_value_encrypted) between 1 and 8192 and left(txt_value_encrypted, 1) = '{'
    ),
    constraint dns_challenge_records_status_valid check (status in ('pending', 'presented', 'validated', 'cleanup_pending', 'cleanup_failed', 'cleaned')),
    constraint dns_challenge_records_presented_state check (presented_at is not null or status = 'pending'),
    constraint dns_challenge_records_validated_state check (validated_at is not null or status not in ('validated', 'cleanup_pending', 'cleanup_failed', 'cleaned')),
    constraint dns_challenge_records_cleaned_state check ((status = 'cleaned' and cleaned_at is not null) or (status <> 'cleaned' and cleaned_at is null)),
    constraint dns_challenge_records_failure_code_format check (
        failure_code is null or (length(failure_code) between 1 and 128 and failure_code ~ '^[a-z][a-z0-9_]{0,127}$')
    ),
    constraint dns_challenge_records_failure_message_format check (
        failure_message is null or (length(failure_message) <= 2048 and failure_message !~ '[[:cntrl:]]')
    ),
    constraint dns_challenge_records_cleanup_failure_state check (
        (status = 'cleanup_failed' and failure_code is not null)
        or (status <> 'cleanup_failed' and failure_code is null and failure_message is null)
    ),
    constraint dns_challenge_records_updated_at_after_created check (updated_at >= created_at)
);

create unique index dns_challenge_records_exact_value_idx
on dns_challenge_records (issuance_job_id, record_name, txt_value_encrypted);
create index dns_challenge_records_job_id_idx on dns_challenge_records (issuance_job_id);
create index dns_challenge_records_certificate_id_idx on dns_challenge_records (certificate_id);
create index dns_challenge_records_version_id_idx on dns_challenge_records (certificate_version_id);
create index dns_challenge_records_cleanup_idx
on dns_challenge_records (status, updated_at)
where status in ('cleanup_pending', 'cleanup_failed');

create table certificate_events (
    id uuid primary key,
    certificate_id uuid not null references certificates(id),
    certificate_version_id uuid references certificate_versions(id),
    issuance_job_id uuid references certificate_issuance_jobs(id),
    event_type text not null,
    result text not null default 'success',
    correlation_id text,
    message text,
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    constraint certificate_events_event_type_format check (length(event_type) between 1 and 128 and event_type ~ '^[a-z][a-z0-9_]{0,127}$'),
    constraint certificate_events_result_valid check (result in ('success', 'failure')),
    constraint certificate_events_correlation_id_format check (correlation_id is null or correlation_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
    constraint certificate_events_message_format check (message is null or (length(message) <= 2048 and message !~ '[[:cntrl:]]')),
    constraint certificate_events_metadata_object check (jsonb_typeof(metadata) = 'object')
);

create trigger certificate_events_append_only
before update or delete or truncate on certificate_events
for each statement execute function certhub_reject_certificate_event_mutation();

create index certificate_events_certificate_created_at_idx on certificate_events (certificate_id, created_at desc, id desc);
create index certificate_events_version_created_at_idx on certificate_events (certificate_version_id, created_at desc)
where certificate_version_id is not null;
create index certificate_events_job_created_at_idx on certificate_events (issuance_job_id, created_at desc)
where issuance_job_id is not null;

-- +goose Down
drop table if exists certificate_events;
drop table if exists dns_challenge_records;
drop table if exists certificate_issuance_jobs;
drop table if exists certificate_versions;
alter table audit_events drop constraint if exists audit_events_scope_certificate_id_fkey;
drop table if exists certificates;

drop function if exists certhub_reject_certificate_event_mutation();
drop function if exists certhub_enforce_certificate_version_overlap();
drop function if exists certhub_enforce_system_application_certificate_limit();
drop function if exists certhub_reject_certificate_version_regression();
drop function if exists certhub_certificate_sans_valid(text[]);
