-- +goose Up
-- +goose StatementBegin
create function certhub_reject_issuer_immutable_update()
returns trigger
language plpgsql
as $$
begin
    if old.name is distinct from new.name
        or old.type is distinct from new.type
        or old.directory_url is distinct from new.directory_url
        or old.environment is distinct from new.environment then
        raise exception 'issuer identity fields are immutable';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create function certhub_require_active_issuer_account()
returns trigger
language plpgsql
as $$
begin
    if new.status = 'active' and not exists (
        select 1
        from acme_accounts
        where issuer_id = new.id
          and status = 'active'
    ) then
        raise exception 'active issuers require an active ACME account';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create function certhub_preserve_active_issuer_account()
returns trigger
language plpgsql
as $$
begin
    if tg_op = 'DELETE' then
        if old.status = 'active'
            and exists (
                select 1
                from issuers
                where id = old.issuer_id
                  and status = 'active'
            )
            and not exists (
                select 1
                from acme_accounts
                where issuer_id = old.issuer_id
                  and status = 'active'
                  and id <> old.id
            ) then
            raise exception 'active issuers require an active ACME account';
        end if;
        return old;
    end if;

    if old.status = 'active'
        and (new.status <> 'active' or new.issuer_id is distinct from old.issuer_id)
        and exists (
            select 1
            from issuers
            where id = old.issuer_id
              and status = 'active'
        )
        and not exists (
            select 1
            from acme_accounts
            where issuer_id = old.issuer_id
              and status = 'active'
              and id <> old.id
        ) then
        raise exception 'active issuers require an active ACME account';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create function certhub_reject_dns_provider_zone_update()
returns trigger
language plpgsql
as $$
begin
    raise exception 'dns_provider_zones are immutable; delete and insert instead';
end;
$$;
-- +goose StatementEnd

create table issuers (
    id uuid primary key,
    name text not null,
    type text not null default 'acme',
    directory_url text not null,
    environment text not null,
    is_default boolean not null default false,
    status text not null default 'disabled',
    renewal_window_seconds integer not null default 2592000,
    contact_email text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint issuers_name_format check (name ~ '^[a-z](?:[a-z0-9_]{0,62}[a-z0-9])?$'),
    constraint issuers_type_valid check (type in ('acme')),
    constraint issuers_directory_url_format check (
        length(directory_url) <= 2048
        and directory_url ~ '^https://[^[:space:]@#]+'
        and directory_url !~ '[[:space:][:cntrl:]]'
        and directory_url !~ '^https://[^/]+@'
        and position('#' in directory_url) = 0
    ),
    constraint issuers_environment_valid check (environment in ('production', 'staging')),
    constraint issuers_status_valid check (status in ('active', 'disabled')),
    constraint issuers_renewal_window_valid check (renewal_window_seconds >= 86400),
    constraint issuers_contact_email_normalized check (
        contact_email = lower(contact_email)
        and length(contact_email) between 3 and 254
        and contact_email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
        and contact_email !~ '[[:cntrl:]]'
    ),
    constraint issuers_updated_at_after_created check (updated_at >= created_at)
);

create trigger issuers_immutable_identity
before update on issuers
for each row execute function certhub_reject_issuer_immutable_update();

create trigger issuers_active_account_required
before insert or update of status on issuers
for each row execute function certhub_require_active_issuer_account();

create unique index issuers_name_unique on issuers (name);
create unique index issuers_one_active_default_idx on issuers ((is_default))
where is_default and status = 'active';
create index issuers_status_idx on issuers (status);
create index issuers_environment_idx on issuers (environment);

create table acme_accounts (
    id uuid primary key,
    issuer_id uuid not null references issuers(id),
    email text not null,
    account_url text not null,
    private_key_pem text not null,
    status text not null default 'active',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint acme_accounts_email_normalized check (
        email = lower(email)
        and length(email) between 3 and 254
        and email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
        and email !~ '[[:cntrl:]]'
    ),
    constraint acme_accounts_url_format check (
        length(account_url) <= 2048
        and account_url ~ '^https://[^[:space:]@#]+'
        and account_url !~ '[[:space:][:cntrl:]]'
        and account_url !~ '^https://[^/]+@'
        and position('#' in account_url) = 0
    ),
    constraint acme_accounts_private_key_envelope_format check (
        length(private_key_pem) between 1 and 8192 and left(private_key_pem, 1) = '{'
    ),
    constraint acme_accounts_status_valid check (status in ('active', 'disabled')),
    constraint acme_accounts_updated_at_after_created check (updated_at >= created_at)
);

create trigger acme_accounts_preserve_active_issuer
before update of issuer_id, status or delete on acme_accounts
for each row execute function certhub_preserve_active_issuer_account();

create unique index acme_accounts_account_url_unique on acme_accounts (account_url);
create unique index acme_accounts_one_active_per_issuer_idx on acme_accounts (issuer_id)
where status = 'active';
create index acme_accounts_issuer_id_idx on acme_accounts (issuer_id);
create index acme_accounts_status_idx on acme_accounts (status);

create table dns_providers (
    id uuid primary key,
    name text not null,
    type text not null,
    credentials_encrypted text not null,
    zone_mode text not null default 'manual',
    last_zone_refresh_at timestamptz,
    zone_refresh_status text not null default 'idle',
    zone_refresh_failure_code text,
    zone_refresh_failure_message text,
    status text not null default 'active',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint dns_providers_name_format check (name ~ '^[a-z](?:[a-z0-9_]{0,62}[a-z0-9])?$'),
    constraint dns_providers_type_valid check (type in ('cloudflare', 'arvancloud')),
    constraint dns_providers_credentials_envelope_format check (
        length(credentials_encrypted) between 1 and 8192 and left(credentials_encrypted, 1) = '{'
    ),
    constraint dns_providers_zone_mode_valid check (zone_mode in ('auto', 'manual')),
    constraint dns_providers_zone_refresh_status_valid check (zone_refresh_status in ('idle', 'pending', 'running', 'succeeded', 'failed')),
    constraint dns_providers_zone_refresh_failure_code_format check (
        zone_refresh_failure_code is null
        or (length(zone_refresh_failure_code) between 1 and 128 and zone_refresh_failure_code ~ '^[a-z][a-z0-9_]{0,127}$')
    ),
    constraint dns_providers_zone_refresh_failure_message_format check (
        zone_refresh_failure_message is null
        or (length(zone_refresh_failure_message) <= 2048 and zone_refresh_failure_message !~ '[[:cntrl:]]')
    ),
    constraint dns_providers_zone_refresh_failure_state check (
        (zone_refresh_status = 'failed' and zone_refresh_failure_code is not null)
        or (zone_refresh_status <> 'failed' and zone_refresh_failure_code is null and zone_refresh_failure_message is null)
    ),
    constraint dns_providers_status_valid check (status in ('active', 'disabled')),
    constraint dns_providers_updated_at_after_created check (updated_at >= created_at)
);

create unique index dns_providers_name_unique on dns_providers (name);
create index dns_providers_status_idx on dns_providers (status);
create index dns_providers_type_idx on dns_providers (type);
create index dns_providers_zone_mode_idx on dns_providers (zone_mode);

create table dns_provider_zones (
    id uuid primary key,
    dns_provider_id uuid not null references dns_providers(id),
    zone_name text not null,
    created_at timestamptz not null default now(),
    constraint dns_provider_zones_name_format check (
        zone_name ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
    )
);

create trigger dns_provider_zones_immutable
before update on dns_provider_zones
for each statement execute function certhub_reject_dns_provider_zone_update();

create unique index dns_provider_zones_provider_name_unique on dns_provider_zones (dns_provider_id, zone_name);
create unique index dns_provider_zones_name_unique on dns_provider_zones (zone_name);
create index dns_provider_zones_provider_id_idx on dns_provider_zones (dns_provider_id);
create index dns_provider_zones_name_length_idx on dns_provider_zones (length(zone_name) desc, zone_name);

create table dns_provider_zone_refresh_jobs (
    id uuid primary key,
    dns_provider_id uuid not null references dns_providers(id),
    status text not null default 'pending',
    locked_by text,
    locked_until timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    discovered_zone_count integer,
    failure_code text,
    failure_message text,
    conflict_zone_name text,
    conflict_dns_provider_id uuid references dns_providers(id),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint dns_provider_zone_refresh_jobs_status_valid check (status in ('pending', 'running', 'succeeded', 'failed', 'canceled')),
    constraint dns_provider_zone_refresh_jobs_locked_by_format check (
        locked_by is null or (length(locked_by) between 1 and 255 and locked_by !~ '[[:cntrl:]]')
    ),
    constraint dns_provider_zone_refresh_jobs_lock_pair check (
        (locked_by is null and locked_until is null) or (locked_by is not null and locked_until is not null)
    ),
    constraint dns_provider_zone_refresh_jobs_started_state check (
        status <> 'running' or started_at is not null
    ),
    constraint dns_provider_zone_refresh_jobs_completed_state check (
        (status in ('succeeded', 'failed', 'canceled') and completed_at is not null)
        or (status in ('pending', 'running') and completed_at is null)
    ),
    constraint dns_provider_zone_refresh_jobs_discovered_count_valid check (
        discovered_zone_count is null or discovered_zone_count >= 0
    ),
    constraint dns_provider_zone_refresh_jobs_failure_code_format check (
        failure_code is null or (length(failure_code) between 1 and 128 and failure_code ~ '^[a-z][a-z0-9_]{0,127}$')
    ),
    constraint dns_provider_zone_refresh_jobs_failure_message_format check (
        failure_message is null or (length(failure_message) <= 2048 and failure_message !~ '[[:cntrl:]]')
    ),
    constraint dns_provider_zone_refresh_jobs_failure_state check (
        (status = 'failed' and failure_code is not null)
        or (status <> 'failed' and failure_code is null and failure_message is null and conflict_zone_name is null and conflict_dns_provider_id is null)
    ),
    constraint dns_provider_zone_refresh_jobs_conflict_state check (
        (failure_code = 'dns_provider_zone_conflict' and conflict_zone_name is not null and conflict_dns_provider_id is not null)
        or (failure_code is distinct from 'dns_provider_zone_conflict' and conflict_zone_name is null and conflict_dns_provider_id is null)
    ),
    constraint dns_provider_zone_refresh_jobs_conflict_zone_format check (
        conflict_zone_name is null
        or conflict_zone_name ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
    ),
    constraint dns_provider_zone_refresh_jobs_updated_at_after_created check (updated_at >= created_at)
);

create unique index dns_provider_zone_refresh_jobs_one_active_per_provider_idx
on dns_provider_zone_refresh_jobs (dns_provider_id)
where status in ('pending', 'running');
create index dns_provider_zone_refresh_jobs_claim_idx
on dns_provider_zone_refresh_jobs (status, locked_until, created_at)
where status in ('pending', 'running');
create index dns_provider_zone_refresh_jobs_provider_id_idx on dns_provider_zone_refresh_jobs (dns_provider_id);

-- +goose Down
drop table if exists dns_provider_zone_refresh_jobs;
drop table if exists dns_provider_zones;
drop table if exists dns_providers;
drop table if exists acme_accounts;
drop table if exists issuers;

drop function if exists certhub_reject_dns_provider_zone_update();
drop function if exists certhub_preserve_active_issuer_account();
drop function if exists certhub_require_active_issuer_account();
drop function if exists certhub_reject_issuer_immutable_update();
