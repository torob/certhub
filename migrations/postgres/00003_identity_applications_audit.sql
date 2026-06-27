-- +goose Up
-- +goose StatementBegin
create function certhub_cidr_array_unique(cidrs cidr[])
returns boolean
language sql
immutable
as $$
    select coalesce(cardinality(cidrs), 0) = (
        select count(distinct cidr_value)::integer
        from unnest(cidrs) as cidr_value
    )
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create function certhub_reject_system_application_token()
returns trigger
language plpgsql
as $$
begin
    if exists (
        select 1
        from applications
        where id = new.application_id
          and system_kind = 'certhub_server'
    ) then
        raise exception 'application tokens cannot be created for system applications';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create function certhub_reject_system_application_grant()
returns trigger
language plpgsql
as $$
begin
    if exists (
        select 1
        from applications
        where id = new.application_id
          and system_kind = 'certhub_server'
    ) then
        raise exception 'user grants cannot be created for system applications';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create function certhub_reject_application_domain_scope_update()
returns trigger
language plpgsql
as $$
begin
    raise exception 'application domain scopes are immutable; delete and insert instead';
end;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create function certhub_reject_audit_event_mutation()
returns trigger
language plpgsql
as $$
begin
    raise exception 'audit_events are append-only';
end;
$$;
-- +goose StatementEnd

create table users (
    id uuid primary key,
    email text not null,
    display_name text not null,
    password_hash text,
    password_2fa_enabled boolean not null default false,
    totp_secret_encrypted text,
    pending_totp_secret_encrypted text,
    oidc_issuer text,
    oidc_subject text,
    global_role text not null default 'user',
    status text not null default 'active',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    last_login_at timestamptz,
    constraint users_email_normalized check (
        email = lower(email)
        and length(email) between 3 and 254
        and email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
        and email !~ '[[:cntrl:]]'
    ),
    constraint users_display_name_format check (length(display_name) between 1 and 255 and display_name !~ '[[:cntrl:]]'),
    constraint users_password_hash_format check (password_hash is null or (length(password_hash) between 1 and 4096 and password_hash !~ '[[:cntrl:]]')),
    constraint users_totp_enabled_secret check (not password_2fa_enabled or totp_secret_encrypted is not null),
    constraint users_totp_envelope_format check (
        totp_secret_encrypted is null or (length(totp_secret_encrypted) between 1 and 8192 and left(totp_secret_encrypted, 1) = '{')
    ),
    constraint users_pending_totp_envelope_format check (
        pending_totp_secret_encrypted is null or (length(pending_totp_secret_encrypted) between 1 and 8192 and left(pending_totp_secret_encrypted, 1) = '{')
    ),
    constraint users_oidc_pair check ((oidc_issuer is null and oidc_subject is null) or (oidc_issuer is not null and oidc_subject is not null)),
    constraint users_oidc_issuer_format check (oidc_issuer is null or (length(oidc_issuer) <= 2048 and oidc_issuer ~ '^https://[^[:space:]]+$' and oidc_issuer !~ '[[:cntrl:]]')),
    constraint users_oidc_subject_format check (oidc_subject is null or (length(oidc_subject) between 1 and 255 and oidc_subject !~ '[[:cntrl:]]')),
    constraint users_global_role_valid check (global_role in ('user', 'admin')),
    constraint users_status_valid check (status in ('active', 'disabled')),
    constraint users_updated_at_after_created check (updated_at >= created_at)
);

create unique index users_email_unique on users (email);
create unique index users_oidc_identity_unique on users (oidc_issuer, oidc_subject)
where oidc_issuer is not null and oidc_subject is not null;
create index users_status_idx on users (status);
create index users_global_role_idx on users (global_role);

create table user_sessions (
    id uuid primary key,
    user_id uuid not null references users(id),
    auth_method text not null,
    access_token_hash text not null,
    refresh_token_hash text not null,
    status text not null default 'active',
    created_at timestamptz not null default now(),
    access_expires_at timestamptz not null,
    refresh_expires_at timestamptz not null,
    last_refreshed_at timestamptz,
    last_used_at timestamptz,
    revoked_at timestamptz,
    revoked_reason text,
    user_agent text,
    source_ip text,
    constraint user_sessions_auth_method_valid check (auth_method in ('password', 'oidc')),
    constraint user_sessions_access_token_hash_format check (access_token_hash ~ '^[A-Za-z0-9_-]{43}$'),
    constraint user_sessions_refresh_token_hash_format check (refresh_token_hash ~ '^[A-Za-z0-9_-]{43}$'),
    constraint user_sessions_status_valid check (status in ('active', 'revoked')),
    constraint user_sessions_refresh_after_access check (refresh_expires_at > access_expires_at),
    constraint user_sessions_revoked_reason_valid check (revoked_reason is null or revoked_reason in ('logout', 'disabled_user', 'refresh_reuse', 'admin_action', 'expired')),
    constraint user_sessions_revoked_state check (
        (status = 'active' and revoked_at is null and revoked_reason is null)
        or (status = 'revoked' and revoked_at is not null and revoked_reason is not null)
    ),
    constraint user_sessions_user_agent_format check (user_agent is null or (length(user_agent) <= 1024 and user_agent !~ '[[:cntrl:]]')),
    constraint user_sessions_source_ip_format check (source_ip is null or (length(source_ip) <= 128 and source_ip !~ '[[:cntrl:]]'))
);

create unique index user_sessions_access_token_hash_unique on user_sessions (access_token_hash);
create unique index user_sessions_refresh_token_hash_unique on user_sessions (refresh_token_hash);
create index user_sessions_user_id_idx on user_sessions (user_id);
create index user_sessions_status_expires_idx on user_sessions (status, access_expires_at, refresh_expires_at);

create table user_session_refresh_tokens (
    id uuid primary key,
    user_session_id uuid not null references user_sessions(id),
    refresh_token_hash text not null,
    status text not null default 'active',
    issued_at timestamptz not null default now(),
    expires_at timestamptz not null,
    rotated_at timestamptz,
    last_seen_at timestamptz,
    constraint user_session_refresh_tokens_hash_format check (refresh_token_hash ~ '^[A-Za-z0-9_-]{43}$'),
    constraint user_session_refresh_tokens_status_valid check (status in ('active', 'rotated', 'revoked', 'reused', 'expired')),
    constraint user_session_refresh_tokens_expiry_after_issue check (expires_at > issued_at),
    constraint user_session_refresh_tokens_rotated_state check ((status <> 'rotated' and rotated_at is null) or (status = 'rotated' and rotated_at is not null))
);

create unique index user_session_refresh_tokens_hash_unique on user_session_refresh_tokens (refresh_token_hash);
create unique index user_session_refresh_tokens_one_active_per_session_idx on user_session_refresh_tokens (user_session_id)
where status = 'active';
create index user_session_refresh_tokens_session_idx on user_session_refresh_tokens (user_session_id);
create index user_session_refresh_tokens_status_expires_idx on user_session_refresh_tokens (status, expires_at);

create table oidc_login_states (
    id uuid primary key,
    state_hash text not null,
    nonce text not null,
    code_verifier_encrypted text not null,
    provider_callback_url text not null,
    frontend_return_url text,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    created_at timestamptz not null default now(),
    source_ip text,
    user_agent text,
    constraint oidc_login_states_state_hash_format check (state_hash ~ '^[A-Za-z0-9_-]{43}$'),
    constraint oidc_login_states_nonce_format check (length(nonce) between 22 and 256 and nonce !~ '[[:cntrl:]]'),
    constraint oidc_login_states_code_verifier_envelope_format check (length(code_verifier_encrypted) between 1 and 8192 and left(code_verifier_encrypted, 1) = '{'),
    constraint oidc_login_states_provider_callback_url_format check (length(provider_callback_url) <= 2048 and provider_callback_url ~ '^https://[^[:space:]]+$' and provider_callback_url !~ '[[:cntrl:]]'),
    constraint oidc_login_states_frontend_return_url_format check (frontend_return_url is null or (length(frontend_return_url) <= 2048 and frontend_return_url ~ '^https://[^[:space:]]+$' and frontend_return_url !~ '[[:cntrl:]]')),
    constraint oidc_login_states_expiry_after_created check (expires_at > created_at),
    constraint oidc_login_states_source_ip_format check (source_ip is null or (length(source_ip) <= 128 and source_ip !~ '[[:cntrl:]]')),
    constraint oidc_login_states_user_agent_format check (user_agent is null or (length(user_agent) <= 1024 and user_agent !~ '[[:cntrl:]]'))
);

create unique index oidc_login_states_state_hash_unique on oidc_login_states (state_hash);
create index oidc_login_states_active_idx on oidc_login_states (expires_at)
where consumed_at is null;

create table oidc_login_handoffs (
    id uuid primary key,
    handoff_hash text not null,
    user_id uuid not null references users(id),
    oidc_login_state_id uuid references oidc_login_states(id),
    frontend_return_url text,
    status text not null default 'active',
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    consumed_at timestamptz,
    source_ip text,
    user_agent text,
    constraint oidc_login_handoffs_handoff_hash_format check (handoff_hash ~ '^[A-Za-z0-9_-]{43}$'),
    constraint oidc_login_handoffs_frontend_return_url_format check (frontend_return_url is null or (length(frontend_return_url) <= 2048 and frontend_return_url ~ '^https://[^[:space:]]+$' and frontend_return_url !~ '[[:cntrl:]]')),
    constraint oidc_login_handoffs_status_valid check (status in ('active', 'consumed', 'expired')),
    constraint oidc_login_handoffs_expiry_after_created check (expires_at > created_at),
    constraint oidc_login_handoffs_consumed_state check ((status = 'consumed' and consumed_at is not null) or (status <> 'consumed' and consumed_at is null)),
    constraint oidc_login_handoffs_source_ip_format check (source_ip is null or (length(source_ip) <= 128 and source_ip !~ '[[:cntrl:]]')),
    constraint oidc_login_handoffs_user_agent_format check (user_agent is null or (length(user_agent) <= 1024 and user_agent !~ '[[:cntrl:]]'))
);

create unique index oidc_login_handoffs_handoff_hash_unique on oidc_login_handoffs (handoff_hash);
create index oidc_login_handoffs_user_id_idx on oidc_login_handoffs (user_id);
create index oidc_login_handoffs_active_idx on oidc_login_handoffs (expires_at)
where status = 'active';

create table applications (
    id uuid primary key,
    name text not null,
    display_name text not null,
    status text not null default 'active',
    system_kind text,
    description text,
    trusted_source_cidrs cidr[] not null default array[]::cidr[],
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint applications_name_format check (name ~ '^[a-z](?:[a-z0-9_]{0,62}[a-z0-9])?$'),
    constraint applications_display_name_format check (length(display_name) between 1 and 255 and display_name !~ '[[:cntrl:]]'),
    constraint applications_status_valid check (status in ('active', 'disabled')),
    constraint applications_system_kind_valid check (system_kind is null or system_kind in ('certhub_server')),
    constraint applications_certhub_server_name_kind check (
        (name = 'certhub_server' and system_kind = 'certhub_server')
        or (name <> 'certhub_server' and system_kind is null)
    ),
    constraint applications_description_format check (description is null or (length(description) <= 2048 and description !~ '[[:cntrl:]]')),
    constraint applications_trusted_source_cidrs_unique check (certhub_cidr_array_unique(trusted_source_cidrs)),
    constraint applications_updated_at_after_created check (updated_at >= created_at)
);

create unique index applications_name_unique on applications (name);
create index applications_status_idx on applications (status);
create index applications_system_kind_idx on applications (system_kind)
where system_kind is not null;

create table application_tokens (
    id uuid primary key,
    application_id uuid not null references applications(id),
    name text not null,
    token_hash text not null,
    status text not null default 'active',
    created_at timestamptz not null default now(),
    expires_at timestamptz,
    last_used_at timestamptz,
    revoked_at timestamptz,
    constraint application_tokens_name_format check (length(name) between 1 and 128 and name !~ '[[:cntrl:]]'),
    constraint application_tokens_hash_format check (token_hash ~ '^[A-Za-z0-9_-]{43}$'),
    constraint application_tokens_status_valid check (status in ('active', 'revoked')),
    constraint application_tokens_expiry_after_created check (expires_at is null or expires_at > created_at),
    constraint application_tokens_revoked_state check (
        (status = 'active' and revoked_at is null)
        or (status = 'revoked' and revoked_at is not null)
    )
);

create trigger application_tokens_no_system_application
before insert or update of application_id on application_tokens
for each row execute function certhub_reject_system_application_token();

create unique index application_tokens_token_hash_unique on application_tokens (token_hash);
create index application_tokens_application_id_idx on application_tokens (application_id);
create index application_tokens_status_expiry_idx on application_tokens (status, expires_at);

create table application_domain_scopes (
    id uuid primary key,
    application_id uuid not null references applications(id),
    value text not null,
    created_at timestamptz not null default now(),
    created_by_user_id uuid references users(id),
    constraint application_domain_scopes_value_format check (
        value ~ '^(\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
    )
);

create trigger application_domain_scopes_immutable
before update on application_domain_scopes
for each statement execute function certhub_reject_application_domain_scope_update();

create unique index application_domain_scopes_application_value_unique on application_domain_scopes (application_id, value);
create index application_domain_scopes_application_id_idx on application_domain_scopes (application_id);
create index application_domain_scopes_value_idx on application_domain_scopes (value);

create table application_user_grants (
    id uuid primary key,
    application_id uuid not null references applications(id),
    user_id uuid not null references users(id),
    role text not null,
    created_at timestamptz not null default now(),
    created_by_user_id uuid references users(id),
    constraint application_user_grants_role_valid check (role in ('viewer', 'certificate_reader', 'manager'))
);

create trigger application_user_grants_no_system_application
before insert or update of application_id on application_user_grants
for each row execute function certhub_reject_system_application_grant();

create unique index application_user_grants_application_user_unique on application_user_grants (application_id, user_id);
create index application_user_grants_application_id_idx on application_user_grants (application_id);
create index application_user_grants_user_id_idx on application_user_grants (user_id);

create table audit_events (
    id uuid primary key,
    identity_type text not null,
    identity_id uuid,
    action text not null,
    target_type text not null,
    target_id uuid,
    scope_application_id uuid references applications(id),
    scope_certificate_id uuid,
    scope_user_id uuid references users(id),
    scope_dns_provider_id uuid,
    result text not null,
    correlation_id text,
    source_ip text,
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    constraint audit_events_identity_type_valid check (identity_type in ('user', 'application', 'system')),
    constraint audit_events_identity_shape check (
        (identity_type = 'system' and identity_id is null)
        or (identity_type in ('user', 'application') and identity_id is not null)
    ),
    constraint audit_events_action_format check (length(action) between 1 and 128 and action ~ '^[a-z][a-z0-9_]{0,127}$'),
    constraint audit_events_target_type_format check (length(target_type) between 1 and 64 and target_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    constraint audit_events_result_valid check (result in ('success', 'failure')),
    constraint audit_events_correlation_id_format check (correlation_id is null or correlation_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
    constraint audit_events_source_ip_format check (source_ip is null or (length(source_ip) <= 128 and source_ip !~ '[[:cntrl:]]')),
    constraint audit_events_metadata_object check (jsonb_typeof(metadata) = 'object')
);

create trigger audit_events_append_only
before update or delete or truncate on audit_events
for each statement execute function certhub_reject_audit_event_mutation();

create index audit_events_created_at_idx on audit_events (created_at desc);
create index audit_events_action_created_at_idx on audit_events (action, created_at desc);
create index audit_events_identity_created_at_idx on audit_events (identity_type, identity_id, created_at desc);
create index audit_events_target_created_at_idx on audit_events (target_type, target_id, created_at desc);
create index audit_events_scope_application_created_at_idx on audit_events (scope_application_id, created_at desc)
where scope_application_id is not null;
create index audit_events_scope_certificate_created_at_idx on audit_events (scope_certificate_id, created_at desc)
where scope_certificate_id is not null;
create index audit_events_scope_user_created_at_idx on audit_events (scope_user_id, created_at desc)
where scope_user_id is not null;
create index audit_events_scope_dns_provider_created_at_idx on audit_events (scope_dns_provider_id, created_at desc)
where scope_dns_provider_id is not null;
create index audit_events_correlation_id_idx on audit_events (correlation_id)
where correlation_id is not null;

-- +goose Down
drop table if exists audit_events;
drop table if exists application_user_grants;
drop table if exists application_domain_scopes;
drop table if exists application_tokens;
drop table if exists applications;
drop table if exists oidc_login_handoffs;
drop table if exists oidc_login_states;
drop table if exists user_session_refresh_tokens;
drop table if exists user_sessions;
drop table if exists users;

drop function if exists certhub_reject_audit_event_mutation();
drop function if exists certhub_reject_application_domain_scope_update();
drop function if exists certhub_reject_system_application_grant();
drop function if exists certhub_reject_system_application_token();
drop function if exists certhub_cidr_array_unique(cidr[]);
