-- +goose Up
alter table user_sessions
    drop constraint user_sessions_revoked_reason_valid,
    add constraint user_sessions_revoked_reason_valid check (
        revoked_reason is null or revoked_reason in (
            'logout',
            'disabled_user',
            'refresh_reuse',
            'admin_action',
            'expired',
            'password_reset',
            'password_2fa_reset'
        )
    );

create table user_password_reset_tokens (
    id uuid primary key,
    user_id uuid not null references users(id),
    token_hash text not null,
    status text not null default 'active',
    created_by_user_id uuid not null references users(id),
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    consumed_at timestamptz,
    constraint user_password_reset_tokens_hash_format check (token_hash ~ '^[A-Za-z0-9_-]{43}$'),
    constraint user_password_reset_tokens_status_valid check (status in ('active', 'consumed', 'expired', 'superseded')),
    constraint user_password_reset_tokens_expiry_after_created check (expires_at > created_at),
    constraint user_password_reset_tokens_consumed_state check (
        (status = 'consumed' and consumed_at is not null)
        or (status <> 'consumed' and consumed_at is null)
    )
);

create unique index user_password_reset_tokens_hash_unique on user_password_reset_tokens (token_hash);
create unique index user_password_reset_tokens_one_active_per_user_idx on user_password_reset_tokens (user_id)
where status = 'active';
create index user_password_reset_tokens_active_idx on user_password_reset_tokens (expires_at)
where status = 'active';

create table password_2fa_login_setups (
    id uuid primary key,
    setup_hash text not null,
    user_id uuid not null references users(id),
    pending_totp_secret_encrypted text not null,
    status text not null default 'active',
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    consumed_at timestamptz,
    source_ip text,
    user_agent text,
    constraint password_2fa_login_setups_hash_format check (setup_hash ~ '^[A-Za-z0-9_-]{43}$'),
    constraint password_2fa_login_setups_totp_envelope_format check (length(pending_totp_secret_encrypted) between 1 and 8192 and left(pending_totp_secret_encrypted, 1) = '{'),
    constraint password_2fa_login_setups_status_valid check (status in ('active', 'consumed', 'expired', 'superseded')),
    constraint password_2fa_login_setups_expiry_after_created check (expires_at > created_at),
    constraint password_2fa_login_setups_consumed_state check (
        (status = 'consumed' and consumed_at is not null)
        or (status <> 'consumed' and consumed_at is null)
    ),
    constraint password_2fa_login_setups_source_ip_format check (source_ip is null or (length(source_ip) <= 128 and source_ip !~ '[[:cntrl:]]')),
    constraint password_2fa_login_setups_user_agent_format check (user_agent is null or (length(user_agent) <= 1024 and user_agent !~ '[[:cntrl:]]'))
);

create unique index password_2fa_login_setups_hash_unique on password_2fa_login_setups (setup_hash);
create unique index password_2fa_login_setups_one_active_per_user_idx on password_2fa_login_setups (user_id)
where status = 'active';
create index password_2fa_login_setups_active_idx on password_2fa_login_setups (expires_at)
where status = 'active';

-- +goose Down
drop table if exists password_2fa_login_setups;
drop table if exists user_password_reset_tokens;

alter table user_sessions
    drop constraint user_sessions_revoked_reason_valid,
    add constraint user_sessions_revoked_reason_valid check (
        revoked_reason is null or revoked_reason in (
            'logout',
            'disabled_user',
            'refresh_reuse',
            'admin_action',
            'expired'
        )
    );
