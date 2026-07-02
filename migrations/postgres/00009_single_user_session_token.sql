-- +goose Up
alter table user_sessions
    drop constraint user_sessions_revoked_reason_valid,
    add constraint user_sessions_revoked_reason_valid check (
        revoked_reason is null or revoked_reason in (
            'logout',
            'disabled_user',
            'refresh_reuse',
            'token_reuse',
            'admin_action',
            'expired',
            'password_reset',
            'password_2fa_reset',
            'auth_model_migration'
        )
    );

update user_sessions
set status = 'revoked',
    revoked_at = coalesce(revoked_at, now()),
    revoked_reason = coalesce(revoked_reason, 'auth_model_migration')
where status = 'active';

drop index if exists user_sessions_refresh_token_hash_unique;
drop index if exists user_sessions_status_expires_idx;

alter table user_sessions
    drop constraint user_sessions_refresh_after_access,
    drop constraint user_sessions_refresh_token_hash_format,
    drop column refresh_token_hash;

alter table user_sessions
    rename column refresh_expires_at to session_expires_at;

alter table user_sessions
    add constraint user_sessions_session_after_access check (session_expires_at >= access_expires_at);

create index user_sessions_status_expires_idx on user_sessions (status, access_expires_at, session_expires_at);

drop table if exists user_session_refresh_tokens;

create table user_session_token_history (
    id uuid primary key,
    user_session_id uuid not null references user_sessions(id),
    access_token_hash text not null,
    status text not null default 'active',
    issued_at timestamptz not null default now(),
    access_expires_at timestamptz not null,
    rotated_at timestamptz,
    last_seen_at timestamptz,
    constraint user_session_token_history_hash_format check (access_token_hash ~ '^[A-Za-z0-9_-]{43}$'),
    constraint user_session_token_history_status_valid check (status in ('active', 'rotated', 'revoked', 'reused', 'expired')),
    constraint user_session_token_history_expiry_after_issue check (access_expires_at > issued_at),
    constraint user_session_token_history_rotated_state check (
        (status not in ('rotated', 'reused') and rotated_at is null)
        or (status = 'rotated' and rotated_at is not null)
        or status = 'reused'
    )
);

create unique index user_session_token_history_hash_unique on user_session_token_history (access_token_hash);
create unique index user_session_token_history_one_active_per_session_idx on user_session_token_history (user_session_id)
where status = 'active';
create index user_session_token_history_session_idx on user_session_token_history (user_session_id);
create index user_session_token_history_status_expires_idx on user_session_token_history (status, access_expires_at);

-- +goose Down
drop table if exists user_session_token_history;

drop index if exists user_sessions_status_expires_idx;

alter table user_sessions
    drop constraint user_sessions_session_after_access;

alter table user_sessions
    rename column session_expires_at to refresh_expires_at;

alter table user_sessions
    add column refresh_token_hash text not null default repeat('A', 43),
    add constraint user_sessions_refresh_token_hash_format check (refresh_token_hash ~ '^[A-Za-z0-9_-]{43}$'),
    add constraint user_sessions_refresh_after_access check (refresh_expires_at > access_expires_at);

alter table user_sessions
    alter column refresh_token_hash drop default;

create unique index user_sessions_refresh_token_hash_unique on user_sessions (refresh_token_hash);
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
    constraint user_session_refresh_tokens_rotated_state check (
        (status not in ('rotated', 'reused') and rotated_at is null)
        or (status = 'rotated' and rotated_at is not null)
        or status = 'reused'
    )
);

create unique index user_session_refresh_tokens_hash_unique on user_session_refresh_tokens (refresh_token_hash);
create unique index user_session_refresh_tokens_one_active_per_session_idx on user_session_refresh_tokens (user_session_id)
where status = 'active';
create index user_session_refresh_tokens_session_idx on user_session_refresh_tokens (user_session_id);
create index user_session_refresh_tokens_status_expires_idx on user_session_refresh_tokens (status, expires_at);

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
