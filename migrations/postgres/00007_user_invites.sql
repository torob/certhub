-- +goose Up
create table user_invites (
    id uuid primary key,
    email text not null,
    global_role text not null default 'user',
    token_hash text not null,
    status text not null default 'active',
    created_by_user_id uuid not null references users(id),
    created_user_id uuid references users(id),
    pending_user_id uuid,
    pending_display_name text,
    pending_password_hash text,
    pending_totp_secret_encrypted text,
    pending_started_at timestamptz,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    consumed_at timestamptz,
    constraint user_invites_email_normalized check (
        email = lower(email)
        and length(email) between 3 and 254
        and email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
        and email !~ '[[:cntrl:]]'
    ),
    constraint user_invites_global_role_valid check (global_role in ('user', 'admin')),
    constraint user_invites_token_hash_format check (token_hash ~ '^[A-Za-z0-9_-]{43}$'),
    constraint user_invites_status_valid check (status in ('active', 'consumed', 'expired')),
    constraint user_invites_expiry_after_created check (expires_at > created_at),
    constraint user_invites_consumed_state check (
        (status = 'consumed' and consumed_at is not null and created_user_id is not null)
        or (status <> 'consumed' and consumed_at is null and created_user_id is null)
    ),
    constraint user_invites_pending_display_name_format check (
        pending_display_name is null or (length(pending_display_name) between 1 and 255 and pending_display_name !~ '[[:cntrl:]]')
    ),
    constraint user_invites_pending_password_hash_format check (
        pending_password_hash is null or (length(pending_password_hash) between 1 and 4096 and pending_password_hash !~ '[[:cntrl:]]')
    ),
    constraint user_invites_pending_totp_envelope_format check (
        pending_totp_secret_encrypted is null or (length(pending_totp_secret_encrypted) between 1 and 8192 and left(pending_totp_secret_encrypted, 1) = '{')
    ),
    constraint user_invites_pending_state check (
        (pending_user_id is null and pending_display_name is null and pending_password_hash is null and pending_totp_secret_encrypted is null and pending_started_at is null)
        or (pending_user_id is not null and pending_display_name is not null and pending_password_hash is not null and pending_totp_secret_encrypted is not null and pending_started_at is not null)
    )
);

create unique index user_invites_token_hash_unique on user_invites (token_hash);
create index user_invites_email_idx on user_invites (email);
create index user_invites_active_expires_idx on user_invites (expires_at)
where status = 'active';

-- +goose Down
drop table if exists user_invites;
