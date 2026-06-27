-- +goose Up
create table certhub_leases (
    name text primary key,
    locked_by text not null,
    locked_until timestamptz not null,
    generation bigint not null default 1,
    lease_token uuid not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint certhub_leases_lease_token_unique unique (lease_token),
    constraint certhub_leases_name_format check (name ~ '^[a-z][a-z0-9_.:-]{0,127}$'),
    constraint certhub_leases_locked_by_format check (locked_by ~ '^[a-z][a-z0-9_.:-]{0,63}/[a-z][a-z0-9_.:-]{0,63}$'),
    constraint certhub_leases_future_expiry check (locked_until > updated_at),
    constraint certhub_leases_generation_positive check (generation > 0)
);

create index certhub_leases_locked_until_idx on certhub_leases (locked_until);

-- +goose Down
drop table if exists certhub_leases;
