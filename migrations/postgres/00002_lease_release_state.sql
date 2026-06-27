-- +goose Up
alter table certhub_leases
    alter column locked_by drop not null,
    alter column lease_token drop not null;

alter table certhub_leases
    drop constraint if exists certhub_leases_future_expiry,
    drop constraint if exists certhub_leases_locked_by_format;

alter table certhub_leases
    add constraint certhub_leases_locked_by_format check (locked_by is null or locked_by ~ '^[a-z][a-z0-9_.:-]{0,63}/[a-z][a-z0-9_.:-]{0,63}$'),
    add constraint certhub_leases_active_state check (
        (
            locked_by is null
            and lease_token is null
            and locked_until <= updated_at
        ) or (
            locked_by is not null
            and lease_token is not null
            and locked_until > updated_at
        )
    );

-- +goose Down
delete from certhub_leases
where locked_by is null
   or lease_token is null;

alter table certhub_leases
    drop constraint if exists certhub_leases_active_state,
    drop constraint if exists certhub_leases_locked_by_format;

alter table certhub_leases
    alter column locked_by set not null,
    alter column lease_token set not null;

alter table certhub_leases
    add constraint certhub_leases_locked_by_format check (locked_by ~ '^[a-z][a-z0-9_.:-]{0,63}/[a-z][a-z0-9_.:-]{0,63}$'),
    add constraint certhub_leases_future_expiry check (locked_until > updated_at);
