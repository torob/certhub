-- +goose Up
drop index if exists issuers_environment_idx;

alter table issuers
    drop column if exists environment;

-- +goose StatementBegin
create or replace function certhub_reject_issuer_immutable_update()
returns trigger
language plpgsql
as $$
begin
    if old.name is distinct from new.name
        or old.type is distinct from new.type
        or old.directory_url is distinct from new.directory_url then
        raise exception 'issuer identity fields are immutable';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd

-- +goose Down
alter table issuers
    add column if not exists environment text not null default 'production';

alter table issuers
    add constraint issuers_environment_valid check (environment in ('production', 'staging'));

alter table issuers
    alter column environment drop default;

create index if not exists issuers_environment_idx on issuers (environment);

-- +goose StatementBegin
create or replace function certhub_reject_issuer_immutable_update()
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
