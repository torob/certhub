-- +goose Up
alter table public.audit_events
    drop constraint if exists audit_events_scope_application_id_fkey,
    drop constraint if exists audit_events_scope_certificate_id_fkey,
    drop constraint if exists audit_events_scope_user_id_fkey,
    drop constraint if exists audit_events_scope_dns_provider_id_fkey;

-- Certificate events remain append-only for direct writes. Deletes reached through
-- a parent foreign-key cascade run at a nested trigger depth and are the only
-- mutation required by certificate hard deletion.
-- +goose StatementBegin
create or replace function public.certhub_reject_certificate_event_mutation() returns trigger
    language plpgsql
    as $$
begin
    if tg_op = 'DELETE' and pg_trigger_depth() > 1 then
        return null;
    end if;
    raise exception 'certificate_events are append-only';
end;
$$;
-- +goose StatementEnd

delete from public.certificates where deleted_at is not null or status = 'deleted';

-- +goose Down
-- Hard deletion and retained audit identifiers make this migration intentionally
-- irreversible: restoring audit foreign keys would require mutating audit history.
-- +goose StatementBegin
do $$
begin
    raise exception 'migration 00004 is irreversible';
end;
$$;
-- +goose StatementEnd
