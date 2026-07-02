-- +goose Up
alter table certificate_versions
add column revocation_reason text,
add column revoked_at timestamptz,
add column revoked_by_user_id uuid references users(id);

update certificate_versions v
set revocation_reason = c.revocation_reason,
    revoked_at = coalesce(c.revoked_at, v.completed_at, v.updated_at),
    revoked_by_user_id = c.revoked_by_user_id
from certificates c
where c.id = v.certificate_id
  and v.status = 'revoked'
  and v.revocation_reason is null
  and c.revocation_reason is not null;

alter table certificate_versions
add constraint certificate_versions_revocation_reason_valid check (
    revocation_reason is null or revocation_reason in ('key_compromise', 'superseded', 'cessation_of_operation', 'unspecified')
);

alter table certificate_versions
add constraint certificate_versions_revoked_state check (
    (status = 'revoked' and revocation_reason is not null and revoked_at is not null)
    or (status <> 'revoked' and revocation_reason is null and revoked_at is null and revoked_by_user_id is null)
);

alter table certificate_versions
drop constraint certificate_versions_reason_valid,
add constraint certificate_versions_reason_valid check (reason in ('initial_issue', 'renewal', 'key_rotation', 'reissue'));

alter table certificate_issuance_jobs
drop constraint certificate_issuance_jobs_reason_valid,
add constraint certificate_issuance_jobs_reason_valid check (reason in ('initial_issue', 'renewal', 'key_rotation', 'reissue', 'revocation_retry', 'dns_cleanup'));

-- +goose Down
alter table certificate_issuance_jobs
drop constraint certificate_issuance_jobs_reason_valid,
add constraint certificate_issuance_jobs_reason_valid check (reason in ('initial_issue', 'renewal', 'key_rotation', 'revocation_retry', 'dns_cleanup'));

alter table certificate_versions
drop constraint certificate_versions_reason_valid,
add constraint certificate_versions_reason_valid check (reason in ('initial_issue', 'renewal', 'key_rotation'));

alter table certificate_versions
drop constraint certificate_versions_revoked_state,
drop constraint certificate_versions_revocation_reason_valid,
drop column revoked_by_user_id,
drop column revoked_at,
drop column revocation_reason;
