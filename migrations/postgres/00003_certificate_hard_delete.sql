-- +goose Up
alter table public.audit_events
    drop constraint audit_events_scope_certificate_id_fkey,
    add constraint audit_events_scope_certificate_id_fkey
        foreign key (scope_certificate_id) references public.certificates(id) on delete set null;

alter table public.certificate_events
    drop constraint certificate_events_certificate_id_fkey,
    add constraint certificate_events_certificate_id_fkey
        foreign key (certificate_id) references public.certificates(id) on delete cascade,
    drop constraint certificate_events_certificate_version_id_fkey,
    add constraint certificate_events_certificate_version_id_fkey
        foreign key (certificate_version_id) references public.certificate_versions(id) on delete cascade,
    drop constraint certificate_events_issuance_job_id_fkey,
    add constraint certificate_events_issuance_job_id_fkey
        foreign key (issuance_job_id) references public.certificate_issuance_jobs(id) on delete cascade;

alter table public.certificate_issuance_jobs
    drop constraint certificate_issuance_jobs_certificate_id_fkey,
    add constraint certificate_issuance_jobs_certificate_id_fkey
        foreign key (certificate_id) references public.certificates(id) on delete cascade,
    drop constraint certificate_issuance_jobs_certificate_version_id_fkey,
    add constraint certificate_issuance_jobs_certificate_version_id_fkey
        foreign key (certificate_version_id) references public.certificate_versions(id) on delete cascade;

alter table public.certificate_versions
    drop constraint certificate_versions_certificate_id_fkey,
    add constraint certificate_versions_certificate_id_fkey
        foreign key (certificate_id) references public.certificates(id) on delete cascade;

alter table public.dns_challenge_records
    drop constraint dns_challenge_records_certificate_id_fkey,
    add constraint dns_challenge_records_certificate_id_fkey
        foreign key (certificate_id) references public.certificates(id) on delete cascade,
    drop constraint dns_challenge_records_certificate_version_id_fkey,
    add constraint dns_challenge_records_certificate_version_id_fkey
        foreign key (certificate_version_id) references public.certificate_versions(id) on delete cascade,
    drop constraint dns_challenge_records_issuance_job_id_fkey,
    add constraint dns_challenge_records_issuance_job_id_fkey
        foreign key (issuance_job_id) references public.certificate_issuance_jobs(id) on delete cascade;

-- +goose Down
alter table public.audit_events
    drop constraint audit_events_scope_certificate_id_fkey,
    add constraint audit_events_scope_certificate_id_fkey
        foreign key (scope_certificate_id) references public.certificates(id);

alter table public.certificate_events
    drop constraint certificate_events_certificate_id_fkey,
    add constraint certificate_events_certificate_id_fkey foreign key (certificate_id) references public.certificates(id),
    drop constraint certificate_events_certificate_version_id_fkey,
    add constraint certificate_events_certificate_version_id_fkey foreign key (certificate_version_id) references public.certificate_versions(id),
    drop constraint certificate_events_issuance_job_id_fkey,
    add constraint certificate_events_issuance_job_id_fkey foreign key (issuance_job_id) references public.certificate_issuance_jobs(id);

alter table public.certificate_issuance_jobs
    drop constraint certificate_issuance_jobs_certificate_id_fkey,
    add constraint certificate_issuance_jobs_certificate_id_fkey foreign key (certificate_id) references public.certificates(id),
    drop constraint certificate_issuance_jobs_certificate_version_id_fkey,
    add constraint certificate_issuance_jobs_certificate_version_id_fkey foreign key (certificate_version_id) references public.certificate_versions(id);

alter table public.certificate_versions
    drop constraint certificate_versions_certificate_id_fkey,
    add constraint certificate_versions_certificate_id_fkey foreign key (certificate_id) references public.certificates(id);

alter table public.dns_challenge_records
    drop constraint dns_challenge_records_certificate_id_fkey,
    add constraint dns_challenge_records_certificate_id_fkey foreign key (certificate_id) references public.certificates(id),
    drop constraint dns_challenge_records_certificate_version_id_fkey,
    add constraint dns_challenge_records_certificate_version_id_fkey foreign key (certificate_version_id) references public.certificate_versions(id),
    drop constraint dns_challenge_records_issuance_job_id_fkey,
    add constraint dns_challenge_records_issuance_job_id_fkey foreign key (issuance_job_id) references public.certificate_issuance_jobs(id);
