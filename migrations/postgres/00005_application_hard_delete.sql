-- +goose Up
alter table public.application_domain_scopes
    drop constraint application_domain_scopes_application_id_fkey,
    add constraint application_domain_scopes_application_id_fkey
        foreign key (application_id) references public.applications(id) on delete cascade;

alter table public.application_tokens
    drop constraint application_tokens_application_id_fkey,
    add constraint application_tokens_application_id_fkey
        foreign key (application_id) references public.applications(id) on delete cascade;

alter table public.application_user_grants
    drop constraint application_user_grants_application_id_fkey,
    add constraint application_user_grants_application_id_fkey
        foreign key (application_id) references public.applications(id) on delete cascade;

alter table public.certificates
    drop constraint certificates_application_id_fkey,
    add constraint certificates_application_id_fkey
        foreign key (application_id) references public.applications(id) on delete cascade;

-- +goose Down
alter table public.application_domain_scopes
    drop constraint application_domain_scopes_application_id_fkey,
    add constraint application_domain_scopes_application_id_fkey
        foreign key (application_id) references public.applications(id);

alter table public.application_tokens
    drop constraint application_tokens_application_id_fkey,
    add constraint application_tokens_application_id_fkey
        foreign key (application_id) references public.applications(id);

alter table public.application_user_grants
    drop constraint application_user_grants_application_id_fkey,
    add constraint application_user_grants_application_id_fkey
        foreign key (application_id) references public.applications(id);

alter table public.certificates
    drop constraint certificates_application_id_fkey,
    add constraint certificates_application_id_fkey
        foreign key (application_id) references public.applications(id);
