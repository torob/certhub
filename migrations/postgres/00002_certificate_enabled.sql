-- +goose Up
alter table public.certificates
    add column enabled boolean default true not null;

-- +goose Down
alter table public.certificates
    drop column enabled;
