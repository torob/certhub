-- +goose Up
-- Certhub sorts normalized_sans in Go byte order. The SAN check compared that
-- order with the database default collation, so locale collations such as
-- en_US.utf8 rejected valid identities like
-- {k2.cf30.e2e.test,k2b.cf30.e2e.test}. Compare with the "C" collation, which
-- is byte order, so the check no longer depends on the database collation.
-- Stored rows are not rewritten and certificate identity does not change.
-- +goose StatementBegin
create or replace function public.certhub_certificate_sans_valid(sans text[]) returns boolean
    language sql immutable
    as $_$
    select coalesce(cardinality(sans), 0) > 0
       and coalesce(cardinality(sans), 0) <= 100
       and sans collate "C" = (
           select array_agg(distinct san collate "C" order by san collate "C")
           from unnest(sans) as san
       )
       and not exists (
           select 1
           from unnest(sans) as san
           where san is null
              or length(san) > 253
              or san !~ '^(\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
       )
$_$;
-- +goose StatementEnd

-- Replacing the function does not recheck stored rows. Rows written by Certhub
-- are already in byte order. Stop here if another writer stored a row that the
-- byte-order check rejects, because a later update of that row would fail.
-- +goose StatementBegin
do $$
declare
    invalid_count bigint;
    invalid_ids text;
begin
    select count(*) into invalid_count
    from public.certificates
    where not public.certhub_certificate_sans_valid(normalized_sans);

    if invalid_count > 0 then
        select string_agg(id::text, ', ' order by id) into invalid_ids
        from (
            select id
            from public.certificates
            where not public.certhub_certificate_sans_valid(normalized_sans)
            order by id
            limit 10
        ) as invalid;
        raise exception 'migration 00006: % certificates have normalized_sans that are not sorted in byte order (first ids: %)', invalid_count, invalid_ids
            using hint = 'Certhub writes normalized_sans in byte order. Correct or delete these certificates, then run the migration again.';
    end if;
end;
$$;
-- +goose StatementEnd

-- +goose Down
-- Restore the collation-dependent check. Stop if a stored row does not satisfy
-- it, for example a certificate with SANs that only byte order accepts, because
-- the previous binary could not update that row.
-- +goose StatementBegin
create or replace function public.certhub_certificate_sans_valid(sans text[]) returns boolean
    language sql immutable
    as $_$
    select coalesce(cardinality(sans), 0) > 0
       and coalesce(cardinality(sans), 0) <= 100
       and sans = (
           select array_agg(distinct san order by san)
           from unnest(sans) as san
       )
       and not exists (
           select 1
           from unnest(sans) as san
           where san is null
              or length(san) > 253
              or san !~ '^(\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
       )
$_$;
-- +goose StatementEnd

-- +goose StatementBegin
do $$
declare
    invalid_count bigint;
    invalid_ids text;
begin
    select count(*) into invalid_count
    from public.certificates
    where not public.certhub_certificate_sans_valid(normalized_sans);

    if invalid_count > 0 then
        select string_agg(id::text, ', ' order by id) into invalid_ids
        from (
            select id
            from public.certificates
            where not public.certhub_certificate_sans_valid(normalized_sans)
            order by id
            limit 10
        ) as invalid;
        raise exception 'migration 00006 cannot be rolled back: % certificates have normalized_sans that the database collation does not accept (first ids: %)', invalid_count, invalid_ids
            using hint = 'Keep migration 00006, or delete these certificates before the rollback.';
    end if;
end;
$$;
-- +goose StatementEnd
