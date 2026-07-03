-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION public.certhub_certificate_sans_valid(sans text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $_$
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


--
-- Name: certhub_cidr_array_unique(cidr[]); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.certhub_cidr_array_unique(cidrs cidr[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce(cardinality(cidrs), 0) = (
        select count(distinct cidr_value)::integer
        from unnest(cidrs) as cidr_value
    )
$$;
-- +goose StatementEnd


--
-- Name: certhub_enforce_certificate_version_overlap(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.certhub_enforce_certificate_version_overlap() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
declare
    active_valid_count integer;
begin
    if new.status = 'valid' and new.not_after > now() then
        select count(*) into active_valid_count
        from certificate_versions
        where certificate_id = new.certificate_id
          and status = 'valid'
          and not_after > now()
          and id <> new.id;

        if active_valid_count >= 2 then
            raise exception 'too many active valid certificate versions';
        end if;
    end if;
    return new;
end;
$$;
-- +goose StatementEnd


--
-- Name: certhub_enforce_system_application_certificate_limit(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.certhub_enforce_system_application_certificate_limit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if new.deleted_at is null
        and exists (
            select 1
            from applications
            where id = new.application_id
              and system_kind = 'certhub_server'
        )
        and exists (
            select 1
            from certificates
            where application_id = new.application_id
              and deleted_at is null
              and id <> new.id
        ) then
        raise exception 'certhub_server application may have at most one active certificate';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd


--
-- Name: certhub_preserve_active_issuer_account(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.certhub_preserve_active_issuer_account() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if tg_op = 'DELETE' then
        if old.status = 'active'
            and exists (
                select 1
                from issuers
                where id = old.issuer_id
                  and status = 'active'
            )
            and not exists (
                select 1
                from acme_accounts
                where issuer_id = old.issuer_id
                  and status = 'active'
                  and id <> old.id
            ) then
            raise exception 'active issuers require an active ACME account';
        end if;
        return old;
    end if;

    if old.status = 'active'
        and (new.status <> 'active' or new.issuer_id is distinct from old.issuer_id)
        and exists (
            select 1
            from issuers
            where id = old.issuer_id
              and status = 'active'
        )
        and not exists (
            select 1
            from acme_accounts
            where issuer_id = old.issuer_id
              and status = 'active'
              and id <> old.id
        ) then
        raise exception 'active issuers require an active ACME account';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd


--
-- Name: certhub_reject_application_domain_scope_update(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.certhub_reject_application_domain_scope_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    raise exception 'application domain scopes are immutable; delete and insert instead';
end;
$$;
-- +goose StatementEnd


--
-- Name: certhub_reject_audit_event_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.certhub_reject_audit_event_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    raise exception 'audit_events are append-only';
end;
$$;
-- +goose StatementEnd


--
-- Name: certhub_reject_certificate_event_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.certhub_reject_certificate_event_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    raise exception 'certificate_events are append-only';
end;
$$;
-- +goose StatementEnd


--
-- Name: certhub_reject_certificate_version_regression(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.certhub_reject_certificate_version_regression() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if exists (
        select 1
        from certificate_versions
        where certificate_id = new.certificate_id
          and version >= new.version
    ) then
        raise exception 'certificate version numbers must increase';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd


--
-- Name: certhub_reject_dns_provider_zone_update(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.certhub_reject_dns_provider_zone_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    raise exception 'dns_provider_zones are immutable; delete and insert instead';
end;
$$;
-- +goose StatementEnd


--
-- Name: certhub_reject_issuer_immutable_update(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.certhub_reject_issuer_immutable_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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


--
-- Name: certhub_reject_system_application_grant(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.certhub_reject_system_application_grant() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if exists (
        select 1
        from applications
        where id = new.application_id
          and system_kind = 'certhub_server'
    ) then
        raise exception 'user grants cannot be created for system applications';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd


--
-- Name: certhub_reject_system_application_token(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.certhub_reject_system_application_token() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if exists (
        select 1
        from applications
        where id = new.application_id
          and system_kind = 'certhub_server'
    ) then
        raise exception 'application tokens cannot be created for system applications';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd


--
-- Name: certhub_require_active_issuer_account(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.certhub_require_active_issuer_account() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if new.status = 'active' and not exists (
        select 1
        from acme_accounts
        where issuer_id = new.id
          and status = 'active'
    ) then
        raise exception 'active issuers require an active ACME account';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: acme_accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.acme_accounts (
    id uuid NOT NULL,
    issuer_id uuid NOT NULL,
    email text NOT NULL,
    account_url text NOT NULL,
    private_key_pem text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT acme_accounts_email_normalized CHECK (((email = lower(email)) AND ((length(email) >= 3) AND (length(email) <= 254)) AND (email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'::text) AND (email !~ '[[:cntrl:]]'::text))),
    CONSTRAINT acme_accounts_private_key_envelope_format CHECK ((((length(private_key_pem) >= 1) AND (length(private_key_pem) <= 8192)) AND ("left"(private_key_pem, 1) = '{'::text))),
    CONSTRAINT acme_accounts_status_valid CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text]))),
    CONSTRAINT acme_accounts_updated_at_after_created CHECK ((updated_at >= created_at)),
    CONSTRAINT acme_accounts_url_format CHECK (((length(account_url) <= 2048) AND (account_url ~ '^https://[^[:space:]@#]+'::text) AND (account_url !~ '[[:space:][:cntrl:]]'::text) AND (account_url !~ '^https://[^/]+@'::text) AND (POSITION(('#'::text) IN (account_url)) = 0)))
);


--
-- Name: application_domain_scopes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.application_domain_scopes (
    id uuid NOT NULL,
    application_id uuid NOT NULL,
    value text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by_user_id uuid,
    CONSTRAINT application_domain_scopes_value_format CHECK ((value ~ '^(\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'::text))
);


--
-- Name: application_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.application_tokens (
    id uuid NOT NULL,
    application_id uuid NOT NULL,
    name text NOT NULL,
    token_hash text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    CONSTRAINT application_tokens_expiry_after_created CHECK (((expires_at IS NULL) OR (expires_at > created_at))),
    CONSTRAINT application_tokens_hash_format CHECK ((token_hash ~ '^[A-Za-z0-9_-]{43}$'::text)),
    CONSTRAINT application_tokens_name_format CHECK ((((length(name) >= 1) AND (length(name) <= 128)) AND (name !~ '[[:cntrl:]]'::text))),
    CONSTRAINT application_tokens_revoked_state CHECK ((((status = 'active'::text) AND (revoked_at IS NULL)) OR ((status = 'revoked'::text) AND (revoked_at IS NOT NULL)))),
    CONSTRAINT application_tokens_status_valid CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text])))
);


--
-- Name: application_user_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.application_user_grants (
    id uuid NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by_user_id uuid,
    CONSTRAINT application_user_grants_role_valid CHECK ((role = ANY (ARRAY['viewer'::text, 'certificate_reader'::text, 'manager'::text])))
);


--
-- Name: applications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.applications (
    id uuid NOT NULL,
    name text NOT NULL,
    display_name text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    system_kind text,
    description text,
    trusted_source_cidrs cidr[] DEFAULT ARRAY[]::cidr[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT applications_certhub_server_name_kind CHECK ((((name = 'certhub_server'::text) AND (system_kind = 'certhub_server'::text)) OR ((name <> 'certhub_server'::text) AND (system_kind IS NULL)))),
    CONSTRAINT applications_description_format CHECK (((description IS NULL) OR ((length(description) <= 2048) AND (description !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT applications_display_name_format CHECK ((((length(display_name) >= 1) AND (length(display_name) <= 255)) AND (display_name !~ '[[:cntrl:]]'::text))),
    CONSTRAINT applications_name_format CHECK ((name ~ '^[a-z](?:[a-z0-9_]{0,62}[a-z0-9])?$'::text)),
    CONSTRAINT applications_status_valid CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text]))),
    CONSTRAINT applications_system_kind_valid CHECK (((system_kind IS NULL) OR (system_kind = 'certhub_server'::text))),
    CONSTRAINT applications_trusted_source_cidrs_unique CHECK (public.certhub_cidr_array_unique(trusted_source_cidrs)),
    CONSTRAINT applications_updated_at_after_created CHECK ((updated_at >= created_at))
);


--
-- Name: audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_events (
    id uuid NOT NULL,
    identity_type text NOT NULL,
    identity_id uuid,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id uuid,
    scope_application_id uuid,
    scope_certificate_id uuid,
    scope_user_id uuid,
    scope_dns_provider_id uuid,
    result text NOT NULL,
    correlation_id text,
    source_ip text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT audit_events_action_format CHECK ((((length(action) >= 1) AND (length(action) <= 128)) AND (action ~ '^[a-z][a-z0-9_]{0,127}$'::text))),
    CONSTRAINT audit_events_correlation_id_format CHECK (((correlation_id IS NULL) OR (correlation_id ~ '^[A-Za-z0-9._:-]{1,128}$'::text))),
    CONSTRAINT audit_events_identity_shape CHECK ((((identity_type = 'system'::text) AND (identity_id IS NULL)) OR ((identity_type = ANY (ARRAY['user'::text, 'application'::text])) AND (identity_id IS NOT NULL)))),
    CONSTRAINT audit_events_identity_type_valid CHECK ((identity_type = ANY (ARRAY['user'::text, 'application'::text, 'system'::text]))),
    CONSTRAINT audit_events_metadata_object CHECK ((jsonb_typeof(metadata) = 'object'::text)),
    CONSTRAINT audit_events_result_valid CHECK ((result = ANY (ARRAY['success'::text, 'failure'::text]))),
    CONSTRAINT audit_events_source_ip_format CHECK (((source_ip IS NULL) OR ((length(source_ip) <= 128) AND (source_ip !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT audit_events_target_type_format CHECK ((((length(target_type) >= 1) AND (length(target_type) <= 64)) AND (target_type ~ '^[a-z][a-z0-9_]{0,63}$'::text)))
);


--
-- Name: certhub_leases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.certhub_leases (
    name text NOT NULL,
    locked_by text,
    locked_until timestamp with time zone NOT NULL,
    generation bigint DEFAULT 1 NOT NULL,
    lease_token uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT certhub_leases_active_state CHECK ((((locked_by IS NULL) AND (lease_token IS NULL) AND (locked_until <= updated_at)) OR ((locked_by IS NOT NULL) AND (lease_token IS NOT NULL) AND (locked_until > updated_at)))),
    CONSTRAINT certhub_leases_generation_positive CHECK ((generation > 0)),
    CONSTRAINT certhub_leases_locked_by_format CHECK (((locked_by IS NULL) OR (locked_by ~ '^[a-z][a-z0-9_.:-]{0,63}/[a-z][a-z0-9_.:-]{0,63}$'::text))),
    CONSTRAINT certhub_leases_name_format CHECK ((name ~ '^[a-z][a-z0-9_.:-]{0,127}$'::text))
);


--
-- Name: certificate_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.certificate_events (
    id uuid NOT NULL,
    certificate_id uuid NOT NULL,
    certificate_version_id uuid,
    issuance_job_id uuid,
    event_type text NOT NULL,
    result text DEFAULT 'success'::text NOT NULL,
    correlation_id text,
    message text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT certificate_events_correlation_id_format CHECK (((correlation_id IS NULL) OR (correlation_id ~ '^[A-Za-z0-9._:-]{1,128}$'::text))),
    CONSTRAINT certificate_events_event_type_format CHECK ((((length(event_type) >= 1) AND (length(event_type) <= 128)) AND (event_type ~ '^[a-z][a-z0-9_]{0,127}$'::text))),
    CONSTRAINT certificate_events_message_format CHECK (((message IS NULL) OR ((length(message) <= 2048) AND (message !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT certificate_events_metadata_object CHECK ((jsonb_typeof(metadata) = 'object'::text)),
    CONSTRAINT certificate_events_result_valid CHECK ((result = ANY (ARRAY['success'::text, 'failure'::text])))
);


--
-- Name: certificate_issuance_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.certificate_issuance_jobs (
    id uuid NOT NULL,
    certificate_id uuid NOT NULL,
    certificate_version_id uuid,
    reason text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempt integer DEFAULT 1 NOT NULL,
    locked_by text,
    locked_until timestamp with time zone,
    next_run_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    failure_code text,
    failure_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT certificate_issuance_jobs_attempt_positive CHECK ((attempt > 0)),
    CONSTRAINT certificate_issuance_jobs_completed_state CHECK ((((status = ANY (ARRAY['succeeded'::text, 'failed'::text, 'canceled'::text])) AND (completed_at IS NOT NULL)) OR ((status = ANY (ARRAY['pending'::text, 'running'::text])) AND (completed_at IS NULL)))),
    CONSTRAINT certificate_issuance_jobs_failure_code_format CHECK (((failure_code IS NULL) OR (((length(failure_code) >= 1) AND (length(failure_code) <= 128)) AND (failure_code ~ '^[a-z][a-z0-9_]{0,127}$'::text)))),
    CONSTRAINT certificate_issuance_jobs_failure_message_format CHECK (((failure_message IS NULL) OR ((length(failure_message) <= 2048) AND (failure_message !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT certificate_issuance_jobs_failure_state CHECK ((((status = 'failed'::text) AND (failure_code IS NOT NULL)) OR ((status <> 'failed'::text) AND (failure_code IS NULL) AND (failure_message IS NULL)))),
    CONSTRAINT certificate_issuance_jobs_lock_pair CHECK ((((locked_by IS NULL) AND (locked_until IS NULL)) OR ((locked_by IS NOT NULL) AND (locked_until IS NOT NULL)))),
    CONSTRAINT certificate_issuance_jobs_locked_by_format CHECK (((locked_by IS NULL) OR (((length(locked_by) >= 1) AND (length(locked_by) <= 255)) AND (locked_by !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT certificate_issuance_jobs_reason_valid CHECK ((reason = ANY (ARRAY['initial_issue'::text, 'renewal'::text, 'key_rotation'::text, 'reissue'::text, 'revocation_retry'::text, 'dns_cleanup'::text]))),
    CONSTRAINT certificate_issuance_jobs_running_state CHECK (((status <> 'running'::text) OR ((locked_by IS NOT NULL) AND (locked_until IS NOT NULL) AND (started_at IS NOT NULL)))),
    CONSTRAINT certificate_issuance_jobs_status_valid CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'succeeded'::text, 'failed'::text, 'canceled'::text]))),
    CONSTRAINT certificate_issuance_jobs_updated_at_after_created CHECK ((updated_at >= created_at))
);


--
-- Name: certificate_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.certificate_versions (
    id uuid NOT NULL,
    certificate_id uuid NOT NULL,
    version integer NOT NULL,
    status text DEFAULT 'issuing'::text NOT NULL,
    reason text NOT NULL,
    cert_pem text,
    chain_pem text,
    fullchain_pem text,
    private_key_pem text,
    not_before timestamp with time zone,
    not_after timestamp with time zone,
    serial_number text,
    fingerprint_sha256 text,
    key_fingerprint_sha256 text,
    material_etag text,
    acme_order_url text,
    certificate_url text,
    acme_revocation_status text,
    acme_revocation_attempts integer DEFAULT 0 NOT NULL,
    acme_revoked_at timestamp with time zone,
    acme_revocation_failure_code text,
    acme_revocation_failure_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    issued_at timestamp with time zone,
    failure_code text,
    failure_message text,
    revocation_reason text,
    revoked_at timestamp with time zone,
    revoked_by_user_id uuid,
    CONSTRAINT certificate_versions_failure_code_format CHECK (((failure_code IS NULL) OR (((length(failure_code) >= 1) AND (length(failure_code) <= 128)) AND (failure_code ~ '^[a-z][a-z0-9_]{0,127}$'::text)))),
    CONSTRAINT certificate_versions_failure_message_format CHECK (((failure_message IS NULL) OR ((length(failure_message) <= 2048) AND (failure_message !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT certificate_versions_failure_state CHECK ((((status = 'failed'::text) AND (failure_code IS NOT NULL)) OR ((status <> 'failed'::text) AND (failure_code IS NULL) AND (failure_message IS NULL)))),
    CONSTRAINT certificate_versions_fingerprint_format CHECK (((fingerprint_sha256 IS NULL) OR (fingerprint_sha256 ~ '^[a-f0-9]{64}$'::text))),
    CONSTRAINT certificate_versions_issuing_started CHECK (((status <> 'issuing'::text) OR (started_at IS NOT NULL))),
    CONSTRAINT certificate_versions_key_fingerprint_format CHECK (((key_fingerprint_sha256 IS NULL) OR (key_fingerprint_sha256 ~ '^[a-f0-9]{64}$'::text))),
    CONSTRAINT certificate_versions_material_etag_format CHECK (((material_etag IS NULL) OR (material_etag ~ '^"cth-mat-v1\.[A-Za-z0-9_-]{43}"$'::text))),
    CONSTRAINT certificate_versions_material_state CHECK ((((status = ANY (ARRAY['valid'::text, 'revoked'::text])) AND (cert_pem IS NOT NULL) AND (chain_pem IS NOT NULL) AND (fullchain_pem IS NOT NULL) AND (private_key_pem IS NOT NULL) AND (not_before IS NOT NULL) AND (not_after IS NOT NULL) AND (serial_number IS NOT NULL) AND (fingerprint_sha256 IS NOT NULL) AND (key_fingerprint_sha256 IS NOT NULL) AND (material_etag IS NOT NULL) AND (issued_at IS NOT NULL)) OR (status = ANY (ARRAY['issuing'::text, 'failed'::text])))),
    CONSTRAINT certificate_versions_private_key_envelope_format CHECK (((private_key_pem IS NULL) OR (((length(private_key_pem) >= 1) AND (length(private_key_pem) <= 8192)) AND ("left"(private_key_pem, 1) = '{'::text)))),
    CONSTRAINT certificate_versions_reason_valid CHECK ((reason = ANY (ARRAY['initial_issue'::text, 'renewal'::text, 'key_rotation'::text, 'reissue'::text]))),
    CONSTRAINT certificate_versions_revocation_attempts_valid CHECK ((acme_revocation_attempts >= 0)),
    CONSTRAINT certificate_versions_revocation_failure_code_format CHECK (((acme_revocation_failure_code IS NULL) OR (((length(acme_revocation_failure_code) >= 1) AND (length(acme_revocation_failure_code) <= 128)) AND (acme_revocation_failure_code ~ '^[a-z][a-z0-9_]{0,127}$'::text)))),
    CONSTRAINT certificate_versions_revocation_failure_message_format CHECK (((acme_revocation_failure_message IS NULL) OR ((length(acme_revocation_failure_message) <= 2048) AND (acme_revocation_failure_message !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT certificate_versions_revocation_reason_valid CHECK (((revocation_reason IS NULL) OR (revocation_reason = ANY (ARRAY['key_compromise'::text, 'superseded'::text, 'cessation_of_operation'::text, 'unspecified'::text])))),
    CONSTRAINT certificate_versions_revocation_status_valid CHECK (((acme_revocation_status IS NULL) OR (acme_revocation_status = ANY (ARRAY['pending'::text, 'succeeded'::text, 'failed'::text, 'not_required'::text])))),
    CONSTRAINT certificate_versions_revoked_state CHECK ((((status = 'revoked'::text) AND (revocation_reason IS NOT NULL) AND (revoked_at IS NOT NULL)) OR ((status <> 'revoked'::text) AND (revocation_reason IS NULL) AND (revoked_at IS NULL) AND (revoked_by_user_id IS NULL)))),
    CONSTRAINT certificate_versions_status_valid CHECK ((status = ANY (ARRAY['issuing'::text, 'valid'::text, 'failed'::text, 'revoked'::text]))),
    CONSTRAINT certificate_versions_terminal_completed CHECK ((((status = ANY (ARRAY['valid'::text, 'failed'::text, 'revoked'::text])) AND (completed_at IS NOT NULL)) OR ((status = 'issuing'::text) AND (completed_at IS NULL)))),
    CONSTRAINT certificate_versions_updated_at_after_created CHECK ((updated_at >= created_at)),
    CONSTRAINT certificate_versions_url_format CHECK ((((acme_order_url IS NULL) OR ((length(acme_order_url) <= 2048) AND (acme_order_url ~ '^https://[^[:space:]@#]+'::text) AND (acme_order_url !~ '[[:cntrl:]]'::text))) AND ((certificate_url IS NULL) OR ((length(certificate_url) <= 2048) AND (certificate_url ~ '^https://[^[:space:]@#]+'::text) AND (certificate_url !~ '[[:cntrl:]]'::text))))),
    CONSTRAINT certificate_versions_validity_window CHECK ((((not_before IS NULL) AND (not_after IS NULL)) OR ((not_before IS NOT NULL) AND (not_after IS NOT NULL) AND (not_after > not_before)))),
    CONSTRAINT certificate_versions_version_positive CHECK ((version > 0))
);


--
-- Name: certificates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.certificates (
    id uuid NOT NULL,
    normalized_sans text[] NOT NULL,
    key_type text NOT NULL,
    issuer_id uuid NOT NULL,
    application_id uuid NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    failure_code text,
    failure_message text,
    revocation_reason text,
    revoked_at timestamp with time zone,
    revoked_by_user_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT certificates_deleted_state CHECK ((((status = 'deleted'::text) AND (deleted_at IS NOT NULL)) OR ((status <> 'deleted'::text) AND (deleted_at IS NULL)))),
    CONSTRAINT certificates_failure_code_format CHECK (((failure_code IS NULL) OR (((length(failure_code) >= 1) AND (length(failure_code) <= 128)) AND (failure_code ~ '^[a-z][a-z0-9_]{0,127}$'::text)))),
    CONSTRAINT certificates_failure_message_format CHECK (((failure_message IS NULL) OR ((length(failure_message) <= 2048) AND (failure_message !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT certificates_failure_state CHECK ((((status = 'failed'::text) AND (failure_code IS NOT NULL)) OR ((status <> 'failed'::text) AND (failure_code IS NULL) AND (failure_message IS NULL)))),
    CONSTRAINT certificates_key_type_valid CHECK ((key_type = ANY (ARRAY['rsa-2048'::text, 'rsa-3072'::text, 'rsa-4096'::text, 'ecdsa-p256'::text, 'ecdsa-p384'::text]))),
    CONSTRAINT certificates_revocation_reason_valid CHECK (((revocation_reason IS NULL) OR (revocation_reason = ANY (ARRAY['key_compromise'::text, 'superseded'::text, 'cessation_of_operation'::text, 'unspecified'::text])))),
    CONSTRAINT certificates_revoked_state CHECK ((((status = 'revoked'::text) AND (revocation_reason IS NOT NULL) AND (revoked_at IS NOT NULL)) OR ((status <> 'revoked'::text) AND (revocation_reason IS NULL) AND (revoked_at IS NULL) AND (revoked_by_user_id IS NULL)))),
    CONSTRAINT certificates_sans_valid CHECK (public.certhub_certificate_sans_valid(normalized_sans)),
    CONSTRAINT certificates_status_valid CHECK ((status = ANY (ARRAY['pending'::text, 'validating_dns'::text, 'issuing'::text, 'ready'::text, 'renewing'::text, 'rotating_key'::text, 'expired'::text, 'revoked'::text, 'failed'::text, 'deleted'::text]))),
    CONSTRAINT certificates_updated_at_after_created CHECK ((updated_at >= created_at))
);


--
-- Name: dns_challenge_records; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dns_challenge_records (
    id uuid NOT NULL,
    issuance_job_id uuid NOT NULL,
    certificate_id uuid NOT NULL,
    certificate_version_id uuid NOT NULL,
    dns_provider_id uuid NOT NULL,
    dns_provider_zone_id uuid NOT NULL,
    authorization_identifier text NOT NULL,
    record_name text NOT NULL,
    txt_value_encrypted text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    presented_at timestamp with time zone,
    validated_at timestamp with time zone,
    cleaned_at timestamp with time zone,
    failure_code text,
    failure_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT dns_challenge_records_authorization_identifier_format CHECK ((authorization_identifier ~ '^(\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'::text)),
    CONSTRAINT dns_challenge_records_cleaned_state CHECK ((((status = 'cleaned'::text) AND (cleaned_at IS NOT NULL)) OR ((status <> 'cleaned'::text) AND (cleaned_at IS NULL)))),
    CONSTRAINT dns_challenge_records_cleanup_failure_state CHECK ((((status = 'cleanup_failed'::text) AND (failure_code IS NOT NULL)) OR ((status <> 'cleanup_failed'::text) AND (failure_code IS NULL) AND (failure_message IS NULL)))),
    CONSTRAINT dns_challenge_records_failure_code_format CHECK (((failure_code IS NULL) OR (((length(failure_code) >= 1) AND (length(failure_code) <= 128)) AND (failure_code ~ '^[a-z][a-z0-9_]{0,127}$'::text)))),
    CONSTRAINT dns_challenge_records_failure_message_format CHECK (((failure_message IS NULL) OR ((length(failure_message) <= 2048) AND (failure_message !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT dns_challenge_records_presented_state CHECK (((presented_at IS NOT NULL) OR (status = 'pending'::text))),
    CONSTRAINT dns_challenge_records_record_name_format CHECK ((record_name ~ '^_acme-challenge(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'::text)),
    CONSTRAINT dns_challenge_records_status_valid CHECK ((status = ANY (ARRAY['pending'::text, 'presented'::text, 'validated'::text, 'cleanup_pending'::text, 'cleanup_failed'::text, 'cleaned'::text]))),
    CONSTRAINT dns_challenge_records_txt_envelope_format CHECK ((((length(txt_value_encrypted) >= 1) AND (length(txt_value_encrypted) <= 8192)) AND ("left"(txt_value_encrypted, 1) = '{'::text))),
    CONSTRAINT dns_challenge_records_updated_at_after_created CHECK ((updated_at >= created_at)),
    CONSTRAINT dns_challenge_records_validated_state CHECK (((validated_at IS NOT NULL) OR (status <> ALL (ARRAY['validated'::text, 'cleanup_pending'::text, 'cleanup_failed'::text, 'cleaned'::text]))))
);


--
-- Name: dns_provider_zone_refresh_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dns_provider_zone_refresh_jobs (
    id uuid NOT NULL,
    dns_provider_id uuid NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    locked_by text,
    locked_until timestamp with time zone,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    discovered_zone_count integer,
    failure_code text,
    failure_message text,
    conflict_zone_name text,
    conflict_dns_provider_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT dns_provider_zone_refresh_jobs_completed_state CHECK ((((status = ANY (ARRAY['succeeded'::text, 'failed'::text, 'canceled'::text])) AND (completed_at IS NOT NULL)) OR ((status = ANY (ARRAY['pending'::text, 'running'::text])) AND (completed_at IS NULL)))),
    CONSTRAINT dns_provider_zone_refresh_jobs_conflict_state CHECK ((((failure_code = 'dns_provider_zone_conflict'::text) AND (conflict_zone_name IS NOT NULL) AND (conflict_dns_provider_id IS NOT NULL)) OR ((failure_code IS DISTINCT FROM 'dns_provider_zone_conflict'::text) AND (conflict_zone_name IS NULL) AND (conflict_dns_provider_id IS NULL)))),
    CONSTRAINT dns_provider_zone_refresh_jobs_conflict_zone_format CHECK (((conflict_zone_name IS NULL) OR (conflict_zone_name ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'::text))),
    CONSTRAINT dns_provider_zone_refresh_jobs_discovered_count_valid CHECK (((discovered_zone_count IS NULL) OR (discovered_zone_count >= 0))),
    CONSTRAINT dns_provider_zone_refresh_jobs_failure_code_format CHECK (((failure_code IS NULL) OR (((length(failure_code) >= 1) AND (length(failure_code) <= 128)) AND (failure_code ~ '^[a-z][a-z0-9_]{0,127}$'::text)))),
    CONSTRAINT dns_provider_zone_refresh_jobs_failure_message_format CHECK (((failure_message IS NULL) OR ((length(failure_message) <= 2048) AND (failure_message !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT dns_provider_zone_refresh_jobs_failure_state CHECK ((((status = 'failed'::text) AND (failure_code IS NOT NULL)) OR ((status <> 'failed'::text) AND (failure_code IS NULL) AND (failure_message IS NULL) AND (conflict_zone_name IS NULL) AND (conflict_dns_provider_id IS NULL)))),
    CONSTRAINT dns_provider_zone_refresh_jobs_lock_pair CHECK ((((locked_by IS NULL) AND (locked_until IS NULL)) OR ((locked_by IS NOT NULL) AND (locked_until IS NOT NULL)))),
    CONSTRAINT dns_provider_zone_refresh_jobs_locked_by_format CHECK (((locked_by IS NULL) OR (((length(locked_by) >= 1) AND (length(locked_by) <= 255)) AND (locked_by !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT dns_provider_zone_refresh_jobs_started_state CHECK (((status <> 'running'::text) OR (started_at IS NOT NULL))),
    CONSTRAINT dns_provider_zone_refresh_jobs_status_valid CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'succeeded'::text, 'failed'::text, 'canceled'::text]))),
    CONSTRAINT dns_provider_zone_refresh_jobs_updated_at_after_created CHECK ((updated_at >= created_at))
);


--
-- Name: dns_provider_zones; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dns_provider_zones (
    id uuid NOT NULL,
    dns_provider_id uuid NOT NULL,
    zone_name text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT dns_provider_zones_name_format CHECK ((zone_name ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'::text))
);


--
-- Name: dns_providers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dns_providers (
    id uuid NOT NULL,
    name text NOT NULL,
    type text NOT NULL,
    credentials_encrypted text NOT NULL,
    zone_mode text DEFAULT 'manual'::text NOT NULL,
    last_zone_refresh_at timestamp with time zone,
    zone_refresh_status text DEFAULT 'idle'::text NOT NULL,
    zone_refresh_failure_code text,
    zone_refresh_failure_message text,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT dns_providers_credentials_envelope_format CHECK ((((length(credentials_encrypted) >= 1) AND (length(credentials_encrypted) <= 8192)) AND ("left"(credentials_encrypted, 1) = '{'::text))),
    CONSTRAINT dns_providers_name_format CHECK ((name ~ '^[a-z](?:[a-z0-9_]{0,62}[a-z0-9])?$'::text)),
    CONSTRAINT dns_providers_status_valid CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text]))),
    CONSTRAINT dns_providers_type_valid CHECK ((type = ANY (ARRAY['cloudflare'::text, 'arvancloud'::text]))),
    CONSTRAINT dns_providers_updated_at_after_created CHECK ((updated_at >= created_at)),
    CONSTRAINT dns_providers_zone_mode_valid CHECK ((zone_mode = ANY (ARRAY['auto'::text, 'manual'::text]))),
    CONSTRAINT dns_providers_zone_refresh_failure_code_format CHECK (((zone_refresh_failure_code IS NULL) OR (((length(zone_refresh_failure_code) >= 1) AND (length(zone_refresh_failure_code) <= 128)) AND (zone_refresh_failure_code ~ '^[a-z][a-z0-9_]{0,127}$'::text)))),
    CONSTRAINT dns_providers_zone_refresh_failure_message_format CHECK (((zone_refresh_failure_message IS NULL) OR ((length(zone_refresh_failure_message) <= 2048) AND (zone_refresh_failure_message !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT dns_providers_zone_refresh_failure_state CHECK ((((zone_refresh_status = 'failed'::text) AND (zone_refresh_failure_code IS NOT NULL)) OR ((zone_refresh_status <> 'failed'::text) AND (zone_refresh_failure_code IS NULL) AND (zone_refresh_failure_message IS NULL)))),
    CONSTRAINT dns_providers_zone_refresh_status_valid CHECK ((zone_refresh_status = ANY (ARRAY['idle'::text, 'pending'::text, 'running'::text, 'succeeded'::text, 'failed'::text])))
);


--
-- Name: issuers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.issuers (
    id uuid NOT NULL,
    name text NOT NULL,
    type text DEFAULT 'acme'::text NOT NULL,
    directory_url text NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    status text DEFAULT 'disabled'::text NOT NULL,
    renewal_window_seconds integer DEFAULT 2592000 NOT NULL,
    contact_email text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT issuers_contact_email_normalized CHECK (((contact_email = lower(contact_email)) AND ((length(contact_email) >= 3) AND (length(contact_email) <= 254)) AND (contact_email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'::text) AND (contact_email !~ '[[:cntrl:]]'::text))),
    CONSTRAINT issuers_directory_url_format CHECK (((length(directory_url) <= 2048) AND (directory_url ~ '^https://[^[:space:]@#]+'::text) AND (directory_url !~ '[[:space:][:cntrl:]]'::text) AND (directory_url !~ '^https://[^/]+@'::text) AND (POSITION(('#'::text) IN (directory_url)) = 0))),
    CONSTRAINT issuers_name_format CHECK ((name ~ '^[a-z](?:[a-z0-9_]{0,62}[a-z0-9])?$'::text)),
    CONSTRAINT issuers_renewal_window_valid CHECK ((renewal_window_seconds >= 86400)),
    CONSTRAINT issuers_status_valid CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text]))),
    CONSTRAINT issuers_type_valid CHECK ((type = 'acme'::text)),
    CONSTRAINT issuers_updated_at_after_created CHECK ((updated_at >= created_at))
);


--
-- Name: oidc_login_handoffs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_login_handoffs (
    id uuid NOT NULL,
    handoff_hash text NOT NULL,
    user_id uuid NOT NULL,
    oidc_login_state_id uuid,
    frontend_return_url text,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    source_ip text,
    user_agent text,
    CONSTRAINT oidc_login_handoffs_consumed_state CHECK ((((status = 'consumed'::text) AND (consumed_at IS NOT NULL)) OR ((status <> 'consumed'::text) AND (consumed_at IS NULL)))),
    CONSTRAINT oidc_login_handoffs_expiry_after_created CHECK ((expires_at > created_at)),
    CONSTRAINT oidc_login_handoffs_frontend_return_url_format CHECK (((frontend_return_url IS NULL) OR ((length(frontend_return_url) <= 2048) AND (frontend_return_url ~ '^https://[^[:space:]]+$'::text) AND (frontend_return_url !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT oidc_login_handoffs_handoff_hash_format CHECK ((handoff_hash ~ '^[A-Za-z0-9_-]{43}$'::text)),
    CONSTRAINT oidc_login_handoffs_source_ip_format CHECK (((source_ip IS NULL) OR ((length(source_ip) <= 128) AND (source_ip !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT oidc_login_handoffs_status_valid CHECK ((status = ANY (ARRAY['active'::text, 'consumed'::text, 'expired'::text]))),
    CONSTRAINT oidc_login_handoffs_user_agent_format CHECK (((user_agent IS NULL) OR ((length(user_agent) <= 1024) AND (user_agent !~ '[[:cntrl:]]'::text))))
);


--
-- Name: oidc_login_states; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_login_states (
    id uuid NOT NULL,
    state_hash text NOT NULL,
    nonce text NOT NULL,
    code_verifier_encrypted text NOT NULL,
    provider_callback_url text NOT NULL,
    frontend_return_url text,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    source_ip text,
    user_agent text,
    CONSTRAINT oidc_login_states_code_verifier_envelope_format CHECK ((((length(code_verifier_encrypted) >= 1) AND (length(code_verifier_encrypted) <= 8192)) AND ("left"(code_verifier_encrypted, 1) = '{'::text))),
    CONSTRAINT oidc_login_states_expiry_after_created CHECK ((expires_at > created_at)),
    CONSTRAINT oidc_login_states_frontend_return_url_format CHECK (((frontend_return_url IS NULL) OR ((length(frontend_return_url) <= 2048) AND (frontend_return_url ~ '^https://[^[:space:]]+$'::text) AND (frontend_return_url !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT oidc_login_states_nonce_format CHECK ((((length(nonce) >= 22) AND (length(nonce) <= 256)) AND (nonce !~ '[[:cntrl:]]'::text))),
    CONSTRAINT oidc_login_states_provider_callback_url_format CHECK (((length(provider_callback_url) <= 2048) AND (provider_callback_url ~ '^https://[^[:space:]]+$'::text) AND (provider_callback_url !~ '[[:cntrl:]]'::text))),
    CONSTRAINT oidc_login_states_source_ip_format CHECK (((source_ip IS NULL) OR ((length(source_ip) <= 128) AND (source_ip !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT oidc_login_states_state_hash_format CHECK ((state_hash ~ '^[A-Za-z0-9_-]{43}$'::text)),
    CONSTRAINT oidc_login_states_user_agent_format CHECK (((user_agent IS NULL) OR ((length(user_agent) <= 1024) AND (user_agent !~ '[[:cntrl:]]'::text))))
);


--
-- Name: password_2fa_login_setups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.password_2fa_login_setups (
    id uuid NOT NULL,
    setup_hash text NOT NULL,
    user_id uuid NOT NULL,
    pending_totp_secret_encrypted text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    source_ip text,
    user_agent text,
    CONSTRAINT password_2fa_login_setups_consumed_state CHECK ((((status = 'consumed'::text) AND (consumed_at IS NOT NULL)) OR ((status <> 'consumed'::text) AND (consumed_at IS NULL)))),
    CONSTRAINT password_2fa_login_setups_expiry_after_created CHECK ((expires_at > created_at)),
    CONSTRAINT password_2fa_login_setups_hash_format CHECK ((setup_hash ~ '^[A-Za-z0-9_-]{43}$'::text)),
    CONSTRAINT password_2fa_login_setups_source_ip_format CHECK (((source_ip IS NULL) OR ((length(source_ip) <= 128) AND (source_ip !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT password_2fa_login_setups_status_valid CHECK ((status = ANY (ARRAY['active'::text, 'consumed'::text, 'expired'::text, 'superseded'::text]))),
    CONSTRAINT password_2fa_login_setups_totp_envelope_format CHECK ((((length(pending_totp_secret_encrypted) >= 1) AND (length(pending_totp_secret_encrypted) <= 8192)) AND ("left"(pending_totp_secret_encrypted, 1) = '{'::text))),
    CONSTRAINT password_2fa_login_setups_user_agent_format CHECK (((user_agent IS NULL) OR ((length(user_agent) <= 1024) AND (user_agent !~ '[[:cntrl:]]'::text))))
);


--
-- Name: user_invites; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_invites (
    id uuid NOT NULL,
    email text NOT NULL,
    global_role text DEFAULT 'user'::text NOT NULL,
    token_hash text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_by_user_id uuid NOT NULL,
    created_user_id uuid,
    pending_user_id uuid,
    pending_display_name text,
    pending_password_hash text,
    pending_totp_secret_encrypted text,
    pending_started_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    CONSTRAINT user_invites_consumed_state CHECK ((((status = 'consumed'::text) AND (consumed_at IS NOT NULL) AND (created_user_id IS NOT NULL)) OR ((status <> 'consumed'::text) AND (consumed_at IS NULL) AND (created_user_id IS NULL)))),
    CONSTRAINT user_invites_email_normalized CHECK (((email = lower(email)) AND ((length(email) >= 3) AND (length(email) <= 254)) AND (email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'::text) AND (email !~ '[[:cntrl:]]'::text))),
    CONSTRAINT user_invites_expiry_after_created CHECK ((expires_at > created_at)),
    CONSTRAINT user_invites_global_role_valid CHECK ((global_role = ANY (ARRAY['user'::text, 'admin'::text]))),
    CONSTRAINT user_invites_pending_display_name_format CHECK (((pending_display_name IS NULL) OR (((length(pending_display_name) >= 1) AND (length(pending_display_name) <= 255)) AND (pending_display_name !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT user_invites_pending_password_hash_format CHECK (((pending_password_hash IS NULL) OR (((length(pending_password_hash) >= 1) AND (length(pending_password_hash) <= 4096)) AND (pending_password_hash !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT user_invites_pending_state CHECK ((((pending_user_id IS NULL) AND (pending_display_name IS NULL) AND (pending_password_hash IS NULL) AND (pending_totp_secret_encrypted IS NULL) AND (pending_started_at IS NULL)) OR ((pending_user_id IS NOT NULL) AND (pending_display_name IS NOT NULL) AND (pending_password_hash IS NOT NULL) AND (pending_totp_secret_encrypted IS NOT NULL) AND (pending_started_at IS NOT NULL)))),
    CONSTRAINT user_invites_pending_totp_envelope_format CHECK (((pending_totp_secret_encrypted IS NULL) OR (((length(pending_totp_secret_encrypted) >= 1) AND (length(pending_totp_secret_encrypted) <= 8192)) AND ("left"(pending_totp_secret_encrypted, 1) = '{'::text)))),
    CONSTRAINT user_invites_status_valid CHECK ((status = ANY (ARRAY['active'::text, 'consumed'::text, 'expired'::text]))),
    CONSTRAINT user_invites_token_hash_format CHECK ((token_hash ~ '^[A-Za-z0-9_-]{43}$'::text))
);


--
-- Name: user_password_reset_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_password_reset_tokens (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_hash text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_by_user_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    CONSTRAINT user_password_reset_tokens_consumed_state CHECK ((((status = 'consumed'::text) AND (consumed_at IS NOT NULL)) OR ((status <> 'consumed'::text) AND (consumed_at IS NULL)))),
    CONSTRAINT user_password_reset_tokens_expiry_after_created CHECK ((expires_at > created_at)),
    CONSTRAINT user_password_reset_tokens_hash_format CHECK ((token_hash ~ '^[A-Za-z0-9_-]{43}$'::text)),
    CONSTRAINT user_password_reset_tokens_status_valid CHECK ((status = ANY (ARRAY['active'::text, 'consumed'::text, 'expired'::text, 'superseded'::text])))
);


--
-- Name: user_session_token_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_session_token_history (
    id uuid NOT NULL,
    user_session_id uuid NOT NULL,
    access_token_hash text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    access_expires_at timestamp with time zone NOT NULL,
    rotated_at timestamp with time zone,
    last_seen_at timestamp with time zone,
    CONSTRAINT user_session_token_history_expiry_after_issue CHECK ((access_expires_at > issued_at)),
    CONSTRAINT user_session_token_history_hash_format CHECK ((access_token_hash ~ '^[A-Za-z0-9_-]{43}$'::text)),
    CONSTRAINT user_session_token_history_rotated_state CHECK ((((status <> ALL (ARRAY['rotated'::text, 'reused'::text])) AND (rotated_at IS NULL)) OR ((status = 'rotated'::text) AND (rotated_at IS NOT NULL)) OR (status = 'reused'::text))),
    CONSTRAINT user_session_token_history_status_valid CHECK ((status = ANY (ARRAY['active'::text, 'rotated'::text, 'revoked'::text, 'reused'::text, 'expired'::text])))
);


--
-- Name: user_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_sessions (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    auth_method text NOT NULL,
    access_token_hash text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    access_expires_at timestamp with time zone NOT NULL,
    session_expires_at timestamp with time zone NOT NULL,
    last_refreshed_at timestamp with time zone,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revoked_reason text,
    user_agent text,
    source_ip text,
    CONSTRAINT user_sessions_access_token_hash_format CHECK ((access_token_hash ~ '^[A-Za-z0-9_-]{43}$'::text)),
    CONSTRAINT user_sessions_auth_method_valid CHECK ((auth_method = ANY (ARRAY['password'::text, 'oidc'::text]))),
    CONSTRAINT user_sessions_revoked_reason_valid CHECK (((revoked_reason IS NULL) OR (revoked_reason = ANY (ARRAY['logout'::text, 'disabled_user'::text, 'refresh_reuse'::text, 'token_reuse'::text, 'admin_action'::text, 'expired'::text, 'password_reset'::text, 'password_2fa_reset'::text, 'auth_model_migration'::text])))),
    CONSTRAINT user_sessions_revoked_state CHECK ((((status = 'active'::text) AND (revoked_at IS NULL) AND (revoked_reason IS NULL)) OR ((status = 'revoked'::text) AND (revoked_at IS NOT NULL) AND (revoked_reason IS NOT NULL)))),
    CONSTRAINT user_sessions_session_after_access CHECK ((session_expires_at >= access_expires_at)),
    CONSTRAINT user_sessions_source_ip_format CHECK (((source_ip IS NULL) OR ((length(source_ip) <= 128) AND (source_ip !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT user_sessions_status_valid CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text]))),
    CONSTRAINT user_sessions_user_agent_format CHECK (((user_agent IS NULL) OR ((length(user_agent) <= 1024) AND (user_agent !~ '[[:cntrl:]]'::text))))
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid NOT NULL,
    email text NOT NULL,
    display_name text NOT NULL,
    password_hash text,
    password_2fa_enabled boolean DEFAULT false NOT NULL,
    totp_secret_encrypted text,
    pending_totp_secret_encrypted text,
    oidc_issuer text,
    oidc_subject text,
    global_role text DEFAULT 'user'::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login_at timestamp with time zone,
    CONSTRAINT users_display_name_format CHECK ((((length(display_name) >= 1) AND (length(display_name) <= 255)) AND (display_name !~ '[[:cntrl:]]'::text))),
    CONSTRAINT users_email_normalized CHECK (((email = lower(email)) AND ((length(email) >= 3) AND (length(email) <= 254)) AND (email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'::text) AND (email !~ '[[:cntrl:]]'::text))),
    CONSTRAINT users_global_role_valid CHECK ((global_role = ANY (ARRAY['user'::text, 'admin'::text]))),
    CONSTRAINT users_oidc_issuer_format CHECK (((oidc_issuer IS NULL) OR ((length(oidc_issuer) <= 2048) AND (oidc_issuer ~ '^https://[^[:space:]]+$'::text) AND (oidc_issuer !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT users_oidc_pair CHECK ((((oidc_issuer IS NULL) AND (oidc_subject IS NULL)) OR ((oidc_issuer IS NOT NULL) AND (oidc_subject IS NOT NULL)))),
    CONSTRAINT users_oidc_subject_format CHECK (((oidc_subject IS NULL) OR (((length(oidc_subject) >= 1) AND (length(oidc_subject) <= 255)) AND (oidc_subject !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT users_password_hash_format CHECK (((password_hash IS NULL) OR (((length(password_hash) >= 1) AND (length(password_hash) <= 4096)) AND (password_hash !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT users_pending_totp_envelope_format CHECK (((pending_totp_secret_encrypted IS NULL) OR (((length(pending_totp_secret_encrypted) >= 1) AND (length(pending_totp_secret_encrypted) <= 8192)) AND ("left"(pending_totp_secret_encrypted, 1) = '{'::text)))),
    CONSTRAINT users_status_valid CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text]))),
    CONSTRAINT users_totp_enabled_secret CHECK (((NOT password_2fa_enabled) OR (totp_secret_encrypted IS NOT NULL))),
    CONSTRAINT users_totp_envelope_format CHECK (((totp_secret_encrypted IS NULL) OR (((length(totp_secret_encrypted) >= 1) AND (length(totp_secret_encrypted) <= 8192)) AND ("left"(totp_secret_encrypted, 1) = '{'::text)))),
    CONSTRAINT users_updated_at_after_created CHECK ((updated_at >= created_at))
);


--
-- Name: acme_accounts acme_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_accounts
    ADD CONSTRAINT acme_accounts_pkey PRIMARY KEY (id);


--
-- Name: application_domain_scopes application_domain_scopes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_domain_scopes
    ADD CONSTRAINT application_domain_scopes_pkey PRIMARY KEY (id);


--
-- Name: application_tokens application_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_tokens
    ADD CONSTRAINT application_tokens_pkey PRIMARY KEY (id);


--
-- Name: application_user_grants application_user_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_grants
    ADD CONSTRAINT application_user_grants_pkey PRIMARY KEY (id);


--
-- Name: applications applications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_pkey PRIMARY KEY (id);


--
-- Name: audit_events audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);


--
-- Name: certhub_leases certhub_leases_lease_token_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certhub_leases
    ADD CONSTRAINT certhub_leases_lease_token_unique UNIQUE (lease_token);


--
-- Name: certhub_leases certhub_leases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certhub_leases
    ADD CONSTRAINT certhub_leases_pkey PRIMARY KEY (name);


--
-- Name: certificate_events certificate_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_events
    ADD CONSTRAINT certificate_events_pkey PRIMARY KEY (id);


--
-- Name: certificate_issuance_jobs certificate_issuance_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_issuance_jobs
    ADD CONSTRAINT certificate_issuance_jobs_pkey PRIMARY KEY (id);


--
-- Name: certificate_versions certificate_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_versions
    ADD CONSTRAINT certificate_versions_pkey PRIMARY KEY (id);


--
-- Name: certificates certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_pkey PRIMARY KEY (id);


--
-- Name: dns_challenge_records dns_challenge_records_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_challenge_records
    ADD CONSTRAINT dns_challenge_records_pkey PRIMARY KEY (id);


--
-- Name: dns_provider_zone_refresh_jobs dns_provider_zone_refresh_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_provider_zone_refresh_jobs
    ADD CONSTRAINT dns_provider_zone_refresh_jobs_pkey PRIMARY KEY (id);


--
-- Name: dns_provider_zones dns_provider_zones_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_provider_zones
    ADD CONSTRAINT dns_provider_zones_pkey PRIMARY KEY (id);


--
-- Name: dns_providers dns_providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_providers
    ADD CONSTRAINT dns_providers_pkey PRIMARY KEY (id);


--
-- Name: issuers issuers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.issuers
    ADD CONSTRAINT issuers_pkey PRIMARY KEY (id);


--
-- Name: oidc_login_handoffs oidc_login_handoffs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_login_handoffs
    ADD CONSTRAINT oidc_login_handoffs_pkey PRIMARY KEY (id);


--
-- Name: oidc_login_states oidc_login_states_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_login_states
    ADD CONSTRAINT oidc_login_states_pkey PRIMARY KEY (id);


--
-- Name: password_2fa_login_setups password_2fa_login_setups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_2fa_login_setups
    ADD CONSTRAINT password_2fa_login_setups_pkey PRIMARY KEY (id);


--
-- Name: user_invites user_invites_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_invites
    ADD CONSTRAINT user_invites_pkey PRIMARY KEY (id);


--
-- Name: user_password_reset_tokens user_password_reset_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_password_reset_tokens
    ADD CONSTRAINT user_password_reset_tokens_pkey PRIMARY KEY (id);


--
-- Name: user_session_token_history user_session_token_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_session_token_history
    ADD CONSTRAINT user_session_token_history_pkey PRIMARY KEY (id);


--
-- Name: user_sessions user_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: acme_accounts_account_url_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX acme_accounts_account_url_unique ON public.acme_accounts USING btree (account_url);


--
-- Name: acme_accounts_issuer_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX acme_accounts_issuer_id_idx ON public.acme_accounts USING btree (issuer_id);


--
-- Name: acme_accounts_one_active_per_issuer_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX acme_accounts_one_active_per_issuer_idx ON public.acme_accounts USING btree (issuer_id) WHERE (status = 'active'::text);


--
-- Name: acme_accounts_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX acme_accounts_status_idx ON public.acme_accounts USING btree (status);


--
-- Name: application_domain_scopes_application_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_domain_scopes_application_id_idx ON public.application_domain_scopes USING btree (application_id);


--
-- Name: application_domain_scopes_application_value_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX application_domain_scopes_application_value_unique ON public.application_domain_scopes USING btree (application_id, value);


--
-- Name: application_domain_scopes_value_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_domain_scopes_value_idx ON public.application_domain_scopes USING btree (value);


--
-- Name: application_tokens_application_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_tokens_application_id_idx ON public.application_tokens USING btree (application_id);


--
-- Name: application_tokens_status_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_tokens_status_expiry_idx ON public.application_tokens USING btree (status, expires_at);


--
-- Name: application_tokens_token_hash_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX application_tokens_token_hash_unique ON public.application_tokens USING btree (token_hash);


--
-- Name: application_user_grants_application_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_user_grants_application_id_idx ON public.application_user_grants USING btree (application_id);


--
-- Name: application_user_grants_application_user_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX application_user_grants_application_user_unique ON public.application_user_grants USING btree (application_id, user_id);


--
-- Name: application_user_grants_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_user_grants_user_id_idx ON public.application_user_grants USING btree (user_id);


--
-- Name: applications_name_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX applications_name_unique ON public.applications USING btree (name);


--
-- Name: applications_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX applications_status_idx ON public.applications USING btree (status);


--
-- Name: applications_system_kind_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX applications_system_kind_idx ON public.applications USING btree (system_kind) WHERE (system_kind IS NOT NULL);


--
-- Name: audit_events_action_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_action_created_at_idx ON public.audit_events USING btree (action, created_at DESC);


--
-- Name: audit_events_correlation_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_correlation_id_idx ON public.audit_events USING btree (correlation_id) WHERE (correlation_id IS NOT NULL);


--
-- Name: audit_events_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_created_at_idx ON public.audit_events USING btree (created_at DESC);


--
-- Name: audit_events_identity_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_identity_created_at_idx ON public.audit_events USING btree (identity_type, identity_id, created_at DESC);


--
-- Name: audit_events_scope_application_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_scope_application_created_at_idx ON public.audit_events USING btree (scope_application_id, created_at DESC) WHERE (scope_application_id IS NOT NULL);


--
-- Name: audit_events_scope_certificate_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_scope_certificate_created_at_idx ON public.audit_events USING btree (scope_certificate_id, created_at DESC) WHERE (scope_certificate_id IS NOT NULL);


--
-- Name: audit_events_scope_dns_provider_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_scope_dns_provider_created_at_idx ON public.audit_events USING btree (scope_dns_provider_id, created_at DESC) WHERE (scope_dns_provider_id IS NOT NULL);


--
-- Name: audit_events_scope_user_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_scope_user_created_at_idx ON public.audit_events USING btree (scope_user_id, created_at DESC) WHERE (scope_user_id IS NOT NULL);


--
-- Name: audit_events_target_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_target_created_at_idx ON public.audit_events USING btree (target_type, target_id, created_at DESC);


--
-- Name: certhub_leases_locked_until_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certhub_leases_locked_until_idx ON public.certhub_leases USING btree (locked_until);


--
-- Name: certificate_events_certificate_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_events_certificate_created_at_idx ON public.certificate_events USING btree (certificate_id, created_at DESC, id DESC);


--
-- Name: certificate_events_job_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_events_job_created_at_idx ON public.certificate_events USING btree (issuance_job_id, created_at DESC) WHERE (issuance_job_id IS NOT NULL);


--
-- Name: certificate_events_version_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_events_version_created_at_idx ON public.certificate_events USING btree (certificate_version_id, created_at DESC) WHERE (certificate_version_id IS NOT NULL);


--
-- Name: certificate_issuance_jobs_active_null_version_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX certificate_issuance_jobs_active_null_version_idx ON public.certificate_issuance_jobs USING btree (certificate_id, reason) WHERE ((certificate_version_id IS NULL) AND (status = ANY (ARRAY['pending'::text, 'running'::text])));


--
-- Name: certificate_issuance_jobs_active_version_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX certificate_issuance_jobs_active_version_idx ON public.certificate_issuance_jobs USING btree (certificate_version_id) WHERE ((certificate_version_id IS NOT NULL) AND (status = ANY (ARRAY['pending'::text, 'running'::text])));


--
-- Name: certificate_issuance_jobs_certificate_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_issuance_jobs_certificate_id_idx ON public.certificate_issuance_jobs USING btree (certificate_id);


--
-- Name: certificate_issuance_jobs_certificate_version_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_issuance_jobs_certificate_version_id_idx ON public.certificate_issuance_jobs USING btree (certificate_version_id) WHERE (certificate_version_id IS NOT NULL);


--
-- Name: certificate_issuance_jobs_claim_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_issuance_jobs_claim_idx ON public.certificate_issuance_jobs USING btree (next_run_at, created_at, id) WHERE (status = ANY (ARRAY['pending'::text, 'running'::text]));


--
-- Name: certificate_versions_certificate_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_versions_certificate_id_idx ON public.certificate_versions USING btree (certificate_id);


--
-- Name: certificate_versions_certificate_version_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX certificate_versions_certificate_version_unique ON public.certificate_versions USING btree (certificate_id, version);


--
-- Name: certificate_versions_latest_valid_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_versions_latest_valid_idx ON public.certificate_versions USING btree (certificate_id, version DESC) WHERE (status = 'valid'::text);


--
-- Name: certificate_versions_material_etag_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_versions_material_etag_idx ON public.certificate_versions USING btree (material_etag) WHERE (material_etag IS NOT NULL);


--
-- Name: certificate_versions_one_issuing_per_certificate_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX certificate_versions_one_issuing_per_certificate_idx ON public.certificate_versions USING btree (certificate_id) WHERE (status = 'issuing'::text);


--
-- Name: certificates_application_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificates_application_id_idx ON public.certificates USING btree (application_id);


--
-- Name: certificates_issuer_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificates_issuer_id_idx ON public.certificates USING btree (issuer_id);


--
-- Name: certificates_sans_gin_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificates_sans_gin_idx ON public.certificates USING gin (normalized_sans);


--
-- Name: certificates_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificates_status_idx ON public.certificates USING btree (status);


--
-- Name: dns_challenge_records_certificate_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dns_challenge_records_certificate_id_idx ON public.dns_challenge_records USING btree (certificate_id);


--
-- Name: dns_challenge_records_cleanup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dns_challenge_records_cleanup_idx ON public.dns_challenge_records USING btree (status, updated_at) WHERE (status = ANY (ARRAY['cleanup_pending'::text, 'cleanup_failed'::text]));


--
-- Name: dns_challenge_records_exact_value_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX dns_challenge_records_exact_value_idx ON public.dns_challenge_records USING btree (issuance_job_id, record_name, txt_value_encrypted);


--
-- Name: dns_challenge_records_job_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dns_challenge_records_job_id_idx ON public.dns_challenge_records USING btree (issuance_job_id);


--
-- Name: dns_challenge_records_version_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dns_challenge_records_version_id_idx ON public.dns_challenge_records USING btree (certificate_version_id);


--
-- Name: dns_provider_zone_refresh_jobs_claim_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dns_provider_zone_refresh_jobs_claim_idx ON public.dns_provider_zone_refresh_jobs USING btree (status, locked_until, created_at) WHERE (status = ANY (ARRAY['pending'::text, 'running'::text]));


--
-- Name: dns_provider_zone_refresh_jobs_one_active_per_provider_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX dns_provider_zone_refresh_jobs_one_active_per_provider_idx ON public.dns_provider_zone_refresh_jobs USING btree (dns_provider_id) WHERE (status = ANY (ARRAY['pending'::text, 'running'::text]));


--
-- Name: dns_provider_zone_refresh_jobs_provider_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dns_provider_zone_refresh_jobs_provider_id_idx ON public.dns_provider_zone_refresh_jobs USING btree (dns_provider_id);


--
-- Name: dns_provider_zones_name_length_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dns_provider_zones_name_length_idx ON public.dns_provider_zones USING btree (length(zone_name) DESC, zone_name);


--
-- Name: dns_provider_zones_name_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX dns_provider_zones_name_unique ON public.dns_provider_zones USING btree (zone_name);


--
-- Name: dns_provider_zones_provider_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dns_provider_zones_provider_id_idx ON public.dns_provider_zones USING btree (dns_provider_id);


--
-- Name: dns_provider_zones_provider_name_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX dns_provider_zones_provider_name_unique ON public.dns_provider_zones USING btree (dns_provider_id, zone_name);


--
-- Name: dns_providers_name_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX dns_providers_name_unique ON public.dns_providers USING btree (name);


--
-- Name: dns_providers_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dns_providers_status_idx ON public.dns_providers USING btree (status);


--
-- Name: dns_providers_type_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dns_providers_type_idx ON public.dns_providers USING btree (type);


--
-- Name: dns_providers_zone_mode_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dns_providers_zone_mode_idx ON public.dns_providers USING btree (zone_mode);


--
-- Name: issuers_name_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX issuers_name_unique ON public.issuers USING btree (name);


--
-- Name: issuers_one_active_default_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX issuers_one_active_default_idx ON public.issuers USING btree (is_default) WHERE (is_default AND (status = 'active'::text));


--
-- Name: issuers_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX issuers_status_idx ON public.issuers USING btree (status);


--
-- Name: oidc_login_handoffs_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oidc_login_handoffs_active_idx ON public.oidc_login_handoffs USING btree (expires_at) WHERE (status = 'active'::text);


--
-- Name: oidc_login_handoffs_handoff_hash_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX oidc_login_handoffs_handoff_hash_unique ON public.oidc_login_handoffs USING btree (handoff_hash);


--
-- Name: oidc_login_handoffs_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oidc_login_handoffs_user_id_idx ON public.oidc_login_handoffs USING btree (user_id);


--
-- Name: oidc_login_states_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oidc_login_states_active_idx ON public.oidc_login_states USING btree (expires_at) WHERE (consumed_at IS NULL);


--
-- Name: oidc_login_states_state_hash_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX oidc_login_states_state_hash_unique ON public.oidc_login_states USING btree (state_hash);


--
-- Name: password_2fa_login_setups_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX password_2fa_login_setups_active_idx ON public.password_2fa_login_setups USING btree (expires_at) WHERE (status = 'active'::text);


--
-- Name: password_2fa_login_setups_hash_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX password_2fa_login_setups_hash_unique ON public.password_2fa_login_setups USING btree (setup_hash);


--
-- Name: password_2fa_login_setups_one_active_per_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX password_2fa_login_setups_one_active_per_user_idx ON public.password_2fa_login_setups USING btree (user_id) WHERE (status = 'active'::text);


--
-- Name: uniq_active_certificate_identity_per_application; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uniq_active_certificate_identity_per_application ON public.certificates USING btree (application_id, normalized_sans, key_type, issuer_id) WHERE (deleted_at IS NULL);


--
-- Name: user_invites_active_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_invites_active_expires_idx ON public.user_invites USING btree (expires_at) WHERE (status = 'active'::text);


--
-- Name: user_invites_email_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_invites_email_idx ON public.user_invites USING btree (email);


--
-- Name: user_invites_token_hash_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX user_invites_token_hash_unique ON public.user_invites USING btree (token_hash);


--
-- Name: user_password_reset_tokens_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_password_reset_tokens_active_idx ON public.user_password_reset_tokens USING btree (expires_at) WHERE (status = 'active'::text);


--
-- Name: user_password_reset_tokens_hash_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX user_password_reset_tokens_hash_unique ON public.user_password_reset_tokens USING btree (token_hash);


--
-- Name: user_password_reset_tokens_one_active_per_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX user_password_reset_tokens_one_active_per_user_idx ON public.user_password_reset_tokens USING btree (user_id) WHERE (status = 'active'::text);


--
-- Name: user_session_token_history_hash_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX user_session_token_history_hash_unique ON public.user_session_token_history USING btree (access_token_hash);


--
-- Name: user_session_token_history_one_active_per_session_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX user_session_token_history_one_active_per_session_idx ON public.user_session_token_history USING btree (user_session_id) WHERE (status = 'active'::text);


--
-- Name: user_session_token_history_session_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_session_token_history_session_idx ON public.user_session_token_history USING btree (user_session_id);


--
-- Name: user_session_token_history_status_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_session_token_history_status_expires_idx ON public.user_session_token_history USING btree (status, access_expires_at);


--
-- Name: user_sessions_access_token_hash_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX user_sessions_access_token_hash_unique ON public.user_sessions USING btree (access_token_hash);


--
-- Name: user_sessions_status_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_sessions_status_expires_idx ON public.user_sessions USING btree (status, access_expires_at, session_expires_at);


--
-- Name: user_sessions_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_sessions_user_id_idx ON public.user_sessions USING btree (user_id);


--
-- Name: users_email_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_email_unique ON public.users USING btree (email);


--
-- Name: users_global_role_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_global_role_idx ON public.users USING btree (global_role);


--
-- Name: users_oidc_identity_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_oidc_identity_unique ON public.users USING btree (oidc_issuer, oidc_subject) WHERE ((oidc_issuer IS NOT NULL) AND (oidc_subject IS NOT NULL));


--
-- Name: users_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_status_idx ON public.users USING btree (status);


--
-- Name: acme_accounts acme_accounts_preserve_active_issuer; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER acme_accounts_preserve_active_issuer BEFORE DELETE OR UPDATE OF issuer_id, status ON public.acme_accounts FOR EACH ROW EXECUTE FUNCTION public.certhub_preserve_active_issuer_account();


--
-- Name: application_domain_scopes application_domain_scopes_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER application_domain_scopes_immutable BEFORE UPDATE ON public.application_domain_scopes FOR EACH STATEMENT EXECUTE FUNCTION public.certhub_reject_application_domain_scope_update();


--
-- Name: application_tokens application_tokens_no_system_application; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER application_tokens_no_system_application BEFORE INSERT OR UPDATE OF application_id ON public.application_tokens FOR EACH ROW EXECUTE FUNCTION public.certhub_reject_system_application_token();


--
-- Name: application_user_grants application_user_grants_no_system_application; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER application_user_grants_no_system_application BEFORE INSERT OR UPDATE OF application_id ON public.application_user_grants FOR EACH ROW EXECUTE FUNCTION public.certhub_reject_system_application_grant();


--
-- Name: audit_events audit_events_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER audit_events_append_only BEFORE DELETE OR UPDATE OR TRUNCATE ON public.audit_events FOR EACH STATEMENT EXECUTE FUNCTION public.certhub_reject_audit_event_mutation();


--
-- Name: certificate_events certificate_events_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER certificate_events_append_only BEFORE DELETE OR UPDATE OR TRUNCATE ON public.certificate_events FOR EACH STATEMENT EXECUTE FUNCTION public.certhub_reject_certificate_event_mutation();


--
-- Name: certificate_versions certificate_versions_monotonic; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER certificate_versions_monotonic BEFORE INSERT ON public.certificate_versions FOR EACH ROW EXECUTE FUNCTION public.certhub_reject_certificate_version_regression();


--
-- Name: certificate_versions certificate_versions_valid_overlap; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER certificate_versions_valid_overlap BEFORE INSERT OR UPDATE OF status, not_after ON public.certificate_versions FOR EACH ROW EXECUTE FUNCTION public.certhub_enforce_certificate_version_overlap();


--
-- Name: certificates certificates_system_application_limit; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER certificates_system_application_limit BEFORE INSERT OR UPDATE OF application_id, deleted_at ON public.certificates FOR EACH ROW EXECUTE FUNCTION public.certhub_enforce_system_application_certificate_limit();


--
-- Name: dns_provider_zones dns_provider_zones_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER dns_provider_zones_immutable BEFORE UPDATE ON public.dns_provider_zones FOR EACH STATEMENT EXECUTE FUNCTION public.certhub_reject_dns_provider_zone_update();


--
-- Name: issuers issuers_active_account_required; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER issuers_active_account_required BEFORE INSERT OR UPDATE OF status ON public.issuers FOR EACH ROW EXECUTE FUNCTION public.certhub_require_active_issuer_account();


--
-- Name: issuers issuers_immutable_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER issuers_immutable_identity BEFORE UPDATE ON public.issuers FOR EACH ROW EXECUTE FUNCTION public.certhub_reject_issuer_immutable_update();


--
-- Name: acme_accounts acme_accounts_issuer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_accounts
    ADD CONSTRAINT acme_accounts_issuer_id_fkey FOREIGN KEY (issuer_id) REFERENCES public.issuers(id);


--
-- Name: application_domain_scopes application_domain_scopes_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_domain_scopes
    ADD CONSTRAINT application_domain_scopes_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);


--
-- Name: application_domain_scopes application_domain_scopes_created_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_domain_scopes
    ADD CONSTRAINT application_domain_scopes_created_by_user_id_fkey FOREIGN KEY (created_by_user_id) REFERENCES public.users(id);


--
-- Name: application_tokens application_tokens_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_tokens
    ADD CONSTRAINT application_tokens_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);


--
-- Name: application_user_grants application_user_grants_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_grants
    ADD CONSTRAINT application_user_grants_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);


--
-- Name: application_user_grants application_user_grants_created_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_grants
    ADD CONSTRAINT application_user_grants_created_by_user_id_fkey FOREIGN KEY (created_by_user_id) REFERENCES public.users(id);


--
-- Name: application_user_grants application_user_grants_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_grants
    ADD CONSTRAINT application_user_grants_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: audit_events audit_events_scope_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_scope_application_id_fkey FOREIGN KEY (scope_application_id) REFERENCES public.applications(id);


--
-- Name: audit_events audit_events_scope_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_scope_certificate_id_fkey FOREIGN KEY (scope_certificate_id) REFERENCES public.certificates(id);


--
-- Name: audit_events audit_events_scope_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_scope_user_id_fkey FOREIGN KEY (scope_user_id) REFERENCES public.users(id);


--
-- Name: certificate_events certificate_events_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_events
    ADD CONSTRAINT certificate_events_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificates(id);


--
-- Name: certificate_events certificate_events_certificate_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_events
    ADD CONSTRAINT certificate_events_certificate_version_id_fkey FOREIGN KEY (certificate_version_id) REFERENCES public.certificate_versions(id);


--
-- Name: certificate_events certificate_events_issuance_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_events
    ADD CONSTRAINT certificate_events_issuance_job_id_fkey FOREIGN KEY (issuance_job_id) REFERENCES public.certificate_issuance_jobs(id);


--
-- Name: certificate_issuance_jobs certificate_issuance_jobs_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_issuance_jobs
    ADD CONSTRAINT certificate_issuance_jobs_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificates(id);


--
-- Name: certificate_issuance_jobs certificate_issuance_jobs_certificate_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_issuance_jobs
    ADD CONSTRAINT certificate_issuance_jobs_certificate_version_id_fkey FOREIGN KEY (certificate_version_id) REFERENCES public.certificate_versions(id);


--
-- Name: certificate_versions certificate_versions_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_versions
    ADD CONSTRAINT certificate_versions_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificates(id);


--
-- Name: certificate_versions certificate_versions_revoked_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_versions
    ADD CONSTRAINT certificate_versions_revoked_by_user_id_fkey FOREIGN KEY (revoked_by_user_id) REFERENCES public.users(id);


--
-- Name: certificates certificates_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);


--
-- Name: certificates certificates_issuer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_issuer_id_fkey FOREIGN KEY (issuer_id) REFERENCES public.issuers(id);


--
-- Name: certificates certificates_revoked_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_revoked_by_user_id_fkey FOREIGN KEY (revoked_by_user_id) REFERENCES public.users(id);


--
-- Name: dns_challenge_records dns_challenge_records_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_challenge_records
    ADD CONSTRAINT dns_challenge_records_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificates(id);


--
-- Name: dns_challenge_records dns_challenge_records_certificate_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_challenge_records
    ADD CONSTRAINT dns_challenge_records_certificate_version_id_fkey FOREIGN KEY (certificate_version_id) REFERENCES public.certificate_versions(id);


--
-- Name: dns_challenge_records dns_challenge_records_dns_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_challenge_records
    ADD CONSTRAINT dns_challenge_records_dns_provider_id_fkey FOREIGN KEY (dns_provider_id) REFERENCES public.dns_providers(id);


--
-- Name: dns_challenge_records dns_challenge_records_dns_provider_zone_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_challenge_records
    ADD CONSTRAINT dns_challenge_records_dns_provider_zone_id_fkey FOREIGN KEY (dns_provider_zone_id) REFERENCES public.dns_provider_zones(id);


--
-- Name: dns_challenge_records dns_challenge_records_issuance_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_challenge_records
    ADD CONSTRAINT dns_challenge_records_issuance_job_id_fkey FOREIGN KEY (issuance_job_id) REFERENCES public.certificate_issuance_jobs(id);


--
-- Name: dns_provider_zone_refresh_jobs dns_provider_zone_refresh_jobs_conflict_dns_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_provider_zone_refresh_jobs
    ADD CONSTRAINT dns_provider_zone_refresh_jobs_conflict_dns_provider_id_fkey FOREIGN KEY (conflict_dns_provider_id) REFERENCES public.dns_providers(id);


--
-- Name: dns_provider_zone_refresh_jobs dns_provider_zone_refresh_jobs_dns_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_provider_zone_refresh_jobs
    ADD CONSTRAINT dns_provider_zone_refresh_jobs_dns_provider_id_fkey FOREIGN KEY (dns_provider_id) REFERENCES public.dns_providers(id);


--
-- Name: dns_provider_zones dns_provider_zones_dns_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_provider_zones
    ADD CONSTRAINT dns_provider_zones_dns_provider_id_fkey FOREIGN KEY (dns_provider_id) REFERENCES public.dns_providers(id);


--
-- Name: oidc_login_handoffs oidc_login_handoffs_oidc_login_state_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_login_handoffs
    ADD CONSTRAINT oidc_login_handoffs_oidc_login_state_id_fkey FOREIGN KEY (oidc_login_state_id) REFERENCES public.oidc_login_states(id);


--
-- Name: oidc_login_handoffs oidc_login_handoffs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_login_handoffs
    ADD CONSTRAINT oidc_login_handoffs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: password_2fa_login_setups password_2fa_login_setups_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_2fa_login_setups
    ADD CONSTRAINT password_2fa_login_setups_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: user_invites user_invites_created_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_invites
    ADD CONSTRAINT user_invites_created_by_user_id_fkey FOREIGN KEY (created_by_user_id) REFERENCES public.users(id);


--
-- Name: user_invites user_invites_created_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_invites
    ADD CONSTRAINT user_invites_created_user_id_fkey FOREIGN KEY (created_user_id) REFERENCES public.users(id);


--
-- Name: user_password_reset_tokens user_password_reset_tokens_created_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_password_reset_tokens
    ADD CONSTRAINT user_password_reset_tokens_created_by_user_id_fkey FOREIGN KEY (created_by_user_id) REFERENCES public.users(id);


--
-- Name: user_password_reset_tokens user_password_reset_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_password_reset_tokens
    ADD CONSTRAINT user_password_reset_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: user_session_token_history user_session_token_history_user_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_session_token_history
    ADD CONSTRAINT user_session_token_history_user_session_id_fkey FOREIGN KEY (user_session_id) REFERENCES public.user_sessions(id);


--
-- Name: user_sessions user_sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--

-- +goose Down
drop trigger if exists acme_accounts_preserve_active_issuer on public.acme_accounts;
drop trigger if exists application_domain_scopes_immutable on public.application_domain_scopes;
drop trigger if exists application_tokens_no_system_application on public.application_tokens;
drop trigger if exists application_user_grants_no_system_application on public.application_user_grants;
drop trigger if exists audit_events_append_only on public.audit_events;
drop trigger if exists certificate_events_append_only on public.certificate_events;
drop trigger if exists certificate_versions_monotonic on public.certificate_versions;
drop trigger if exists certificate_versions_valid_overlap on public.certificate_versions;
drop trigger if exists certificates_system_application_limit on public.certificates;
drop trigger if exists dns_provider_zones_immutable on public.dns_provider_zones;
drop trigger if exists issuers_active_account_required on public.issuers;
drop trigger if exists issuers_immutable_identity on public.issuers;

alter table if exists public.acme_accounts drop constraint if exists acme_accounts_issuer_id_fkey;
alter table if exists public.application_domain_scopes drop constraint if exists application_domain_scopes_application_id_fkey;
alter table if exists public.application_domain_scopes drop constraint if exists application_domain_scopes_created_by_user_id_fkey;
alter table if exists public.application_tokens drop constraint if exists application_tokens_application_id_fkey;
alter table if exists public.application_user_grants drop constraint if exists application_user_grants_application_id_fkey;
alter table if exists public.application_user_grants drop constraint if exists application_user_grants_created_by_user_id_fkey;
alter table if exists public.application_user_grants drop constraint if exists application_user_grants_user_id_fkey;
alter table if exists public.audit_events drop constraint if exists audit_events_scope_application_id_fkey;
alter table if exists public.audit_events drop constraint if exists audit_events_scope_certificate_id_fkey;
alter table if exists public.audit_events drop constraint if exists audit_events_scope_user_id_fkey;
alter table if exists public.certificate_events drop constraint if exists certificate_events_certificate_id_fkey;
alter table if exists public.certificate_events drop constraint if exists certificate_events_certificate_version_id_fkey;
alter table if exists public.certificate_events drop constraint if exists certificate_events_issuance_job_id_fkey;
alter table if exists public.certificate_issuance_jobs drop constraint if exists certificate_issuance_jobs_certificate_id_fkey;
alter table if exists public.certificate_issuance_jobs drop constraint if exists certificate_issuance_jobs_certificate_version_id_fkey;
alter table if exists public.certificate_versions drop constraint if exists certificate_versions_certificate_id_fkey;
alter table if exists public.certificate_versions drop constraint if exists certificate_versions_revoked_by_user_id_fkey;
alter table if exists public.certificates drop constraint if exists certificates_application_id_fkey;
alter table if exists public.certificates drop constraint if exists certificates_issuer_id_fkey;
alter table if exists public.certificates drop constraint if exists certificates_revoked_by_user_id_fkey;
alter table if exists public.dns_challenge_records drop constraint if exists dns_challenge_records_certificate_id_fkey;
alter table if exists public.dns_challenge_records drop constraint if exists dns_challenge_records_certificate_version_id_fkey;
alter table if exists public.dns_challenge_records drop constraint if exists dns_challenge_records_dns_provider_id_fkey;
alter table if exists public.dns_challenge_records drop constraint if exists dns_challenge_records_dns_provider_zone_id_fkey;
alter table if exists public.dns_challenge_records drop constraint if exists dns_challenge_records_issuance_job_id_fkey;
alter table if exists public.dns_provider_zone_refresh_jobs drop constraint if exists dns_provider_zone_refresh_jobs_conflict_dns_provider_id_fkey;
alter table if exists public.dns_provider_zone_refresh_jobs drop constraint if exists dns_provider_zone_refresh_jobs_dns_provider_id_fkey;
alter table if exists public.dns_provider_zones drop constraint if exists dns_provider_zones_dns_provider_id_fkey;
alter table if exists public.oidc_login_handoffs drop constraint if exists oidc_login_handoffs_oidc_login_state_id_fkey;
alter table if exists public.oidc_login_handoffs drop constraint if exists oidc_login_handoffs_user_id_fkey;
alter table if exists public.password_2fa_login_setups drop constraint if exists password_2fa_login_setups_user_id_fkey;
alter table if exists public.user_invites drop constraint if exists user_invites_created_by_user_id_fkey;
alter table if exists public.user_invites drop constraint if exists user_invites_created_user_id_fkey;
alter table if exists public.user_password_reset_tokens drop constraint if exists user_password_reset_tokens_created_by_user_id_fkey;
alter table if exists public.user_password_reset_tokens drop constraint if exists user_password_reset_tokens_user_id_fkey;
alter table if exists public.user_session_token_history drop constraint if exists user_session_token_history_user_session_id_fkey;
alter table if exists public.user_sessions drop constraint if exists user_sessions_user_id_fkey;

drop index if exists public.acme_accounts_account_url_unique;
drop index if exists public.acme_accounts_issuer_id_idx;
drop index if exists public.acme_accounts_one_active_per_issuer_idx;
drop index if exists public.acme_accounts_status_idx;
drop index if exists public.application_domain_scopes_application_id_idx;
drop index if exists public.application_domain_scopes_application_value_unique;
drop index if exists public.application_domain_scopes_value_idx;
drop index if exists public.application_tokens_application_id_idx;
drop index if exists public.application_tokens_status_expiry_idx;
drop index if exists public.application_tokens_token_hash_unique;
drop index if exists public.application_user_grants_application_id_idx;
drop index if exists public.application_user_grants_application_user_unique;
drop index if exists public.application_user_grants_user_id_idx;
drop index if exists public.applications_name_unique;
drop index if exists public.applications_status_idx;
drop index if exists public.applications_system_kind_idx;
drop index if exists public.audit_events_action_created_at_idx;
drop index if exists public.audit_events_correlation_id_idx;
drop index if exists public.audit_events_created_at_idx;
drop index if exists public.audit_events_identity_created_at_idx;
drop index if exists public.audit_events_scope_application_created_at_idx;
drop index if exists public.audit_events_scope_certificate_created_at_idx;
drop index if exists public.audit_events_scope_dns_provider_created_at_idx;
drop index if exists public.audit_events_scope_user_created_at_idx;
drop index if exists public.audit_events_target_created_at_idx;
drop index if exists public.certhub_leases_locked_until_idx;
drop index if exists public.certificate_events_certificate_created_at_idx;
drop index if exists public.certificate_events_job_created_at_idx;
drop index if exists public.certificate_events_version_created_at_idx;
drop index if exists public.certificate_issuance_jobs_active_null_version_idx;
drop index if exists public.certificate_issuance_jobs_active_version_idx;
drop index if exists public.certificate_issuance_jobs_certificate_id_idx;
drop index if exists public.certificate_issuance_jobs_certificate_version_id_idx;
drop index if exists public.certificate_issuance_jobs_claim_idx;
drop index if exists public.certificate_versions_certificate_id_idx;
drop index if exists public.certificate_versions_certificate_version_unique;
drop index if exists public.certificate_versions_latest_valid_idx;
drop index if exists public.certificate_versions_material_etag_idx;
drop index if exists public.certificate_versions_one_issuing_per_certificate_idx;
drop index if exists public.certificates_application_id_idx;
drop index if exists public.certificates_issuer_id_idx;
drop index if exists public.certificates_sans_gin_idx;
drop index if exists public.certificates_status_idx;
drop index if exists public.dns_challenge_records_certificate_id_idx;
drop index if exists public.dns_challenge_records_cleanup_idx;
drop index if exists public.dns_challenge_records_exact_value_idx;
drop index if exists public.dns_challenge_records_job_id_idx;
drop index if exists public.dns_challenge_records_version_id_idx;
drop index if exists public.dns_provider_zone_refresh_jobs_claim_idx;
drop index if exists public.dns_provider_zone_refresh_jobs_one_active_per_provider_idx;
drop index if exists public.dns_provider_zone_refresh_jobs_provider_id_idx;
drop index if exists public.dns_provider_zones_name_length_idx;
drop index if exists public.dns_provider_zones_name_unique;
drop index if exists public.dns_provider_zones_provider_id_idx;
drop index if exists public.dns_provider_zones_provider_name_unique;
drop index if exists public.dns_providers_name_unique;
drop index if exists public.dns_providers_status_idx;
drop index if exists public.dns_providers_type_idx;
drop index if exists public.dns_providers_zone_mode_idx;
drop index if exists public.issuers_name_unique;
drop index if exists public.issuers_one_active_default_idx;
drop index if exists public.issuers_status_idx;
drop index if exists public.oidc_login_handoffs_active_idx;
drop index if exists public.oidc_login_handoffs_handoff_hash_unique;
drop index if exists public.oidc_login_handoffs_user_id_idx;
drop index if exists public.oidc_login_states_active_idx;
drop index if exists public.oidc_login_states_state_hash_unique;
drop index if exists public.password_2fa_login_setups_active_idx;
drop index if exists public.password_2fa_login_setups_hash_unique;
drop index if exists public.password_2fa_login_setups_one_active_per_user_idx;
drop index if exists public.uniq_active_certificate_identity_per_application;
drop index if exists public.user_invites_active_expires_idx;
drop index if exists public.user_invites_email_idx;
drop index if exists public.user_invites_token_hash_unique;
drop index if exists public.user_password_reset_tokens_active_idx;
drop index if exists public.user_password_reset_tokens_hash_unique;
drop index if exists public.user_password_reset_tokens_one_active_per_user_idx;
drop index if exists public.user_session_token_history_hash_unique;
drop index if exists public.user_session_token_history_one_active_per_session_idx;
drop index if exists public.user_session_token_history_session_idx;
drop index if exists public.user_session_token_history_status_expires_idx;
drop index if exists public.user_sessions_access_token_hash_unique;
drop index if exists public.user_sessions_status_expires_idx;
drop index if exists public.user_sessions_user_id_idx;
drop index if exists public.users_email_unique;
drop index if exists public.users_global_role_idx;
drop index if exists public.users_oidc_identity_unique;
drop index if exists public.users_status_idx;

alter table if exists public.acme_accounts drop constraint if exists acme_accounts_pkey;
alter table if exists public.application_domain_scopes drop constraint if exists application_domain_scopes_pkey;
alter table if exists public.application_tokens drop constraint if exists application_tokens_pkey;
alter table if exists public.application_user_grants drop constraint if exists application_user_grants_pkey;
alter table if exists public.applications drop constraint if exists applications_pkey;
alter table if exists public.audit_events drop constraint if exists audit_events_pkey;
alter table if exists public.certhub_leases drop constraint if exists certhub_leases_lease_token_unique;
alter table if exists public.certhub_leases drop constraint if exists certhub_leases_pkey;
alter table if exists public.certificate_events drop constraint if exists certificate_events_pkey;
alter table if exists public.certificate_issuance_jobs drop constraint if exists certificate_issuance_jobs_pkey;
alter table if exists public.certificate_versions drop constraint if exists certificate_versions_pkey;
alter table if exists public.certificates drop constraint if exists certificates_pkey;
alter table if exists public.dns_challenge_records drop constraint if exists dns_challenge_records_pkey;
alter table if exists public.dns_provider_zone_refresh_jobs drop constraint if exists dns_provider_zone_refresh_jobs_pkey;
alter table if exists public.dns_provider_zones drop constraint if exists dns_provider_zones_pkey;
alter table if exists public.dns_providers drop constraint if exists dns_providers_pkey;
alter table if exists public.issuers drop constraint if exists issuers_pkey;
alter table if exists public.oidc_login_handoffs drop constraint if exists oidc_login_handoffs_pkey;
alter table if exists public.oidc_login_states drop constraint if exists oidc_login_states_pkey;
alter table if exists public.password_2fa_login_setups drop constraint if exists password_2fa_login_setups_pkey;
alter table if exists public.user_invites drop constraint if exists user_invites_pkey;
alter table if exists public.user_password_reset_tokens drop constraint if exists user_password_reset_tokens_pkey;
alter table if exists public.user_session_token_history drop constraint if exists user_session_token_history_pkey;
alter table if exists public.user_sessions drop constraint if exists user_sessions_pkey;
alter table if exists public.users drop constraint if exists users_pkey;

drop table if exists public.certificate_events;
drop table if exists public.dns_challenge_records;
drop table if exists public.certificate_issuance_jobs;
drop table if exists public.certificate_versions;
drop table if exists public.certificates;
drop table if exists public.audit_events;
drop table if exists public.application_user_grants;
drop table if exists public.application_domain_scopes;
drop table if exists public.application_tokens;
drop table if exists public.oidc_login_handoffs;
drop table if exists public.oidc_login_states;
drop table if exists public.user_session_token_history;
drop table if exists public.password_2fa_login_setups;
drop table if exists public.user_password_reset_tokens;
drop table if exists public.user_invites;
drop table if exists public.user_sessions;
drop table if exists public.acme_accounts;
drop table if exists public.dns_provider_zone_refresh_jobs;
drop table if exists public.dns_provider_zones;
drop table if exists public.dns_providers;
drop table if exists public.issuers;
drop table if exists public.applications;
drop table if exists public.users;
drop table if exists public.certhub_leases;

drop function if exists public.certhub_require_active_issuer_account();
drop function if exists public.certhub_reject_system_application_token();
drop function if exists public.certhub_reject_system_application_grant();
drop function if exists public.certhub_reject_issuer_immutable_update();
drop function if exists public.certhub_reject_dns_provider_zone_update();
drop function if exists public.certhub_reject_certificate_version_regression();
drop function if exists public.certhub_reject_certificate_event_mutation();
drop function if exists public.certhub_reject_audit_event_mutation();
drop function if exists public.certhub_reject_application_domain_scope_update();
drop function if exists public.certhub_preserve_active_issuer_account();
drop function if exists public.certhub_enforce_system_application_certificate_limit();
drop function if exists public.certhub_enforce_certificate_version_overlap();
drop function if exists public.certhub_cidr_array_unique(cidr[]);
drop function if exists public.certhub_certificate_sans_valid(text[]);
