# Certhub Backend Spec

## Summary

Certhub backend is the source of truth for company TLS certificates. Applications create and retrieve certificates. Users are humans who manage Applications and may inspect or download certificate material only when explicitly granted access to the relevant Application.

The backend owns certificate issuance through ACME DNS-01. Consumers do not talk to Let's Encrypt, Cloudflare, or ArvanCloud directly. Application clients authenticate to Certhub, fetch certificate material by criteria when a ready certificate already exists, and create a Certificate only when no ready material is available.

## Goals

- Provide one company-wide API for TLS certificate creation and retrieval.
- Issue Let's Encrypt certificates using ACME DNS-01.
- Support Cloudflare and ArvanCloud DNS providers in v1.
- Reuse ready certificates only within the same Application when the normalized SAN set and issuance options match policy.
- Check Application domain scopes before issuance or reuse.
- Enforce explicit User-to-Application access before allowing human users to inspect or download Application certificates.
- Store certificate material, metadata, issuance state, ownership, access grants, and audit events.
- Support web, CLI, and Kubernetes operator clients through the same API.

## Technology Choices

- Backend server implementation language: Go.
- Database: PostgreSQL.
- Database access must use parameterized queries or typed query builders; string-concatenated SQL with user input is forbidden.
- Database schema and migrations are part of the backend ownership. Migrations must be versioned, reviewed, and safe to run repeatedly.
- PostgreSQL constraints and indexes must enforce the data model invariants that cannot safely live only in Go code, including uniqueness, foreign keys, and immutable-record patterns where practical.
- Go domain types should model enum values explicitly and validate API input before persistence.

## Architecture

The backend must follow a layered adapter/service/model structure.

Required layers:

- Adapter/view layer: HTTP handlers, server-binary commands, workers, and startup wiring. This layer translates transport or command input into service calls and translates service results into HTTP responses, command output, worker state, logs, metrics, and audit context.
- Service layer: owns business rules, validation, authorization-sensitive invariants, transactions, audit construction, encryption/decryption decisions, password hashing, token hashing, ACME orchestration, DNS provider orchestration, and certificate lifecycle behavior.
- Model/repository layer: owns domain models, persistence mapping, database queries, migrations, locking, and PostgreSQL constraint handling.

Rules:

- HTTP handlers and `certhub-server` command-line jobs must call the same service functions for the same operation.
- Server-binary commands must not write tables directly except through shared migration/repository primitives used by services.
- Business rules must not be duplicated between HTTP handlers, commands, and workers. If a rule applies to both API and command workflows, it belongs in the service layer.
- Authorization entrypoints may differ by adapter. HTTP handlers authorize a User or Application identity; direct database management commands run with internal system authority. The service layer must receive an explicit actor/context so audit events and permission checks remain intentional.
- Models and repositories must not depend on HTTP request types, CLI flag parsing, frontend concepts, or Kubernetes operator concepts.

## Non-Goals

- Certhub is not a certificate authority.
- Certhub does not issue self-signed certificates in v1.
- Certhub does not expose direct DNS provider credentials to clients.
- Certhub does not require clients to know ACME challenge details.
- Users do not create User-owned or personal certificates in v1. Authorized Users may create Application-owned Certificates through User-authenticated management APIs.

## Configuration

Certhub has two configuration layers:

- Process configuration: deployment-time settings loaded before the backend starts.
- Operational configuration: database-backed settings managed by admin APIs, such as issuers, DNS providers, DNS zones, normal Applications, Users, grants, tokens, and domain scopes.

Process configuration must be provided by a YAML config file in v1. The backend serving process is started only with `certhub-server run`. The run command accepts the config path with `certhub-server run --config <path>` or, when the flag is omitted, `CERTHUB_SERVER_CONFIG`. Operators may pass `--migrate` to apply pending database migrations before the backend starts serving. Environment variables must not override server process configuration values in v1, except for `CERTHUB_SERVER_CONFIG` selecting the config file path and explicitly configured secret-value references described below. Certhub must validate process configuration at startup and fail fast when a required value is missing or malformed. Changing process configuration requires restarting the backend process.

Operational configuration is changed through the public admin APIs and persisted in the database. It must not be configured through the server YAML config file. Initial bootstrap uses direct database management commands under the `certhub-server` binary, not an unauthenticated HTTP API.

Exception: the reserved `certhub_server` Application and its serving-certificate desired state are process-config managed. Public APIs and the web UI may read that state but must not change it. The backend process reconciles database rows for that reserved Application from process configuration.

### Server Config File

Config file requirements:

- The file format is YAML.
- The config file path must be absolute after resolution.
- The config file must be a regular file. Certhub must reject symlinks, device files, and directories.
- The config file must not be group-writable or world-writable.
- Parent directories must not be world-writable and must not be symlinks.
- Operators are responsible for keeping secrets out of the server config file and using documented `*_env` keys for secret values. Certhub must not scan the server config file to infer whether it contains secrets.
- YAML parsing must reject unknown keys, duplicate keys, type mismatches, and implicit type surprises that would change a string such as `yes`, `on`, or `0123` into another type.
- The YAML file must be self-contained for all non-secret values in v1. Certhub must not support environment-variable interpolation, include directives, remote config references, or secondary secret-file references for server process configuration.
- Secret process-config values may optionally be provided through environment variables only when the YAML file explicitly names the environment variable with a documented `*_env` key.
- Supported v1 secret environment references are `database.url_env`, `encryption.key_env`, and `outbound_http.proxies.<name>.url_env`.
- Exactly one of `database.url` or `database.url_env` must be set. Exactly one of `encryption.key` or `encryption.key_env` must be set.
- Environment variable names in `*_env` keys must match `^[A-Z_][A-Z0-9_]*$`.
- If a `*_env` key is configured, the named environment variable must exist, must be non-empty, and its value must pass the same validation as the inline secret field.
- Apart from `CERTHUB_SERVER_CONFIG` selecting the YAML file path, environment variables are not used for defaults and do not override YAML values. The YAML file remains the source of truth for whether a secret comes from an environment variable and which variable name is used.
- Secret values in the config file must never be logged, written to audit metadata, returned by APIs, exposed in health-check output, or printed in startup errors.

Configuration keys:

| Key | Required | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `database.url` | Required unless `database.url_env` is set | secret string | None | Database connection URL. Must not be logged or returned by APIs. |
| `database.url_env` | Required unless `database.url` is set | env var name | None | Name of an environment variable containing `database.url`. |
| `encryption.key` | Required unless `encryption.key_env` is set | `base64_32_bytes` | None | Root application encryption key. See `Encryption Key`. |
| `encryption.key_env` | Required unless `encryption.key` is set | env var name | None | Name of an environment variable containing `encryption.key`. |
| `http.bind_addr` | No | string | `:8080` | HTTP listen address for the backend process. |
| `http.require_https` | No | boolean | `true` | Requires effective HTTPS for the normal TCP API. Disable only for local development or isolated test environments. |
| `http.trusted_proxy_cidrs` | No | string array | Empty | CIDRs for reverse proxies whose forwarded headers may be trusted for client IP and scheme derivation. Empty means forwarded headers are ignored. |
| `server.public_hostname` | Required when self-certificate sync is enabled | `dns_name` | Empty | Exact public DNS hostname for this Certhub server. Used for Host allowlisting, URL generation, the self-certificate SAN, and future server-hostname features. |
| `tls.cert_file` | No | filesystem path | Empty | Optional fullchain PEM path for the backend process's direct TLS listener. Must be configured together with `tls.key_file`. |
| `tls.key_file` | No | filesystem path | Empty | Optional private-key PEM path for the backend process's direct TLS listener. Must be configured together with `tls.cert_file`. |
| `self_certificate.sync_enabled` | No | boolean | `false` | Enables server-managed local filesystem sync for Certhub's own serving certificate from the reserved `certhub_server` Application. |
| `self_certificate.output_dir` | Required when self-certificate sync is enabled | filesystem path | None | Local directory where the server writes Certhub's own certificate material atomically. |
| `self_certificate.issuer` | Required when self-certificate sync is enabled | `machine_name` | None | Issuer name used for Certhub's config-managed serving certificate. |
| `self_certificate.key_type` | No | enum | `ecdsa-p256` | Key type used for Certhub's config-managed serving certificate. |
| `self_certificate.sync_interval_seconds` | No | integer | `300` | Periodic self-certificate sync interval. Must be positive. |
| `log.level` | No | enum | `info` | One of `debug`, `info`, `warn`, `error`. |
| `workers.concurrency` | No | integer | `4` | Maximum concurrent issuer worker jobs. Must be positive. |
| `api.default_retry_after_seconds` | No | integer | `10` | Default retry hint for pending material/archive responses when no more specific retry time is known. Must be positive. |
| `acme.order_timeout_seconds` | No | integer | `600` | Timeout for one ACME order attempt. Must be positive. |
| `dns.propagation_timeout_seconds` | No | integer | `120` | Maximum DNS propagation wait before an issuance attempt fails. Must be positive. |
| `dns.propagation_poll_seconds` | No | integer | `5` | DNS propagation polling interval. Must be positive and lower than `dns.propagation_timeout_seconds`. |
| `dns.propagation_resolvers.<provider_type>.type` | No | enum | `system` | DNS resolver used for propagation checks for `cloudflare` or `arvancloud`. One of `system`, `dns`, `doh`, `dot`. |
| `dns.propagation_resolvers.<provider_type>.endpoint` | Required for `dns`, `doh`, `dot` | string | None | Resolver endpoint. `dns` and `dot` use `host:port`; `doh` uses an HTTPS URL. Must be empty for `system`. |
| `dns.propagation_resolvers.<provider_type>.tls_server_name` | No | DNS name | Endpoint host | Optional TLS server name for `dot`. Must be empty for other resolver types. |
| `dns.propagation_resolvers.<provider_type>.proxy` | No | machine_name or empty string | Empty | Named proxy used for `doh` and `dot` propagation checks. Empty means direct. Must be empty for `system` and `dns`. |
| `outbound_http.proxies` | No | map | Empty | Named outbound HTTP proxies. Each map key must be `machine_name`; each value must set exactly one of `url` or `url_env`. |
| `outbound_http.proxies.<name>.url` | Required unless `url_env` is set | `outbound_proxy_url` | None | Proxy URL for a named outbound proxy. Supports `http://` and `https://` schemes. |
| `outbound_http.proxies.<name>.url_env` | Required unless `url` is set | env var name | None | Name of an environment variable containing the proxy URL for a named outbound proxy. |
| `outbound_http.acme.proxy` | No | machine_name or empty string | Empty | Named proxy used for ACME/Lets Encrypt outbound requests. Empty means direct. |
| `outbound_http.dns_providers.cloudflare.proxy` | No | machine_name or empty string | Empty | Named proxy used for Cloudflare DNS API requests. Empty means direct. |
| `outbound_http.dns_providers.arvancloud.proxy` | No | machine_name or empty string | Empty | Named proxy used for ArvanCloud DNS API requests. Empty means direct. |
| `outbound_http.oidc.proxy` | No | machine_name or empty string | Empty | Named proxy used for OIDC discovery, authorization metadata, token exchange, and userinfo requests. Empty means direct. |
| `auth.password.enabled` | No | boolean | `true` | Enables `POST /v1/auth/login` with User email and password. |
| `auth.password.2fa_required` | No | boolean | `true` | Requires native Certhub 2FA for password login. Applies only to password auth, not OIDC. |
| `auth.oidc.enabled` | No | boolean | `false` | Enables OIDC browser login endpoints. |
| `auth.oidc.issuer_url` | Required when OIDC is enabled | `https_url` | None | OIDC issuer URL. |
| `auth.oidc.client_id` | Required when OIDC is enabled | string | None | OIDC public client ID. |
| `auth.oidc.redirect_url` | Required when OIDC is enabled | `https_url` | None | Callback URL registered with the OIDC provider. |
| `auth.oidc.allowed_return_urls` | No | string array | Empty | Optional allowlist for frontend return URLs after OIDC login. Empty means only `auth.oidc.redirect_url` origin is allowed. |
| `auth.user_access_token_ttl_seconds` | No | integer | `300` | Lifetime for human User access tokens. Default is 5 minutes. Must be positive. |
| `auth.user_session_ttl_seconds` | No | integer | `28800` | Absolute lifetime for human User login sessions. Default is 8 hours. Must be greater than access token TTL. |
| `application_tokens.default_ttl_seconds` | No | integer | `7776000` | Default Application token lifetime when the create request omits `expires_at`. Default is 90 days. Must be positive. |
| `application_tokens.max_ttl_seconds` | No | integer | `31536000` | Maximum Application token lifetime for non-null `expires_at` values. Default is 365 days. Must be positive and greater than or equal to the default TTL. Does not apply to explicit `expires_at=null` non-expiring tokens. |

Minimal example:

```yaml
database:
  url: "postgres://certhub:secret@postgres:5432/certhub?sslmode=require"
encryption:
  key: "base64-encoded-32-byte-key"
http:
  bind_addr: ":8080"
  require_https: true
  trusted_proxy_cidrs: []
server:
  public_hostname: "certhub.torob.dev"
tls:
  cert_file: ""
  key_file: ""
self_certificate:
  sync_enabled: false
  output_dir: ""
  issuer: ""
  key_type: "ecdsa-p256"
  sync_interval_seconds: 300
log:
  level: "info"
workers:
  concurrency: 4
api:
  default_retry_after_seconds: 10
acme:
  order_timeout_seconds: 600
dns:
  propagation_timeout_seconds: 120
  propagation_poll_seconds: 5
  propagation_resolvers:
    cloudflare:
      type: system
    arvancloud:
      type: doh
      endpoint: "https://cloudflare-dns.com/dns-query"
      proxy: "corp_proxy"
outbound_http:
  proxies:
    corp_proxy:
      url: "https://proxy.example:8443"
  acme:
    proxy: "corp_proxy"
  dns_providers:
    cloudflare:
      proxy: "corp_proxy"
    arvancloud:
      proxy: ""
  oidc:
    proxy: ""
auth:
  password:
    enabled: true
    2fa_required: true
  oidc:
    enabled: false
    issuer_url: ""
    client_id: ""
    redirect_url: ""
    allowed_return_urls: []
  user_access_token_ttl_seconds: 300
  user_session_ttl_seconds: 28800
  password_reset_ttl_seconds: 3600
application_tokens:
  default_ttl_seconds: 7776000
  max_ttl_seconds: 31536000
```

Equivalent secret-from-environment example:

```yaml
database:
  url_env: "CERTHUB_DATABASE_URL"
encryption:
  key_env: "CERTHUB_ENCRYPTION_KEY"
outbound_http:
  proxies:
    corp_proxy:
      url_env: "CERTHUB_CORP_PROXY_URL"
```

### Server Commands

#### `certhub-server run`

Summary: Start the Certhub backend HTTP server, embedded web UI, workers, and metrics endpoint.

Description and notes:

- `run` is the only `certhub-server` command that starts the long-running backend serving process.
- Operators must start the server with `certhub-server run`, not bare `certhub-server`.
- Bare `certhub-server` without a subcommand must not start listeners, workers, metrics, the web UI, or any database-mutating job. It should print command help and exit non-zero unless the user explicitly requested help with `--help` or `help`.
- `certhub-server --help`, `certhub-server help`, and `certhub-server help <command...>` must print command-specific help to stdout and exit `0` without loading config, connecting to PostgreSQL, reading secrets, starting listeners/workers, or mutating state.
- Every command group and leaf command must support `--help` and `-h`. Examples include `certhub-server run --help`, `certhub-server bootstrap --help`, and `certhub-server bootstrap create-admin --help`.
- Unknown commands should fail with exit code `2` and include a helpful error. The misspelled `boostrap` form must not be accepted as an alias for `bootstrap`.
- `run` loads and validates the YAML server config, opens PostgreSQL, starts required workers, serves backend APIs, serves embedded web UI assets, exposes health/readiness/metrics, and handles graceful shutdown.
- `run --migrate` must run required migrations before serving API traffic. Plain `run` must check migration status and fail closed before serving API traffic when migrations are pending or the database schema is incompatible with the binary.
- `run` must acquire any process-level locks needed to prevent unsafe duplicate workers when multiple server replicas are not supported by a specific worker type.
- `run` must use the same service-layer functions as workers and HTTP handlers.

Example:

```bash
certhub-server run [--migrate] [--config /etc/certhub/server.yaml]
```

#### `certhub-server generate-encryption-key`

Summary: Generate a value compatible with `encryption.key`.

Description and notes:

- This is an offline utility command. It must not start the HTTP listener, worker loops, metrics endpoint, or web UI.
- It must not require a config file, PostgreSQL connection, existing encryption key, network access, or operational database state.
- It must generate exactly 32 bytes using a cryptographically secure random source and print the strict standard-base64 encoding of those bytes to stdout.
- Output must be a single line containing only the base64 key and a trailing newline.
- The generated value must pass the `base64_32_bytes` validation used for `encryption.key`.
- The command must exit non-zero if secure randomness is unavailable or stdout write fails.
- The command must not log the generated key, write it to files, write audit events, send telemetry, or print explanatory text by default.
- The command should support `--help`, but no flag is required for normal generation.

Example:

```bash
certhub-server generate-encryption-key
```

#### Direct Database Management Commands

Summary: Run bootstrap and emergency management jobs directly against PostgreSQL.

Description and notes:

- Direct database management commands are subcommands of `certhub-server`.
- They are intended for first bootstrap, emergency recovery, and self-certificate prerequisite setup when the HTTPS API is not yet reachable.
- Every bootstrap-related backend job must be available through this server-binary command-line interface. Certhub must not expose any bootstrap public API in v1.
- They must load server process configuration from the same YAML config path rules as the server process.
- They connect directly to PostgreSQL using `database.url` or `database.url_env`.
- They must not start the HTTP listener, worker loops, metrics endpoint, or web UI.
- They must not require TLS, User login, Application token authentication, or an already-running server process.
- They must run required migrations or fail closed on migration incompatibility before mutating database state.
- They must use the same service-layer functions as HTTP handlers. Commands must not duplicate business rules, validation, authorization-sensitive invariants, audit construction, encryption, password hashing, ACME/DNS credential handling, or model persistence logic.
- Commands run with internal system authority and must write audit events with `identity_type=system`, `identity_id=null`, and command metadata that identifies the command name without including secrets.
- Commands must validate input with the same validators used by API handlers.
- Secret inputs must not be accepted as positional arguments or ordinary command-line flags because process arguments are commonly visible through process listings and shell history, except that `bootstrap create-admin --password <value>` is supported as an explicitly documented convenience path. Prefer stdin, an environment variable explicitly named by a flag, or a protected file whose safety checks match config-file secret handling.
- Command output must be machine-readable when `--json` is set and human-readable otherwise. In both modes, output must not include secrets except for one-time bootstrap TOTP provisioning material explicitly documented below.

Common flags:

```text
--config <path>     server YAML config path; overrides CERTHUB_SERVER_CONFIG
--json              print JSON output
```

Required bootstrap and management commands:

```text
certhub-server migrate [--config <path>]
certhub-server bootstrap --interactive [--config <path>]
certhub-server bootstrap create-admin [--config <path>] --email <email> --display-name <name> [--password <value>|--password-stdin|--password-env <env>|--password-file <path>] [--allow-existing-admin]
certhub-server bootstrap create-admin --interactive [--config <path>] [--allow-existing-admin]
certhub-server bootstrap create-issuer [--config <path>] --name <machine_name> --directory-url <https_url> --contact-email <email> [--default] [--renewal-window-seconds <seconds>]
certhub-server bootstrap create-dns-provider [--config <path>] --name <machine_name> --type <cloudflare|arvancloud> --zone-mode <auto|manual> [--credentials-stdin|--credentials-env <env>|--credentials-file <path>]
certhub-server bootstrap add-dns-provider-zone [--config <path>] --dns-provider <name-or-id> --zone <dns_name>
certhub-server bootstrap refresh-dns-provider-zones [--config <path>] --dns-provider <name-or-id>
```

Command-specific rules:

- `migrate` applies pending PostgreSQL migrations and exits. It is safe to run before other bootstrap commands. Other direct database commands may run migrations automatically before their own service call, but must use the same migration runner and locking.
- `bootstrap create-admin` creates a global `admin` User. It must fail if any active global admin already exists unless `--allow-existing-admin` is set for explicit emergency recovery. Successful creation must write a `bootstrap_admin_created` audit event with `identity_type=system`.
- `bootstrap create-admin` must support password auth or passwordless OIDC provisioning by verified email when OIDC is enabled. It must not accept OIDC issuer or subject from a human. It accepts at most one explicit password source from `--password`, `--password-stdin`, `--password-env`, or `--password-file`; when no explicit source is provided on a TTY human-output run, it prompts for password and confirmation. If password is provided while `auth.password.2fa_required=true`, the command must generate and enable TOTP and print the provisioning URI exactly once.
- `bootstrap create-issuer` must call the same issuer creation/update service rules as the User-authenticated issuer management API, except that the actor is system command authority.
- `bootstrap create-dns-provider` must call the same DNS provider creation service rules as the User-authenticated DNS provider management API. Provider credentials are write-only, validated against the provider-specific typed schema, encrypted before storage, and never printed.
- `bootstrap add-dns-provider-zone` is for manual-zone bootstrap. It must call the same service rules as the DNS provider zone management API.
- `bootstrap refresh-dns-provider-zones` is for auto-zone bootstrap. It may call the DNS provider API using the configured outbound proxy policy and must call the same refresh service rules as the authenticated management API.
- Direct database commands must be idempotent where the corresponding service operation is idempotent. When not idempotent, conflicts must be explicit and must not silently mutate unrelated records.

Interactive bootstrap mode:

- `certhub-server bootstrap --interactive` starts a terminal wizard for first bootstrap and emergency recovery tasks. It may guide the operator through admin creation, issuer creation, DNS provider creation, manual DNS zone insertion, auto DNS zone refresh, and self-certificate prerequisite checks.
- `certhub-server bootstrap create-admin --interactive` starts only the guided admin creation flow.
- Interactive mode must require stdin and stderr/stdout connected to a TTY. In non-TTY mode it must fail with a clear usage error instead of silently reading secrets from piped input.
- Interactive prompts must collect missing non-secret fields, validate each value with the same validators used by noninteractive commands, and show field-specific errors before asking again.
- Interactive password prompts must disable terminal echo, require password confirmation, apply the password policy before creating the User, and never write the password to stdout, logs, command history, audit metadata, or crash output.
- If the interactive admin flow configures password login while `auth.password.2fa_required=true`, Certhub must generate a TOTP secret, display the provisioning URI exactly once, optionally render a terminal QR code derived from that URI, prompt the operator for a current TOTP code, and verify the code before committing the admin User.
- If TOTP confirmation fails or the operator aborts before confirmation, Certhub must not create a password-enabled admin User with an unconfirmed TOTP secret. The command must roll back any partially prepared User/TOTP state.
- If the interactive admin flow creates a passwordless OIDC-provisioned admin, Certhub-native TOTP is not required.
- `--interactive` is incompatible with `--json`; interactive output is human-oriented and must still avoid printing secrets except for one-time TOTP provisioning material.

First self-certificate bootstrap through commands:

1. Generate `encryption.key` with `certhub-server generate-encryption-key`.
2. Write `server.yaml`, including `self_certificate.sync_enabled=true`, `server.public_hostname`, `self_certificate.output_dir`, `self_certificate.issuer`, and optional `tls.cert_file`/`tls.key_file` pointing at the future `current` files.
3. Run `certhub-server migrate`.
4. Run `certhub-server bootstrap create-admin --interactive` when bootstrapping manually, or use the noninteractive `create-admin` flags from automation.
5. Run `certhub-server bootstrap create-issuer`.
6. Run `certhub-server bootstrap create-dns-provider`.
7. Run either `certhub-server bootstrap add-dns-provider-zone` for manual provider zones or `certhub-server bootstrap refresh-dns-provider-zones` for auto provider zones.
8. Start `certhub-server run --config <path>`. The server reconciles `certhub_server`, issues its Certificate, writes local TLS material, and enables future TCP TLS handshakes when valid material is available.

Process configuration requirements:

- Secret values must never be logged, written to audit metadata, returned by APIs, or exposed in health-check output.
- Non-secret configuration may be included in diagnostics, but diagnostics must clearly mark defaults versus explicitly configured values.
- Numeric values must reject zero, negative numbers, non-integers, and values outside implementation-defined safe maximums.
- `server.public_hostname` must be an exact DNS hostname. It must not include a scheme, port, path, query, fragment, wildcard, IP literal, or public-suffix-only value. Certhub normalizes it to lowercase and trims a trailing root dot.
- If `server.public_hostname` is non-empty, normal TCP API and web requests must reject effective `Host` values that do not match it. Host validation parses the request host as `hostname[:port]`, compares only the normalized DNS hostname portion, and rejects malformed hosts or IP literals. Host validation must run before route handling, authentication, request body parsing, and SPA fallback. Only trusted proxy headers may influence the effective host.
- `tls.cert_file` and `tls.key_file` must either both be empty or both be configured. If configured, Certhub serves direct TLS from these local files. If omitted, deployments must use a trusted TLS-terminating proxy or explicit local-development HTTP mode.
- TLS certificate files may point at `self_certificate.output_dir/current/fullchain.pem` and `self_certificate.output_dir/current/privkey.pem`. Normally, if direct TLS file paths are configured but files are missing or invalid, the direct TLS listener cannot serve traffic. Exception: when `self_certificate.sync_enabled=true` and `tls.cert_file`/`tls.key_file` point at those self-certificate `current` paths, missing files at startup are allowed. The backend must still start internal workers, and the direct TLS listener may start in a pending-certificate state until valid material is written.
- When `self_certificate.sync_enabled=true`, `server.public_hostname`, `self_certificate.output_dir`, and `self_certificate.issuer` are required. The server must create needed private directories safely, reject unsafe symlinks and world/group-writable parent directories, and write private-key files with mode `0600`.
- `self_certificate.issuer` must use `machine_name` format and must reference an active Lets Encrypt issuer in operational configuration before self-certificate issuance can succeed.
- `self_certificate.key_type` must be one of the supported key types.
- `http.trusted_proxy_cidrs` entries must be valid CIDRs. If empty, Certhub must ignore `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Proto`, and related headers.
- `outbound_http.proxies` keys must be unique `machine_name` values. A proxy entry must set exactly one of `url` or `url_env`.
- `outbound_http.proxies.<name>.url` and env-provided proxy URLs must use `outbound_proxy_url` format. Both `http://` and `https://` proxy schemes are valid.
- `outbound_http.*.proxy` references must be empty or match a configured proxy name.
- Empty proxy references mean direct outbound connection for that upstream class.
- Certhub must not read standard proxy environment variables such as `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY` implicitly. Outbound proxy use is controlled only by the server YAML config.
- Issuers, ACME accounts, DNS providers, DNS provider zones, normal Applications, and normal Application domain scopes are not process configuration. They are database-backed operational configuration.

### Encryption Key

Certhub must be configured with an application encryption key used to encrypt sensitive database values.

Requirements:

- Required before the backend starts.
- Must be provided by deployment secret management and must never be stored in the database.
- Must use format `base64_32_bytes`: strict base64 string that decodes to exactly 32 bytes.
- Must encrypt sensitive database values before persistence and decrypt them only in memory when needed.
- Must not be logged, returned by any API, written to audit metadata, or exposed in health-check output.
- Must be used to derive a separate AEAD encryption key with `HKDF-SHA256(encryption.key, info="certhub-db-aead-v1")`.
- Must be used to derive a separate material ETag HMAC key with `HKDF-SHA256(encryption.key, info="certhub-material-etag-v1")`.
- Must be used to derive a separate token hash HMAC key with `HKDF-SHA256(encryption.key, info="certhub-token-hash-v1")`.
- Must be used to derive a separate OIDC state HMAC key with `HKDF-SHA256(encryption.key, info="certhub-oidc-state-v1")`.
- V1 supports one active encryption key with fixed encryption envelope `key_id="default"`.
- Online key rotation and keyring support are out of scope for v1. Future key rotation must use a new envelope/keyring design and migration plan.

Sensitive database values include:

- Certificate private keys.
- ACME account private keys.
- DNS provider credentials.
- TOTP secrets and pending TOTP secrets for password 2FA.
- OIDC PKCE code verifiers.

Application token values and User access token values are not encrypted; only token hashes are stored.

### Database Encryption Envelope

Sensitive database values must use authenticated encryption, not unauthenticated encryption or ad hoc encoding.

Required v1 encryption envelope:

- Algorithm: `AES-256-GCM`.
- Key: `HKDF-SHA256(encryption.key, info="certhub-db-aead-v1")`.
- Nonce: 96 random bits generated independently for every encrypted value. Nonces must never be reused with the same derived key.
- AAD: stable context string containing at least table name, column name, row ID, and envelope version. Row IDs must be generated before encrypting values for new rows.
- Stored envelope fields: `version`, `alg`, `key_id`, `nonce`, `ciphertext`, and `aad_context`.
- `key_id` must be `default` in v1 and identifies the single configured encryption key without storing the plaintext key.
- Decryption must fail closed when authentication fails, the algorithm is unsupported, the key ID is unknown, or AAD does not match the expected row context.
- Future encryption algorithms or key rotations must use a new envelope version/keyring design and a migration plan.

### Transport Security and Request Context

The normal TCP API carries bearer tokens, Application tokens, certificate private keys, DNS credentials, and administration traffic. Certhub must protect those values in transit.

Transport rules:

- When `http.require_https=true`, every normal TCP API endpoint except `/healthz`, `/readyz`, and `/metrics` must require effective HTTPS.
- Effective HTTPS is true when the request is received over a direct TLS connection, or when the socket peer is a configured trusted proxy and a trusted forwarded-proto header says `https`.
- Requests for secret-bearing endpoints over effective plaintext HTTP must fail before authentication or request-body processing.
- Deployments that terminate TLS outside Certhub must bind Certhub only to a trusted internal listener and configure `http.trusted_proxy_cidrs` for the TLS-terminating proxies.
- `http.require_https=false` is allowed only for local development and isolated tests. Production deployments must not disable it.

Source-IP rules:

- By default, `source_ip` is the TCP socket peer IP.
- Certhub must parse `Forwarded`, `X-Forwarded-For`, and `X-Forwarded-Proto` only when the immediate socket peer is inside `http.trusted_proxy_cidrs`.
- When parsing forwarded client IPs, Certhub must walk the chain from the socket peer toward the client and select the nearest untrusted IP as the effective client IP.
- Malformed forwarded headers must be ignored for client IP and scheme derivation and should be logged as sanitized security events.
- Rate limiting, audit events, and request logs must use the derived effective `source_ip`.
- Client-supplied forwarded headers from untrusted peers must not affect rate limits, audit metadata, logs, or HTTPS enforcement.
- Application trusted source CIDR checks must use the same derived effective `source_ip`.
- If an Application has trusted source CIDRs configured and Certhub cannot derive a valid effective client IP, Application-token authentication must fail closed.

### Outbound HTTP Proxying

Certhub may route server-initiated outbound HTTP requests through named proxies configured in server YAML.

Scope:

- ACME/Lets Encrypt requests use `outbound_http.acme.proxy`.
- Cloudflare DNS API requests use `outbound_http.dns_providers.cloudflare.proxy`.
- ArvanCloud DNS API requests use `outbound_http.dns_providers.arvancloud.proxy`.
- DNS propagation checks may use `dns.propagation_resolvers.<provider_type>.proxy` when the resolver type is `doh` or `dot`.
- OIDC discovery, metadata, token exchange, and userinfo requests use `outbound_http.oidc.proxy`.
- Database connections, inbound HTTP serving, local filesystem reads/writes, and CLI/operator client traffic do not use these outbound HTTP proxy settings.
- Direct database management commands use these outbound HTTP proxy settings only when they call configured upstreams, such as DNS provider zone refresh; their direct PostgreSQL connection never uses an HTTP proxy.

Rules:

- Proxy selection is process configuration, not database-backed operational configuration. DNS provider rows select provider credentials and zones; server YAML selects egress routing.
- Proxy URLs may use either `http://` or `https://`.
- An `http://` proxy means Certhub connects to the proxy over plaintext HTTP. For HTTPS upstream URLs, Certhub must use HTTP CONNECT so the upstream TLS session remains end-to-end between Certhub and the upstream service.
- An `https://` proxy means Certhub connects to the proxy over TLS and validates the proxy TLS certificate, then uses CONNECT for HTTPS upstream URLs.
- Certhub must validate upstream TLS certificates normally after CONNECT. Proxy use must not disable certificate verification, skip hostname verification, or trust proxy-presented upstream certificates.
- ACME, DNS provider, and OIDC upstream URLs must remain HTTPS unless a future explicit internal-provider exception is documented. Proxy configuration does not make plaintext upstreams acceptable.
- Proxy URLs containing credentials are secrets. They should be provided with `url_env`; if provided inline, they must be redacted everywhere secrets are redacted.
- Logs, metrics, audit metadata, readiness details, and public errors may include the selected proxy name and upstream class, but must not include proxy credentials or full proxy URLs.
- Proxy connection, authentication, DNS, TLS, and CONNECT failures must surface as sanitized upstream dependency errors and must not leak proxy credentials or upstream request bodies.
- Different upstream classes may intentionally use different proxies or direct connections. For example, ACME and Cloudflare can use `corp_proxy` while ArvanCloud uses direct egress by setting `outbound_http.dns_providers.arvancloud.proxy` to an empty string.

DNS propagation resolver examples:

```yaml
dns:
  propagation_resolvers:
    cloudflare:
      type: system
    arvancloud:
      type: dns
      endpoint: "1.1.1.1:53"
```

```yaml
dns:
  propagation_resolvers:
    cloudflare:
      type: doh
      endpoint: "https://cloudflare-dns.com/dns-query"
      proxy: "corp_proxy"
```

```yaml
dns:
  propagation_resolvers:
    cloudflare:
      type: dot
      endpoint: "1.1.1.1:853"
      tls_server_name: "cloudflare-dns.com"
      proxy: "corp_proxy"
```

### Embedded Web UI Serving

The Certhub server binary serves the production web UI static assets in v1. This removes the need for Nginx or another separate static file server in the default deployment.

Serving rules:

- Release builds must embed the built frontend assets into the Go server binary using Go `embed`.
- The embedded asset set must contain only production frontend build output. It must not include frontend source files, source maps by default, tests, fixtures, local paths, package-manager caches, or development-only assets.
- The same HTTP listener serves both backend APIs and the web UI.
- `/v1/...`, `/healthz`, `/readyz`, and `/metrics` are backend routes and must never fall back to `index.html`.
- Unknown backend route prefixes must return backend-style errors, not the frontend application shell.
- Frontend routes outside backend-reserved prefixes may use SPA fallback to `index.html`, so paths such as `/applications/<id>` can be handled by the CSR router.
- Static file serving must use the embedded filesystem or another fixed build artifact. It must not serve arbitrary filesystem paths from operator-controlled configuration in production.
- Directory listing is forbidden.

Static response cache rules:

- `index.html` must use `Cache-Control: no-store` or a short revalidation policy so clients do not pin old asset references.
- Hashed JavaScript, CSS, font, icon, and image assets may use long-lived immutable cache headers such as `Cache-Control: public, max-age=31536000, immutable`.
- Non-hashed static assets must use `Cache-Control: no-store` or a short revalidation policy.
- The same-origin runtime frontend config script must use `Cache-Control: no-store` and may expose only non-secret startup UI capability booleans such as whether OIDC login is enabled.
- Backend API responses, auth responses, certificate material responses, and archive responses must never inherit static asset cache headers.

Static response security headers:

- Web UI responses must set `X-Content-Type-Options: nosniff`.
- Web UI responses must set `Referrer-Policy: no-referrer` or `strict-origin-when-cross-origin`.
- Web UI responses must deny framing with `Content-Security-Policy: frame-ancestors 'none'` unless a future explicit embedding requirement changes this.
- Web UI responses must use a restrictive `Content-Security-Policy` that allows scripts, styles, images, fonts, and connections only from the same origin by default. OIDC navigation/redirects are auth flows and must not require loading scripts or visual assets from the identity provider.
- If `http.require_https=true`, web UI routes follow the same effective HTTPS requirement as secret-bearing API routes.

Security considerations:

- Same-binary serving intentionally makes the web UI and API same-origin. This simplifies deployment, but any XSS in the web UI can issue API requests as the logged-in User while their access token is present in browser `sessionStorage`.
- Backend authorization, audit logging, and private-key access checks must remain authoritative. The web UI is not a security boundary and must not be trusted to hide or block actions by itself.
- Production CSP must avoid `unsafe-inline`, `unsafe-eval`, remote script sources, remote style sources, remote font sources, and remote image sources unless a future reviewed exception is documented. If inline bootstrapping becomes unavoidable, use nonces or hashes rather than broad unsafe directives.
- V1 browser authentication uses bearer tokens supplied by JavaScript, not ambient cookie authentication. This reduces CSRF exposure, but if cookie-based auth is introduced later, state-changing endpoints must add explicit CSRF defenses.
- Tokens, private keys, DNS credentials, OIDC authorization codes, OIDC state, PKCE code verifiers, and TOTP secrets must never appear in frontend URLs, static files, source maps, logs, telemetry, or error pages.
- Serving the UI from the API listener means every network location that can reach the API can also reach the login page and static UI. Network-level exposure must be controlled by firewall, ingress, VPN, or load balancer policy when the admin surface should be private.
- Static routing must fail closed. Route confusion between API paths and SPA fallback is a security issue because it can hide broken API calls behind successful HTML responses.
- Cache mistakes are security issues. Private API responses must not be cached, and `index.html` must not be cached long enough to pin stale JavaScript with old security behavior.
- Static file path traversal and directory listing are security issues. Production serving must use embedded assets or a fixed build artifact, never a configurable arbitrary filesystem root.
- Production source maps are security-sensitive. They must be excluded by default because they can expose implementation details and make XSS discovery easier.

### Password Hashing

User passwords must be hashed with Argon2id.

Recommended v1 parameters:

| Parameter | Value |
| --- | --- |
| Algorithm | `argon2id` |
| Version | `v=19` |
| Memory | `65536` KiB minimum |
| Iterations | `3` |
| Parallelism | `1` or `2` |
| Salt | At least 16 random bytes per password |
| Hash length | 32 bytes |
| Stored format | PHC string |

Example stored format:

```text
$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
```

Rules:

- Plaintext passwords must never be stored.
- Each password must use a unique random salt.
- Algorithm and parameters must be stored in the PHC string.
- Verification must use a standard Argon2id implementation and constant-time comparison.
- Certhub must rehash on successful login when the stored parameters are weaker than current policy.
- Password hashing is only for human passwords. It must not be used for high-entropy Application tokens, User access tokens.

### Password Policy and Login Rate Limiting

Password policy:

- Minimum length: 12 characters.
- Maximum length: 1024 characters.
- Reject NUL and control characters.
- Reject passwords equal to the User email.
- Do not silently trim passwords; spaces are allowed and are significant.
- Password policy applies to `certhub-server bootstrap create-admin`, admin User creation, and password replacement.

Password login rate limiting:

- Applies to password verification and TOTP verification.
- Must key limits by normalized email plus source IP and by source IP alone.
- Must return `429 rate_limited` when limits are exceeded.
- Must not reveal whether the normalized email belongs to a User.
- Successful login clears failure counters for the normalized email plus source IP key.
- Recommended v1 defaults: 5 failed attempts per 5 minutes for one normalized email plus source IP, and 50 failed attempts per 5 minutes per source IP.

### Token Hashing

Application tokens and User access tokens are high-entropy random secrets. Certhub must hash them with keyed HMAC-SHA-256, not Argon2id, bcrypt, or another password hashing algorithm.

Hash formula:

```text
token_hash = base64url_no_padding(
  HMAC-SHA256(token_hash_key, full_token_value)
)
```

Where:

- `token_hash_key = HKDF-SHA256(encryption.key, info="certhub-token-hash-v1")`.
- `full_token_value` is the exact token string, including prefix, such as `cth_uat_v1_<secret>`.

Rules:

- Store only `token_hash`, never raw token values.
- Use the same token hash algorithm for `application_tokens.token_hash`, `user_sessions.access_token_hash`, `user_sessions.access_token_hash`, and `user_session_token_history.access_token_hash`.
- Compare token hashes using constant-time comparison.
- Token hash output length is the base64url-no-padding encoding of 32 bytes.
- A future token hash algorithm must use a versioned derivation `info` string and a migration plan.

## Core Concepts

### User

A User is a real human interacting with Certhub through the web application or User-authenticated API sessions.

Users cannot create personal certificates. If a User needs a certificate, they must create or use an Application. Authorized Users may create Application-owned Certificates through the web-console endpoint for that Application; Application clients use Application-token runtime endpoints.

By default, a User has no access to any Application. Access must be granted explicitly per Application. A User with global role `admin` has full access to every Application and all administrative APIs.

Creating an Application requires global role `admin`.

Users may use their current User access token to inspect or download certificates only for Applications they are allowed to access.

### Human Authentication and User Sessions

Users can authenticate through:

- Username/password login using `POST /v1/auth/login` when password auth is enabled.
- OIDC browser login using the configured OIDC provider when OIDC is enabled.
- Short-lived User access tokens returned by login or refresh.

Password auth requirements:

- Passwords must never be stored in plaintext.
- `users.password_hash` stores an Argon2id PHC string as defined in `Password Hashing`.
- Login must fail for disabled Users, missing password hashes, and invalid credentials.
- Certhub supports native 2FA only for password authentication.
- `auth.password.2fa_required` defaults to `true`; password login requires a valid second factor after the password is verified unless this setting is explicitly disabled.
- Supported v1 password 2FA method is TOTP.
- OIDC login does not require Certhub-native 2FA and must not require MFA claims such as `amr` or `acr`.
- Failed login responses must not reveal whether the email exists.

OIDC auth requirements:

- Certhub v1 supports only OIDC Authorization Code Flow with PKCE.
- The OIDC client must be configured as a public client that does not require a client secret.
- Certhub must not support OIDC implicit flow, hybrid flow, resource-owner password flow, device flow, or client-secret based token exchange in v1.
- PKCE must use `code_challenge_method=S256`; `plain` is not allowed.
- Certhub creates a pending OIDC login with cryptographically random `state`, `nonce`, and `code_verifier`. `state` and `code_verifier` must use 32 random bytes encoded as base64url without padding; `nonce` must have at least 128 bits of entropy.
- Certhub stores only `state_hash`, not raw `state`. `state_hash` is `base64url_no_padding(HMAC-SHA256(oidc_state_hash_key, raw_state))`, where `oidc_state_hash_key` is derived as defined in `Encryption Key`.
- Only `state`, `nonce`, and the derived `code_challenge` are sent to the OIDC provider.
- The authorization request must use `response_type=code`, `code_challenge=<base64url(SHA256(code_verifier))>`, and `code_challenge_method=S256`.
- The token request must include the matching `code_verifier` and exactly the configured `auth.oidc.redirect_url`; it must never use the frontend return URL as the provider callback URI.
- Certhub must validate issuer, audience, signature, expiry, nonce, and state before accepting an OIDC callback.
- OIDC state comparison must use constant-time comparison of the stored HMAC value.
- The provider-facing callback is `GET /v1/auth/oidc/callback?code=...&state=...`. It must not return Certhub User access tokens directly to the browser.
- After successful provider callback validation, Certhub creates a short-lived, single-use login handoff ID, stores only its HMAC hash, and redirects the browser to the validated frontend return URL with the handoff ID.
- The frontend exchanges the handoff ID through `POST /v1/auth/oidc/handoff` to receive Certhub User access tokens. Tokens must never appear in provider callback URLs, frontend URLs, logs, browser history, or referrers.
- OIDC login maps to an existing active User by `(oidc_issuer, oidc_subject)` when present. If no OIDC link exists, Certhub may link by email only when the provider asserts `email_verified=true` or equivalent provider-specific verified-email evidence, exactly one active User has the same normalized email, and both OIDC link fields are null. If the verification claim is missing or false, email-linking must be rejected. OIDC issuer and subject are internal provider-derived identifiers; they must not be set, replaced, or cleared by admins, bootstrap commands, direct public API fields, or the web UI.
- If no active provisioned User matches the OIDC identity, login fails with `user_not_provisioned`.

User login session requirements:

- Users must not have personal access tokens or API tokens in v1.
- Successful password or OIDC login creates a User login session and returns one User access token plus `access_expires_at` and fixed `session_expires_at`.
- User access tokens are opaque random bearer secrets used for normal User-authenticated API calls and pre-expiry rotation. They are short-lived; default lifetime is `auth.user_access_token_ttl_seconds=300`.
- `session_expires_at` is fixed at login from `auth.user_session_ttl_seconds=28800` and does not slide on refresh.
- User access tokens must not be JWTs or self-contained signed tokens in v1.
- User access tokens must be backend-generated random values with at least 128 bits of entropy; 256 bits is recommended.
- Raw User access tokens are returned only by login, OIDC handoff, forced 2FA setup completion, and refresh. The database stores only token hashes.
- Refresh must rotate the access token only before `access_expires_at`; expired access tokens cannot be refreshed and require login.
- Reuse of an already-rotated access token must revoke the whole login session and return an authentication failure.
- Logout revokes the current login session and invalidates its current access token.
- Disabled Users, revoked sessions, expired sessions, and expired access tokens cannot authenticate or refresh.

### Token Structure

Certhub tokens must have an explicit public class prefix followed by an opaque random secret. The prefix identifies the token class. The secret carries no encoded claims and must not be parsed.

Token formats:

| Token class | Format | Used in |
| --- | --- | --- |
| Application token | `cth_app_v1_<secret>` | `Authorization: Bearer` for Application-authenticated APIs. |
| User access token | `cth_uat_v1_<secret>` | `Authorization: Bearer` for User-authenticated APIs and `POST /v1/auth/refresh` body. |

`<secret>` is `base64url_no_padding(32 random bytes)` in v1, which is exactly 43 characters matching `^[A-Za-z0-9_-]{43}$`.

Rules:

- Token prefixes are not secret.
- Token secrets are opaque random values. They are not JWTs, are not encrypted payloads, and do not contain claims.
- Certhub must hash the full token value, including prefix and secret, before lookup.
- Certhub must select the lookup path by exact prefix before any database lookup.
- `cth_app_v1_` tokens are looked up only in `application_tokens.token_hash`.
- `cth_uat_v1_` tokens are looked up only in `user_sessions.access_token_hash`.
- Missing bearer credentials, malformed tokens, unknown prefixes, unknown token hashes, expired tokens, and revoked tokens must fail with `401 invalid_token`.
- A valid User access token on an Application-token endpoint must fail with `403 application_token_required`.
- A valid Application token on a User-authenticated endpoint must fail with `403 user_token_required`.
- Unknown prefixes, malformed tokens, and tokens with the wrong prefix for the endpoint must fail authentication without trying other token stores.
- Future token formats must use a new versioned prefix.
- Application tokens may be expiring or non-expiring.
- If `expires_at` is omitted when a token is created, Certhub must set it to now plus `application_tokens.default_ttl_seconds`.
- If `expires_at` is explicitly `null`, Certhub creates a non-expiring Application token.
- Non-null Application token expiration must not exceed `application_tokens.max_ttl_seconds`.

### Server Self-Certificate Sync

Certhub may manage the certificate used by its own HTTPS listener. The desired state for that reserved certificate comes only from process configuration; public APIs and the web UI must not mutate it.

- The Application name `certhub_server` is reserved for Certhub's own serving certificate.
- Certhub creates or protects this Application as a system Application with `system_kind=certhub_server`.
- The reserved Application's Certificate and CertificateVersions are normal rows in `certificates` and `certificate_versions`.
- Issuance, renewal, DNS-01, material storage, encryption, ETags, audit metadata, and CertificateVersion overlap constraints are the same as for all other Certificates.
- `server.public_hostname`, `self_certificate.issuer`, and `self_certificate.key_type` are the single source of truth for the reserved Application's desired domain scope and Certificate identity.
- `server.public_hostname` is intentionally generic. The same hostname may be used for Host allowlisting, URL generation, the self-certificate SAN, and future server-hostname features.
- In v1, the `certhub_server` Application may have at most one non-deleted Certificate. This avoids ambiguous server serving material.

Config reconciliation:

- When `self_certificate.sync_enabled=true`, the backend process periodically reconciles the reserved database state from process configuration.
- The reconcile loop must ensure the `certhub_server` Application exists, is `active`, has `system_kind=certhub_server`, and has server-owned display metadata.
- The reconcile loop must replace the reserved Application's domain scopes so it has exactly one scope matching normalized `server.public_hostname`. The scope row for this Application is a server-managed projection row; operators change it by changing process configuration.
- The reconcile loop must ensure exactly one non-deleted Certificate exists for the identity `(certhub_server application_id, normalized single-SAN set containing server.public_hostname, self_certificate.key_type, self_certificate.issuer)`.
- If the configured hostname, issuer, or key type changes, the reconcile loop must mark the previous nonmatching reserved Certificate deleted locally and create a new Certificate for the new desired identity. This delete is a local Certhub state transition and must not revoke the CA certificate unless a separate internal policy explicitly requests revocation.
- The reconcile loop must preserve the last locally published TLS files until the new desired Certificate has a valid CertificateVersion. A config change must not replace valid serving files with missing or pending material.
- The reconcile loop must enqueue initial issuance or renewal using the same internal issuance services as normal Certificates.
- If the issuer or DNS/provider operational configuration required to issue the desired certificate is missing, inactive, or unauthorized, reconcile must leave existing local material unchanged and report the condition through sanitized logs, metrics, readiness details, and audit events where applicable.
- Reconcile-created changes must write normal non-secret audit events with `identity_type=system` and enough metadata to identify the changed Application, domain scope, Certificate, and configured public hostname.

Server-managed local sync:

- When `self_certificate.sync_enabled=true`, the backend process periodically selects the latest valid CertificateVersion for the current desired reserved Certificate and writes it to `self_certificate.output_dir`.
- The server must use the same local material layout and atomic update semantics as the CLI: immutable release directories, safe staging, `current` symlink switch, `cert.pem`, `chain.pem`, `fullchain.pem`, `privkey.pem`, and `.certhub-material.json`.
- The server must not call public `/v1/sync/...` endpoints or require an Application token for its own certificate. It reads through internal database/material services after normal startup dependencies are available.
- If no valid CertificateVersion exists yet for the desired reserved Certificate, self-sync records a sanitized warning/metric and preserves the last local material unchanged.
- Self-sync must never delete or overwrite a previously synced valid local certificate merely because the database is temporarily unavailable, decryption fails, issuance is pending, issuance fails, or the Certificate is revoked/deleted. It must stop publishing new material and surface the condition through logs, metrics, readiness details, and audit events where applicable.
- If the reserved Certificate is revoked or deleted, the server must stop publishing new material. It may keep the last local files on disk for operator recovery, but must report the state clearly; operators decide when to remove files or disable direct TLS.
- Each material-changing publish writes a `server_self_certificate_synced` audit event with `identity_type=system`, `scope_application_id`, `scope_certificate_id`, CertificateVersion ID, material ETag, and non-secret file target metadata. No-op syncs where the local `current` files already match the desired material must not emit this audit event.
- Failed publish attempts write sanitized logs and metrics. Audit events for repeated failures should be rate-limited or state-change based to avoid audit spam.

Serving behavior:

- The backend HTTPS listener reads its serving certificate from `tls.cert_file` and `tls.key_file`, not directly from PostgreSQL.
- If the direct TLS listener is in pending-certificate state for a self-managed certificate, TLS handshakes may fail until valid material is loaded. This pending state must not prevent internal reconcile workers, health checks, or readiness diagnostics from running.
- When `self_certificate.sync_enabled=true` and `tls.cert_file`/`tls.key_file` point at the self-certificate `current` files, the backend must automatically reload updated TLS material without operator assistance. It must not require a process restart, signal, API call, CLI command, or manual file operation after self-sync publishes a new release.
- Automatic reload may be implemented with a filesystem watcher, periodic file identity/metadata check, or direct notification from the self-sync publisher. The implementation must detect the atomic `current` switch and load the new `fullchain.pem`/`privkey.pem` pair.
- Reload must validate that the new certificate and private key parse successfully, match each other, are currently time-valid, include `server.public_hostname`, and are usable by the TLS stack before switching.
- If reload validation succeeds, future TLS handshakes must use the new certificate. Existing established TLS connections may continue using the certificate negotiated when the connection was created.
- If reload validation fails because files are missing, unreadable, malformed, mismatched, expired, not yet valid, missing the configured hostname, or otherwise unusable, the server must keep the last successfully loaded certificate for future handshakes and report the reload failure through sanitized logs, metrics, and readiness details.
- The active TLS configuration must either keep the previous valid certificate or switch atomically to a newly loaded valid certificate; it must never enter a state with no certificate because a reload attempt failed.
- Database unavailability must not prevent the process from starting far enough to serve with existing local TLS files when available and expose liveness/readiness. Normal API readiness still fails until PostgreSQL and required services recover.
- First-time bootstrap can be completed through direct database management commands before TCP TLS is available. Operators create the first admin and configure issuer/DNS operational state through `certhub-server bootstrap ...` commands, then self-certificate reconcile can issue and publish the config-managed `certhub_server` Certificate after the server starts.

Reserved Application management rules:

- Users cannot create a normal Application named `certhub_server`.
- Users and public APIs cannot rename, disable, patch, or delete the `certhub_server` Application.
- Users and public APIs cannot create, delete, or update domain scopes for `certhub_server`.
- Users and public APIs cannot create Certificates for `certhub_server` or run lifecycle mutations on its Certificate, including manual renewal, key rotation, revocation, or local delete.
- Application tokens cannot be created for `certhub_server` in v1 because server self-sync uses internal services, not Application-token authentication.
- User grants cannot be assigned to `certhub_server` in v1. Only global `admin` Users can view it.
- Public write attempts against `certhub_server` or its Certificate must return `409 Conflict` with `error.code=system_managed_resource`.

### Application

An Application is a workload or system that creates and retrieves certificates. It represents an app, CI job, Kubernetes operator, deployment automation, or other machine consumer.

Each Application has tokens and domain scopes. Application tokens do not have roles or permissions. The main Application-side authorization check for certificate issuance or reuse is whether every requested domain is covered by that Application's domain scopes.

Applications may also define trusted source IP/CIDR ranges. This is not a standalone authentication method. A valid Application token is always required first; trusted source CIDRs are an optional additional restriction on where that token may be used from.

The reserved `certhub_server` Application is a system Application for Certhub's own serving certificate. It follows the special management and self-sync rules in `Server Self-Certificate Sync`.

### Application Token and Source-IP Authentication

Application authentication has two ordered checks:

1. Validate the presented Application token by prefix, hash lookup, token status, token expiration, and Application status.
2. If the authenticated Application has non-empty `trusted_source_cidrs`, require the derived effective `source_ip` to be inside at least one configured CIDR.

Rules:

- IP/CIDR matching must never replace token authentication.
- Application requests without an Application token must fail even when the request source IP is trusted.
- Application requests with a valid token but a source IP outside `trusted_source_cidrs` must fail with `403 application_source_ip_denied`.
- Application source-IP restrictions apply to all Application-token endpoints, including `/v1/auth/me` when called with an Application token and every `/v1/sync/...` endpoint.
- User-authenticated management APIs are not restricted by an Application's `trusted_source_cidrs`; they are controlled by User roles and Application grants.
- `trusted_source_cidrs` must be evaluated using the trusted-proxy source-IP rules in `Transport Security and Request Context`.
- Exact trusted IP inputs may be accepted by the API and normalized to single-host CIDRs, such as `203.0.113.10/32` or `2001:db8::10/128`.
- Empty `trusted_source_cidrs` means no source-IP restriction beyond normal transport, token, and rate-limit checks.

### Application Access

Application access grants connect Users to Applications.

Supported v1 User-to-Application grant roles:

- `viewer`: read Application metadata and certificate metadata.
- `certificate_reader`: includes `viewer` and can download certificate material, including private keys.
- `manager`: includes `certificate_reader` and can manage Application tokens, domain scopes, certificate lifecycle actions, and User grants for that Application.

The global `admin` role bypasses per-Application grants.

### Domain Scope

A domain scope defines which names an Application may request.

Domain scope input has a single value:

- Values without `*` are exact scopes, such as `torob.io`.
- Values with `*` are wildcard scopes, such as `*.torob.dev` or `*.api.torob.dev`.

Wildcard scopes follow the public CA wildcard shape. The `*` must be the full left-most label and it matches exactly one DNS label. For example, `*.torob.dev` authorizes `api.torob.dev` and the valid wildcard SAN `*.torob.dev`, but it does not authorize `a.b.torob.dev`.

For deeper names, grant a wildcard at that level, such as `*.b.torob.dev`, or grant exact names such as `a.b.torob.dev`. Certhub must reject invalid wildcard scopes and certificate identifiers such as `*.*.torob.dev`, `a.*.torob.dev`, and `api.*.torob.dev`.

Authorization edge cases:

| Scope | Authorizes | Does not authorize |
| --- | --- | --- |
| `torob.dev` | `torob.dev` | `api.torob.dev`, `*.torob.dev` |
| `api.torob.dev` | `api.torob.dev` | `torob.dev`, `*.torob.dev`, `a.api.torob.dev` |
| `*.torob.dev` | `api.torob.dev`, `*.torob.dev` | `torob.dev`, `a.b.torob.dev`, `*.b.torob.dev` |
| `*.b.torob.dev` | `a.b.torob.dev`, `*.b.torob.dev` | `b.torob.dev`, `x.a.b.torob.dev`, `*.torob.dev` |

Rules:

- Exact scopes authorize only the exact same DNS name and never authorize wildcard SANs.
- Wildcard scopes authorize exactly one concrete DNS label at the wildcard position and the same wildcard SAN value.
- Wildcard scopes do not authorize the apex name below the wildcard.
- A single Certificate request may include both an exact SAN and the corresponding wildcard SAN, such as `torob.dev` and `*.torob.dev`. Each SAN is authorized independently, so the exact SAN still requires an exact scope and the wildcard SAN still requires a wildcard scope.
- Every requested SAN must be covered by at least one active scope on the authenticated Application. If one SAN is uncovered, the whole request fails with `domain_not_authorized`.
- If multiple scopes match a SAN, any one active scope is sufficient.
- Scope values whose non-wildcard suffix is a public suffix must be rejected, such as `com`, `*.com`, `co.uk`, and `*.co.uk`.
- Deleting a domain scope affects future Application-token create, reuse, criteria-based material retrieval, renewal, and key rotation checks for names no longer covered by remaining scopes. It does not revoke already issued CA certificates by itself.

### Certificate

A Certificate is the stable logical certificate identity. It does not represent only one issuance event.

A CertificateVersion stores issued TLS material:

- Leaf certificate PEM.
- Issuer chain PEM.
- Fullchain PEM.
- Private key PEM.
- Validity window.
- Serial number.
- Key fingerprint.
- Issue reason.

A Certificate stores stable metadata:

- Normalized SANs.
- Key type.
- Issuer.
- Application ID.
- Whether new lifecycle issuance is enabled.
- Status and lifecycle metadata.

Certificate enablement is independent from operational `status`. A disabled Certificate keeps all CertificateVersions and may continue serving any active valid version until expiry. Disabling does not revoke CA material and does not block explicit per-version revocation. It prevents new initial issuance, renewal, reissue, and key rotation from starting.

## Certificate Identity and Reuse

Certhub must normalize requested domains before computing identity:

- Lowercase.
- Trim trailing dot.
- Convert IDNs to punycode.
- Validate as DNS identifiers acceptable for public TLS certificates.
- Deduplicate.
- Sort lexicographically.

Exact and wildcard identifiers are distinct SANs. Certhub must allow a single Certificate identity to contain both an exact identifier and its corresponding wildcard identifier, such as `torob.dev` and `*.torob.dev`, when both identifiers are valid and independently authorized by Application domain scopes.

Certificate identity is:

```text
application_id
+ normalized SAN set
+ key_type
+ issuer
```

If identity matches an existing non-deleted Certificate for the selected Application and every requested SAN is covered by that Application's domain scopes, Certhub reuses that Certificate identity instead of creating a new Certificate row. The selected Application is the authenticated Application for Application-token runtime endpoints and the URL Application for User-authenticated web management endpoints. If a latest valid CertificateVersion exists, material endpoints return it. If no valid material exists, Certhub follows the concrete reissue rules below.

Certificate storage constraints:

- `application_id` is required for every Certificate.
- Certificates are never shared across Applications in v1.

Certhub must create or select a different Certificate identity when:

- Certificate is missing.
- Application, key type, or issuer differs.

Certhub must create a new CertificateVersion for an existing Certificate identity when:

- Certificate is inside the renewal window.
- Manual renewal is requested and an active valid CertificateVersion exists.
- Key rotation is explicitly requested and an active valid CertificateVersion exists.
- Reissue is explicitly requested because no active valid CertificateVersion exists and no CertificateVersion is currently issuing.

Reissue rules:

- `failed` parent Certificate: Application `POST /v1/sync/certificates` and User web-console `POST /v1/applications/{application_id}/certificates` must return Certificate metadata with `status=failed` and must not automatically enqueue reissue.
- User lifecycle endpoints may retry an identity with no active valid version and no issuing version through `POST /v1/certificates/{certificate_id}/reissue`.
- `POST /v1/certificates/{certificate_id}/renew` and `POST /v1/certificates/{certificate_id}/rotate-key` must return `409 certificate_no_active_version` when no active valid CertificateVersion exists.
- `POST /v1/certificates/{certificate_id}/reissue` must return `409 conflict` when an active valid CertificateVersion exists or any CertificateVersion is currently issuing.
- Certificates are never deleted through public APIs. Reissue keeps the same Certificate identity and creates a new CertificateVersion.

Enablement rules:

- New Certificates default to `enabled=true`.
- Application `manager` Users and global admins may change enablement; public writes to a reserved `certhub_server` Certificate return `409 system_managed_resource`.
- `POST /v1/sync/certificates` and `POST /v1/applications/{application_id}/certificates` return existing disabled Certificate metadata without creating a CertificateVersion or issuance job.
- Manual renew, key rotation, and reissue on a disabled Certificate return non-retryable `409 certificate_disabled`.
- Work already pending or running when disablement commits may finish, including its existing retries. Disablement prevents only later work from starting.
- Re-enabling does not enqueue work immediately. Later normal sync, manual lifecycle, or periodic renewal triggers may start work.

When explicit User lifecycle reissue starts, Certhub must transition the parent Certificate to an issuing state before creating the new issuing CertificateVersion. This transition clears parent Certificate failure and revocation metadata so parent status constraints remain valid. CertificateVersion revocation metadata remains preserved. When that reissue succeeds, the parent Certificate becomes `ready`.

Key compromise is modeled as revocation plus key rotation. It is not a separate Certificate status.

User access for Certificate ID-based APIs is derived as follows:

- Global `admin` can inspect, download, and run lifecycle actions for any Certificate.
- Non-admin User access is based on the User's grant on the Certificate's `application_id`.
- Non-admin Users need at least `viewer` to inspect certificate metadata.
- Non-admin Users need `certificate_reader` or `manager` to download certificate material.
- Non-admin Users need `manager` to create Application-owned certificates through web-console APIs and to run lifecycle actions such as renew, key rotation, revocation, and deletion.

Default v1 values:

- `key_type`: `ecdsa-p256`.
- `issuer`: omitted requests use the single active issuer with `default=true`.
- `issuers.renewal_window_seconds`: `2592000` seconds, 30 days before expiry.

Allowed v1 `key_type` values:

- `rsa-2048`
- `rsa-3072`
- `rsa-4096`
- `ecdsa-p256`
- `ecdsa-p384`

Issuer selection rules:

- If a request specifies `issuer`, it must match an active issuer `name`; otherwise Certhub returns `400 invalid_request`.
- If a request omits `issuer`, exactly one active issuer must have `default=true`; otherwise Certhub returns `409 issuer_not_configured`.
- At most one active issuer may have `default=true`.

## Status Values

Certificate statuses:

- `pending`: Certificate row exists but issuance work has not started.
- `validating_dns`: ACME DNS-01 challenge is being prepared or validated.
- `issuing`: ACME order is being finalized and no valid retrievable CertificateVersion exists yet.
- `ready`: at least one valid retrievable CertificateVersion exists.
- `renewing`: renewal is in progress. If the current version is still valid, material endpoints may continue returning it.
- `rotating_key`: key rotation is in progress. If the current version is still valid, material endpoints may continue returning it.
- `expired`: certificate is past `not_after` and has no valid retrievable CertificateVersion.
- `revoked`: certificate was revoked.
- `failed`: no valid retrievable CertificateVersion exists and the latest issuance, renewal, reissue, or key rotation failed. If replacement fails while an older CertificateVersion is still valid, the Certificate may remain `ready` and expose the failure through CertificateVersion metadata and audit events.
- `deleted`: local Certificate availability was removed; deleted Certificates are ignored by criteria lookup and hidden from normal list/detail APIs.

## Public API

All API responses with bodies must be JSON except archive endpoints, whose successful `200 OK` responses are `application/gzip`, and `/metrics`, whose successful `200 OK` response uses Prometheus text exposition. Conditional `204 No Content` and `304 Not Modified` responses have no body. Certificate PEM values are returned as JSON string fields by TLS material endpoints or as files inside tar.gz archives returned by TLS archive endpoints.

All mutating requests must write audit events.

All endpoints should accept `X-Request-ID` with format `correlation_id`. If absent, Certhub generates a correlation ID. Responses, logs, and audit events must include the effective correlation ID.

### API Contract Requirements

`api/openapi.yaml` is required before implementation starts and is the concrete HTTP contract for Certhub v1.

Rules:

- Every public endpoint listed in this spec must be represented in `api/openapi.yaml`.
- Every endpoint must define request body schemas, success response schemas, error response schemas, path parameters, query parameters, and examples where applicable.
- Public resource IDs in API paths and response identity fields are raw UUID strings. Human-friendly names such as Application `name`, issuer `name`, and DNS provider `name` are separate fields and must not be used as path IDs.
- List endpoints use `limit` and `offset` pagination in v1. Cursor pagination is out of scope unless a future spec revision changes a specific endpoint.
- `limit` and `offset` validation and response metadata must be consistent across list endpoints.
- `error.details` shapes must be defined for every error code that returns structured details.

### Conditional Material Retrieval

TLS material endpoints support conditional retrieval using the stored `certificate_versions.material_etag`.

`material_etag` format:

```text
"cth-mat-v1." + base64url_no_padding(
  HMAC-SHA256(material_etag_key, canonical_material_descriptor)
)
```

The HTTP header value must include the surrounding quotes, for example:

```http
ETag: "cth-mat-v1.JYjzT2o0Gd9c6SwJ5YYRWR6d9xWJ9G7dy2cW3rQpQ9E"
```

Because HMAC-SHA256 produces 32 bytes, the base64url-without-padding suffix is exactly 43 characters. The full strong ETag format is a quoted string matching `"cth-mat-v1.<43 base64url characters>"`.

The canonical material descriptor is derived only from the exact returned material:

```text
cth-material-v1
cert_pem_sha256=<sha256(cert_pem)>
chain_pem_sha256=<sha256(chain_pem)>
fullchain_pem_sha256=<sha256(fullchain_pem)>
private_key_pem_sha256=<sha256(private_key_pem)>
```

Rules:

- Certhub generates and stores `material_etag` when CertificateVersion material is stored.
- Clients must treat ETags as opaque and resend the full quoted value exactly as received.
- Only strong ETags are allowed. Certhub must not emit weak `W/` ETags.
- ETag must change whenever `cert_pem`, `chain_pem`, `fullchain_pem`, or `private_key_pem` changes.
- Material responses that return certificate material must include `ETag: <material_etag>`.
- Material responses must include `Cache-Control: no-store`, `Pragma: no-cache`, and `Vary: Authorization`.
- JSON material responses must include non-secret certificate metadata needed by sync clients, including `certificate_id`, `application_id`, normalized domains, `key_type`, `issuer_id`, `issuer_name`, version, validity timestamps, serial number, fingerprints, and `material_etag`.
- Criteria-based `POST /v1/sync/certificates/tls-material` and `POST /v1/sync/certificates/tls-archive` accept `If-None-Match`.
- Certhub must authenticate, authorize, resolve the requested Certificate identity or ID, and select the latest valid CertificateVersion before evaluating `If-None-Match`; conditional responses must not bypass access checks.
- If `If-None-Match` equals the latest valid CertificateVersion `material_etag`, criteria-based `POST` endpoints return `204 No Content` with `ETag: <material_etag>` and no body.
- If `If-None-Match` is absent, malformed, weak, or does not match the latest valid CertificateVersion `material_etag`, Certhub returns material normally with `200 OK`.
- ID-based `GET /v1/certificates/{certificate_id}/tls-archive` accepts `If-None-Match`.
- If `If-None-Match` equals the latest valid CertificateVersion `material_etag`, the ID-based archive endpoint returns `304 Not Modified` with `ETag: <material_etag>` and no body.
- `private_key_read` audit events are written only when material is returned with `200 OK`; unchanged `204 No Content` and `304 Not Modified` responses must not write `private_key_read`.

### API Summary

| Method | URL | Summary |
| --- | --- | --- |
| `GET` | `/healthz` | Return liveness for the backend process. |
| `GET` | `/readyz` | Return readiness for serving API traffic. |
| `GET` | `/metrics` | Expose Prometheus metrics for internal scraping. |
| `POST` | `/v1/auth/login` | Exchange User email/password for a User access token. |
| `POST` | `/v1/auth/password-2fa/setup` | Start TOTP setup for the current User. |
| `POST` | `/v1/auth/password-2fa/confirm` | Confirm TOTP setup for the current User. |
| `DELETE` | `/v1/auth/password-2fa` | Disable TOTP for the current User. |
| `GET` | `/v1/auth/oidc/login` | Start OIDC browser login. |
| `GET` | `/v1/auth/oidc/callback` | Complete provider-facing OIDC callback and redirect to frontend with a short-lived handoff ID. |
| `POST` | `/v1/auth/oidc/handoff` | Exchange a short-lived OIDC handoff ID for a User access token. |
| `POST` | `/v1/auth/refresh` | Rotate the current User access token before it expires. |
| `POST` | `/v1/auth/logout` | Revoke the current User login session. |
| `GET` | `/v1/auth/me` | Return the authenticated User or Application identity. |
| `POST` | `/v1/sync/certificates` | Ensure a Certificate exists for criteria and start issuance when needed. |
| `POST` | `/v1/sync/certificates/tls-material` | Return current TLS material as JSON for an exact criteria match using an Application token. |
| `POST` | `/v1/sync/certificates/tls-archive` | Return current TLS material as a tar.gz archive for an exact criteria match using an Application token. |
| `GET` | `/v1/certificates` | List certificate metadata with optional filters such as domain, Application, status, enablement, and expiry. |
| `GET` | `/v1/certificates/{certificate_id}` | Return certificate metadata by ID for human/web-console workflows. |
| `PATCH` | `/v1/certificates/{certificate_id}` | Enable or disable new lifecycle issuance for a Certificate. |
| `GET` | `/v1/certificates/{certificate_id}/versions` | List CertificateVersion metadata for one certificate. |
| `GET` | `/v1/certificates/{certificate_id}/versions/{certificate_version_id}/events` | List operational issuance events for one CertificateVersion. |
| `GET` | `/v1/certificates/{certificate_id}/versions/{certificate_version_id}/tls-archive` | Return TLS material for a specific downloadable CertificateVersion as a tar.gz archive. |
| `POST` | `/v1/certificates/{certificate_id}/versions/{certificate_version_id}/revoke` | Revoke one specific CertificateVersion. |
| `GET` | `/v1/certificates/{certificate_id}/tls-archive` | Return current TLS material as a tar.gz archive for a certificate selected by ID. |
| `POST` | `/v1/certificates/{certificate_id}/renew` | Start renewal for a certificate selected by ID. |
| `POST` | `/v1/certificates/{certificate_id}/rotate-key` | Start key rotation for a certificate selected by ID. |
| `POST` | `/v1/certificates/{certificate_id}/reissue` | Start reissue when no active valid or issuing CertificateVersion exists. |
| `GET` | `/v1/certificates/{certificate_id}/events` | List audit events related to one certificate. |
| `GET` | `/v1/users` | List Users visible to the authenticated User. |
| `GET` | `/v1/users/lookup` | Resolve one active User by exact email for grant workflows. |
| `POST` | `/v1/users` | Create a User. |
| `GET` | `/v1/users/{user_id}` | Return User metadata by ID. |
| `PATCH` | `/v1/users/{user_id}` | Update mutable User fields. |
| `GET` | `/v1/applications` | List Applications visible to the authenticated User. |
| `POST` | `/v1/applications` | Create an Application. |
| `GET` | `/v1/applications/{application_id}` | Return Application metadata by ID. |
| `PATCH` | `/v1/applications/{application_id}` | Update mutable Application fields. |
| `POST` | `/v1/applications/{application_id}/certificates` | Ensure a Certificate exists for an Application selected by ID and start issuance when needed. |
| `POST` | `/v1/applications/{application_id}/tokens` | Create an Application token and return the raw token once. |
| `GET` | `/v1/applications/{application_id}/tokens` | List Application token metadata without raw token values. |
| `POST` | `/v1/applications/{application_id}/tokens/{token_id}/rotate` | Rotate an Application token secret in place and return the raw token once. |
| `DELETE` | `/v1/applications/{application_id}/tokens/{token_id}` | Revoke an Application token. |
| `POST` | `/v1/applications/{application_id}/domain-scopes` | Add an immutable domain scope to an Application. |
| `GET` | `/v1/applications/{application_id}/domain-scopes` | List domain scopes for an Application. |
| `DELETE` | `/v1/applications/{application_id}/domain-scopes/{scope_id}` | Delete an Application domain scope. |
| `GET` | `/v1/applications/{application_id}/users` | List User grants on an Application. |
| `PUT` | `/v1/applications/{application_id}/users/{user_id}` | Create or replace a User grant on an Application. |
| `DELETE` | `/v1/applications/{application_id}/users/{user_id}` | Remove a User grant from an Application. |
| `GET` | `/v1/issuers` | List configured ACME issuers. |
| `POST` | `/v1/issuers` | Create an ACME issuer and let Certhub create or reuse its ACME account. |
| `GET` | `/v1/issuers/{issuer_id}` | Return issuer metadata by ID. |
| `PATCH` | `/v1/issuers/{issuer_id}` | Update mutable issuer fields or disable an issuer. |
| `GET` | `/v1/dns-providers` | List DNS provider configurations. |
| `POST` | `/v1/dns-providers` | Create a DNS provider with write-only credentials. |
| `GET` | `/v1/dns-providers/{dns_provider_id}` | Return DNS provider metadata by ID without credentials. |
| `PATCH` | `/v1/dns-providers/{dns_provider_id}` | Update mutable DNS provider fields or replace credentials. |
| `GET` | `/v1/dns-providers/{dns_provider_id}/zones` | List active zones configured for a DNS provider. |
| `POST` | `/v1/dns-providers/{dns_provider_id}/zones` | Add a zone to a manual-mode DNS provider. |
| `DELETE` | `/v1/dns-providers/{dns_provider_id}/zones/{zone_id}` | Delete a zone from a manual-mode DNS provider. |
| `GET` | `/v1/dns-providers/{dns_provider_id}/zones/discovered` | Return zones discovered from the provider API as suggestions or refresh input. |
| `POST` | `/v1/dns-providers/{dns_provider_id}/zones/refresh` | Refresh auto-mode DNS provider zones from the provider API. |
| `GET` | `/v1/audit-events` | List audit events with filters. |

Local material sync namespace rule: `/v1/sync/...` is reserved for Application-token endpoints used by CLI, Kubernetes operator, and local agents to sync certificate material from Certhub to local state. Certhub's own server self-certificate sync is internal backend behavior and must not call or expose a separate `/v1/sync/...` endpoint. DNS provider zone discovery and provider-zone refresh are management operations and stay under `/v1/dns-providers/...`.

### Endpoint Details

#### GET /healthz

Summary: Return liveness for the backend process.

Description and notes:

- Used by process supervisors and Kubernetes liveness probes.
- Must not require authentication.
- Must not check external dependencies such as PostgreSQL, DNS providers, or ACME. Those checks belong in readiness or metrics.
- Must not return secrets or process configuration values.

```http
GET /healthz
```

Query params: None.

Request body: None.

Expected responses:

- `200 OK`: process is alive.

#### GET /readyz

Summary: Return readiness for serving API traffic.

Description and notes:

- Used by load balancers and Kubernetes readiness probes.
- Must not require authentication.
- Checks PostgreSQL connectivity, migration compatibility, encryption key availability, and required process configuration.
- Does not require DNS providers or ACME to be healthy, because temporary provider failures should not remove all API capacity.
- Must not return secrets or decrypted values.

```http
GET /readyz
```

Query params: None.

Request body: None.

Expected responses:

- `200 OK`: backend is ready.
- `503 Service Unavailable`: backend is not ready; response includes non-secret failed check names.

#### GET /metrics

Summary: Expose Prometheus metrics for internal scraping.

Description and notes:

- Intended for internal monitoring only.
- Must not expose private keys, raw tokens, DNS provider credentials, decrypted values, or raw domain lists as high-cardinality labels.
- Deployments must protect this endpoint by network policy, reverse-proxy auth, or binding it to an internal listener.

```http
GET /metrics
```

Query params: None.

Request body: None.

Expected responses:

- `200 OK`: Prometheus text exposition.

#### POST /v1/auth/login

Summary: Exchange User email/password for a User access token.

Description and notes:

- Used by web password login.
- Requires `auth.password.enabled=true`.
- Creates a User login session only after required TOTP is satisfied.
- Returns a short-lived User access token and fixed session expiry, or `password_2fa_setup_required` with a one-time setup token and TOTP provisioning payload when instance policy requires 2FA and the User has no configured password 2FA.
- If password 2FA is enabled for the User or required by `auth.password.2fa_required`, the request must include a valid TOTP code.
- Missing TOTP may return `password_2fa_required` only after the primary password is valid and the User is otherwise eligible to authenticate. Missing configured TOTP when policy requires it returns `password_2fa_setup_required` without creating a session.
- Unknown email, disabled User, missing password hash, and invalid password must all return the same generic `401 invalid_credentials` response.
- OIDC users are not required to have Certhub password 2FA.
- Must update `users.last_login_at` on success.
- Must write `user_login_succeeded` or `user_login_failed` audit events without storing the password, access token, or raw access token.

```http
POST /v1/auth/login
Content-Type: application/json
```

Query params: None.

Request body:

```json
{
  "email": "user@example.com",
  "password": "password",
  "totp_code": "123456"
}
```

`totp_code` is required only for password login when password 2FA is required or enabled for that User.

Expected responses:

- `200 OK`: login succeeded with User metadata and tokens, or forced password 2FA setup is required with `password_2fa_setup_token` and `password_2fa`.
- `400 Bad Request`: invalid body.
- `401 Unauthorized`: credentials are invalid or TOTP code is invalid (`invalid_credentials` or `invalid_2fa_code`). Disabled Users and Users without password login must be folded into `invalid_credentials`.
- `403 Forbidden`: password auth is disabled or TOTP code is missing after valid primary credentials (`password_auth_disabled` or `password_2fa_required`).
- `429 Too Many Requests`: login is rate limited.

#### POST /v1/auth/password-2fa/setup

Summary: Start TOTP setup for the current User.

Description and notes:

- Requires a valid User access token from password login or OIDC login.
- Creates a pending TOTP secret for the User.
- Does not enable 2FA until confirmed.
- Returns the TOTP issuer, account label, secret, and provisioning URI once.
- Must write audit events without storing the secret in audit metadata.

```http
POST /v1/auth/password-2fa/setup
Authorization: Bearer <user-access-token>
```

Query params: None.

Request body: None.

Expected responses:

- `200 OK`: pending TOTP setup created.
- `401 Unauthorized`: access token is missing, invalid, or expired.
- `403 Forbidden`: User is disabled.
- `409 Conflict`: password 2FA is already enabled or setup is already pending.

#### POST /v1/auth/password-2fa/confirm

Summary: Confirm TOTP setup for the current User.

Description and notes:

- Requires a valid User access token.
- Verifies a TOTP code against the pending secret.
- Enables password 2FA for future password logins.
- Must write `password_2fa_enabled` audit event.

```http
POST /v1/auth/password-2fa/confirm
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body:

```json
{
  "totp_code": "123456"
}
```

Expected responses:

- `200 OK`: password 2FA enabled.
- `400 Bad Request`: invalid body.
- `401 Unauthorized`: access token is missing, invalid, or expired (`invalid_token`), or TOTP code is invalid (`invalid_2fa_code`).
- `404 Not Found`: no pending setup exists.

#### DELETE /v1/auth/password-2fa

Summary: Disable TOTP for the current User.

Description and notes:

- Requires a valid User access token.
- Requires the current password or a valid TOTP code unless performed by global `admin` through User administration.
- If `auth.password.2fa_required=true`, disabling 2FA must be rejected unless password login is also disabled for that User.
- Must write `password_2fa_disabled` audit event.

```http
DELETE /v1/auth/password-2fa
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body:

```json
{
  "password": "password",
  "totp_code": "123456"
}
```

Expected responses:

- `204 No Content`: password 2FA disabled.
- `400 Bad Request`: invalid body.
- `401 Unauthorized`: access token is missing, invalid, or expired (`invalid_token`), or password/TOTP proof is invalid (`invalid_credentials` or `invalid_2fa_code`).
- `403 Forbidden`: 2FA is required by policy (`password_2fa_required`).

#### GET /v1/auth/oidc/login

Summary: Start OIDC browser login.

Description and notes:

- Requires `auth.oidc.enabled=true`.
- Creates an OIDC state, nonce, and PKCE `code_verifier`.
- Stores the pending login in `oidc_login_states` with an expiry and sanitized `return_url` when provided.
- Returns or redirects to the provider authorization URL.
- Authorization URL must use `response_type=code`, `code_challenge_method=S256`, and a `code_challenge` derived from the server-side `code_verifier`.
- Must not create a User by itself.
- Must not use or require an OIDC client secret.

```http
GET /v1/auth/oidc/login
```

Query params:

- `return_url`: optional frontend return URL after login. Must be an allowed same-origin or configured return target. This is not the OIDC provider callback URL.

Request body: None.

Expected responses:

- `302 Found`: redirect to OIDC provider authorization URL.
- `400 Bad Request`: invalid return URL.
- `403 Forbidden`: OIDC auth is disabled.

#### GET /v1/auth/oidc/callback

Summary: Complete the provider-facing OIDC callback and redirect to the frontend with a short-lived handoff ID.

Description and notes:

- Validates provider callback state, nonce, issuer, audience, signature, and token expiry.
- Looks up the pending OIDC login by HMAC-hashing the returned `state` and redeems the authorization code with the stored PKCE `code_verifier`.
- The token exchange must use exactly `auth.oidc.redirect_url` as the OIDC callback URI.
- Rejects callbacks with missing, expired, consumed, reused, or unknown `state`.
- Consumes or deletes the `oidc_login_states` row atomically before creating a login handoff.
- Rejects providers that do not honor PKCE `S256`.
- Maps the identity to an existing active User as described in `Human Authentication and User Sessions`.
- Creates a short-lived, single-use row in `oidc_login_handoffs` for the mapped User.
- Redirects to the validated frontend return URL with the raw handoff ID in the URL.
- Must not include User access tokens in the callback response, redirect URL, logs, audit metadata, or error pages.
- Must write OIDC callback success/failure audit events without storing raw `state`, authorization code, code verifier, provider tokens, or handoff ID.

```http
GET /v1/auth/oidc/callback?code=<authorization-code>&state=<opaque-state>
```

Query params:

- `code`: OIDC authorization code from the provider.
- `state`: OIDC state returned by the provider.

Request body: None.

Expected responses:

- `302 Found`: callback succeeded; redirect target is the frontend callback route with a short-lived handoff ID.
- `400 Bad Request`: missing code or state.
- `401 Unauthorized`: OIDC callback validation failed.
- `403 Forbidden`: OIDC auth is disabled, User is disabled, or User is not provisioned.

#### POST /v1/auth/oidc/handoff

Summary: Exchange a short-lived OIDC handoff ID for a User access token.

Description and notes:

- Used by the frontend callback route after `GET /v1/auth/oidc/callback` redirects back from the backend.
- Consumes a single-use handoff ID created by the provider-facing callback.
- Looks up the handoff by HMAC-hashing the raw handoff ID; raw handoff IDs are never stored.
- Rejects missing, expired, consumed, reused, unknown, or malformed handoff IDs.
- Creates a User login session only when the handoff is valid and the User is still active.
- Returns a short-lived opaque User access token and longer-lived opaque access token.
- Must update `users.last_login_at` on success.
- Must write `user_login_succeeded` or `user_login_failed` audit events without storing raw handoff IDs or tokens.
- Frontend must remove the handoff ID from the URL and browser history immediately after exchange.

```http
POST /v1/auth/oidc/handoff
Content-Type: application/json
```

Query params: None.

Request body:

```json
{
  "handoff_id": "opaque-handoff-id"
}
```

Expected responses:

- `200 OK`: OIDC login succeeded; response includes User metadata, opaque access token, access token expiry, opaque access token, access token expiry, and fixed session expiry.
- `400 Bad Request`: invalid body or malformed handoff ID.
- `401 Unauthorized`: handoff is missing, expired, consumed, reused, or unknown.
- `403 Forbidden`: OIDC auth is disabled or User is disabled.

#### POST /v1/auth/refresh

Summary: Rotate the current User access token before it expires.

Description and notes:

- Used by web clients to rotate the current User access token before it expires.
- Requires a valid, current, active, unrotated access token in the JSON body.
- Requires `access_expires_at > now` and `session_expires_at > now`; expired access tokens cannot be refreshed.
- Returns a new short-lived User access token, `access_expires_at`, and the unchanged `session_expires_at`.
- Reuse of an already-rotated access token is detected through `user_session_token_history` and must revoke the whole login session.
- Must write `user_session_refreshed` on success and an audit failure event on invalid, expired, session-expired, or reused tokens.

```http
POST /v1/auth/refresh
Content-Type: application/json
```

Query params: None.

Request body:

```json
{
  "access_token": "cth_uat_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
```

Expected responses:

- `200 OK`: refresh succeeded; response includes new opaque access token, access token expiry, and fixed session expiry.
- `400 Bad Request`: invalid body.
- `401 Unauthorized`: access token is missing, invalid, expired, rotated, or revoked (`invalid_token`) or the absolute session expired (`session_expired`).

#### POST /v1/auth/logout

Summary: Revoke the current User login session.

Description and notes:

- Requires a valid User access token.
- Revokes the current login session and invalidates its access token.
- Does not affect Application tokens.
- Must write `user_session_revoked`.

```http
POST /v1/auth/logout
Authorization: Bearer <user-access-token>
```

Query params: None.

Request body: None.

Expected responses:

- `204 No Content`: session revoked.
- `401 Unauthorized`: access token is missing, malformed, unknown, expired, revoked, or session is already revoked (`invalid_token`).

#### GET /v1/auth/me

Summary: Return the authenticated User or Application identity.

Description and notes:

- Used by web clients to determine the current User identity and available actions. Application-token clients may use it to verify the authenticated Application when needed.
- User responses include global role, password-login availability, password-2FA status, whether password 2FA may be disabled by the current User under instance policy, and may include display name.
- Application responses identify the Application and do not include User grant data.

```http
GET /v1/auth/me
Authorization: Bearer <user-access-token|application-token>
```

Query params: None.

Request body: None.

Expected responses:

- `200 OK`: identity metadata.
- `401 Unauthorized`: token is missing, invalid, expired, or revoked.
- `403 Forbidden`: Application token is valid but source IP is not trusted for the Application.

#### POST /v1/sync/certificates

Summary: Ensure a Certificate exists for criteria and start issuance when needed.

Description and notes:

- Requires an Application token; User access tokens must use `POST /v1/applications/{application_id}/certificates` for web-console creation.
- Application clients should call this endpoint only after criteria-based material retrieval returns `404 certificate_not_found`.
- If criteria-based material retrieval returns `409 certificate_not_ready`, clients must not call this endpoint again just to wait; they should retry the same material or archive endpoint with backoff. If retrieval returns `409 certificate_no_active_version`, a User reissue action is required.
- Normalizes and validates requested domains.
- Checks that every requested domain is covered by the authenticated Application's domain scopes.
- Computes certificate identity from authenticated Application ID, normalized SANs, key type, and issuer.
- `issuer` is optional. If omitted, Certhub selects the single active default issuer.
- Creates the `certificates` row synchronously if it does not already exist.
- Returns Certificate status metadata only. It must not return certificate PEM, private key PEM, or archives.
- If a matching Certificate already exists, the endpoint is idempotent and returns that Certificate metadata.
- If the matching Certificate has no valid material and no issuing CertificateVersion, Certhub enqueues issuance when the Certificate state is eligible under the reissue rules.
- If the matching Certificate is failed, Certhub returns Certificate metadata with `status=failed` and does not enqueue reissue.
- If the matching Certificate is revoked and not eligible for Application-triggered reissue, Certhub returns Certificate metadata with `status=revoked` and does not enqueue issuance.
- Application readiness polling must use `POST /v1/sync/certificates/tls-material` or `POST /v1/sync/certificates/tls-archive`.

```http
POST /v1/sync/certificates
Authorization: Bearer <application-token>
Content-Type: application/json
```

Query params: None.

Request body:

```json
{
  "domains": ["api.torob.dev", "*.torob.dev"],
  "key_type": "ecdsa-p256",
  "issuer": "letsencrypt_production"
}
```

Expected responses:

- `200 OK`: an existing Certificate is returned as metadata, including terminal states that require User lifecycle action.
- `202 Accepted`: Certificate exists and issuance, renewal, reissue, or key rotation is pending or in progress; response includes `Retry-After` for the next material/archive retry.
- `400 Bad Request`: invalid domains, key type, or issuer.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: token is not an Application token, source IP is not trusted for the Application, or domains are not authorized.
- `409 Conflict`: conflicting certificate identity state or issuer is not configured.

#### POST /v1/applications/{application_id}/certificates

Summary: Ensure a Certificate exists for an Application selected by ID and start issuance when needed.

Description and notes:

- User/web-console endpoint for creating Application-owned Certificates.
- Requires a User access token; Application tokens are rejected.
- Requires Application `manager` grant or global `admin`.
- The Certificate is owned by the URL Application. Users never create personal certificates.
- Normalizes and validates requested domains.
- Checks that every requested domain is covered by the URL Application's domain scopes.
- Computes certificate identity from URL Application ID, normalized SANs, key type, and issuer.
- `issuer` is optional. If omitted, Certhub selects the single active default issuer.
- Creates the `certificates` row synchronously if it does not already exist.
- Returns Certificate status metadata only. It must not return certificate PEM, private key PEM, or archives.
- If a matching Certificate already exists for the same Application identity, the endpoint is idempotent and returns that Certificate metadata.
- If the matching Certificate has no valid material and no issuing CertificateVersion, Certhub enqueues issuance when the Certificate state is eligible under the reissue rules.
- If the matching Certificate is failed, Certhub returns Certificate metadata with `status=failed` and does not enqueue reissue. The User must use an explicit lifecycle action to retry.
- If the matching Certificate is revoked and not eligible for reissue, Certhub returns Certificate metadata with `status=revoked` and does not enqueue issuance.
- For the reserved `certhub_server` Application, this endpoint must return `409 system_managed_resource`. The backend reconcile loop creates and updates that Application's Certificate from process configuration.
- Readiness should be checked from the web console by refreshing certificate metadata or by using the ID-based archive endpoint when the User has material access.

```http
POST /v1/applications/{application_id}/certificates
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body:

```json
{
  "domains": ["api.torob.dev", "*.torob.dev"],
  "key_type": "ecdsa-p256",
  "issuer": "letsencrypt_production"
}
```

Expected responses:

- `200 OK`: an existing Certificate is returned as metadata, including terminal states that require lifecycle action.
- `202 Accepted`: Certificate exists and issuance, renewal, reissue, or key rotation is pending or in progress; response includes `Retry-After` when useful.
- `400 Bad Request`: invalid domains, key type, or issuer.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: token is not a User access token, User lacks `manager` access, or domains are not authorized for the Application.
- `404 Not Found`: Application does not exist or is not visible to the User.
- `409 Conflict`: conflicting certificate identity state, issuer is not configured, or the Application is the config-managed `certhub_server`.

#### POST /v1/sync/certificates/tls-material

Summary: Return current TLS material as JSON for an exact criteria match using an Application token.

Description and notes:

- This endpoint returns certificate material as JSON string fields.
- Requires an Application token. User access tokens are rejected.
- The Application is identified exclusively from the token; request body must not include `application_id`.
- The authenticated Application must be authorized for every requested SAN by its domain scopes.
- Always returns the latest valid CertificateVersion for the exact matching certificate.
- Supports conditional retrieval with `If-None-Match`.
- Must create a `private_key_read` audit event only when material is returned with `200 OK`.
- If the certificate identity does not exist, return `404 certificate_not_found`; Application clients should then call `POST /v1/sync/certificates` once with the same criteria.
- If the certificate identity exists but no valid material is available and an issuing CertificateVersion exists, return `409 certificate_not_ready` with JSON status metadata and `Retry-After` when retryable, including post-expiry reissue. Application clients should periodically retry this same endpoint with the same criteria.
- If the certificate identity exists but no valid material is available because the latest issuance, renewal, reissue, or key rotation failed, return `409 certificate_issuance_failed` with `details.certificate_id`, `details.status=failed`, `details.failure_code`, and `details.failure_message`.
- If the certificate identity exists but no active valid CertificateVersion exists and no issuing or failed latest version exists, return `409 certificate_no_active_version` with JSON status metadata. Application clients must not call `POST /v1/sync/certificates` unless a later lookup returns `404 certificate_not_found`.

```http
POST /v1/sync/certificates/tls-material
Authorization: Bearer <application-token>
Content-Type: application/json
If-None-Match: "<optional-material-etag>"
```

Query params: None.

Request body:

```json
{
  "domains": ["api.torob.dev", "*.torob.dev"],
  "key_type": "ecdsa-p256",
  "issuer": "letsencrypt_production"
}
```

The request body must not contain `application_id`; Certhub derives the Application from the token.

Expected responses:

- `200 OK`: JSON certificate material, including private key and `material_etag`.
  - `ETag: <material_etag>`
  - `Cache-Control: no-store`
  - `Pragma: no-cache`
  - `Vary: Authorization`
- `204 No Content`: `If-None-Match` matches the latest valid material; no body and no `private_key_read` audit event.
  - `ETag: <material_etag>`
  - `Cache-Control: no-store`
  - `Pragma: no-cache`
  - `Vary: Authorization`
- `400 Bad Request`: invalid criteria.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: token is not an Application token, source IP is not trusted for the Application, or domains are not authorized for the Application.
- `404 Not Found`: no matching certificate identity exists; client should call `POST /v1/sync/certificates`.
- `409 Conflict`: matching certificate exists but has no valid current material; response includes current status metadata such as `certificate_not_ready`, `certificate_no_active_version`, or `certificate_issuance_failed`.

#### POST /v1/sync/certificates/tls-archive

Summary: Return current TLS material as a tar.gz archive for an exact criteria match using an Application token.

Description and notes:

- This endpoint uses the same criteria, authorization, latest-version selection, conditional retrieval, and audit rules as `POST /v1/sync/certificates/tls-material`.
- Requires an Application token. User access tokens are rejected.
- The Application is identified exclusively from the token; request body must not include `application_id`.
- Successful responses are binary `application/gzip`, not JSON.
- Error responses are JSON.
- Archive entry names must be fixed by Certhub and must not be derived from user input.
- Archive must include `cert.pem`, `chain.pem`, `fullchain.pem`, `privkey.pem`, and `metadata.json`.
- `metadata.json` contains non-secret certificate metadata such as domains, key type, issuer, Application ID, not-before, not-after, serial number, fingerprint, and `material_etag`.
- Successful responses must set `Content-Disposition: attachment; filename="<safe_certificate_name>.tar.gz"`, where `<safe_certificate_name>` is derived from the first normalized SAN on the Certificate. If the SAN list is unavailable, Certhub must use the Certificate ID as the basename.
- `<safe_certificate_name>` must not contain `*` or `.`. Only the fixed `.tar.gz` extension contains dots. Derivation is deterministic:
  - Lowercase the selected SAN and trim one trailing dot.
  - Replace a leading `*.` with `wildcard_`.
  - Replace every remaining `.` with `_`.
  - Replace any remaining `*` with `wildcard`.
  - Allow only `a-z`, `0-9`, `_`, and `-` in the basename.
  - Collapse repeated `_` and trim leading/trailing `_`.
- Example: SAN `*.torob.dev` becomes filename `wildcard_torob_dev.tar.gz`.

```http
POST /v1/sync/certificates/tls-archive
Authorization: Bearer <application-token>
Content-Type: application/json
Accept: application/gzip
If-None-Match: "<optional-material-etag>"
```

Query params: None.

Request body: Same criteria body as `POST /v1/sync/certificates/tls-material`.

Expected responses:

- `200 OK`: tar.gz archive containing current TLS material.
  - `Content-Type: application/gzip`
  - `Content-Disposition: attachment; filename="<safe_certificate_name>.tar.gz"`
  - `ETag: <material_etag>`
  - `Cache-Control: no-store`
  - `Pragma: no-cache`
  - `Vary: Authorization`
- `204 No Content`: `If-None-Match` matches the latest valid material; no body and no `private_key_read` audit event.
  - `ETag: <material_etag>`
  - `Cache-Control: no-store`
  - `Pragma: no-cache`
  - `Vary: Authorization`
- `400 Bad Request`: invalid criteria.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: token is not an Application token, source IP is not trusted for the Application, or domains are not authorized for the Application.
- `404 Not Found`: no matching certificate identity exists; client should call `POST /v1/sync/certificates`.
- `406 Not Acceptable`: requested response media type is not supported.
- `409 Conflict`: matching certificate exists but has no valid current material; response includes current status metadata such as `certificate_not_ready`, `certificate_no_active_version`, or `certificate_issuance_failed`.

#### GET /v1/certificates

Summary: List certificate metadata with optional filters.

Description and notes:

- User/web-console inventory endpoint.
- Returns metadata only; private keys and PEM material must not be included.
- User visibility follows the Certificate ID-based access rules from `Certificate Identity and Reuse`.
- Application clients should use `POST /v1/sync/certificates/tls-material` or `POST /v1/sync/certificates/tls-archive` when they need certificate material.

```http
GET /v1/certificates
Authorization: Bearer <user-access-token>
```

Query params:

- `domain`: optional domain/SAN filter.
- `application`: optional Application machine name or ID filter.
- `status`: optional certificate status filter.
- `expires_before`: optional timestamp filter.

Request body: None.

Expected responses:

- `200 OK`: list of visible certificate metadata.
- `400 Bad Request`: invalid query parameter.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: authenticated identity cannot list certificates.

#### GET /v1/certificates/{certificate_id}

Summary: Return certificate metadata by ID for human/web-console workflows.

Description and notes:

- User/web-console endpoint for humans working with known Certificate IDs.
- Application clients must use criteria-based material retrieval when they need certificate material.
- Does not return private keys or PEM material.
- User visibility follows the Certificate ID-based access rules from `Certificate Identity and Reuse`.

```http
GET /v1/certificates/{certificate_id}
Authorization: Bearer <user-access-token>
```

Query params: None.

Request body: None.

Expected responses:

- `200 OK`: certificate metadata.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: token is not a User access token.
- `404 Not Found`: certificate does not exist or is not visible to the User.

#### PATCH /v1/certificates/{certificate_id}

Updates the backend-owned Certificate enablement state. The JSON body is exactly `{ "enabled": boolean }`; empty bodies and unknown fields return `400 invalid_request`. Global admins and Users with `manager` access to the owning Application may call it. The operation is idempotent, returns updated Certificate metadata, changes `updated_at` only on a transition, and emits `certificate_enabled` or `certificate_disabled` only on a transition. It does not revoke or delete existing CertificateVersions.

#### GET /v1/certificates/{certificate_id}/versions

Summary: List CertificateVersion metadata for one certificate.

Description and notes:

- User/web-console endpoint for certificate detail, renewal history, and version history.
- Application clients must not use this endpoint for material sync.
- Does not return private keys, PEM material, DNS provider credentials, ACME account keys, or raw ACME authorization bodies.
- User visibility follows the Certificate ID-based access rules from `Certificate Identity and Reuse`.
- Returns versions sorted by `version` descending by default so the newest version is first.
- Includes every CertificateVersion for the visible Certificate, including expired, revoked, failed, issuing, renewal, and key-rotation versions.
- For deleted Certificates, this endpoint returns `404 Not Found`; deleted-certificate audit history remains available through `GET /v1/certificates/{certificate_id}/events` when permissions allow.

```http
GET /v1/certificates/{certificate_id}/versions
Authorization: Bearer <user-access-token>
```

Query params: Optional pagination.

Request body: None.

Expected responses:

- `200 OK`: list of CertificateVersion metadata.
- `400 Bad Request`: invalid pagination parameter.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: token is not a User access token.
- `404 Not Found`: certificate does not exist, is deleted, or is not visible to the User.

#### GET /v1/certificates/{certificate_id}/versions/{certificate_version_id}/events

Summary: List operational issuance events for one CertificateVersion.

Description and notes:

- User/web-console endpoint for troubleshooting exactly what the issuance worker did for a CertificateVersion.
- User visibility follows the Certificate ID-based access rules from `Certificate Identity and Reuse`.
- Returns `certificate_events`, not `audit_events`; these are worker and lifecycle operational events scoped to the CertificateVersion.
- Events are sorted oldest first by `created_at` and stable ID so the response can be rendered as a timeline.
- Event metadata must be structured JSON and must not contain private keys, raw ACME account keys, DNS provider credentials, raw DNS TXT values, raw tokens, or TOTP/password material.
- Failure events must include a sanitized actionable `message` and `metadata.failure_code`/`metadata.failure_message` when a worker knows the root cause. Opaque storage messages such as bare `SQLSTATE P0001` must be converted to an operator-actionable reason when the failing worker phase is known.
- Previewing or reading these events is not a private-key access operation.

```http
GET /v1/certificates/{certificate_id}/versions/{certificate_version_id}/events
Authorization: Bearer <user-access-token>
```

Query params: Optional pagination.

Request body: None.

Expected responses:

- `200 OK`: list of operational CertificateVersion events.
- `400 Bad Request`: invalid pagination parameter.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: token is not a User access token.
- `404 Not Found`: certificate or CertificateVersion does not exist, is deleted, or is not visible to the User.

#### GET /v1/certificates/{certificate_id}/tls-archive

Summary: Return current TLS material as a tar.gz archive for a certificate selected by ID.

Description and notes:

- User/web-console endpoint for humans working with known Certificate IDs.
- Uses the same User authorization, latest-version selection, conditional retrieval, archive contents, safe filename, and audit rules as the criteria-based archive endpoint.
- Application tokens are rejected; Application clients must use criteria-based material retrieval.
- Successful responses are binary `application/gzip`, not JSON.
- Error responses are JSON.

```http
GET /v1/certificates/{certificate_id}/tls-archive
Authorization: Bearer <user-access-token>
Accept: application/gzip
If-None-Match: "<optional-material-etag>"
```

Query params: None.

Request body: None.

Expected responses:

- `200 OK`: tar.gz archive containing current TLS material.
  - `Content-Type: application/gzip`
  - `Content-Disposition: attachment; filename="<safe_certificate_name>.tar.gz"`
  - `ETag: <material_etag>`
  - `Cache-Control: no-store`
  - `Pragma: no-cache`
  - `Vary: Authorization`
- `304 Not Modified`: `If-None-Match` matches the latest valid material; no body and no `private_key_read` audit event.
  - `ETag: <material_etag>`
  - `Cache-Control: no-store`
  - `Pragma: no-cache`
  - `Vary: Authorization`
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: token is not a User access token or User lacks private-key access.
- `404 Not Found`: certificate does not exist or is not visible.
- `406 Not Acceptable`: requested response media type is not supported.
- `409 Conflict`: certificate exists but has no valid current material; response includes current status metadata such as `certificate_not_ready`, `certificate_no_active_version`, or `certificate_issuance_failed`.

#### POST /v1/certificates/{certificate_id}/renew

Summary: Start renewal for a certificate selected by ID.

Description and notes:

- User/web-console lifecycle endpoint.
- Requires `manager` access on the Certificate's `application_id` or global `admin`.
- Requires current Application domain scopes to cover every normalized SAN on the Certificate.
- Creates a higher-numbered CertificateVersion with reason `renewal` and a fresh private key.
- If the latest active valid CertificateVersion is not inside the selected issuer's renewal window, this endpoint returns `409 renewal_not_due` and does not create a CertificateVersion or job.
- If no active valid CertificateVersion exists because previous material is expired, this endpoint may create a recovery renewal CertificateVersion.
- Manual renewal follows the same version-overlap constraints as auto renewal.
- If a Certificate already has a `status=issuing` CertificateVersion with `reason=renewal`, this endpoint is idempotent and returns the existing in-progress renewal instead of creating another version.
- If a Certificate has any other `status=issuing` CertificateVersion, such as initial issuance or key rotation, this endpoint returns `409 conflict` and does not create another version.
- If creating a renewal could result in more than two valid, not-expired CertificateVersions, Certhub must reject the request with `409 renewal_overlap_exists`.
- If the Certificate belongs to the reserved `certhub_server` Application, this endpoint must return `409 system_managed_resource`. The server reconcile and auto-renewal processes manage that Certificate.

```http
POST /v1/certificates/{certificate_id}/renew
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body: Optional operator note or lifecycle metadata.

Expected responses:

- `202 Accepted`: renewal started or already in progress.
- `400 Bad Request`: request body is malformed or contains invalid lifecycle metadata.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User lacks lifecycle access or current Application domain scopes no longer cover the Certificate SANs.
- `404 Not Found`: certificate does not exist or is not visible.
- `409 Conflict`: certificate state does not allow renewal, including `renewal_overlap_exists` or `system_managed_resource`.

#### POST /v1/certificates/{certificate_id}/rotate-key

Summary: Start key rotation for a certificate selected by ID.

Description and notes:

- User/web-console lifecycle endpoint.
- Requires `manager` access on the Certificate's `application_id` or global `admin`.
- Requires current Application domain scopes to cover every normalized SAN on the Certificate.
- Creates a new private key and a higher-numbered CertificateVersion with reason `key_rotation`.
- Sets parent Certificate status to `rotating_key` while key rotation is in progress, unless the parent is transitioning from `revoked` or `failed` under the reissue rules.
- Key rotation follows the same replacement-overlap constraints as renewal.
- If a Certificate already has a `status=issuing` CertificateVersion with `reason=key_rotation`, this endpoint is idempotent and returns the existing in-progress key rotation.
- If a Certificate has any other `status=issuing` CertificateVersion, this endpoint returns `409 conflict` and does not create another version.
- If key rotation could result in more than two valid, not-expired CertificateVersions, Certhub must reject the request with `409 Conflict`.
- If the Certificate belongs to the reserved `certhub_server` Application, this endpoint must return `409 system_managed_resource`. Change `self_certificate.key_type` to request a new key type for Certhub's own serving certificate.

```http
POST /v1/certificates/{certificate_id}/rotate-key
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body: Optional operator note or lifecycle metadata.

Expected responses:

- `202 Accepted`: key rotation started or already in progress.
- `400 Bad Request`: request body is malformed or contains invalid lifecycle metadata.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User lacks lifecycle access or current Application domain scopes no longer cover the Certificate SANs.
- `404 Not Found`: certificate does not exist or is not visible.
- `409 Conflict`: certificate state does not allow key rotation or the Certificate is system-managed.

#### POST /v1/certificates/{certificate_id}/versions/{certificate_version_id}/revoke

Summary: Revoke one specific CertificateVersion.

Description and notes:

- User/web-console lifecycle endpoint.
- Requires `manager` access on the Certificate's `application_id` or global `admin`.
- Request body must include an explicit `reason` from the revocation reason enum. The backend must not silently default a missing revocation reason.
- Marks only the selected CertificateVersion `revoked` immediately for current material selection.
- Sets `certificate_versions.revocation_reason`, `revoked_at`, and `revoked_by_user_id` immediately.
- Attempts ACME revocation for the selected version when applicable.
- If ACME revocation fails after local revocation is accepted, local version status remains `revoked`; Certhub records failure metadata and audit events and allows retry.
- Repeating this endpoint for an already locally revoked version retries ACME revocation when `acme_revocation_status=failed` or `pending`.
- Repeating this endpoint is idempotent success when required ACME revocation has already succeeded or is marked `not_required`.
- Revocation does not delete Certificate metadata, CertificateVersion metadata, material, or audit events.
- If the Certificate belongs to the reserved `certhub_server` Application, this endpoint must return `409 system_managed_resource`. Operators change or disable the desired serving certificate through process configuration.

```http
POST /v1/certificates/{certificate_id}/versions/{certificate_version_id}/revoke
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body:

```json
{
  "reason": "key_compromise",
  "note": "Private key was exposed in CI logs"
}
```

Valid `reason` values: `key_compromise`, `superseded`, `cessation_of_operation`, `unspecified`.

Expected responses:

- `202 Accepted`: version revocation recorded and remote ACME revocation queued or retried.
- `400 Bad Request`: request body is malformed or contains an invalid revocation reason or note.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User lacks lifecycle access.
- `404 Not Found`: certificate does not exist or is not visible.
- `409 Conflict`: certificate/version state does not allow revocation or the Certificate is system-managed.

#### POST /v1/certificates/{certificate_id}/reissue

Summary: Start reissue when no active valid or issuing CertificateVersion exists.

Description and notes:

- User/web-console lifecycle endpoint.
- Requires `manager` access on the Certificate's `application_id` or global `admin`.
- Requires current Application domain scopes to cover every normalized SAN on the Certificate.
- Creates a higher-numbered CertificateVersion with reason `reissue`.
- Clears parent Certificate revocation metadata when reissuing from a revoked parent; historical CertificateVersion revocation metadata remains intact.
- Returns `409 conflict` when an active valid CertificateVersion exists or any CertificateVersion is already issuing; use renew or rotate-key for active certificates.
- If the Certificate belongs to the reserved `certhub_server` Application, this endpoint must return `409 system_managed_resource`.

```http
POST /v1/certificates/{certificate_id}/reissue
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Request body: Optional operator note or lifecycle metadata.

Expected responses:

- `202 Accepted`: reissue started.
- `400 Bad Request`: request body is malformed or contains invalid lifecycle metadata.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User lacks lifecycle access or current Application domain scopes no longer cover the Certificate SANs.
- `404 Not Found`: certificate does not exist or is not visible.
- `409 Conflict`: certificate state does not allow reissue or the Certificate is system-managed.

#### GET /v1/certificates/{certificate_id}/events

Summary: List audit events related to one certificate.

Description and notes:

- User/web-console endpoint.
- User visibility follows the Certificate ID-based access rules from `Certificate Identity and Reuse`.
- Unlike normal certificate detail APIs, this endpoint may return events for a deleted Certificate. For deleted Certificates, global admins may inspect events, and non-admin Users may inspect events only while they currently have access to the owning Application. If the Certificate does not exist or the User lacks current visibility to the owning Application, return `404 Not Found`.
- Events must include identity, action, target, timestamp, result, and HTTP metadata.

```http
GET /v1/certificates/{certificate_id}/events
Authorization: Bearer <user-access-token>
```

Query params: Optional pagination and event filters.

Request body: None.

Expected responses:

- `200 OK`: list of audit events for the certificate.
- `400 Bad Request`: invalid filter or pagination parameter.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: token is not a User access token.
- `404 Not Found`: certificate does not exist or is not visible.

#### GET /v1/users

Summary: List Users visible to the authenticated User.

Description and notes:

- Admin-only in v1.
- Used by the web console for access management.
- Each returned User includes `application_grant_count` for list views.

```http
GET /v1/users
Authorization: Bearer <user-access-token>
```

Query params: Optional pagination and search filters.

Request body: None.

Expected responses:

- `200 OK`: list of User metadata.
- `400 Bad Request`: invalid query parameter.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin.

#### GET /v1/users/lookup

Summary: Resolve one active User by exact email for grant workflows.

Description and notes:

- Used by the web console when an Application `manager` needs to grant access to a specific User but cannot list all Users.
- Global `admin` may use this endpoint without `application_id`.
- Non-admin Users must provide `application_id` and must have `manager` access to that Application.
- Lookup is exact by normalized email. It is not a prefix search or directory listing.
- Returns only minimal active User metadata needed to create an Application grant: User ID, email, display name, status, and whether the User is already granted to the requested Application.
- Disabled Users are not returned to non-admin callers.
- Responses and errors must be rate limited and audited to reduce User enumeration risk.

```http
GET /v1/users/lookup?email=user@example.com&application_id=<application-id>
Authorization: Bearer <user-access-token>
```

Query params:

- `email`: required exact User email.
- `application_id`: required for non-admin callers; optional for global `admin`.

Request body: None.

Expected responses:

- `200 OK`: minimal User metadata for the matching active User.
- `400 Bad Request`: missing or invalid email, or missing `application_id` for non-admin callers.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin and lacks `manager` access to the Application.
- `404 Not Found`: no active matching User is visible for this lookup.
- `429 Too Many Requests`: lookup is rate limited.

#### POST /v1/users

Summary: Create a one-time User invite link.

Description and notes:

- Admin-only in v1.
- Does not create the User immediately.
- Accepts the invited email and selected `global_role` only.
- Generates a raw invite token once, stores only its HMAC token hash, and returns a signup URL containing the raw token.
- The invite expires after `auth.user_invite_ttl_seconds`, default `86400`.
- Creating an invite conflicts with an existing User email or an existing active unexpired invite for the same email.
- User login sessions are created only by login endpoints, not by invite or User administration APIs.

```http
POST /v1/users
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body:

```json
{
  "email": "user@example.com",
  "global_role": "user"
}
```

Expected responses:

- `201 Created`: invite link created.
- `400 Bad Request`: invalid body.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin.
- `409 Conflict`: email already exists or has an active invite.

#### GET /v1/auth/user-invites/{invite_token}

Summary: Preview an active User invite before signup.

Description and notes:

- Public unauthenticated endpoint.
- Returns email, selected global role, expiration time, and whether password 2FA is required by instance policy.
- Missing, expired, consumed, and malformed invite tokens all return `invalid_invite`.
- Does not consume the invite.

#### POST /v1/auth/user-invites/{invite_token}/signup

Summary: Start or complete signup from an invite.

Description and notes:

- Public unauthenticated endpoint.
- Accepts `display_name` and `password`.
- Validates password policy against the invited email and stores only a password hash.
- If `auth.password.2fa_required=false`, creates an active User and consumes the invite atomically.
- If `auth.password.2fa_required=true`, stores pending signup state on the invite and returns TOTP provisioning data. The frontend must render the `provisioning_uri` as a QR code.
- The invite is not consumed until the account is completed successfully.

#### POST /v1/auth/user-invites/{invite_token}/signup/confirm-2fa

Summary: Complete invite signup after validating TOTP setup.

Description and notes:

- Public unauthenticated endpoint.
- Accepts a six-digit `totp_code`.
- Verifies the code against the pending TOTP secret before creating the User.
- On success, creates an active User with password 2FA enabled, consumes the invite atomically, and clears pending invite secrets.
- Wrong TOTP returns `invalid_2fa_code` and leaves the invite usable until expiration.
- A consumed invite cannot be reused.

Expected responses:

- `200 OK`: signup completed or TOTP setup required.
- `400 Bad Request`: invalid body.
- `401 Unauthorized`: invalid TOTP code for confirm.
- `403 Forbidden`: password authentication is disabled.
- `404 Not Found`: invite is invalid, expired, or already used.
- `409 Conflict`: User email already exists.

#### GET /v1/users/{user_id}

Summary: Return User metadata by ID.

Description and notes:

- Admin-only in v1, except future self-service views may allow reading the current User.
- Does not return raw token values.
- Returns `application_grant_count`.
- The User detail response may include `application_grants` for admin web-console detail views. These are read-only grant summaries and do not replace `/v1/applications/{application_id}/users` for managing grants.

```http
GET /v1/users/{user_id}
Authorization: Bearer <user-access-token>
```

Query params: None.

Request body: None.

Expected responses:

- `200 OK`: User metadata.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not allowed to inspect this User.
- `404 Not Found`: User does not exist.

#### PATCH /v1/users/{user_id}

Summary: Update mutable User fields.

Description and notes:

- Admin-only in v1.
- Mutable fields include display name, global role, and status. OIDC link fields are internal provider-derived state and are not mutable through this endpoint.
- Changing status to disabled prevents future authentication.
- Admin password changes use `POST /v1/users/{user_id}/password-reset-link`; direct plaintext password mutation is not accepted here.
- Admin password 2FA reset uses `DELETE /v1/users/{user_id}/password-2fa`; direct TOTP provisioning or reset flags are not accepted here.
- OIDC links must keep `(oidc_issuer, oidc_subject)` unique when written internally by the OIDC login flow.

```http
PATCH /v1/users/{user_id}
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body: Partial User update.

Expected responses:

- `200 OK`: updated User metadata.
- `400 Bad Request`: invalid body.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin.
- `404 Not Found`: User does not exist.
- `409 Conflict`: update violates uniqueness or state constraints.

#### POST /v1/users/{user_id}/password-reset-link

Summary: Create a one-time password reset link for a User.

Description and notes:

- Admin-only in v1.
- Stores only a hash of the reset token.
- A new link supersedes any active password reset link for the same User.
- The link expires after `auth.password_reset_ttl_seconds`, default `3600`.
- Must write `password_reset_link_created` without storing the raw link or token.

Expected responses:

- `200 OK`: response includes `password_reset.email`, `password_reset.expires_at`, and one-time `password_reset.reset_url`.
- `401 Unauthorized`, `403 Forbidden`, `404 Not Found` as usual.

#### DELETE /v1/users/{user_id}/password-2fa

Summary: Disable password 2FA for a User and revoke active sessions.

Description and notes:

- Admin-only in v1.
- Clears active and pending TOTP state, sets `password_2fa_enabled=false`, revokes active sessions with reason `password_2fa_reset`, and returns updated User metadata.
- Idempotent when password 2FA is already disabled.
- Must write `password_2fa_reset` without storing TOTP secrets or codes.

Expected responses:

- `200 OK`: updated User metadata.
- `401 Unauthorized`, `403 Forbidden`, `404 Not Found` as usual.

#### GET /v1/auth/password-resets/{reset_token}

Summary: Preview a password reset link without consuming it.

- Invalid, expired, consumed, or superseded links return `invalid_password_reset`.

#### POST /v1/auth/password-resets/{reset_token}

Summary: Complete a password reset.

- Validates the password policy, updates only `password_hash`, consumes the reset link, revokes active sessions with reason `password_reset`, and does not clear password 2FA.
- Invalid, expired, consumed, or superseded links return `invalid_password_reset`.

#### POST /v1/auth/password-2fa/login-setup/confirm

Summary: Complete forced password-login 2FA setup.

- Accepts `setup_token` and `totp_code`.
- Wrong TOTP returns `invalid_2fa_code` without consuming the setup token.
- Success consumes the setup token, enables password 2FA, creates a normal login session, and returns the standard token response.

#### GET /v1/applications

Summary: List Applications visible to the authenticated User.

Description and notes:

- Normal Users see only Applications where they have an explicit grant.
- Admin Users see all Applications.
- Application tokens do not use this endpoint for certificate workflows.
- Each returned Application includes web-console read-model fields needed for list views: `current_user_role`, `domain_scope_count`, `token_count`, `trusted_source_cidr_count`, `certificate_count`, and `last_used_at`.
- `current_user_role` is `admin` for global admins, otherwise the caller's explicit Application grant role. It is a read-only response field and is not stored on the Application row.

```http
GET /v1/applications
Authorization: Bearer <user-access-token>
```

Query params: Optional pagination, search, and status filters.

Request body: None.

Expected responses:

- `200 OK`: list of Application metadata.
- `400 Bad Request`: invalid query parameter.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: identity cannot list Applications.

#### POST /v1/applications

Summary: Create an Application.

Description and notes:

- Admin-only in v1.
- Applications are certificate-creating identities.
- Users have no access to newly created Applications unless granted or globally admin.
- The name `certhub_server` is reserved. Normal Application creation with that name must fail; the reserved system Application is created or protected by Certhub.

```http
POST /v1/applications
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body: Application `name`, `display_name`, optional `description`, status, and optional `trusted_source_cidrs`.

Expected responses:

- `201 Created`: Application created.
- `400 Bad Request`: invalid body.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin.
- `409 Conflict`: Application name already exists.

#### GET /v1/applications/{application_id}

Summary: Return Application metadata by ID.

Description and notes:

- Requires any explicit grant on the Application or global `admin`.
- Does not return raw Application token values.
- Returns the same Application read-model fields as `GET /v1/applications`.

```http
GET /v1/applications/{application_id}
Authorization: Bearer <user-access-token>
```

Query params: None.

Request body: None.

Expected responses:

- `200 OK`: Application metadata.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: token is not a User access token.
- `404 Not Found`: Application does not exist or is not visible.

#### PATCH /v1/applications/{application_id}

Summary: Update mutable Application fields.

Description and notes:

- Requires Application `manager` grant or global `admin`.
- Mutable fields include display name, description, status, and `trusted_source_cidrs`.
- Application `name` should remain stable after creation unless implementation explicitly allows renaming with conflict checks.
- For the reserved `certhub_server` Application, this endpoint must return `409 system_managed_resource`. The backend reconcile loop owns all mutable state for that Application.

```http
PATCH /v1/applications/{application_id}
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body: Partial Application update. `trusted_source_cidrs`, when present, replaces the full trusted source CIDR list after validation and normalization.

Expected responses:

- `200 OK`: updated Application metadata.
- `400 Bad Request`: invalid body.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User lacks manager access.
- `404 Not Found`: Application does not exist or is not visible.
- `409 Conflict`: update violates uniqueness/state constraints or the Application is system-managed.

#### POST /v1/applications/{application_id}/tokens

Summary: Create an Application token and return the raw token once.

Description and notes:

- Requires Application `manager` grant or global `admin`.
- Application tokens have no roles or permissions.
- Raw token value is shown only in this response and only the hash is stored.
- Token creation does not bypass Application `trusted_source_cidrs`; source-IP restrictions are configured on the Application and apply when the raw token is later used.
- If `expires_at` is omitted, Certhub sets the token expiration from `application_tokens.default_ttl_seconds`.
- If `expires_at` is explicitly `null`, Certhub creates a non-expiring token.
- Requested non-null token expiration must not exceed `application_tokens.max_ttl_seconds`.
- `application_tokens.max_ttl_seconds` does not apply to explicit `expires_at=null`; non-expiring tokens are allowed through normal Application token creation authorization and remain valid until revoked or the Application is disabled.
- Token creation for the reserved `certhub_server` Application must return `409 system_managed_resource` because server self-certificate sync uses internal services, not Application-token authentication.

```http
POST /v1/applications/{application_id}/tokens
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body: Token name and optional nullable expiration.

Expected responses:

- `201 Created`: token metadata and one-time raw token value.
- `400 Bad Request`: invalid body, invalid expiration, or expiration exceeds maximum lifetime.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User lacks manager access.
- `404 Not Found`: Application does not exist or is not visible.
- `409 Conflict`: token creation is not allowed for the reserved system Application.

#### GET /v1/applications/{application_id}/tokens

Summary: List Application token metadata without raw token values.

Description and notes:

- Requires Application `manager` grant or global `admin`.
- Must never return raw token values.

```http
GET /v1/applications/{application_id}/tokens
Authorization: Bearer <user-access-token>
```

Query params: Optional pagination and status filters.

Request body: None.

Expected responses:

- `200 OK`: list of token metadata.
- `400 Bad Request`: invalid query parameter.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User lacks manager access.
- `404 Not Found`: Application does not exist or is not visible.

#### POST /v1/applications/{application_id}/tokens/{token_id}/rotate

Summary: Rotate an Application token secret in place and return the raw token once.

Description and notes:

- Requires Application `manager` grant or global `admin`.
- Rotation preserves the existing token ID, name, status, and creation time.
- Rotation replaces `token_hash`, clears `last_used_at`, and returns the new raw token only in this response.
- If `expires_at` is omitted, Certhub sets the rotated token expiration from `application_tokens.default_ttl_seconds`.
- If `expires_at` is explicitly `null`, Certhub makes the rotated token non-expiring.
- Requested non-null token expiration must not exceed `application_tokens.max_ttl_seconds`.
- Revoked tokens cannot be rotated.
- Rotation for the reserved `certhub_server` Application must return `409 system_managed_resource`.

```http
POST /v1/applications/{application_id}/tokens/{token_id}/rotate
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body: Optional nullable expiration.

Expected responses:

- `200 OK`: token metadata and one-time replacement raw token value.
- `400 Bad Request`: invalid body, invalid expiration, or expiration exceeds maximum lifetime.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User lacks manager access.
- `404 Not Found`: Application or active token does not exist or is not visible.
- `409 Conflict`: token rotation is not allowed for the reserved system Application.

#### DELETE /v1/applications/{application_id}/tokens/{token_id}

Summary: Revoke an Application token.

Description and notes:

- Requires Application `manager` grant or global `admin`.
- Revoked tokens cannot authenticate.
- This operation should be idempotent for already revoked tokens.

```http
DELETE /v1/applications/{application_id}/tokens/{token_id}
Authorization: Bearer <user-access-token>
```

Query params: None.

Request body: None.

Expected responses:

- `204 No Content`: token revoked or already inactive.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User lacks manager access.
- `404 Not Found`: Application or token does not exist or is not visible.

#### POST /v1/applications/{application_id}/domain-scopes

Summary: Add an immutable domain scope to an Application.

Description and notes:

- Requires Application `manager` grant or global `admin`.
- Scope values are exact domains or valid left-most wildcards.
- Clients must not submit a separate scope type; Certhub derives `kind` from `value`.
- Scope records are immutable after creation.
- For the reserved `certhub_server` Application, this endpoint must return `409 system_managed_resource`. The backend reconcile loop derives its scope from `server.public_hostname`.

```http
POST /v1/applications/{application_id}/domain-scopes
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body:

```json
{
  "value": "*.torob.dev"
}
```

Expected responses:

- `201 Created`: domain scope created.
- `400 Bad Request`: invalid scope value.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User lacks manager access.
- `404 Not Found`: Application does not exist or is not visible.
- `409 Conflict`: scope already exists for the Application or the Application is system-managed.

#### GET /v1/applications/{application_id}/domain-scopes

Summary: List domain scopes for an Application.

Description and notes:

- Requires any explicit Application grant or global `admin`.
- Responses may include computed `kind`: `exact` or `wildcard`.
- Stored domain scopes include `application_id` and `value`; `kind` is not persisted.

```http
GET /v1/applications/{application_id}/domain-scopes
Authorization: Bearer <user-access-token>
```

Query params: Optional pagination.

Request body: None.

Expected responses:

- `200 OK`: list of domain scopes.
- `400 Bad Request`: invalid query parameter.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: token is not a User access token.
- `404 Not Found`: Application does not exist or is not visible.

#### DELETE /v1/applications/{application_id}/domain-scopes/{scope_id}

Summary: Delete an Application domain scope.

Description and notes:

- Requires Application `manager` grant or global `admin`.
- Domain scopes have no PATCH endpoint; updates are delete plus insert.
- Deleting a scope affects future Certificate creation, reuse, criteria-based material retrieval, renewal, and key-rotation authorization.
- Deleting a scope does not revoke existing certificates by itself and does not remove ID-based User access granted through the owning Application.
- For the reserved `certhub_server` Application, this endpoint must return `409 system_managed_resource`. Operators change its scope by changing `server.public_hostname`.

```http
DELETE /v1/applications/{application_id}/domain-scopes/{scope_id}
Authorization: Bearer <user-access-token>
```

Query params: None.

Request body: None.

Expected responses:

- `204 No Content`: scope deleted.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User lacks manager access.
- `404 Not Found`: Application or scope does not exist or is not visible.
- `409 Conflict`: Application is system-managed.

#### GET /v1/applications/{application_id}/users

Summary: List User grants on an Application.

Description and notes:

- Requires Application `manager` grant or global `admin`.
- Shows explicit User access only; global admin access is not represented as an Application grant.

```http
GET /v1/applications/{application_id}/users
Authorization: Bearer <user-access-token>
```

Query params: Optional pagination.

Request body: None.

Expected responses:

- `200 OK`: list of User grants.
- `400 Bad Request`: invalid query parameter.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User lacks manager access.
- `404 Not Found`: Application does not exist or is not visible.

#### PUT /v1/applications/{application_id}/users/{user_id}

Summary: Create or replace a User grant on an Application.

Description and notes:

- Requires Application `manager` grant or global `admin`.
- Role must be `viewer`, `certificate_reader`, or `manager`.
- Replaces any existing grant for the same User and Application.
- User grants cannot be assigned to the reserved `certhub_server` Application in v1. Only global admins can view it.

```http
PUT /v1/applications/{application_id}/users/{user_id}
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body:

```json
{
  "role": "certificate_reader"
}
```

Expected responses:

- `200 OK`: existing grant replaced.
- `201 Created`: new grant created.
- `400 Bad Request`: invalid role.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User lacks manager access.
- `404 Not Found`: Application or target User does not exist.
- `409 Conflict`: grants are not allowed for the reserved system Application.

#### DELETE /v1/applications/{application_id}/users/{user_id}

Summary: Remove a User grant from an Application.

Description and notes:

- Requires Application `manager` grant or global `admin`.
- Removing a grant immediately removes that User's explicit access to Application-owned certificates.
- User grants cannot exist on the reserved `certhub_server` Application in v1.
- For the reserved `certhub_server` Application, this endpoint must return `409 system_managed_resource`.

```http
DELETE /v1/applications/{application_id}/users/{user_id}
Authorization: Bearer <user-access-token>
```

Query params: None.

Request body: None.

Expected responses:

- `204 No Content`: grant removed or already absent.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User lacks manager access.
- `404 Not Found`: Application or target User does not exist.
- `409 Conflict`: Application is system-managed.

#### GET /v1/issuers

Summary: List configured ACME issuers.

Description and notes:

- Admin-only in v1.
- Issuer examples are `letsencrypt_production` and `letsencrypt_staging`.
- Applications never select ACME accounts directly.

```http
GET /v1/issuers
Authorization: Bearer <user-access-token>
```

Query params: Optional pagination and status filters.

Request body: None.

Expected responses:

- `200 OK`: list of issuer metadata.
- `400 Bad Request`: invalid query parameter.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin.

#### POST /v1/issuers

Summary: Create an ACME issuer and let Certhub create or reuse its ACME account.

Description and notes:

- Admin-only in v1.
- Certhub registers or reuses the ACME account with the CA.
- An issuer cannot be active unless a usable active ACME account exists.
- `renewal_window_seconds` may be omitted; Certhub stores default `2592000`.

```http
POST /v1/issuers
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body:

```json
{
  "name": "letsencrypt_production",
  "type": "acme",
  "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
  "default": true,
  "status": "active",
  "renewal_window_seconds": 2592000,
  "contact_email": "platform@example.com"
}
```

Expected responses:

- `201 Created`: issuer created and ACME account available.
- `400 Bad Request`: invalid body or unsupported issuer config.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin.
- `409 Conflict`: issuer name already exists or default issuer constraint is violated.

#### GET /v1/issuers/{issuer_id}

Summary: Return issuer metadata by ID.

Description and notes:

- Admin-only in v1.
- Returns operational issuer metadata and associated ACME account status.
- Must not return ACME account private keys.

```http
GET /v1/issuers/{issuer_id}
Authorization: Bearer <user-access-token>
```

Query params: None.

Request body: None.

Expected responses:

- `200 OK`: issuer metadata.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin.
- `404 Not Found`: issuer does not exist.

#### PATCH /v1/issuers/{issuer_id}

Summary: Update mutable issuer operational fields or disable an issuer.

Description and notes:

- Admin-only in v1.
- Mutable fields are `default`, `status`, `renewal_window_seconds`, and `contact_email`.
- Immutable fields are `name`, `type`, and `directory_url`; changing them requires creating a new issuer.
- Setting `status=active` requires a usable active ACME account.
- Setting `default=true` must preserve the constraint that at most one active issuer is default.
- Disabling an issuer prevents new issuance and renewal selection for that issuer but does not delete historical Certificates, CertificateVersions, ACME accounts, or audit events.

```http
PATCH /v1/issuers/{issuer_id}
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body: Partial issuer update with only mutable fields.

Expected responses:

- `200 OK`: updated issuer metadata.
- `400 Bad Request`: invalid body or immutable field attempted.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin.
- `404 Not Found`: issuer does not exist.
- `409 Conflict`: default issuer constraint or issuer activation constraint is violated.

#### GET /v1/dns-providers

Summary: List DNS provider configurations.

Description and notes:

- Admin-only in v1.
- Responses must not include provider credentials.
- DNS provider examples are `cloudflare_main` and `arvancloud_main`.

```http
GET /v1/dns-providers
Authorization: Bearer <user-access-token>
```

Query params: Optional pagination, type, zone mode, and status filters.

Request body: None.

Expected responses:

- `200 OK`: list of DNS provider metadata.
- `400 Bad Request`: invalid query parameter.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin.

#### POST /v1/dns-providers

Summary: Create a DNS provider with write-only credentials.

Description and notes:

- Admin-only in v1.
- Credentials are validated against the provider-specific typed schema, encrypted, and never returned.
- `auto` mode requires provider API support for listing zones.

```http
POST /v1/dns-providers
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body: Provider name, type, zone mode, status, and provider-specific credentials.

Expected responses:

- `201 Created`: DNS provider created.
- `400 Bad Request`: invalid body, credentials, or unsupported auto mode.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin.
- `409 Conflict`: provider name already exists.

#### GET /v1/dns-providers/{dns_provider_id}

Summary: Return DNS provider metadata by ID without credentials.

Description and notes:

- Admin-only in v1.
- Must never return raw or decrypted credentials.
- Shows zone mode, status, last successful zone refresh time, current zone refresh status, and sanitized latest zone refresh failure metadata.

```http
GET /v1/dns-providers/{dns_provider_id}
Authorization: Bearer <user-access-token>
```

Query params: None.

Request body: None.

Expected responses:

- `200 OK`: DNS provider metadata.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin.
- `404 Not Found`: DNS provider does not exist.

#### PATCH /v1/dns-providers/{dns_provider_id}

Summary: Update mutable DNS provider fields or replace credentials.

Description and notes:

- Admin-only in v1.
- Credentials are write-only; replacement accepts a new provider-specific credential payload but responses never include credentials.
- Changing `zone_mode` may affect who can write `dns_provider_zones`.

```http
PATCH /v1/dns-providers/{dns_provider_id}
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body: Partial provider update, optionally including replacement credentials.

Expected responses:

- `200 OK`: updated DNS provider metadata.
- `400 Bad Request`: invalid body or credentials.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin.
- `404 Not Found`: DNS provider does not exist.
- `409 Conflict`: update violates uniqueness or mode constraints.

#### GET /v1/dns-providers/{dns_provider_id}/zones

Summary: List active zones configured for a DNS provider.

Description and notes:

- Admin-only in v1.
- All rows in `dns_provider_zones` are considered active and valid for provider selection.
- In `auto` mode, these rows are managed only by Certhub sync.

```http
GET /v1/dns-providers/{dns_provider_id}/zones
Authorization: Bearer <user-access-token>
```

Query params: Optional pagination.

Request body: None.

Expected responses:

- `200 OK`: list of configured zones.
- `400 Bad Request`: invalid query parameter.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin.
- `404 Not Found`: DNS provider does not exist.

#### POST /v1/dns-providers/{dns_provider_id}/zones

Summary: Add a zone to a manual-mode DNS provider.

Description and notes:

- Admin-only in v1.
- Allowed only when `zone_mode=manual`.
- At most one row may exist for the same zone name across all providers.
- Applications never select DNS providers; Certhub uses longest normalized DNS-label-boundary suffix match during issuance.

```http
POST /v1/dns-providers/{dns_provider_id}/zones
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body:

```json
{
  "zone_name": "torob.dev"
}
```

Expected responses:

- `201 Created`: zone added.
- `400 Bad Request`: invalid zone name.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin or provider is auto-mode.
- `404 Not Found`: DNS provider does not exist.
- `409 Conflict`: zone already exists for this or another provider.

#### DELETE /v1/dns-providers/{dns_provider_id}/zones/{zone_id}

Summary: Delete a zone from a manual-mode DNS provider.

Description and notes:

- Admin-only in v1.
- Allowed only when `zone_mode=manual`.
- Zone records are immutable; user-facing updates are delete plus insert.

```http
DELETE /v1/dns-providers/{dns_provider_id}/zones/{zone_id}
Authorization: Bearer <user-access-token>
```

Query params: None.

Request body: None.

Expected responses:

- `204 No Content`: zone deleted.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin or provider is auto-mode.
- `404 Not Found`: DNS provider or zone does not exist.

#### GET /v1/dns-providers/{dns_provider_id}/zones/discovered

Summary: Return zones discovered from the provider API as suggestions or refresh input.

Description and notes:

- Admin-only in v1.
- Requires provider implementation and credentials that support zone listing.
- In manual mode, discovered zones are suggestions only and are not automatically added.

```http
GET /v1/dns-providers/{dns_provider_id}/zones/discovered
Authorization: Bearer <user-access-token>
```

Query params: None.

Request body: None.

Expected responses:

- `200 OK`: discovered zones.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin.
- `404 Not Found`: DNS provider does not exist.
- `409 Conflict`: provider cannot list zones or credentials are unusable.

#### POST /v1/dns-providers/{dns_provider_id}/zones/refresh

Summary: Refresh auto-mode DNS provider zones from the provider API.

Description and notes:

- Admin-only in v1.
- Allowed only when `zone_mode=auto`.
- Starts a durable asynchronous zone refresh job and returns job metadata.
- If a refresh job is already pending or running for the provider, this endpoint is idempotent and returns the existing active job.
- The worker replaces the provider's zone rows with the discovered zone list only after discovery succeeds and conflict checks pass.
- If discovery fails, Certhub records `dns_zone_discovery_failed` and must not silently remove existing zones.
- If the discovered zone list conflicts with an active zone owned by another DNS provider, Certhub must fail the refresh job transaction, preserve the previous zone list unchanged, and store structured conflict details naming the conflicting zone and provider IDs.
- The web UI observes refresh progress from DNS provider metadata and the returned refresh job status.

```http
POST /v1/dns-providers/{dns_provider_id}/zones/refresh
Authorization: Bearer <user-access-token>
Content-Type: application/json
```

Query params: None.

Request body: Optional operator note.

Expected responses:

- `202 Accepted`: refresh job started or an existing active refresh job is returned.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin or provider is manual-mode.
- `404 Not Found`: DNS provider does not exist.
- `409 Conflict`: provider already has a terminal conflict state that requires admin action (`dns_provider_zone_conflict`).
- `503 Service Unavailable`: worker queue is unavailable.

#### GET /v1/audit-events

Summary: List audit events with filters.

Description and notes:

- Admin Users may query global audit events.
- Non-admin Users may query only scoped audit events for Applications they can access and related resources, such as Certificates owned by those Applications.
- Non-admin queries must include a scope filter such as `application_id` or `certificate_id`; unscoped global audit listing requires global `admin`.
- Scoped responses must redact or omit targets, metadata, and identity details that are outside the User's visible resources.
- Audit events must include identity type, identity ID, action, target, timestamp, result, and HTTP metadata.
- Required event names are defined in the `audit_events` data model section and must stay stable.

```http
GET /v1/audit-events
Authorization: Bearer <user-access-token>
```

Query params: Optional pagination plus filters for time range, identity, action, target, result, certificate, Application, and HTTP correlation ID.

Request body: None.

Expected responses:

- `200 OK`: list of audit events.
- `400 Bad Request`: invalid filter or pagination parameter.
- `401 Unauthorized`: token is missing or invalid.
- `403 Forbidden`: User is not an admin for global queries, or requested scoped resources are not visible.

## Issuance Flow

Issuance, renewal, key rotation, revocation retry, and DNS challenge cleanup are durable database-backed jobs. V1 must be safe when multiple server replicas or worker processes are running, even if the initial deployment uses one replica.

Worker rules:

- Workers claim jobs through PostgreSQL row-level locking or an equivalent lease pattern, such as `SELECT ... FOR UPDATE SKIP LOCKED`.
- Each claimed job must record `locked_by` and `locked_until`.
- Expired leases are reclaimable by another worker.
- Completed issuance steps must be idempotent when retried after a worker crash.
- DNS challenge cleanup must use the recorded TXT record names and exact TXT values from the database, not recompute or guess them from current order state.
- There must be at most one active issuance job for one CertificateVersion, and at most one CertificateVersion with `status=issuing` per Certificate.
- Workers must append operational `certificate_events` as significant issuance steps occur, including CertificateVersion load/create/attach, private-key readiness, ACME order create/fetch/finalize, authorization fetch, DNS challenge record create/reuse, DNS presentation, DNS propagation, ACME challenge accept, DNS cleanup queueing, material storage, and failure points. These events must include non-secret structured metadata sufficient for operators to identify the failing provider, zone, authorization, job attempt, and root-cause phase. Failures caused by the active-valid-CertificateVersion limit must be recorded as an actionable version-overlap failure, including active/max version counts.

1. Application client calls `POST /v1/sync/certificates/tls-material` or `POST /v1/sync/certificates/tls-archive` with the complete certificate criteria.
2. Backend derives the Application from the token, normalizes domains, checks Application domain-scope coverage, and computes the certificate identity.
3. If a matching ready certificate exists and `If-None-Match` matches its `material_etag`, backend returns `204 No Content` for criteria-based endpoints without a `private_key_read` audit event. The flow ends.
4. If a matching ready certificate exists and material is needed, backend returns the latest valid CertificateVersion material, includes `ETag: <material_etag>`, and writes a `private_key_read` audit event. The flow ends.
5. If no matching certificate identity exists, backend returns `404 certificate_not_found`.
6. Application client calls `POST /v1/sync/certificates` with the same criteria.
7. Backend repeats validation and identity computation, creates or reuses the Certificate row for the authenticated Application, enqueues issuance when needed, and returns Certificate status metadata only.
8. Application client does not poll any separate request resource for readiness. It periodically retries the same `POST /v1/sync/certificates/tls-material` or `POST /v1/sync/certificates/tls-archive` call with the same criteria.
9. While issuance is pending, material/archive endpoints return `409 certificate_not_ready` with current status metadata and retry guidance.
10. Issuer worker loads the Certhub-managed ACME account for the selected issuer.
11. Issuer worker creates an ACME order through lego.
12. For each ACME DNS-01 authorization, Certhub selects the DNS provider zone by longest normalized DNS-label-boundary suffix match against that authorization's DNS name.
13. One certificate order may use multiple DNS provider zones, provider accounts, or DNS provider implementations when SANs span zones. For example, a single Certificate may include one SAN whose authorization is presented through Cloudflare and another SAN whose authorization is presented through ArvanCloud. Every required authorization must have exactly one matching active zone, otherwise issuance fails with `dns_provider_not_found`.
14. lego calls each selected DNS provider `Present` to create the required `_acme-challenge` TXT records through Cloudflare or ArvanCloud.
15. Certhub must durably track each presented challenge record name, DNS provider, provider zone, and exact TXT value before validation is attempted.
16. Issuer worker waits for DNS propagation with the resolver configured for the selected DNS provider type, records resolver metadata and sanitized lookup failures in CertificateVersion events, and then asks Let's Encrypt to validate.
17. Issuer worker finalizes the order and stores certificate material, including `material_etag`, in a new CertificateVersion.
18. Issuer worker deletes DNS challenge records through lego `CleanUp` for each provider/zone used. Cleanup must remove only the exact TXT values Certhub presented for this order and must preserve unrelated `_acme-challenge` values.
19. Certificate status becomes `ready`.
20. The next material/archive retry returns the latest valid material or `204 No Content` if `If-None-Match` already matches.
21. If issuance fails, material/archive retries return `409 certificate_issuance_failed` with failure metadata; clients should stop after their own timeout or failure policy.

Every step from CertificateVersion creation or reuse through material storage or failure must be visible through `GET /v1/certificates/{certificate_id}/versions/{certificate_version_id}/events`. This timeline is operational state, not an audit log. It must be safe for managers to inspect when troubleshooting DNS propagation, issuer, provider, or ACME failures.

Web-console Certificate creation uses the same issuance and reconciliation path:

1. User with Application `manager` access or global `admin` calls `POST /v1/applications/{application_id}/certificates` with complete certificate criteria.
2. Backend loads the URL Application, normalizes domains, checks that every SAN is covered by that Application's domain scopes, and computes the certificate identity from URL Application ID, normalized SANs, key type, and issuer.
3. Backend creates or reuses the Certificate row for that Application and enqueues issuance when needed.
4. The web console refreshes `GET /v1/certificates/{certificate_id}` or certificate events to show readiness and failure state.
5. When material is needed and the User has `certificate_reader`, `manager`, or global `admin`, the web console uses the ID-based archive endpoint. It must not use criteria-based Application-token material endpoints.

## CertificateVersion Reconciliation

Creating or reusing a Certificate row creates an internal Certhub responsibility to make the Certificate usable. Clients never create CertificateVersions directly and never call ACME, DNS provider, renewal, or repair APIs to make a CertificateVersion exist.

Certhub must reconcile every non-deleted Certificate as follows:

1. If the Certificate has a latest valid retrievable CertificateVersion outside the renewal window, no issuance work is required.
2. If the Certificate has no valid retrievable CertificateVersion and no CertificateVersion with `status=issuing`, Certhub must create or enqueue exactly one issuing CertificateVersion when the Certificate state is eligible under the issuance, renewal, or reissue rules.
3. For a newly created Certificate, the first issuing CertificateVersion uses `version=1` and `reason=initial_issue`.
4. If an issuing CertificateVersion already exists, reconciliation must not create another issuing version for the same Certificate.
5. If issuance fails, Certhub records failure metadata on the Certificate, failed CertificateVersion, and issuance job. Retry behavior must be explicit policy; automatic retry must still preserve the one-issuing-version and one-active-job constraints.
6. If an active valid CertificateVersion enters the renewal window, the background renewal worker must enqueue renewal when no issuing CertificateVersion already exists.
7. If no active valid CertificateVersion exists, reconciliation must not enqueue renewal or key rotation; explicit User reissue is required.
8. Reconciliation must never violate the valid-version overlap limits from `Auto Renewal Process` and `certificate_versions`.

Failed issuing jobs:

- A worker crash before terminal state leaves the job claim to expire. Another worker may reclaim it and continue or fail it after checking durable step state.
- A provider, ACME, validation, or internal error transitions the job to `failed` and the CertificateVersion to `failed`, unless an older valid version keeps the parent Certificate in `ready` as described in `Status Values`.
- Automatic retries, when implemented, must create a new job attempt for the same issuing CertificateVersion or retry the same failed job only after acquiring a fresh lease. They must not create a second issuing CertificateVersion for the same Certificate.
- Manual retry through lifecycle endpoints must follow the failed-state reissue rules and overlap constraints.
- DNS cleanup must still be attempted after issuance failure when TXT records were presented. Cleanup failure is recorded separately and must not resurrect material serving.

Material/archive endpoints expose reconciliation state only as normal lookup responses. Response priority is:

1. `200 OK` or `204 No Content` when valid material is available.
2. `409 certificate_not_ready` when no valid material is available and a CertificateVersion with `status=issuing` exists, including post-expiry reissue.
3. `409 certificate_issuance_failed` when no valid material is available and the latest issuance, renewal, reissue, or key rotation failed.
4. `409 certificate_no_active_version` when no active valid material is available, no CertificateVersion with `status=issuing` exists, and the latest work is not a failed issuing attempt.

## Auto Renewal Process

1. Certhub must evaluate Certificates for renewal before expiry using the selected issuer's `renewal_window_seconds`.
2. When the latest valid CertificateVersion enters the renewal window, Certhub must enqueue renewal automatically when the Certificate is enabled, the issuer is active, current Application domain scopes still cover every SAN, no issuing CertificateVersion exists, and replacement-overlap constraints allow it.
3. Auto renewal must be idempotent. For one Certificate, there must be at most one in-progress CertificateVersion with `status=issuing` at any time, including initial issuance, renewal, and key rotation.
4. Renewal creates a higher-numbered CertificateVersion for the same Certificate identity. It does not create a new Certificate row.
5. Every newly created CertificateVersion gets a fresh private key. Retrying the same in-progress issuing CertificateVersion reuses that version's already persisted private key.
6. While renewal is in progress and the current CertificateVersion is still inside its validity window, material/archive endpoints must continue returning that current valid version.
7. If renewal fails while an older CertificateVersion is still valid, material/archive endpoints must still return the older valid version. The renewal failure must be visible through Certificate metadata, CertificateVersion metadata, and audit events, but it must not break material retrieval until no valid version remains.
8. After renewal succeeds, material/archive endpoints must return the renewed CertificateVersion because it has the highest valid `version`.
9. A Certificate must have at most one valid, not-expired CertificateVersion outside a replacement overlap.
10. A replacement overlap starts when renewal or key rotation is created while an older CertificateVersion is still valid and ends when the older CertificateVersion expires.
11. During replacement overlap, a Certificate may temporarily have two valid, not-expired CertificateVersions: the older version that is still usable and the newly issued replacement version.
12. A Certificate must never have more than two valid, not-expired CertificateVersions.
13. Manual renewal and key rotation use the same overlap constraints. If manual renewal would create more than two valid, not-expired CertificateVersions, Certhub must reject it with `409 renewal_overlap_exists`. If key rotation would create more than two valid, not-expired CertificateVersions, Certhub must reject it with `409 Conflict`.
14. Old valid CertificateVersions may remain stored until their natural `not_after`, but API material endpoints must always return the latest valid CertificateVersion.
15. Expired CertificateVersions must never be returned from `tls-material` or `tls-archive`.
16. If a certificate identity exists but no active valid CertificateVersion exists and no issuing CertificateVersion exists, material/archive endpoints return `409 certificate_no_active_version`.
17. `409 certificate_no_active_version` is not retryable. A User with lifecycle access must start `POST /v1/certificates/{certificate_id}/reissue`.
18. Application clients must handle `409 certificate_no_active_version` as a terminal cycle failure. They must not call `POST /v1/sync/certificates` unless material/archive lookup returns `404 certificate_not_found`.

## Observability

Certhub must expose enough operational signal to detect certificate expiry risk, issuance failures, DNS provider failures, authentication problems, and queue stalls before clients lose valid material.

Health and metrics endpoints:

- `GET /healthz` is a liveness endpoint and must be cheap, unauthenticated, and dependency-light.
- `GET /readyz` is a readiness endpoint and must check PostgreSQL connectivity, migration compatibility, encryption key availability, and required process configuration.
- `GET /metrics` exposes Prometheus metrics for internal scraping and must not expose secrets or high-cardinality raw domain labels.

Logging requirements:

- Logs must be structured JSON.
- Every HTTP request log must include timestamp, level, method, path template, status, latency, correlation ID, identity type, identity ID when authenticated, and error code when applicable.
- Worker logs must include job type, Certificate ID, CertificateVersion ID when available, issuer ID, DNS provider ID when available, result, duration, correlation ID or job ID, and error code when applicable.
- Logs must redact private keys, raw tokens, passwords, DNS provider credentials, ACME account keys, and encrypted secret payloads.

Secret redaction and external error sanitization:

- Certhub must sanitize all externally sourced error strings before storing them in `failure_message`, audit metadata, logs, or public API responses.
- Certificate issuance failures must persist the sanitized actual root-cause error text in `failure_message` on the failed job and failed CertificateVersion, and on the parent Certificate when no active valid material remains.
- `certificate_issuance_failed` audit events must include sanitized failure metadata sufficient for operators to troubleshoot: stable `failure_code`, sanitized `failure_message`, job reason, job attempt, retryable flag, and resulting job status.
- Sanitization must redact Authorization and Cookie headers, raw Application tokens, raw User access tokens, passwords, TOTP codes, TOTP secrets, provisioning URIs, OIDC authorization codes, OIDC state values, OIDC code verifiers, private keys, ACME account keys, DNS provider credentials, and encrypted payloads.
- Sanitization must apply before persistence, not only at render time.
- Public `failure_message` values should prefer stable, non-secret summaries. Full provider responses may be logged only after the same sanitizer runs.

Required metrics:

- `certhub_certificates_total{status,issuer_id}`.
- `certhub_certificate_versions_total{status,reason,issuer_id}`.
- `certhub_certificate_expires_in_seconds{issuer_id}` as a histogram or gauge family without domain labels.
- `certhub_issuance_jobs_total{result,reason,issuer_id,dns_provider_type}`.
- `certhub_issuance_duration_seconds{result,reason,issuer_id}`.
- `certhub_dns_challenge_duration_seconds{result,dns_provider_type}`.
- `certhub_worker_jobs_in_progress{job_type}`.
- `certhub_worker_queue_depth{job_type}`.
- `certhub_worker_oldest_queued_seconds{job_type}`.
- `certhub_http_requests_total{method,path,status,error_code}` using route templates, not raw paths.
- `certhub_auth_attempts_total{method,result}`.
- `certhub_private_key_reads_total{result}`.
- `certhub_server_self_certificate_sync_total{result,reason}`.
- `certhub_server_self_certificate_last_success_timestamp_seconds`.
- `certhub_acme_requests_total{issuer_id,result}`.
- `certhub_dns_provider_requests_total{provider_type,result}`.

Recommended alerts:

- A Certificate has no valid CertificateVersion and is not successfully issuing.
- A Certificate enters the renewal window and renewal has not succeeded before an operator-defined deadline.
- A Certificate will expire soon and no newer valid CertificateVersion exists.
- An issuing CertificateVersion is older than the ACME order timeout plus operational margin.
- Worker queue depth or oldest queued age exceeds operational limits.
- DNS provider errors, ACME errors, rate limits, or authentication failures exceed baseline.
- Readiness fails for PostgreSQL, migration compatibility, encryption key, or required process configuration.
- Decryption failures occur for stored sensitive payloads.

## Data Model

The database is PostgreSQL. Use UUIDs for primary keys unless the implementation chooses a stronger local ID convention. All timestamp fields are UTC `timestamptz`.

PostgreSQL type mapping:

- `string` maps to `text` with explicit application validation and database checks where useful.
- `string array` maps to `text[]`.
- `cidr array` maps to PostgreSQL `cidr[]`.
- `JSON object` maps to `jsonb`.
- `encrypted text` and `encrypted JSON object` store the authenticated encryption envelope defined in `Database Encryption Envelope` as `bytea` or `text`; the implementation must choose one representation consistently.
- `enum` may be implemented as PostgreSQL enum types or checked `text`; either way, invalid values must be rejected at the database boundary.

### String Validation

Backend validation is authoritative for strings supplied by external clients, including web users, CLI users, Application API clients, and Kubernetes CR authors. User-provided non-human strings must be validated at the API boundary before they are used or persisted. Except where a format explicitly defines normalization, user-provided machine-oriented strings must reject leading/trailing whitespace, control characters, and non-ASCII characters.

Human-facing strings such as `display_name`, token `name`, `description`, and `failure_message` are not machine identifiers. They must still have length limits and must reject NUL/control characters, but they do not use the machine-name validators below.

Reusable formats:

| Format | Validation |
| --- | --- |
| `machine_name` | Length 1-64. Regex: `^[a-z](?:[a-z0-9_]{0,62}[a-z0-9])?$`. Lowercase ASCII only. Used for stable operator-chosen names. Hyphen is not allowed. |
| `base64_32_bytes` | Strict RFC 4648 base64 with no whitespace. Decoded value must be exactly 32 bytes. |
| `secret_string` | Length 1-4096. Reject NUL and control characters. Provider-specific validators may add stricter checks when the provider documents a stable token format. |
| `dns_name` | Normalize by lowercasing, trimming one trailing dot, and converting IDNs to ASCII punycode. Stored value must be 1-253 octets, contain at least two labels, have labels 1-63 octets, and each label must match `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`. No wildcard. |
| `dns_txt_owner_name` | DNS owner name for generated TXT records. Normalize like `dns_name`, but labels may also start with `_` when required by DNS protocols, such as `_acme-challenge`. No wildcard. |
| `wildcard_dns_name` | Normalized DNS name with exactly one wildcard label: `*.` followed by a valid `dns_name`. `*` must be the full left-most label. Values such as `*.*.torob.dev`, `a.*.torob.dev`, and `api.*.torob.dev` are invalid. |
| `certificate_identifier` | Either `dns_name` or `wildcard_dns_name`. Must be acceptable for public TLS issuance. |
| `email` | Lowercase normalized mailbox address, max 254 characters, parsed with an email parser. No display-name form. |
| `https_url` | Absolute `https://` URL, max 2048 characters, valid host, no username/password, no fragment. |
| `outbound_proxy_url` | Absolute `http://` or `https://` URL, max 2048 characters, valid host, optional port, optional username/password, no path other than empty or `/`, no query, and no fragment. `https://` means TLS to the proxy itself. |
| `ip_or_cidr` | IPv4 address, IPv6 address, IPv4 CIDR, or IPv6 CIDR. Exact IP inputs normalize to single-host CIDRs. CIDR inputs normalize to canonical network form and must reject invalid prefix lengths, hostnames, empty strings, whitespace, and control characters. |
| `correlation_id` | Length 1-128. Regex: `^[A-Za-z0-9._:-]+$`. If an inbound correlation ID is invalid, Certhub must generate a valid internal one instead of persisting the invalid value. |
| `token_secret_v1` | Exactly 43 base64url characters without padding. Regex: `^[A-Za-z0-9_-]{43}$`. Generated from 32 random bytes. |
| `certhub_token_v1` | One of `cth_app_v1_<token_secret_v1>` or `cth_uat_v1_<token_secret_v1>`. |

API schemas should distinguish raw input strings from normalized stored/output strings for DNS-derived formats. Request schemas may accept normalizable uppercase, trailing-root-dot, and IDN values where this section says the backend normalizes them; response schemas must return normalized lowercase ASCII/punycode values without a trailing root dot.

Reusable enums:

| Enum | Values |
| --- | --- |
| `key_type` | `rsa-2048`, `rsa-3072`, `rsa-4096`, `ecdsa-p256`, `ecdsa-p384` |

### `users`

Human identities.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable User ID. |
| `email` | string | Required, unique, format `email` | User login/email. |
| `display_name` | string | Required, length 1-255, no control characters | Human-readable name. |
| `password_hash` | string | Nullable | Argon2id PHC password hash. Null means password login is not available for this User. |
| `password_2fa_enabled` | boolean | Required, default `false` | Whether password login requires TOTP for this User. Applies only to password auth. |
| `totp_secret_encrypted` | encrypted text | Nullable | Active TOTP secret encrypted with Certhub encryption key. Required when `password_2fa_enabled=true`. |
| `pending_totp_secret_encrypted` | encrypted text | Nullable | Pending TOTP setup secret encrypted with Certhub encryption key until confirmation. |
| `oidc_issuer` | string | Nullable, format `https_url`, internal-only | OIDC issuer this User is linked to. Written only by the OIDC login flow. |
| `oidc_subject` | string | Nullable, length 1-255, no control characters, internal-only | Stable OIDC subject value from the issuer. Written only by the OIDC login flow. |
| `global_role` | enum | Required, one of `user`, `admin`; default `user` | Global User privilege level. |
| `status` | enum | Required, one of `active`, `disabled`; default `active` | Disabled Users cannot authenticate. |
| `created_at` | timestamptz | Required | Creation time. |
| `updated_at` | timestamptz | Required | Last metadata update. |
| `last_login_at` | timestamptz | Nullable | Last successful web or token authentication. |

Constraints:

- `(oidc_issuer, oidc_subject)` must be unique when both values are non-null.
- `oidc_issuer` and `oidc_subject` must not be set, replaced, or cleared from human-admin APIs, bootstrap flags, or the web UI.
- `password_hash` must be written only by Certhub after password policy validation and Argon2id hashing; plaintext passwords must never be stored.
- `totp_secret_encrypted` and `pending_totp_secret_encrypted` must never be returned by list/detail APIs, logs, or audit metadata.
- If `auth.password.2fa_required=true`, Users with `password_hash` must have `password_2fa_enabled=true` before password login can create a session.
- OIDC login ignores `password_2fa_enabled` and does not require TOTP.

### `user_invites`

One-time signup invitations created by admins.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable invite row ID. |
| `email` | string | Required, normalized email | Email address that will become the User email. |
| `global_role` | enum | Required, one of `user`, `admin`; default `user` | Role assigned after signup completes. |
| `token_hash` | string | Required, unique | HMAC-SHA-256 hash of the raw invite token. Raw invite tokens are never stored. |
| `status` | enum | Required, one of `active`, `consumed`, `expired`; default `active` | Active invites may be used until expiry; consumed invites cannot be reused. |
| `created_by_user_id` | UUID | Required, foreign key to `users.id` | Admin that generated the invite. |
| `created_user_id` | UUID | Nullable, foreign key to `users.id` | User created when the invite is consumed. |
| `pending_*` | mixed | Nullable | Pending display name, password hash, User ID, and encrypted TOTP secret for forced-2FA signup. |
| `created_at` | timestamptz | Required | Invite creation time. |
| `expires_at` | timestamptz | Required | Invite expiration time. |
| `consumed_at` | timestamptz | Nullable | Successful signup completion time. |

Constraints:

- `token_hash` must be derived from the full raw invite token including the `cth_inv_v1_` prefix.
- Pending signup state must be cleared when the invite is consumed.
- Raw invite tokens, TOTP secrets, TOTP codes, and invite URLs must never be written to logs or audit metadata.

### `user_sessions`

Login sessions for human Users. User access tokens are opaque random bearer secrets, not JWTs. Access tokens are short-lived and used for User-authenticated API calls and pre-expiry rotation. The absolute session deadline is fixed at login.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable session ID. It must not be encoded into a self-contained token. |
| `user_id` | UUID | Required, foreign key to `users.id`, indexed | User that owns the login session. |
| `auth_method` | enum | Required, one of `password`, `oidc` | Login method that created the session. |
| `access_token_hash` | string | Required, unique | HMAC-SHA-256 hash of the full current opaque access token value, including `cth_uat_v1_` prefix. Raw access tokens are never stored. |
| `status` | enum | Required, one of `active`, `revoked`; default `active` | Revoked sessions cannot authenticate or refresh. |
| `created_at` | timestamptz | Required | Creation time. |
| `access_expires_at` | timestamptz | Required | Expiry of the most recently issued access token for this session. |
| `session_expires_at` | timestamptz | Required | Fixed absolute login-session expiry. |
| `last_refreshed_at` | timestamptz | Nullable | Last successful refresh time. |
| `last_used_at` | timestamptz | Nullable | Last successful API use by an access token from this session. |
| `revoked_at` | timestamptz | Nullable | Session revocation time. |
| `revoked_reason` | enum | Nullable, one of `logout`, `disabled_user`, `token_reuse`, `admin_action`, `expired`, `password_reset`, `password_2fa_reset`, `auth_model_migration` | Why the session was revoked or closed. |
| `user_agent` | string | Nullable, max length 1024, no control characters | Optional login client User-Agent for audit and troubleshooting. |
| `source_ip` | string | Nullable | Derived effective login source IP when available. |

Constraints:

- Raw access tokens must never be stored.
- Access-token authentication must hash the presented opaque token and look up an active, unexpired `user_sessions` row by `access_token_hash`.
- `session_expires_at` must be greater than `access_expires_at`.
- Expired, revoked, or disabled-User sessions must not authenticate.
- Access token rotation must update `access_token_hash`, `access_expires_at`, and `last_refreshed_at` atomically without changing `session_expires_at`.
- Reuse of an old access token after rotation must revoke the session with `revoked_reason=token_reuse`.

### `user_session_token_history`

Access-token history for detecting reuse after rotation.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable token-history ID. |
| `user_session_id` | UUID | Required, foreign key to `user_sessions.id`, indexed | Session that issued this access token. |
| `access_token_hash` | string | Required, unique | HMAC-SHA-256 hash of the full access token value, including `cth_uat_v1_` prefix. |
| `status` | enum | Required, one of `active`, `rotated`, `revoked`, `reused`, `expired`; default `active` | Access-token state. |
| `issued_at` | timestamptz | Required | Time the access token was issued. |
| `access_expires_at` | timestamptz | Required | Access token expiry. |
| `rotated_at` | timestamptz | Nullable | Time the token was replaced by a newer access token. |
| `last_seen_at` | timestamptz | Nullable | Last time this token hash was presented. |

Constraints:

- Each User session may have at most one `active` token-history row.
- `user_sessions.access_token_hash` must match the active row for the session.
- On refresh, Certhub must mark the old active row `rotated`, insert a new active row, and update `user_sessions.access_token_hash` atomically.
- If a presented access token matches a `rotated`, `revoked`, `reused`, or `expired` row, Certhub must revoke the parent `user_sessions` row with `revoked_reason=token_reuse`.
- History rows must not contain raw access tokens.

### `oidc_login_states`

Pending OIDC PKCE login state.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable pending-login ID. |
| `state_hash` | string | Required, unique | HMAC-SHA-256 hash of the opaque OIDC `state` value. Raw state is not stored. |
| `nonce` | string | Required, length 22-256 | OIDC nonce sent in the authorization request; must contain at least 128 bits of entropy. |
| `code_verifier_encrypted` | encrypted text | Required | PKCE code verifier encrypted with Certhub encryption key. |
| `provider_callback_url` | string | Required, format `https_url` | Exact callback URL used with the provider; must equal `auth.oidc.redirect_url`. |
| `frontend_return_url` | string | Nullable, format `https_url` | Validated frontend return URL after login. |
| `expires_at` | timestamptz | Required | Pending login expiry; recommended maximum is 10 minutes. |
| `consumed_at` | timestamptz | Nullable | Set when callback consumes the state. |
| `created_at` | timestamptz | Required | Creation time. |
| `source_ip` | string | Nullable | Derived effective login source IP when available. |
| `user_agent` | string | Nullable, max length 1024, no control characters | Login client User-Agent when available. |

Constraints:

- Pending OIDC state is single-use. Callback must set `consumed_at` or delete the row atomically before issuing a User session.
- Expired or consumed states must be rejected.
- `state_hash` must be computed with `oidc_state_hash_key` and compared in constant time.
- `code_verifier_encrypted` must never be logged or returned.
- `frontend_return_url`, when provided, must match `auth.oidc.allowed_return_urls` or the default same-origin rule.

### `oidc_login_handoffs`

Short-lived single-use bridge from the backend-owned OIDC callback to the browser frontend route.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable handoff row ID. |
| `handoff_hash` | string | Required, unique | HMAC-SHA-256 hash of the raw opaque handoff ID. Raw handoff IDs are never stored. |
| `user_id` | UUID | Required, foreign key to `users.id`, indexed | User that will receive a login session if the handoff is consumed. |
| `oidc_login_state_id` | UUID | Nullable, foreign key to `oidc_login_states.id` | Consumed OIDC login state that created this handoff, when retained for traceability. |
| `frontend_return_url` | string | Nullable, format `https_url` | Validated frontend callback/return URL used after provider callback succeeds. |
| `status` | enum | Required, one of `active`, `consumed`, `expired`; default `active` | Handoff lifecycle state. |
| `created_at` | timestamptz | Required | Creation time. |
| `expires_at` | timestamptz | Required | Handoff expiry; recommended maximum is 120 seconds. |
| `consumed_at` | timestamptz | Nullable | Time the frontend exchanged the handoff for Certhub tokens. |
| `source_ip` | string | Nullable | Derived effective source IP from the callback when available. |
| `user_agent` | string | Nullable, max length 1024, no control characters | Browser User-Agent when available. |

Constraints:

- Handoffs are single-use. `POST /v1/auth/oidc/handoff` must atomically mark the row consumed before returning User access tokens.
- Expired, consumed, reused, unknown, or malformed handoffs must not create a User session.
- Handoff IDs must have at least 128 bits of entropy; 256 bits is recommended.
- Raw handoff IDs must not be logged, audited, stored, or retained in browser history after frontend handling.

### `applications`

Certificate-owning identities.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable Application ID. |
| `name` | string | Required, unique, format `machine_name` | Machine-friendly Application name. |
| `display_name` | string | Required, length 1-255, no control characters | Human-readable Application name. |
| `status` | enum | Required, one of `active`, `disabled`; default `active` | Disabled Applications cannot authenticate or create certificates. |
| `system_kind` | enum | Nullable, one of `certhub_server`; default null | Marks reserved system Applications. Null means a normal User-created Application. |
| `description` | string | Nullable, max length 2048, no control characters | Optional operator context. |
| `trusted_source_cidrs` | cidr array | Required, default empty array | Optional source IP/CIDR restriction for Application-token authentication. Empty means any source IP may use a valid token. Exact IP inputs are normalized to `/32` for IPv4 or `/128` for IPv6. |
| `created_at` | timestamptz | Required | Creation time. |
| `updated_at` | timestamptz | Required | Last metadata update. |

Constraints:

- `trusted_source_cidrs` API input values must use `ip_or_cidr` format and must be stored as valid IPv4 or IPv6 CIDRs after normalization.
- `trusted_source_cidrs` must not contain duplicates after canonical normalization.
- `trusted_source_cidrs` restrict only Application-token authentication for this Application. They do not grant access and do not affect User-authenticated management APIs.
- When `trusted_source_cidrs` is non-empty, a valid token from a source IP outside every configured CIDR must not authenticate.
- `system_kind=certhub_server` requires `name='certhub_server'`.
- `name='certhub_server'` requires `system_kind=certhub_server`.
- Normal Application create/update APIs cannot set or clear `system_kind`.
- The reserved system Application cannot be renamed, patched, disabled, or deleted through public APIs in v1.
- The reserved system Application's desired state is reconciled by the backend from process configuration, not by User or Application API calls.

### `application_tokens`

Bearer tokens used by Applications, CI jobs, and operators. Application tokens use the `cth_app_v1_<secret>` structure and do not carry roles or permissions.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable token ID. |
| `application_id` | UUID | Required, foreign key to `applications.id`, indexed | Application that owns the token. |
| `name` | string | Required, length 1-128, no control characters | Human-readable token name. |
| `token_hash` | string | Required, unique | HMAC-SHA-256 hash of the full Application token value, including `cth_app_v1_` prefix; raw token is shown only once. |
| `status` | enum | Required, one of `active`, `revoked`; default `active` | Revoked tokens cannot authenticate. |
| `created_at` | timestamptz | Required | Creation time. |
| `expires_at` | timestamptz | Nullable | Expiration time. Null means the token does not expire by time. Defaults from `application_tokens.default_ttl_seconds` when omitted during token creation. |
| `last_used_at` | timestamptz | Nullable | Last successful use. |
| `revoked_at` | timestamptz | Nullable | Revocation time. |

Constraints:

- Revoked, expired, or disabled-Application tokens must not authenticate.
- `expires_at`, when non-null and `expires_at <= now`, makes the token expired.
- `expires_at`, when non-null, must not exceed `application_tokens.max_ttl_seconds` from creation or rotation time.
- Null `expires_at` is allowed, intentionally bypasses `application_tokens.max_ttl_seconds`, and means the token is non-expiring until revoked or the Application is disabled.
- Tokens must not be created for Applications with `system_kind=certhub_server`.

### `application_user_grants`

Explicit User access to Applications.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable grant ID. |
| `application_id` | UUID | Required, foreign key to `applications.id`, indexed | Application being granted. |
| `user_id` | UUID | Required, foreign key to `users.id`, indexed | User receiving access. |
| `role` | enum | Required, one of `viewer`, `certificate_reader`, `manager` | User role for this Application. |
| `created_at` | timestamptz | Required | Grant creation time. |
| `created_by_user_id` | UUID | Nullable, foreign key to `users.id` | User/admin that created the grant. |

Constraints:

- `(application_id, user_id)` must be unique.
- Grants must not be created for Applications with `system_kind=certhub_server`.

### `domain_scopes`

Domains an Application may request.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable scope ID. |
| `application_id` | UUID | Required, foreign key to `applications.id`, indexed | Application that owns the scope. |
| `value` | string | Required, format `certificate_identifier` | Exact domain or valid left-most wildcard, such as `api.torob.dev` or `*.torob.dev`. |
| `created_at` | timestamptz | Required | Creation time. |
| `created_by_user_id` | UUID | Nullable, foreign key to `users.id` | User/admin that created the scope. |

Constraints: `(application_id, value)` must be unique. Wildcards must be valid public CA style: only one full left-most `*` label is allowed. Values at public-suffix boundaries, such as `com`, `*.com`, `co.uk`, and `*.co.uk`, must be rejected. The entire record is immutable after creation. `kind` is a computed API/UI value, not a stored field. For `system_kind=certhub_server`, the row is a server-managed projection row derived from `server.public_hostname`; public APIs must not create or delete it.

### `certificates`

Stable logical certificate identities.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable Certificate ID. |
| `enabled` | boolean | Required, default `true` | Whether new initial issuance, renewal, reissue, and key rotation may start. Independent from operational status and validity. |
| `normalized_sans` | string array | Required, non-empty, sorted, deduplicated | Canonical SAN set. |
| `key_type` | enum | Required, one of `key_type` enum values | Key type used for the private key. |
| `issuer_id` | UUID | Required, foreign key to `issuers.id` | Issuer used. |
| `application_id` | UUID | Required, foreign key to `applications.id`, indexed | Application that owns this Certificate. Certificates are not shared across Applications in v1. |
| `status` | enum | Required | One of `pending`, `validating_dns`, `issuing`, `ready`, `renewing`, `rotating_key`, `expired`, `revoked`, `failed`, `deleted`. |
| `failure_code` | string | Nullable | Backend-generated stable error code for the latest failed issuance, renewal, reissue, or key rotation. |
| `failure_message` | string | Nullable, max length 2048, no control characters | Sanitized human-readable failure details for the latest failed issuance, renewal, reissue, or key rotation. Must not contain secrets or unsanitized provider responses. |
| `created_at` | timestamptz | Required | Creation time. |
| `updated_at` | timestamptz | Required | Last metadata update. |
| `deleted_at` | timestamptz | Nullable | Set when local Certificate availability is removed. Deleted Certificates are retained for audit/history but ignored by criteria lookup. |

Constraints:

- `uniq_active_certificate_identity_per_application`: exactly one non-deleted Certificate may exist for `(application_id, normalized_sans, key_type, issuer_id)`.
- `uniq_certhub_server_active_certificate`: at most one non-deleted Certificate may exist for the Application where `system_kind=certhub_server`.
- For `system_kind=certhub_server`, the non-deleted Certificate identity must match process configuration and is created, deleted, or replaced only by the backend reconcile loop.

If a lookup by exact identity returns more than one non-deleted Certificate, that is a data integrity bug and must fail internally rather than returning an arbitrary match. Deleted Certificates are ignored by criteria-based material lookup and Certificate create identity lookup.

### `certificate_versions`

Issued certificate material for a logical Certificate.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable version ID. |
| `certificate_id` | UUID | Required, foreign key to `certificates.id`, indexed | Parent Certificate. |
| `version` | integer | Required, positive, monotonically increasing per `certificate_id` | Sortable version number. Latest valid material is the highest valid version. |
| `status` | enum | Required, one of `issuing`, `valid`, `failed`, `revoked` | Version lifecycle state. Expiry is derived from `not_after`, not stored as a status. |
| `reason` | enum | Required, one of `initial_issue`, `renewal`, `key_rotation`, `reissue` | Why this version was issued. Manual renew uses `renewal`; manual key rotation uses `key_rotation`; no-active-version recovery uses `reissue`. |
| `cert_pem` | text | Nullable until `status=valid`; required for `valid` and `revoked` | Public leaf certificate PEM. |
| `chain_pem` | text | Nullable until `status=valid`; required for `valid` and `revoked` | Public issuer chain PEM. |
| `fullchain_pem` | text | Nullable until `status=valid`; required for `valid` and `revoked` | Public leaf certificate plus issuer chain PEM. |
| `private_key_pem` | encrypted text | Nullable until key is selected; required while the version is eligible for material retrieval | Private key PEM encrypted with Certhub encryption key. May be cleared only after the version can no longer be returned by material endpoints and retention policy allows it. |
| `not_before` | timestamptz | Nullable until `status=valid`; required for `valid` and `revoked` | Certificate validity start. |
| `not_after` | timestamptz | Nullable until `status=valid`; required for `valid` and `revoked` | Certificate expiry. |
| `serial_number` | string | Nullable until `status=valid`; required for `valid` and `revoked` | CA-issued serial number. |
| `fingerprint_sha256` | string | Nullable until `status=valid`; required for `valid` and `revoked` | SHA-256 fingerprint of the leaf certificate. |
| `key_fingerprint_sha256` | string | Nullable until key is selected; required for `valid` and `revoked` | SHA-256 fingerprint of the public key/private key pair. |
| `material_etag` | string | Nullable until `status=valid`; required for `valid` and `revoked`, indexed | Strong opaque HTTP ETag for the exact returned TLS material, including surrounding quotes. Generated only by Certhub. |
| `acme_order_url` | string | Nullable | ACME order URL for troubleshooting. |
| `certificate_url` | string | Nullable | ACME certificate URL when available. |
| `revocation_reason` | enum | Nullable, one of `key_compromise`, `superseded`, `cessation_of_operation`, `unspecified` | Local revocation reason for this version. Required when a version is revoked by user action. |
| `revoked_at` | timestamptz | Nullable | Local version revocation time. |
| `revoked_by_user_id` | UUID | Nullable, foreign key to `users.id` | User that requested version revocation when available. |
| `acme_revocation_status` | enum | Nullable, one of `pending`, `succeeded`, `failed`, `not_required` | Remote ACME revocation state for locally revoked versions. Null means revocation has not been requested. |
| `acme_revocation_attempts` | integer | Required, default `0`, non-negative | Number of ACME revocation attempts for this version. |
| `acme_revoked_at` | timestamptz | Nullable | Time ACME revocation succeeded. |
| `acme_revocation_failure_code` | string | Nullable | Stable sanitized failure code from the latest ACME revocation attempt. |
| `acme_revocation_failure_message` | string | Nullable, max length 2048, no control characters | Sanitized human-readable failure details from latest ACME revocation attempt. Must not contain secrets or unsanitized provider responses. |
| `created_at` | timestamptz | Required | Version row creation time; used to detect stuck issuing work. |
| `updated_at` | timestamptz | Required | Last version metadata update. |
| `started_at` | timestamptz | Required when `status=issuing` | Time issuance, renewal, reissue, or key rotation work started. |
| `completed_at` | timestamptz | Nullable | Time the version reached terminal state `valid`, `failed`, or `revoked`. |
| `issued_at` | timestamptz | Nullable until `status=valid`; required for `valid` and `revoked` | Time material was stored. |
| `failure_code` | string | Nullable | Backend-generated stable error code when status is `failed`. |
| `failure_message` | string | Nullable, max length 2048, no control characters | Sanitized human-readable failure details when status is `failed`. Must not contain secrets or unsanitized provider responses. |

Constraints:

- `(certificate_id, version)` must be unique.
- Version numbers must only increase for a given Certificate and must not be reused.
- Each Certificate must have at most one CertificateVersion with `status=issuing`.
- Each Certificate must have at most one valid, not-expired CertificateVersion except during a replacement overlap.
- A replacement overlap starts when renewal or key rotation is created while an older CertificateVersion is still valid and ends when the older CertificateVersion expires.
- During a replacement overlap, each Certificate may have at most two valid, not-expired CertificateVersions: the older still-valid version and the newly issued replacement version.
- Each Certificate must never have more than two valid, not-expired CertificateVersions.
- A version is valid for material selection only when `status=valid`, required material fields are present, `private_key_pem` is present, `not_before <= now < not_after`, and the parent Certificate is not revoked, failed, or deleted.
- `private_key_pem` must not be cleared while the CertificateVersion is the latest valid version or while it is the older still-valid version during replacement overlap.
- `material_etag` must be generated when material is stored and must not be provided or updated by clients.
- `material_etag` must match the format and HMAC rules in `Conditional Material Retrieval`.
- `material_etag` must change whenever any returned material field changes.
- When a version is locally revoked and ACME revocation is required, `acme_revocation_status` must be `pending`, `succeeded`, or `failed`.
- Repeating `POST /v1/certificates/{certificate_id}/versions/{certificate_version_id}/revoke` must retry ACME revocation for that locally revoked version when `acme_revocation_status=failed` or `pending` and must be idempotent when ACME revocation already succeeded.

Certificate material consistency constraints:

- `cert_pem` must equal the first certificate block in `fullchain_pem`.
- `chain_pem` must equal the remaining certificate blocks in `fullchain_pem`.
- `private_key_pem` plaintext, when present, must match the leaf certificate public key.
- Leaf certificate SANs must match the parent Certificate's `normalized_sans`.

Renewal and key rotation both create a new row with a fresh `key_fingerprint_sha256`. Retrying the same in-progress issuing row preserves that row's `key_fingerprint_sha256`.

Current material endpoints must always return the latest active valid CertificateVersion, selected by highest `version` for the Certificate. Expired, failed, revoked, or incomplete versions must not be returned as current material. Version archive endpoints may return any downloadable `valid` or `revoked` CertificateVersion that still has certificate, chain, fullchain, private key, validity, fingerprint, and ETag material. If no active valid version exists and an issuing version exists, current material endpoints must return `409 certificate_not_ready`; otherwise they must return `409 certificate_no_active_version` instead of returning stale PEM material.

### `issuance_jobs`

Durable worker jobs for issuance, renewal, key rotation, revocation retry, and DNS challenge cleanup.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable job ID. |
| `certificate_id` | UUID | Required, foreign key to `certificates.id`, indexed | Certificate affected by this job. |
| `certificate_version_id` | UUID | Nullable, foreign key to `certificate_versions.id`, indexed | CertificateVersion being issued, renewed, rotated, revoked, or cleaned up when applicable. |
| `reason` | enum | Required, one of `initial_issue`, `renewal`, `key_rotation`, `revocation_retry`, `dns_cleanup` | Why the job exists. Manual renew uses `renewal`; manual key rotation uses `key_rotation`. |
| `status` | enum | Required, one of `pending`, `running`, `succeeded`, `failed`, `canceled`; default `pending` | Job lifecycle state. |
| `attempt` | integer | Required, positive, default `1` | Attempt number for retry accounting. |
| `locked_by` | string | Nullable, max length 255, no control characters | Worker identity that currently owns the lease. |
| `locked_until` | timestamptz | Nullable | Lease expiry. Expired leases are reclaimable. |
| `next_run_at` | timestamptz | Required | Earliest time a worker may claim this job. |
| `started_at` | timestamptz | Nullable | Time current or latest attempt started. |
| `completed_at` | timestamptz | Nullable | Time the job reached terminal state. |
| `failure_code` | string | Nullable | Stable sanitized failure code for failed jobs. |
| `failure_message` | string | Nullable, max length 2048, no control characters | Sanitized failure details. Must not contain secrets or unsanitized provider responses. |
| `created_at` | timestamptz | Required | Job creation time. |
| `updated_at` | timestamptz | Required | Last metadata update. |

Constraints:

- Workers must claim jobs with row-level locking or leases, such as `FOR UPDATE SKIP LOCKED`.
- An active job is one with `status` in `pending` or `running`.
- There must be at most one active issuance/replacement job for a CertificateVersion.
- Job completion must be idempotent. Retrying a completed step after a crash must not create duplicate CertificateVersions, duplicate DNS TXT records, or duplicate successful audit events.
- Failed jobs preserve enough failure metadata for material endpoints and web UI diagnostics without storing secrets.

### `dns_challenge_records`

Durable record of ACME DNS-01 TXT values presented by Certhub.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable DNS challenge record ID. |
| `issuance_job_id` | UUID | Required, foreign key to `issuance_jobs.id`, indexed | Job that presented or must clean up this TXT value. |
| `certificate_id` | UUID | Required, foreign key to `certificates.id`, indexed | Certificate being issued. |
| `certificate_version_id` | UUID | Required, foreign key to `certificate_versions.id`, indexed | CertificateVersion being issued. |
| `dns_provider_id` | UUID | Required, foreign key to `dns_providers.id` | Provider used to present this record. |
| `dns_provider_zone_id` | UUID | Required, foreign key to `dns_provider_zones.id` | Zone selected by longest suffix match. |
| `authorization_identifier` | string | Required, format `certificate_identifier` | ACME authorization identifier that required this DNS-01 challenge. |
| `record_name` | string | Required, format `dns_txt_owner_name` | Full `_acme-challenge...` TXT owner name. |
| `txt_value_encrypted` | encrypted text | Required | Exact TXT value presented, encrypted because it authorizes issuance while valid. |
| `status` | enum | Required, one of `pending`, `presented`, `validated`, `cleanup_pending`, `cleanup_failed`, `cleaned`; default `pending` | Challenge record lifecycle state. |
| `presented_at` | timestamptz | Nullable | Time TXT value was presented. |
| `validated_at` | timestamptz | Nullable | Time ACME validation succeeded. |
| `cleaned_at` | timestamptz | Nullable | Time cleanup removed the exact TXT value. |
| `failure_code` | string | Nullable | Stable sanitized failure code for present/validation/cleanup failures. |
| `failure_message` | string | Nullable, max length 2048, no control characters | Sanitized failure details. Must not include TXT values, credentials, headers, or provider secrets. |
| `created_at` | timestamptz | Required | Creation time. |
| `updated_at` | timestamptz | Required | Last metadata update. |

Constraints:

- Cleanup must remove only the exact TXT value recorded in `txt_value_encrypted` for the recorded `record_name` and provider zone.
- Cleanup must preserve unrelated TXT values at the same `_acme-challenge` name.
- TXT values must not be logged, returned by APIs, written to audit metadata, or exposed in metrics.
- If cleanup fails, Certhub records `cleanup_failed` and can retry cleanup through a durable job.

### `issuers`

Configured ACME issuers.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable issuer ID. |
| `name` | string | Required, unique, format `machine_name` | Machine-friendly issuer name, such as `letsencrypt_production`. |
| `type` | enum | Required, value `acme` in v1 | Issuer implementation type. |
| `directory_url` | string | Required, format `https_url` | ACME directory URL. |
| `default` | boolean | Required, default false | Whether this issuer is selected by default. |
| `status` | enum | Required, one of `active`, `disabled`; default `active` | Disabled issuers cannot issue. |
| `renewal_window_seconds` | integer | Required, positive, default `2592000`, minimum `86400` | How many seconds before `not_after` Certhub should start automatic renewal. Default is 30 days. |
| `contact_email` | string | Required, format `email` | Contact email used when Certhub creates or reuses the issuer ACME account. |
| `created_at` | timestamptz | Required | Creation time. |
| `updated_at` | timestamptz | Required | Last metadata update. |

Constraints:

- At most one active issuer may have `default=true`; enforce with a partial unique constraint.
- Requests that omit issuer require exactly one active default issuer. If no active default issuer exists or more than one active issuer is marked default, omitted-issuer requests fail with `issuer_not_configured`.
- `renewal_window_seconds` must be lower than the shortest certificate lifetime this issuer is allowed to produce.
- `default`, `status`, `renewal_window_seconds`, and `contact_email` are mutable through `PATCH /v1/issuers/{issuer_id}`.
- `name`, `type`, and `directory_url` are immutable after creation.

### `dns_providers`

DNS provider configurations used for DNS-01.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable DNS provider ID. |
| `name` | string | Required, unique, format `machine_name` | Machine-friendly provider name. |
| `type` | enum | Required, one of `cloudflare`, `arvancloud` | Provider implementation. |
| `credentials_encrypted` | encrypted JSON object | Required | Provider credentials encrypted with Certhub encryption key. |
| `zone_mode` | enum | Required, one of `auto`, `manual`; default `manual` | How Certhub learns zones for this provider. |
| `last_zone_refresh_at` | timestamptz | Nullable | Last successful automatic zone discovery/refresh. |
| `zone_refresh_status` | enum | Required, one of `idle`, `pending`, `running`, `succeeded`, `failed`; default `idle` | Durable status of the latest auto-mode zone refresh. |
| `zone_refresh_failure_code` | string | Nullable | Stable sanitized failure code from latest failed zone refresh. |
| `zone_refresh_failure_message` | string | Nullable, max length 2048, no control characters | Sanitized failure details from latest failed zone refresh. Must not contain credentials or unsanitized provider responses. |
| `status` | enum | Required, one of `active`, `disabled`; default `active` | Disabled providers cannot create challenges. |
| `created_at` | timestamptz | Required | Creation time. |
| `updated_at` | timestamptz | Required | Last metadata update. |

Credentials are write-only through the API, encrypted before database persistence, and must never be returned in responses.

The plaintext credential payload must be selected by `type` and validated against a typed backend schema before encryption. Arbitrary unvalidated JSON must not be accepted or persisted. The backend serializes the validated provider-specific struct to JSON, encrypts it, and stores the encrypted envelope in `credentials_encrypted`.

Credential schemas:

| Provider type | Plaintext backend struct | Required fields |
| --- | --- | --- |
| `cloudflare` | `CloudflareCredentials` | `api_token` format `secret_string` |
| `arvancloud` | `ArvanCloudCredentials` | `api_key` format `secret_string`; full Authorization header value, including `Apikey` when required |

### `dns_provider_zone_refresh_jobs`

Durable management jobs for refreshing auto-mode DNS provider zones.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable refresh job ID. |
| `dns_provider_id` | UUID | Required, foreign key to `dns_providers.id`, indexed | Provider whose zones are being refreshed. |
| `status` | enum | Required, one of `pending`, `running`, `succeeded`, `failed`, `canceled`; default `pending` | Refresh job lifecycle state. |
| `locked_by` | string | Nullable, max length 255, no control characters | Worker identity that currently owns the lease. |
| `locked_until` | timestamptz | Nullable | Lease expiry. Expired leases are reclaimable. |
| `started_at` | timestamptz | Nullable | Time current or latest attempt started. |
| `completed_at` | timestamptz | Nullable | Time the job reached terminal state. |
| `discovered_zone_count` | integer | Nullable, non-negative | Number of zones discovered on successful refresh. |
| `failure_code` | string | Nullable | Stable sanitized failure code for failed refresh jobs, including `dns_provider_zone_conflict` when applicable. |
| `failure_message` | string | Nullable, max length 2048, no control characters | Sanitized failure details. Must not contain provider credentials or unsanitized provider responses. |
| `conflict_zone_name` | string | Nullable, format `dns_name` | Conflicting zone name when failure is `dns_provider_zone_conflict`. |
| `conflict_dns_provider_id` | UUID | Nullable, foreign key to `dns_providers.id` | Existing provider that owns `conflict_zone_name` when conflict occurs. |
| `created_at` | timestamptz | Required | Job creation time. |
| `updated_at` | timestamptz | Required | Last metadata update. |

Constraints:

- There must be at most one active refresh job with `status` in `pending` or `running` per DNS provider.
- Workers must claim refresh jobs with row-level locking or leases, such as `FOR UPDATE SKIP LOCKED`.
- Failed refresh jobs must preserve the previous `dns_provider_zones` rows unchanged.
- Successful refresh jobs replace immutable zone rows by delete plus insert in one transaction.
- Provider `zone_refresh_status` and failure fields must be updated atomically with refresh job transitions.

### `dns_provider_zones`

Zones available for DNS-01 challenges.

All rows in this table are considered active and valid for issuance.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable DNS provider zone ID. |
| `dns_provider_id` | UUID | Required, foreign key to `dns_providers.id`, indexed | Provider that manages this zone. |
| `zone_name` | string | Required, format `dns_name` | DNS zone suffix, such as `torob.dev`. |
| `created_at` | timestamptz | Required | Creation time. |

Constraints:

- `(dns_provider_id, zone_name)` must be unique.
- At most one `dns_provider_zones` row may exist for the same `zone_name` across all providers.
- Zone matching uses the row with the longest normalized DNS-label-boundary suffix match. Partial label suffixes must not match.
- `zone_name` must be a DNS zone name, not a certificate wildcard or `_acme-challenge` name.
- Rows are immutable after creation. There is no in-place update. User-facing updates are translated by Certhub into delete plus insert.

Auto mode behavior:

- Certhub must enqueue a durable refresh job to discover zones when the provider is created/activated and on explicit refresh.
- Refresh workers call the DNS provider API to discover zones.
- A successful refresh replaces the provider's `dns_provider_zones` rows with the discovered zone list in one transaction.
- Users cannot manually create, update, or delete zones for auto-mode providers.
- If discovery fails, Certhub records `dns_zone_discovery_failed` and must not silently remove the existing zone rows.
- If the discovered list contains a zone that conflicts with a `dns_provider_zones` row owned by another provider, the refresh job must fail with `dns_provider_zone_conflict`, preserve the previous rows unchanged, and store structured details containing the conflicting `zone_name`, current provider ID, and conflicting provider ID.

Manual mode behavior:

- Admins create and delete `dns_provider_zones` rows manually.
- If the UI/API offers an update action, Certhub must translate it into deleting the old immutable row and inserting a new row.
- If the provider supports zone discovery, Certhub may expose discovered zones as suggestions, but it must not automatically add them in manual mode.

### `acme_accounts`

ACME account state for issuers.

Certhub creates and manages these rows when an admin creates or activates an ACME issuer. Applications and normal Users must not create ACME accounts directly.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable ACME account ID. |
| `issuer_id` | UUID | Required, foreign key to `issuers.id`, indexed | Issuer this account belongs to. |
| `email` | string | Required, format `email` | ACME account contact email. |
| `account_url` | string | Required, unique | ACME account URL returned by the CA. |
| `private_key_pem` | encrypted text | Required | ACME account private key encrypted with Certhub encryption key. |
| `status` | enum | Required, one of `active`, `disabled`; default `active` | Disabled accounts cannot issue. |
| `created_at` | timestamptz | Required | Creation time. |
| `updated_at` | timestamptz | Required | Last metadata update. |

Constraint: one active ACME account per issuer is the v1 default. An issuer cannot be `active` unless Certhub has a usable active ACME account for it.

### `certificate_events`

Operational Certificate and CertificateVersion timeline events.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable event ID. |
| `certificate_id` | UUID | Required, foreign key to `certificates.id`, indexed | Certificate being issued, renewed, reissued, rotated, revoked, or cleaned up. |
| `certificate_version_id` | UUID | Nullable, foreign key to `certificate_versions.id`, indexed | CertificateVersion affected by this event when known. |
| `issuance_job_id` | UUID | Nullable, foreign key to `issuance_jobs.id`, indexed | Worker job that produced this event when applicable. |
| `event_type` | string | Required, indexed | Stable operational event name such as `dns_challenge_propagated`. |
| `result` | enum | Required, one of `success`, `failure` | Event result. |
| `correlation_id` | string | Nullable, format `correlation_id` | HTTP or worker correlation ID when available. |
| `message` | string | Nullable | Sanitized human-readable detail. |
| `metadata` | JSON object | Required, default `{}` | Non-secret structured details for troubleshooting. |
| `created_at` | timestamptz | Required, indexed | Event time. |

Certificate events are append-only operational telemetry. `metadata` and `message` must not contain private keys, raw tokens, ACME account private keys, DNS provider credentials, raw DNS TXT values, passwords, TOTP secrets, or TOTP codes.

### `audit_events`

Immutable audit log.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | UUID | Primary key | Stable audit event ID. |
| `identity_type` | enum | Required, one of `user`, `application`, `system` | Authenticated identity that caused the event. |
| `identity_id` | UUID | Nullable | User ID or Application ID. Null only for `system`. |
| `action` | string | Required, indexed | Backend-generated event action, such as `private_key_read`. |
| `target_type` | string | Required | Backend-generated target resource type. |
| `target_id` | UUID | Nullable | Target resource ID when available. |
| `scope_application_id` | UUID | Nullable, foreign key to `applications.id`, indexed | Application scope used for non-admin audit visibility when the event relates to an Application or Application-owned resource. |
| `scope_certificate_id` | UUID | Nullable, foreign key to `certificates.id`, indexed | Certificate scope used for certificate-specific audit visibility. |
| `scope_user_id` | UUID | Nullable, foreign key to `users.id`, indexed | User scope for User-related audit visibility. |
| `scope_dns_provider_id` | UUID | Nullable, foreign key to `dns_providers.id`, indexed | DNS provider scope for admin troubleshooting and future scoped views. |
| `result` | enum | Required, one of `success`, `failure` | Event result. |
| `correlation_id` | string | Nullable, format `correlation_id` | HTTP correlation ID. |
| `source_ip` | string | Nullable | Derived effective client IP when available. |
| `metadata` | JSON object | Required, default `{}` | Non-secret structured details. |
| `created_at` | timestamptz | Required, indexed | Event time. |

Audit events are append-only. `metadata` must not contain private keys, raw tokens, or DNS provider credentials.

Visibility rules:

- Admin Users may query all audit events.
- Non-admin Users may query only events scoped to Applications they can access and related resources, such as Application-owned Certificates.
- Non-admin audit visibility must be computed from `scope_application_id` and `scope_certificate_id`, not from free-form `metadata`.
- Scoped audit APIs must not reveal hidden resource IDs, hidden User details, secrets, or metadata for resources outside the User's Application grants.
- Every audit action must define which scope columns it populates. Events without an Application or Certificate scope are visible only to global `admin` unless a future spec grants another scoped view.

Required audit actions include:

- `bootstrap_admin_created`
- `user_created`
- `user_invite_created`
- `user_invite_signup_started`
- `user_invite_consumed`
- `user_updated`
- `user_login_succeeded`
- `user_login_failed`
- `user_session_created`
- `user_session_refreshed`
- `user_session_revoked`
- `password_2fa_setup_started`
- `password_2fa_enabled`
- `password_2fa_disabled`
- `application_created`
- `application_updated`
- `application_token_created`
- `application_token_rotated`
- `application_token_revoked`
- `domain_scope_created`
- `domain_scope_deleted`
- `application_access_granted`
- `application_access_revoked`
- `issuer_created`
- `issuer_updated`
- `issuer_disabled`
- `acme_account_created`
- `dns_provider_created`
- `dns_provider_updated`
- `dns_provider_credentials_replaced`
- `dns_provider_zone_added`
- `dns_provider_zone_removed`
- `dns_provider_zone_refresh_started`
- `dns_provider_zone_refreshed`
- `dns_zone_discovery_failed`
- `certificate_created`
- `certificate_enabled`
- `certificate_disabled`
- `certificate_issuance_started`
- `certificate_issuance_succeeded`
- `certificate_issuance_failed`
- `certificate_renewal_started`
- `certificate_renewal_succeeded`
- `certificate_renewal_failed`
- `certificate_key_rotation_started`
- `certificate_key_rotation_succeeded`
- `certificate_key_rotation_failed`
- `certificate_revoked`
- `certificate_revocation_retried`
- `certificate_revocation_failed`
- `certificate_deleted`
- `private_key_read`
- `server_self_certificate_synced`

## Authorization

Global roles:

- `user`: default human role with no Application access by default.
- `admin`: full access to every Application and all administrative APIs.

User Application grant roles:

- `viewer`
- `certificate_reader`
- `manager`

Permission names:

- `users:admin`
- `applications:admin`
- `issuers:admin`
- `dns_providers:admin`
- `audit_events:read`

Application domain-scope checks must be performed for:

- Certificate creation from Application tokens.
- Certificate creation from User-authenticated web-console endpoints.
- Criteria-based certificate material retrieval from Application tokens.
- Returning existing Application-owned certificates.
- Renewal and key rotation.

User Application access must be checked for:

- Listing or inspecting Application-owned certificates.
- Creating Application-owned certificates through User-authenticated web-console endpoints.
- Downloading certificate material.
- Reading audit events scoped to an Application, Application-owned Certificate, or related visible resource.
- Application token management.
- Application domain scope management.
- Certificate lifecycle operations.

Creating an Application requires global role `admin`.

Authentication token rules:

- Missing, malformed, unknown-prefix, unknown-hash, expired, or revoked bearer tokens fail with `401 invalid_token`, except login and refresh endpoints which use their specific auth errors.
- Expired, rotated, malformed, unknown-prefix, or unknown-hash User access tokens sent to `POST /v1/auth/refresh` fail with `401 invalid_token`.
- A valid User access token sent to an Application-token endpoint fails with `403 application_token_required`.
- A valid Application token sent to a User-authenticated endpoint fails with `403 user_token_required`.
- Disabled Users, disabled Applications, revoked User sessions, expired User sessions, revoked Application tokens, and expired Application tokens cannot authenticate.
- Application token expiry is enforced with `application_tokens.expires_at`; a non-null value at or before the current time makes the token invalid.
- A valid Application token from an untrusted source IP fails with `403 application_source_ip_denied` when the Application has non-empty `trusted_source_cidrs`.

## Error Handling

All non-2xx JSON error responses must use the same envelope:

```json
{
  "error": {
    "code": "domain_not_authorized",
    "message": "Application is not authorized for api.torob.dev",
    "retryable": false,
    "retry_after_seconds": null,
    "details": {}
  }
}
```

Rules:

- `error.code` is stable and machine-readable.
- `error.message` is human-readable and safe to display.
- `error.retryable` tells CLI, frontend, Kubernetes operator, and Application clients whether retrying the same request can succeed without changing input.
- `error.retry_after_seconds` is required when `retryable=true` and Certhub knows a useful delay. When present, the HTTP `Retry-After` header must also be set to the same number of seconds.
- `error.details` is optional structured data and must not contain secrets.
- CLI and frontend clients must branch on `error.code`, not on free-form message text.
- New public error codes require updating this table and the CLI/frontend handling sections.

| Code | HTTP status | Retryable | CLI exit | Frontend/CLI handling |
| --- | --- | --- | --- | --- |
| `invalid_domain` | `400` | No | `2` | Show validation error next to the domain input. |
| `invalid_request` | `400` | No | `2` | Show request validation error. |
| `invalid_token` | `401` | No | `3` | Clear invalid credential state or ask for a valid token. |
| `invalid_credentials` | `401` | No | `3` | Show generic login failure without revealing whether the User exists. |
| `invalid_token` | `401` | No | `3` | Clear local session state and require login. |
| `session_expired` | `401` | No | `3` | Clear local session state and require login. |
| `invalid_2fa_code` | `401` | No | `3` | Show generic invalid authentication code. |
| `oidc_auth_failed` | `401` | No | `3` | Restart OIDC login. |
| `application_token_required` | `403` | No | `4` | Use an Application token for Application certificate workflows. |
| `user_token_required` | `403` | No | `4` | Use a User login session for management and web-console workflows. |
| `application_source_ip_denied` | `403` | No | `4` | Application token is valid, but this client source IP is not trusted for the Application. Move the client to an allowed network or update the Application trusted source CIDRs. |
| `application_access_denied` | `403` | No | `4` | Show permission denied. |
| `private_key_access_denied` | `403` | No | `4` | Hide/disable private-key download actions. |
| `domain_not_authorized` | `403` | No | `4` | Show the uncovered SANs when provided in `details`. |
| `password_auth_disabled` | `403` | No | `3` | Hide password login or tell the User to use OIDC. |
| `password_2fa_required` | `403` | No | `3` | Prompt for password 2FA setup or TOTP code as appropriate. |
| `user_disabled` | `403` | No | `3` | Show account disabled outside password-login credential checks. Password login must use `invalid_credentials` for disabled Users. |
| `user_not_provisioned` | `403` | No | `3` | Show that an admin must provision the User. |
| `certificate_not_found` | `404` | No | `5` | Application clients may call `POST /v1/sync/certificates`; human clients show not found. |
| `certificate_not_ready` | `409` | Yes | `6` | Retry the same material/archive endpoint after `Retry-After`. |
| `certificate_expired` | `409` | Yes | `6` | Deprecated compatibility code for older clients; current no-active-version states use `certificate_no_active_version`. |
| `certificate_issuance_failed` | `409` | No | `7` | Stop polling and show failure metadata. `details.failure_code` may contain a stable underlying cause such as `dns_provider_not_found` or `dns_validation_failed`. |
| `certificate_revoked` | `409` | No | `7` | Deprecated compatibility code for older clients; version revocation metadata is exposed on CertificateVersion responses. |
| `certificate_no_active_version` | `409` | No | `7` | Stop polling current material and require a User `reissue` lifecycle action. |
| `certificate_disabled` | `409` | No | `1` | Refresh Certificate metadata and keep lifecycle controls disabled until an authorized User re-enables it. |
| `not_acceptable` | `406` | No | `2` | Request an accepted response media type. |
| `renewal_overlap_exists` | `409` | No | `1` | Show lifecycle conflict and current valid versions. |
| `renewal_not_due` | `409` | No | `1` | Manual renewal was requested before the active CertificateVersion entered the issuer renewal window. |
| `system_managed_resource` | `409` | No | `1` | The resource is owned by backend process configuration. Show read-only/config-managed state instead of retrying the write. |
| `conflict` | `409` | No | `1` | Show conflict and require operator action. |
| `issuer_not_configured` | `409` | No | `1` | Admin must configure exactly one active default issuer or select an active issuer explicitly. |
| `service_unavailable` | `503` | Yes | `8` | Backend readiness, worker queue, or generic dependency is temporarily unavailable. Retry with backoff. |
| `issuer_unavailable` | `503` | Yes | `8` | Transient issuer, ACME account, or issuer dependency outage. Retry with backoff. |
| `dns_provider_not_found` | `409` | No | `7` | Admin must configure a matching DNS provider zone. Material lookup endpoints expose this as `details.failure_code` under `certificate_issuance_failed`. |
| `dns_provider_zone_conflict` | `409` | No | `1` | Admin must resolve conflicting DNS provider zones. Details name the conflicting zone and provider IDs. |
| `dns_provider_unavailable` | `503` | Yes | `8` | Retry with backoff. |
| `dns_zone_discovery_failed` | `503` | Yes | `8` | Retry or let admin inspect provider configuration. |
| `dns_validation_failed` | `409` | No | `7` | Stop polling and show validation failure. Material lookup endpoints expose this as `details.failure_code` under `certificate_issuance_failed`. |
| `rate_limited` | `429` | Yes | `8` | Retry only after `Retry-After`. |

## Tests

Required backend scenarios:

- PostgreSQL migrations are idempotent and create required foreign keys, uniqueness constraints, and indexes.
- Go enum/domain types reject invalid API values before database persistence.
- `certhub-server run` loads server process configuration only from the YAML config file selected by `certhub-server run --config <path>` or `CERTHUB_SERVER_CONFIG`; environment variables do not override server config values except for `CERTHUB_SERVER_CONFIG` selecting the config file path and explicitly configured `database.url_env`, `encryption.key_env`, and `outbound_http.proxies.<name>.url_env`.
- `certhub-server run --migrate` applies pending migrations before starting HTTP listeners, while plain `certhub-server run` fails closed when migrations are pending.
- Bare `certhub-server` without a subcommand prints help and does not start HTTP listeners, workers, metrics, web UI, migrations, or database-mutating jobs.
- `certhub-server run` is the only command that starts the long-running backend serving process.
- Backend startup rejects missing, unreadable, non-regular, symlinked, group/world-writable config files, and rejects config files under unsafe parent directories.
- Backend startup rejects YAML config files with unknown keys, duplicate keys, type mismatches, invalid scalar coercions, malformed YAML, and secret values included in startup error output.
- Backend startup accepts secret values from environment variables only when `database.url_env`, `encryption.key_env`, or `outbound_http.proxies.<name>.url_env` names the environment variable in YAML.
- Backend startup rejects secret env references when both inline and env fields are set, neither is set, the env var name is malformed, the env var is missing or empty, or the env var value fails the same validation as the inline secret.
- Backend startup rejects environment-variable interpolation, include directives, remote config references, and secondary secret-file references in the server YAML config.
- `certhub-server generate-encryption-key` prints exactly one newline-terminated base64 value that decodes to 32 bytes and passes `encryption.key` validation.
- `certhub-server generate-encryption-key` works without a config file, database, network, existing encryption key, or operational state.
- `certhub-server generate-encryption-key` does not print explanatory text, write files, start listeners/workers, emit audit events, or log the generated key.
- Repeated `generate-encryption-key` runs produce distinct values in normal operation and fail closed when the secure random source is unavailable or stdout cannot be written.
- Backend startup fails when required process configuration is missing or invalid.
- Optional process configuration uses documented defaults when omitted.
- Numeric process configuration rejects zero, negative numbers, non-integers, and invalid relative values such as DNS poll interval greater than DNS propagation timeout.
- Backend startup rejects invalid `server.public_hostname`, including wildcards, schemes, ports, paths, query strings, fragments, IP literals, public-suffix-only values, and an empty value when self-certificate sync is enabled.
- Backend startup rejects invalid outbound proxy configuration, including duplicate proxy names, invalid `outbound_proxy_url` values, unsupported proxy URL schemes, proxy entries with both `url` and `url_env`, proxy entries with neither, malformed `url_env` names, missing env vars, empty env vars, and references to unknown proxy names.
- Outbound proxy tests prove `http://` and `https://` proxy URLs are both accepted, HTTPS proxy certificates are validated, and proxy URL credentials are redacted from logs, metrics, audit metadata, readiness details, and errors.
- Outbound routing tests prove ACME/Lets Encrypt and Cloudflare requests use their configured proxy while ArvanCloud requests go direct when `outbound_http.dns_providers.arvancloud.proxy` is empty.
- Outbound HTTPS tests prove upstream TLS verification remains enabled through HTTP CONNECT and fails closed on invalid upstream certificates or hostname mismatch.
- Host allowlist tests prove requests with unconfigured effective hosts are rejected before routing, authentication, body parsing, side effects, and SPA fallback.
- Backend startup rejects invalid `http.trusted_proxy_cidrs`.
- Backend startup rejects partially configured direct TLS file settings and unsafe self-certificate output directories.
- Backend startup allows missing direct TLS files only when `self_certificate.sync_enabled=true` and `tls.cert_file`/`tls.key_file` point at `self_certificate.output_dir/current/fullchain.pem` and `self_certificate.output_dir/current/privkey.pem`; otherwise missing configured TLS files fail startup.
- First-boot self-certificate tests prove operators can run direct database commands to migrate, create the first admin, configure issuer, configure DNS provider credentials, and configure or refresh DNS zones before the HTTPS API is reachable; after the server starts with pending direct TLS, it issues the `certhub_server` Certificate, publishes local material, and automatically enables successful future TCP TLS handshakes without a restart.
- Server self-certificate reconcile tests create or protect `certhub_server`, derive its domain scope from `server.public_hostname`, create exactly one desired Certificate, enqueue issuance when needed, and preserve existing local material while the desired replacement is pending.
- Server self-certificate reconcile tests prove changing the configured public hostname, issuer, or key type locally deletes the previous reserved Certificate row, creates a new one, and does not perform CA revocation unless an explicit internal policy requires it.
- Server self-certificate sync writes `cert.pem`, `chain.pem`, `fullchain.pem`, `privkey.pem`, and metadata using the same atomic release-directory semantics and private-key permissions as the CLI.
- Server self-certificate sync reads only the reserved `certhub_server` Application's latest valid CertificateVersion and never calls public `/v1/sync/...` endpoints or requires an Application token.
- Server self-certificate sync preserves the last local material unchanged when PostgreSQL is unavailable, decryption fails, issuance is pending, issuance fails, or the reserved Certificate is revoked/deleted.
- Server self-certificate sync records sanitized logs, metrics, and material-changing `server_self_certificate_synced` audit events without logging PEM material or private keys.
- Direct TLS reload tests prove that when self-sync publishes a new valid release, the backend automatically loads it for future TLS handshakes without restart, signal, API call, CLI command, or manual operator action.
- Direct TLS reload tests prove that malformed, mismatched, expired, not-yet-valid, unreadable, or wrong-hostname replacement material is rejected and the previously loaded certificate remains active for future TLS handshakes.
- Reserved `certhub_server` Application tests prove normal Users cannot create that name and no public API identity can rename, patch, disable, delete it, create/delete its domain scopes, create Application tokens for it, assign User grants to it, create Certificates for it, or run lifecycle mutations on its Certificate.
- Reserved `certhub_server` write tests assert `409 system_managed_resource` and prove the rejected writes do not partially mutate database state.
- Secret-bearing TCP API endpoints reject effective plaintext HTTP when `http.require_https=true`.
- HTTPS enforcement tests include large and malformed request bodies and prove body parsing, authentication, and handler side effects do not run before plaintext rejection.
- Forwarded client IP and scheme headers are ignored from untrusted peers and accepted only from configured trusted proxies.
- Trusted-proxy tests cover malformed chains, mixed IPv4/IPv6 hops, conflicting `Forwarded` and `X-Forwarded-*` headers, and proxy peers outside every configured CIDR.
- Embedded web UI serves `/` and frontend routes through `index.html` while `/v1/...`, `/healthz`, `/readyz`, and `/metrics` never use SPA fallback.
- Unknown API/backend route prefixes return backend-style errors instead of frontend HTML.
- Reserved backend prefixes return backend errors even when requests send browser-like `Accept: text/html` headers.
- Embedded static serving forbids directory listings and cannot read arbitrary filesystem paths from operator-controlled configuration.
- Embedded static serving rejects traversal-style paths, including raw or URL-encoded `..`, repeated slashes, backslashes, and paths that would escape the embedded asset root.
- Embedded static traversal tests include double-encoded path segments and separator variants that differ between Unix and Windows-style paths.
- Production embedded asset set excludes frontend source files, source maps by default, tests, fixtures, package-manager caches, local paths, and development-only assets.
- Embedded web UI responses set required security headers including `X-Content-Type-Options`, `Referrer-Policy`, and restrictive `Content-Security-Policy`.
- Production CSP for web UI responses does not allow `unsafe-inline`, `unsafe-eval`, remote script origins, remote style origins, remote font origins, or remote image origins.
- CSP and security headers are present on `index.html`, frontend route fallback responses, static asset responses, and embedded web UI `404` responses.
- The runtime frontend config script is served by the backend with no-store cache headers and does not expose OIDC issuer URLs, client IDs, redirect URLs, tokens, or provider metadata.
- Static asset content types are allowlisted and paired with `X-Content-Type-Options: nosniff`; unknown embedded asset types are not served as executable script or style content.
- Embedded web UI cache headers distinguish `index.html`, hashed static assets, non-hashed static assets, and backend API responses.
- Only content-hashed immutable assets receive long-lived public cache headers; `index.html`, frontend route fallbacks, non-hashed assets, and errors do not.
- Auth, session, User, Application, DNS provider, issuer, audit, and certificate-management API responses use private/no-store cache behavior where sensitive or identity-specific data is present.
- API cache tests cover success, `401`, `403`, `404`, and validation-error responses so auth failures and hidden resources are not cacheable by shared caches.
- `HEAD`, `204`, and `304` responses preserve the required cache and security headers while returning no response body.
- Backend error responses for API endpoints are JSON and never return the frontend HTML shell.
- Backend startup fails when `encryption.key` is missing or invalid.
- `encryption.key` rejects non-base64 values and base64 values that do not decode to exactly 32 bytes.
- Sensitive database values use the documented AES-256-GCM envelope with unique nonces, row-context AAD, key ID, and fail-closed authentication.
- Tampering with encrypted database ciphertext, nonce, key ID, or row-context AAD fails closed and does not return partially decrypted data.
- Decryption failures, token lookup failures, OIDC failures, and DNS provider failures are logged and audited without leaking raw secrets or sensitive upstream response bodies.
- User passwords are stored only as Argon2id PHC strings with at least the documented v1 parameters.
- Password policy rejects too-short passwords, overlong passwords, control characters, and passwords equal to the User email.
- Passwords are not trimmed; leading/trailing spaces are significant when allowed by policy.
- Password verification uses Argon2id and constant-time comparison through a standard library.
- Successful login rehashes passwords when stored Argon2id parameters are weaker than current policy.
- Password and TOTP login rate limiting returns `rate_limited` without revealing whether the email exists and uses the derived effective `source_ip`.
- Spoofed `X-Forwarded-For` or `Forwarded` headers from untrusted peers do not bypass rate limits or alter audit `source_ip`.
- Application tokens and User access tokens are hashed with `base64url_no_padding(HMAC-SHA256(token_hash_key, full_token_value))`.
- `token_hash_key` is derived with `HKDF-SHA256(encryption.key, info="certhub-token-hash-v1")`.
- Token hashing includes the full prefixed token value and does not use Argon2id, bcrypt, or another password hash.
- Public HTTP routing tests prove no `/v1/bootstrap/...` endpoints exist on any listener.
- Command-surface tests prove `certhub-server --help`, `help <command...>`, command-group `--help`, and leaf-command `--help` exit `0`, write help to stdout, leave stderr empty, and do not perform config, database, secret, listener, worker, migration, or mutation side effects.
- Command-surface tests prove the misspelled `certhub-server boostrap` is rejected and suggests `bootstrap` without executing bootstrap behavior.
- Direct database command tests prove `certhub-server migrate` and every `certhub-server bootstrap ...` command runs without starting HTTP listeners, workers, metrics, web UI, TLS, User login, Application token authentication, or an already-running server process.
- Direct database command tests prove commands load the same YAML config rules as the server process, connect directly to PostgreSQL, run migrations or fail closed, and acquire the same migration/service locks as the server.
- Direct database command tests prove commands call the same service-layer functions as HTTP handlers by sharing validation failures, uniqueness conflicts, audit event construction, encryption behavior, password hashing behavior, DNS provider credential handling, and immutable-record behavior.
- Direct database command tests prove commands do not accept secrets as positional arguments or ordinary command-line flags, and support secret input only from stdin, explicitly named environment variables, or protected files.
- `certhub-server bootstrap create-admin` can create the first `admin` User with system authority while still enforcing field validation and unique email.
- `certhub-server bootstrap create-admin` is rejected after an active admin exists unless `--allow-existing-admin` is set.
- `certhub-server bootstrap create-admin` with password and default password-2FA policy generates and enables TOTP, returns the provisioning URI once, writes `bootstrap_admin_created`, and never logs or audits the TOTP secret.
- `certhub-server bootstrap --interactive` and `certhub-server bootstrap create-admin --interactive` require a TTY and fail closed in non-TTY mode.
- Interactive admin creation tests prove password prompts disable echo, require confirmation, enforce password policy before mutation, and never print or log the password.
- Interactive admin 2FA tests prove Certhub displays the TOTP provisioning URI exactly once, verifies a current TOTP code before committing the admin User, and rolls back all User/TOTP state when the operator aborts or confirmation fails.
- Interactive bootstrap wizard tests prove issuer, DNS provider, and DNS zone choices call the same services and validators as the noninteractive bootstrap commands.
- `certhub-server bootstrap create-issuer`, `create-dns-provider`, `add-dns-provider-zone`, and `refresh-dns-provider-zones` enforce the same service validations and audit/secret-redaction behavior as their authenticated management API equivalents.
- Admin User creation generates a one-time invite link with configured expiration and stores only the invite token hash.
- Invite signup without forced 2FA creates one active User and consumes the invite exactly once.
- Invite signup with forced 2FA returns TOTP provisioning data, requires the frontend QR-code setup step to validate a current TOTP code, and creates the User only after successful TOTP confirmation.
- Consumed, expired, missing, and malformed invite tokens return `invalid_invite` and cannot create another User.
- Password login succeeds for active Users with valid password hashes and returns a short-lived User access token plus a fixed session expiry.
- Password login failures use `invalid_credentials` without revealing whether the email exists.
- Password login for disabled Users, Users without password hashes, unknown emails, and wrong passwords all return the same generic `invalid_credentials`.
- Password login returns `password_2fa_required` for missing TOTP only after valid primary credentials.
- Omitting `auth.password.2fa_required` uses default `true`.
- Password login with `auth.password.2fa_required=true` requires configured TOTP and a valid `totp_code`.
- Password login with enabled per-User 2FA requires a valid `totp_code` even when global 2FA is not required.
- Invalid TOTP returns `invalid_2fa_code`; missing setup when required returns `password_2fa_required`.
- OIDC login succeeds or fails independently from Certhub password 2FA state and never requires `totp_code`, `amr`, or `acr`.
- Password 2FA setup stores TOTP secrets encrypted and never writes secrets or TOTP codes to logs or audit metadata.
- Login-created access tokens use `auth.user_access_token_ttl_seconds`, defaulting to 300 seconds.
- User sessions use fixed `auth.user_session_ttl_seconds`; this deadline does not slide on refresh.
- User access tokens are opaque random values, are not JWTs, and are never validated by parsing embedded claims.
- User access token authentication hashes the presented token and looks up `user_sessions.access_token_hash`.
- Application tokens use `cth_app_v1_<secret>`, User access tokens use `cth_uat_v1_<secret>`, where `<secret>` is 32 random bytes encoded as 43-character base64url without padding.
- Token authentication chooses exactly one lookup path by token prefix and never tries multiple token stores for one presented token.
- Token lookup uses constant-time comparison or database equality on HMAC outputs only; raw token values are never compared against stored data.
- Token values in `Authorization` headers are redacted from request logs, audit metadata, metrics labels, panic output, and error responses.
- Authorization parsing rejects multiple credentials, duplicate Authorization headers, non-Bearer schemes, missing bearer values, and bearer values with leading or trailing whitespace.
- Valid User access tokens on Application-token endpoints are rejected with `application_token_required`.
- Valid Application tokens on User-authenticated endpoints are rejected with `user_token_required`.
- Missing, unknown, expired, revoked, malformed, or unknown-prefix bearer tokens return `invalid_token`.
- Unknown or malformed token prefixes fail authentication without trying other token stores.
- `POST /v1/auth/refresh` rotates the access token and invalidates the previous access token atomically.
- Reusing an already-rotated access token revokes the whole login session.
- Reusing a rotated access token is detected through `user_session_token_history`, even after `user_sessions.access_token_hash` has changed.
- `POST /v1/auth/logout` revokes the current login session and invalidates its access token.
- `POST /v1/auth/logout` returns `invalid_token` for missing, malformed, expired, revoked, or unknown access tokens.
- Disabled Users, revoked sessions, expired access tokens cannot authenticate.
- Missing, malformed, expired, revoked, or unknown bearer tokens return `invalid_token`.
- Expired Application tokens cannot authenticate.
- Application token authentication always requires a valid token even when the source IP matches an Application trusted source CIDR.
- Application token authentication succeeds from any source IP when `trusted_source_cidrs` is empty.
- Application token authentication fails with `application_source_ip_denied` when `trusted_source_cidrs` is non-empty and the derived effective `source_ip` is outside every configured CIDR.
- Application source-IP checks use trusted proxy parsing rules; spoofed forwarded headers from untrusted peers do not satisfy `trusted_source_cidrs`.
- Application `trusted_source_cidrs` accepts exact IPv4/IPv6 addresses and CIDR inputs, normalizes exact IPs to host CIDRs, rejects invalid CIDRs, and rejects duplicates after normalization.
- Application token creation applies the default expiration when `expires_at` is omitted.
- Application token creation rejects expirations beyond `application_tokens.max_ttl_seconds`.
- Application token creation with explicit `expires_at=null` creates a non-expiring token for non-system Applications without special admin-only handling beyond normal Application token creation authorization and without applying `application_tokens.max_ttl_seconds`.
- OIDC callback validation rejects invalid issuer, audience, signature, nonce, state, and expired tokens.
- OIDC pending login state is stored in `oidc_login_states` as an HMAC hash, expires, is compared in constant time, and is consumed exactly once.
- OIDC callback replay with the same state fails after the first successful consumption.
- OIDC callback with mismatched state, missing state, mismatched nonce, wrong redirect URI, wrong code verifier, or `plain` PKCE fails without creating a User session.
- Provider-facing OIDC callback uses `GET /v1/auth/oidc/callback`, creates a short-lived handoff, redirects to the frontend, and never returns Certhub User tokens directly.
- `POST /v1/auth/oidc/handoff` consumes a valid handoff exactly once and creates the User session.
- Expired, consumed, reused, unknown, or malformed OIDC handoff IDs fail without creating a User session.
- Raw OIDC handoff IDs are stored only as hashes and are removed from frontend URLs after exchange.
- OIDC `return_url` is accepted only when it matches `auth.oidc.allowed_return_urls` or the default same-origin rule.
- OIDC `return_url` rejects open-redirect payloads, protocol-relative URLs, username/password URLs, fragments, and lookalike origins.
- OIDC login creates cryptographically random `state`, `nonce`, and PKCE `code_verifier`, sends only `code_challenge` with `code_challenge_method=S256`, and redeems the callback authorization code with the matching `code_verifier`.
- OIDC token exchange always uses `auth.oidc.redirect_url`, never the frontend `return_url`.
- OIDC email-linking is rejected unless the provider supplies verified-email evidence such as `email_verified=true`.
- OIDC `plain` PKCE, implicit flow, hybrid flow, resource-owner password flow, device flow, and client-secret based token exchange are rejected or unsupported.
- OIDC login maps only to active provisioned Users and returns `user_not_provisioned` when no User matches.
- User personal access token CRUD endpoints do not exist in v1.
- User-provided non-human strings enforce their documented formats at the API boundary, including `machine_name`, `dns_name`, `certificate_identifier`, `https_url`, `email`, `ip_or_cidr`, `correlation_id`, and provider credential schemas.
- ACME issuer `directory_url` validation rejects non-HTTPS URLs, URL userinfo, fragments, localhost, loopback, link-local, and private-address targets unless a future explicit internal-ACME allowlist is documented.
- User-provided `machine_name` accepts lowercase ASCII letters, digits, and underscore only; names containing hyphen are rejected.
- User-provided machine strings reject leading/trailing whitespace, control characters, and unexpected non-ASCII characters unless their format explicitly normalizes the input.
- `key_type` validation accepts only `rsa-2048`, `rsa-3072`, `rsa-4096`, `ecdsa-p256`, and `ecdsa-p384`.
- All mutating admin endpoints write required audit actions, including issuer changes, DNS provider changes, credential replacement, zone add/delete/refresh, and Application grant changes.
- Certificate private keys, ACME account private keys, and DNS provider credentials are encrypted before database persistence.
- ACME account private keys and DNS provider credentials are decrypted only inside issuance, revocation, zone discovery, and credential validation paths that require them.
- DNS provider credentials are validated against the provider-specific backend struct before encryption; arbitrary extra or missing credential fields are rejected.
- DNS provider credential create and replace tests cover wrong provider type, missing required secret fields, unknown extra secret fields, malformed JSON, and previously valid credentials becoming unusable after replacement.
- Failed DNS provider credential replacement preserves the previous encrypted credentials and does not leave partially updated credential metadata.
- Raw DNS provider credentials and decrypted private keys are never returned from list/detail APIs that are not certificate material download APIs.
- Application token raw values and User access token raw values are never stored; only hashes are persisted.
- Standard error envelopes never include raw tokens, passwords, TOTP codes, TOTP secrets, DNS provider credentials, ACME account keys, private keys, PEM material, OIDC authorization codes, OIDC state, PKCE code verifiers, encrypted payloads, or database connection strings.
- Redaction tests inject unique canary values for every secret type and assert they are absent from logs, metrics, audit metadata, errors, readiness details, and persisted non-secret JSON fields.
- Same SANs in different order reuse the same certificate identity for the same Application.
- User access token calls to `POST /v1/sync/certificates` return `application_token_required`.
- User access token calls to `POST /v1/applications/{application_id}/certificates` can create or reuse an Application-owned Certificate only when the User has Application `manager` access or global `admin`.
- Application token calls to `POST /v1/applications/{application_id}/certificates` are rejected because Application clients must use `POST /v1/sync/certificates`.
- Application tokens have no roles or permissions.
- Active, unexpired Application tokens can request or reuse their own Application's certificates only when every requested domain is covered by their Application domain scopes.
- Exact domain scope `torob.dev` authorizes only `torob.dev` and does not authorize `api.torob.dev` or `*.torob.dev`.
- Wildcard domain scope `*.torob.dev` authorizes `api.torob.dev` and `*.torob.dev`, but not `torob.dev`, `a.b.torob.dev`, or `*.b.torob.dev`.
- Exact scopes never authorize wildcard SANs, and wildcard scopes never authorize apex names.
- A single Certificate may contain both an exact SAN and its corresponding wildcard SAN, such as `torob.dev` and `*.torob.dev`, as long as every SAN is independently covered by an active Application domain scope.
- Domain scopes at public-suffix boundaries such as `*.com` and `*.co.uk` are rejected.
- Unauthorized Application domain create returns `domain_not_authorized`.
- Users have no Application access by default.
- Non-admin Users cannot create Applications.
- Users with `viewer` access can inspect metadata but cannot download private keys.
- Users with `certificate_reader` access can download certificates for that Application.
- Users with `viewer` or `certificate_reader` access cannot create Certificates for that Application.
- Users with `manager` access can create Certificates for that Application when every requested SAN is covered by that Application's domain scopes.
- Users with `manager` access can resolve active target Users by exact email through `GET /v1/users/lookup` for Applications they manage, without receiving a global User list.
- Non-admin User lookup without `application_id`, without manager access, or with non-exact/invalid email is rejected.
- Users with global role `admin` can access all Applications.
- Admin Users can create Certificates for any Application when every requested SAN is covered by that Application's domain scopes.
- Admin Users can query global audit events.
- Non-admin Users can query audit events only when scoped to Applications or Certificates they can access.
- Non-admin unscoped audit queries and audit queries for hidden Applications or Certificates return `403` or `404` without leaking hidden resource details.
- Audit scoping tests assert non-admin visibility uses structured `scope_application_id` and `scope_certificate_id` columns, not free-form JSON metadata.
- Criteria-based material retrieval returns an existing ready certificate without new ACME issuance.
- Missing material (`404`) is followed by `POST /v1/sync/certificates`; clients then retry material/archive endpoints until ready or failed.
- Creating a Certificate row without valid material triggers Certhub reconciliation to create or enqueue exactly one issuing CertificateVersion when the Certificate state is eligible for issuance.
- Not-ready material (`409`) is handled by retrying material/archive endpoints; there is no separate request resource to poll.
- Expired material is not returned by current material endpoints. If a post-expiry reissue is issuing, clients receive `409 certificate_not_ready`; if the latest post-expiry work failed, clients receive `409 certificate_issuance_failed`; if no active valid version exists and no issuing or failed latest work exists, clients receive `409 certificate_no_active_version`.
- Revoked CertificateVersions are not returned by current material endpoints, but remain downloadable through the version archive endpoint while their material is retained.
- The background renewal worker enqueues exactly one automatic renewal when an active valid CertificateVersion enters the selected issuer's `renewal_window_seconds` and issuer, domain-scope, and overlap constraints allow it.
- Renewal in progress while the old version is still valid returns the old valid CertificateVersion from material endpoints.
- Successful renewal creates a higher-numbered CertificateVersion and material endpoints return that newest valid version.
- Failed renewal while an older version is still valid does not break material retrieval; material endpoints continue returning the older valid version.
- A Certificate has at most one `status=issuing` CertificateVersion at any time.
- A Certificate has at most one valid, not-expired CertificateVersion except during replacement overlap, and never more than two valid, not-expired CertificateVersions.
- Manual renewal while a renewal CertificateVersion is already `status=issuing` returns the existing in-progress renewal instead of creating another version.
- Manual renewal while a non-renewal CertificateVersion is `status=issuing` returns `409 conflict`.
- Manual renewal that could create more than two valid, not-expired CertificateVersions is rejected with `renewal_overlap_exists`.
- Manual renewal and key rotation are rejected when there is no active valid CertificateVersion or when current Application domain scopes no longer cover every Certificate SAN.
- Key rotation creates a higher-numbered CertificateVersion on the same Certificate identity, not a new Certificate row, and follows replacement-overlap constraints.
- Reissue after no-active-version state uses the same Certificate identity when triggered by `POST /v1/certificates/{certificate_id}/reissue`.
- Current material endpoints do not return material from revoked, expired, failed, or incomplete CertificateVersions.
- Revoking a CertificateVersion marks only that version revoked for current serving immediately; other active valid versions remain current if present.
- ACME revocation failure after local revocation keeps local state revoked and records `certificate_revocation_failed`.
- Repeating version revoke after ACME revocation failure retries remote revocation and records `certificate_revocation_retried`.
- Repeating version revoke after local and ACME revocation have both succeeded is idempotent and does not create duplicate revocation side effects.
- A CertificateVersion is never deleted through public APIs.
- Multiple Applications requesting the same SANs get separate Certificate rows and CertificateVersions.
- Current retrievable CertificateVersions must retain `private_key_pem`; private keys may only be cleared for versions that can no longer be returned.
- Deleting a domain scope blocks future Application-token criteria retrieval for names no longer covered by remaining scopes, but does not revoke existing Certificates.
- DNS provider failure marks issuance failed and writes audit event.
- DNS provider and ACME failure messages are sanitized before they are persisted, logged, audited, or returned.
- DNS provider and ACME upstream responses containing credentials, TXT values, account keys, bearer tokens, request headers, or provider account identifiers are sanitized before persistence, logs, audit metadata, and API errors.
- Multi-SAN certificates can use multiple DNS provider zones and multiple DNS provider implementations in the same Certificate order; each ACME authorization uses its own longest normalized DNS-label-boundary active zone.
- Issuance fails with `failure_code=dns_provider_not_found` if any authorization has no matching active provider zone; material endpoints expose it through `certificate_issuance_failed`.
- DNS provider `auto` mode refreshes zones from provider API into `dns_provider_zones` and rejects User edits to the zone list.
- DNS provider `auto` mode refresh creates a durable `dns_provider_zone_refresh_jobs` row and returns `202 Accepted` with job metadata.
- Failed DNS provider `auto` refresh preserves the previous zone rows and records sanitized failure metadata without replacing them with an empty or partial discovery result.
- DNS provider `auto` refresh that discovers a zone already owned by another provider fails the refresh job with `dns_provider_zone_conflict` and preserves the previous zone rows unchanged.
- DNS provider `manual` mode uses only admin-added zones; discovered zones are suggestions only.
- DNS provider selection uses longest normalized DNS-label-boundary suffix match and fails with `failure_code=dns_provider_not_found` when no zone matches.
- DNS-01 cleanup removes only exact TXT values Certhub presented for the current order and preserves unrelated `_acme-challenge` TXT values.
- DNS-01 cleanup failure records a sanitized error without logging or returning the ACME TXT value.
- Issuance workers claim durable jobs with row-level locking or leases and expired leases are reclaimable.
- Worker crash recovery retries idempotently without creating duplicate CertificateVersions, duplicate active jobs, duplicate DNS challenge records, or duplicate successful audit events.
- DNS challenge records store exact TXT values encrypted and cleanup uses those recorded values.
- Duplicate active DNS provider zones for the same exact zone are rejected.
- Omitted issuer requires exactly one active default issuer; no active default or multiple active defaults returns non-retryable `issuer_not_configured`, and multiple active defaults are rejected by constraint.
- Transient issuer or ACME account dependency outages return retryable `issuer_unavailable`.
- Application-token certificate material retrieval uses criteria-based endpoints: `POST /v1/sync/certificates/tls-material` and `POST /v1/sync/certificates/tls-archive`.
- Criteria-based material endpoints reject User access tokens and reject request bodies containing `application_id`.
- User login-session certificate material retrieval uses the ID-based endpoint: `GET /v1/certificates/{certificate_id}/tls-archive`.
- The ID-based archive endpoint rejects Application tokens and requires `certificate_reader`, `manager`, or global `admin`.
- ID-based resource APIs return `404` when a resource does not exist or is not visible; `403` is reserved for visible resources where the authenticated identity lacks the requested action or uses the wrong token class.
- Conditional material requests evaluate authentication and authorization before `If-None-Match`; unauthorized clients cannot use matching ETags to learn whether material exists or changed.
- Malformed, weak, or cross-certificate `If-None-Match` values never produce `204` or `304` and do not reveal whether a hidden Certificate exists.
- Criteria-based material endpoints and the ID-based archive endpoint write `private_key_read` audit events only when returning material with `200 OK`.
- Material endpoints return `ETag: <material_etag>` and `Cache-Control: no-store`, `Pragma: no-cache`, and `Vary: Authorization`.
- Criteria-based material endpoints return `204 No Content` without `private_key_read` audit when `If-None-Match` matches latest valid `material_etag`.
- The ID-based archive endpoint returns `304 Not Modified` without `private_key_read` audit when `If-None-Match` matches latest valid `material_etag`.
- Tar.gz archive endpoints contain only fixed entry names and never include absolute paths, `..` paths, symlinks, hard links, device entries, user-controlled filenames, raw token values, or backend filesystem paths.
- CertificateVersion `material_etag` is generated from exact returned material and changes when cert, chain, fullchain, or private key changes.
- Archive endpoints return `application/gzip` containing `cert.pem`, `chain.pem`, `fullchain.pem`, `privkey.pem`, and `metadata.json`.
- Archive endpoints set `Content-Disposition: attachment; filename="<safe_certificate_name>.tar.gz"` where `<safe_certificate_name>` is derived from the first normalized SAN, falls back to Certificate ID, and contains no `*` or `.`.
- Certificate lifecycle operations use only ID-based endpoints; criteria-based renew, rotate-key, reissue, and version revoke endpoints do not exist.
- Renewal creates a higher-numbered CertificateVersion with a new private key only when an active valid version exists and is inside the issuer renewal window.
- Key rotation creates a higher-numbered CertificateVersion with a new private key and is not gated by the renewal window, but still requires an active valid version.
- Reissue creates a higher-numbered CertificateVersion when no active valid version exists and no version is issuing.
- Key rotation sets parent Certificate status `rotating_key` while in progress and records key-rotation failures in Certificate and CertificateVersion failure metadata.
- Identity changes create a new Certificate row, not just a new CertificateVersion.
- CertificateVersions have `created_at`, `updated_at`, `started_at`, and `completed_at` timestamps sufficient to detect stuck issuing work.
- Invalid wildcard values such as `*.*.torob.dev`, `a.*.torob.dev`, and `api.*.torob.dev` are rejected as both domain scopes and certificate SANs.
- All JSON error responses use the standard error envelope with stable `error.code`, `retryable`, `retry_after_seconds`, and non-secret `details`.
- Retryable errors with `retry_after_seconds` also set the HTTP `Retry-After` header.
- `/healthz` returns liveness without external dependency checks.
- `/readyz` reports readiness failures for PostgreSQL, migration compatibility, encryption key, and required process configuration without exposing secrets.
- `/metrics` exposes required Prometheus metrics without private keys, raw tokens, credentials, or high-cardinality raw domain labels.
- Structured logs redact private keys, raw tokens, passwords, DNS provider credentials, ACME account keys, and encrypted payloads.
