# Certhub CLI Spec

## Summary

Certhub CLI is a narrow certificate material sync tool. Its only v1 purpose is to retrieve the latest TLS certificate material from the Certhub backend for one or more complete certificate criteria sets and update local files on disk. It supports both one-shot sync and a built-in scheduler mode for container or long-running host deployments.

The CLI talks only to the Certhub backend API. It does not implement ACME, DNS-01, Cloudflare, ArvanCloud, certificate lifecycle management, User login, Application administration, or User administration locally.

The CLI authenticates only with an Application token. User access tokens are not supported by the CLI in v1.

The CLI is not required for Certhub's own HTTPS serving certificate in v1. The backend server has a separate self-certificate sync path for the reserved `certhub_server` Application.

Each backend request must send an `X-Request-ID` correlation ID and include it in error output when the backend returns one.

## Technology Choices

- Implementation language: Go.
- Distribution format: native command-line binary and minimal container image.
- Runtime behavior: Certhub API client only; no local ACME, DNS provider, or lifecycle implementation.

## Goals

- Keep one or more local TLS material directories up to date from Certhub.
- Be safe to run from cron, systemd services, deployment scripts, Docker Compose, container schedulers, and host provisioning scripts.
- Provide a built-in scheduler mode so a CLI container can periodically sync without requiring cron or systemd inside the container.
- Avoid rewriting local files when the backend material has not changed.
- Write private keys with safe permissions.
- Avoid leaking private keys, bearer tokens, or PEM material to logs.

## Non-Goals

- No User login, OIDC login, User session refresh, logout, or 2FA commands.
- No Application creation, token management, User management, grant management, issuer management, or DNS provider management.
- No server bootstrap, first-admin creation, migration, issuer bootstrap, or DNS provider bootstrap commands. Those direct database management jobs belong to the `certhub-server` binary.
- No explicit certificate lifecycle, version revoke, inspect, or list commands.
- No local ACME or DNS provider behavior.
- No ID-based certificate retrieval in v1. The CLI always uses criteria-based retrieval.
- No syncing of Certhub's own reserved `certhub_server` serving certificate; that local filesystem sync is owned by the backend server.

## Configuration

Configuration sources:

- Config file: source of all non-secret sync configuration.
- Environment variables: allowed only for `CERTHUB_URL` and `CERTHUB_TOKEN`.
- Command-line flags: runtime mode and output controls only. They must not define or override certificate criteria, output paths, or configured sync behavior.

Environment variables:

```text
CERTHUB_URL
CERTHUB_TOKEN
```

Default config file:

```text
$HOME/.config/certhub/config.yaml
```

Config format:

```yaml
url: https://certhub.example.com
# token may be omitted from the file when CERTHUB_TOKEN is provided.
token: cth_app_v1_example_redacted
allow_plain_http_for_local_development: false
sync:
  wait: true
  timeout: 5m
  poll_interval: 10s
  force: false
  fail_fast: false
scheduler:
  interval: 6h
  jitter: 30s
  run_on_start: true
certificates:
  - domains:
      - api.torob.dev
      - "*.torob.dev"
    key_type: ecdsa-p256
    issuer: letsencrypt_production
    out_dir: /etc/certhub/api
  - domains:
      - admin.torob.dev
    out_dir: /etc/certhub/admin
```

Rules:

- `token` must be an Application token with prefix `cth_app_v1_`.
- The backend may also require this Application token to be used from one of the Application's trusted source IP/CIDR ranges. The CLI still sends only the token; it does not send or claim a source IP.
- User access tokens with prefix `cth_uat_v1_` must be rejected locally before making backend calls.
- The CLI must not write tokens to shell history, logs, stdout, stderr, or metadata files.
- Config files containing tokens must have mode `0600`; otherwise the CLI must refuse to use the stored token.
- Only `url` and `token` may be overridden by environment variables, using `CERTHUB_URL` and `CERTHUB_TOKEN`.
- The config file does not support environment-variable interpolation. A literal value such as `${CERTHUB_TOKEN}` must be treated as an invalid token string, not expanded.
- If `CERTHUB_TOKEN` is set, the config file may omit `token` or may contain a token that is overridden for that process. File-mode checks for stored tokens apply only when a raw token value is present in the file.
- Domains, key type, issuer, output directories, wait behavior, timeout, poll interval, force behavior, fail-fast behavior, scheduler timing behavior, and `allow_plain_http_for_local_development` must come only from the config file.
- Command-line flags may only choose the config path, output format, quiet mode, and whether `run` executes one sync cycle with `--once`.
- Command-line flags must not set or override certificate criteria, output directories, key type, issuer, wait behavior, timeout, poll interval, force behavior, fail-fast behavior, scheduler interval, scheduler jitter, scheduler run-on-start behavior, `allow_plain_http_for_local_development`, or which certificates are synced.
- `allow_plain_http_for_local_development` defaults to `false`. When `false`, `url` must use `https://`. When `true`, `http://` is allowed only for local development.
- `certificates` is the preferred config shape for multi-certificate sync.
- Each configured certificate entry must have non-empty `domains` and `out_dir`.
- Configured certificate entries do not have names in v1. `certhub-cli run` syncs every configured certificate entry during each sync cycle.
- `key_type` and `issuer` are optional per certificate entry.
- Top-level `sync` contains default sync behavior for every configured certificate.
- Top-level `scheduler` contains scheduler behavior for `certhub-cli run` when `--once` is not set.
- `scheduler.interval` is required for scheduler mode and must be positive. One-shot mode does not require a `scheduler` block.
- `scheduler.jitter` is optional, defaults to `0`, and adds a random delay up to the configured duration before each scheduled cycle to avoid synchronized fleet traffic.
- `scheduler.run_on_start` defaults to `true`. When `true`, the first sync cycle starts immediately after startup validation. When `false`, the first sync cycle starts after `scheduler.interval` plus optional jitter.
- A certificate entry may override `wait`, `timeout`, `poll_interval`, and `force` for that entry.
- Top-level `domains`, `key_type`, `issuer`, and `out_dir` may be supported as a config-file-only single-certificate shorthand, but must not be mixed with `certificates`.

## Input Validation

The CLI should prevalidate non-human command arguments when the backend format is known, then pass backend validation errors through unchanged.

Fields that should use backend-compatible validators include:

- Certificate domains: `certificate_identifier`.
- Issuer name: `machine_name`.
- Key type: documented enum.
- File output paths are local filesystem paths and must not use machine-name validation.

## Command

### Run Certificate Material Sync

```bash
certhub-cli run
```

`certhub-cli run` is the single v1 entrypoint. By default it runs as a long-running scheduler. For one-shot sync, pass `--once`.

Flags:

```text
--config <path>                  optional config file path
--once                           run one sync cycle and exit instead of scheduler mode
--json                           print machine-readable sync summary
--quiet                          suppress non-error human output
```

Backend calls:

```http
POST /v1/sync/certificates/tls-material
POST /v1/sync/certificates
```

Rules:

- The CLI sends the complete criteria on every backend request: normalized domains, optional key type, and optional issuer.
- The CLI derives Application identity only from the Application token. It must never send `application_id`.
- The CLI first builds a sync plan. Each plan item contains domains, optional key type, optional issuer, and output directory.
- If the config contains `certificates`, the plan contains all configured entries.
- If the config uses top-level single-certificate shorthand, the plan contains that one configured entry.
- There are no certificate selection flags in v1. Every configured certificate entry is synced during every `certhub-cli run` sync cycle.
- Command-line flags must not create ad hoc certificate criteria. Every synced certificate must be defined in the config file.
- `certhub-cli run --once` runs one complete sync cycle for every configured certificate entry and exits.
- `certhub-cli run` without `--once` runs scheduler mode and repeats the same full configured sync plan.
- Each plan item uses the same backend flow independently.
- For each plan item, the first request is always `POST /v1/sync/certificates/tls-material`.
- If that item's local metadata contains `material_etag`, the CLI sends `If-None-Match`.
- If the backend returns `200 OK`, the CLI writes the returned material to that item's output directory and updates metadata.
- If the backend returns `204 No Content`, the CLI leaves that item's existing files unchanged and marks the item successful.
- If the backend returns `404 certificate_not_found`, the CLI calls `POST /v1/sync/certificates` once with the same criteria, then retries `POST /v1/sync/certificates/tls-material`.
- If the backend returns `409 certificate_not_ready`, the CLI retries only when that configured certificate entry has `wait=true`.
- If `wait=false` and material is unavailable, that item fails with code `6`.
- If the backend returns `409 certificate_issuance_failed`, that item fails with code `7`. The CLI should display `error.details.failure_code` when present, such as `dns_provider_not_found` or `dns_validation_failed`.
- If the backend returns `409 certificate_no_active_version`, that item fails with code `7` and should tell the operator that User reissue is required.
- If the backend returns `409 issuer_not_configured`, that item fails with code `1` and should tell the operator that issuer configuration is required.
- The CLI must use backend `Retry-After` or `error.retry_after_seconds` before the configured `poll_interval`.
- If timeout occurs, that item fails with code `8`.
- By default, multi-certificate sync continues after an item fails so unrelated certificates can still update.
- Configured `fail_fast=true` stops the run after the first item failure.
- The process exit code is `0` only when every configured certificate entry succeeds. If any item fails, the process exits with the highest item exit code.
- Configured `force=true` bypasses each item's local `material_etag` optimization but must still write only material returned by the backend.

## Local Files

Each configured certificate entry has one `out_dir`. The CLI writes material into immutable release directories and atomically switches a `current` symlink.

Live paths:

```text
<out_dir>/current/cert.pem
<out_dir>/current/chain.pem
<out_dir>/current/fullchain.pem
<out_dir>/current/privkey.pem
<out_dir>/current/.certhub-material.json
```

Internal layout:

```text
<out_dir>/releases/<generation>/cert.pem
<out_dir>/releases/<generation>/chain.pem
<out_dir>/releases/<generation>/fullchain.pem
<out_dir>/releases/<generation>/privkey.pem
<out_dir>/releases/<generation>/.certhub-material.json
<out_dir>/.certhub-staging/<temporary-generation>/
<out_dir>/current -> releases/<generation>
```

Metadata file:

```json
{
  "domains": ["*.torob.dev", "api.torob.dev"],
  "key_type": "ecdsa-p256",
  "issuer": "letsencrypt_production",
  "certificate_id": "018f6a8e-4f7d-7c2b-a4b9-7c771a4f1d41",
  "version": 3,
  "material_etag": "\"cth-mat-v1.JYjzT2o0Gd9c6SwJ5YYRWR6d9xWJ9G7dy2cW3rQpQ9E\"",
  "serial_number": "03aabb",
  "fingerprint_sha256": "abc123",
  "not_before": "2026-06-24T00:00:00Z",
  "not_after": "2026-09-22T00:00:00Z",
  "last_synced_at": "2026-06-24T12:00:00Z"
}
```

Write rules:

- The CLI must create each configured certificate's `out_dir`, `releases`, and `.certhub-staging` directories if they do not exist.
- Directories created by the CLI should use mode `0750`.
- `privkey.pem` must be written with mode `0600`.
- Certificate and chain files should be written with mode `0644`.
- `.certhub-material.json` should be written with mode `0644` and must not contain private key material or tokens.
- Material-set updates must be atomic. A consumer reading through `<out_dir>/current/` must see either the full previous material set or the full new material set, never a mixture.
- To update material, the CLI writes all files and metadata into a temporary staging directory under `<out_dir>/.certhub-staging`, sets file modes, `fsync`s files and directories when practical, renames the staging directory into `<out_dir>/releases/<generation>`, then atomically replaces the `<out_dir>/current` symlink with a symlink to that release.
- The CLI must never modify files inside an existing release directory.
- If any step fails before the `current` symlink switch, the previous `current` target must remain unchanged.
- If the symlink switch succeeds but later cleanup fails, the sync is still successful and cleanup can be retried later.
- The CLI should hold an exclusive lock per `out_dir` while updating that directory to avoid concurrent writers racing on `current`.
- Old release directories may be garbage-collected only after a successful switch, and the CLI should keep at least the previous release by default.
- PEM material must not be printed to stdout/stderr or logs.
- Existing releases are not modified. Updating local material means publishing a new release and switching `current`.

## Output

Default human output should print one brief line per configured certificate:

```text
updated /etc/certhub/api certificate_id=018f6a8e-4f7d-7c2b-a4b9-7c771a4f1d41 version=3 not_after=2026-09-22T00:00:00Z
current /etc/certhub/admin material_etag="cth-mat-v1.JYjzT2o0Gd9c6SwJ5YYRWR6d9xWJ9G7dy2cW3rQpQ9E"
```

For failures in a multi-certificate run, stderr should include the output directory, domains, backend error code, and request ID when available.

`--json` output always uses a result array, even when only one certificate entry is configured:

```json
{
  "changed": true,
  "configured": 2,
  "succeeded": 2,
  "failed": 0,
  "results": [
    {
      "changed": true,
      "out_dir": "/etc/certhub/api",
      "domains": ["*.torob.dev", "api.torob.dev"],
      "certificate_id": "018f6a8e-4f7d-7c2b-a4b9-7c771a4f1d41",
      "version": 3,
      "material_etag": "\"cth-mat-v1.JYjzT2o0Gd9c6SwJ5YYRWR6d9xWJ9G7dy2cW3rQpQ9E\"",
      "not_after": "2026-09-22T00:00:00Z",
      "request_id": "req_123"
    },
    {
      "changed": false,
      "out_dir": "/etc/certhub/admin",
      "domains": ["admin.torob.dev"],
      "material_etag": "\"cth-mat-v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"",
      "request_id": "req_124"
    }
  ]
}
```

Errors must be printed to stderr and return non-zero exit codes. The CLI must parse the backend standard error envelope and branch on `error.code`, not message text.

## Exit Codes

```text
0 success
1 general error
2 invalid arguments
3 authentication failed
4 authorization denied
5 not found
6 certificate not ready
7 issuance failed
8 timeout or retryable backend dependency unavailable
9 local filesystem write failed
```

Mapping:

- `invalid_domain`, `invalid_request`, and `not_acceptable`: `2`.
- `invalid_token`, `invalid_credentials`, `session_expired`, and `invalid_token`: `3`.
- `application_token_required`, `user_token_required`, `application_access_denied`, `application_source_ip_denied`, and `domain_not_authorized`: `4`.
- `certificate_not_found` after the create attempt still cannot find metadata: `5`.
- `certificate_not_ready`: `6` when not waiting.
- `certificate_issuance_failed` and `certificate_no_active_version`: `7`. If present, include nested `failure_code` or no-active-version metadata in error output.
- `issuer_not_configured`: `1`.
- `service_unavailable`, `issuer_unavailable`, `dns_provider_unavailable`, `dns_zone_discovery_failed`, `rate_limited`, and polling timeout: `8`.
- Local file write, permission, atomic rename, or metadata write failure: `9`.

## Polling Behavior

Polling is used only for configured certificate entries whose config has `wait=true`.

Default:

- Poll interval: backend `Retry-After` or `retry_after_seconds`, otherwise configured `poll_interval`.
- Timeout: configured `timeout`, applied independently to each configured certificate entry.

Per-certificate flow:

1. Call `POST /v1/sync/certificates/tls-material`.
2. On `200 OK`, write material and exit `0`.
3. On `204 No Content`, leave files unchanged and exit `0`.
4. On `404 certificate_not_found`, call `POST /v1/sync/certificates` once.
5. Retry `POST /v1/sync/certificates/tls-material` until ready, failed, or timed out.

The CLI must not poll `POST /v1/sync/certificates`. Readiness is observed only through `POST /v1/sync/certificates/tls-material`.

### Scheduler Mode

`certhub-cli run` without `--once` is a long-running process that repeatedly runs the same full configured sync plan.

When `--json` is used in scheduler mode, the CLI prints one JSON sync summary per cycle as newline-delimited JSON.

Rules:

- Scheduler mode uses the same backend calls, criteria, authorization, local file layout, atomic write behavior, error handling, and exit-code mapping as one-shot sync.
- Scheduler timing comes only from the config file `scheduler` block.
- Scheduler mode must validate the full config before starting the first cycle.
- Scheduler cycles must not overlap. If one cycle is still running when the next interval would start, the next cycle waits until the current cycle completes.
- After a cycle completes, the next cycle starts after `scheduler.interval` plus optional random jitter.
- `SIGTERM` and `SIGINT` trigger graceful shutdown. The CLI must stop scheduling new cycles, allow an in-progress atomic file update to either complete or fail safely, then exit.
- If config validation fails at startup, scheduler exits non-zero.
- A failed sync cycle does not terminate scheduler mode unless the failure is a local configuration error that cannot be fixed without changing config. Backend failures, authorization failures, revoked certificates, and issuance failures are reported for that cycle and retried only according to normal scheduler timing.
- Scheduler mode must not watch config files or reload config dynamically in v1. Configuration changes require restarting the process.
- Docker and Docker Compose deployments should run `certhub-cli run` without `--once` as the container command and mount output directories as volumes.

## Container Image

The CLI has a dedicated Dockerfile at `deploy/docker/cli.Dockerfile`.

Container image rules:

- The image contains the `certhub-cli` binary and only runtime files required to make HTTPS requests, such as CA certificates.
- The image must not contain source code, tests, package-manager caches, build caches, `.git`, local config files, tokens, certificate material, or private keys.
- The image must run as a non-root user by default when possible.
- The default entrypoint is the `certhub-cli` binary. The default command should run `run --config /etc/certhub/config.yaml`.
- One-shot sync remains possible by overriding the container command to `run --once --config /etc/certhub/config.yaml`.
- The image must not bake in `CERTHUB_URL`, `CERTHUB_TOKEN`, certificate criteria, or output paths.
- Docker Compose deployments must pass `CERTHUB_URL` and `CERTHUB_TOKEN` through environment variables or secrets and must mount the config file and output directories explicitly.
- Output volume ownership and permissions must allow the container user to perform atomic writes without making private keys readable by group or world.

## Security Requirements

- Require an Application token. Reject User tokens locally.
- Do not print private keys, certificate PEM, bearer tokens, request Authorization headers, or backend material JSON.
- Do not include private keys or tokens in logs or metadata.
- Write private-key files with `0600`.
- Use HTTPS Certhub URLs by default. Plain HTTP should require an explicit local-development override.
- Respect backend domain-scope checks; do not attempt client-side bypass logic.
- Respect backend Application trusted source CIDR checks; do not attempt to set spoofed forwarded headers or otherwise claim a different source IP.
- Never use certificate IDs for retrieval in v1. Always send full criteria.
- Treat `material_etag` as an opaque value.
- Scheduler mode must not log raw tokens, private keys, PEM material, or full backend material JSON between cycles.

## Tests

Required CLI scenarios:

- CLI rejects missing URL, missing Application token, missing domains, or missing output directory.
- CLI reads only `CERTHUB_URL` and `CERTHUB_TOKEN` from environment variables; all other non-secret config comes from the config file.
- CLI refuses to read a config file containing `token` when the file mode is broader than `0600`.
- CLI refuses token-bearing config files reached through unsafe symlinks, owned by another user, or located under group/world-writable parent directories.
- CLI rejects duplicate YAML keys that could shadow `token`, `out_dir`, `domains`, or sync behavior.
- CLI rejects unsupported command-line flags that try to set certificate criteria, output directories, key type, issuer, wait behavior, timeout, poll interval, force behavior, fail-fast behavior, scheduler timing behavior, or `allow_plain_http_for_local_development`.
- CLI accepts a config with multiple `certificates` entries and syncs all of them.
- CLI does not support certificate selection flags; every configured certificate entry is synced.
- CLI rejects configured certificate entries without `domains` or `out_dir`.
- CLI rejects User access tokens before making backend calls.
- CLI treats `403 application_source_ip_denied` as a non-retryable authorization failure and includes the backend request ID when available.
- CLI never sends `Forwarded`, `X-Forwarded-For`, or other headers that attempt to claim a different source IP.
- CLI rejects plain HTTP Certhub URLs unless config-file-only `allow_plain_http_for_local_development=true`.
- CLI verifies TLS certificates by default and has no silent `insecure_skip_verify` behavior.
- CLI does not forward `Authorization` headers when following redirects to a different host, port, or scheme.
- CLI sends criteria-based `POST /v1/sync/certificates/tls-material` and never sends `application_id`.
- CLI sends `If-None-Match` when `.certhub-material.json` contains `material_etag`.
- `204 No Content` exits `0` and leaves files unchanged.
- `200 OK` writes `cert.pem`, `chain.pem`, `fullchain.pem`, `privkey.pem`, and `.certhub-material.json`.
- Multi-certificate sync writes each certificate to its own `out_dir` release and stores independent `.certhub-material.json` metadata.
- Private key file mode is `0600`.
- Release directories, staging directories, and generated private-key parent directories are created with modes that do not grant group or world write access.
- File mode tests run with permissive and restrictive `umask` values and still produce the required directory and private-key modes.
- Metadata does not contain tokens or private key material.
- Human output, JSON output, errors, and logs never contain private keys, certificate PEM, raw backend material JSON, bearer tokens, or Authorization headers.
- Material updates are atomic by publishing an immutable release directory and switching `current`; failed writes before the switch do not change current local material.
- Atomic update tests include pre-existing malicious symlinks in `.certhub-staging`, `releases`, and `current`; the CLI must not write private key material outside `out_dir`.
- Atomic update tests include symlink race attempts for final material filenames and `current`; the CLI must fail without following the attacker-controlled path.
- CLI refuses to write when `out_dir`, `releases`, `.certhub-staging`, or `current` is an unsafe symlink, non-directory, or path escaping the configured output directory.
- CLI refuses to use existing `out_dir`, `releases`, or `.certhub-staging` directories that are owned by another user or are group/world-writable.
- Existing release directories are immutable: a sync never modifies files inside a previous release, even when cleanup fails.
- Failed writes, failed fsyncs, and failed renames leave no partial private key or backend material JSON in the active `current` release.
- `404 certificate_not_found` calls `POST /v1/sync/certificates` once, then resumes material polling.
- `409 certificate_not_ready` with configured `wait=false` exits `6`.
- `409 certificate_not_ready` with configured `wait=true` polls until material is ready or timeout occurs.
- `certificate_issuance_failed` exits `7` and displays nested `failure_code` when present.
- `certificate_no_active_version` exits `7` and displays reissue guidance.
- Retryable backend dependency errors and rate limits use backend retry hints.
- Polling timeout exits `8`.
- In multi-certificate sync, one item failure does not prevent later items from syncing unless configured `fail_fast=true`.
- In multi-certificate sync, any item failure makes the process exit non-zero with the highest item exit code.
- Configured `fail_fast=true` stops after the first item failure.
- `certhub-cli run --once` runs one full configured sync cycle and exits.
- `certhub-cli run` without `--once` runs all configured certificates on each cycle and never overlaps cycles.
- Scheduler timing uses only config-file `scheduler.interval`, `scheduler.jitter`, and `scheduler.run_on_start`.
- Scheduler handles `SIGTERM` and `SIGINT` without leaving partial private key or backend material JSON in the active `current` release.
- Scheduler mode continues after backend/runtime sync failures and waits until the next configured cycle, except startup config validation failures exit non-zero.
- CLI Docker image contains only the static binary and required runtime CA files, runs without embedded secrets, and defaults to `run --config /etc/certhub/config.yaml`.
- CLI Docker image supports one-shot sync by overriding the container command to `run --once --config /etc/certhub/config.yaml`.
- Docker Compose tests mount config and output volumes, pass only `CERTHUB_URL` and `CERTHUB_TOKEN` through env/secrets, and verify private key file permissions on mounted volumes.
- `--json` produces stable machine-readable result arrays and never includes PEM material.
- `--json` never includes bearer tokens, Authorization headers, private keys, certificate PEM, or DNS criteria secrets.
