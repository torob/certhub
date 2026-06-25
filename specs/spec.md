# Certhub Spec

## Summary

Certhub is the company source of truth for public TLS certificates. Applications, local agents, CLI users, Kubernetes operators, and web-console users interact with Certhub instead of talking directly to Let's Encrypt, DNS providers, or local certificate stores.

This file glues the component specs together. It defines the reading order, ownership boundaries, and consistency rules between specs.

## Technology Choices

- Backend server: Go.
- CLI: Go.
- Kubernetes operator: Go.
- Web UI: TypeScript in client-side rendering mode (CSR).
- Database: PostgreSQL.

## Spec Files

- `spec.md`: umbrella spec, reading order, cross-spec precedence, and product boundary summary.
- `backend-spec.md`: Go backend API, data model, authorization, issuance, renewal, DNS-01, security, observability, and PostgreSQL persistence.
- `frontend-spec.md`: TypeScript CSR web console for all management workflows.
- `cli-spec.md`: Go local sync CLI that retrieves certificate material from Certhub, updates local files atomically, and uses `certhub-cli run` for both scheduler mode and one-shot mode with `--once`.
- `k8s-operator-spec.md`: Go Kubernetes operator that syncs Certhub certificate material into Kubernetes TLS Secrets.
- `dependencies-spec.md`: approved third-party libraries and tools for server, CLI, operator, and web UI.
- `repo-structure-spec.md`: repository layout, package boundaries, build artifacts, deployment assets, and migration plan.

## Reading Order

1. Read `backend-spec.md` first. It is the source of truth for domain concepts, API behavior, authorization, persistence, and certificate lifecycle.
2. Read `frontend-spec.md` next. It defines how humans perform all management work through the web interface.
3. Read `cli-spec.md` for host/local certificate material sync behavior.
4. Read `k8s-operator-spec.md` for Kubernetes certificate material sync behavior.
5. Read `dependencies-spec.md` before adding or changing third-party libraries.
6. Read `repo-structure-spec.md` before implementation starts or when moving files into the target repository layout.

## Product Boundaries

Certhub has four runtime components:

- Backend server: Go service with ACME/DNS-01 workers, API surface, audit log, PostgreSQL persistence, embedded web UI serving, and optional process-config-managed self-certificate sync for its reserved `certhub_server` Application.
- Web application: TypeScript CSR management console for Users and admins, built into static assets served by the backend server binary.
- CLI: Go Application-token client for syncing local files through `certhub-cli run`, either in default scheduler mode or one-shot mode with `--once`.
- Kubernetes operator: Go Application-token client that syncs material into Kubernetes Secrets.

The backend is the only component that:

- Talks to Let's Encrypt or any ACME CA.
- Talks to Cloudflare, ArvanCloud, or other DNS providers.
- Stores private keys, ACME accounts, provider credentials, tokens, Users, Applications, and audit events.
- Decides certificate identity, reuse, renewal, key rotation, revocation, and deletion semantics.

## Identity Model

- Users are humans.
- Applications are certificate-owning identities.
- Users do not own personal certificates.
- Users can create Application-owned Certificates through the web interface when authorized.
- Applications use Application tokens for runtime/local sync flows.
- Application token authentication always requires a valid Application token. Applications may also restrict accepted token use to trusted source IP/CIDR ranges.
- Application tokens have no roles; domain authorization comes only from Application domain scopes.

## Certificate Access Model

There are two certificate access families:

- Management and human access: ID-based, User-authenticated endpoints under `/v1/certificates/...`.
- Local material sync: criteria-based, Application-token endpoints under `/v1/sync/certificates...`.

Rules:

- Web management must use User access tokens and ID-based or Application ID-based endpoints.
- CLI and Kubernetes operator must use Application tokens and `/v1/sync/...` endpoints.
- Browser code must not call `/v1/sync/...` with a User login session.
- Application-token clients must not send `application_id`; the backend derives the Application from the token.
- Application-token clients cannot authenticate by IP address alone. Trusted source IP/CIDR checks are an optional additional restriction after token validation.

## Management Rule

All management work must be possible through the web interface when the backend exposes a User-authenticated management endpoint.

Management includes:

- Users.
- Applications.
- Application tokens.
- User grants.
- Domain scopes.
- Application-owned Certificate creation.
- Certificate lifecycle actions.
- Issuers.
- DNS providers and zones.
- Audit events.

CLI and Kubernetes operator are not management surfaces in v1. They sync certificate material from Certhub to local runtime stores.

## Shared API Rules

- Public API changes must be reflected in `backend-spec.md`.
- Frontend, CLI, and operator specs must be updated when a backend endpoint they use changes.
- Error responses use the backend standard error envelope.
- Clients branch on `error.code`, not free-form message text.
- Retryable errors must honor `Retry-After` or `retry_after_seconds` when present.
- Sensitive values must never be written to logs, telemetry, local metadata, or audit details.

## Local Material Sync

Local material sync means copying the latest valid certificate material from Certhub to a local runtime store.

Sync clients:

- Backend server may reconcile Certhub's own reserved `certhub_server` certificate desired state from process configuration to database state, then sync its latest valid material to local filesystem files for its HTTPS listener.
- CLI syncs material to local filesystem directories through `certhub-cli run`, using `--once` for one-shot mode.
- Kubernetes operator syncs material to Kubernetes TLS Secrets.

Sync endpoints:

- `POST /v1/sync/certificates`
- `POST /v1/sync/certificates/tls-material`
- `POST /v1/sync/certificates/tls-archive`

Local material sync does not mean DNS provider zone refresh or ACME issuance. DNS provider zone discovery and refresh are management operations under the DNS provider API namespace.

## Source Of Truth

When specs overlap, use this precedence:

1. `backend-spec.md` for API behavior, data model, security, auth, and lifecycle semantics.
2. `frontend-spec.md` for web UX and management coverage.
3. `cli-spec.md` for local filesystem sync behavior.
4. `k8s-operator-spec.md` for Kubernetes reconcile behavior.
5. `repo-structure-spec.md` for repository layout and implementation organization.

If a conflict is found, update the lower-precedence spec to match the higher-precedence spec, unless the product decision itself changes.

## Implementation Gate

Before implementation starts, these must be true:

- Backend public endpoints used by frontend, CLI, and operator are explicitly listed.
- The web spec covers every User-authenticated management endpoint.
- CLI and operator specs use only `/v1/sync/...` for Application-token material sync.
- DNS provider refresh endpoints are not under `/v1/sync/...`.
- Repository structure spec identifies where each component and shared package belongs.
- Server binary embeds the production web UI static assets so v1 deployment does not require Nginx or another separate static file server.
- Server self-certificate sync, when enabled, is limited to the reserved process-config-managed `certhub_server` Application and does not replace CLI/operator sync for other Applications.
- Security test coverage exists for backend auth, embedded web serving, cache/CSP behavior, secret redaction, ACME/DNS credential handling, frontend token and XSS handling, CLI local file writes, Kubernetes Secret/RBAC behavior, dependency supply chain, and release artifacts.
- Security checks include negative tests that prove rejected credentials, unauthorized identities, hostile paths, malicious HTML-like input, and leaked-secret canaries fail closed.
- Secret canary tests cover backend logs, metrics, audit metadata, frontend browser storage, CLI local files and output, Kubernetes status/events, and release artifacts.
- `api/openapi.yaml` exists before implementation starts and defines every public endpoint, request body, response body, error envelope, pagination parameter, filter parameter, and example needed by backend, frontend, CLI, and operator.
