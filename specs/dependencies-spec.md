# Certhub Dependencies Spec

## Summary

This spec lists approved third-party libraries and tools for Certhub v1. Third-party means anything that is not part of the programming language standard library.

The implementation should prefer standard library functionality where it is sufficient. Adding a third-party dependency not listed here requires updating this spec and review before use.

## Dependency Rules

- Pin all Go dependencies through `go.mod` and `go.sum`.
- Pin all web dependencies through `web/package.json` and the committed lockfile.
- Keep release binaries self-contained and compatible with the binary artifact rules in `repo-structure-spec.md`.
- Prefer pure-Go dependencies for Go binaries. Any dependency that requires cgo must be explicitly reviewed before use.
- Separate runtime dependencies from build-time and code-generation tools.
- Do not add framework libraries only for convenience if the standard library or a small local package is enough.
- Do not add dependencies whose upstream repository or package registry marks them as archived, deprecated, or unmaintained.
- Before adding or upgrading a dependency, check the upstream repository status, package registry deprecation metadata where applicable, and recent release/maintenance activity.
- Dependency changes must run vulnerability checks for Go and npm dependency graphs.
- Dependency changes must preserve committed lockfiles and checksum files; unpinned transitive dependency changes require review.
- Dependency changes must review licenses for compatibility with company policy and redistribution.
- Dependency changes must not introduce cgo, native postinstall scripts, binary downloads, or runtime dynamic-library requirements without explicit review.
- Dependency changes must not introduce browser runtime network calls to third-party origins.

## Go Dependencies

### Server Runtime

| Dependency | Purpose |
| --- | --- |
| `github.com/go-acme/lego/v4` | ACME client and DNS-01 provider integrations, including Cloudflare and ArvanCloud. |
| `github.com/jackc/pgx/v5` | PostgreSQL driver and connection pool. |
| `github.com/pressly/goose/v3` | PostgreSQL migration runner. |
| `golang.org/x/crypto` | Argon2id password hashing and other non-standard Go crypto helpers when needed. |
| `github.com/pquerna/otp` | TOTP generation and validation for password-login 2FA. |
| `github.com/coreos/go-oidc/v3` | OIDC provider discovery and ID-token verification. |
| `golang.org/x/oauth2` | OAuth2/OIDC PKCE flow support. |
| `golang.org/x/net/idna` | IDN normalization to ASCII punycode for certificate identifiers and domain scopes. |
| `golang.org/x/net/publicsuffix` | Public suffix boundary checks for rejecting unsafe exact and wildcard domain scopes. |
| `github.com/google/uuid` | UUID generation and parsing. |
| `github.com/prometheus/client_golang` | Prometheus metrics instrumentation and `/metrics` handler. |

### CLI Runtime

| Dependency | Purpose |
| --- | --- |
| `go.yaml.in/yaml/v4` | YAML configuration file parsing. |

The CLI should otherwise use the Go standard library and shared local packages under `pkg/`.

### Kubernetes Operator Runtime

| Dependency | Purpose |
| --- | --- |
| `sigs.k8s.io/controller-runtime` | Kubernetes controller runtime, reconciliation loop, API client, manager, watches, and status updates. |
| `go.yaml.in/yaml/v4` | YAML configuration file parsing if the operator supports file-based local configuration. |

The operator should otherwise use shared local packages under `pkg/` for Certhub API communication and certificate material handling.

### Go Build And Code Generation

| Dependency | Purpose |
| --- | --- |
| `github.com/sqlc-dev/sqlc` | Generate type-safe Go database access code from SQL. Build-time/code-generation dependency only. |
| `github.com/oapi-codegen/oapi-codegen/v2` | Generate Go OpenAPI types, clients, and server glue. Build-time/code-generation dependency only. |

Generated code may be committed if the repository chooses committed generated API/database code. The generator binaries themselves must not be embedded in release binaries.

## TypeScript Dependencies

### Web Runtime

| Dependency | Purpose |
| --- | --- |
| `react` | Web UI component framework. |
| `react-dom` | React browser rendering. |
| `react-router` | Client-side routing for the CSR web application. |
| `@tanstack/react-query` | Server-state fetching, caching, invalidation, and mutation handling. |
| `openapi-fetch` | Type-safe HTTP client generated from the OpenAPI schema. |
| `zod` | Client-side validation for user input and parsed API data where useful. |
| `lucide-react` | Icon set for buttons, navigation, and compact UI controls. |

### Web Build And Code Generation

| Dependency | Purpose |
| --- | --- |
| `vite` | TypeScript CSR development server and production bundler. |
| `typescript` | Type checking and compilation support. |
| `openapi-typescript` | Generate TypeScript types from `api/openapi.yaml`. |

Build-time web dependencies must not be served to browsers except through normal frontend bundling output.

## Tests

Required dependency and supply-chain checks:

- Dependency allowlist checks fail when `go.mod`, `web/package.json`, or lockfiles add a runtime or build dependency not listed in this spec.
- Go and web lockfile drift checks fail when dependency manifests and committed checksum/lock files disagree.
- Frozen install checks verify Go module sums and web lockfile integrity hashes before tests or release builds run.
- Dependency checks reject unreviewed Git URL, tarball URL, local path, workspace escape, or registry-alias dependencies.
- Go vulnerability checks cover every Go module and build/code-generation tool used for release artifacts.
- Web dependency audits cover runtime and build dependency graphs and fail on known exploitable production-impacting vulnerabilities.
- Vulnerability ignore rules require an expiry date, affected component, severity, and mitigation note.
- Dependency review checks fail for archived, deprecated, unmaintained, yanked, or registry-deprecated packages.
- Dependency review checks fail when a new dependency introduces cgo, native postinstall scripts, binary downloads, install-time network fetches, or runtime dynamic-library requirements without explicit review.
- Package-manager install scripts are disabled or audited in CI; any dependency that requires an install script must be explicitly reviewed.
- Browser bundle checks fail when dependency code adds third-party runtime network origins, remote asset URLs, `eval`, dynamic remote script loading, or unsafe HTML rendering helpers.
- Release artifact checks prove build-time/code-generation tools and package-manager caches are not embedded in binaries, containers, or frontend assets.
- Release artifact checks include SBOM generation from the locked dependency graph and fail when artifacts contain dependencies absent from the SBOM.

## Explicitly Avoided Dependencies

- No Go web framework dependency such as `gin`, `echo`, or `fiber` in v1 unless the API implementation proves the standard `net/http` approach is insufficient.
- No ORM such as `gorm`; database access uses SQL, `pgx`, and generated code from `sqlc`.
- No CLI framework such as `cobra` in v1; the CLI is intentionally limited to `certhub-cli run` with default scheduler mode and `--once` one-shot mode, and should use the standard Go flag package unless the command surface grows further.
- No cgo-based dependency without explicit review.
- No `gopkg.in/yaml.v3`; its upstream repository is archived/unmaintained. Use `go.yaml.in/yaml/v4` for new code.
