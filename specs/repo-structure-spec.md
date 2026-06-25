# Certhub Repository Structure Spec

## Summary

Certhub should use a monorepo. The backend server, CLI, Kubernetes operator, web application, API contracts, deployment assets, and specs are part of one product and should evolve together.

The repository should make ownership boundaries clear while keeping shared protocol, validation, and client code close to the components that use them.

## Technology Choices

- Backend server, CLI, and Kubernetes operator are implemented in Go.
- Web UI is implemented in TypeScript and runs in client-side rendering mode (CSR).
- Backend persistence uses PostgreSQL.
- Repository layout must make these technology boundaries visible in source paths and build targets.

## Goals

- Keep backend, CLI, operator, frontend, specs, and API contracts in one repository.
- Make the Go server, CLI, and operator build as separate binaries.
- Keep backend-only implementation private under `internal/`.
- Keep reusable Go client/types under `pkg/` only when they are intended for import outside one binary.
- Keep the TypeScript web application isolated under `web/`.
- Keep API contracts and examples easy to find and test.
- Keep deployment assets separate from application logic.

## Non-Goals

- Do not split server, CLI, operator, and frontend into separate repositories in v1.
- Do not put backend implementation packages under `pkg/`.
- Do not require frontend code to import Go internals.
- Do not put generated build artifacts in the repository.

## Target Layout

```text
certhub/
  README.md
  go.mod
  go.sum
  Makefile

  specs/
    spec.md
    backend-spec.md
    frontend-spec.md
    cli-spec.md
    k8s-operator-spec.md
    dependencies-spec.md
    repo-structure-spec.md

  api/
    openapi.yaml
    examples/
      sync-certificate-request.json
      sync-material-response.json
      certificate-create-request.json

  cmd/
    certhub-server/
      main.go
    certhub-cli/
      main.go
    certhub-operator/
      main.go

  internal/
    app/
    auth/
    users/
    applications/
    certificates/
    issuers/
    acme/
    dnsproviders/
    audit/
    syncapi/
    storage/
    migrations/
    config/
    commands/
    crypto/
    httpapi/
    workers/

  pkg/
    certhubclient/
    certcriteria/
    material/
    errors/

  web/
    package.json
    package-lock.json
    src/
    public/

  deploy/
    docker/
      server.Dockerfile
      cli.Dockerfile
      operator.Dockerfile
    helm/
      certhub-server/
      certhub-operator/
    systemd/
      certhub-sync.service

  config/
    examples/
      server.yaml
      cli.yaml
      operator.env

  migrations/
    postgres/

  scripts/
    lint.sh
    test.sh

  test/
    integration/
    e2e/
```

## Top-Level Rules

- `cmd/` contains only binary entrypoints and wiring.
- `internal/` contains implementation packages not intended for external import.
- `pkg/` contains stable reusable Go packages shared by CLI/operator and optionally external users.
- `web/` contains all frontend TypeScript source and frontend package manager files.
- `api/` contains OpenAPI and request/response examples.
- `deploy/` contains runtime packaging, Helm charts, Dockerfiles, and systemd units.
- `config/examples/` contains example configuration only, not production secrets.
- `migrations/postgres/` contains database migrations shipped with the server.
- `internal/migrations/` contains Go migration runner, embedding, and migration orchestration code only. SQL migration files live under `migrations/postgres/`.
- `test/` contains integration and end-to-end tests that cross package or component boundaries.

## Go Components

Certhub uses one Go module at repository root.

Go binaries:

- `cmd/certhub-server`: backend API server, workers, and direct database management commands such as `migrate` and `bootstrap ...`.
- `cmd/certhub-cli`: CLI sync tool.
- `cmd/certhub-operator`: Kubernetes operator.

Go binary artifact rules:

- Release binaries must not rely on dynamically loaded libraries at runtime. Prefer pure Go builds with `CGO_ENABLED=0`; any dependency that requires cgo must be explicitly reviewed and must still produce a self-contained release artifact.
- Release compilation must minimize binary size where practical, including `-trimpath` and linker flags such as `-s -w`.
- Release binaries must not embed unused development assets, test fixtures, debug-only data, or local build paths.

Shared Go rules:

- Server-only logic stays under `internal/`.
- `internal/httpapi/`, `internal/commands/`, and `internal/workers/` are adapter/view layers. They translate HTTP requests, server-binary commands, and background jobs into service calls.
- Business logic that must be shared by HTTP handlers, direct database commands, and workers belongs in service packages under `internal/`, such as `internal/users/`, `internal/applications/`, `internal/certificates/`, `internal/issuers/`, `internal/dnsproviders/`, `internal/audit/`, and `internal/syncapi/`.
- Model, repository, migration, locking, and storage code belongs below the service layer, primarily under `internal/storage/`, `internal/migrations/`, and domain package repository files.
- Direct database management commands must not duplicate HTTP handler business rules or write database tables directly except through shared migration/repository primitives used by services.
- CLI/operator reusable HTTP client code belongs in `pkg/certhubclient`.
- Certificate criteria normalization shared across clients belongs in `pkg/certcriteria`.
- TLS material response types and local file helpers that are reusable by CLI, operator, and server self-certificate sync belong in `pkg/material`.
- Public error envelope types belong in `pkg/errors`.

## Frontend

The web application lives under `web/`.

Rules:

- Frontend code consumes the backend API through generated or hand-written TypeScript API clients.
- Frontend package manager files stay inside `web/`.
- Frontend build output must not be committed.
- Frontend assets must live under `web/` and be copied or bundled into the normal frontend build output.
- Deployed frontend HTML, JavaScript, CSS, fonts, icons, images, favicons, source maps, and other UI assets must be served by the same web server. Do not depend on CDN-hosted or third-party hosted UI assets.
- V1 release builds embed the production frontend build output into `cmd/certhub-server` using Go `embed`.
- The build pipeline copies built frontend assets from `web/` into a generated artifact outside source-controlled directories before embedding.
- Production frontend source maps must be disabled by default. Debug/internal builds may include source maps only when explicitly requested.

## API Contracts

`api/openapi.yaml` is the machine-readable HTTP API contract.

Rules:

- Public endpoint changes must update `api/openapi.yaml`.
- `api/openapi.yaml` is required before implementation starts and is the source of truth for concrete HTTP request/response schemas.
- Every public endpoint must have explicit request schemas, response schemas, error schemas, pagination/filter parameters, and examples where the endpoint accepts or returns JSON.
- Request/response examples in `api/examples/` should cover sync material retrieval, Application certificate creation, User login, and common error envelopes.
- CLI, operator, and frontend behavior should be checked against the API contract during CI.

## Specs

Markdown specs live under `specs/`.

Current spec files:

- `backend-spec.md`
- `frontend-spec.md`
- `cli-spec.md`
- `k8s-operator-spec.md`
- `dependencies-spec.md`
- `repo-structure-spec.md`
- `spec.md`

## Deployment

Deployment assets live under `deploy/`.

Rules:

- Dockerfiles must build from repository source and must not contain environment-specific secrets.
- `deploy/docker/cli.Dockerfile` builds the CLI image used for one-shot sync or built-in scheduler mode in Docker Compose and other container runtimes.
- Helm charts must support installing server and operator independently.
- systemd units are examples for host-based server and long-running CLI sync deployments.
- Server deployment manifests should mount or generate the YAML server config file and pass it to `certhub-server run --config <path>`.
- Deployment manifests should reference configuration through files, Kubernetes Secrets, Helm values, or component-specific environment variables where still allowed, not hard-coded credentials.

## Tests

Test placement:

- Unit tests live next to the Go package or frontend module they test.
- Backend integration tests live under `test/integration`.
- End-to-end product tests live under `test/e2e`.
- Frontend UI tests live under `web/` unless they require a full backend, in which case they belong under `test/e2e`.

Required repository-level checks:

- Go unit tests.
- Go integration tests where Postgres is available.
- Go vulnerability check for all Go modules and tools used by release builds.
- Go static analysis for security-relevant issues where practical, including unchecked errors around file writes, archive creation, crypto use, and HTTP handlers.
- Frontend typecheck, lint, and tests.
- Frontend dependency audit and production bundle checks for external asset URLs, source maps, unsafe eval, and unsafe HTML rendering patterns.
- OpenAPI validation.
- Generated client drift check if code generation is used.
- Secret scanning for the repository, generated examples, embedded assets, and test fixtures.
- Release binary checks verify no dynamic library dependency, no embedded frontend source maps by default, no development or test assets, no local build paths, no embedded secrets, and expected size-reduction flags.
- Release archive/package checks verify only intended binaries, migrations, deployment assets, licenses, and documentation are included.
- Release archive/package checks fail if artifacts include `.git`, `.env`, `node_modules`, package-manager caches, coverage output, temporary build directories, test fixtures, or local configuration files.
- Release checks publish checksums, an SBOM, and build provenance metadata for each binary, archive, container, or package artifact.
- Embedded server release checks verify the production web asset set is generated outside source-controlled directories and cannot include `web/src`, package-manager caches, or frontend test fixtures.
- Embedded server release checks reject symlinks in generated web assets and prove embedded asset paths cannot escape the generated asset root.
- Container/image or package scans, when release artifacts are produced.
- Container/image checks verify build secrets, package-manager credentials, shell history, and layer caches are absent from final images.
- Deployment artifact checks verify Dockerfiles, Helm charts, and systemd examples contain no hard-coded credentials and grant only documented server, CLI, and operator filesystem and Kubernetes access.
- Markdown/spec lint where practical.

## Migration Plan

1. Keep spec files under `specs/`.
2. Keep root `README.md`, `go.mod`, and `Makefile`.
3. Add or refine binary entrypoints under `cmd/`.
4. Add backend package skeleton under `internal/`.
5. Add `web/` frontend scaffold.
6. Create `api/openapi.yaml` before implementation work starts and keep it synchronized with the specs.
