#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export CODEX_TOOLS="${CODEX_TOOLS:-$HOME/.tools}"
export PATH="$CODEX_TOOLS/go/1.26.5/bin:$CODEX_TOOLS/bin:$PATH"
export GOCACHE="${GOCACHE:-$HOME/.cache/go-build}"
export GOPATH="${GOPATH:-$HOME/go}"
export GOMODCACHE="${GOMODCACHE:-$HOME/go/pkg/mod}"
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"

go_bin="${GO_BIN:-$CODEX_TOOLS/go/1.26.5/bin/go}"
if [ ! -x "$go_bin" ]; then
  go_bin="go"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for PostgreSQL integration certification" >&2
  exit 1
fi

image="${CERTHUB_POSTGRES_IMAGE:-postgres:16.3}"
container="certhub-postgres-integration-$$"
password="certhub"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d \
  --name "$container" \
  -e POSTGRES_USER=certhub \
  -e POSTGRES_PASSWORD="$password" \
  -e POSTGRES_DB=certhub \
  -p 127.0.0.1::5432 \
  "$image" >/dev/null

port="$(docker inspect -f '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' "$container")"

for _ in $(seq 1 60); do
  if docker exec "$container" pg_isready -U certhub -d certhub >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! docker exec "$container" pg_isready -U certhub -d certhub >/dev/null 2>&1; then
  echo "PostgreSQL did not become ready" >&2
  exit 1
fi

export CERTHUB_TEST_DATABASE_URL="postgres://certhub:${password}@127.0.0.1:${port}/certhub?sslmode=disable"

"$go_bin" test ./internal/migrations ./internal/storage ./internal/auth ./internal/commands \
  -run 'Test(PostgresMigrationsApplyIdempotently|Milestone3RepositoriesWithPostgres|Milestone4RepositoriesWithPostgres|Milestone5CertificateLifecycleRepositoryWithPostgres|OIDCLoginFlowWithPostgresServiceTransactions|MigrateWithPostgresIntegration|RunMigrationModeWithPostgresIntegration)$' \
  -count=1 -v

echo "PostgreSQL integration certification passed."
