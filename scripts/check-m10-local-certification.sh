#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cleanup() {
  if [ "${CERTHUB_KEEP_CERTIFICATION_ARTIFACTS:-}" != "1" ]; then
    rm -rf "$repo_root/dist" "$repo_root/web/dist" "$repo_root/web/node_modules"
  fi
}
trap cleanup EXIT

export CODEX_TOOLS="${CODEX_TOOLS:-$HOME/.tools}"
local_go="$CODEX_TOOLS/go/1.26.5/bin/go"
if [ ! -x "$local_go" ]; then
  local_go="go"
fi
export PATH="$CODEX_TOOLS/go/1.26.5/bin:$CODEX_TOOLS/node/24.15.0/bin:$CODEX_TOOLS/helm/3.16.2/linux-amd64:$CODEX_TOOLS/bin:$PATH"
export GOCACHE="${GOCACHE:-$HOME/.cache/go-build}"
export GOPATH="${GOPATH:-$HOME/go}"
export GOMODCACHE="${GOMODCACHE:-$HOME/go/pkg/mod}"
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"

make contract build release-artifacts

./scripts/check-postgres-integration.sh

"$local_go" test ./internal/httpapi ./test/e2e -count=1 -v

make release-scaffold-check

echo "M10 local certification passed."
