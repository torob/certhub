#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export CODEX_TOOLS="${CODEX_TOOLS:-$HOME/.tools}"
local_go="$CODEX_TOOLS/go/1.26.5/bin/go"
if [ ! -x "$local_go" ]; then
  local_go="go"
fi
export PATH="$CODEX_TOOLS/go/1.26.5/bin:$CODEX_TOOLS/bin:$PATH"
export GOCACHE="${GOCACHE:-$HOME/.cache/go-build}"
export GOPATH="${GOPATH:-$HOME/go}"
export GOMODCACHE="${GOMODCACHE:-$HOME/go/pkg/mod}"
export GOPROXY="https://proxy.golang.org,direct"
export CERTHUB_EXTERNAL_OIDC=1
export CERTHUB_EXTERNAL_OIDC_CREDENTIALS_FILE="${CERTHUB_EXTERNAL_OIDC_CREDENTIALS_FILE:-/home/torob/certhub-test-secrets.txt}"

"$local_go" test ./test/integration -run TestExternalZITADELOIDCDiscoveryCompatibility -count=1 -v
