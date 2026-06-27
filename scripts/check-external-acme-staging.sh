#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export CODEX_TOOLS="${CODEX_TOOLS:-$HOME/.tools}"
export PATH="$CODEX_TOOLS/go/1.26.4/bin:$CODEX_TOOLS/bin:$PATH"
export GOCACHE="${GOCACHE:-$HOME/.cache/go-build}"
export GOPATH="${GOPATH:-$HOME/go}"
export GOMODCACHE="${GOMODCACHE:-$HOME/go/pkg/mod}"
export GOPROXY="https://proxy.golang.org,direct"

go_bin="${GO_BIN:-$CODEX_TOOLS/go/1.26.4/bin/go}"
if [ ! -x "$go_bin" ]; then
  go_bin="go"
fi

export CERTHUB_EXTERNAL_ACME=1
export CERTHUB_EXTERNAL_DNS_CREDENTIALS_FILE="${CERTHUB_EXTERNAL_DNS_CREDENTIALS_FILE:-/home/torob/certhub-test-secrets.txt}"
export CERTHUB_EXTERNAL_ACME_DIRECTORY_URL="https://acme-staging-v02.api.letsencrypt.org/directory"

"$go_bin" test ./test/integration -run '^TestExternalACMEStagingDNS01IssuanceAndRevocation$' -count=1 -v -timeout 12m
