#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

export CODEX_TOOLS="${CODEX_TOOLS:-$HOME/.tools}"
export PATH="$CODEX_TOOLS/bin:$PATH"
export GOCACHE="${GOCACHE:-$HOME/.cache/go-build}"
export GOPATH="${GOPATH:-$HOME/go}"
export GOMODCACHE="${GOMODCACHE:-$HOME/go/pkg/mod}"
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"

go_bin="${GO_BIN:-${GO:-go}}"
if resolved_go_bin="$(command -v "$go_bin" 2>/dev/null)"; then
  go_bin="$resolved_go_bin"
fi
if [ -x "$go_bin" ]; then
  go_bin_dir="$(cd -- "$(dirname -- "$go_bin")" && pwd)"
  export PATH="$go_bin_dir:$PATH"
fi
cd "$repo_root"

snapshot_file() {
  local file="$1"
  if [ -f "$file" ]; then
    sha256sum "$file"
  else
    printf 'missing  %s\n' "$file"
  fi
}

assert_go_files_unchanged() {
  local before_mod="$1"
  local before_sum="$2"
  local after_mod
  local after_sum
  after_mod="$(snapshot_file go.mod)"
  after_sum="$(snapshot_file go.sum)"

  if [ "$before_mod" != "$after_mod" ] || [ "$before_sum" != "$after_sum" ]; then
    echo "go.mod or go.sum changed during Go vulnerability verification" >&2
    git diff -- go.mod go.sum >&2 || true
    exit 1
  fi
}

mkdir -p "$GOCACHE" "$GOMODCACHE"

before_mod="$(snapshot_file go.mod)"
before_sum="$(snapshot_file go.sum)"

GOFLAGS=-mod=readonly "$go_bin" list -m all >/dev/null
govulncheck_bin="$(GO_BIN="$go_bin" ./scripts/install-govulncheck.sh)"

assert_go_files_unchanged "$before_mod" "$before_sum"

mapfile -t packages < <(GOFLAGS=-mod=readonly "$go_bin" list ./... | awk '$0 !~ /\/dist(\/|$)/ && $0 !~ /\/certhub-full-e2e-artifacts(\/|$)/')
GOFLAGS=-mod=readonly "$govulncheck_bin" "${packages[@]}"

assert_go_files_unchanged "$before_mod" "$before_sum"
echo "Go vulnerability check passed with $("$govulncheck_bin" -version | awk '/^Scanner:/ { print $2 }')."
