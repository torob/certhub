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
mkdir -p "$GOCACHE" "$GOMODCACHE"

cd "$repo_root"

snapshot_file() {
  local file="$1"
  if [ -f "$file" ]; then
    sha256sum "$file"
  else
    printf 'missing  %s\n' "$file"
  fi
}

before_mod="$(snapshot_file go.mod)"
before_sum="$(snapshot_file go.sum)"

"$go_bin" mod verify
GOFLAGS=-mod=readonly "$go_bin" list -m all >/dev/null
GOFLAGS=-mod=readonly "$go_bin" list ./... >/dev/null

after_mod="$(snapshot_file go.mod)"
after_sum="$(snapshot_file go.sum)"

if [ "$before_mod" != "$after_mod" ] || [ "$before_sum" != "$after_sum" ]; then
  echo "Go module lock/checksum files changed during readonly verification" >&2
  git diff -- go.mod go.sum >&2 || true
  exit 1
fi

if [ ! -f go.sum ]; then
  module_count="$("$go_bin" list -m all | wc -l | tr -d ' ')"
  if [ "$module_count" = "1" ]; then
    echo "Go module lockfile check passed: go.sum absent because there are no third-party modules."
    exit 0
  fi
  echo "go.sum is missing but third-party modules are present" >&2
  exit 1
fi

echo "Go module lockfile check passed."
