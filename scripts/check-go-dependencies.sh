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

if [ -n "$("$go_bin" env GOWORK)" ]; then
  echo "Go workspace mode is not allowed for Certhub dependency checks" >&2
  exit 1
fi

if "$go_bin" env CGO_ENABLED | grep -qx '1'; then
  echo "dependency checks must run with CGO_ENABLED=0" >&2
  exit 1
fi

tmp_packages="$(mktemp)"
tmp_modules="$(mktemp)"
tmp_gomod="$(mktemp)"
trap 'rm -f "$tmp_packages" "$tmp_modules" "$tmp_gomod"' EXIT

mapfile -t packages < <(GOFLAGS=-mod=readonly "$go_bin" list ./... | awk '$0 !~ /\/dist(\/|$)/ && $0 !~ /\/certhub-full-e2e-artifacts(\/|$)/')
GOFLAGS=-mod=readonly "$go_bin" list -deps -json "${packages[@]}" >"$tmp_packages"
GOFLAGS=-mod=readonly "$go_bin" list -m -u -json all >"$tmp_modules"
"$go_bin" mod edit -json >"$tmp_gomod"

node scripts/check-go-modules.mjs \
  --go-mod "$tmp_gomod" \
  --module-graph "$tmp_modules" \
  --package-graph "$tmp_packages"
node scripts/check-go-packages.mjs "$tmp_packages"
