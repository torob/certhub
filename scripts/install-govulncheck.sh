#!/usr/bin/env bash
set -euo pipefail

GOVULNCHECK_VERSION="${GOVULNCHECK_VERSION:-1.5.0}"
GOVULNCHECK_MODULE_VERSION="${GOVULNCHECK_MODULE_VERSION:-v$GOVULNCHECK_VERSION}"
CODEX_TOOLS="${CODEX_TOOLS:-$HOME/.tools}"
GO_VERSION="${GO_VERSION:-1.26.5}"
INSTALL_DIR="$CODEX_TOOLS/govulncheck/$GOVULNCHECK_VERSION"
GOVULNCHECK_BIN="$INSTALL_DIR/bin/govulncheck"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

export CODEX_TOOLS
export PATH="$CODEX_TOOLS/go/$GO_VERSION/bin:$CODEX_TOOLS/bin:$PATH"
export GOCACHE="${GOCACHE:-$HOME/.cache/go-build}"
export GOPATH="${GOPATH:-$HOME/go}"
export GOMODCACHE="${GOMODCACHE:-$HOME/go/pkg/mod}"
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"

go_bin=""
if [ -x "$CODEX_TOOLS/go/$GO_VERSION/bin/go" ]; then
  go_bin="$CODEX_TOOLS/go/$GO_VERSION/bin/go"
else
  go_bin="${GO_BIN:-${GO:-go}}"
  go_bin="$(command -v "$go_bin" || true)"
fi

if [ -z "$go_bin" ] || [ ! -x "$go_bin" ]; then
  echo "Go $GO_VERSION or another usable go binary is required to install govulncheck" >&2
  exit 1
fi

mkdir -p "$GOCACHE" "$GOMODCACHE" "$GOPATH" "$INSTALL_DIR/bin"

cd "$REPO_ROOT"

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
    echo "go.mod or go.sum changed while installing/verifying govulncheck" >&2
    git diff -- go.mod go.sum >&2 || true
    exit 1
  fi
}

verify_govulncheck() {
  local bin="$1"
  [ -x "$bin" ] || return 1
  "$bin" -version 2>/dev/null | grep -qx "Scanner: govulncheck@$GOVULNCHECK_MODULE_VERSION"
}

before_mod="$(snapshot_file go.mod)"
before_sum="$(snapshot_file go.sum)"

if ! verify_govulncheck "$GOVULNCHECK_BIN"; then
  echo "Using go: $go_bin" >&2
  echo "go version: $("$go_bin" version)" >&2
  echo "Installing govulncheck@$GOVULNCHECK_MODULE_VERSION into $INSTALL_DIR" >&2
  GOBIN="$INSTALL_DIR/bin" "$go_bin" install "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_MODULE_VERSION" >&2
fi

if ! verify_govulncheck "$GOVULNCHECK_BIN"; then
  echo "expected govulncheck@$GOVULNCHECK_MODULE_VERSION at $GOVULNCHECK_BIN" >&2
  "$GOVULNCHECK_BIN" -version >&2 || true
  exit 1
fi

assert_go_files_unchanged "$before_mod" "$before_sum"
printf '%s\n' "$GOVULNCHECK_BIN"
