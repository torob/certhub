#!/usr/bin/env bash
set -euo pipefail

REDOCLY_VERSION="${REDOCLY_VERSION:-2.35.1}"
CODEX_TOOLS="${CODEX_TOOLS:-$HOME/.tools}"
NODE_VERSION="${NODE_VERSION:-24.15.0}"
INSTALL_DIR="$CODEX_TOOLS/redocly-cli/$REDOCLY_VERSION"
REDOCLY_BIN="$INSTALL_DIR/node_modules/.bin/redocly"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LOCKED_PACKAGE_JSON="$SCRIPT_DIR/redocly-package.json"
LOCKED_PACKAGE_LOCK="$SCRIPT_DIR/redocly-package-lock.json"

export CODEX_TOOLS
export PATH="$CODEX_TOOLS/bin:$PATH"

LOCAL_NODE_DIR="$CODEX_TOOLS/node/$NODE_VERSION/bin"
NODE_BIN=""
NPM_BIN=""

if [ -x "$LOCAL_NODE_DIR/node" ] && [ -x "$LOCAL_NODE_DIR/npm" ]; then
  NODE_BIN="$LOCAL_NODE_DIR/node"
  NPM_BIN="$LOCAL_NODE_DIR/npm"
elif [ -x "$CODEX_TOOLS/bin/node" ] && [ -x "$CODEX_TOOLS/bin/npm" ]; then
  NODE_BIN="$CODEX_TOOLS/bin/node"
  NPM_BIN="$CODEX_TOOLS/bin/npm"
else
  if [ -n "${NVM_DIR:-}" ] && [ -s "$NVM_DIR/nvm.sh" ]; then
    # Preserve the existing NVM fallback for hosts without a versioned local Node.
    # shellcheck disable=SC1090
    . "$NVM_DIR/nvm.sh"
    nvm use "v$NODE_VERSION" >/dev/null 2>&1 || nvm use "$NODE_VERSION" >/dev/null 2>&1 || true
  fi
  NODE_BIN="${NODE:-node}"
  NPM_BIN="${NPM:-npm}"
  NODE_BIN="$(command -v "$NODE_BIN" || true)"
  NPM_BIN="$(command -v "$NPM_BIN" || true)"
fi

if [ -n "$NODE_BIN" ]; then
  export PATH="$(dirname "$NODE_BIN"):$PATH"
fi
if [ -n "$NPM_BIN" ]; then
  export PATH="$(dirname "$NPM_BIN"):$PATH"
fi

installed_package_files_match() {
  [ -f "$INSTALL_DIR/package.json" ] &&
    [ -f "$INSTALL_DIR/package-lock.json" ] &&
    cmp -s "$LOCKED_PACKAGE_JSON" "$INSTALL_DIR/package.json" &&
    cmp -s "$LOCKED_PACKAGE_LOCK" "$INSTALL_DIR/package-lock.json"
}

if [ -x "$REDOCLY_BIN" ]; then
  actual="$("$REDOCLY_BIN" --version)"
  if [ "$actual" = "$REDOCLY_VERSION" ] && installed_package_files_match; then
    printf '%s\n' "$REDOCLY_BIN"
    exit 0
  fi
  if [ "$actual" = "$REDOCLY_VERSION" ]; then
    echo "Installed Redocly package files differ from committed locks; reinstalling." >&2
  fi
fi

if [ -z "$NODE_BIN" ] || [ ! -x "$NODE_BIN" ] || [ -z "$NPM_BIN" ] || [ ! -x "$NPM_BIN" ]; then
  echo "node and npm are required to install @redocly/cli@$REDOCLY_VERSION" >&2
  exit 1
fi

echo "Using node: $NODE_BIN" >&2
echo "node version: $("$NODE_BIN" --version)" >&2
echo "Using npm: $NPM_BIN" >&2
echo "npm version: $("$NPM_BIN" --version)" >&2
mkdir -p "$INSTALL_DIR"
cp "$LOCKED_PACKAGE_JSON" "$INSTALL_DIR/package.json"
cp "$LOCKED_PACKAGE_LOCK" "$INSTALL_DIR/package-lock.json"
"$NPM_BIN" ci \
  --prefix "$INSTALL_DIR" \
  --registry https://registry.npmjs.org \
  --ignore-scripts \
  --no-audit \
  --no-fund >&2

actual="$("$REDOCLY_BIN" --version)"
if [ "$actual" != "$REDOCLY_VERSION" ]; then
  echo "expected redocly $REDOCLY_VERSION, got $actual" >&2
  exit 1
fi

if ! installed_package_files_match; then
  echo "installed Redocly package files do not match committed lock files" >&2
  exit 1
fi

printf '%s\n' "$REDOCLY_BIN"
