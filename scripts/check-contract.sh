#!/usr/bin/env bash
set -euo pipefail

mode="${1:-all}"
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

export CODEX_TOOLS="${CODEX_TOOLS:-$HOME/.tools}"
export PATH="$CODEX_TOOLS/bin:$PATH"

redocly_bin="${REDOCLY_BIN:-}"
if [ -z "$redocly_bin" ]; then
  redocly_bin="$("$repo_root/scripts/install-redocly.sh")"
fi

if ! command -v node >/dev/null 2>&1; then
  echo "node is required for contract baseline checks" >&2
  exit 1
fi

cd "$repo_root"

run_openapi_lint() {
  echo "Redocly: $("$redocly_bin" --version)"
  "$redocly_bin" lint api/openapi.yaml --format stylish
}

run_baseline() {
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN
  "$redocly_bin" bundle api/openapi.yaml --output "$tmpdir/openapi.json" --ext json
  node scripts/check-openapi-contract.mjs "$tmpdir/openapi.json" api/examples
}

case "$mode" in
  openapi)
    run_openapi_lint
    ;;
  baseline)
    run_baseline
    ;;
  all)
    run_openapi_lint
    run_baseline
    ;;
  *)
    echo "usage: $0 [all|openapi|baseline]" >&2
    exit 2
    ;;
esac
