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
cd "$repo_root"

packages_json="$(mktemp)"
trap 'rm -f "$packages_json"' EXIT
mapfile -t packages < <(GOFLAGS=-mod=readonly "$go_bin" list ./cmd/... ./internal/... ./pkg/... ./migrations/... ./test/...)
GOFLAGS=-mod=readonly "$go_bin" list -deps -json "${packages[@]}" >"$packages_json"
third_party_modules="$(node - "$packages_json" <<'JS'
const fs = require("node:fs");
const path = process.argv[2];
const content = fs.readFileSync(path, "utf8").trim();
const modules = new Map();
for (const chunk of content ? content.split(/\n(?=\{)/) : []) {
  const pkg = JSON.parse(chunk);
  const mod = pkg.Module;
  if (mod && mod.Path && mod.Path !== "github.com/torob/certhub") modules.set(mod.Path, mod.Version || "");
}
for (const [path, version] of [...modules].sort()) console.log(`${path} ${version}`);
JS
)"
third_party_count="$(printf '%s\n' "$third_party_modules" | sed '/^$/d' | wc -l | tr -d ' ')"

if [ "$third_party_count" = "0" ]; then
  echo "Go license check passed: no third-party Go modules."
  exit 0
fi

failures=()
while read -r module version; do
  [ -n "$module" ] || continue
  module_dir="$(GOFLAGS=-mod=readonly "$go_bin" list -m -f '{{.Dir}}' "$module")"
  if [ -z "$module_dir" ]; then
    GOFLAGS=-mod=readonly "$go_bin" mod download "$module"
    module_dir="$(GOFLAGS=-mod=readonly "$go_bin" list -m -f '{{.Dir}}' "$module")"
  fi
  case "$module" in
    go.yaml.in/yaml/v4)
      if ! grep -Rqs "SPDX-License-Identifier: Apache-2.0\\|Apache License" "$module_dir/LICENSE" "$module_dir/LICENSE"* 2>/dev/null; then
        failures+=("$module $version: Apache-2.0 license evidence not found")
      fi
      ;;
    github.com/jackc/pgpassfile|github.com/jackc/pgservicefile|github.com/jackc/pgx/v5|github.com/jackc/puddle/v2|github.com/mfridman/interpolate|github.com/pressly/goose/v3|github.com/skip2/go-qrcode|go.uber.org/multierr)
      if ! grep -Rqs "MIT License\\|Permission is hereby granted" "$module_dir/LICENSE" "$module_dir/LICENSE"* 2>/dev/null; then
        failures+=("$module $version: MIT license evidence not found")
      fi
      ;;
    github.com/sethvargo/go-retry)
      if ! grep -Rqs "Apache License" "$module_dir/LICENSE" "$module_dir/LICENSE"* 2>/dev/null; then
        failures+=("$module $version: Apache-2.0 license evidence not found")
      fi
      ;;
    golang.org/x/crypto|golang.org/x/net|golang.org/x/sync|golang.org/x/sys|golang.org/x/term|golang.org/x/text)
      if ! grep -Rqs "Redistribution and use in source and binary forms" "$module_dir/LICENSE" "$module_dir/LICENSE"* 2>/dev/null; then
        failures+=("$module $version: BSD-style license evidence not found")
      fi
      ;;
    *)
      failures+=("$module $version: no reviewed license rule")
      ;;
  esac
done <<<"$third_party_modules"

if [ "${#failures[@]}" -gt 0 ]; then
  echo "Go license policy failed:" >&2
  for failure in "${failures[@]}"; do
    echo "- $failure" >&2
  done
  exit 1
fi

echo "Go license check passed: reviewed license evidence for ${third_party_count} third-party Go module(s)."
