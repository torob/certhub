#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
argocd_bin="${ARGOCD_BIN:-argocd}"
config_map="$repo_root/deploy/helm/certhub-operator/argocd/argocd-cm-patch.yaml"
fixtures="$repo_root/test/argocd-health/fixtures"

if ! command -v "$argocd_bin" >/dev/null 2>&1; then
  echo "argocd is required for Argo CD health checks" >&2
  exit 1
fi

version="$($argocd_bin version --client --short)"
if [[ "$version" != argocd:\ v3.4.2+* ]]; then
  echo "Argo CD CLI v3.4.2 is required, got: $version" >&2
  exit 1
fi

check_health() {
  local fixture="$1"
  local expected_status="$2"
  local output

  output="$($argocd_bin admin settings resource-overrides health \
    "$fixtures/$fixture.yaml" \
    --argocd-cm-path "$config_map" \
    --loglevel error)"
  if ! grep -F "STATUS: $expected_status" <<<"$output" >/dev/null; then
    echo "$fixture: expected $expected_status" >&2
    echo "$output" >&2
    exit 1
  fi
}

check_health absent-status Progressing
check_health stale-generation Progressing
check_health pending Progressing
check_health validating-dns Progressing
check_health issuing Progressing
check_health failed Degraded
check_health incomplete-ready Progressing
check_health fully-ready Healthy

echo "Argo CD CerthubCertificate health checks passed with $version."
