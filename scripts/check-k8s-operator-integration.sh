#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [ "${CERTHUB_EXTERNAL_K8S:-}" != "1" ]; then
  echo "Skipping Kubernetes operator integration; set CERTHUB_EXTERNAL_K8S=1 to use the current kube context."
  exit 0
fi

export CODEX_TOOLS="${CODEX_TOOLS:-$HOME/.tools}"
export PATH="$CODEX_TOOLS/helm/3.16.2/linux-amd64:$CODEX_TOOLS/bin:$PATH"

kubectl_bin="${KUBECTL_BIN:-kubectl}"
helm_bin="${HELM_BIN:-helm}"

if ! command -v "$kubectl_bin" >/dev/null 2>&1; then
  echo "kubectl is required for Kubernetes operator integration" >&2
  exit 1
fi
if ! command -v "$helm_bin" >/dev/null 2>&1; then
  echo "helm is required for Kubernetes operator integration" >&2
  exit 1
fi

"$kubectl_bin" version --client=true >/dev/null
"$helm_bin" version --short >/dev/null
"$kubectl_bin" version --request-timeout=10s >/dev/null

namespace=""
second_namespace=""
rendered=""
created_crd=0

cleanup() {
  local status="$?"
  local cleanup_failed=0
  if [ -n "$rendered" ]; then
    rm -f "$rendered"
  fi
  if [ "${CERTHUB_KEEP_K8S_TEST_RESOURCES:-}" = "1" ]; then
    if [ -n "$namespace" ]; then
      echo "Keeping Kubernetes test resources in namespaces $namespace and $second_namespace."
    fi
    exit "$status"
  fi
  if [ -n "$namespace" ]; then
    if ! "$kubectl_bin" delete namespace "$namespace" --ignore-not-found=true --wait=false >/dev/null 2>&1; then
      echo "failed to delete Kubernetes test namespace $namespace" >&2
      cleanup_failed=1
    fi
  fi
  if [ -n "$second_namespace" ]; then
    if ! "$kubectl_bin" delete namespace "$second_namespace" --ignore-not-found=true --wait=false >/dev/null 2>&1; then
      echo "failed to delete Kubernetes test namespace $second_namespace" >&2
      cleanup_failed=1
    fi
  fi
  if [ "$created_crd" = "1" ]; then
    if ! "$kubectl_bin" delete crd "$crd_name" --ignore-not-found=true >/dev/null 2>&1; then
      echo "failed to delete Kubernetes test CRD $crd_name" >&2
      cleanup_failed=1
    fi
  fi
  if [ "$status" = "0" ] && [ "$cleanup_failed" != "0" ]; then
    exit 1
  fi
  exit "$status"
}
trap cleanup EXIT

require_can_i() {
  local verb="$1"
  shift
  local answer
  answer="$("$kubectl_bin" auth can-i "$verb" "$@" --request-timeout=10s || true)"
  if [ "$answer" != "yes" ]; then
    echo "current Kubernetes identity cannot $verb $*" >&2
    exit 1
  fi
}

require_can_i create namespaces
require_can_i delete namespaces

crd_name="certhubcertificates.certs.torob.dev"
if "$kubectl_bin" get crd "$crd_name" --request-timeout=10s >/dev/null 2>&1; then
  echo "Using existing CRD $crd_name."
else
  if [ "${CERTHUB_EXTERNAL_K8S_MANAGE_CRD:-}" != "1" ]; then
    echo "CRD $crd_name is not installed; set CERTHUB_EXTERNAL_K8S_MANAGE_CRD=1 only on a disposable cluster to let this script create and later delete it." >&2
    exit 1
  fi
  require_can_i create customresourcedefinitions.apiextensions.k8s.io
  require_can_i delete customresourcedefinitions.apiextensions.k8s.io
  "$kubectl_bin" apply -f deploy/helm/certhub-operator/crds/certs.torob.dev_certhubcertificates.yaml
  "$kubectl_bin" wait --for=condition=Established "crd/$crd_name" --timeout=60s
  created_crd=1
fi

suffix="$(date -u +%Y%m%d%H%M%S)-$$"
namespace="certhub-k8s-test-$suffix"
second_namespace="$namespace-second"
release="cth-k8s-test"

"$kubectl_bin" create namespace "$namespace" >/dev/null
"$kubectl_bin" create namespace "$second_namespace" >/dev/null
"$kubectl_bin" label namespace "$namespace" app.kubernetes.io/part-of=certhub-k8s-integration >/dev/null
"$kubectl_bin" label namespace "$second_namespace" app.kubernetes.io/part-of=certhub-k8s-integration >/dev/null
"$kubectl_bin" create secret generic certhub-token \
  --namespace "$namespace" \
  --from-literal=token='cth_app_v1_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ' >/dev/null

rendered="$(mktemp)"
"$helm_bin" template "$release" deploy/helm/certhub-operator \
  --namespace "$namespace" \
  --values deploy/helm/certhub-operator/ci/values.yaml \
  --set "watchNamespaces[0]=$namespace" \
  --set "watchNamespaces[1]=$second_namespace" \
  --show-only templates/serviceaccount.yaml \
  --show-only templates/rbac.yaml >"$rendered"
"$kubectl_bin" apply --namespace "$namespace" -f "$rendered" >/dev/null

"$kubectl_bin" apply --namespace "$namespace" -f - >/dev/null <<'YAML'
apiVersion: certs.torob.dev/v1alpha1
kind: CerthubCertificate
metadata:
  name: gateway
spec:
  domains:
    - gateway.example.com
  secretName: gateway-tls
  keyType: ecdsa-p256
  issuer: letsencrypt_staging
  secretDeletionPolicy: Retain
YAML

expect_invalid_cr() {
  local expected_pattern="$1"
  local err_file
  err_file="$(mktemp)"
  if "$kubectl_bin" apply --namespace "$namespace" --dry-run=server -f - >/dev/null 2>"$err_file"; then
    rm -f "$err_file"
    echo "Kubernetes API accepted an invalid CerthubCertificate" >&2
    exit 1
  fi
  if ! grep -E "$expected_pattern" "$err_file" >/dev/null; then
    echo "invalid CerthubCertificate failed for an unexpected reason" >&2
    sed 's/cth_app_v1_[A-Za-z0-9_-]*/[REDACTED_TOKEN]/g' "$err_file" >&2
    rm -f "$err_file"
    exit 1
  fi
  rm -f "$err_file"
}

expect_invalid_cr 'spec\.domains|domains' <<'YAML'
apiVersion: certs.torob.dev/v1alpha1
kind: CerthubCertificate
metadata:
  name: invalid-domain
spec:
  domains:
    - " bad_domain"
  secretName: gateway-tls
YAML

expect_invalid_cr 'spec\.secretName|secretName' <<'YAML'
apiVersion: certs.torob.dev/v1alpha1
kind: CerthubCertificate
metadata:
  name: invalid-secret-name
spec:
  domains:
    - gateway.example.com
  secretName: "../gateway-tls"
YAML

service_account="system:serviceaccount:$namespace:$release-certhub-operator"

expect_can_i_as_operator() {
  local expected="$1"
  shift
  local answer
  answer="$("$kubectl_bin" auth can-i "$@" --as="$service_account" --request-timeout=10s || true)"
  if [ "$answer" != "$expected" ]; then
    echo "operator ServiceAccount RBAC mismatch: expected $expected for: $*" >&2
    echo "actual: $answer" >&2
    exit 1
  fi
}

expect_can_i_as_operator yes get certhubcertificates.certs.torob.dev --namespace "$namespace"
expect_can_i_as_operator yes list certhubcertificates.certs.torob.dev --namespace "$namespace"
expect_can_i_as_operator yes watch certhubcertificates.certs.torob.dev --namespace "$namespace"
expect_can_i_as_operator no update certhubcertificates.certs.torob.dev --namespace "$namespace"
expect_can_i_as_operator yes update certhubcertificates.certs.torob.dev --subresource=status --namespace "$namespace"
expect_can_i_as_operator yes patch certhubcertificates.certs.torob.dev --subresource=finalizers --namespace "$namespace"

expect_can_i_as_operator yes get secrets/certhub-token --namespace "$namespace"
expect_can_i_as_operator yes get secrets/unrelated-secret --namespace "$namespace"
expect_can_i_as_operator yes create secrets --namespace "$namespace"
expect_can_i_as_operator no list secrets --namespace "$namespace"
expect_can_i_as_operator yes update secrets/gateway-tls --namespace "$namespace"
expect_can_i_as_operator yes patch secrets/gateway-tls --namespace "$namespace"
expect_can_i_as_operator yes delete secrets/gateway-tls --namespace "$namespace"
expect_can_i_as_operator yes update secrets/unrelated-secret --namespace "$namespace"
expect_can_i_as_operator yes delete secrets/unrelated-secret --namespace "$namespace"

expect_can_i_as_operator yes get certhubcertificates.certs.torob.dev --namespace "$second_namespace"
expect_can_i_as_operator yes list certhubcertificates.certs.torob.dev --namespace "$second_namespace"
expect_can_i_as_operator yes watch certhubcertificates.certs.torob.dev --namespace "$second_namespace"
expect_can_i_as_operator no update certhubcertificates.certs.torob.dev --namespace "$second_namespace"
expect_can_i_as_operator yes update certhubcertificates.certs.torob.dev --subresource=status --namespace "$second_namespace"
expect_can_i_as_operator yes patch certhubcertificates.certs.torob.dev --subresource=finalizers --namespace "$second_namespace"
expect_can_i_as_operator yes get secrets/arbitrary-tls --namespace "$second_namespace"
expect_can_i_as_operator yes create secrets --namespace "$second_namespace"
expect_can_i_as_operator yes update secrets/arbitrary-tls --namespace "$second_namespace"
expect_can_i_as_operator yes patch secrets/arbitrary-tls --namespace "$second_namespace"
expect_can_i_as_operator yes delete secrets/arbitrary-tls --namespace "$second_namespace"
expect_can_i_as_operator no list secrets --namespace "$second_namespace"

expect_can_i_as_operator no get secrets/certhub-token --namespace default
expect_can_i_as_operator no create secrets --namespace default
expect_can_i_as_operator no update secrets/gateway-tls --namespace default
expect_can_i_as_operator no list secrets --all-namespaces

echo "Kubernetes operator CRD admission and multi-namespace RBAC validation passed for $namespace and $second_namespace."
