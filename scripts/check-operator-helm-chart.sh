#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
chart="${1:-$repo_root/deploy/helm/certhub-operator}"
helm_bin="${HELM_BIN:-helm}"
kubeconform_bin="${KUBECONFORM_BIN:-kubeconform}"
valid_values="$chart/ci/values.yaml"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

if ! command -v "$helm_bin" >/dev/null 2>&1; then
  echo "helm is required for operator chart checks" >&2
  exit 1
fi

expect_template_failure() {
  local name="$1"
  shift
  if "$helm_bin" template test-operator "$chart" \
    --namespace certhub \
    --values "$valid_values" \
    "$@" >"$tmp_dir/$name.stdout" 2>"$tmp_dir/$name.stderr"; then
    echo "operator chart unexpectedly accepted invalid case: $name" >&2
    exit 1
  fi
}

if "$helm_bin" template test-operator "$chart" \
  --namespace certhub >"$tmp_dir/missing-required-values.stdout" 2>"$tmp_dir/missing-required-values.stderr"; then
  echo "operator chart unexpectedly accepted missing required values" >&2
  exit 1
fi

"$helm_bin" lint --strict "$chart" --values "$valid_values" >/dev/null

default_rendered="$tmp_dir/default.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub \
  --values "$valid_values" \
  --include-crds >"$default_rendered"

for expected in \
  'replicas: 1' \
  'type: Recreate' \
  'terminationGracePeriodSeconds: 30' \
  'image: "ghcr.io/torob/certhub-operator:0.1.0"' \
  'value: "certhub"' \
  'app.kubernetes.io/managed-by: Helm'; do
  if ! grep -F "$expected" "$default_rendered" >/dev/null; then
    echo "default operator render missing: $expected" >&2
    exit 1
  fi
done

expect_template_failure multiple-replicas --set replicaCount=2
expect_template_failure zero-replicas --set replicaCount=0
expect_template_failure insecure-url --set certhub.url=http://certhub.example.test
expect_template_failure malformed-duration --set certhub.resyncInterval=soon
expect_template_failure invalid-port --set metrics.service.port=70000
expect_template_failure duplicate-secret-name \
  --set 'managedSecretNames[0]=gateway-tls' \
  --set 'managedSecretNames[1]=gateway-tls'
expect_template_failure contradictory-scope \
  --set clusterScoped=true \
  --set watchNamespace=apps
expect_template_failure unknown-value --set unexpectedValue=true
expect_template_failure monitor-without-service \
  --set metrics.service.enabled=false \
  --set metrics.serviceMonitor.enabled=true
expect_template_failure tag-and-digest \
  --set image.tag=test \
  --set image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

namespaced_rendered="$tmp_dir/namespaced.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub-system \
  --values "$valid_values" \
  --set watchNamespace=apps >"$namespaced_rendered"
for expected in 'namespace: apps' 'value: "apps"' 'kind: Role'; do
  if ! grep -F "$expected" "$namespaced_rendered" >/dev/null; then
    echo "custom-namespace render missing: $expected" >&2
    exit 1
  fi
done
if grep -F 'kind: ClusterRole' "$namespaced_rendered" >/dev/null; then
  echo "custom-namespace render unexpectedly contains cluster RBAC" >&2
  exit 1
fi

namespaced_a="$tmp_dir/namespaced-a.yaml"
namespaced_b="$tmp_dir/namespaced-b.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace operator-a \
  --values "$valid_values" \
  --set watchNamespace=apps >"$namespaced_a"
"$helm_bin" template test-operator "$chart" \
  --namespace operator-b \
  --values "$valid_values" \
  --set watchNamespace=apps >"$namespaced_b"
role_name_a="$(awk '/^kind: Role$/ { found=1; next } found && /^  name:/ { print $2; exit }' "$namespaced_a")"
role_name_b="$(awk '/^kind: Role$/ { found=1; next } found && /^  name:/ { print $2; exit }' "$namespaced_b")"
if [ -z "$role_name_a" ] || [ -z "$role_name_b" ] || [ "$role_name_a" = "$role_name_b" ]; then
  echo "cross-namespace RBAC names are not release-namespace-unique" >&2
  exit 1
fi

cluster_a="$tmp_dir/cluster-a.yaml"
cluster_b="$tmp_dir/cluster-b.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub-a \
  --values "$valid_values" \
  --set clusterScoped=true >"$cluster_a"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub-b \
  --values "$valid_values" \
  --set clusterScoped=true >"$cluster_b"
for expected in 'kind: ClusterRole' 'value: ""' 'value: "certhub-a"'; do
  if ! grep -F "$expected" "$cluster_a" >/dev/null; then
    echo "cluster render missing: $expected" >&2
    exit 1
  fi
done
cluster_name_a="$(awk '/^kind: ClusterRole$/ { found=1; next } found && /^  name:/ { print $2; exit }' "$cluster_a")"
cluster_name_b="$(awk '/^kind: ClusterRole$/ { found=1; next } found && /^  name:/ { print $2; exit }' "$cluster_b")"
if [ -z "$cluster_name_a" ] || [ -z "$cluster_name_b" ] || [ "$cluster_name_a" = "$cluster_name_b" ]; then
  echo "cluster-scoped resource names are not namespace-unique" >&2
  exit 1
fi

no_create_rendered="$tmp_dir/no-create.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub \
  --values "$valid_values" \
  --set rbac.createTargetSecrets=false >"$no_create_rendered"
if grep -A2 'resources: \["secrets"\]' "$no_create_rendered" | grep -F 'verbs: ["create"]' >/dev/null; then
  echo "target Secret create permission rendered while disabled" >&2
  exit 1
fi

no_rbac_rendered="$tmp_dir/no-rbac.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub \
  --values "$valid_values" \
  --set rbac.create=false >"$no_rbac_rendered"
if grep -E '^kind: (Role|RoleBinding|ClusterRole|ClusterRoleBinding)$' "$no_rbac_rendered" >/dev/null; then
  echo "RBAC resources rendered while rbac.create=false" >&2
  exit 1
fi

digest_rendered="$tmp_dir/digest.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub \
  --values "$valid_values" \
  --set image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >"$digest_rendered"
if ! grep -F 'image: "ghcr.io/torob/certhub-operator@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$digest_rendered" >/dev/null; then
  echo "operator digest image did not render as expected" >&2
  exit 1
fi

monitor_rendered="$tmp_dir/monitor.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub \
  --values "$valid_values" \
  --set metrics.serviceMonitor.enabled=true >"$monitor_rendered"
for expected in 'kind: ServiceMonitor' 'port: metrics' 'path: /metrics'; do
  if ! grep -F "$expected" "$monitor_rendered" >/dev/null; then
    echo "ServiceMonitor render missing: $expected" >&2
    exit 1
  fi
done

long_release=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
long_rendered="$tmp_dir/long-name.yaml"
"$helm_bin" template "$long_release" "$chart" \
  --namespace certhub \
  --values "$valid_values" >"$long_rendered"
while IFS= read -r name; do
  if [ "${#name}" -gt 63 ]; then
    echo "operator chart rendered a resource name longer than 63 characters: $name" >&2
    exit 1
  fi
done < <(awk '/^  name:/ { print $2 }' "$long_rendered")
token_role_count="$(awk '
  /^kind: Role$/ { role=1; next }
  /^kind:/ { role=0 }
  role && /^  name:/ { names[$2]++ }
  END { for (name in names) if (names[name] > 1) duplicates++ ; print duplicates+0 }
' "$long_rendered")"
if [ "$token_role_count" != "0" ]; then
  echo "long release name produced duplicate Role names" >&2
  exit 1
fi

package_dir="$tmp_dir/package"
mkdir -p "$package_dir"
"$helm_bin" package "$chart" \
  --version 9.8.7 \
  --app-version 9.8.7 \
  --destination "$package_dir" >/dev/null
packaged_chart="$package_dir/certhub-operator-9.8.7.tgz"
packaged_rendered="$tmp_dir/packaged.yaml"
"$helm_bin" template test-operator "$packaged_chart" \
  --namespace certhub \
  --values "$valid_values" >"$packaged_rendered"
if ! grep -F 'image: "ghcr.io/torob/certhub-operator:9.8.7"' "$packaged_rendered" >/dev/null; then
  echo "packaged operator chart does not default to its appVersion image" >&2
  exit 1
fi

if command -v "$kubeconform_bin" >/dev/null 2>&1; then
  "$kubeconform_bin" -strict -summary -ignore-missing-schemas "$default_rendered" >/dev/null
fi

echo "Operator Helm chart checks passed."
