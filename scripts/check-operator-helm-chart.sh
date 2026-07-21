#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
chart="${1:-$repo_root/deploy/helm/certhub-operator}"
helm_bin="${HELM_BIN:-helm}"
kubeconform_bin="${KUBECONFORM_BIN:-kubeconform}"
kubectl_bin="${KUBECTL_BIN:-kubectl}"
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

expect_contains() {
  local file="$1"
  local expected="$2"
  if ! grep -F -- "$expected" "$file" >/dev/null; then
    echo "$(basename "$file") missing expected content: $expected" >&2
    exit 1
  fi
}

expect_not_contains() {
  local file="$1"
  local unexpected="$2"
  if grep -F -- "$unexpected" "$file" >/dev/null; then
    echo "$(basename "$file") unexpectedly contains: $unexpected" >&2
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
  'name: CERTHUB_TOKEN' \
  'secretKeyRef:' \
  'name: "certhub-token"' \
  'key: "token"' \
  'name: WATCH_NAMESPACES' \
  'value: "certhub"' \
  'verbs: ["get", "list", "watch", "patch"]' \
  'verbs: ["create", "get", "update", "patch", "delete"]' \
  'app.kubernetes.io/managed-by: Helm'; do
  if ! grep -F "$expected" "$default_rendered" >/dev/null; then
    echo "default operator render missing: $expected" >&2
    exit 1
  fi
done
expect_not_contains "$default_rendered" 'kind: NetworkPolicy'
expect_not_contains "$default_rendered" 'kind: CiliumNetworkPolicy'
expect_not_contains "$default_rendered" 'CERTHUB_ALLOWED_SECRET_NAMES'
expect_not_contains "$default_rendered" 'CERTHUB_TOKEN_SECRET_'
expect_not_contains "$default_rendered" 'resourceNames:'
expect_not_contains "$default_rendered" 'certhubcertificates/finalizers'
if grep -E 'name: WATCH_NAMESPACE$' "$default_rendered" >/dev/null; then
  echo "default operator render contains removed WATCH_NAMESPACE environment variable" >&2
  exit 1
fi

custom_token_ref="$tmp_dir/custom-token-ref.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub \
  --values "$valid_values" \
  --set certhub.tokenSecretName=operator-auth \
  --set certhub.tokenSecretKey=application-token \
  --show-only templates/deployment.yaml >"$custom_token_ref"
for expected in \
  'name: CERTHUB_TOKEN' \
  'secretKeyRef:' \
  'name: "operator-auth"' \
  'key: "application-token"'; do
  expect_contains "$custom_token_ref" "$expected"
done
expect_not_contains "$custom_token_ref" 'CERTHUB_TOKEN_SECRET_'

expect_template_failure multiple-replicas --set replicaCount=2
expect_template_failure zero-replicas --set replicaCount=0
expect_template_failure insecure-url --set certhub.url=http://certhub.example.test
expect_template_failure malformed-duration --set certhub.resyncInterval=soon

short_resync="$tmp_dir/short-resync.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub \
  --values "$valid_values" \
  --set certhub.resyncInterval=30s \
  --show-only templates/deployment.yaml >"$short_resync"
expect_contains "$short_resync" 'name: CERTHUB_RESYNC_INTERVAL'
expect_contains "$short_resync" 'value: "30s"'
expect_template_failure invalid-port --set metrics.service.port=70000
expect_template_failure removed-managed-secret-names \
  --set 'managedSecretNames[0]=gateway-tls'
expect_template_failure removed-watch-namespace \
  --set watchNamespace=apps
expect_template_failure removed-token-secret-namespace \
  --set certhub.tokenSecretNamespace=apps
expect_template_failure removed-create-target-secrets \
  --set rbac.createTargetSecrets=false
expect_template_failure scalar-watch-namespaces \
  --set watchNamespaces=apps
expect_template_failure duplicate-watch-namespace \
  --set 'watchNamespaces[0]=apps' \
  --set 'watchNamespaces[1]=apps'
expect_template_failure invalid-watch-namespace \
  --set 'watchNamespaces[0]=UPPER'
expect_template_failure contradictory-scope \
  --set clusterScoped=true \
  --set 'watchNamespaces[0]=apps'
expect_template_failure unknown-value --set unexpectedValue=true
expect_template_failure monitor-without-service \
  --set metrics.service.enabled=false \
  --set metrics.serviceMonitor.enabled=true
expect_template_failure tag-and-digest \
  --set image.tag=test \
  --set image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
expect_template_failure invalid-network-policy-provider \
  --set networkPolicy.provider=calico
expect_template_failure scalar-kubernetes-ingress \
  --set networkPolicy.kubernetes.ingress=allow
expect_template_failure scalar-cilium-egress \
  --set networkPolicy.cilium.egress=allow
expect_template_failure non-object-kubernetes-rule \
  --set-json 'networkPolicy.kubernetes.ingress=["allow"]'
expect_template_failure non-object-cilium-rule \
  --set-json 'networkPolicy.cilium.egress=[443]'
expect_template_failure enabled-cilium-without-rules \
  --set networkPolicy.enabled=true
expect_template_failure enabled-kubernetes-without-rules \
  --set networkPolicy.enabled=true \
  --set networkPolicy.provider=kubernetes
expect_template_failure enabled-cilium-with-only-kubernetes-rules \
  --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.kubernetes.ingress=[]'

kubernetes_ingress_only="$tmp_dir/network-policy-kubernetes-ingress-only.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub \
  --values "$valid_values" \
  --set networkPolicy.enabled=true \
  --set networkPolicy.provider=kubernetes \
  --set-json 'networkPolicy.kubernetes.ingress=[]' \
  --show-only templates/networkpolicy.yaml >"$kubernetes_ingress_only"
for expected in \
  'apiVersion: networking.k8s.io/v1' \
  'kind: NetworkPolicy' \
  'name: test-operator-certhub-operator-network-policy' \
  'app.kubernetes.io/name: certhub-operator' \
  'app.kubernetes.io/instance: test-operator' \
  'podSelector:' \
  '- Ingress' \
  'ingress:' \
  '[]'; do
  expect_contains "$kubernetes_ingress_only" "$expected"
done
expect_not_contains "$kubernetes_ingress_only" 'kind: CiliumNetworkPolicy'
expect_not_contains "$kubernetes_ingress_only" '- Egress'
expect_not_contains "$kubernetes_ingress_only" '  egress:'

kubernetes_egress_only="$tmp_dir/network-policy-kubernetes-egress-only.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub \
  --values "$valid_values" \
  --set networkPolicy.enabled=true \
  --set networkPolicy.provider=kubernetes \
  --set-json 'networkPolicy.kubernetes.egress=[{}]' \
  --show-only templates/networkpolicy.yaml >"$kubernetes_egress_only"
for expected in '- Egress' 'egress:' '- {}'; do
  expect_contains "$kubernetes_egress_only" "$expected"
done
expect_not_contains "$kubernetes_egress_only" '- Ingress'
expect_not_contains "$kubernetes_egress_only" '  ingress:'

kubernetes_bidirectional="$tmp_dir/network-policy-kubernetes-bidirectional.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub \
  --values "$valid_values" \
  --set networkPolicy.enabled=true \
  --set networkPolicy.provider=kubernetes \
  --set-json 'networkPolicy.kubernetes.ingress=[{"from":[{"namespaceSelector":{"matchLabels":{"team":"platform"}}}],"ports":[{"port":8080,"protocol":"TCP"}]}]' \
  --set-json 'networkPolicy.kubernetes.egress=[{"to":[{"ipBlock":{"cidr":"10.0.0.0/8","except":["10.1.0.0/16"]}}],"ports":[{"port":443,"protocol":"TCP"}]}]' \
  --show-only templates/networkpolicy.yaml >"$kubernetes_bidirectional"
for expected in \
  '- Ingress' \
  '- Egress' \
  'namespaceSelector:' \
  'team: platform' \
  'port: 8080' \
  'ipBlock:' \
  'cidr: 10.0.0.0/8' \
  '- 10.1.0.0/16' \
  'port: 443' \
  'protocol: TCP'; do
  expect_contains "$kubernetes_bidirectional" "$expected"
done

cilium_ingress_only="$tmp_dir/network-policy-cilium-ingress-only.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub \
  --values "$valid_values" \
  --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.cilium.ingress=[]' \
  --show-only templates/networkpolicy.yaml >"$cilium_ingress_only"
for expected in \
  'apiVersion: cilium.io/v2' \
  'kind: CiliumNetworkPolicy' \
  'name: test-operator-certhub-operator-network-policy' \
  'app.kubernetes.io/name: certhub-operator' \
  'app.kubernetes.io/instance: test-operator' \
  'endpointSelector:' \
  'ingress:' \
  '[]'; do
  expect_contains "$cilium_ingress_only" "$expected"
done
expect_not_contains "$cilium_ingress_only" 'kind: NetworkPolicy'
expect_not_contains "$cilium_ingress_only" 'kind: CiliumClusterwideNetworkPolicy'
expect_not_contains "$cilium_ingress_only" '  egress:'
expect_not_contains "$cilium_ingress_only" 'policyTypes:'

cilium_egress_only="$tmp_dir/network-policy-cilium-egress-only.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub \
  --values "$valid_values" \
  --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.cilium.egress=[{}]' \
  --show-only templates/networkpolicy.yaml >"$cilium_egress_only"
for expected in 'egress:' '- {}'; do
  expect_contains "$cilium_egress_only" "$expected"
done
expect_not_contains "$cilium_egress_only" '  ingress:'

cilium_bidirectional="$tmp_dir/network-policy-cilium-bidirectional.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub \
  --values "$valid_values" \
  --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.cilium.ingress=[{"fromEndpoints":[{"matchLabels":{"app.kubernetes.io/name":"trusted-client"}}],"toPorts":[{"ports":[{"port":"8080","protocol":"TCP"}]}]}]' \
  --set-json 'networkPolicy.cilium.egress=[{"toFQDNs":[{"matchName":"certhub.example.test"}],"toPorts":[{"ports":[{"port":"443","protocol":"TCP"}]}]}]' \
  --show-only templates/networkpolicy.yaml >"$cilium_bidirectional"
for expected in \
  'fromEndpoints:' \
  'app.kubernetes.io/name: trusted-client' \
  'toFQDNs:' \
  'matchName: certhub.example.test' \
  'port: "8080"' \
  'port: "443"' \
  'protocol: TCP'; do
  expect_contains "$cilium_bidirectional" "$expected"
done

namespaced_rendered="$tmp_dir/namespaced.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub-system \
  --values "$valid_values" \
  --set 'watchNamespaces[0]=apps' >"$namespaced_rendered"
for expected in \
  'namespace: apps' \
  'name: WATCH_NAMESPACES' \
  'value: "apps"' \
  'name: CERTHUB_TOKEN' \
  'secretKeyRef:' \
  'kind: Role' \
  'verbs: ["create", "get", "update", "patch", "delete"]'; do
  if ! grep -F "$expected" "$namespaced_rendered" >/dev/null; then
    echo "custom-namespace render missing: $expected" >&2
    exit 1
  fi
done
expect_not_contains "$namespaced_rendered" 'CERTHUB_TOKEN_SECRET_'
expect_not_contains "$namespaced_rendered" 'resourceNames:'
if grep -F 'kind: ClusterRole' "$namespaced_rendered" >/dev/null; then
  echo "custom-namespace render unexpectedly contains cluster RBAC" >&2
  exit 1
fi

multi_namespaced_rendered="$tmp_dir/multi-namespaced.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace certhub-system \
  --values "$valid_values" \
  --set 'watchNamespaces[0]=apps' \
  --set 'watchNamespaces[1]=staging' >"$multi_namespaced_rendered"
for expected in \
  'namespace: apps' \
  'namespace: staging' \
  'value: "apps,staging"' \
  'name: CERTHUB_TOKEN' \
  'secretKeyRef:' \
  'verbs: ["create", "get", "update", "patch", "delete"]'; do
  expect_contains "$multi_namespaced_rendered" "$expected"
done
watch_role_count="$(awk '
  /^kind: Role$/ { role=1; next }
  /^kind:/ { role=0 }
  role && /^  namespace: (apps|staging)$/ { count++ }
  END { print count+0 }
' "$multi_namespaced_rendered")"
if [ "$watch_role_count" != "2" ]; then
  echo "multi-namespace render did not create exactly one Role per watched namespace" >&2
  exit 1
fi
total_role_count="$(grep -c '^kind: Role$' "$multi_namespaced_rendered" || true)"
total_role_binding_count="$(grep -c '^kind: RoleBinding$' "$multi_namespaced_rendered" || true)"
if [ "$total_role_count" != "2" ] || [ "$total_role_binding_count" != "2" ]; then
  echo "multi-namespace render contains unexpected token-specific RBAC" >&2
  exit 1
fi
expect_not_contains "$multi_namespaced_rendered" 'resourceNames:'
expect_not_contains "$multi_namespaced_rendered" 'CERTHUB_TOKEN_SECRET_'

namespaced_a="$tmp_dir/namespaced-a.yaml"
namespaced_b="$tmp_dir/namespaced-b.yaml"
"$helm_bin" template test-operator "$chart" \
  --namespace operator-a \
  --values "$valid_values" \
  --set 'watchNamespaces[0]=apps' >"$namespaced_a"
"$helm_bin" template test-operator "$chart" \
  --namespace operator-b \
  --values "$valid_values" \
  --set 'watchNamespaces[0]=apps' >"$namespaced_b"
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
for expected in \
  'kind: ClusterRole' \
  'value: ""' \
  'name: CERTHUB_TOKEN' \
  'secretKeyRef:' \
  'verbs: ["create", "get", "update", "patch", "delete"]'; do
  if ! grep -F "$expected" "$cluster_a" >/dev/null; then
    echo "cluster render missing: $expected" >&2
    exit 1
  fi
done
if grep -E '^kind: (Role|RoleBinding)$' "$cluster_a" >/dev/null; then
  echo "cluster render unexpectedly contains namespaced token RBAC" >&2
  exit 1
fi
expect_not_contains "$cluster_a" 'resourceNames:'
expect_not_contains "$cluster_a" 'CERTHUB_TOKEN_SECRET_'
cluster_name_a="$(awk '/^kind: ClusterRole$/ { found=1; next } found && /^  name:/ { print $2; exit }' "$cluster_a")"
cluster_name_b="$(awk '/^kind: ClusterRole$/ { found=1; next } found && /^  name:/ { print $2; exit }' "$cluster_b")"
if [ -z "$cluster_name_a" ] || [ -z "$cluster_name_b" ] || [ "$cluster_name_a" = "$cluster_name_b" ]; then
  echo "cluster-scoped resource names are not namespace-unique" >&2
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
packaged_policy="$tmp_dir/packaged-network-policy.yaml"
"$helm_bin" template test-operator "$packaged_chart" \
  --namespace certhub \
  --values "$valid_values" \
  --set networkPolicy.enabled=true \
  --set networkPolicy.provider=kubernetes \
  --set-json 'networkPolicy.kubernetes.egress=[]' \
  --show-only templates/networkpolicy.yaml >"$packaged_policy"
for expected in 'kind: NetworkPolicy' '- Egress' 'egress:' '[]'; do
  expect_contains "$packaged_policy" "$expected"
done

if command -v "$kubeconform_bin" >/dev/null 2>&1; then
  "$kubeconform_bin" -strict -summary -ignore-missing-schemas "$default_rendered" >/dev/null
  "$kubeconform_bin" -strict -summary "$kubernetes_ingress_only" >/dev/null
  "$kubeconform_bin" -strict -summary "$kubernetes_egress_only" >/dev/null
  "$kubeconform_bin" -strict -summary "$kubernetes_bidirectional" >/dev/null
fi

if command -v "$kubectl_bin" >/dev/null 2>&1 &&
  "$kubectl_bin" get crd ciliumnetworkpolicies.cilium.io \
    --request-timeout=5s >/dev/null 2>&1; then
  cilium_server_dry_run="$tmp_dir/network-policy-cilium-server-dry-run.yaml"
  "$helm_bin" template test-operator "$chart" \
    --namespace default \
    --values "$valid_values" \
    --set networkPolicy.enabled=true \
    --set-json 'networkPolicy.cilium.egress=[]' \
    --show-only templates/networkpolicy.yaml >"$cilium_server_dry_run"
  "$kubectl_bin" apply --dry-run=server \
    --request-timeout=10s \
    --filename "$cilium_server_dry_run" >/dev/null
fi

echo "Operator Helm chart checks passed."
