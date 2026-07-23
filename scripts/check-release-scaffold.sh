#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="$repo_root/dist"
helm_bin="${HELM_BIN:-helm}"
node_bin="${NODE_BIN:-${NODE:-node}}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

for name in certhub-server certhub-cli certhub-operator; do
  bin="$dist_dir/bin/$name"
  if [ ! -x "$bin" ]; then
    echo "missing executable release scaffold binary: $bin" >&2
    exit 1
  fi
  if command -v ldd >/dev/null 2>&1 && ldd "$bin" 2>&1 | grep -v 'not a dynamic executable' | grep -q .; then
    echo "$bin appears to have dynamic runtime dependencies" >&2
    ldd "$bin" >&2 || true
    exit 1
  fi
  if strings "$bin" | grep -E "$repo_root|/tmp/|web/src|node_modules" >/dev/null; then
    echo "$bin contains a forbidden local/build path or frontend source reference" >&2
    exit 1
  fi
done

if ! strings "$dist_dir/bin/certhub-server" | grep -E '/assets/index-[A-Za-z0-9_-]+\.(js|css)' >/dev/null; then
  echo "certhub-server does not appear to embed production Vite assets" >&2
  exit 1
fi
if strings "$dist_dir/bin/certhub-server" | grep -F 'Placeholder for generated production web assets' >/dev/null; then
  echo "certhub-server appears to embed placeholder web assets" >&2
  exit 1
fi

if find "$dist_dir" -type d \( -name .git -o -name node_modules -o -name coverage -o -name .cache \) | grep -q .; then
  echo "dist contains forbidden release scaffold directories" >&2
  exit 1
fi

if find "$dist_dir" -type f \( -name '*.map' -o -name '.env' \) | grep -q .; then
  echo "dist contains forbidden release scaffold files" >&2
  exit 1
fi

release_dir="$dist_dir/release"
for required in certhub-release.tar.gz sbom.json provenance.json checksums.txt; do
  if [ ! -f "$release_dir/$required" ]; then
    echo "missing release artifact: $release_dir/$required" >&2
    exit 1
  fi
done

if ! (cd "$release_dir" && sha256sum -c checksums.txt >/dev/null); then
  echo "release checksums do not verify" >&2
  exit 1
fi

archive_files="$tmp_dir/archive-files.txt"
tar -tzf "$release_dir/certhub-release.tar.gz" >"$archive_files"
if grep -E '(^|/)(\.git|node_modules|coverage|\.cache|test|tmp)(/|$)|\.map$|(^|/)\.env$|web/src' "$archive_files" >/dev/null; then
  echo "release archive contains forbidden paths" >&2
  grep -E '(^|/)(\.git|node_modules|coverage|\.cache|test|tmp)(/|$)|\.map$|(^|/)\.env$|web/src' "$archive_files" >&2 || true
  exit 1
fi
if grep -E '\.(go|ts|tsx|jsx)$' "$archive_files" >/dev/null; then
  echo "release archive contains source files" >&2
  grep -E '\.(go|ts|tsx|jsx)$' "$archive_files" >&2 || true
  exit 1
fi

tar -xzf "$release_dir/certhub-release.tar.gz" -C "$tmp_dir"

"$node_bin" - "$release_dir/sbom.json" "$release_dir/provenance.json" <<'NODE'
const fs = require("fs");
const [sbomPath, provenancePath] = process.argv.slice(2);
const sbom = JSON.parse(fs.readFileSync(sbomPath, "utf8"));
const provenance = JSON.parse(fs.readFileSync(provenancePath, "utf8"));
function fail(message) {
  console.error(message);
  process.exit(1);
}
if (sbom.schema !== "certhub-release-sbom-v1") fail("release SBOM is missing expected schema");
if (!Array.isArray(sbom.artifacts) || !sbom.artifacts.some((a) => a.path === "bin/certhub-server" && a.type === "binary")) fail("release SBOM is missing binary artifacts");
if (!sbom.artifacts.some((a) => a.path === "deploy/helm/certhub-server/Chart.yaml" && a.type === "helm")) fail("release SBOM is missing Helm artifacts");
for (const type of ["archive", "binary", "helm", "dockerfile", "systemd", "config", "migration", "openapi", "spec", "manifest"]) {
  if (!sbom.artifacts.some((a) => a.type === type)) fail(`release SBOM missing ${type} artifact coverage`);
}
if (provenance.schema !== "certhub-build-provenance-v1") fail("release provenance is missing expected schema");
if (!provenance.source?.git_commit || typeof provenance.source.dirty !== "boolean") fail("release provenance missing source commit/dirty fields");
if (!provenance.tools?.go || !provenance.tools?.node) fail("release provenance missing tool versions");
for (const key of ["certhub-server", "certhub-cli", "certhub-operator"]) {
  if (!/^[a-f0-9]{64}$/.test(provenance.binaries?.[key] || "")) fail(`release provenance missing ${key} hash`);
}
for (const key of ["go_mod_sha256", "go_sum_sha256", "package_lock_sha256"]) {
  if (!/^[a-f0-9]{64}$/.test(provenance.inputs?.[key] || "")) fail(`release provenance missing ${key}`);
}
if (!String(provenance.inputs?.docker_ca_base || "").includes("@sha256:")) fail("release provenance missing pinned Docker base digest");
if (!/^[a-f0-9]{64}$/.test(provenance.sbom_sha256 || "")) fail("release provenance missing SBOM hash");
NODE

"$helm_bin" lint "$tmp_dir/certhub/deploy/helm/certhub-server" >/dev/null
"$helm_bin" template test-server "$tmp_dir/certhub/deploy/helm/certhub-server" --namespace certhub --include-crds >/dev/null
HELM_BIN="$helm_bin" "$repo_root/scripts/check-operator-helm-chart.sh" "$tmp_dir/certhub/deploy/helm/certhub-operator" >/dev/null

server_rendered="$tmp_dir/server-rendered.yaml"
operator_rendered="$tmp_dir/operator-rendered.yaml"
"$helm_bin" template test-server "$tmp_dir/certhub/deploy/helm/certhub-server" --namespace certhub >"$server_rendered"
"$helm_bin" template test-operator "$tmp_dir/certhub/deploy/helm/certhub-operator" \
  --namespace certhub \
  --include-crds \
  --values "$tmp_dir/certhub/deploy/helm/certhub-operator/ci/values.yaml" \
  --set clusterScoped=true >"$operator_rendered"
for expected in \
  "automountServiceAccountToken: false" \
  "fsGroup: 65532" \
  "fsGroupChangePolicy: OnRootMismatch" \
  "revisionHistoryLimit: 3" \
  "defaultMode: 0440"; do
  if ! grep -F "$expected" "$server_rendered" "$tmp_dir/certhub/deploy/helm/certhub-server/values.yaml" >/dev/null; then
    echo "server chart render/defaults missing: $expected" >&2
    exit 1
  fi
done
server_zero_revision_history="$tmp_dir/server-zero-revision-history.yaml"
"$helm_bin" template test-server "$tmp_dir/certhub/deploy/helm/certhub-server" \
  --namespace certhub \
  --set revisionHistoryLimit=0 \
  --show-only templates/deployment.yaml >"$server_zero_revision_history"
if ! grep -F "revisionHistoryLimit: 0" "$server_zero_revision_history" >/dev/null; then
  echo "server chart did not render revisionHistoryLimit override" >&2
  exit 1
fi
"$node_bin" - "$tmp_dir/certhub/deploy/helm/certhub-server/values.yaml" "$tmp_dir/certhub/deploy/helm/certhub-operator/values.yaml" <<'NODE'
const fs = require("fs");
for (const valuesPath of process.argv.slice(2)) {
  const text = fs.readFileSync(valuesPath, "utf8");
  const match = text.match(/^\s*tag:\s*(.*?)\s*(?:#.*)?$/m);
  const tag = match?.[1]?.replace(/^["']|["']$/g, "").trim();
  const isOperator = valuesPath.includes("certhub-operator");
  if (tag === "latest" || (!isOperator && !tag)) {
    console.error(`${valuesPath} must use an appVersion-derived or explicit non-latest image tag`);
    process.exit(1);
  }
}
NODE
for expected in \
  'name: CERTHUB_TOKEN' \
  'secretKeyRef:' \
  'name: "certhub-token"' \
  'key: "token"'; do
  if ! grep -F "$expected" "$operator_rendered" >/dev/null; then
    echo "operator chart render missing token Secret injection: $expected" >&2
    exit 1
  fi
done
if grep -E '^kind: (Role|RoleBinding)$|CERTHUB_TOKEN_SECRET_|resourceNames:' "$operator_rendered" >/dev/null; then
  echo "operator cluster-scoped render contains removed token configuration or RBAC" >&2
  exit 1
fi
for expected in \
  'name: CERTHUB_HTTP_RETRY_MAX_ATTEMPTS' \
  'value: "5"' \
  'name: CERTHUB_HTTP_RETRY_INITIAL_BACKOFF' \
  'value: "1s"' \
  'name: CERTHUB_HTTP_RETRY_MAX_BACKOFF' \
  'value: "8s"' \
  'verbs: ["create", "get", "update", "patch", "delete"]'; do
  if ! grep -F "$expected" "$operator_rendered" >/dev/null; then
    echo "operator chart render missing retry default: $expected" >&2
    exit 1
  fi
done

operator_multi_namespace_rendered="$tmp_dir/operator-multi-namespace-rendered.yaml"
"$helm_bin" template test-operator "$tmp_dir/certhub/deploy/helm/certhub-operator" \
  --namespace certhub \
  --values "$tmp_dir/certhub/deploy/helm/certhub-operator/ci/values.yaml" \
  --set 'watchNamespaces[0]=apps' \
  --set 'watchNamespaces[1]=staging' >"$operator_multi_namespace_rendered"
for expected in \
  'namespace: apps' \
  'namespace: staging' \
  'name: WATCH_NAMESPACES' \
  'value: "apps,staging"' \
  'name: CERTHUB_TOKEN' \
  'secretKeyRef:' \
  'verbs: ["create", "get", "update", "patch", "delete"]'; do
  if ! grep -F "$expected" "$operator_multi_namespace_rendered" >/dev/null; then
    echo "release scaffold operator multi-namespace render missing: $expected" >&2
    exit 1
  fi
done
operator_multi_role_count="$(grep -c '^kind: Role$' "$operator_multi_namespace_rendered" || true)"
operator_multi_binding_count="$(grep -c '^kind: RoleBinding$' "$operator_multi_namespace_rendered" || true)"
if [ "$operator_multi_role_count" != "2" ] || [ "$operator_multi_binding_count" != "2" ] ||
  grep -E 'CERTHUB_TOKEN_SECRET_|resourceNames:' "$operator_multi_namespace_rendered" >/dev/null; then
  echo "release scaffold operator render contains unexpected token-specific RBAC" >&2
  exit 1
fi

operator_policy_rendered="$tmp_dir/operator-policy-rendered.yaml"
"$helm_bin" template test-operator "$tmp_dir/certhub/deploy/helm/certhub-operator" \
  --namespace certhub \
  --values "$tmp_dir/certhub/deploy/helm/certhub-operator/ci/values.yaml" \
  --set networkPolicy.enabled=true \
  --set networkPolicy.provider=kubernetes \
  --set-json 'networkPolicy.kubernetes.ingress=[]' \
  --show-only templates/networkpolicy.yaml >"$operator_policy_rendered"
for expected in \
  'apiVersion: networking.k8s.io/v1' \
  'kind: NetworkPolicy' \
  'app.kubernetes.io/name: certhub-operator' \
  '- Ingress' \
  'ingress:' \
  '[]'; do
  if ! grep -F -- "$expected" "$operator_policy_rendered" >/dev/null; then
    echo "release scaffold operator chart network policy missing: $expected" >&2
    exit 1
  fi
done

operator_retry_rendered="$tmp_dir/operator-retry-rendered.yaml"
"$helm_bin" template test-operator "$tmp_dir/certhub/deploy/helm/certhub-operator" \
  --namespace certhub \
  --values "$tmp_dir/certhub/deploy/helm/certhub-operator/ci/values.yaml" \
  --set certhub.httpRetryMaxAttempts=1 \
  --set certhub.httpRetryInitialBackoff=250ms \
  --set certhub.httpRetryMaxBackoff=2s >"$operator_retry_rendered"
for expected in 'value: "1"' 'value: "250ms"' 'value: "2s"'; do
  if ! grep -F "$expected" "$operator_retry_rendered" >/dev/null; then
    echo "operator chart render missing retry override: $expected" >&2
    exit 1
  fi
done

IMAGE_CHECK_CONTEXT="$tmp_dir/certhub" IMAGE_CHECK_BINARY_DIR=bin "$repo_root/scripts/check-cli-image.sh"

echo "Release scaffold policy passed."
