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

for chart in certhub-server certhub-operator; do
  "$helm_bin" lint "$tmp_dir/certhub/deploy/helm/$chart" >/dev/null
  "$helm_bin" template "test-$chart" "$tmp_dir/certhub/deploy/helm/$chart" --namespace certhub --include-crds >/dev/null
done

server_rendered="$tmp_dir/server-rendered.yaml"
operator_rendered="$tmp_dir/operator-rendered.yaml"
"$helm_bin" template test-server "$tmp_dir/certhub/deploy/helm/certhub-server" --namespace certhub >"$server_rendered"
"$helm_bin" template test-operator "$tmp_dir/certhub/deploy/helm/certhub-operator" --namespace certhub --include-crds --set clusterScoped=true --set watchNamespace=apps >"$operator_rendered"
for expected in \
  "automountServiceAccountToken: false" \
  "fsGroup: 65532" \
  "fsGroupChangePolicy: OnRootMismatch" \
  "defaultMode: 0440"; do
  if ! grep -F "$expected" "$server_rendered" "$tmp_dir/certhub/deploy/helm/certhub-server/values.yaml" >/dev/null; then
    echo "server chart render/defaults missing: $expected" >&2
    exit 1
  fi
done
"$node_bin" - "$tmp_dir/certhub/deploy/helm/certhub-server/values.yaml" "$tmp_dir/certhub/deploy/helm/certhub-operator/values.yaml" <<'NODE'
const fs = require("fs");
for (const valuesPath of process.argv.slice(2)) {
  const text = fs.readFileSync(valuesPath, "utf8");
  const match = text.match(/^\s*tag:\s*["']?([^"'\n#]+)["']?/m);
  const tag = match?.[1]?.trim();
  if (!tag || tag === "latest") {
    console.error(`${valuesPath} must default to a non-latest image tag`);
    process.exit(1);
  }
}
NODE
if ! grep -A1 'name: CERTHUB_TOKEN_SECRET_NAMESPACE' "$operator_rendered" | grep -F 'value: "certhub"' >/dev/null; then
  echo "operator cluster-scoped token namespace default does not match release namespace" >&2
  exit 1
fi

IMAGE_CHECK_CONTEXT="$tmp_dir/certhub" IMAGE_CHECK_BINARY_DIR=bin "$repo_root/scripts/check-cli-image.sh"

echo "Release scaffold policy passed."
