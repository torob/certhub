#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="$repo_root/dist"
release_dir="$dist_dir/release"
archive_root="$release_dir/certhub"
source_date_epoch="${SOURCE_DATE_EPOCH:-0}"
generated_at="${BUILD_TIMESTAMP:-$(date -u -d "@$source_date_epoch" +%Y-%m-%dT%H:%M:%SZ)}"
go_bin="${GO_BIN:-go}"
node_bin="${NODE:-node}"

rm -rf "$release_dir"
mkdir -p "$archive_root"

for bin in certhub-server certhub-cli certhub-operator; do
  if [ ! -x "$dist_dir/bin/$bin" ]; then
    echo "missing release binary: $dist_dir/bin/$bin" >&2
    exit 1
  fi
done

host_os="$("$go_bin" env GOOS)"
host_arch="$("$go_bin" env GOARCH)"
platform_bin_dir="$dist_dir/bin/$host_os-$host_arch"
mkdir -p "$platform_bin_dir"
for bin in certhub-server certhub-cli certhub-operator; do
  cp -a "$dist_dir/bin/$bin" "$platform_bin_dir/$bin"
done

mkdir -p "$archive_root/bin" "$archive_root/config/examples" "$archive_root/deploy" "$archive_root/api" "$archive_root/specs" "$archive_root/migrations/postgres" "$archive_root/manifests"
cp -a "$dist_dir/bin/." "$archive_root/bin/"
cp -a "$repo_root/config/examples/." "$archive_root/config/examples/"
mkdir -p "$archive_root/deploy/docker" "$archive_root/deploy/helm" "$archive_root/deploy/systemd"
cp -a "$repo_root/deploy/docker/." "$archive_root/deploy/docker/"
cp -a "$repo_root/deploy/helm/certhub-server" "$archive_root/deploy/helm/"
cp -a "$repo_root/deploy/helm/certhub-operator" "$archive_root/deploy/helm/"
cp -a "$repo_root/deploy/systemd/." "$archive_root/deploy/systemd/"
cp -a "$repo_root/api/openapi.yaml" "$archive_root/api/openapi.yaml"
cp -a "$repo_root/specs/." "$archive_root/specs/"
find "$repo_root/migrations/postgres" -maxdepth 1 -type f -name '*.sql' -exec cp -a {} "$archive_root/migrations/postgres/" \;
cp -a "$repo_root/go.mod" "$repo_root/go.sum" "$archive_root/manifests/"
cp -a "$repo_root/web/package.json" "$repo_root/web/package-lock.json" "$archive_root/manifests/"
find "$archive_root" -name .gitkeep -type f -delete

cat >"$archive_root/README.release.md" <<'README'
# Certhub Release Artifact

This archive contains static Certhub binaries, deployment manifests, example
configuration, OpenAPI/specification files, and PostgreSQL migration SQL.
Secrets, local configuration, package-manager caches, source control metadata,
test fixtures, and frontend source assets are intentionally excluded.
README

if find "$archive_root" -type l | grep -q .; then
  echo "release archive staging contains symlinks" >&2
  find "$archive_root" -type l >&2
  exit 1
fi

(
  cd "$release_dir"
  tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner -cf - certhub | gzip -n > certhub-release.tar.gz
)

(
  cd "$repo_root"
  SOURCE_DATE_EPOCH="$source_date_epoch" BUILD_TIMESTAMP="$generated_at" "$node_bin" scripts/generate-release-sbom.mjs "$archive_root" >"$release_dir/sbom.json"
)

git_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || true)"
if git -C "$repo_root" diff --quiet --ignore-submodules HEAD -- 2>/dev/null && git -C "$repo_root" diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
  git_dirty=false
else
  git_dirty=true
fi
go_version="$("$go_bin" version 2>/dev/null | sed 's/"/\\"/g')"
node_version="$("$node_bin" --version 2>/dev/null | sed 's/"/\\"/g')"
go_mod_sha256="$(sha256sum "$repo_root/go.mod" | awk '{print $1}')"
go_sum_sha256="$(sha256sum "$repo_root/go.sum" | awk '{print $1}')"
package_lock_sha256="$(sha256sum "$repo_root/web/package-lock.json" | awk '{print $1}')"
server_sha256="$(sha256sum "$dist_dir/bin/certhub-server" | awk '{print $1}')"
cli_sha256="$(sha256sum "$dist_dir/bin/certhub-cli" | awk '{print $1}')"
operator_sha256="$(sha256sum "$dist_dir/bin/certhub-operator" | awk '{print $1}')"
sbom_sha256="$(sha256sum "$release_dir/sbom.json" | awk '{print $1}')"

cat >"$release_dir/provenance.json" <<EOF
{
  "schema": "certhub-build-provenance-v1",
  "generated_at": "$generated_at",
  "source": {
    "type": "local workspace",
    "git_commit": "$git_commit",
    "dirty": $git_dirty
  },
  "tools": {
    "go": "$go_version",
    "node": "$node_version"
  },
  "inputs": {
    "go_mod_sha256": "$go_mod_sha256",
    "go_sum_sha256": "$go_sum_sha256",
    "package_lock_sha256": "$package_lock_sha256",
    "docker_ca_base": "docker.io/library/alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"
  },
  "binaries": {
    "certhub-server": "$server_sha256",
    "certhub-cli": "$cli_sha256",
    "certhub-operator": "$operator_sha256"
  },
  "sbom_sha256": "$sbom_sha256",
  "go_build_flags": "-trimpath -buildvcs=false -ldflags '-s -w'",
  "web_output": "dist/web",
  "archive": "certhub-release.tar.gz"
}
EOF

(
  cd "$release_dir"
  {
    sha256sum certhub-release.tar.gz sbom.json provenance.json
    find certhub -type f -print0 | sort -z | xargs -0 sha256sum
  } > checksums.txt
)

echo "Release artifacts written to $release_dir"
