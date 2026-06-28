#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="$repo_root/dist"
release_dir="$dist_dir/release"
web_dist_dir="$dist_dir/web"
web_embed_dir="$repo_root/internal/webui/assets"
go_bin="${GO_BIN:-go}"
node_bin="${NODE_BIN:-${NODE:-node}}"
npm_bin="${NPM_BIN:-${NPM:-npm}}"
version="${RELEASE_VERSION:-${GITHUB_REF_NAME:-v0.1.0}}"
version="${version#v}"
source_date_epoch="${SOURCE_DATE_EPOCH:-0}"
generated_at="${BUILD_TIMESTAMP:-$(date -u -d "@$source_date_epoch" +%Y-%m-%dT%H:%M:%SZ)}"
targets=(linux/amd64 linux/arm64)
binaries=(certhub-server certhub-cli certhub-operator)

cd "$repo_root"
rm -rf "$release_dir" "$dist_dir/bin/linux-amd64" "$dist_dir/bin/linux-arm64"
mkdir -p "$release_dir" "$dist_dir/bin"

(
  cd "$repo_root/web"
  "$npm_bin" ci --ignore-scripts --registry https://registry.npmjs.org
  "$npm_bin" run typecheck
  "$npm_bin" run build
)

tmp_assets="$(mktemp -d)"
tmp_stage="$(mktemp -d)"
cleanup() {
  find "$web_embed_dir" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  cp -a "$tmp_assets/assets"/. "$web_embed_dir"/
  rm -rf "$tmp_assets" "$tmp_stage"
}
trap cleanup EXIT

mkdir -p "$tmp_assets/assets"
cp -a "$web_embed_dir"/. "$tmp_assets/assets"/
find "$web_embed_dir" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
cp -a "$web_dist_dir"/. "$web_embed_dir"/

for target in "${targets[@]}"; do
  target_os="${target%/*}"
  target_arch="${target#*/}"
  platform_dir="$dist_dir/bin/$target_os-$target_arch"
  mkdir -p "$platform_dir"
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" GOCACHE="${GOCACHE:-$HOME/.cache/go-build}" GOPATH="${GOPATH:-$HOME/go}" GOMODCACHE="${GOMODCACHE:-$HOME/go/pkg/mod}" GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}" GOFLAGS=-mod=readonly "$go_bin" build -trimpath -buildvcs=false -ldflags "-s -w" -o "$platform_dir/certhub-server" ./cmd/certhub-server
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" GOCACHE="${GOCACHE:-$HOME/.cache/go-build}" GOPATH="${GOPATH:-$HOME/go}" GOMODCACHE="${GOMODCACHE:-$HOME/go/pkg/mod}" GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}" GOFLAGS=-mod=readonly "$go_bin" build -trimpath -buildvcs=false -ldflags "-s -w" -o "$platform_dir/certhub-cli" ./cmd/certhub-cli
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" GOCACHE="${GOCACHE:-$HOME/.cache/go-build}" GOPATH="${GOPATH:-$HOME/go}" GOMODCACHE="${GOMODCACHE:-$HOME/go/pkg/mod}" GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}" GOFLAGS=-mod=readonly "$go_bin" build -trimpath -buildvcs=false -ldflags "-s -w" -o "$platform_dir/certhub-operator" ./cmd/certhub-operator

  for bin in "${binaries[@]}"; do
    cp -a "$platform_dir/$bin" "$release_dir/${bin}_${version}_${target_os}_${target_arch}"
  done

  archive_root="$tmp_stage/certhub"
  rm -rf "$archive_root"
  mkdir -p "$archive_root/bin" "$archive_root/config/examples" "$archive_root/deploy" "$archive_root/api" "$archive_root/specs" "$archive_root/migrations/postgres" "$archive_root/manifests"
  cp -a "$platform_dir"/. "$archive_root/bin"/
  cp -a "$repo_root/config/examples"/. "$archive_root/config/examples"/
  mkdir -p "$archive_root/deploy/docker" "$archive_root/deploy/helm" "$archive_root/deploy/systemd"
  cp -a "$repo_root/deploy/docker"/. "$archive_root/deploy/docker"/
  cp -a "$repo_root/deploy/helm/certhub-server" "$archive_root/deploy/helm"/
  cp -a "$repo_root/deploy/helm/certhub-operator" "$archive_root/deploy/helm"/
  cp -a "$repo_root/deploy/systemd"/. "$archive_root/deploy/systemd"/
  cp -a "$repo_root/api/openapi.yaml" "$archive_root/api/openapi.yaml"
  cp -a "$repo_root/specs"/. "$archive_root/specs"/
  find "$repo_root/migrations/postgres" -maxdepth 1 -type f -name '*.sql' -exec cp -a {} "$archive_root/migrations/postgres/" \;
  cp -a "$repo_root/go.mod" "$repo_root/go.sum" "$archive_root/manifests"/
  cp -a "$repo_root/web/package.json" "$repo_root/web/package-lock.json" "$archive_root/manifests"/
  find "$archive_root" -name .gitkeep -type f -delete

  cat >"$archive_root/README.release.md" <<'README'
# Certhub Release Artifact

This archive contains static Certhub binaries for one Linux platform,
deployment manifests, example configuration, OpenAPI/specification files, and
PostgreSQL migration SQL.
README

  (
    cd "$tmp_stage"
    tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner -cf - certhub | gzip -n > "$release_dir/certhub_${version}_${target_os}_${target_arch}.tar.gz"
  )
done

last_archive_root="$tmp_stage/certhub"
SOURCE_DATE_EPOCH="$source_date_epoch" BUILD_TIMESTAMP="$generated_at" GO_BIN="$go_bin" "$node_bin" "$repo_root/scripts/generate-release-sbom.mjs" "$last_archive_root" >"$release_dir/sbom.json"

git_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || true)"
if git -C "$repo_root" diff --quiet --ignore-submodules HEAD -- 2>/dev/null && git -C "$repo_root" diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
  git_dirty=false
else
  git_dirty=true
fi
go_version="$("$go_bin" version 2>/dev/null | sed 's/"/\\"/g')"
node_version="$("$node_bin" --version 2>/dev/null | sed 's/"/\\"/g')"

cat >"$release_dir/provenance.json" <<EOF
{
  "schema": "certhub-multiarch-build-provenance-v1",
  "version": "$version",
  "generated_at": "$generated_at",
  "source": {
    "type": "github repository",
    "repository": "github.com/torob/certhub",
    "git_commit": "$git_commit",
    "dirty": $git_dirty
  },
  "tools": {
    "go": "$go_version",
    "node": "$node_version"
  },
  "platforms": ["linux/amd64", "linux/arm64"],
  "go_build_flags": "-trimpath -buildvcs=false -ldflags '-s -w'"
}
EOF

(
  cd "$release_dir"
  find . -maxdepth 1 -type f ! -name checksums.txt -printf '%P\0' | sort -z | xargs -0 sha256sum > checksums.txt
)

echo "Multi-arch release artifacts written to $release_dir"
