#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
context_dir="${IMAGE_CHECK_CONTEXT:-$repo_root}"
binary_dir="${IMAGE_CHECK_BINARY_DIR:-dist/bin}"
tmp_dir="$(mktemp -d)"
cids=()
images=()

cleanup() {
  for cid in "${cids[@]}"; do
    docker rm -f "$cid" >/dev/null 2>&1 || true
  done
  for image in "${images[@]}"; do
    docker image rm -f "$image" >/dev/null 2>&1 || true
  done
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for image release checks" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "docker daemon is required for image release checks" >&2
  exit 1
fi

check_image() {
  local name="$1"
  local dockerfile="$2"
  local binary="$3"
  local expected_cmd="$4"
  local image="certhub-${name}:release-check"
  local rootfs="$tmp_dir/${name}.tar"
  local files="$tmp_dir/${name}.files"

  docker build --pull=false --build-arg "BINARY_DIR=$binary_dir" -f "$context_dir/deploy/docker/$dockerfile" -t "$image" "$context_dir" >/dev/null
  images+=("$image")

  local user
  user="$(docker image inspect --format '{{.Config.User}}' "$image")"
  if [ "$user" != "65532:65532" ]; then
    echo "$name image must run as 65532:65532, got: $user" >&2
    exit 1
  fi

  local entrypoint
  entrypoint="$(docker image inspect --format '{{json .Config.Entrypoint}}' "$image")"
  if [ "$entrypoint" != "[\"/usr/local/bin/$binary\"]" ]; then
    echo "unexpected $name image entrypoint: $entrypoint" >&2
    exit 1
  fi

  local cmd
  cmd="$(docker image inspect --format '{{json .Config.Cmd}}' "$image")"
  if [ "$cmd" != "$expected_cmd" ]; then
    echo "unexpected $name image cmd: $cmd" >&2
    exit 1
  fi

  local cid
  cid="$(docker create "$image")"
  cids+=("$cid")
  docker export "$cid" -o "$rootfs"
  tar -tf "$rootfs" >"$files"

  for required in \
    "etc/ssl/certs/ca-certificates.crt" \
    "usr/local/bin/$binary"; do
    if ! grep -Fx "$required" "$files" >/dev/null; then
      echo "$name image missing required file: $required" >&2
      exit 1
    fi
  done

  if grep -E '(^|/)(\.git|node_modules|coverage|\.cache|src|web|test)(/|$)|\.map$|(^|/)\.env$' "$files" >/dev/null; then
    echo "$name image contains forbidden source, cache, or development paths" >&2
    grep -E '(^|/)(\.git|node_modules|coverage|\.cache|src|web|test)(/|$)|\.map$|(^|/)\.env$' "$files" >&2 || true
    exit 1
  fi

  tar -xOf "$rootfs" "usr/local/bin/$binary" | strings >"$tmp_dir/${name}.strings"
  if grep -E -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$tmp_dir/${name}.strings" >/dev/null; then
    echo "$name image binary appears to contain embedded private key material" >&2
    exit 1
  fi
}

check_image "server" "server.Dockerfile" "certhub-server" '["run","--config","/etc/certhub/server.yaml"]'
check_image "cli" "cli.Dockerfile" "certhub-cli" '["run","--config","/etc/certhub/cli.yaml"]'
check_image "operator" "operator.Dockerfile" "certhub-operator" '["run"]'

echo "Container image policy passed."
