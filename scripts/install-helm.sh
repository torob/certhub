#!/usr/bin/env bash
set -euo pipefail

version="${HELM_VERSION:-3.22.1}"
tools_dir="${CODEX_TOOLS:-$HOME/.tools}"
install_dir="$tools_dir/helm/$version"
helm_bin="$install_dir/linux-amd64/helm"
case "$version" in
  3.22.1)
    expected_sha256="896cf63684a42a723d61c980369d6e588330927deb13676ca0d85006dd6da0ea"
    ;;
  *)
    echo "unsupported Helm version for checksum-pinned install: $version" >&2
    exit 1
    ;;
esac

if [ ! -x "$helm_bin" ]; then
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT
  mkdir -p "$install_dir"
  curl -fsSL "https://get.helm.sh/helm-v${version}-linux-amd64.tar.gz" -o "$tmp_dir/helm.tar.gz"
  printf '%s  %s\n' "$expected_sha256" "$tmp_dir/helm.tar.gz" | sha256sum -c >/dev/null
  tar -xzf "$tmp_dir/helm.tar.gz" -C "$install_dir"
fi

"$helm_bin" version --short
