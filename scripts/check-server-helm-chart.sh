#!/usr/bin/env bash
set -euo pipefail

# Render-only checks for the certhub-server Helm chart. The server listens on
# the port in the embedded server config (http.bind_addr). The container port,
# the probes and the Service target must follow that port, and service.port
# must change only the Service port.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
chart="${1:-$repo_root/deploy/helm/certhub-server}"
helm_bin="${HELM_BIN:-helm}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

if ! command -v "$helm_bin" >/dev/null 2>&1; then
  echo "helm is required for server chart checks" >&2
  exit 1
fi

render() {
  local name="$1"
  shift
  "$helm_bin" template test-server "$chart" --namespace certhub "$@" >"$tmp_dir/$name.yaml"
  "$helm_bin" template test-server "$chart" --namespace certhub "$@" \
    --show-only templates/deployment.yaml >"$tmp_dir/$name-deployment.yaml"
  "$helm_bin" template test-server "$chart" --namespace certhub "$@" \
    --show-only templates/service.yaml >"$tmp_dir/$name-service.yaml"
  "$helm_bin" template test-server "$chart" --namespace certhub "$@" \
    --show-only templates/configmap.yaml >"$tmp_dir/$name-configmap.yaml"
}

field() {
  local file="$1"
  local key="$2"
  awk -v key="$key:" '$1 == key { print $2 }' "$file"
}

bind_port() {
  local file="$1"
  local addr
  addr="$(awk '$1 == "bind_addr:" { print $2 }' "$file" | tr -d "\"'")"
  printf '%s\n' "${addr##*:}"
}

# expect_ports CASE SERVICE_PORT LISTEN_PORT
expect_ports() {
  local name="$1"
  local want_service_port="$2"
  local want_listen_port="$3"
  local deployment="$tmp_dir/$name-deployment.yaml"
  local service="$tmp_dir/$name-service.yaml"
  local configmap="$tmp_dir/$name-configmap.yaml"
  local listen_port container_port service_port target_port probe_ports

  listen_port="$(bind_port "$configmap")"
  container_port="$(field "$deployment" containerPort)"
  service_port="$(field "$service" port)"
  target_port="$(field "$service" targetPort)"
  probe_ports="$(awk '$1 == "port:" { print $2 }' "$deployment" | sort -u | tr '\n' ' ')"

  if [ "$listen_port" != "$want_listen_port" ]; then
    echo "$name: server config listens on port '$listen_port', want '$want_listen_port'" >&2
    exit 1
  fi
  if [ "$container_port" != "$listen_port" ]; then
    echo "$name: containerPort '$container_port' does not match server bind_addr port '$listen_port'" >&2
    exit 1
  fi
  if ! grep -E '^ *- name: http$' "$deployment" >/dev/null; then
    echo "$name: container port is not named http" >&2
    exit 1
  fi
  if [ "$probe_ports" != "http " ]; then
    echo "$name: probes must use the named port http, got '$probe_ports'" >&2
    exit 1
  fi
  if [ "$service_port" != "$want_service_port" ]; then
    echo "$name: Service port '$service_port', want '$want_service_port'" >&2
    exit 1
  fi
  if [ "$target_port" != "http" ]; then
    echo "$name: Service targetPort '$target_port', want 'http'" >&2
    exit 1
  fi
}

expect_template_failure() {
  local name="$1"
  local message="$2"
  shift 2
  if "$helm_bin" template test-server "$chart" --namespace certhub "$@" \
    >"$tmp_dir/$name.stdout" 2>"$tmp_dir/$name.stderr"; then
    echo "server chart unexpectedly accepted invalid case: $name" >&2
    exit 1
  fi
  if ! grep -F -- "$message" "$tmp_dir/$name.stderr" >/dev/null; then
    echo "server chart invalid case $name failed without expected message: $message" >&2
    cat "$tmp_dir/$name.stderr" >&2
    exit 1
  fi
}

# config_with_bind_addr ADDR NAME writes a values file with the chart's
# default config block, changed only in http.bind_addr.
config_with_bind_addr() {
  local addr="$1"
  sed "s|bind_addr: \":8080\"|bind_addr: \"$addr\"|" "$chart/values.yaml" |
    awk '/^config:/ { on = 1; print; next } on && /^[^ ]/ { exit } on { print }' >"$tmp_dir/config-$2.yaml"
  if ! grep -F "bind_addr: \"$addr\"" "$tmp_dir/config-$2.yaml" >/dev/null; then
    echo "could not build config override with bind_addr $addr" >&2
    exit 1
  fi
}

"$helm_bin" lint --strict "$chart" >/dev/null

render default
expect_ports default 8080 8080

render service-port-80 --set service.port=80
expect_ports service-port-80 80 8080

config_with_bind_addr ":9090" listen-9090
render listen-9090 --values "$tmp_dir/config-listen-9090.yaml"
expect_ports listen-9090 8080 9090

config_with_bind_addr "0.0.0.0:9443" listen-host
render listen-host --values "$tmp_dir/config-listen-host.yaml" --set service.port=443
expect_ports listen-host 443 9443

config_with_bind_addr ":http" named-port
expect_template_failure named-port "http.bind_addr" --values "$tmp_dir/config-named-port.yaml"

config_with_bind_addr ":0" zero-port
expect_template_failure zero-port "http.bind_addr" --values "$tmp_dir/config-zero-port.yaml"

echo "Server Helm chart checks passed."
