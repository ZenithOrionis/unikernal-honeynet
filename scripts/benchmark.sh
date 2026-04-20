#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

measure_ready() {
  local url="$1"
  local attempts="${2:-50}"
  local delay="${3:-0.2}"
  local start_ms
  local end_ms
  start_ms="$(date +%s%3N)"

  for _ in $(seq 1 "${attempts}"); do
    if curl --silent --output /dev/null --max-time 2 "${url}"; then
      end_ms="$(date +%s%3N)"
      echo $((end_ms - start_ms))
      return 0
    fi
    sleep "${delay}"
  done

  echo "timeout"
}

echo "==> Readiness checks"
echo "Unikernel router ready in: $(measure_ready 'http://localhost:8081') ms"
echo "Docker baseline ready in: $(measure_ready 'http://localhost:8090') ms"

echo
echo "==> Reset timing"
reset_start="$(date +%s%3N)"
"${SCRIPT_DIR}/reset_instances.sh" >/dev/null
reset_ready="$(measure_ready 'http://localhost:8081' 80 0.25)"
if [[ "${reset_ready}" == "timeout" ]]; then
  echo "Reset result: timeout waiting for router decoy"
else
  reset_end="$(date +%s%3N)"
  echo "Reset workflow completed in $((reset_end - reset_start)) ms"
  echo "Router became reachable after ${reset_ready} ms"
fi

echo
echo "==> Memory hints"
if command -v docker >/dev/null 2>&1; then
  docker stats --no-stream honeynet-baseline || true
fi

ps -eo pid,rss,comm,args | grep -E 'qemu-system|firecracker' | grep -v grep || true

echo
echo "Interpret the output as a quick demo aid, not as a rigorous benchmark harness."

