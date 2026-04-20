#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
APP_DIR="${ROOT_DIR}/unikernel-decoy"

COLLECTOR_URL="${COLLECTOR_URL:-http://10.0.2.2:5000/event}"
DETACH="${DETACH:-1}"
DISABLE_ACCELERATION="${DISABLE_ACCELERATION:-0}"

RUN_FLAGS=(--plat qemu --arch x86_64 --rm)
if [[ "${DETACH}" == "1" ]]; then
  RUN_FLAGS+=(-d)
fi
if [[ "${DISABLE_ACCELERATION}" == "1" ]]; then
  RUN_FLAGS+=(-W)
fi

remove_if_present() {
  local name="$1"
  kraft remove "${name}" >/dev/null 2>&1 || true
}

launch_instance() {
  local name="$1"
  local host_port="$2"
  local profile="$3"
  local title="$4"
  local hostname="$5"
  local label="$6"

  remove_if_present "${name}"

  echo "==> Launching ${name} on localhost:${host_port}"
  kraft run "${RUN_FLAGS[@]}" \
    --name "${name}" \
    --prefix-name \
    -p "${host_port}:80" \
    -e "DECOY_PROFILE=${profile}" \
    -e "DECOY_ID=${hostname}" \
    -e "DECOY_TITLE=${title}" \
    -e "DECOY_HOSTNAME=${hostname}" \
    -e "DECOY_LABEL=${label}" \
    -e "COLLECTOR_URL=${COLLECTOR_URL}" \
    "${APP_DIR}"
}

echo "==> Using collector endpoint ${COLLECTOR_URL}"

launch_instance "uk-router" "8081" "router" "EdgeRouter X" "gw-core-01" "WAN routing node"
launch_instance "uk-nvr" "8082" "nvr" "SecureVision NVR" "cam-admin-02" "CCTV storage controller"
launch_instance "uk-admin" "8083" "admin" "Internal Control Panel" "ops-panel-03" "Enterprise operations portal"

echo
echo "Instances should now be reachable at:"
echo "  http://localhost:8081"
echo "  http://localhost:8082"
echo "  http://localhost:8083"
echo
echo "Use 'kraft ps -a' to inspect runtime state."

