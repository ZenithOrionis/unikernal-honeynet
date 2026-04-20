#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
APP_DIR="${ROOT_DIR}/unikernel-decoy"
LOG_DIR="${ROOT_DIR}/logs"

mkdir -p "${LOG_DIR}"

ensure_buildkit() {
  if [[ -n "${KRAFTKIT_BUILDKIT_HOST:-}" ]]; then
    return
  fi

  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required to materialize the rootfs Dockerfile for the unikernel workload."
    exit 1
  fi

  if ! docker ps --format '{{.Names}}' | grep -qx 'buildkitd'; then
    if docker ps -a --format '{{.Names}}' | grep -qx 'buildkitd'; then
      docker start buildkitd >/dev/null
    else
      docker run -d --name buildkitd --privileged moby/buildkit:latest >/dev/null
    fi
  fi

  export KRAFTKIT_BUILDKIT_HOST="docker-container://buildkitd"
}

ensure_buildkit

BUILD_LOG="${LOG_DIR}/build-$(date +%Y%m%d-%H%M%S).log"

echo "==> Building unikernel workload from ${APP_DIR}"
echo "==> Build log: ${BUILD_LOG}"

cd "${APP_DIR}"
kraft build --plat qemu --arch x86_64 . 2>&1 | tee "${BUILD_LOG}"

echo "==> Build finished"

