#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Stopping and removing existing honeynet unikernel instances"
for name in uk-router uk-nvr uk-admin; do
  kraft stop "${name}" >/dev/null 2>&1 || true
  kraft remove "${name}" >/dev/null 2>&1 || true
done

echo "==> Relaunching clean copies"
"${SCRIPT_DIR}/launch_instances.sh"

