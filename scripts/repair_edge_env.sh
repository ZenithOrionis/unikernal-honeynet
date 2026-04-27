#!/usr/bin/env bash
set -euo pipefail

set_runtime_settings() {
  local env_file="$1"
  local delay="$2"

  sed -i '/KRAFT_LOCK/d;/KRAFTKIT/d;/STARTUP_DELAY/d' "${env_file}"
  {
    printf '%s\n' 'KRAFT_LOCK_FILE=/run/honeynet-kraft.lock'
    printf '%s\n' 'KRAFT_LOCK_TIMEOUT_SECONDS=180'
    printf '%s\n' 'KRAFTKIT_NO_CHECK_UPDATES=true'
    printf 'STARTUP_DELAY_SECONDS=%s\n' "${delay}"
  } >> "${env_file}"
}

set_runtime_settings /etc/honeynet-decoy-router.env 0
set_runtime_settings /etc/honeynet-decoy-nvr.env 35
set_runtime_settings /etc/honeynet-decoy-admin.env 70
