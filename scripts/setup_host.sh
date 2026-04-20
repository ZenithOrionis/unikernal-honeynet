#!/usr/bin/env bash
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This setup script currently targets Debian/Ubuntu hosts."
  exit 1
fi

SUDO=""
if [[ "${EUID}" -ne 0 ]]; then
  SUDO="sudo"
fi

echo "==> Installing host dependencies"
$SUDO apt-get update
$SUDO apt-get install -y \
  ca-certificates \
  curl \
  git \
  jq \
  lsb-release \
  python3 \
  python3-pip \
  python3-venv \
  qemu-kvm \
  qemu-system-x86 \
  cpu-checker \
  sqlite3 \
  docker.io

if ! command -v kraft >/dev/null 2>&1; then
  echo "==> Installing KraftKit"
  curl --proto '=https' --tlsv1.2 -sSf https://get.kraftkit.sh | sh
else
  echo "==> KraftKit already installed"
fi

echo "==> Enabling Docker service"
$SUDO systemctl enable --now docker >/dev/null 2>&1 || true

echo "==> Ensuring local user can access docker and kvm"
$SUDO usermod -aG docker "${SUDO_USER:-$USER}" >/dev/null 2>&1 || true
$SUDO usermod -aG kvm "${SUDO_USER:-$USER}" >/dev/null 2>&1 || true

echo
echo "==> Host summary"
uname -a
echo
lscpu | sed -n '1,12p'
echo

echo "==> KVM check"
if command -v kvm-ok >/dev/null 2>&1; then
  $SUDO kvm-ok || true
elif [[ -e /dev/kvm ]]; then
  ls -l /dev/kvm
else
  echo "/dev/kvm not found"
fi
echo

echo "==> KraftKit version"
if command -v kraft >/dev/null 2>&1; then
  if ! kraft --version 2>/dev/null; then
    kraft version
  fi
else
  echo "kraft command was not found after installation"
fi

echo
echo "Setup complete. If docker or kvm group membership was just added, log out and back in before running the demo."
