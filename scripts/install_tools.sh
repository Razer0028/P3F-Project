#!/usr/bin/env bash
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
  echo "apt-get not available. Please install tools manually." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

check_nameserver() {
  if ! grep -qE '^\s*nameserver\s+' /etc/resolv.conf 2>/dev/null; then
    echo "No nameserver entries found in /etc/resolv.conf." >&2
    return 1
  fi
  return 0
}

check_dns() {
  local host="$1"
  if ! getent ahosts "$host" >/dev/null 2>&1; then
    echo "DNS lookup failed for ${host}." >&2
    return 1
  fi
  return 0
}

if ! check_nameserver; then
  echo "Fix DNS (add a nameserver) and re-run this tool install." >&2
  exit 1
fi
if ! check_dns "deb.debian.org"; then
  echo "DNS resolution is failing. Fix /etc/resolv.conf or network settings and re-run." >&2
  exit 1
fi

required_packages=(
  ansible
  openssh-client
  python3
  python3-venv
  python3-pip
  wireguard
  wireguard-tools
  resolvconf
  curl
  gnupg
  lsb-release
  ca-certificates
)

apt-get update -y
apt-get install -y "${required_packages[@]}"

if ! command -v terraform >/dev/null 2>&1; then
  if ! check_dns "apt.releases.hashicorp.com"; then
    echo "DNS resolution failed for apt.releases.hashicorp.com. Fix DNS and re-run to install Terraform." >&2
    exit 1
  fi
  echo "Terraform not found. Adding HashiCorp repo..."
  install -m 0755 -d /usr/share/keyrings
  curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
  chmod 0644 /usr/share/keyrings/hashicorp-archive-keyring.gpg
  release=$(lsb_release -cs)
  echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com ${release} main" > /etc/apt/sources.list.d/hashicorp.list
  apt-get update -y
  apt-get install -y terraform
else
  echo "Terraform already installed."
fi

echo "Tool install complete."
