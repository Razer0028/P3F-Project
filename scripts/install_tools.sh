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

ensure_fallback_dns() {
  local head_dir="/etc/resolvconf/resolv.conf.d"
  local head_file="${head_dir}/head"
  if [ ! -d "${head_dir}" ]; then
    mkdir -p "${head_dir}"
  fi
  if ! grep -qE '^\s*nameserver\s+' "${head_file}" 2>/dev/null; then
    printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" >> "${head_file}"
  fi
  if command -v resolvconf >/dev/null 2>&1; then
    resolvconf -u || true
  fi
}

ensure_dns_or_exit() {
  local host="$1"
  if check_nameserver && check_dns "${host}"; then
    return 0
  fi
  echo "Attempting to apply fallback DNS..." >&2
  ensure_fallback_dns
  if check_nameserver && check_dns "${host}"; then
    return 0
  fi
  echo "DNS resolution is failing for ${host}. Fix /etc/resolv.conf or network settings and re-run." >&2
  exit 1
}

ensure_dns_or_exit "deb.debian.org"

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
  ensure_dns_or_exit "apt.releases.hashicorp.com"
  echo "Terraform not found. Adding HashiCorp repo..."
  install -m 0755 -d /usr/share/keyrings
  tmp_key=$(mktemp)
  curl_opts=(--fail --silent --show-error --location --retry 3 --retry-connrefused --connect-timeout 5 --max-time 20)
  if ! curl "${curl_opts[@]}" https://apt.releases.hashicorp.com/gpg -o "${tmp_key}"; then
    echo "Failed to download HashiCorp GPG key (network/DNS). Fix network and re-run." >&2
    rm -f "${tmp_key}"
    exit 1
  fi
  gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg "${tmp_key}"
  rm -f "${tmp_key}"
  chmod 0644 /usr/share/keyrings/hashicorp-archive-keyring.gpg
  release=$(lsb_release -cs)
  echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com ${release} main" > /etc/apt/sources.list.d/hashicorp.list
  apt-get update -y
  apt-get install -y terraform
else
  echo "Terraform already installed."
fi

echo "Tool install complete."
