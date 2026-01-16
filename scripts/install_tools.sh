#!/usr/bin/env bash
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
  echo "apt-get not available. Please install tools manually." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

required_packages=(
  ansible
  openssh-client
  python3
  python3-venv
  python3-pip
  curl
  gnupg
  lsb-release
  ca-certificates
)

apt-get update -y
apt-get install -y "${required_packages[@]}"

if ! command -v terraform >/dev/null 2>&1; then
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
