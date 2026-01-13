#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_SLUG="${PROJECT_SLUG:-edge-stack}"
CONFIG_DIR="${IAC_CONFIG_DIR:-${HOME}/.config/${PROJECT_SLUG}}"
VAULT_PASS="${IAC_VAULT_PASS:-${CONFIG_DIR}/vault_pass}"
ANSIBLE_DIR="${CONFIG_DIR}/ansible"
TF_DIR="${CONFIG_DIR}/terraform"
TF_CF_DIR="${CONFIG_DIR}/terraform-cloudflare"

info() {
  printf "[%s] %s\n" "INFO" "$*"
}

warn() {
  printf "[%s] %s\n" "WARN" "$*" >&2
}

ensure_dir() {
  local dir="$1"
  if [ ! -d "$dir" ]; then
    mkdir -p "$dir"
    chmod 700 "$dir" || true
  fi
}

copy_if_missing() {
  local src="$1"
  local dest="$2"
  if [ -f "$dest" ]; then
    return 0
  fi
  if [ ! -f "$src" ]; then
    warn "Missing example file: $src"
    return 1
  fi
  cp "$src" "$dest"
  info "Created: $dest"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

info "Bootstrap: ${PROJECT_SLUG}"
info "Repo: $ROOT_DIR"

missing=()
for cmd in python3 ansible ansible-playbook ansible-vault ssh ssh-keyscan; do
  if ! has_cmd "$cmd"; then
    missing+=("$cmd")
  fi
done

if [ "${#missing[@]}" -gt 0 ]; then
  warn "Missing tools: ${missing[*]}"
fi

if ! has_cmd terraform; then
  warn "Terraform not found (optional, required for EC2/Cloudflare provisioning)."
fi

ensure_dir "$CONFIG_DIR"
ensure_dir "$ANSIBLE_DIR"
ensure_dir "$ANSIBLE_DIR/host_vars"
ensure_dir "$ANSIBLE_DIR/group_vars"
ensure_dir "$TF_DIR"
ensure_dir "$TF_CF_DIR"

if [ ! -f "$VAULT_PASS" ]; then
  warn "Vault password file not found: $VAULT_PASS"
  warn "Create it with:"
  warn "  printf '%s\n' 'YOUR_VAULT_PASSWORD' > $VAULT_PASS && chmod 600 $VAULT_PASS"
fi

copy_if_missing "$ROOT_DIR/ansible/inventory/hosts.ini.example" "$ANSIBLE_DIR/hosts.ini"
copy_if_missing "$ROOT_DIR/ansible/group_vars/all.yml" "$ANSIBLE_DIR/group_vars/all.yml"
copy_if_missing "$ROOT_DIR/terraform/terraform.tfvars.example" "$TF_DIR/terraform.tfvars"
copy_if_missing "$ROOT_DIR/terraform-cloudflare/terraform.tfvars.example" "$TF_CF_DIR/terraform.tfvars"

for host in onprem-1 vps-1 ec2-1; do
  target="$ANSIBLE_DIR/host_vars/${host}.yml"
  example="$ROOT_DIR/ansible/host_vars/${host}.yml.example"
  if [ -f "$target" ]; then
    continue
  fi
  if [ ! -f "$example" ]; then
    warn "Missing example vault file: $example"
    continue
  fi
  if [ ! -f "$VAULT_PASS" ]; then
    warn "Skip vault create for $host (vault password missing)."
    continue
  fi
  if ! has_cmd ansible-vault; then
    warn "Skip vault create for $host (ansible-vault missing)."
    continue
  fi
  tmp="$(mktemp)"
  cp "$example" "$tmp"
  ANSIBLE_VAULT_PASSWORD_FILE="$VAULT_PASS" ansible-vault encrypt "$tmp" --output "$target" >/dev/null
  rm -f "$tmp"
  info "Created vault file: $target"
  chmod 600 "$target" || true

done

info "Bootstrap complete."
info "Next steps:"
info "  - Review ${ANSIBLE_DIR}/hosts.ini and terraform tfvars files"
info "  - Fill vault files with secrets (ansible-vault edit ...)"
info "  - Run: make validate"
