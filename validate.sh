#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_SLUG="${PROJECT_SLUG:-edge-stack}"
CONFIG_DIR="${IAC_CONFIG_DIR:-${HOME}/.config/${PROJECT_SLUG}}"
INV="${CONFIG_DIR}/ansible/hosts.ini"
if [ ! -f "$INV" ]; then
  INV="$ROOT_DIR/ansible/inventory/hosts.ini"
fi
export ANSIBLE_CONFIG="$ROOT_DIR/ansible.cfg"

if ! command -v ansible >/dev/null 2>&1; then
  echo "ansible not found"
  exit 1
fi

if ! grep -qE "^[^#].*ansible_host=" "$INV"; then
  echo "No hosts found in inventory."
  exit 0
fi

has_group() {
  local group="[$1]"
  awk -v group="$group" '
    BEGIN { found = 0 }
    /^[[:space:]]*#/ { next }
    /^\[/ { found = ($0 == group); next }
    found && NF { exit 0 }
    END { exit found ? 0 : 1 }
  ' "$INV"
}

run() {
  local host="$1"
  local cmd="$2"
  ansible "$host" -i "$INV" -m shell -a "$cmd"
}

run_group() {
  local group="$1"
  local cmd="$2"
  if ! has_group "$group"; then
    echo "skip: group $group not in inventory"
    return 0
  fi
  run "$group" "$cmd"
}

# Basic connectivity
run all "uname -a"

# WireGuard status
run_group onprem "systemctl is-active wg-quick@wg0 || true"
run_group onprem "systemctl is-active wg-quick@wg1 || true"
run_group vps "systemctl is-active wg-quick@wg0 || true"
run_group ec2 "systemctl is-active wg-quick@wg1 || true"

# WireGuard sanity (no double active)
run_group onprem "bash -lc 'a=$(systemctl is-active wg-quick@wg0 2>/dev/null || true); b=$(systemctl is-active wg-quick@wg1 2>/dev/null || true); echo wg0=\$a wg1=\$b; if [ \"\$a\" = active ] && [ \"\$b\" = active ]; then echo WARN: both wg0 and wg1 active; fi'"

# Service checks
run_group onprem "systemctl is-active failover_core.service || true"
run_group onprem "systemctl is-active docker.service apache2.service || true"
run_group onprem "test -f /opt/serveradmin/config/portal_services.json && echo portal_services.json: ok || echo portal_services.json: missing"
run_group vps "systemctl is-active cloudflared.service || true"
run_group vps "systemctl is-active suricata.service || true"
run_group vps "systemctl is-active frr.service || true"
run_group ec2 "systemctl is-active suricata.service || true"
run_group ec2 "systemctl is-active ssh.service || true"
run_group onprem "command -v vtysh >/dev/null 2>&1 && vtysh -c 'show bfd peers' || true"
run_group vps "command -v vtysh >/dev/null 2>&1 && vtysh -c 'show bfd peers' || true"

# DNS checks
run_group vps "grep -E '^nameserver' /etc/resolv.conf || true"
run_group vps "getent hosts cloudflare.com | head -n 1 || true"
run_group ec2 "getent hosts deb.debian.org | head -n 1 || true"

# Ports (sample)
run_group onprem "ss -tulpn | head -n 30"
run_group vps "ss -tulpn | head -n 30"
run_group ec2 "ss -tulpn | head -n 30"

echo "validate done"
