#!/usr/bin/env bash
set -euo pipefail

if ! command -v wg >/dev/null 2>&1; then
  echo "wireguard-tools (wg) is required." >&2
  echo "Install: apt install wireguard-tools (Debian/Ubuntu)" >&2
  exit 1
fi

prompt() {
  local label="$1"
  local def="${2:-}"
  local val
  if [ -n "$def" ]; then
    read -r -p "$label [$def]: " val
    val="${val:-$def}"
  else
    read -r -p "$label: " val
  fi
  printf "%s" "$val"
}

iface_name="$(prompt "Interface name" "wg0")"
iface_address="$(prompt "Interface address" "10.100.0.2/32")"
listen_port="$(prompt "Listen port (optional)" "")"
dns_value="$(prompt "DNS (optional)" "")"
peer_public="$(prompt "Peer public key" "")"
peer_allowed="$(prompt "Peer AllowedIPs" "0.0.0.0/0")"
peer_endpoint="$(prompt "Peer endpoint host:port (optional)" "")"
peer_keepalive="$(prompt "PersistentKeepalive (optional)" "25")"

if [ -z "$peer_public" ]; then
  peer_public="REPLACE_ME"
  echo "WARN: peer public key is empty; using REPLACE_ME." >&2
fi

private_key="$(wg genkey)"
public_key="$(printf "%s" "$private_key" | wg pubkey)"

echo ""
echo "# Public key (share with peer)"
echo "$public_key"
echo ""
echo "# Vault snippet (paste into ~/.config/edge-stack/ansible/host_vars/<host>.yml)"
echo "wireguard_raw_configs:"
echo "  - name: \"${iface_name}\""
echo "    content: |"
echo "      [Interface]"
echo "      Address = ${iface_address}"
if [ -n "$listen_port" ]; then
  echo "      ListenPort = ${listen_port}"
fi
echo "      PrivateKey = ${private_key}"
if [ -n "$dns_value" ]; then
  echo "      DNS = ${dns_value}"
fi
echo ""
echo "      [Peer]"
echo "      PublicKey = ${peer_public}"
echo "      AllowedIPs = ${peer_allowed}"
if [ -n "$peer_endpoint" ]; then
  echo "      Endpoint = ${peer_endpoint}"
fi
if [ -n "$peer_keepalive" ]; then
  echo "      PersistentKeepalive = ${peer_keepalive}"
fi
