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

default_gateway() {
  ip route show default 0.0.0.0/0 2>/dev/null | awk '/default/ {print $3; exit}'
}

default_interface() {
  ip route show default 0.0.0.0/0 2>/dev/null | awk '/default/ {print $5; exit}'
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

post_up_lines=()
post_down_lines=()
if [[ "$peer_allowed" == *"0.0.0.0/0"* ]]; then
  endpoint_host="${peer_endpoint%:*}"
  endpoint_ip=""
  if [[ "$endpoint_host" =~ ^[0-9.]+$ ]]; then
    endpoint_ip="$endpoint_host"
  fi
  endpoint_ip="$(prompt "Endpoint IP for policy route (optional)" "$endpoint_ip")"
  if [ -n "$endpoint_ip" ]; then
    gw="$(default_gateway)"
    iface="$(default_interface)"
    if [ -z "$gw" ]; then
      gw="$(prompt "Default gateway" "")"
    fi
    if [ -z "$iface" ]; then
      iface="$(prompt "Default interface" "")"
    fi
    table_id="$(prompt "Policy route table ID" "51821")"
    if [ -n "$gw" ] && [ -n "$iface" ]; then
      post_up_lines+=("ip route add ${endpoint_ip}/32 via ${gw} dev ${iface} table ${table_id}")
      post_down_lines+=("ip route del ${endpoint_ip}/32 via ${gw} dev ${iface} table ${table_id}")
    fi
  fi
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
if [ "${#post_up_lines[@]}" -gt 0 ]; then
  for line in "${post_up_lines[@]}"; do
    echo "      PostUp = ${line}"
  done
fi
if [ "${#post_down_lines[@]}" -gt 0 ]; then
  for line in "${post_down_lines[@]}"; do
    echo "      PostDown = ${line}"
  done
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
