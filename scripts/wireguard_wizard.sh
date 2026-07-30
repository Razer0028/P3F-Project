#!/usr/bin/env bash
set -euo pipefail

if ! command -v wg >/dev/null 2>&1; then
  echo "wireguard-tools（wg コマンド）が必要です。" >&2
  echo "インストール: apt install wireguard-tools（Debian/Ubuntu）" >&2
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

iface_name="$(prompt "インターフェース名" "wg0")"
iface_address="$(prompt "インターフェースのアドレス" "10.100.0.2/32")"
listen_port="$(prompt "待ち受けポート（任意）" "")"
dns_value="$(prompt "DNS（任意）" "")"
peer_public="$(prompt "ピアの公開鍵" "")"
peer_allowed="$(prompt "ピアの AllowedIPs" "0.0.0.0/0")"
peer_endpoint="$(prompt "ピアのエンドポイント host:port（任意）" "")"
peer_keepalive="$(prompt "PersistentKeepalive（任意）" "25")"

if [ -z "$peer_public" ]; then
  peer_public="REPLACE_ME"
  echo "WARN: ピアの公開鍵が空のため REPLACE_ME を使用します。" >&2
fi

private_key="$(wg genkey)"
public_key="$(printf "%s" "$private_key" | wg pubkey)"

echo ""
echo "# 公開鍵（ピアに共有してください）"
echo "$public_key"
echo ""
echo "# Vault スニペット（~/.config/edge-stack/ansible/host_vars/<host>.yml に貼り付けてください）"
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
