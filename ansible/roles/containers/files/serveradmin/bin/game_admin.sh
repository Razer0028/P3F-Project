#!/bin/bash
set -euo pipefail

ACTION="${1:-}"
GAME="${2:-}"
shift 2 || true

MAX_BYTES=524288
CONFIG_PATH="/opt/serveradmin/config/portal_services.json"

declare -A CONTAINERS=(
  ["minecraft"]="minecraft_server"
  ["valheim"]="valheim_server"
  ["7dtd"]="7dtd-server"
)

declare -A CONFIG_PATHS=(
  ["minecraft:server.properties"]="{{ containers_root }}/minecraft/data/server.properties"
  ["minecraft:whitelist.json"]="{{ containers_root }}/minecraft/data/whitelist.json"
  ["minecraft:ops.json"]="{{ containers_root }}/minecraft/data/ops.json"
  ["minecraft:banned-players.json"]="{{ containers_root }}/minecraft/data/banned-players.json"
  ["minecraft:banned-ips.json"]="{{ containers_root }}/minecraft/data/banned-ips.json"
  ["valheim:adminlist.txt"]="{{ containers_root }}/valheim_server/data/saves/adminlist.txt"
  ["valheim:permittedlist.txt"]="{{ containers_root }}/valheim_server/data/saves/permittedlist.txt"
  ["valheim:bannedlist.txt"]="{{ containers_root }}/valheim_server/data/saves/bannedlist.txt"
  ["7dtd:serverconfig.xml"]="{{ containers_root }}/7dtd_server/serverfiles/serverconfig.xml"
  ["7dtd:serveradmin.xml"]="{{ containers_root }}/7dtd_server/data/home/.local/share/7DaysToDie/Saves/serveradmin.xml"
)

die() {
  echo "ERR: $*" >&2
  exit 1
}

ensure_game_enabled() {
  [ -n "$GAME" ] || die "game is required"
  if [ -r "$CONFIG_PATH" ]; then
    if ! python3 - "$CONFIG_PATH" "$GAME" <<'PY'
import json
import sys

path = sys.argv[1]
game = sys.argv[2]
try:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except Exception:
    sys.exit(0)

enabled = data.get("enabled", [])
services = data.get("services", {})
if not isinstance(enabled, list) or not isinstance(services, dict):
    sys.exit(0)

if game not in enabled:
    sys.exit(1)

service = services.get(game, {})
if not isinstance(service, dict) or service.get("type") != "game":
    sys.exit(1)
PY
    then
      die "game is disabled: $GAME"
    fi
  fi
}

container_running() {
  local name="$1"
  /usr/bin/docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -q true
}

clean_cmd() {
  printf '%s' "$1" | tr -d '\r\n'
}

cmd_minecraft() {
  local cmd="$1"
  local props="{{ containers_root }}/minecraft/data/server.properties"
  [ -r "$props" ] || die "server.properties not found"

  local enabled pass port
  enabled="$(grep -E '^enable-rcon=' "$props" | tail -n 1 | cut -d= -f2- | tr -d '\r' || true)"
  pass="$(grep -E '^rcon.password=' "$props" | tail -n 1 | cut -d= -f2- | tr -d '\r' || true)"
  port="$(grep -E '^rcon.port=' "$props" | tail -n 1 | cut -d= -f2- | tr -d '\r' || true)"

  [ "$enabled" = "true" ] || die "rcon is disabled (enable-rcon=false)"
  [ -n "$pass" ] || die "rcon password is empty"
  [ -n "$port" ] || port="25575"

  local host="${RCON_HOST:-host.docker.internal}"

  python3 - "$host" "$port" "$pass" "$cmd" <<'PY'
import random
import socket
import struct
import sys

host = sys.argv[1]
port = int(sys.argv[2])
password = sys.argv[3]
command = sys.argv[4]

def send_packet(sock, req_id, pkt_type, payload):
    data = struct.pack("<ii", req_id, pkt_type) + payload.encode("utf-8") + b"\x00\x00"
    sock.sendall(struct.pack("<i", len(data)) + data)

def recv_packet(sock):
    header = sock.recv(4)
    if not header:
        return None
    length = struct.unpack("<i", header)[0]
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            break
        buf += chunk
    if len(buf) < 8:
        return None
    req_id, pkt_type = struct.unpack("<ii", buf[:8])
    payload = buf[8:-2].decode("utf-8", errors="replace")
    return req_id, pkt_type, payload

sock = socket.create_connection((host, port), timeout=2)
req_id = random.randint(1, 2**31 - 1)

send_packet(sock, req_id, 3, password)
resp = recv_packet(sock)
if resp is None:
    print("ERR: no auth response", file=sys.stderr)
    sys.exit(1)
if resp[0] != req_id:
    resp2 = recv_packet(sock)
    if resp2 is not None:
        resp = resp2
if resp[0] == -1:
    print("ERR: rcon auth failed", file=sys.stderr)
    sys.exit(1)

send_packet(sock, req_id, 2, command)
parts = []
while True:
    resp = recv_packet(sock)
    if resp is None:
        break
    if resp[0] != req_id:
        continue
    parts.append(resp[2])
    if len(resp[2]) < 4096:
        break

print("".join(parts).strip())
PY
}

cmd_7dtd() {
  local cmd="$1"
  local container="${CONTAINERS[$GAME]}"
  container_running "$container" || die "container is not running"
  /usr/bin/docker exec -e CMD="$cmd" "$container" /bin/bash -lc '
    cmd="${CMD//$'\''\r'\''/}"
    cmd="${cmd//$'\''\n'\''/}"
    [ -n "$cmd" ] || exit 2
    exec 3<>/dev/tcp/127.0.0.1/8081
    printf "%s\r\n" "$cmd" >&3
    sleep 0.2
    timeout 2 cat <&3 | head -c 4000 || true
  '
}

config_path() {
  local key="$1"
  local full="${GAME}:${key}"
  local path="${CONFIG_PATHS[$full]:-}"
  [ -n "$path" ] || die "config not allowed: ${full}"
  printf '%s' "$path"
}

config_get() {
  local key="$1"
  local path
  path="$(config_path "$key")"
  [ -r "$path" ] || die "config not readable: $path"
  cat "$path"
}

config_set() {
  local key="$1"
  local path
  path="$(config_path "$key")"
  local dir
  dir="$(dirname "$path")"
  mkdir -p "$dir"

  local tmp
  tmp="$(mktemp)"
  cat > "$tmp"
  local size
  size="$(wc -c < "$tmp" | tr -d ' ')"
  if [ "$size" -gt "$MAX_BYTES" ]; then
    rm -f "$tmp"
    die "config too large (${size} bytes)"
  fi

  local mode=""
  local owner=""
  if [ -e "$path" ]; then
    mode="$(stat -c %a "$path" 2>/dev/null || echo '')"
    owner="$(stat -c %u:%g "$path" 2>/dev/null || echo '')"
    cp -a "$path" "${path}.bak_$(date +%Y%m%d_%H%M%S)" || true
  fi

  mv "$tmp" "$path"
  [ -n "$mode" ] && chmod "$mode" "$path" || true
  [ -n "$owner" ] && chown "$owner" "$path" || true

  echo "OK"
}

case "$ACTION" in
  cmd)
    ensure_game_enabled
    cmd_raw="$*"
    cmd="$(clean_cmd "$cmd_raw")"
    [ -n "$cmd" ] || die "command is empty"
    [ "${#cmd}" -le 256 ] || die "command too long"
    case "$GAME" in
      minecraft) cmd_minecraft "$cmd" ;;
      7dtd) cmd_7dtd "$cmd" ;;
      valheim) die "valheim console is not available" ;;
      *) die "unknown game: $GAME" ;;
    esac
    ;;
  config-get)
    ensure_game_enabled
    key="${1:-}"
    [ -n "$key" ] || die "config key is required"
    config_get "$key"
    ;;
  config-set)
    ensure_game_enabled
    key="${1:-}"
    [ -n "$key" ] || die "config key is required"
    config_set "$key"
    ;;
  *)
    die "usage: $0 {cmd <game> <command>|config-get <game> <key>|config-set <game> <key>}"
    ;;
esac
