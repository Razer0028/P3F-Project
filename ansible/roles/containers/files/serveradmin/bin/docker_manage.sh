#!/bin/bash
# /opt/serveradmin/bin/docker_manage.sh
#
# 役割:
#   - コンテナ状態の集約(JSON出力)
#   - コンテナの start / stop / build / delete
#   - 操作ログの記録
#
# 使い方:
#   docker_manage.sh status
#   docker_manage.sh start  <container> <user_email>
#   docker_manage.sh stop   <container> <user_email>
#   docker_manage.sh build  <container> <user_email>
#   docker_manage.sh delete <container> <user_email>

LOGFILE="/opt/serveradmin/logs/web_actions.log"

CONFIG_PATH="/opt/serveradmin/config/portal_services.json"
DEFAULT_CONTAINERS=("minecraft_server" "valheim_server" "7dtd-server")
ALLOWED_CONTAINERS=()

declare -A COMPOSE_DIRS

action="$1"
container="$2"
who="$3"

default_compose_dir() {
    case "$1" in
        minecraft_server) echo "{{ containers_root }}/minecraft";;
        valheim_server) echo "{{ containers_root }}/valheim_server";;
        7dtd-server) echo "{{ containers_root }}/7dtd_server";;
        web_portal) echo "{{ containers_root }}/web";;
        player_monitor) echo "{{ containers_root }}/monitor";;
        *) echo "";;
    esac
}

compose_dir_for() {
    local name="$1"
    if [ -n "${COMPOSE_DIRS[$name]:-}" ]; then
        echo "${COMPOSE_DIRS[$name]}"
        return 0
    fi
    default_compose_dir "$name"
}

is_allowed() {
    local name="$1"
    for c in "${ALLOWED_CONTAINERS[@]}"; do
        if [ "$c" = "$name" ]; then
            return 0
        fi
    done
    return 1
}

is_known() {
    local dir
    dir="$(compose_dir_for "$1")"
    [ -n "$dir" ]
}

load_allowed_containers() {
    if [ -r "$CONFIG_PATH" ]; then
        mapfile -t ALLOWED_CONTAINERS < <(
            python3 - "$CONFIG_PATH" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except Exception:
    sys.exit(0)

enabled = data.get("enabled", [])
services = data.get("services", {})
if not isinstance(enabled, list) or not isinstance(services, dict):
    sys.exit(0)

for service_id in enabled:
    service = services.get(service_id, {})
    if not isinstance(service, dict):
        continue
    name = service.get("container")
    if isinstance(name, str) and name:
        print(name)
PY
        )

        while IFS='|' read -r name dir; do
            if [ -n "$name" ] && [ -n "$dir" ]; then
                COMPOSE_DIRS["$name"]="$dir"
            fi
        done < <(
            python3 - "$CONFIG_PATH" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except Exception:
    sys.exit(0)

services = data.get("services", {})
if not isinstance(services, dict):
    sys.exit(0)

for service in services.values():
    if not isinstance(service, dict):
        continue
    name = service.get("container")
    compose_dir = service.get("compose_dir")
    if isinstance(name, str) and name and isinstance(compose_dir, str) and compose_dir:
        print(f"{name}|{compose_dir}")
PY
        )
    fi

    if [ ${#ALLOWED_CONTAINERS[@]} -eq 0 ]; then
        ALLOWED_CONTAINERS=("${DEFAULT_CONTAINERS[@]}")
    fi
}

load_allowed_containers

case "$action" in
  status)
    # 各コンテナの稼働状態と docker ps のステータステキストをJSONで返す
    # PHP側はこれを json_decode する
    echo "{"
    first=1
    for c in "${ALLOWED_CONTAINERS[@]}"; do
        st=$(docker ps --filter "name=^/${c}$" --format '{{.Status}}')

        if [ -z "$st" ]; then
            state="stopped"
            detail=""
        else
            state="running"
            detail="$st"
        fi

        # ダブルクォートを最低限エスケープ
        safe_detail=$(echo "$detail" | sed 's/"/\\"/g')

        if [ $first -eq 0 ]; then
            echo ","
        fi
        first=0

        echo "  \"${c}\": { \"state\": \"${state}\", \"detail\": \"${safe_detail}\" }"
    done
    echo "}"
    exit 0
    ;;

  start)
    if ! is_allowed "$container"; then
        echo "DENY: $container is not allowed"
        exit 1
    fi

    if /usr/bin/docker inspect "$container" >/dev/null 2>&1; then
        /usr/bin/docker start "$container" >/tmp/docker_manage_tmp 2>&1
        code=$?
        action_label="START"
    else
        if ! is_known "$container"; then
            echo "DENY: $container is not known"
            exit 1
        fi
        compose_dir="$(compose_dir_for "$container")"
        if [ -z "$compose_dir" ] || [ ! -d "$compose_dir" ]; then
            echo "DENY: compose dir not found for $container"
            exit 1
        fi
        (cd "$compose_dir" && /usr/bin/docker compose up -d --build) >/tmp/docker_manage_tmp 2>&1
        code=$?
        action_label="UP"
    fi

    ts=$(date +%F %T)
    echo "$ts [$who] $action_label $container code=$code" >> "$LOGFILE"

    cat /tmp/docker_manage_tmp
    exit $code
    ;;

  stop)
    if ! is_allowed "$container"; then
        echo "DENY: $container is not allowed"
        exit 1
    fi

    /usr/bin/docker stop "$container" >/tmp/docker_manage_tmp 2>&1
    code=$?

    ts=$(date '+%F %T')
    echo "$ts [$who] STOP $container code=$code" >> "$LOGFILE"

    cat /tmp/docker_manage_tmp
    exit $code
    ;;

  build)
    if ! is_known "$container"; then
        echo "DENY: $container is not known"
        exit 1
    fi

    compose_dir="$(compose_dir_for "$container")"
    if [ -z "$compose_dir" ] || [ ! -d "$compose_dir" ]; then
        echo "DENY: compose dir not found for $container"
        exit 1
    fi

    (cd "$compose_dir" && /usr/bin/docker compose build) >/tmp/docker_manage_tmp 2>&1
    code=$?

    ts=$(date '+%F %T')
    echo "$ts [$who] BUILD $container dir=$compose_dir code=$code" >> "$LOGFILE"

    cat /tmp/docker_manage_tmp
    exit $code
    ;;

  delete)
    if ! is_known "$container"; then
        echo "DENY: $container is not known"
        exit 1
    fi

    compose_dir="$(compose_dir_for "$container")"
    if [ -z "$compose_dir" ] || [ ! -d "$compose_dir" ]; then
        echo "DENY: compose dir not found for $container"
        exit 1
    fi

    (cd "$compose_dir" && /usr/bin/docker compose down --remove-orphans --rmi local) >/tmp/docker_manage_tmp 2>&1
    code=$?

    ts=$(date '+%F %T')
    echo "$ts [$who] DELETE $container dir=$compose_dir code=$code" >> "$LOGFILE"

    cat /tmp/docker_manage_tmp
    exit $code
    ;;

  *)
    echo "usage: $0 {status|start <container> <user>|stop <container> <user>|build <container> <user>|delete <container> <user>}"
    exit 1
    ;;
esac
