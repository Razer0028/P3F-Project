#!/bin/bash
set -e

MONITOR_USER="${MONITOR_USER:-edge}"

echo "[INFO] Setting up /run permissions..."
# cron が書き込めるようにする
mkdir -p /run
chmod 755 /run

echo "[INFO] Starting cron as root..."
cron

if [ -S /var/run/docker.sock ]; then
  sock_gid=$(stat -c %g /var/run/docker.sock || true)
  if [ -n "$sock_gid" ]; then
    if ! getent group "$sock_gid" >/dev/null; then
      groupadd -g "$sock_gid" docker-host || true
    fi
    group_name=$(getent group "$sock_gid" | cut -d: -f1)
    if [ -n "$group_name" ] && [ "$MONITOR_USER" != "root" ]; then
      usermod -aG "$group_name" "$MONITOR_USER" || true
    fi
  fi
fi

echo "[INFO] Dropping to ${MONITOR_USER} user..."
exec su "$MONITOR_USER" -c "python3 /opt/serveradmin/scripts/player_monitor.py"
