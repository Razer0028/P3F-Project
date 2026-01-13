#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_SLUG="${PROJECT_SLUG:-edge-stack}"
CONFIG_DIR="${IAC_CONFIG_DIR:-${HOME}/.config/${PROJECT_SLUG}}"
ANSIBLE_DIR="${CONFIG_DIR}/ansible"
CONFIG="${ANSIBLE_DIR}/group_vars/all.yml"
INVENTORY="${ANSIBLE_DIR}/hosts.ini"

mkdir -p "${ANSIBLE_DIR}/group_vars"

prompt() {
  local var="$1"
  local msg="$2"
  local def="$3"
  local val
  if [ -n "$def" ]; then
    read -r -p "$msg [$def]: " val
    val="${val:-$def}"
  else
    read -r -p "$msg: " val
  fi
  printf "%s" "$val"
}

onprem_ip="$(prompt onprem_ip "On-prem IP (example: 192.0.2.10)" "")"
vps_ip="$(prompt vps_ip "VPS public IP (example: 198.51.100.10)" "")"
ec2_ip="$(prompt ec2_ip "EC2 public IP (example: 203.0.113.10)" "")"

onprem_user="$(prompt onprem_user "On-prem SSH user" root)"
vps_user="$(prompt vps_user "VPS SSH user" root)"
ec2_user="$(prompt ec2_user "EC2 SSH user" admin)"
project_name="$(prompt project_name "Project name" edge-stack)"

onprem_key_name="$(prompt onprem_key_name "On-prem SSH key name" onprem_ed25519)"
vps_key_name="$(prompt vps_key_name "VPS SSH key name" vps_ed25519)"
ec2_key_name="$(prompt ec2_key_name "EC2 SSH key name" ec2_key.pem)"

timezone="$(prompt timezone 'Timezone (example: Asia/Tokyo)' 'Asia/Tokyo')"

cat > "$INVENTORY" <<EOT2
[onprem]
onprem-1 ansible_host=$onprem_ip ansible_user=$onprem_user ansible_ssh_private_key_file=~/.ssh/$onprem_key_name

[vps]
vps-1 ansible_host=$vps_ip ansible_user=$vps_user ansible_ssh_private_key_file=~/.ssh/$vps_key_name

[ec2]
ec2-1 ansible_host=$ec2_ip ansible_user=$ec2_user ansible_ssh_private_key_file=~/.ssh/$ec2_key_name

[all:vars]
ansible_python_interpreter=/usr/bin/python3
EOT2

cat > "$CONFIG" <<EOT2
---
project_name: "$project_name"
timezone: "$timezone"

# WireGuard
wireguard_manage: false
wireguard_enable_on_boot: false
wireguard_restart_on_change: false
wireguard_allow_overwrite: false

# Backup
backups_manage: false
backup_full_enabled: false
backup_games_enabled: true
backup_games_cron: "0 * * * *"

nas_mount: "/mnt/nas"
backup_root: "/mnt/nas/backup"
backup_games_root: "/mnt/nas/backup_games"
backup_full_script: "/usr/local/sbin/backup_to_nas.sh"
backup_games_script: "/usr/local/sbin/backup_games_to_nas.sh"
backup_full_log: "/var/log/backup_rsync.log"
backup_games_log: "/var/log/backup_games_rsync.log"

# Admin portal
web_portal_admin_enable: true
web_portal_admin_allow_cidrs: []
web_portal_admin_deny_cidrs: []
EOT2

cat <<EOF

setup complete:
- $INVENTORY
- $CONFIG
EOF
