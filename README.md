# P3F-Project (edge-stack IaC)

IaC workspace for the on-prem + VPS + EC2 failover stack.

## What this repo covers

- On-prem (Debian 12): Docker workloads, Apache, failover_core, backups.
- VPS edge: WireGuard, FRR/BFD, Suricata (custom rules + DDoS notify), Cloudflared tunnel.
- EC2 edge: WireGuard, Suricata (no FRR).
- Cloudflare DNS updates via failover_core.
- NAS backups for full system and game data.

## Requirements

- Ansible (2.14+ recommended), Python3, ssh-agent.
- Terraform (1.5+) for EC2 provisioning (optional).
- SSH keys for on-prem, VPS, EC2 (stored under ~/.ssh on the portal host, usually /root/.ssh).

## Docs

- `docs/overview.md`: 構成概要/通信フロー
- `docs/credentials_guide.md`: Cloudflare/AWS 認証情報とドメイン準備
- `docs/operations.md`: 管理者ポータル/portctl/フェイルオーバー運用

## Public distribution notes

- Keep secrets local. Do not commit `~/.config/edge-stack/ansible/host_vars/*.yml` or `~/.config/edge-stack/ansible/hosts.ini`.
- Use example files as a starting point:
  - `ansible/inventory/hosts.ini.example`
  - `ansible/host_vars/onprem-1.yml.example`
  - `ansible/host_vars/vps-1.yml.example`
  - `ansible/host_vars/ec2-1.yml.example`
- Cloudflared tunnel setup guidance lives in `docs/cloudflared_setup.md`.

## Required inputs (before deploy)

- Hosts: on-prem/VPS/EC2 IPs, SSH users, SSH key names (files live in ~/.ssh, usually /root/.ssh).
- Cloudflare: account ID, zone name (YOUR_DOMAIN), API token via env.
- Terraform (EC2): aws_region, instance_type, key_name, allowed_ssh_cidrs, instance_name.
  - AMI: `ami_mode=manual` なら `ami_id`、`ami_mode=auto` なら `ami_owners` + `ami_name_filter`。
- Failover: failover_ec2_ip, failover_vps_ip, failover_dns_record_name.
- Notifications (optional): Discord webhook (shared for DDoS + portal notifications).
- WireGuard samples assume `10.100.0.0/24` (replace to fit your network).
- Admin allow CIDRs should include WG/LAN; empty list blocks admin access.
- LAN CIDRs are auto-detected on the portal host when checking status.
- BFD uses UDP 3784/3785 on wg0; ensure it is allowed on the VPS.
- Failback health uses TCP 18080 on the VPS; allow it (or restrict to your on-prem IP).

## Vault secrets (host_vars/*.yml)

- WireGuard private keys/configs.
- Cloudflared config + credentials JSON.
- Failover Cloudflare token / zone ID / record ID.
- Suricata rules (if custom).
- DDoS notify (VPS only): notify targets (uses the shared Discord webhook).
- Admin portal credentials (required).
- Failover AWS credentials default to profile default. If you want to keep Terraform/admin credentials separate, set failover_aws_profile to a dedicated name (e.g. failover).

## Public release checklist

- Keep `~/.config/edge-stack/ansible/host_vars/*.yml` and `~/.config/edge-stack/ansible/hosts.ini` out of git.
- Keep `~/.config/edge-stack/terraform/terraform.tfvars` and `~/.config/edge-stack/terraform-cloudflare/terraform.tfvars` out of git.
- Replace placeholder values (YOUR_*) before deploying.
- Review portal outputs to ensure no real IPs or secrets are shown.

## WireGuard helper (optional)

Generate keys and a Vault-ready snippet:

  ./scripts/wireguard_wizard.sh

## AWS IAM policy (Terraform)

Terraform needs additional EC2 read permissions to refresh state. Use a policy
like `docs/iam_terraform_policy.json`, or attach AmazonEC2ReadOnlyAccess plus
an EC2 write policy for create/destroy.

## Quick start (Ansible)

1) Run the interactive setup to generate inventory and base variables.

  ./setup.sh

2) Create a local vault password file (not committed).

  mkdir -p ~/.config/edge-stack
  chmod 700 ~/.config/edge-stack
  printf "%s\n" "YOUR_VAULT_PASSWORD" > ~/.config/edge-stack/vault_pass
  chmod 600 ~/.config/edge-stack/vault_pass

3) Add SSH host keys (host_key_checking is enabled).

  ssh-keyscan -H <onprem_ip> >> ~/.ssh/known_hosts
  ssh-keyscan -H <vps_ip> >> ~/.ssh/known_hosts
  ssh-keyscan -H <ec2_ip> >> ~/.ssh/known_hosts

4) Put secrets in Ansible Vault files (per-host).

  ansible-vault edit ~/.config/edge-stack/ansible/host_vars/onprem-1.yml
  ansible-vault edit ~/.config/edge-stack/ansible/host_vars/vps-1.yml
  ansible-vault edit ~/.config/edge-stack/ansible/host_vars/ec2-1.yml

5) Apply safely with tags (examples).

  ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini ansible/site.yml -l vps --tags base
  ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini ansible/site.yml -l vps --tags cloudflared \
    -e cloudflared_allow_overwrite=true -e cloudflared_restart_on_change=true -e cloudflared_manage_service=true

6) Validate.

  make validate

Notes:
- Vault password file: `~/.config/edge-stack/vault_pass` (or set `ANSIBLE_VAULT_PASSWORD_FILE`).
- WireGuard wg0/wg1 should not be active at the same time. The failover_core script enforces this.
- Credentials guide (JP): `docs/credentials_guide.md`

## One-command workflows

- Full deploy (Terraform + Ansible all hosts):
  make deploy

- Destroy EC2 resources created by Terraform:
  make destroy

- Targeted deploys:
  make deploy-onprem
  make deploy-vps
  make deploy-ec2

## Required host variables (examples)

These live in ~/.config/edge-stack/ansible/host_vars/*.yml and are encrypted with Ansible Vault.

- WireGuard (on-prem, VPS, EC2)
  - wireguard_raw_configs or wireguard_configs
  - wireguard_primary (optional)

- FRR (VPS + on-prem for BFD)
  - Use `frr_generate_config: true` plus `frr_bfd_peers` and `frr_bfd_interface`, or
  - Provide `frr_config_content` and `frr_daemons_content` manually.

- Suricata (VPS, EC2)
  - suricata_custom_rules_content
  - suricata_custom_rules_path

- Cloudflared (VPS)
  - cloudflared_config_content
  - cloudflared_credentials_path
  - cloudflared_credentials_content

- Failover core (on-prem)
  - failover_instance_id
  - failover_region
  - failover_ec2_ip
  - failover_cf_token
  - failover_cf_zone_id
  - failover_cf_record_id
  - failover_dns_record_name
  - failover_vps_ip
  - failover_auto_failback ("yes" or "no")
  - failover_failback_request_file
  - failover_core_state (started/stopped)
  - failover_core_enable (true/false)

## Failover core behavior

- Auto-failback is controlled by failover_auto_failback.
- Manual failback uses failover_failback_request_file; create the file to request failback.
- Failover triggers on BFD down; failback checks the VPS health endpoint (port 18080).
- On startup, the script reconciles wg0/wg1 and routes to VPS when startup force is enabled.

## Backups

- Full backup is optional (backup_full_enabled).
- Game data backup runs hourly by default (backup_games_cron).
- Adjust backup paths in ~/.config/edge-stack/ansible/group_vars/all.yml.

## Terraform (EC2 skeleton)

The terraform/ directory contains a minimal EC2 stack that creates a VPC
(auto or custom CIDR), a public subnet with IGW + route table, a security
group, optional EIP, and an optional KeyPair from a public key.

  cd terraform
  terraform init
  terraform plan -var-file=~/.config/edge-stack/terraform/terraform.tfvars
  terraform apply -var-file=~/.config/edge-stack/terraform/terraform.tfvars

Notes:
- `~/.config/edge-stack/terraform/terraform.tfvars` is local-only and should not be committed.
- Set `source_dest_check = false` if the EC2 instance needs to forward traffic.

VPS provisioning is manual by design; use Ansible to configure it.

## Common commands

- make bootstrap
- make validate
- make tf-init
- make tf-plan
- make tf-apply
- make tf-destroy

## Local setup portal

An optional local/LAN portal can generate inventory files, run allowed tasks,
and upload SSH keys. It runs with a token printed in the terminal (required for
uploads and task execution).

  make portal

LAN access (binds to 0.0.0.0):

  make portal-lan

Portal actions are whitelisted (Terraform/Ansible/Validate). Destructive actions
require a confirm word. If you do not need the portal after setup, delete `portal/`.
