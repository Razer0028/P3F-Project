# containers role

Deploys container build contexts and helper scripts for the edge-stack stack.

## Variables
- `containers_manage` (bool): enable this role.
- `containers_root` (string): base path for container directories. Default `/srv/edge-stack`.
- `containers_owner` (string): owner user for container directories. Default `edge`.
- `containers_group` (string): owner group for container directories. Default `edge`.
- `containers_manage_user` (bool): create/update containers owner/group. Default `true`.
- `containers_owner_uid` (int): UID for monitor container build (auto-detected).
- `containers_owner_gid` (int): GID for monitor container build (auto-detected).
- `containers_enabled` (list): which services to deploy (minecraft, valheim, 7dtd, web_portal, player_monitor).
- `containers_start` (bool): run `docker compose up -d --build` for enabled services.
- `web_portal_discord_webhook` (string): optional webhook to write into `web/.env`.
- `web_portal_admin_enable` (bool): enable `/admin` auth for the game server portal.
- `web_portal_admin_user` (string): admin login (store in Vault).
- `web_portal_admin_password` (string): admin password (store in Vault).
- `web_portal_admin_realm` (string): digest realm (default `admin-panel`).
- `web_portal_admin_allow_cidrs` (list): allowed CIDRs for `/admin` (default uses RFC 5737 example ranges).
- `web_portal_admin_deny_cidrs` (list): denied CIDRs for `/admin` (optional).
- `web_portal_admin_htdigest` (string): optional precomputed digest line (advanced/manual).

## Admin auth

## Game container archives
Game build contexts are stored as tar.gz under `ansible/roles/containers/files/archives/` and are extracted on deploy.
Recommended flow:
- Set `web_portal_admin_enable: true` in group vars.
- Store `web_portal_admin_user` and `web_portal_admin_password` in Vault (`~/.config/edge-stack/ansible/host_vars/onprem-1.yml`).

Advanced/manual flow:
- If you already have an htdigest line, keep `web_portal_admin_enable: false` and set `web_portal_admin_htdigest`.

To generate a digest line manually (local machine):

  htdigest -c /tmp/.htdigest admin-panel admin

Copy the single line from `/tmp/.htdigest` into your variables. An example file is at
`ansible/roles/containers/files/web_portal/admin/.htdigest.example`.

## Outputs
- `/opt/serveradmin/bin/{docker_manage.sh,game_admin.sh}`
- `/opt/serveradmin/scripts/player_monitor.py`
- `/opt/serveradmin/config/portal_services.json`
- `{{ containers_root }}/monitor/opt_serveradmin/*` mirror for the web portal mount.
