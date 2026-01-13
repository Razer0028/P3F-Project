# failover_core

Deploys the failover controller script and optional UDP DDoS receiver, then enables the systemd units.

## Variables

Required for real use:
- `failover_instance_id`
- `failover_ec2_ip`
- `failover_cf_token`
- `failover_cf_zone_id`
- `failover_cf_record_id`
- `failover_dns_record_name`
- `failover_vps_ip`

Key toggles:
- `failover_core_manage` (default: false)
- `failover_core_require_vars` (default: true)
- `failover_auto_failback` (default: "no")
- `failover_core_restart_on_change` (default: true)
- `failover_ddos_receiver_manage` (default: true)

## Behavior notes

- On startup, the controller checks VPS health and prefers the VPS route when possible.
- When `failover_auto_failback` is enabled, the controller enforces the VPS route whenever VPS is healthy.
- Manual failback can be triggered by creating the file defined in
  `failover_failback_request_file`.

## Notes

- Store secrets in `host_vars` or Ansible Vault, not in `group_vars`.
