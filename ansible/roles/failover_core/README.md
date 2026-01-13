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
- `failover_startup_force_vps` (default: true)
- `failover_bfd_require_up_once` (default: true)
- `failover_core_restart_on_change` (default: true)
- `failover_ddos_receiver_manage` (default: true)

## Behavior notes

- Failover is driven by BFD (down threshold).
- Failback checks the VPS health endpoint (port 18080).
- When wg1 is active, the controller keeps a route to the VPS health IP via the LAN default
  gateway so failback checks can succeed (controlled by `failover_vps_health_route_*`).
- On startup, the controller checks VPS health and prefers the VPS route when possible.
- When `failover_startup_force_vps` is true, it forces wg0 + DNS to the VPS at startup
  even if health checks are unavailable.
- When `failover_bfd_require_up_once` is true, failover waits until BFD has been "up"
  at least once to avoid switching during initial provisioning.
- When `failover_auto_failback` is enabled, the controller enforces the VPS route whenever VPS is healthy.
- Manual failback can be triggered by creating the file defined in
  `failover_failback_request_file`.

## Notes

- Store secrets in `host_vars` or Ansible Vault, not in `group_vars`.
