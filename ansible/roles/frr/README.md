# frr

Installs FRR (optional), deploys `frr.conf` and `daemons`, and optionally manages the service.

## Variables

- `frr_manage` (default: false)
- `frr_require_vars` (default: false)
- `frr_install_if_missing` (default: true)
- `frr_allow_overwrite` (default: false)
- `frr_restart_on_change` (default: false)
- `frr_manage_service` (default: false)
- `frr_generate_config` (default: false)

Config payloads:
- `frr_config_content`
- `frr_daemons_content`
Optional auto-generation:
- `frr_hostname` (default: inventory hostname)
- `frr_log` (default: syslog informational)
- `frr_bfd_peers` (list of peer IPs)
- `frr_bfd_interface` (default: wg0)
- `frr_bfd_min_rx` / `frr_bfd_min_tx` (default: 300)
- `frr_bfd_multiplier` (default: 3)

## Notes

- Keep restart disabled until you are ready to cut over.
- Store host-specific configs in `host_vars` (use Vault if needed).
- If you set `frr_generate_config: true`, the role writes a minimal BFD-only
  `frr.conf` and `daemons` based on the peer list.
