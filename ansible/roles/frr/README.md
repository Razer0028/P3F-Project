# frr

Installs FRR (optional), deploys `frr.conf` and `daemons`, and optionally manages the service.

## Variables

- `frr_manage` (default: false)
- `frr_require_vars` (default: false)
- `frr_install_if_missing` (default: true)
- `frr_allow_overwrite` (default: false)
- `frr_restart_on_change` (default: false)
- `frr_manage_service` (default: false)

Config payloads:
- `frr_config_content`
- `frr_daemons_content`

## Notes

- Keep restart disabled until you are ready to cut over.
- Store host-specific configs in `host_vars` (use Vault if needed).
