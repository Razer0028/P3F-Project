# suricata

Installs Suricata (optional), deploys `suricata.yaml` (optional) and custom rules, and optionally manages the service.

## Variables

- `suricata_manage` (default: false)
- `suricata_require_vars` (default: false)
- `suricata_install_if_missing` (default: true)
- `suricata_allow_overwrite` (default: false)
- `suricata_restart_on_change` (default: false)
- `suricata_manage_service` (default: false)

Config payloads:
- `suricata_yaml_content` (optional)
- `suricata_custom_rules_content` (required if `suricata_require_vars: true`)

## Notes

- Set `suricata_yaml_manage: true` only if you intend to manage the full config.
- Keep restart disabled until you are ready to cut over.
- Store host-specific configs in `host_vars` (use Vault if needed).
