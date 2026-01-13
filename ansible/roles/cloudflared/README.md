# cloudflared

Installs Cloudflared (optional), deploys config/credentials, and optionally manages the service.

## Variables

- `cloudflared_manage` (default: false)
- `cloudflared_require_vars` (default: false)
- `cloudflared_install_if_missing` (default: false)
- `cloudflared_allow_overwrite` (default: false)
- `cloudflared_restart_on_change` (default: false)
- `cloudflared_manage_service` (default: false)

Config payloads:
- `cloudflared_config_content`
- `cloudflared_credentials_path` / `cloudflared_credentials_content`
- `cloudflared_cert_path` / `cloudflared_cert_content`

## Notes

- Keep restart disabled until you are ready to cut over.
- Store host-specific configs in `host_vars` (use Vault if needed).
