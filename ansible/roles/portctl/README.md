# portctl

Deploys the VPS port forwarding portal (agent + web UI).

## Variables
- portctl_manage (default: false)
- portctl_manage_service (default: true)
- portctl_install_if_missing (default: true)
- portctl_allow_overwrite (default: false)
- portctl_restart_on_change (default: true)
- portctl_packages (default: python3, php-cli, ufw)
- portctl_agent_path (default: /opt/portctl/agent.py)
- portctl_rules_path (default: /opt/portctl/rules.json)
- portctl_config_path (default: /etc/portctl/config.json)
- portctl_default_dest_ip (default: "")
- portctl_public_interface (default: "")
- portctl_web_root (default: /srv/portctl-web)
- portctl_web_port (default: 9000)
- portctl_web_wg_bind (default: "")
- portctl_web_local_bind (default: 127.0.0.1)
- portctl_enable_web_wg (default: true)
- portctl_enable_web_local (default: true)

## Notes
- The agent edits /etc/ufw/before.rules and uses ufw route allow.
- Set portctl_public_interface only when auto-detection picks the wrong NIC.

## Notes
- Set portctl_default_dest_ip or specify dest_ip per rule; it is required for forwarding.
- When portctl_enable_web_wg is true, set portctl_web_wg_bind to your wg IP.
