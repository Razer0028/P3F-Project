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
- portctl_default_dest_ip (default: )
- portctl_public_interface (default: )
- portctl_nat_enable (default: false)
- portctl_nat_source (default: )
- portctl_nat_interface (default: )
- portctl_web_root (default: /srv/portctl-web)
- portctl_web_port (default: 9000)
- portctl_web_wg_bind (default: )
- portctl_web_local_bind (default: 127.0.0.1)
- portctl_wg_service (default: wg-quick@wg0.service)
- portctl_wg_interface (default: wg0)
- portctl_enable_web_wg (default: true)
- portctl_enable_web_local (default: true)

## Notes
- portctl_public_interface is auto-detected from ansible_default_ipv4 unless overridden.
- portctl_web_wg_bind is auto-detected from WireGuard config or live wg interface when empty.
- If your wg interface name differs, set portctl_wg_interface.
- Set portctl_default_dest_ip or specify dest_ip per rule; it is required for forwarding.
