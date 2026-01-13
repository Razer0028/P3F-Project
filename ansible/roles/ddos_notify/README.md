# ddos_notify

Deploys a lightweight Suricata alert watcher that only notifies on DDoS signatures.
It tails `eve.json` and sends UDP alerts (optional fallback) and Discord webhook messages.

## Variables

- `ddos_notify_manage` (default: false)
- `ddos_notify_manage_service` (default: true)
- `ddos_notify_service_state` (default: started)
- `ddos_notify_service_name` (default: ddos_watch)

Paths:
- `ddos_notify_script_path` (default: /opt/ddos_notify/ddos_watch_udp.py)
- `ddos_notify_unit_path` (default: /etc/systemd/system/ddos_watch.service)
- `ddos_notify_eve_log` (default: /var/log/suricata/eve.json)

Notification:
- `ddos_notify_primary_ip` (required)
- `ddos_notify_fallback_ip` (optional)
- `ddos_notify_port` (default: 9001)
- `ddos_notify_signatures` (list of alert signatures)

Discord (optional):
- `ddos_notify_discord_webhook` (empty disables)
- `ddos_notify_discord_cooldown` (default: 300)
- `ddos_notify_user_agent` (default: curl/8.0)

## Notes

- Use Vault for webhook secrets and IPs.
- The signatures must match the Suricata rule `msg` exactly.
