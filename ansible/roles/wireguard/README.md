# wireguard

Manages WireGuard configs and unit conflicts.

Required variables (example structure):

wireguard_manage: true
wireguard_configs:
  - name: wg0
    address: "10.100.0.2/32"
    private_key: "..."
    listen_port: 51820
    dns: "1.1.1.1"
    peers:
      - public_key: "..."
        allowed_ips: "0.0.0.0/0"
        endpoint: "VPS_PUBLIC_IP:51820"
        persistent_keepalive: 25

Optional:
- wireguard_allow_overwrite: false (default)
- wireguard_enable_on_boot: true
- wireguard_primary: wg0
