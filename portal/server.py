#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import shutil
import socketserver
import http.server
import cgi
import threading
import time
import uuid
import re
import subprocess
import tempfile
import ipaddress
import csv
import io
import configparser
import secrets
from urllib.parse import urlparse, parse_qs

ALLOWED_UPLOAD_TARGETS = {
    "onprem": "onprem_ed25519",
    "vps": "vps_ed25519",
    "ec2": "ec2_key.pem",
}

ALLOWED_SAVE_TARGETS = {
    "ansible/hosts.ini": "text",
    "ansible/group_vars/all.yml": "text",
    "terraform/terraform.tfvars": "text",
    "terraform-cloudflare/terraform.tfvars": "text",
    "tmp/secrets_checklist.txt": "text",
    "tmp/admin_vault_snippet.txt": "text",
    "tmp/failover_aws_vault_snippet.txt": "text",
    "tmp/ddos_vps_vault_snippet.txt": "text",
    "tmp/cloudflared_vps_vault_snippet.txt": "text",
    "tmp/cloudflared_ec2_vault_snippet.txt": "text",
    "tmp/next_steps.txt": "text",
}

MAX_UPLOAD_BYTES = 64 * 1024
MAX_SAVE_BYTES = 120 * 1024
MAX_LOG_BYTES = 8000

PROJECT_SLUG = os.environ.get("PORTAL_PROJECT_SLUG", "edge-stack")
CONFIG_DIR = os.environ.get("PORTAL_CONFIG_DIR", f"~/.config/{PROJECT_SLUG}")
VAULT_PASS_PATH = os.environ.get("PORTAL_VAULT_PASS", f"{CONFIG_DIR}/vault_pass")
SECRETS_META_PATH = pathlib.Path(CONFIG_DIR).expanduser() / "portal_secrets.json"
CLOUDFLARE_TOKEN_PATH = pathlib.Path(CONFIG_DIR).expanduser() / "cloudflare_token"
OUTPUT_ROOT = pathlib.Path(os.environ.get("PORTAL_OUTPUT_DIR", CONFIG_DIR)).expanduser()
OUTPUT_ANSIBLE_DIR = OUTPUT_ROOT / "ansible"
OUTPUT_INVENTORY_PATH = OUTPUT_ANSIBLE_DIR / "hosts.ini"
OUTPUT_GROUP_VARS_PATH = OUTPUT_ANSIBLE_DIR / "group_vars" / "all.yml"
OUTPUT_HOST_VARS_DIR = OUTPUT_ANSIBLE_DIR / "host_vars"
OUTPUT_TFVARS_PATH = OUTPUT_ROOT / "terraform" / "terraform.tfvars"
OUTPUT_TFVARS_CF_PATH = OUTPUT_ROOT / "terraform-cloudflare" / "terraform.tfvars"

SURICATA_CUSTOM_RULES_PATH = os.environ.get("PORTAL_SURICATA_RULES", "/home/gameadmin/Uploads/portal_uploads/custom.rules.txt")
SURICATA_CUSTOM_RULES_DEST = "/etc/suricata/rules/custom.rules"
SURICATA_RULES_MARKER = "# Managed by portal: suricata rules"
SURICATA_RULES_END_MARKER = "# End managed by portal: suricata rules"

FAILOVER_HOST_VARS_REL = "ansible/host_vars/onprem-1.yml"
FAILOVER_RULES_MARKER = "# Managed by portal: failover core"
CLOUDFLARED_RULES_MARKER = "# Managed by portal: cloudflared"
CLOUDFLARED_RULES_END_MARKER = "# End managed by portal: cloudflared"
WIREGUARD_RULES_MARKER = "# Managed by portal: wireguard"
WIREGUARD_RULES_END_MARKER = "# End managed by portal: wireguard"
CLOUDFLARED_DEFAULT_ORIGIN = "http://10.0.0.2:8082"
AUTO_IMPORT_MARKER = "# Managed by portal: auto-import"
AUTO_IMPORT_ENV = os.environ.get("PORTAL_AUTO_IMPORT", "true").strip().lower()
AUTO_IMPORT_ENABLED = AUTO_IMPORT_ENV not in {"0", "false", "no", "off"}
WG_DEFAULT_CIDR = "10.0.0.0/24"
WG_ONPREM_ADDRESS = "10.0.0.2/24"
WG_EDGE_ADDRESS = "10.0.0.1/24"
WG_LISTEN_PORT = 51820
WG_ALLOWED_IPS = "0.0.0.0/0"
WG_KEEPALIVE = 25
WG_MTU = 1420
WG_NAT_INTERFACE_PLACEHOLDER = "<AUTO_IFACE>"

def response_json(handler, status, payload):
    data = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def read_json(path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None


def write_json(path, payload):
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))






def parse_yaml_bool(text, key):
    if not text:
        return False
    prefix = f"{key}:"
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.startswith(prefix):
            continue
        value = stripped.split(":", 1)[1].strip().lower()
        return value in {"true", "yes", "1", "on"}
    return False


def inventory_has_group(text, group):
    if not text:
        return False
    header = f"[{group}]"
    found = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            found = (stripped == header)
            continue
        if found:
            return True
    return False




def escape_yaml(value):
    if value is None:
        return "\"\""
    text = str(value)
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    return f"\"{text}\""


def indent_block(text, spaces):
    prefix = " " * spaces
    return "\n".join(f"{prefix}{line}" for line in text.splitlines())


def normalize_text(text):
    return text.replace("\r\n", "\n").replace("\r", "\n")


def parse_yaml_value(text, key):
    if not text:
        return ""
    prefix = f"{key}:"
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.startswith(prefix):
            continue
        value = stripped.split(":", 1)[1].strip()
        if value.startswith(("\"", "'")) and value.endswith(("\"", "'")):
            value = value[1:-1]
        return value
    return ""


def parse_inventory_group_ip(text, group):
    if not text:
        return ""
    header = f"[{group}]"
    found = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            found = (stripped == header)
            continue
        if found:
            parts = stripped.split()
            if not parts:
                continue
            host = ""
            for token in parts[1:]:
                if token.startswith("ansible_host="):
                    host = token.split("=", 1)[1]
                    break
            if not host:
                host = parts[0]
            return host
    return ""


def parse_inventory_group_host(text, group):
    if not text:
        return {}
    header = f"[{group}]"
    in_group = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            in_group = (stripped == header)
            continue
        if not in_group:
            continue
        parts = stripped.split()
        if not parts:
            continue
        info = {"alias": parts[0]}
        for token in parts[1:]:
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            info[key.strip()] = value.strip()
        return info
    return {}


def resolve_key_path(raw):
    if not raw:
        return None
    try:
        path = pathlib.Path(raw).expanduser()
    except Exception:
        return None
    return path if path.exists() else None


def ensure_key_loaded(key_path, passphrase):
    if not key_path or not passphrase:
        return True, ""
    return add_key_to_agent(key_path, passphrase)


def run_ssh_command(host, user, key_path, command, sudo_password="", timeout=12):
    if not host or not user:
        return "", "Missing host/user"
    target = f"{user}@{host}"
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=8"]
    if key_path:
        cmd += ["-i", str(key_path), "-o", "IdentitiesOnly=yes"]
    cmd.append(target)
    cmd.append(command)
    try:
        result = subprocess.run(
            cmd,
            input=(sudo_password + "\n") if sudo_password else None,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except Exception as exc:
        return "", str(exc)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "ssh failed").strip()
        return "", detail
    return result.stdout, ""


def read_remote_file(host, user, key_path, path, sudo_password="", timeout=12):
    if not path:
        return "", "Missing path"
    if user == "root":
        cmd = f"cat {path}"
        return run_ssh_command(host, user, key_path, cmd, "", timeout)
    cmd = f"sudo -S -p \"\" cat {path}"
    return run_ssh_command(host, user, key_path, cmd, sudo_password, timeout)


def read_local_file(path):
    try:
        return pathlib.Path(path).read_text(encoding="utf-8", errors="replace"), ""
    except Exception as exc:
        return "", str(exc)


def sanitize_wg_content(content):
    return normalize_text(content).rstrip("\n")

def generate_wg_keypair():
    if shutil.which("wg") is None:
        return "", "", "wg command not found"
    try:
        private_key = subprocess.check_output(["wg", "genkey"], text=True).strip()
        public_key = subprocess.check_output(["wg", "pubkey"], input=private_key + "\n", text=True).strip()
        if not private_key or not public_key:
            return "", "", "wg returned empty key"
        return private_key, public_key, ""
    except Exception as exc:
        return "", "", str(exc)

def build_wg_config_item(name, address, private_key, peer, enable_nat=False, dns=None, listen_port=WG_LISTEN_PORT):
    item = {
        "name": name,
        "address": address,
        "private_key": private_key,
        "peers": [peer],
    }
    if listen_port is not None:
        item["listen_port"] = listen_port
    if enable_nat:
        item["enable_nat"] = True
    if dns:
        item["dns"] = dns
    if WG_MTU:
        item["mtu"] = WG_MTU
    return item


def normalize_client_allowed_ip(raw):
    value = (raw or "").strip()
    if not value:
        return "", "portctl_default_dest_ip is empty"
    try:
        if "/" in value:
            iface = ipaddress.ip_interface(value)
            return f"{iface.ip}/32", ""
        ip = ipaddress.ip_address(value)
        return f"{ip}/32", ""
    except ValueError:
        return "", f"Invalid client IP: {value}"

def build_simple_wireguard_configs(output_root, inventory_text, client_allowed_ip):
    errors = {}
    vps_ip = parse_inventory_group_ip(inventory_text, "vps")
    ec2_ip = parse_inventory_group_ip(inventory_text, "ec2")

    onprem_wg0_priv, onprem_wg0_pub, err = generate_wg_keypair()
    if err:
        errors["wireguard_onprem_wg0"] = err
    onprem_wg1_priv, onprem_wg1_pub, err = generate_wg_keypair()
    if err:
        errors["wireguard_onprem_wg1"] = err
    vps_priv, vps_pub, err = generate_wg_keypair()
    if err:
        errors["wireguard_vps_wg0"] = err
    ec2_priv, ec2_pub, err = generate_wg_keypair()
    if err:
        errors["wireguard_ec2_wg1"] = err

    if errors:
        return {}, errors

    vps_endpoint = f"{vps_ip}:{WG_LISTEN_PORT}" if vps_ip else ""
    ec2_endpoint = f"{ec2_ip}:{WG_LISTEN_PORT}" if ec2_ip else ""

    onprem_wg0 = build_wg_config_item(
        "wg0",
        WG_ONPREM_ADDRESS,
        onprem_wg0_priv,
        {
            "public_key": vps_pub,
            "allowed_ips": WG_ALLOWED_IPS,
            "endpoint": vps_endpoint,
            "persistent_keepalive": WG_KEEPALIVE,
        },
        dns="8.8.8.8",
        listen_port=None,
    )
    onprem_wg1 = build_wg_config_item(
        "wg1",
        WG_ONPREM_ADDRESS,
        onprem_wg1_priv,
        {
            "public_key": ec2_pub,
            "allowed_ips": WG_ALLOWED_IPS,
            "endpoint": ec2_endpoint,
            "persistent_keepalive": WG_KEEPALIVE,
        },
        dns="8.8.8.8",
        listen_port=None,
    )
    vps_wg0 = build_wg_config_item(
        "wg0",
        WG_EDGE_ADDRESS,
        vps_priv,
        {
            "public_key": onprem_wg0_pub,
            "allowed_ips": client_allowed_ip,
        },
        enable_nat=True,
    )
    ec2_wg1 = build_wg_config_item(
        "wg1",
        WG_EDGE_ADDRESS,
        ec2_priv,
        {
            "public_key": onprem_wg1_pub,
            "allowed_ips": client_allowed_ip,
        },
        enable_nat=True,
    )

    return {
        "onprem-1": [onprem_wg0, onprem_wg1],
        "vps-1": [vps_wg0],
        "ec2-1": [ec2_wg1],
    }, {}


def build_wireguard_config_block(configs, primary, allow_overwrite=True, enable_on_boot=True, restart_on_change=True):
    if not configs:
        return ""
    lines = [
        WIREGUARD_RULES_MARKER,
        "wireguard_manage: true",
        f"wireguard_allow_overwrite: {str(bool(allow_overwrite)).lower()}",
        f"wireguard_enable_on_boot: {str(bool(enable_on_boot)).lower()}",
        f"wireguard_restart_on_change: {str(bool(restart_on_change)).lower()}",
    ]
    if primary:
        lines.append(f"wireguard_primary: \"{primary}\"")
    lines.append("wireguard_configs:")
    for item in configs:
        name = escape_yaml(item.get("name", "wg0"))
        address = escape_yaml(item.get("address", ""))
        private_key = escape_yaml(item.get("private_key", ""))
        listen_port = item.get("listen_port", WG_LISTEN_PORT)
        if not address.strip("\"") or not private_key.strip("\""):
            continue
        lines.append(f"  - name: {name}")
        lines.append(f"    address: {address}")
        lines.append(f"    private_key: {private_key}")
        lines.append(f"    listen_port: {listen_port}")
        if item.get("enable_nat"):
            lines.append("    enable_nat: true")
        lines.append("    peers:")
        for peer in item.get("peers", []):
            public_key = escape_yaml(peer.get("public_key", ""))
            allowed_ips = escape_yaml(peer.get("allowed_ips", ""))
            if not public_key.strip("\"") or not allowed_ips.strip("\""):
                continue
            lines.append(f"      - public_key: {public_key}")
            lines.append(f"        allowed_ips: {allowed_ips}")
            endpoint = peer.get("endpoint")
            if endpoint:
                lines.append(f"        endpoint: {escape_yaml(endpoint)}")
            keepalive = peer.get("persistent_keepalive")
            if keepalive:
                lines.append(f"        persistent_keepalive: {keepalive}")
    lines.append(WIREGUARD_RULES_END_MARKER)
    lines.append("")
    return "\n".join(lines)


def render_wireguard_config(item, nat_interface):
    lines = [
        "[Interface]",
        f"Address = {item.get('address', '')}",
        f"PrivateKey = {item.get('private_key', '')}",
    ]
    listen_port = item.get("listen_port")
    if listen_port is not None:
        lines.append(f"ListenPort = {listen_port}")
    mtu = item.get("mtu")
    if mtu:
        lines.append(f"MTU = {mtu}")
    dns = item.get("dns")
    if dns:
        lines.append(f"DNS = {dns}")
    if item.get("enable_nat"):
        iface = nat_interface or WG_NAT_INTERFACE_PLACEHOLDER
        lines.append(f"PostUp = iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE")
        lines.append(f"PostDown = iptables -t nat -D POSTROUTING -o {iface} -j MASQUERADE")
    lines.append("")
    for peer in item.get("peers", []):
        lines.append("[Peer]")
        lines.append(f"PublicKey = {peer.get('public_key', '')}")
        allowed_ips = peer.get("allowed_ips")
        if allowed_ips:
            lines.append(f"AllowedIPs = {allowed_ips}")
        endpoint = peer.get("endpoint")
        if endpoint:
            lines.append(f"Endpoint = {endpoint}")
        keepalive = peer.get("persistent_keepalive")
        if keepalive:
            lines.append(f"PersistentKeepalive = {keepalive}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def upsert_wireguard_block(existing_text, new_block):
    if WIREGUARD_RULES_MARKER not in existing_text:
        return (existing_text.rstrip() + "\n\n" + new_block).strip() + "\n"
    start = existing_text.find(WIREGUARD_RULES_MARKER)
    end_marker = WIREGUARD_RULES_END_MARKER
    end = existing_text.find(end_marker, start)
    if end != -1:
        end += len(end_marker)
        return (existing_text[:start].rstrip() + "\n" + new_block + existing_text[end:].lstrip()).rstrip() + "\n"
    return (existing_text[:start].rstrip() + "\n" + new_block).rstrip() + "\n"


def build_wireguard_block(configs, primary, allow_overwrite=True, enable_on_boot=True, restart_on_change=True):
    if not configs:
        return ""
    lines = [
        "wireguard_manage: true",
        f"wireguard_allow_overwrite: {str(bool(allow_overwrite)).lower()}",
        f"wireguard_enable_on_boot: {str(bool(enable_on_boot)).lower()}",
        f"wireguard_restart_on_change: {str(bool(restart_on_change)).lower()}",
    ]
    if primary:
        lines.append(f"wireguard_primary: \"{primary}\"")
    lines.append("wireguard_raw_configs:")
    for cfg in configs:
        name = cfg.get("name")
        content = cfg.get("content", "")
        if not name or not content:
            continue
        lines.append(f"  - name: \"{name}\"")
        lines.append("    content: |")
        lines.append(indent_block(content, 6))
    return "\n".join(lines) + "\n"


def normalize_suricata_yaml(content):
    text = normalize_text(content).rstrip("\n")
    return re.sub(r"(^\s*-\s*interface:\s*)(?!default\b)\S+", r"\1eth0", text, flags=re.MULTILINE)


def build_suricata_block(yaml_content, rules_content):
    if not yaml_content or not rules_content:
        return ""
    yaml_clean = normalize_suricata_yaml(yaml_content)
    rules_clean = normalize_text(rules_content).rstrip("\n")
    return "\n".join(
        [
            "suricata_manage: true",
            "suricata_manage_service: true",
            "suricata_restart_on_change: true",
            "suricata_allow_overwrite: true",
            "suricata_yaml_manage: true",
            "suricata_yaml_content: |",
            indent_block(yaml_clean, 2),
            f"suricata_custom_rules_path: {SURICATA_CUSTOM_RULES_DEST}",
            "suricata_custom_rules_content: |",
            indent_block(rules_clean or "# empty", 2),
            "",
        ]
    )


def build_frr_block(config_content, daemons_content):
    if not config_content or not daemons_content:
        return ""
    cfg_clean = normalize_text(config_content).rstrip("\n")
    daemons_clean = normalize_text(daemons_content).rstrip("\n")
    return "\n".join(
        [
            "frr_manage: true",
            "frr_manage_service: true",
            "frr_allow_overwrite: true",
            "frr_restart_on_change: true",
            "frr_generate_config: false",
            "frr_config_content: |",
            indent_block(cfg_clean, 2),
            "frr_daemons_content: |",
            indent_block(daemons_clean, 2),
            "",
        ]
    )


def parse_ufw_rules(text):
    ufw_rules = []
    forward_rules = []
    forward_dest_ips = []
    if not text:
        return ufw_rules, forward_rules, ""

    def add_ufw(rule):
        if rule and rule not in ufw_rules:
            ufw_rules.append(rule)

    def add_forward(rule):
        if not rule:
            return
        key = f"{rule.get('protocol')}:{rule.get('ext_port')}:{rule.get('dest_ip')}:{rule.get('dest_port')}"
        if any(
            r.get("protocol") == rule.get("protocol")
            and r.get("ext_port") == rule.get("ext_port")
            and r.get("dest_ip") == rule.get("dest_ip")
            and r.get("dest_port") == rule.get("dest_port")
            for r in forward_rules
        ):
            return
        forward_rules.append(rule)

    for line in normalize_text(text).splitlines():
        stripped = line.strip()
        if not stripped.startswith("-A ufw-user-"):
            continue

        proto_match = re.search(r"-p\s+(tcp|udp)", stripped)
        proto = proto_match.group(1) if proto_match else ""
        dport_match = re.search(r"--dport\s+(\S+)", stripped)
        dports_match = re.search(r"--dports\s+(\S+)", stripped)
        src_match = re.search(r"-s\s+(\S+)", stripped)
        dest_match = re.search(r"-d\s+(\S+)", stripped)
        in_if_match = re.search(r"-i\s+(\S+)", stripped)
        out_if_match = re.search(r"-o\s+(\S+)", stripped)

        if stripped.startswith("-A ufw-user-input"):
            if dport_match or dports_match:
                port_spec = dport_match.group(1) if dport_match else dports_match.group(1)
                if proto:
                    add_ufw(f"allow {port_spec}/{proto}")
            elif src_match:
                add_ufw(f"allow from {src_match.group(1)}")
            continue

        if not stripped.startswith("-A ufw-user-forward"):
            continue

        if dest_match and (dport_match or dports_match) and proto:
            dest_ip = dest_match.group(1)
            port_spec = dport_match.group(1) if dport_match else dports_match.group(1)
            add_forward(
                {
                    "ext_port": port_spec,
                    "dest_port": port_spec,
                    "protocol": proto,
                    "dest_ip": dest_ip,
                }
            )
            if dest_ip not in forward_dest_ips:
                forward_dest_ips.append(dest_ip)
            continue

        if in_if_match and out_if_match:
            in_if = in_if_match.group(1)
            out_if = out_if_match.group(1)
            add_ufw(f"route allow in on {in_if} out on {out_if}")
            continue

        if in_if_match and src_match:
            in_if = in_if_match.group(1)
            add_ufw(f"route allow in on {in_if} from {src_match.group(1)}")

    default_dest_ip = forward_dest_ips[0] if forward_dest_ips else ""
    return ufw_rules, forward_rules, default_dest_ip


def build_portctl_block(ufw_rules, forward_rules, default_dest_ip):
    if not ufw_rules and not forward_rules:
        return ""
    ufw_yaml = ""
    if ufw_rules:
        escaped = []
        for rule in ufw_rules:
            safe = rule.replace("\\", "\\\\").replace("\"", "\\\"")
            escaped.append(f"  - \"{safe}\"")
        ufw_yaml = "\n".join(escaped)
    forward_yaml = ""
    if forward_rules:
        blocks = []
        for rule in forward_rules:
            blocks.append(
                "\n".join(
                    [
                        "  - ext_port: \"{ext}\"".format(ext=rule["ext_port"]),
                        "    dest_port: \"{dest}\"".format(dest=rule["dest_port"]),
                        "    protocol: \"{proto}\"".format(proto=rule["protocol"]),
                        "    dest_ip: \"{dest_ip}\"".format(dest_ip=rule["dest_ip"]),
                    ]
                )
            )
        forward_yaml = "\n".join(blocks)
    lines = [
        "portctl_manage: true",
        "portctl_manage_service: true",
        "portctl_apply_rules: true",
        f"portctl_default_dest_ip: \"{default_dest_ip}\"" if default_dest_ip else "portctl_default_dest_ip: \"\"",
    ]
    if ufw_rules:
        lines.append("portctl_ufw_rules:")
        lines.append(ufw_yaml)
    else:
        lines.append("portctl_ufw_rules: []")
    if forward_rules:
        lines.append("portctl_forward_rules:")
        lines.append(forward_yaml)
    else:
        lines.append("portctl_forward_rules: []")
    lines.append("")
    return "\n".join(lines)


def extract_vault_yaml(text):
    if not text:
        return ""
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(line.rstrip())
    return "\n".join(lines).strip()


def write_host_vars(output_root, host, content):
    if not content:
        return {}
    rel_path = f"ansible/host_vars/{host}.yml"
    abs_path = resolve_output_path(output_root, rel_path)
    if not abs_path:
        return {}
    if abs_path.exists():
        try:
            existing = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            existing = ""
        if AUTO_IMPORT_MARKER not in existing.splitlines()[:2]:
            return {}
    final_content = f"{AUTO_IMPORT_MARKER}\n{content.strip()}\n"
    abs_path.parent.mkdir(parents=True, exist_ok=True)
    abs_path.write_text(final_content, encoding="utf-8")
    os.chmod(abs_path, 0o600)
    record_secret_path(abs_path)
    return {rel_path: {"bytes": len(final_content.encode('utf-8'))}}


def write_wireguard_host_vars(output_root, host, content):
    if not content:
        return {}
    rel_path = f"ansible/host_vars/{host}.yml"
    abs_path = resolve_output_path(output_root, rel_path)
    if not abs_path:
        return {}
    existing = ""
    if abs_path.exists():
        try:
            existing = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            existing = ""
        if WIREGUARD_RULES_MARKER not in existing and "wireguard_manage:" in existing:
            return {}
        content_to_write = upsert_wireguard_block(existing, content)
    else:
        content_to_write = content
    abs_path.parent.mkdir(parents=True, exist_ok=True)
    abs_path.write_text(content_to_write, encoding="utf-8")
    os.chmod(abs_path, 0o600)
    record_secret_path(abs_path)
    return {rel_path: {"bytes": len(content_to_write.encode("utf-8"))}}


def maybe_write_auto_host_vars(output_root, inventory_text, group_vars_text, secrets, setup_mode):
    if not AUTO_IMPORT_ENABLED:
        return {}, {}, {}
    if setup_mode == "beginner":
        return maybe_write_auto_host_vars_simple(output_root, inventory_text, group_vars_text)
    return {}, {}, {}


def maybe_write_auto_host_vars_simple(output_root, inventory_text, group_vars_text):
    wireguard_enabled = parse_yaml_bool(group_vars_text, "wireguard_manage")
    saved = {}
    errors = {}
    wg_outputs = {}
    host_sections = {}
    wireguard_blocks = {}
    host_groups = {"onprem-1": "onprem", "vps-1": "vps", "ec2-1": "ec2"}
    for host_name in host_groups:
        host_sections[host_name] = []

    host_sections["vps-1"].append("base_disable_apparmor: true")
    host_sections["ec2-1"].append("base_disable_apparmor: true")
    host_sections["vps-1"].append("base_ufw_before_rules_manage: true")
    host_sections["ec2-1"].append("base_ufw_before_rules_manage: true")
    host_sections["vps-1"].append("portctl_ufw_before_rules_manage: true")
    host_sections["ec2-1"].append("portctl_ufw_before_rules_manage: true")

    if wireguard_enabled:
        dest_ip = parse_yaml_value(group_vars_text, "portctl_default_dest_ip")
        client_allowed, client_error = normalize_client_allowed_ip(dest_ip)
        if client_error:
            errors["wireguard_client_ip"] = client_error
        else:
            configs, wg_errors = build_simple_wireguard_configs(output_root, inventory_text, client_allowed)
            errors.update(wg_errors)
            if not wg_errors:
                onprem_block = build_wireguard_config_block(configs.get("onprem-1"), "wg0", allow_overwrite=True, enable_on_boot=True)
                if onprem_block:
                    wireguard_blocks["onprem-1"] = onprem_block
                vps_block = build_wireguard_config_block(configs.get("vps-1"), "wg0", allow_overwrite=True, enable_on_boot=True)
                if vps_block:
                    wireguard_blocks["vps-1"] = vps_block
                ec2_block = build_wireguard_config_block(configs.get("ec2-1"), "wg1", allow_overwrite=True, enable_on_boot=True)
                if ec2_block:
                    wireguard_blocks["ec2-1"] = ec2_block
                wg_onprem = configs.get("onprem-1", [])
                wg_vps = configs.get("vps-1", [])
                wg_ec2 = configs.get("ec2-1", [])
                if len(wg_onprem) > 0:
                    wg_outputs["onprem_wg0"] = render_wireguard_config(wg_onprem[0], "")
                if len(wg_onprem) > 1:
                    wg_outputs["onprem_wg1"] = render_wireguard_config(wg_onprem[1], "")
                if len(wg_vps) > 0:
                    wg_outputs["vps_wg0"] = render_wireguard_config(wg_vps[0], WG_NAT_INTERFACE_PLACEHOLDER)
                if len(wg_ec2) > 0:
                    wg_outputs["ec2_wg1"] = render_wireguard_config(wg_ec2[0], WG_NAT_INTERFACE_PLACEHOLDER)

    ddos_path = output_root / "tmp" / "ddos_vps_vault_snippet.txt"
    if ddos_path.exists():
        ddos_yaml = extract_vault_yaml(ddos_path.read_text(encoding="utf-8", errors="replace"))
        if ddos_yaml:
            host_sections["vps-1"].append(ddos_yaml + "\n")

    for host, blocks in host_sections.items():
        group = host_groups.get(host, "")
        if group and not inventory_has_group(inventory_text, group):
            continue
        content = "\n".join(blocks).rstrip()
        if not content:
            continue
        saved.update(write_host_vars(output_root, host, content))

    for host, block in wireguard_blocks.items():
        group = host_groups.get(host, "")
        if group and not inventory_has_group(inventory_text, group):
            continue
        saved.update(write_wireguard_host_vars(output_root, host, block))

    return saved, errors, wg_outputs


def read_tfvars_value(path, key):
    if not path or not path.exists():
        return ""
    prefix = f"{key} ="
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.startswith(prefix):
            continue
        value = stripped.split("=", 1)[1].strip()
        if value.startswith(("\"", "'")) and value.endswith(("\"", "'")):
            value = value[1:-1]
        return value
    return ""


def parse_cloudflared_snippet(path):
    if not path.exists():
        return "", ""
    hostname = ""
    origin = ""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "", ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("hostname:"):
            hostname = stripped.split(":", 1)[1].strip().strip("\"'")
        if stripped.startswith("service:"):
            value = stripped.split(":", 1)[1].strip().strip("\"'")
            if value and value != "http_status:404" and not origin:
                origin = value
    return hostname, origin


def terraform_output_json(terraform_dir):
    try:
        output = subprocess.check_output(
            ["terraform", "output", "-json"],
            cwd=str(terraform_dir),
            text=True,
        )
    except Exception:
        return read_tfstate_outputs(terraform_dir)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return read_tfstate_outputs(terraform_dir)


def read_tfstate_outputs(terraform_dir):
    state_path = pathlib.Path(terraform_dir) / "terraform.tfstate"
    if not state_path.exists():
        return {}
    try:
        data = json.loads(state_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}
    outputs = data.get("outputs")
    return outputs if isinstance(outputs, dict) else {}


def terraform_output_value(output_json, key):
    if not isinstance(output_json, dict):
        return ""
    entry = output_json.get(key)
    if isinstance(entry, dict) and "value" in entry:
        return entry.get("value")
    return entry


def build_suricata_host_vars(rules_text):
    cleaned = rules_text.replace("\r\n", "\n").rstrip("\n")
    if not cleaned:
        cleaned = "# empty"
    indented = "\n".join(f"  {line}" for line in cleaned.split("\n"))
    return (
        f"{SURICATA_RULES_MARKER}\n"
        "suricata_allow_overwrite: true\n"
        f"suricata_custom_rules_path: {SURICATA_CUSTOM_RULES_DEST}\n"
        "suricata_custom_rules_content: |\n"
        f"{indented}\n"
        f"{SURICATA_RULES_END_MARKER}\n"
    )


def upsert_suricata_block(existing_text, new_block):
    if SURICATA_RULES_MARKER not in existing_text:
        return (existing_text.rstrip() + "\n\n" + new_block).strip() + "\n"
    start = existing_text.find(SURICATA_RULES_MARKER)
    end_marker = SURICATA_RULES_END_MARKER
    end = existing_text.find(end_marker, start)
    if end != -1:
        end += len(end_marker)
        return (existing_text[:start].rstrip() + "\n" + new_block + existing_text[end:].lstrip()).rstrip() + "\n"
    return (existing_text[:start].rstrip() + "\n" + new_block).rstrip() + "\n"


def extract_yaml_block(text, key):
    if not text:
        return ""
    lines = text.splitlines()
    start = None
    for idx, line in enumerate(lines):
        if line.strip() == f"{key}: |":
            start = idx + 1
            break
    if start is None:
        return ""
    block = []
    for line in lines[start:]:
        if line.startswith("  "):
            block.append(line[2:])
            continue
        if line.strip() == "":
            block.append("")
            continue
        break
    return "\n".join(block).rstrip("\n")


def load_suricata_rules_text(custom_path, repo_root):
    rules_path = pathlib.Path(custom_path).expanduser() if custom_path else None
    if rules_path and rules_path.exists():
        text = rules_path.read_text(encoding="utf-8", errors="replace")
        if text.strip():
            return text
    example_path = pathlib.Path(repo_root) / "ansible" / "host_vars" / "ec2-1.yml.example"
    if not example_path.exists():
        return ""
    example_text = example_path.read_text(encoding="utf-8", errors="replace")
    return extract_yaml_block(example_text, "suricata_custom_rules_content")


def maybe_write_suricata_host_vars(output_root, repo_root, inventory_text, group_vars_text):
    if not parse_yaml_bool(group_vars_text, "suricata_manage"):
        return {}
    rules_text = load_suricata_rules_text(SURICATA_CUSTOM_RULES_PATH, repo_root)
    if not rules_text.strip():
        return {}
    content = build_suricata_host_vars(rules_text)
    saved = {}
    for group in ("vps", "ec2"):
        if not inventory_has_group(inventory_text, group):
            continue
        rel_path = f"ansible/host_vars/{group}-1.yml"
        abs_path = resolve_output_path(output_root, rel_path)
        if not abs_path:
            continue
        if abs_path.exists():
            try:
                existing = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                existing = ""
            content_to_write = upsert_suricata_block(existing, content)
        else:
            content_to_write = content
        abs_path.parent.mkdir(parents=True, exist_ok=True)
        abs_path.write_text(content_to_write, encoding="utf-8")
        os.chmod(abs_path, 0o600)
        record_secret_path(abs_path)
        saved[rel_path] = {"bytes": len(content_to_write.encode("utf-8"))}
    return saved




def maybe_write_failover_host_vars(output_root, repo_root, inventory_text, group_vars_text, force=False):
    if not force and not parse_yaml_bool(group_vars_text, "failover_core_manage"):
        return {}
    if not inventory_has_group(inventory_text, "onprem"):
        return {}

    failover_path = resolve_output_path(output_root, FAILOVER_HOST_VARS_REL)
    if not failover_path:
        return {}

    tfvars_path = output_root / "terraform" / "terraform.tfvars"
    region = read_tfvars_value(tfvars_path, "aws_region")
    if not region:
        region = parse_yaml_value(group_vars_text, "aws_region")

    vps_ip = parse_inventory_group_ip(inventory_text, "vps")
    cf_token = read_cloudflare_token()

    tf_outputs = terraform_output_json(repo_root / "terraform")
    instance_id = terraform_output_value(tf_outputs, "instance_id") or ""
    public_ip = terraform_output_value(tf_outputs, "public_ip") or ""
    access_key_id = terraform_output_value(tf_outputs, "failover_access_key_id") or ""
    secret_access_key = terraform_output_value(tf_outputs, "failover_secret_access_key") or ""

    cf_outputs = terraform_output_json(repo_root / "terraform-cloudflare")
    zone_id = terraform_output_value(cf_outputs, "zone_id") or ""
    record_id = terraform_output_value(cf_outputs, "failover_record_id") or ""
    record_name = terraform_output_value(cf_outputs, "failover_record_name") or ""

    required = [
        instance_id,
        public_ip,
        cf_token,
        zone_id,
        record_id,
        record_name,
        vps_ip,
        region,
        access_key_id,
        secret_access_key,
    ]
    if not all(required):
        return {}

    if failover_path.exists():
        try:
            existing = failover_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            existing = ""
        if FAILOVER_RULES_MARKER not in existing.splitlines()[:2]:
            return {}

    content = "\n".join(
        [
            FAILOVER_RULES_MARKER,
            f"failover_instance_id: {escape_yaml(instance_id)}",
            f"failover_region: {escape_yaml(region)}",
            f"failover_ec2_ip: {escape_yaml(public_ip)}",
            f"failover_cf_token: {escape_yaml(cf_token)}",
            f"failover_cf_zone_id: {escape_yaml(zone_id)}",
            f"failover_cf_record_id: {escape_yaml(record_id)}",
            f"failover_dns_record_name: {escape_yaml(record_name)}",
            f"failover_vps_ip: {escape_yaml(vps_ip)}",
            "failover_aws_profile: \"failover\"",
            f"failover_aws_access_key_id: {escape_yaml(access_key_id)}",
            f"failover_aws_secret_access_key: {escape_yaml(secret_access_key)}",
            "failover_aws_session_token: \"\"",
            "failover_core_enable: true",
            "failover_core_state: started",
            "",
        ]
    )

    failover_path.parent.mkdir(parents=True, exist_ok=True)
    failover_path.write_text(content, encoding="utf-8")
    os.chmod(failover_path, 0o600)
    record_secret_path(failover_path)
    return {FAILOVER_HOST_VARS_REL: {"bytes": len(content.encode("utf-8"))}}


def build_cloudflared_host_vars(tunnel_id, hostname, origin, credentials_json):
    if not tunnel_id or not hostname or not credentials_json:
        return ""
    credentials_path = f"/etc/cloudflared/{tunnel_id}.json"
    origin_value = origin or CLOUDFLARED_DEFAULT_ORIGIN
    escaped_tunnel = escape_yaml(tunnel_id)
    escaped_hostname = escape_yaml(hostname)
    escaped_origin = escape_yaml(origin_value)
    escaped_credentials_path = escape_yaml(credentials_path)
    indented_creds = indent_block(credentials_json.strip() or "{}", 2)
    return "\n".join(
        [
            CLOUDFLARED_RULES_MARKER,
            "cloudflared_manage: true",
            "cloudflared_install_if_missing: true",
            "cloudflared_require_vars: true",
            "cloudflared_manage_service: true",
            "cloudflared_restart_on_change: true",
            "cloudflared_allow_overwrite: true",
            "cloudflared_enable_service: true",
            "cloudflared_config_content: |",
            f"  tunnel: {escaped_tunnel}",
            f"  credentials-file: {escaped_credentials_path}",
            "  ingress:",
            f"    - hostname: {escaped_hostname}",
            f"      service: {escaped_origin}",
            "    - service: http_status:404",
            f"cloudflared_credentials_path: {escaped_credentials_path}",
            "cloudflared_credentials_content: |",
            f"{indented_creds}",
            CLOUDFLARED_RULES_END_MARKER,
            "",
        ]
    )


def upsert_cloudflared_block(existing_text, new_block):
    if CLOUDFLARED_RULES_MARKER not in existing_text:
        return (existing_text.rstrip() + "\n\n" + new_block).strip() + "\n"
    start = existing_text.find(CLOUDFLARED_RULES_MARKER)
    end_marker = CLOUDFLARED_RULES_END_MARKER
    end = existing_text.find(end_marker, start)
    if end != -1:
        end += len(end_marker)
        return (existing_text[:start].rstrip() + "\n" + new_block + existing_text[end:].lstrip()).rstrip() + "\n"
    return (existing_text[:start].rstrip() + "\n" + new_block).rstrip() + "\n"


def maybe_write_cloudflared_host_vars(output_root, repo_root, inventory_text, group_vars_text):
    if not parse_yaml_bool(group_vars_text, "cloudflared_manage"):
        return {}

    tfvars_path = output_root / "terraform-cloudflare" / "terraform.tfvars"
    cf_outputs = terraform_output_json(repo_root / "terraform-cloudflare")
    if not cf_outputs:
        return {}

    saved = {}
    for group in ("vps", "ec2"):
        if not inventory_has_group(inventory_text, group):
            continue
        is_vps = group == "vps"
        tunnel_id = terraform_output_value(cf_outputs, "vps_tunnel_id" if is_vps else "ec2_tunnel_id") or ""
        credentials_json = terraform_output_value(
            cf_outputs,
            "vps_tunnel_credentials_json" if is_vps else "ec2_tunnel_credentials_json",
        ) or ""
        hostname_key = "cf_vps_hostname" if is_vps else "cf_ec2_hostname"
        hostname = read_tfvars_value(tfvars_path, hostname_key)
        snippet_path = output_root / "tmp" / f"cloudflared_{group}_vault_snippet.txt"
        snippet_hostname, snippet_origin = parse_cloudflared_snippet(snippet_path)
        if not hostname:
            hostname = snippet_hostname
        origin = snippet_origin
        if not origin:
            dest_ip = parse_yaml_value(group_vars_text, "portctl_default_dest_ip") or parse_yaml_value(group_vars_text, "port_forward_dest_ip")
            if dest_ip:
                origin = f"http://{dest_ip}:8082"
        if not origin:
            origin = CLOUDFLARED_DEFAULT_ORIGIN

        content = build_cloudflared_host_vars(tunnel_id, hostname, origin, credentials_json)
        if not content:
            continue

        rel_path = f"ansible/host_vars/{group}-1.yml"
        abs_path = resolve_output_path(output_root, rel_path)
        if not abs_path:
            continue
        if abs_path.exists():
            try:
                existing = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                existing = ""
            content = upsert_cloudflared_block(existing, content)
        abs_path.parent.mkdir(parents=True, exist_ok=True)
        abs_path.write_text(content, encoding="utf-8")
        os.chmod(abs_path, 0o600)
        record_secret_path(abs_path)
        saved[rel_path] = {"bytes": len(content.encode("utf-8"))}
    return saved


def load_secret_meta():
    data = read_json(SECRETS_META_PATH)
    if isinstance(data, dict) and isinstance(data.get("paths"), list):
        normalized = []
        for entry in data["paths"]:
            if isinstance(entry, str):
                normalized.append({"path": entry, "persistent": False})
            elif isinstance(entry, dict) and entry.get("path"):
                normalized.append(
                    {
                        "path": entry["path"],
                        "persistent": bool(entry.get("persistent")),
                    }
                )
        return {"paths": normalized}
    return {"paths": []}


def inventory_cloudflared_groups(inventory_text):
    groups = []
    for group in ("vps", "ec2"):
        if inventory_has_group(inventory_text, group):
            groups.append(group)
    return groups


def cloudflared_host_vars_missing(output_root, groups):
    missing = {}
    for group in groups:
        rel_path = f"ansible/host_vars/{group}-1.yml"
        abs_path = resolve_output_path(output_root, rel_path)
        if not abs_path or not abs_path.exists():
            missing[group] = "host_vars missing"
            continue
        try:
            text = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            missing[group] = "host_vars unreadable"
            continue
        if CLOUDFLARED_RULES_MARKER not in text:
            missing[group] = "cloudflared block missing"
            continue
        if "cloudflared_config_content:" not in text or "cloudflared_credentials_content:" not in text:
            missing[group] = "cloudflared fields missing"
    return missing


def record_secret_path(path, persistent=False):
    if not path:
        return
    meta = load_secret_meta()
    entry_path = str(path)
    for entry in meta["paths"]:
        if entry.get("path") == entry_path:
            if persistent and not entry.get("persistent"):
                entry["persistent"] = True
                SECRETS_META_PATH.parent.mkdir(parents=True, exist_ok=True)
                write_json(SECRETS_META_PATH, meta)
            return
    meta["paths"].append({"path": entry_path, "persistent": bool(persistent)})
    SECRETS_META_PATH.parent.mkdir(parents=True, exist_ok=True)
    write_json(SECRETS_META_PATH, meta)


def cleanup_secrets(include_persistent=False):
    meta = load_secret_meta()
    removed = []
    remaining = []
    for entry in meta.get("paths", []):
        entry_path = entry.get("path")
        if not entry_path:
            continue
        persistent = bool(entry.get("persistent"))
        if persistent and not include_persistent:
            remaining.append(entry)
            continue
        path = pathlib.Path(entry_path).expanduser()
        if path.exists():
            try:
                path.unlink()
                removed.append(str(path))
            except OSError:
                pass
    if remaining:
        SECRETS_META_PATH.parent.mkdir(parents=True, exist_ok=True)
        write_json(SECRETS_META_PATH, {"paths": remaining})
    elif SECRETS_META_PATH.exists():
        try:
            SECRETS_META_PATH.unlink()
        except OSError:
            pass
    return removed


def read_cloudflare_token():
    if CLOUDFLARE_TOKEN_PATH.exists():
        return CLOUDFLARE_TOKEN_PATH.read_text().strip()
    return ""


def write_cloudflare_token(token):
    CLOUDFLARE_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    CLOUDFLARE_TOKEN_PATH.write_text(token.strip() + "\n")
    os.chmod(CLOUDFLARE_TOKEN_PATH, 0o600)
    record_secret_path(CLOUDFLARE_TOKEN_PATH, persistent=True)
    return CLOUDFLARE_TOKEN_PATH


def resolve_repo_path(repo_root, relative_path):
    candidate = (repo_root / relative_path).resolve()
    if candidate == repo_root or repo_root in candidate.parents:
        return candidate
    return None


def resolve_output_path(output_root, relative_path):
    candidate = (output_root / relative_path).resolve()
    if candidate == output_root or output_root in candidate.parents:
        return candidate
    return None


def missing_tools_for_action(action):
    required = []
    if action == "validate":
        required.append("ansible")
    if action.startswith("ansible"):
        required.append("ansible-playbook")
    if action.startswith("tf-"):
        required.append("terraform")
    missing = [tool for tool in required if shutil.which(tool) is None]
    return missing


SAFE_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def sanitize_key_name(raw, fallback):
    name = (raw or "").strip()
    if not name:
        return fallback
    if "/" in name or "\\" in name:
        return fallback
    if not SAFE_KEY_NAME_RE.match(name):
        return fallback
    return name


def sanitize_profile_name(raw, fallback="default"):
    name = (raw or "").strip()
    if not name:
        return fallback
    if name == "default":
        return "default"
    if not SAFE_KEY_NAME_RE.match(name):
        return fallback
    return name


def parse_aws_credentials_csv(data):
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None, "Invalid CSV encoding"
    reader = csv.DictReader(io.StringIO(text))
    rows = [row for row in reader if row and any(row.values())]
    if not rows:
        return None, "CSV has no credential rows"
    row = rows[0]
    normalized = {}
    for key, value in row.items():
        if key is None:
            continue
        normalized[key.strip().lower()] = (value or "").strip()
    key_id = normalized.get("access key id") or normalized.get("access key")
    secret = normalized.get("secret access key") or normalized.get("secret key")
    if not key_id or not secret:
        return None, "Access key ID / Secret access key not found"
    return {
        "access_key_id": key_id,
        "secret_access_key": secret,
    }, ""


def write_aws_credentials(profile, key_id, secret_key):
    aws_dir = pathlib.Path("~/.aws").expanduser()
    aws_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    credentials_path = aws_dir / "credentials"
    config = configparser.RawConfigParser()
    if credentials_path.exists():
        config.read(credentials_path)
    if not config.has_section(profile):
        config.add_section(profile)
    config.set(profile, "aws_access_key_id", key_id)
    config.set(profile, "aws_secret_access_key", secret_key)
    with credentials_path.open("w") as handle:
        config.write(handle)
    os.chmod(credentials_path, 0o600)
    record_secret_path(credentials_path, persistent=True)
    return credentials_path


def write_aws_config(profile, region):
    if not region:
        return None
    aws_dir = pathlib.Path("~/.aws").expanduser()
    aws_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    config_path = aws_dir / "config"
    config = configparser.RawConfigParser()
    if config_path.exists():
        config.read(config_path)
    section = "default" if profile == "default" else f"profile {profile}"
    if not config.has_section(section):
        config.add_section(section)
    config.set(section, "region", region)
    config.set(section, "output", "json")
    with config_path.open("w") as handle:
        config.write(handle)
    os.chmod(config_path, 0o600)
    record_secret_path(config_path, persistent=True)
    return config_path




def ensure_vault_pass():
    vault_path = pathlib.Path(VAULT_PASS_PATH).expanduser()
    if vault_path.exists():
        return vault_path, False
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(24)
    vault_path.write_text(token + "\n", encoding="utf-8")
    os.chmod(vault_path, 0o600)
    record_secret_path(vault_path, persistent=True)
    return vault_path, True


def ensure_ssh_agent():
    sock = os.environ.get("SSH_AUTH_SOCK")
    if sock and pathlib.Path(sock).exists():
        return True, ""
    try:
        output = subprocess.check_output(["ssh-agent", "-s"], text=True)
    except Exception as exc:
        return False, str(exc)
    sock_match = re.search(r"SSH_AUTH_SOCK=([^;]+);", output)
    pid_match = re.search(r"SSH_AGENT_PID=([0-9]+);", output)
    if not sock_match or not pid_match:
        return False, "Failed to start ssh-agent"
    os.environ["SSH_AUTH_SOCK"] = sock_match.group(1)
    os.environ["SSH_AGENT_PID"] = pid_match.group(1)
    return True, ""


def add_key_to_agent(key_path, passphrase):
    ok, error = ensure_ssh_agent()
    if not ok:
        return False, error
    if not passphrase:
        return True, ""
    askpass_script = None
    pass_file = None
    try:
        pass_file = tempfile.NamedTemporaryFile("w", delete=False)
        pass_file.write(passphrase)
        pass_file.flush()
        os.fchmod(pass_file.fileno(), 0o600)
        pass_file.close()

        askpass_script = tempfile.NamedTemporaryFile("w", delete=False)
        askpass_script.write("#!/bin/sh\ncat \"%s\"\n" % pass_file.name)
        askpass_script.flush()
        os.fchmod(askpass_script.fileno(), 0o700)
        askpass_script.close()

        env = os.environ.copy()
        env["SSH_ASKPASS"] = askpass_script.name
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["DISPLAY"] = env.get("DISPLAY", "none")
        result = subprocess.run(
            ["ssh-add", str(key_path)],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "ssh-add failed").strip()
            return False, detail
        return True, ""
    finally:
        for tmp in (askpass_script, pass_file):
            if tmp:
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass


def read_public_key(key_path, passphrase=""):
    pub_path = pathlib.Path(str(key_path) + ".pub")
    if pub_path.exists():
        return pub_path.read_text().strip()

    env = os.environ.copy()
    askpass_script = None
    pass_file = None
    if passphrase:
        pass_file = tempfile.NamedTemporaryFile("w", delete=False)
        pass_file.write(passphrase)
        pass_file.flush()
        os.fchmod(pass_file.fileno(), 0o600)
        pass_file.close()

        askpass_script = tempfile.NamedTemporaryFile("w", delete=False)
        askpass_script.write("#!/bin/sh\ncat \"%s\"\n" % pass_file.name)
        askpass_script.flush()
        os.fchmod(askpass_script.fileno(), 0o700)
        askpass_script.close()
        env["SSH_ASKPASS"] = askpass_script.name
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["DISPLAY"] = env.get("DISPLAY", "none")
    try:
        output = subprocess.check_output(
            ["ssh-keygen", "-y", "-f", str(key_path)],
            text=True,
            env=env,
            stdin=subprocess.DEVNULL,
        )
        return output.strip()
    except Exception:
        return None
    finally:
        for tmp in (askpass_script, pass_file):
            if tmp:
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass


def detect_lan_cidrs():
    try:
        output = subprocess.check_output(
            ["ip", "-o", "-f", "inet", "addr", "show"],
            text=True,
        )
    except Exception:
        return []

    skip_prefixes = ("docker", "veth", "virbr", "br-", "wg", "tun", "tap")
    cidrs = []
    for line in output.splitlines():
        parts = line.split()
        if "inet" not in parts:
            continue
        ifname = parts[1]
        if ifname == "lo" or ifname.startswith(skip_prefixes):
            continue
        try:
            inet_index = parts.index("inet")
            addr = parts[inet_index + 1]
            iface = ipaddress.IPv4Interface(addr)
        except (ValueError, IndexError):
            continue
        if iface.ip.is_loopback or iface.ip.is_link_local:
            continue
        cidr = str(iface.network)
        if cidr not in cidrs:
            cidrs.append(cidr)
    return cidrs


def detect_wg_ips():
    try:
        output = subprocess.check_output(
            ["ip", "-o", "-f", "inet", "addr", "show"],
            text=True,
        )
    except Exception:
        return {}

    wg_ips = {}
    for line in output.splitlines():
        parts = line.split()
        if "inet" not in parts:
            continue
        ifname = parts[1]
        if not ifname.startswith("wg"):
            continue
        try:
            inet_index = parts.index("inet")
            addr = parts[inet_index + 1]
        except (ValueError, IndexError):
            continue
        ip = addr.split("/")[0]
        if ip and ifname not in wg_ips:
            wg_ips[ifname] = ip
    return wg_ips



def read_log_tail(path):
    if not path.exists():
        return ""
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        offset = max(0, size - MAX_LOG_BYTES)
        handle.seek(offset)
        data = handle.read().decode("utf-8", errors="replace")
        return data


class PortalState:
    def __init__(self, repo_root):
        self.repo_root = repo_root
        self.output_root = OUTPUT_ROOT
        self.portal_root = repo_root / "portal"
        self.jobs_dir = repo_root / "tmp" / "portal_jobs"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.jobs_dir, 0o700)
        self.output_root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.allowed_actions = self._build_actions()
        self.destructive_actions = {"tf-apply", "tf-destroy", "tf-cf-apply", "tf-cf-destroy"}

    def _build_actions(self):
        inventory_path = str(self.output_root / "ansible" / "hosts.ini")
        tfvars_path = str(OUTPUT_TFVARS_PATH)
        tfvars_cf_path = str(OUTPUT_TFVARS_CF_PATH)
        ansible_env = {
            "ANSIBLE_CONFIG": "./ansible.cfg",
            "ANSIBLE_HOST_KEY_CHECKING": "False",
            "ANSIBLE_SSH_COMMON_ARGS": (
                "-o StrictHostKeyChecking=no "
                "-o UserKnownHostsFile=/dev/null "
                "-o LogLevel=ERROR "
                "-o ServerAliveInterval=20 "
                "-o ServerAliveCountMax=3 "
                "-o ConnectTimeout=10 "
                "-o ConnectionAttempts=3"
            ),
            "IAC_CONFIG_DIR": str(self.output_root),
        }
        aws_credentials = pathlib.Path("~/.aws/credentials").expanduser()
        aws_config = pathlib.Path("~/.aws/config").expanduser()
        terraform_env = {
            "TF_IN_AUTOMATION": "1",
            "AWS_SHARED_CREDENTIALS_FILE": str(aws_credentials),
            "AWS_CONFIG_FILE": str(aws_config),
            "AWS_SDK_LOAD_CONFIG": "1",
        }
        ansible_base = [
            "ansible-playbook",
            "-i",
            inventory_path,
            "ansible/site.yml",
            "--tags",
            "base",
        ]
        ansible_cloudflared = [
            "ansible-playbook",
            "-i",
            inventory_path,
            "ansible/site.yml",
            "-l",
            "vps",
            "--tags",
            "cloudflared",
        ]
        ansible_portctl = [
            "ansible-playbook",
            "-i",
            inventory_path,
            "ansible/site.yml",
            "-l",
            "vps",
            "--tags",
            "portctl",
        ]
        ansible_vps = [
            "ansible-playbook",
            "-i",
            inventory_path,
            "ansible/site.yml",
            "-l",
            "vps",
        ]
        ansible_ec2 = [
            "ansible-playbook",
            "-i",
            inventory_path,
            "ansible/site.yml",
            "-l",
            "ec2",
        ]
        ansible_onprem = [
            "ansible-playbook",
            "-i",
            inventory_path,
            "ansible/site.yml",
            "-l",
            "onprem",
        ]
        ansible_failover_core = [
            "ansible-playbook",
            "-i",
            inventory_path,
            "ansible/site.yml",
            "-l",
            "onprem",
            "--tags",
            "failover_core",
            "-e",
            "failover_core_manage=true",
            "-e",
            "failover_core_enable=true",
            "-e",
            "failover_core_state=started",
        ]
        ansible_vps_check = ansible_vps + ["--check"]
        terraform_dir = self.repo_root / "terraform"
        terraform_cf_dir = self.repo_root / "terraform-cloudflare"

        return {
            "validate": {
                "cmd": ["./scripts/validate.sh"],
                "cwd": self.repo_root,
                "env": ansible_env,
            },
            "install-tools": {
                "cmd": ["bash", "-lc", "./scripts/install_tools.sh"],
                "cwd": self.repo_root,
                "env": {"DEBIAN_FRONTEND": "noninteractive"},
            },
            "ansible-base": {
                "cmd": ansible_base,
                "cwd": self.repo_root,
                "env": ansible_env,
            },
            "ansible-cloudflared": {
                "cmd": ansible_cloudflared,
                "cwd": self.repo_root,
                "env": ansible_env,
                "retry": {
                    "enabled": True,
                    "retries": 2,
                    "delay": 10,
                    "patterns": [
                        "Failed to connect to the host via ssh",
                        "Connection timed out",
                        "Connection closed by remote host",
                        "kex_exchange_identification",
                        "Host key verification failed",
                        "ssh: connect to host",
                    ],
                },
            },
            "ansible-portctl": {
                "cmd": ansible_portctl,
                "cwd": self.repo_root,
                "env": ansible_env,
            },
            "ansible-vps": {
                "cmd": ansible_vps,
                "cwd": self.repo_root,
                "env": ansible_env,
            },
            "ansible-ec2": {
                "cmd": ansible_ec2,
                "cwd": self.repo_root,
                "env": ansible_env,
            },
            "ansible-onprem": {
                "cmd": ansible_onprem,
                "cwd": self.repo_root,
                "env": ansible_env,
            },
            "ansible-failover-core": {
                "cmd": ansible_failover_core,
                "cwd": self.repo_root,
                "env": ansible_env,
            },
            "ansible-vps-check": {
                "cmd": ansible_vps_check,
                "cwd": self.repo_root,
                "env": ansible_env,
            },
            "tf-init": {
                "cmd": ["terraform", "init"],
                "cwd": terraform_dir,
                "env": terraform_env,
            },
            "tf-plan": {
                "cmd": ["bash", "-lc", f"terraform init -input=false && terraform plan -input=false -var-file={tfvars_path}"],
                "cwd": terraform_dir,
                "env": terraform_env,
            },
            "tf-apply": {
                "cmd": ["bash", "-lc", f"terraform init -input=false && terraform apply -input=false -auto-approve -var-file={tfvars_path}"],
                "cwd": terraform_dir,
                "env": terraform_env,
            },
            "tf-destroy": {
                "cmd": ["bash", "-lc", f"terraform init -input=false && terraform destroy -input=false -auto-approve -var-file={tfvars_path}"],
                "cwd": terraform_dir,
                "env": terraform_env,
            },
            "tf-cf-init": {
                "cmd": ["terraform", "init"],
                "cwd": terraform_cf_dir,
                "env": terraform_env,
            },
            "tf-cf-plan": {
                "cmd": ["bash", "-lc", f"terraform init -input=false && terraform plan -input=false -var-file={tfvars_cf_path}"],
                "cwd": terraform_cf_dir,
                "env": terraform_env,
            },
            "tf-cf-apply": {
                "cmd": ["bash", "-lc", f"terraform init -input=false && terraform apply -input=false -auto-approve -var-file={tfvars_cf_path}"],
                "cwd": terraform_cf_dir,
                "env": terraform_env,
            },
            "tf-cf-destroy": {
                "cmd": ["bash", "-lc", f"terraform init -input=false && terraform destroy -input=false -auto-approve -var-file={tfvars_cf_path}"],
                "cwd": terraform_cf_dir,
                "env": terraform_env,
            },
        }

    def any_running(self):
        for job_file in self.jobs_dir.glob("*.json"):
            job = read_json(job_file)
            if job and job.get("status") == "running":
                return True
        return False

    def create_job(self, action, command, cwd, env, cleanup=False, retry=None):
        job_id = f"job_{uuid.uuid4().hex[:8]}"
        log_path = self.jobs_dir / f"{job_id}.log"
        job_path = self.jobs_dir / f"{job_id}.json"
        job = {
            "id": job_id,
            "action": action,
            "status": "running",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "log_path": str(log_path),
            "command": command,
            "cwd": str(cwd),
            "cleanup": bool(cleanup),
            "retry": retry or {},
        }
        write_json(job_path, job)

        def runner():
            combined_env = os.environ.copy()
            combined_env.update(env or {})
            with log_path.open("w", encoding="utf-8") as log:
                log.write(f"Action: {action}\n")
                log.write(f"Command: {' '.join(command)}\n")
                log.write(f"Working dir: {cwd}\n\n")
                log.flush()
                attempts = 1
                retry_enabled = bool(retry and retry.get("enabled"))
                if retry_enabled:
                    attempts += max(0, int(retry.get("retries", 0)))
                delay = int(retry.get("delay", 5)) if retry_enabled else 0
                patterns = retry.get("patterns", []) if retry_enabled else []
                return_code = 1
                attempt = 1
                while attempt <= attempts:
                    if attempt > 1:
                        log.write(f"\nRetrying ({attempt}/{attempts}) after {delay}s...\n")
                        log.flush()
                        time.sleep(delay)
                    attempt_start = log.tell()
                    try:
                        process = __import__("subprocess").Popen(
                            command,
                            cwd=str(cwd),
                            stdout=log,
                            stderr=log,
                            env=combined_env,
                        )
                        return_code = process.wait()
                    except Exception as exc:  # pragma: no cover
                        log.write(f"\nExecution error: {exc}\n")
                        return_code = 1
                    log.flush()
                    if return_code == 0:
                        break
                    if not patterns or attempt >= attempts:
                        break
                    try:
                        with log_path.open("r", encoding="utf-8", errors="replace") as reader:
                            reader.seek(attempt_start)
                            attempt_text = reader.read()
                    except Exception:
                        attempt_text = ""
                    if not any(pat in attempt_text for pat in patterns):
                        break
                    attempt += 1
                if return_code == 0 and action in {"tf-apply", "tf-cf-apply"}:
                    try:
                        inventory_text = OUTPUT_INVENTORY_PATH.read_text(encoding="utf-8", errors="replace") if OUTPUT_INVENTORY_PATH.exists() else ""
                        group_vars_text = OUTPUT_GROUP_VARS_PATH.read_text(encoding="utf-8", errors="replace") if OUTPUT_GROUP_VARS_PATH.exists() else ""
                        saved = maybe_write_failover_host_vars(self.output_root, self.repo_root, inventory_text, group_vars_text)
                        if saved:
                            log.write("\nPortal updated failover host_vars:\n")
                            for rel_path in saved:
                                log.write(f"- {rel_path}\n")
                        cloudflared_saved = maybe_write_cloudflared_host_vars(self.output_root, self.repo_root, inventory_text, group_vars_text)
                        if cloudflared_saved:
                            log.write("\nPortal updated cloudflared host_vars:\n")
                            for rel_path in cloudflared_saved:
                                log.write(f"- {rel_path}\n")
                    except Exception as exc:
                        log.write(f"\nPortal failed to update failover host_vars: {exc}\n")

                if return_code == 0 and cleanup:
                    removed = cleanup_secrets(include_persistent=False)
                    if removed:
                        log.write("\nCleanup removed files:\n")
                        for path in removed:
                            log.write(f"- {path}\n")
                    else:
                        log.write("\nCleanup: no files removed.\n")
            job_update = read_json(job_path) or job
            job_update["status"] = "success" if return_code == 0 else "failed"
            job_update["return_code"] = return_code
            job_update["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            write_json(job_path, job_update)

        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        return job

    def list_jobs(self):
        jobs = []
        for job_file in sorted(self.jobs_dir.glob("*.json")):
            job = read_json(job_file)
            if job:
                jobs.append(job)
        return jobs

    def get_job(self, job_id):
        job_path = self.jobs_dir / f"{job_id}.json"
        return read_json(job_path)


class PortalHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, directory=None, state=None, **kwargs):
        self.state = state
        super().__init__(*args, directory=directory, **kwargs)

    def _token_required(self):
        token = os.environ.get("PORTAL_UPLOAD_TOKEN", "")
        return token

    def _check_token(self, payload=None):
        token = self._token_required()
        if not token:
            return False, "Upload token not set"
        header_token = self.headers.get("X-Portal-Token", "")
        if header_token and header_token == token:
            return True, ""
        if payload and payload.get("token") == token:
            return True, ""
        return False, "Invalid token"

    def do_POST(self):
        if self.path == "/upload":
            self._handle_upload()
            return
        if self.path == "/api/save":
            self._handle_save()
            return
        if self.path == "/api/keygen":
            self._handle_keygen()
            return
        if self.path == "/api/cloudflare-token":
            self._handle_cloudflare_token()
            return
        if self.path == "/api/cleanup":
            self._handle_cleanup()
            return
        if self.path == "/api/aws-credentials":
            self._handle_aws_credentials()
            return
        if self.path == "/api/run":
            self._handle_run()
            return
        response_json(self, 404, {"ok": False, "error": "Not found"})

    def do_GET(self):
        if self.path.startswith("/api/terraform-output"):
            self._handle_terraform_output()
            return
        if self.path.startswith("/api/status"):
            self._handle_status()
            return
        if self.path.startswith("/api/jobs"):
            self._handle_jobs()
            return
        super().do_GET()

    def _handle_upload(self):
        token = self._token_required()
        if not token:
            response_json(self, 500, {"ok": False, "error": "Upload token not set"})
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length > MAX_UPLOAD_BYTES + 4096:
            response_json(self, 413, {"ok": False, "error": "File too large"})
            return

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            response_json(self, 400, {"ok": False, "error": "Invalid content type"})
            return

        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": content_type,
            },
        )

        form_token = form.getfirst("token", "")
        if form_token != token:
            response_json(self, 403, {"ok": False, "error": "Invalid token"})
            return

        target = form.getfirst("target", "")
        if target not in ALLOWED_UPLOAD_TARGETS:
            response_json(self, 400, {"ok": False, "error": "Invalid target"})
            return

        if "file" not in form:
            response_json(self, 400, {"ok": False, "error": "No file provided"})
            return

        file_item = form["file"]
        if not getattr(file_item, "file", None):
            response_json(self, 400, {"ok": False, "error": "Invalid file"})
            return

        data = file_item.file.read(MAX_UPLOAD_BYTES + 1)
        if not data:
            response_json(self, 400, {"ok": False, "error": "Empty file"})
            return
        if len(data) > MAX_UPLOAD_BYTES:
            response_json(self, 413, {"ok": False, "error": "File too large"})
            return

        key_name = sanitize_key_name(form.getfirst("key_name", ""), ALLOWED_UPLOAD_TARGETS[target])
        passphrase = form.getfirst("passphrase", "")
        ssh_dir = pathlib.Path("~/.ssh").expanduser()
        ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        target_path = ssh_dir / key_name
        target_path.write_bytes(data)
        os.chmod(target_path, 0o600)
        record_secret_path(target_path, persistent=True)

        agent_error = ""
        if passphrase:
            ok, error = add_key_to_agent(target_path, passphrase)
            if not ok:
                agent_error = error

        response_json(
            self,
            200,
            {
                "ok": True,
                "path": str(target_path),
                "agent_error": agent_error,
            },
        )


    def _handle_keygen(self):
        token_ok, message = self._check_token()
        if not token_ok:
            response_json(self, 403, {"ok": False, "error": message})
            return

        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            response_json(self, 400, {"ok": False, "error": "Invalid JSON"})
            return

        key_name = sanitize_key_name(payload.get("key_name", ""), ALLOWED_UPLOAD_TARGETS["ec2"])
        passphrase = payload.get("passphrase", "")
        ssh_dir = pathlib.Path("~/.ssh").expanduser()
        ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        key_path = ssh_dir / key_name
        created = False

        if not key_path.exists():
            cmd = ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", passphrase]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "ssh-keygen failed").strip()
                response_json(self, 500, {"ok": False, "error": detail})
                return
            os.chmod(key_path, 0o600)
            pub_path = pathlib.Path(str(key_path) + ".pub")
            if pub_path.exists():
                os.chmod(pub_path, 0o644)
            created = True
            record_secret_path(key_path, persistent=True)
            if pub_path.exists():
                record_secret_path(pub_path, persistent=True)

        public_key = read_public_key(key_path, passphrase)
        if not public_key:
            response_json(self, 500, {"ok": False, "error": "Public key unavailable"})
            return

        agent_error = ""
        if passphrase:
            ok, error = add_key_to_agent(key_path, passphrase)
            if not ok:
                agent_error = error

        response_json(
            self,
            200,
            {
                "ok": True,
                "created": created,
                "path": str(key_path),
                "public_key": public_key,
                "agent_error": agent_error,
            },
        )

    def _handle_cloudflare_token(self):
        token_ok, message = self._check_token()
        if not token_ok:
            response_json(self, 403, {"ok": False, "error": message})
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length > MAX_UPLOAD_BYTES + 4096:
            response_json(self, 413, {"ok": False, "error": "File too large"})
            return

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            response_json(self, 400, {"ok": False, "error": "Invalid content type"})
            return

        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": content_type,
            },
        )

        token_value = (form.getfirst("token", "") or "").strip()
        if "file" in form and getattr(form["file"], "file", None):
            data = form["file"].file.read(MAX_UPLOAD_BYTES + 1)
            if len(data) > MAX_UPLOAD_BYTES:
                response_json(self, 413, {"ok": False, "error": "File too large"})
                return
            try:
                token_value = data.decode("utf-8").strip()
            except UnicodeDecodeError:
                response_json(self, 400, {"ok": False, "error": "Invalid token encoding"})
                return

        if not token_value:
            response_json(self, 400, {"ok": False, "error": "Token is empty"})
            return

        token_path = write_cloudflare_token(token_value)
        response_json(
            self,
            200,
            {"ok": True, "path": str(token_path)},
        )

    def _handle_cleanup(self):
        token_ok, message = self._check_token()
        if not token_ok:
            response_json(self, 403, {"ok": False, "error": message})
            return
        removed = cleanup_secrets(include_persistent=True)
        response_json(self, 200, {"ok": True, "removed": removed})

    def _handle_aws_credentials(self):
        token_ok, message = self._check_token()
        if not token_ok:
            response_json(self, 403, {"ok": False, "error": message})
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length > MAX_UPLOAD_BYTES + 4096:
            response_json(self, 413, {"ok": False, "error": "File too large"})
            return

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            response_json(self, 400, {"ok": False, "error": "Invalid content type"})
            return

        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": content_type,
            },
        )

        file_item = form["file"] if "file" in form else None
        if isinstance(file_item, list):
            file_item = file_item[0] if file_item else None
        if file_item is None or getattr(file_item, "file", None) is None:
            response_json(self, 400, {"ok": False, "error": "No file provided"})
            return

        data = file_item.file.read(MAX_UPLOAD_BYTES + 1)
        if not data:
            response_json(self, 400, {"ok": False, "error": "Empty file"})
            return
        if len(data) > MAX_UPLOAD_BYTES:
            response_json(self, 413, {"ok": False, "error": "File too large"})
            return

        profile = sanitize_profile_name(form.getfirst("profile", "default"), "default")
        region = (form.getfirst("region", "") or "").strip()

        creds, error = parse_aws_credentials_csv(data)
        if not creds:
            response_json(self, 400, {"ok": False, "error": error})
            return

        credentials_path = write_aws_credentials(
            profile,
            creds["access_key_id"],
            creds["secret_access_key"],
        )
        config_path = write_aws_config(profile, region)

        response_json(
            self,
            200,
            {
                "ok": True,
                "profile": profile,
                "credentials_path": str(credentials_path),
                "config_path": str(config_path) if config_path else "",
                "region": region,
            },
        )


    def _handle_save(self):
        token_ok, message = self._check_token()
        if not token_ok:
            response_json(self, 403, {"ok": False, "error": message})
            return

        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            response_json(self, 400, {"ok": False, "error": "Invalid JSON"})
            return

        files = payload.get("files")
        setup_mode = payload.get("mode", "custom")
        secrets = payload.get("secrets", {})
        if not isinstance(secrets, dict):
            secrets = {}
        if not isinstance(files, dict) or not files:
            response_json(self, 400, {"ok": False, "error": "No files provided"})
            return

        if setup_mode == "beginner":
            ensure_vault_pass()

        saved = {}
        errors = {}
        warnings = {}
        for rel_path, content in files.items():
            if rel_path not in ALLOWED_SAVE_TARGETS:
                errors[rel_path] = "Path not allowed"
                continue
            if not isinstance(content, str):
                errors[rel_path] = "Invalid content"
                continue
            encoded = content.encode("utf-8")
            if len(encoded) > MAX_SAVE_BYTES:
                errors[rel_path] = "File too large"
                continue
            abs_path = resolve_output_path(self.state.output_root, rel_path)
            if not abs_path:
                errors[rel_path] = "Invalid path"
                continue
            abs_path.parent.mkdir(parents=True, exist_ok=True)
            abs_path.write_text(content, encoding="utf-8")
            saved[rel_path] = {"bytes": len(encoded)}

        if errors:
            response_json(self, 400, {"ok": False, "error": "Failed to save some files", "details": errors, "saved": saved})
            return

        group_vars_text = files.get("ansible/group_vars/all.yml", "")
        inventory_text = files.get("ansible/hosts.ini", "")
        extra_saved = maybe_write_suricata_host_vars(self.state.output_root, self.state.repo_root, inventory_text, group_vars_text)
        if extra_saved:
            saved.update(extra_saved)

        failover_saved = maybe_write_failover_host_vars(self.state.output_root, self.state.repo_root, inventory_text, group_vars_text)
        if failover_saved:
            saved.update(failover_saved)

        cloudflared_saved = maybe_write_cloudflared_host_vars(self.state.output_root, self.state.repo_root, inventory_text, group_vars_text)
        if cloudflared_saved:
            saved.update(cloudflared_saved)
        if parse_yaml_bool(group_vars_text, "cloudflared_manage"):
            groups = inventory_cloudflared_groups(inventory_text)
            if groups:
                missing = cloudflared_host_vars_missing(self.state.output_root, groups)
                if missing:
                    warnings["cloudflared"] = {
                        "message": (
                            "Cloudflared host_vars not generated yet. "
                            "Run Cloudflare Apply (tf-cf-apply) then Save to generate."
                        ),
                        "details": missing,
                    }

        auto_saved, auto_errors, wg_outputs = maybe_write_auto_host_vars(
            self.state.output_root,
            inventory_text,
            group_vars_text,
            secrets,
            setup_mode,
        )
        if auto_saved:
            saved.update(auto_saved)

        response_json(
            self,
            200,
            {
                "ok": True,
                "saved": saved,
                "imported": auto_saved,
                "import_errors": auto_errors,
                "warnings": warnings,
                "wireguard_configs": wg_outputs,
            },
        )

    def _handle_run(self):
        token_ok, message = self._check_token()
        if not token_ok:
            response_json(self, 403, {"ok": False, "error": message})
            return

        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            response_json(self, 400, {"ok": False, "error": "Invalid JSON"})
            return

        action = payload.get("action", "")
        confirm = payload.get("confirm", "")
        cleanup = bool(payload.get("cleanup"))
        if action not in self.state.allowed_actions:
            response_json(self, 400, {"ok": False, "error": "Action not allowed"})
            return

        if action == "ansible-failover-core":
            inventory_text = OUTPUT_INVENTORY_PATH.read_text(encoding="utf-8", errors="replace") if OUTPUT_INVENTORY_PATH.exists() else ""
            group_vars_text = OUTPUT_GROUP_VARS_PATH.read_text(encoding="utf-8", errors="replace") if OUTPUT_GROUP_VARS_PATH.exists() else ""
            maybe_write_failover_host_vars(self.state.output_root, self.state.repo_root, inventory_text, group_vars_text, force=True)
            failover_path = resolve_output_path(self.state.output_root, FAILOVER_HOST_VARS_REL)
            if not failover_path or not failover_path.exists():
                response_json(
                    self,
                    400,
                    {"ok": False, "error": "Failover host_vars not ready. Terraform outputs/Cloudflare token are missing."},
                )
                return

        if action in self.state.destructive_actions:
            if action == "tf-apply" and confirm != "APPLY":
                response_json(self, 400, {"ok": False, "error": "Confirm word required (APPLY)"})
                return
            if action == "tf-destroy" and confirm != "DESTROY":
                response_json(self, 400, {"ok": False, "error": "Confirm word required (DESTROY)"})
                return

        if action.startswith("ansible") or action == "validate":
            ensure_vault_pass()

        if action == "ansible-cloudflared":
            inventory_text = OUTPUT_INVENTORY_PATH.read_text(encoding="utf-8", errors="replace") if OUTPUT_INVENTORY_PATH.exists() else ""
            group_vars_text = OUTPUT_GROUP_VARS_PATH.read_text(encoding="utf-8", errors="replace") if OUTPUT_GROUP_VARS_PATH.exists() else ""
            if parse_yaml_bool(group_vars_text, "cloudflared_manage"):
                saved_cloudflared = maybe_write_cloudflared_host_vars(self.state.output_root, self.state.repo_root, inventory_text, group_vars_text)
                groups = inventory_cloudflared_groups(inventory_text)
                if groups:
                    missing = cloudflared_host_vars_missing(self.state.output_root, groups)
                    if missing:
                        response_json(
                            self,
                            400,
                            {
                                "ok": False,
                                "error": (
                                    "Cloudflared host_vars missing. "
                                    "Run Cloudflare Apply (tf-cf-apply) then Save. (Cloudflare適用→保存が必要です)"
                                ),
                                "details": missing,
                            },
                        )
                        return

        if action in {'tf-plan', 'tf-apply', 'tf-destroy'}:
            if not OUTPUT_TFVARS_PATH.exists():
                response_json(
                    self,
                    400,
                    {'ok': False, 'error': 'terraform.tfvars not found. 先にファイル生成→保存してください。'},
                )
                return
        if action in {'tf-cf-plan', 'tf-cf-apply', 'tf-cf-destroy'}:
            if not OUTPUT_TFVARS_CF_PATH.exists():
                response_json(
                    self,
                    400,
                    {'ok': False, 'error': 'terraform-cloudflare.tfvars not found. 先にファイル生成→保存してください。'},
                )
                return
        missing_tools = missing_tools_for_action(action)
        if missing_tools:
            response_json(
                self,
                400,
                {"ok": False, "error": f"Missing tools: {', '.join(missing_tools)} (必要ツールが見つかりません。インストールして再実行してください)"},
            )
            return
        with self.state.lock:
            if self.state.any_running():
                response_json(self, 409, {"ok": False, "error": "Another job is running"})
                return
            info = self.state.allowed_actions[action]
            env = dict(info.get("env", {}))
            if action.startswith("tf-"):
                aws_credentials = pathlib.Path("~/.aws/credentials").expanduser()
                aws_config = pathlib.Path("~/.aws/config").expanduser()
                if aws_credentials.exists():
                    env["AWS_SHARED_CREDENTIALS_FILE"] = str(aws_credentials)
                if aws_config.exists():
                    env["AWS_CONFIG_FILE"] = str(aws_config)
                    env["AWS_SDK_LOAD_CONFIG"] = "1"
                else:
                    env.pop("AWS_CONFIG_FILE", None)
                    env["AWS_SDK_LOAD_CONFIG"] = "0"
                profile = read_tfvars_value(OUTPUT_TFVARS_PATH, "aws_profile")
                if profile:
                    env["AWS_PROFILE"] = profile
                    env["AWS_DEFAULT_PROFILE"] = profile
            if action.startswith("tf-cf"):
                cf_token = read_cloudflare_token()
                if not cf_token:
                    response_json(
                        self,
                        400,
                        {"ok": False, "error": "Cloudflare API token not saved. 先にトークンを保存してください。"},
                    )
                    return
                env["CLOUDFLARE_API_TOKEN"] = cf_token
            job = self.state.create_job(action, info["cmd"], info["cwd"], env, cleanup, info.get("retry"))

        response_json(self, 200, {"ok": True, "job_id": job["id"]})


    def _handle_status(self):
        token_ok, message = self._check_token()
        if not token_ok:
            response_json(self, 403, {"ok": False, "error": message})
            return
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        onprem_key = sanitize_key_name(params.get("onprem_key", [""])[0], ALLOWED_UPLOAD_TARGETS["onprem"])
        vps_key = sanitize_key_name(params.get("vps_key", [""])[0], ALLOWED_UPLOAD_TARGETS["vps"])
        ec2_key = sanitize_key_name(params.get("ec2_key", [""])[0], ALLOWED_UPLOAD_TARGETS["ec2"])

        files = {}
        for rel_path in ALLOWED_SAVE_TARGETS:
            abs_path = resolve_output_path(self.state.output_root, rel_path)
            if abs_path and abs_path.exists():
                files[rel_path] = {"exists": True, "bytes": abs_path.stat().st_size, "path": str(abs_path)}
            else:
                files[rel_path] = {"exists": False, "bytes": 0, "path": str(abs_path) if abs_path else ""}

        vault_pass_path = pathlib.Path(VAULT_PASS_PATH).expanduser()
        vault_pass = {
            "path": VAULT_PASS_PATH,
            "exists": vault_pass_path.exists(),
        }

        vault_files = {}
        for rel_path in [
            "ansible/host_vars/onprem-1.yml",
            "ansible/host_vars/vps-1.yml",
            "ansible/host_vars/ec2-1.yml",
        ]:
            abs_path = resolve_output_path(self.state.output_root, rel_path)
            vault_files[rel_path] = {
                "exists": bool(abs_path and abs_path.exists()),
                "path": str(abs_path) if abs_path else "",
            }

        ssh_keys = {}
        key_paths = {
            "ansible": f"~/.ssh/{onprem_key}",
            "vps": f"~/.ssh/{vps_key}",
            "ec2": f"~/.ssh/{ec2_key}",
        }
        for name, rel_path in key_paths.items():
            key_path = pathlib.Path(rel_path).expanduser()
            ssh_keys[name] = {
                "path": str(key_path),
                "exists": key_path.exists(),
            }

        tools = {
            "ansible": shutil.which("ansible") is not None,
            "ansible-playbook": shutil.which("ansible-playbook") is not None,
            "terraform": shutil.which("terraform") is not None,
            "ssh": shutil.which("ssh") is not None,
            "ssh-keygen": shutil.which("ssh-keygen") is not None,
            "ssh-keyscan": shutil.which("ssh-keyscan") is not None,
            "python3": shutil.which("python3") is not None,
        }

        aws_credentials_path = pathlib.Path("~/.aws/credentials").expanduser()
        aws_config_path = pathlib.Path("~/.aws/config").expanduser()
        cf_token_path = CLOUDFLARE_TOKEN_PATH.expanduser()
        secrets = {
            "aws_credentials": {
                "path": str(aws_credentials_path),
                "exists": aws_credentials_path.exists(),
            },
            "aws_config": {
                "path": str(aws_config_path),
                "exists": aws_config_path.exists(),
            },
            "cloudflare_token": {
                "path": str(cf_token_path),
                "exists": cf_token_path.exists(),
            },
        }

        response_json(
            self,
            200,
            {
                "ok": True,
                "output_root": str(self.state.output_root),
                "files": files,
                "vault_pass": vault_pass,
                "vault_files": vault_files,
                "ssh_keys": ssh_keys,
                "lan_cidrs": detect_lan_cidrs(),
                "wg_ips": detect_wg_ips(),
                "tools": tools,
                "secrets": secrets,
            },
        )

    def _handle_terraform_output(self):
        token_ok, message = self._check_token()
        if not token_ok:
            response_json(self, 403, {"ok": False, "error": message})
            return

        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        stack = (params.get("stack", ["ec2"])[0] or "ec2").strip().lower()
        if stack not in {"ec2", "cloudflare"}:
            response_json(self, 400, {"ok": False, "error": "Invalid stack"})
            return

        if stack == "cloudflare":
            tf_dir = self.state.repo_root / "terraform-cloudflare"
            outputs = terraform_output_json(tf_dir)
            response_json(
                self,
                200,
                {
                    "ok": True,
                    "stack": "cloudflare",
                    "outputs": {
                        "zone_id": terraform_output_value(outputs, "zone_id") or "",
                        "zone_name": terraform_output_value(outputs, "zone_name") or "",
                        "failover_record_id": terraform_output_value(outputs, "failover_record_id") or "",
                        "failover_record_name": terraform_output_value(outputs, "failover_record_name") or "",
                        "vps_tunnel_id": terraform_output_value(outputs, "vps_tunnel_id") or "",
                        "ec2_tunnel_id": terraform_output_value(outputs, "ec2_tunnel_id") or "",
                        "vps_tunnel_credentials_json": terraform_output_value(outputs, "vps_tunnel_credentials_json") or "",
                        "ec2_tunnel_credentials_json": terraform_output_value(outputs, "ec2_tunnel_credentials_json") or "",
                    },
                },
            )
            return

        tf_dir = self.state.repo_root / "terraform"
        outputs = terraform_output_json(tf_dir)
        response_json(
            self,
            200,
            {
                "ok": True,
                "stack": "ec2",
                "outputs": {
                    "public_ip": terraform_output_value(outputs, "public_ip") or "",
                    "elastic_ip": terraform_output_value(outputs, "elastic_ip") or "",
                    "instance_id": terraform_output_value(outputs, "instance_id") or "",
                    "failover_access_key_id": terraform_output_value(outputs, "failover_access_key_id") or "",
                    "failover_secret_access_key": terraform_output_value(outputs, "failover_secret_access_key") or "",
                },
            },
        )

    def _handle_jobs(self):
        token_ok, message = self._check_token()
        if not token_ok:
            response_json(self, 403, {"ok": False, "error": message})
            return

        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) == 2:
            jobs = self.state.list_jobs()
            response_json(self, 200, {"ok": True, "jobs": jobs})
            return
        if len(parts) >= 3:
            job_id = parts[2]
            job = self.state.get_job(job_id)
            if not job:
                response_json(self, 404, {"ok": False, "error": "Job not found"})
                return
            if len(parts) == 4 and parts[3] == "logs":
                log_path = pathlib.Path(job.get("log_path", ""))
                response_json(self, 200, {"ok": True, "log": read_log_tail(log_path)})
                return
            response_json(self, 200, {"ok": True, "job": job})
            return
        response_json(self, 404, {"ok": False, "error": "Not found"})


def main():
    parser = argparse.ArgumentParser(description="edge-stack portal server")
    parser.add_argument("--bind", default="127.0.0.1", help="Bind address")
    parser.add_argument("--port", type=int, default=8000, help="Port")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parent.parent
    state = PortalState(repo_root)
    handler = lambda *h_args, **h_kwargs: PortalHandler(
        *h_args, directory=str(state.portal_root), state=state, **h_kwargs
    )

    with http.server.ThreadingHTTPServer((args.bind, args.port), handler) as httpd:
        print(f"Serving portal on http://{args.bind}:{args.port}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
