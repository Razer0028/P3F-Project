#!/usr/bin/env python3
import socket
import os
import json
import subprocess
import re
import ipaddress

SOCK_PATH = "/run/portctl.sock"
RULES_FILE = "/opt/portctl/rules.json"
BEFORE_RULES = "/etc/ufw/before.rules"
CONFIG_FILE = "/etc/portctl/config.json"
DEFAULT_DEST_IP = "10.100.0.2"
SKIP_PREFIXES = ("lo", "wg", "docker", "br", "veth", "virbr", "tun", "tap")


def load_rules():
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)


def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)


def validate_port(port_str):
    if ":" in str(port_str):
        parts = str(port_str).split(":")
        if len(parts) != 2:
            return False
        try:
            p1, p2 = int(parts[0]), int(parts[1])
            return 1 <= p1 <= 65535 and 1 <= p2 <= 65535 and p1 <= p2
        except Exception:
            return False
    try:
        p = int(port_str)
        return 1 <= p <= 65535
    except Exception:
        return False


def validate_ip(ip):
    if "/" in ip:
        ip = ip.split("/")[0]
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def is_candidate_interface(name):
    if not name:
        return False
    return not name.startswith(SKIP_PREFIXES)


def parse_default_interface():
    ok, out = run_cmd("ip -4 route show default")
    if not ok:
        return ""
    for line in out.splitlines():
        parts = line.split()
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return ""


def list_global_interfaces():
    ok, out = run_cmd("ip -4 -o addr show scope global")
    if not ok:
        return []
    interfaces = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name = parts[1]
        addr = parts[3].split("/")[0]
        interfaces.append((name, addr))
    return interfaces


def detect_public_interface(config):
    configured = (config.get("public_interface") or "").strip()
    if configured:
        return configured

    default_iface = parse_default_interface()
    if default_iface and is_candidate_interface(default_iface):
        return default_iface

    candidates = list_global_interfaces()
    for name, addr in candidates:
        if not is_candidate_interface(name):
            continue
        try:
            ip = ipaddress.ip_address(addr)
            if not (ip.is_private or ip.is_loopback or ip.is_link_local):
                return name
        except ValueError:
            continue

    for name, _ in candidates:
        if is_candidate_interface(name):
            return name

    if default_iface:
        return default_iface

    try:
        for _, name in socket.if_nameindex():
            if is_candidate_interface(name):
                return name
    except Exception:
        pass

    return "eth0"


def default_dest_ip(config):
    value = (config.get("default_dest_ip") or "").strip()
    return value if value else DEFAULT_DEST_IP


def reload_ufw():
    run_cmd("ufw reload")


def list_forward():
    return {"status": "ok", "rules": load_rules()}


def add_forward(ext_port, protocol, dest_ip, dest_port, force=False):
    config = load_config()
    dest_ip = dest_ip or default_dest_ip(config)
    main_if = detect_public_interface(config)

    if not validate_port(str(ext_port)):
        return {"status": "error", "message": "無効な外部ポート"}
    if not validate_port(str(dest_port)):
        return {"status": "error", "message": "無効な転送先ポート"}
    if not validate_ip(dest_ip):
        return {"status": "error", "message": "無効なIPアドレス"}
    if protocol not in ["tcp", "udp", "both"]:
        return {"status": "error", "message": "プロトコルはtcp/udp/bothのいずれか"}

    rules = load_rules()
    protos = ["tcp", "udp"] if protocol == "both" else [protocol]

    for proto in protos:
        rule_id = f"{ext_port}-{proto}-{dest_ip}-{dest_port}"
        exists = any(r.get("id") == rule_id for r in rules)
        if exists and not force:
            continue

        ufw_cmd = f"ufw route allow proto {proto} from any to {dest_ip} port {dest_port}"
        run_cmd(ufw_cmd)

        if ":" in str(ext_port):
            ports = str(ext_port).split(":")
            dest_ports = str(dest_port).split(":") if ":" in str(dest_port) else [dest_port, dest_port]
            dnat_rule = (
                f"-A PREROUTING -i {main_if} -p {proto} --dport {ports[0]}:{ports[1]} "
                f"-j DNAT --to-destination {dest_ip}:{dest_ports[0]}-{dest_ports[1]}"
            )
        else:
            dnat_rule = (
                f"-A PREROUTING -i {main_if} -p {proto} --dport {ext_port} "
                f"-j DNAT --to-destination {dest_ip}:{dest_port}"
            )

        with open(BEFORE_RULES, "r") as f:
            content = f.read()

        if dnat_rule not in content:
            marker = "*nat"
            if marker not in content:
                nat_block = "*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n\n"
                content = nat_block + content
            new_content = content.replace(marker, marker + "\n" + dnat_rule)
            with open(BEFORE_RULES, "w") as f:
                f.write(new_content)

        if not exists:
            rules.append({
                "id": rule_id,
                "ext_port": str(ext_port),
                "protocol": proto,
                "dest_ip": dest_ip,
                "dest_port": str(dest_port),
            })

    save_rules(rules)
    reload_ufw()
    return {"status": "ok", "message": "ルールを追加しました"}


def apply_existing_rules():
    rules = load_rules()
    if not rules:
        return
    for rule in rules:
        add_forward(
            rule.get("ext_port"),
            rule.get("protocol"),
            rule.get("dest_ip"),
            rule.get("dest_port"),
            force=True,
        )


def delete_forward(rule_id):
    rules = load_rules()
    rule = next((r for r in rules if r.get("id") == rule_id), None)
    if not rule:
        return {"status": "error", "message": "ルールが見つかりません"}

    proto = rule["protocol"]
    dest_ip = rule["dest_ip"]
    dest_port = rule["dest_port"]
    ext_port = rule["ext_port"]

    run_cmd(f"ufw route delete allow proto {proto} from any to {dest_ip} port {dest_port}")

    with open(BEFORE_RULES, "r") as f:
        lines = f.readlines()

    new_lines = [l for l in lines if not (f"--dport {ext_port}" in l and f"--to-destination {dest_ip}" in l)]

    with open(BEFORE_RULES, "w") as f:
        f.writelines(new_lines)

    rules = [r for r in rules if r.get("id") != rule_id]
    save_rules(rules)
    reload_ufw()
    return {"status": "ok", "message": "ルールを削除しました"}


def list_ufw():
    ok, out = run_cmd("ufw status numbered")
    if not ok:
        return {"status": "error", "message": "UFW状態取得失敗"}

    rules = []
    for line in out.split("\n"):
        match = re.match(r"\[\s*(\d+)\]\s+(.+)", line)
        if match:
            rules.append({"num": match.group(1), "rule": match.group(2).strip()})

    return {"status": "ok", "rules": rules}


def add_ufw(rule):
    dangerous = [";", "&&", "||", "|", "`", "$", ">", "<", "\n", "\r"]
    for d in dangerous:
        if d in rule:
            return {"status": "error", "message": "無効な文字が含まれています"}

    if not rule or rule.strip() in ["allow", "deny", "reject", "limit"]:
        return {"status": "error", "message": "ポートまたはIPを指定してください"}

    ok, out = run_cmd(f"ufw {rule}")
    if ok:
        return {"status": "ok", "message": "ルールを追加しました"}
    return {"status": "error", "message": out}


def delete_ufw(num):
    try:
        num = int(num)
    except Exception:
        return {"status": "error", "message": "無効なルール番号"}

    ok, out = run_cmd(f"yes | ufw delete {num}")
    if ok:
        return {"status": "ok", "message": "ルールを削除しました"}
    return {"status": "error", "message": out}


def handle(data):
    try:
        req = json.loads(data)
    except Exception:
        return {"status": "error", "message": "Invalid JSON"}

    action = req.get("action", "")

    handlers = {
        "list_forward": lambda: list_forward(),
        "add_forward": lambda: add_forward(
            req.get("ext_port"), req.get("protocol"), req.get("dest_ip"), req.get("dest_port")
        ),
        "delete_forward": lambda: delete_forward(req.get("id")),
        "list_ufw": lambda: list_ufw(),
        "add_ufw": lambda: add_ufw(req.get("rule")),
        "delete_ufw": lambda: delete_ufw(req.get("num")),
    }

    if action in handlers:
        return handlers[action]()
    return {"status": "error", "message": "Unknown action"}


def main():
    if os.path.exists(SOCK_PATH):
        os.remove(SOCK_PATH)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(SOCK_PATH)
    os.chmod(SOCK_PATH, 0o666)
    sock.listen(5)

    try:
        apply_existing_rules()
    except Exception as e:
        print(f"Failed to apply existing rules: {e}")

    print(f"Agent listening on {SOCK_PATH}")

    while True:
        conn, _ = sock.accept()
        try:
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(chunk) < 4096:
                    break

            if data:
                result = handle(data.decode("utf-8"))
                conn.sendall(json.dumps(result).encode("utf-8"))
        except Exception as e:
            try:
                conn.sendall(json.dumps({"status": "error", "message": str(e)}).encode("utf-8"))
            except Exception:
                pass
        finally:
            conn.close()


if __name__ == "__main__":
    main()
