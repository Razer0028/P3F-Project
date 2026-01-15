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




def load_secret_meta():
    data = read_json(SECRETS_META_PATH)
    if isinstance(data, dict) and isinstance(data.get("paths"), list):
        return data
    return {"paths": []}


def record_secret_path(path):
    if not path:
        return
    meta = load_secret_meta()
    entry = str(path)
    if entry not in meta["paths"]:
        meta["paths"].append(entry)
        SECRETS_META_PATH.parent.mkdir(parents=True, exist_ok=True)
        write_json(SECRETS_META_PATH, meta)


def cleanup_secrets():
    meta = load_secret_meta()
    removed = []
    for entry in meta.get("paths", []):
        path = pathlib.Path(entry).expanduser()
        if path.exists():
            try:
                path.unlink()
                removed.append(str(path))
            except OSError:
                pass
    if SECRETS_META_PATH.exists():
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
    record_secret_path(CLOUDFLARE_TOKEN_PATH)
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
    record_secret_path(credentials_path)
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
    record_secret_path(config_path)
    return config_path


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
        ansible_env = {"ANSIBLE_CONFIG": "./ansible.cfg", "IAC_CONFIG_DIR": str(self.output_root)}
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
        ansible_vps_check = ansible_vps + ["--check"]
        terraform_dir = self.repo_root / "terraform"
        terraform_cf_dir = self.repo_root / "terraform-cloudflare"

        return {
            "validate": {
                "cmd": ["./scripts/validate.sh"],
                "cwd": self.repo_root,
                "env": ansible_env,
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
            "ansible-vps-check": {
                "cmd": ansible_vps_check,
                "cwd": self.repo_root,
                "env": ansible_env,
            },
            "tf-init": {
                "cmd": ["terraform", "init"],
                "cwd": terraform_dir,
                "env": {"TF_IN_AUTOMATION": "1"},
            },
            "tf-plan": {
                "cmd": ["bash", "-lc", f"terraform init -input=false && terraform plan -input=false -var-file={tfvars_path}"],
                "cwd": terraform_dir,
                "env": {"TF_IN_AUTOMATION": "1"},
            },
            "tf-apply": {
                "cmd": ["bash", "-lc", f"terraform init -input=false && terraform apply -input=false -auto-approve -var-file={tfvars_path}"],
                "cwd": terraform_dir,
                "env": {"TF_IN_AUTOMATION": "1"},
            },
            "tf-destroy": {
                "cmd": ["bash", "-lc", f"terraform init -input=false && terraform destroy -input=false -auto-approve -var-file={tfvars_path}"],
                "cwd": terraform_dir,
                "env": {"TF_IN_AUTOMATION": "1"},
            },
            "tf-cf-init": {
                "cmd": ["terraform", "init"],
                "cwd": terraform_cf_dir,
                "env": {"TF_IN_AUTOMATION": "1"},
            },
            "tf-cf-plan": {
                "cmd": ["bash", "-lc", f"terraform init -input=false && terraform plan -input=false -var-file={tfvars_cf_path}"],
                "cwd": terraform_cf_dir,
                "env": {"TF_IN_AUTOMATION": "1"},
            },
            "tf-cf-apply": {
                "cmd": ["bash", "-lc", f"terraform init -input=false && terraform apply -input=false -auto-approve -var-file={tfvars_cf_path}"],
                "cwd": terraform_cf_dir,
                "env": {"TF_IN_AUTOMATION": "1"},
            },
            "tf-cf-destroy": {
                "cmd": ["bash", "-lc", f"terraform init -input=false && terraform destroy -input=false -auto-approve -var-file={tfvars_cf_path}"],
                "cwd": terraform_cf_dir,
                "env": {"TF_IN_AUTOMATION": "1"},
            },
        }

    def any_running(self):
        for job_file in self.jobs_dir.glob("*.json"):
            job = read_json(job_file)
            if job and job.get("status") == "running":
                return True
        return False

    def create_job(self, action, command, cwd, env, cleanup=False):
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
                if return_code == 0 and cleanup:
                    removed = cleanup_secrets()
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
        record_secret_path(target_path)

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
            record_secret_path(key_path)
            if pub_path.exists():
                record_secret_path(pub_path)

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
        removed = cleanup_secrets()
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
        if not isinstance(files, dict) or not files:
            response_json(self, 400, {"ok": False, "error": "No files provided"})
            return

        saved = {}
        errors = {}
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

        response_json(self, 200, {"ok": True, "saved": saved})

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

        if action in self.state.destructive_actions:
            if action == "tf-apply" and confirm != "APPLY":
                response_json(self, 400, {"ok": False, "error": "Confirm word required (APPLY)"})
                return
            if action == "tf-destroy" and confirm != "DESTROY":
                response_json(self, 400, {"ok": False, "error": "Confirm word required (DESTROY)"})
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
        with self.state.lock:
            if self.state.any_running():
                response_json(self, 409, {"ok": False, "error": "Another job is running"})
                return
            info = self.state.allowed_actions[action]
            env = dict(info.get("env", {}))
            if action.startswith("tf-cf"):
                cf_token = read_cloudflare_token()
                if cf_token:
                    env["CLOUDFLARE_API_TOKEN"] = cf_token
            job = self.state.create_job(action, info["cmd"], info["cwd"], env, cleanup)

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
            "ansible-playbook": shutil.which("ansible-playbook") is not None,
            "terraform": shutil.which("terraform") is not None,
            "ssh": shutil.which("ssh") is not None,
            "ssh-keyscan": shutil.which("ssh-keyscan") is not None,
            "python3": shutil.which("python3") is not None,
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
