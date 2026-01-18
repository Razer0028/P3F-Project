#!/usr/bin/env python3
import json
import os
import subprocess
import sys


def run(cmd, env):
    try:
        result = subprocess.run(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return 127, "", "aws cli not found"
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def respond(payload):
    safe = {key: "" if value is None else str(value) for key, value in payload.items()}
    sys.stdout.write(json.dumps(safe))


def main():
    try:
        query = json.load(sys.stdin)
    except json.JSONDecodeError:
        respond({"exists": "false", "error": "invalid json"})
        return

    kind = (query.get("kind") or "").strip()
    name = (query.get("name") or "").strip()
    profile = (query.get("profile") or "").strip()
    region = (query.get("region") or "").strip()

    env = os.environ.copy()
    if profile:
        env["AWS_PROFILE"] = profile
        env["AWS_DEFAULT_PROFILE"] = profile
    if region:
        env["AWS_REGION"] = region
        env["AWS_DEFAULT_REGION"] = region

    if not name:
        respond({"exists": "false"})
        return

    if kind == "key_pair":
        cmd = ["aws", "ec2", "describe-key-pairs", "--key-names", name, "--output", "json"]
        if region:
            cmd.extend(["--region", region])
        code, stdout, stderr = run(cmd, env)
        if code == 0:
            respond({"exists": "true"})
            return
        if "InvalidKeyPair.NotFound" in stderr:
            respond({"exists": "false"})
            return
        respond({"exists": "false", "error": stderr or "lookup failed"})
        return

    if kind == "iam_user":
        cmd = ["aws", "iam", "get-user", "--user-name", name, "--output", "json"]
        code, stdout, stderr = run(cmd, env)
        if code == 0:
            respond({"exists": "true"})
            return
        if "NoSuchEntity" in stderr:
            respond({"exists": "false"})
            return
        respond({"exists": "false", "error": stderr or "lookup failed"})
        return

    if kind == "iam_policy":
        cmd = ["aws", "iam", "list-policies", "--scope", "Local", "--output", "json"]
        code, stdout, stderr = run(cmd, env)
        if code != 0:
            respond({"exists": "false", "error": stderr or "lookup failed"})
            return
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            respond({"exists": "false", "error": "invalid policy json"})
            return
        for policy in payload.get("Policies", []):
            if policy.get("PolicyName") == name:
                respond({"exists": "true", "arn": policy.get("Arn", "")})
                return
        respond({"exists": "false", "arn": ""})
        return

    respond({"exists": "false", "error": "unknown kind"})


if __name__ == "__main__":
    main()
