#!/usr/bin/env python3
"""Run a command with secrets from the macOS keychain injected as environment variables.

    with_secrets.py <secret-name> [<secret-name> ...] -- <command> [args...]

Secret names are the keys under `secrets:` in homelab.yaml. Values never touch the
command line, a file or the conversation; the command's output is filtered so a
secret that gets echoed is replaced by ***REDACTED***.

Secret kinds (secrets.<name>.kind):
  proxmox_token  value "user@realm!tokenid=uuid" → PROXMOX_VE_ENDPOINT, PROXMOX_VE_API_TOKEN (OpenTofu bpg),
                 PROXMOX_URL, PROXMOX_USERNAME, PROXMOX_TOKEN (Packer)
  s3_credentials value "ACCESS_KEY_ID:SECRET_ACCESS_KEY" → AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
                 (OpenTofu S3 state backend — MinIO, Garage, AWS)
  env            plain value → the variable named in secrets.<name>.env (default)
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402


def env_for(cfg: dict, name: str) -> tuple[dict, str]:
    entry = hmlib.secret_entry(cfg, name)
    value = hmlib.read_secret(cfg, name)
    kind = entry.get("kind", "env")
    env: dict[str, str] = {}
    if kind == "proxmox_token":
        endpoint = hmlib.get(cfg, "proxmox.endpoint")
        if not endpoint:
            raise hmlib.ConfigError("proxmox.endpoint is not set in homelab.yaml.")
        if "=" not in value or "!" not in value.split("=", 1)[0]:
            raise hmlib.ConfigError(f"Keychain item for {name!r} must look like user@realm!tokenid=secret.")
        token_id, secret = value.split("=", 1)
        endpoint = endpoint.rstrip("/")
        env.update(PROXMOX_VE_ENDPOINT=endpoint + "/", PROXMOX_VE_API_TOKEN=value,
                   PROXMOX_URL=endpoint + "/api2/json", PROXMOX_USERNAME=token_id, PROXMOX_TOKEN=secret)
        if hmlib.get(cfg, "proxmox.verify_tls", True) is False:
            env.update(PROXMOX_VE_INSECURE="true", PROXMOX_INSECURE_SKIP_TLS_VERIFY="true")
    elif kind == "s3_credentials":
        if ":" not in value:
            raise hmlib.ConfigError(f"Keychain item for {name!r} must look like ACCESS_KEY_ID:SECRET_ACCESS_KEY.")
        key_id, secret = value.split(":", 1)
        env.update(AWS_ACCESS_KEY_ID=key_id, AWS_SECRET_ACCESS_KEY=secret)
    else:
        var = entry.get("env")
        if not var:
            raise hmlib.ConfigError(f"secrets.{name}.env is not set (name of the environment variable).")
        env[var] = value
    return env, value


def main(argv: list[str]) -> int:
    if "--" not in argv or argv.index("--") == 0 or argv.index("--") == len(argv) - 1:
        print(__doc__, file=sys.stderr)
        return 2
    sep = argv.index("--")
    names, cmd = argv[:sep], argv[sep + 1:]
    try:
        cfg = hmlib.load_config()
        env, secrets = dict(os.environ), []
        for n in names:
            e, v = env_for(cfg, n)
            env.update(e)
            secrets.append(v)
            for sep in ("=", ":"):  # token secret / S3 secret key on their own
                if sep in v:
                    secrets.append(v.split(sep, 1)[1])
    except hmlib.ConfigError as e:
        print(f"with_secrets: {e}", file=sys.stderr)
        return 3
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    assert proc.stdout
    for line in proc.stdout:
        sys.stdout.write(hmlib.redact(line, secrets))
        sys.stdout.flush()
    return proc.wait()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
