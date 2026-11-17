#!/usr/bin/env python3
"""`tofu init` with the state backend configured from homelab.yaml (opentofu.state_backend).

    tofu_init.py [--env homelab | --site NAME] [--print] [-- extra tofu init args, e.g. -upgrade | -migrate-state]

Backends:
  local  state file on this Mac OUTSIDE the repository (default
         ~/.local/share/homelab/tofu-state/<site.name>/<env>.tfstate, directory mode 700).
         Back it up (Time Machine). No secrets needed.
  s3     any S3-compatible bucket (MinIO, Garage, AWS) with lockfile locking. Credentials come
         from the keychain: run as  with_secrets.py <opentofu.state_secret> -- python3 tofu_init.py

Keeps tofu/environments/<env>/backend.tf's backend type in line with the config (rewrites it
when the backend changes; then pass `-- -migrate-state` to move existing state, with approval).
Backend settings (paths, bucket, endpoint) are passed as -backend-config, so backend.tf stays generic.
Several sites: each site's environment (--site NAME = tofu/environments/NAME) has its own state; a fixed
opentofu.local.path or opentofu.s3.key must then contain {env}, or the sites would share one state.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402

BACKEND_TF = """# OpenTofu state backend: {kind}. Never stored in Git.
# Settings come from homelab.yaml (opentofu.*) via scripts — don't edit them in here:
#   python3 $HM/scripts/tofu_init.py{hint}
terraform {{
  backend "{kind}" {{}}
}}
"""


def per_env(cfg, key: str, value: str, env: str) -> str:
    """A configured state path/key for this environment: {env} filled in. Without {env} it is only valid for the
    default environment — another one would share (and then destroy) that state."""
    if "{env}" in value:
        return value.replace("{env}", env)
    if env != hmlib.default_env(cfg):
        raise hmlib.ConfigError(f"{key} has no {{env}}, so environment {env!r} would use the state of "
                                f"{hmlib.default_env(cfg)!r}. Put {{env}} in it (e.g. …/{{env}}.tfstate); for the "
                                "existing state of the default environment that is a -migrate-state, with a yes.")
    return value


def local_path(cfg, env: str) -> Path:
    p = hmlib.get(cfg, "opentofu.local.path") or ""
    if p:
        return Path(os.path.expanduser(per_env(cfg, "opentofu.local.path", p, env)))
    site = hmlib.get(cfg, "site.name", "homelab") or "homelab"
    return Path.home() / ".local" / "share" / "homelab" / "tofu-state" / site / f"{env}.tfstate"


def backend_args(cfg, env: str) -> tuple[str, list[str]]:
    kind = hmlib.get(cfg, "opentofu.state_backend", "local") or "local"
    if kind == "local":
        path = local_path(cfg, env)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.parent.chmod(0o700)
        return kind, [f"-backend-config=path={path}"]
    if kind == "s3":
        s3 = hmlib.get(cfg, "opentofu.s3", {}) or {}
        missing = [k for k in ("endpoint", "bucket") if not s3.get(k)]
        if missing:
            raise hmlib.ConfigError("opentofu.s3." + " and opentofu.s3.".join(missing) + " must be set in homelab.yaml.")
        if not (os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY")):
            secret = hmlib.get(cfg, "opentofu.state_secret", "s3-state")
            raise hmlib.ConfigError(f"S3 credentials missing — run via: with_secrets.py {secret} -- python3 tofu_init.py")
        site = hmlib.get(cfg, "site.name", "homelab") or "homelab"
        key = per_env(cfg, "opentofu.s3.key", str(s3["key"]), env) if s3.get("key") else f"{site}/{env}.tfstate"
        args = [f"-backend-config=bucket={s3['bucket']}",
                f"-backend-config=key={key}",
                f"-backend-config=region={s3.get('region') or 'us-east-1'}",
                f'-backend-config=endpoints={{s3="{s3["endpoint"]}"}}',
                f"-backend-config=use_path_style={str(s3.get('use_path_style', True)).lower()}",
                "-backend-config=use_lockfile=true"]
        if not str(s3["endpoint"]).rstrip("/").endswith("amazonaws.com"):  # MinIO/Garage/…: skip AWS-only calls
            args += ["-backend-config=skip_credentials_validation=true", "-backend-config=skip_region_validation=true",
                     "-backend-config=skip_requesting_account_id=true", "-backend-config=skip_metadata_api_check=true",
                     "-backend-config=skip_s3_checksum=true"]
        return kind, args
    raise hmlib.ConfigError(f"opentofu.state_backend must be local or s3, not {kind!r}.")


def ensure_backend_tf(env_dir: Path, kind: str) -> bool:
    f = env_dir / "backend.tf"
    current = re.search(r'backend\s+"(\w+)"', f.read_text()).group(1) if f.exists() else None
    if current == kind:
        return False
    hint = "" if kind == "local" else "   (under with_secrets.py <state secret>)"
    f.write_text(BACKEND_TF.format(kind=kind, hint=hint))
    print(f"backend.tf: {current or 'none'} → {kind}" + ("  (if the old backend already holds state: re-run with -- -migrate-state, needs approval)"
                                                        if current else ""), file=sys.stderr)
    return True


def main():
    argv = sys.argv[1:]
    extra = argv[argv.index("--") + 1:] if "--" in argv else []
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--env")
    g.add_argument("--site", help="the site's environment (sites: in homelab.yaml)")
    ap.add_argument("--print", action="store_true", help="show the init command, don't run it")
    a = ap.parse_args(argv[:argv.index("--")] if "--" in argv else argv)
    try:
        cfg = hmlib.load_config()
        env = a.env or hmlib.tofu_env(cfg, a.site)
        env_dir = Path(cfg["_root"]) / "tofu" / "environments" / env
        if not env_dir.is_dir():
            raise hmlib.ConfigError(f"{env_dir} does not exist")
        kind, args = backend_args(cfg, env)
    except hmlib.ConfigError as e:
        print(f"tofu_init: {e}", file=sys.stderr)
        return 3
    cmd = ["tofu", "init", "-input=false", *args, *extra]
    if a.print:
        print(f"[{kind}] cd {env_dir} && " + " ".join(cmd))
        return 0
    ensure_backend_tf(env_dir, kind)
    return subprocess.run(cmd, cwd=env_dir).returncode


if __name__ == "__main__":
    sys.exit(main())
