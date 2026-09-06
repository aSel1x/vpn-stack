"""Thin wrappers around docker for the sing-box service."""

import subprocess

from vpnctl.paths import ROOT, SCRIPTS_DIR


def check_config(config_dir) -> tuple[bool, str]:
    """Validate a sing-box config directory via the one shared definition."""
    result = subprocess.run(
        ["bash", str(SCRIPTS_DIR / "check.sh"), str(config_dir)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def apply() -> tuple[bool, str]:
    result = subprocess.run(
        ["docker", "compose", "up", "-d", "--force-recreate", "--no-deps", "sing-box"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()
