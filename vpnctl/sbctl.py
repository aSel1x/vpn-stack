"""Validate a sing-box config tree.

There used to be an `apply()` here too, a second `docker compose up -d
--force-recreate sing-box` that nothing called: composectl owns the container
lifecycle, and a private copy of "how sing-box gets restarted" is exactly how
one of them ends up not matching what apply actually does. Deleted rather than
fixed.
"""

from __future__ import annotations

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
