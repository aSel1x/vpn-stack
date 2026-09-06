"""Reconcile ufw against the enabled protocol set.

Rules this tool owns are tagged `vpn-stack:<protocol>` in their comment, so it
can add and remove its own without touching anything a human added by hand.

22/tcp is a hard invariant: it is never removed, whatever the registry says,
because the only way to fix a mistake here is through it.
"""

from __future__ import annotations

import re
import subprocess

from vpnctl import protocols

SSH_RULE = "22/tcp"
TAG = "vpn-stack"


def _ufw(*args: str) -> tuple[bool, str]:
    result = subprocess.run(["ufw", *args], capture_output=True, text=True)
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def available() -> bool:
    return subprocess.run(["which", "ufw"], capture_output=True).returncode == 0


def current_tagged() -> dict[str, str]:
    """{port/proto: protocol name} for rules this tool added."""
    ok, output = _ufw("status")
    if not ok:
        return {}
    found: dict[str, str] = {}
    for line in output.splitlines():
        match = re.search(rf"^(\S+)\s+ALLOW\s+.*#\s*{TAG}:(\S+)", line)
        if match:
            found[match.group(1)] = match.group(2)
    return found


def desired(enabled: list[protocols.Protocol]) -> dict[str, str]:
    return {str(port): proto.name for proto in enabled for port in proto.ports}


def reconcile(enabled: list[protocols.Protocol], dry_run: bool = False) -> tuple[bool, list[str]]:
    if not available():
        return True, ["ufw not installed, skipping firewall reconciliation"]

    want = desired(enabled)
    have = current_tagged()
    actions: list[str] = []

    for rule, proto_name in sorted(want.items()):
        if rule in have:
            continue
        actions.append(f"+ allow {rule} ({proto_name})")
        if not dry_run:
            ok, out = _ufw("allow", rule, "comment", f"{TAG}:{proto_name}")
            if not ok:
                return False, actions + [f"FAILED: {out}"]

    for rule, proto_name in sorted(have.items()):
        if rule in want:
            continue
        if rule == SSH_RULE:
            actions.append(f"! refusing to remove {SSH_RULE} (invariant)")
            continue
        actions.append(f"- delete {rule} (was {proto_name})")
        if not dry_run:
            ok, out = _ufw("--force", "delete", "allow", rule)
            if not ok:
                return False, actions + [f"FAILED: {out}"]

    return True, actions or ["firewall already matches the enabled set"]
