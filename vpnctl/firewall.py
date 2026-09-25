"""Reconcile ufw against the enabled protocol set.

Rules this tool owns are tagged `vpn-stack:<protocol>` in their comment, so it
can add and remove its own without touching anything a human added by hand.

The invariant is the tag, not a port number: a rule tagged `vpn-stack:ssh` is
never removed, whatever port it names, because the only way to fix a mistake
here is through it. The exemption was the literal `22/tcp` once, and on any box
whose sshd is elsewhere that spelling bricks the server: the app's provisioner
allows the operator's chosen ssh port and tags it `vpn-stack:ssh`, no protocol
in the registry is called `ssh`, so the rule is always in `have` and never in
`want` -- and the first converging `apply` runs `ufw --force delete allow
2222/tcp` against an active default-deny firewall, long after the install
deadman was disarmed. Recovery is through the hosting provider's console. So
`ssh` is a reserved tag here, off limits to the registry, and protected by name
in the removal loop.
"""

from __future__ import annotations

import re
import subprocess

from vpnctl import protocols

SSH_TAG = "ssh"  # reserved: the door this tool came in through
SSH_RULE = "22/tcp"  # belt and braces, for a default-port rule that lost its tag
TAG = "vpn-stack"


def _ufw(*args: str) -> tuple[bool, str]:
    result = subprocess.run(["ufw", *args], capture_output=True, text=True)
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def available() -> bool:
    return subprocess.run(["which", "ufw"], capture_output=True).returncode == 0


def _status_lines() -> list[str]:
    """`ufw status` as lines, or none of them.

    Needs root; without it every view of the firewall is empty, and the only
    consequence is re-adding rules ufw dedupes -- never deleting a live one.
    """
    ok, output = _ufw("status")
    return output.splitlines() if ok else []


def _tagged(lines: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in lines:
        match = re.search(rf"^(\S+)\s+ALLOW\s+.*#\s*{TAG}:(\S+)", line)
        if match:
            found[match.group(1)] = match.group(2)
    return found


def _untagged(lines: list[str]) -> set[str]:
    found: set[str] = set()
    for line in lines:
        match = re.search(r"^(\S+)\s+ALLOW\s+Anywhere\s*(#.*)?$", line)
        if match and not re.search(rf"#\s*{TAG}:", match.group(2) or ""):
            found.add(match.group(1))
    return found


def current_tagged() -> dict[str, str]:
    """{port/proto: protocol name} for rules this tool added."""
    return _tagged(_status_lines())


def current_untagged() -> set[str]:
    """{port/proto} for blanket ALLOW rules that are not ours.

    Only rules from `Anywhere` count. A narrower hand-added rule (`ALLOW
    10.0.0.0/8`) is a different rule to ufw and to the outside world, so
    treating it as "already allowed" would leave the protocol's port closed to
    every client while reconcile reported it served.

    A rule with somebody else's comment is untagged for this purpose: it is
    equally not ours to adopt or delete.
    """
    return _untagged(_status_lines())


def desired(enabled: list[protocols.Protocol]) -> dict[str, str]:
    """{port/proto: protocol name} the registry wants open.

    Never a rule tagged `ssh`: that tag names the administrative door, which
    the removal loop protects unconditionally, and a protocol answering to it
    would make "is this rule protected?" depend on which of the two wrote it.
    A protocol called `ssh` can only arrive by someone adding one to the
    registry, so this fires in the test suite rather than on a live server.
    """
    if any(proto.name == SSH_TAG for proto in enabled):
        raise ValueError(
            f"{TAG}:{SSH_TAG} is reserved for the ssh rule and cannot be a protocol name"
        )
    return {str(port): proto.name for proto in enabled for port in proto.ports}


def reconcile(
    enabled: list[protocols.Protocol], dry_run: bool = False
) -> tuple[bool, list[str]]:
    if not available():
        return True, ["ufw not installed, skipping firewall reconciliation"]

    want = desired(enabled)
    # One read of `ufw status`, two views of it: a second read could see a rule
    # the first did not, and the add path decides between "open it" and "a human
    # already opened it" on exactly that difference.
    status = _status_lines()
    have = _tagged(status)
    by_hand = _untagged(status)
    actions: list[str] = []

    for rule, proto_name in sorted(want.items()):
        if rule in have:
            continue
        if rule in by_hand:
            # `ufw allow <rule> comment vpn-stack:<proto>` over an identical
            # untagged rule has two outcomes depending on the ufw version, and
            # both are wrong quietly: either ufw skips the add and every apply
            # from here on re-reports the same no-op, or it rewrites the rule
            # with our comment and this tool now believes it owns a rule a
            # human added -- and deletes it the moment that protocol is turned
            # off. The port is open either way, so say so and change nothing.
            actions.append(
                f"~ {rule} already allowed by hand and untagged, left alone "
                f"({proto_name} is served; tag it {TAG}:{proto_name} to hand it over)"
            )
            continue
        actions.append(f"+ allow {rule} ({proto_name})")
        if not dry_run:
            ok, out = _ufw("allow", rule, "comment", f"{TAG}:{proto_name}")
            if not ok:
                return False, actions + [f"FAILED: {out}"]

    for rule, proto_name in sorted(have.items()):
        if rule in want:
            continue
        if proto_name == SSH_TAG or rule == SSH_RULE:
            why = (
                f"tagged {TAG}:{SSH_TAG}"
                if proto_name == SSH_TAG
                else f"the default ssh port, tagged {TAG}:{proto_name}"
            )
            actions.append(
                f"! refusing to remove {rule} ({why} -- the only way back in)"
            )
            continue
        actions.append(f"- delete {rule} (was {proto_name})")
        if not dry_run:
            ok, out = _ufw("--force", "delete", "allow", rule)
            if not ok:
                return False, actions + [f"FAILED: {out}"]

    return True, actions or ["firewall already matches the enabled set"]
