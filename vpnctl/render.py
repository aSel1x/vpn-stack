"""Render the whole config as a candidate tree, validate it, then promote.

Replaces the old snapshot/restore dance. Instead of mutating the live files and
putting them back if validation fails, we build a complete new tree beside the
live one, validate *that*, and swap a symlink only on success. The live tree is
never invalid for a single instant, so there is nothing to roll back -- and the
guarantee now covers the certs and the ikev2 env too, not just two fragments.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from vpnctl import protocols, secrets_store, state, users_store
from vpnctl.dotenv import read as read_env
from vpnctl.paths import ENV_FILE, RENDERED_LINK, SING_BOX_COMMON, STATE_DIR
from vpnctl.protocols import dnstt

KEEP_GENERATIONS = 5


def build_tree(
    secrets: secrets_store.Secrets,
    users: list[users_store.User],
    enabled: list[protocols.Protocol],
) -> dict[str, bytes]:
    """Pure: (secrets, users, enabled) -> {relative path: contents}."""
    protocols.assert_ports_disjoint(enabled)

    tree: dict[str, bytes] = {}
    # The tracked, non-secret halves of the sing-box config come from git.
    for path in sorted(SING_BOX_COMMON.glob("*.json")):
        tree[f"sing-box/{path.name}"] = path.read_bytes()

    for proto in enabled:
        for rel, content in proto.render(secrets, users).items():
            if rel in tree:
                raise protocols.RenderError(
                    f"{proto.name} would overwrite {rel}, already written"
                )
            tree[rel] = content
    return tree


def write_candidate(tree: dict[str, bytes]) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    candidate = STATE_DIR / f"rendered-{stamp}"
    if candidate.exists():
        shutil.rmtree(candidate)
    candidate.mkdir(parents=True, exist_ok=True)
    candidate.chmod(0o700)
    for rel, content in tree.items():
        target = candidate / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        # Anything that is a key stays 0600; the rest is world-readable inside
        # a 0700 parent, which the sing-box container needs in order to read it.
        # The mode is set at creation, not after: write_bytes() then chmod()
        # leaves a private key at the umask default for the width of a syscall.
        mode = 0o600 if target.name.endswith((".key", ".env")) else 0o644
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
        target.chmod(mode)  # O_CREAT mode is masked by umask; this is not.
    return candidate


def promote(candidate: Path) -> None:
    """Atomically point `rendered` at the candidate.

    `os.replace` on a symlink is atomic, so a reader either sees the whole old
    tree or the whole new one -- never a half-written mixture.
    """
    tmp_link = STATE_DIR / ".rendered.new"
    if tmp_link.is_symlink() or tmp_link.exists():
        tmp_link.unlink()
    tmp_link.symlink_to(candidate.name)
    os.replace(tmp_link, RENDERED_LINK)


def prune(keep: int = KEEP_GENERATIONS) -> list[Path]:
    """Drop old generations, always keeping the one `rendered` points at."""
    live = RENDERED_LINK.resolve() if RENDERED_LINK.exists() else None
    generations = sorted(
        (p for p in STATE_DIR.glob("rendered-*") if p.is_dir()),
        key=lambda p: p.name,
        reverse=True,
    )
    removed = []
    for old in generations[keep:]:
        if old == live:
            continue
        shutil.rmtree(old)
        removed.append(old)
    return removed


def dnstt_zone() -> str:
    """dnstt's delegated zone, read here because the registry may not read it.

    os.environ first, then .env: that is compose's own precedence -- a shell
    variable beats the file -- and reading only the file would let an exported
    value move the container's zone while Python went on handing out the other.
    Nothing sources .env into this process (the vpnctl shim does not, and
    `uv run` only does when told to), so os.environ alone would be empty on the
    server.
    """
    return os.environ.get(dnstt.ZONE_VAR) or read_env(ENV_FILE).get(dnstt.ZONE_VAR, "")


def snapshot() -> secrets_store.Secrets:
    """The keyring plus the deployment config the pure layer needs, as one value.

    render() and share() take (secrets, ...) and nothing else, which is what
    keeps them free of open() and usable by an app with no server round-trip.
    Non-secret deployment config -- dnstt's zone -- therefore has to arrive the
    same way, and this is the edge where the impure read happens. dnstt.py held
    it in a module global resolved at import instead, so a caller holding only
    (secrets, user, host) got an empty zone and share() raised at it: the exact
    seam the purity rule exists to keep open, closed by the fix to a different
    bug.

    Absent stays absent rather than becoming an empty entry, mirroring
    secrets_store.load(): a zero-length value is not a value. render() warns
    about it, share() refuses.
    """
    keyring = secrets_store.load()
    zone = dnstt_zone()
    if not zone:
        return keyring
    return secrets_store.Secrets(
        values={**keyring.values, dnstt.ZONE_KEY: zone.encode()}
    )


def missing_deployment_config(proto: protocols.Protocol) -> str | None:
    """What `protocol on` has to refuse for, before it writes anything.

    Lives beside the read it depends on rather than in cli.py, so the command
    surface stays free of protocol names; the registry's own home for this is a
    field on Protocol, and until it has one the single case is here.
    """
    if proto.name == dnstt.NAME and not dnstt_zone():
        return dnstt.NO_ZONE
    return None


def render_all() -> tuple[dict[str, bytes], list[protocols.Protocol]]:
    """Build the tree for the current state. Does not write anything."""
    users = users_store.load()
    enabled = state.enabled_protocols()
    return build_tree(snapshot(), users, enabled), enabled
