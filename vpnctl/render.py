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
from vpnctl.paths import RENDERED_LINK, SING_BOX_COMMON, STATE_DIR

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


def render_all() -> tuple[dict[str, bytes], list[protocols.Protocol]]:
    """Build the tree for the current state. Does not write anything."""
    secrets = secrets_store.load()
    users = users_store.load()
    enabled = state.enabled_protocols()
    return build_tree(secrets, users, enabled), enabled
