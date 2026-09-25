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
import tempfile
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


def _rmtree_not_live(path: Path) -> None:
    """Delete a generation, refusing the one `rendered` points at.

    The invariant, kept separate from the naming scheme that makes it
    unreachable: two running containers bind-mount paths under the live tree, so
    removing it does not fail loudly -- it leaves sing-box and dnstt-sshd holding
    deleted inodes, serving until the next restart and then refusing to start,
    with the config they were serving gone from the disk and unrecoverable
    except by another render.
    """
    live = RENDERED_LINK.resolve() if RENDERED_LINK.is_symlink() else None
    if live is not None and path.resolve() == live:
        raise protocols.RenderError(
            f"refusing to delete {path}: it is the live rendered tree that "
            "`rendered` points at and that the containers are mounted from."
        )
    shutil.rmtree(path)


def write_candidate(tree: dict[str, bytes]) -> Path:
    # mkdtemp rather than a name derived only from the clock. The stamp is at
    # one-second resolution, and this used to rmtree whatever already had that
    # name before rendering into it -- so two applies inside the same second (a
    # `user add` scripted in a loop, or a deploy racing the boot unit) had the
    # second one delete the tree the first had just promoted and the containers
    # were mounted from. The stamp stays in the prefix because `prune` orders
    # generations by name, `.gitignore` and `vpn backup` both match `rendered*`,
    # and a human reading the state directory needs to see when each was built.
    # mkdtemp also creates at 0700 in one syscall instead of mkdir-then-chmod.
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    candidate = Path(tempfile.mkdtemp(prefix=f"rendered-{stamp}-", dir=STATE_DIR))
    for rel, content in tree.items():
        target = candidate / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        # 0600 for everything, decided by default rather than by filename.
        # This used to be `0600 if name ends in .key or .env else 0644`, and
        # `dnstt-sshd/logins` ends in neither -- so the plaintext list of every
        # user's dnstt password was rendered world-readable, contained only by
        # the 0700 parent. Same failure shape as an exact-path .gitignore rule:
        # a new credential-bearing output is covered only if somebody remembers
        # to extend the list, and nobody did. Nothing needs the wider mode --
        # every rendered path is bind-mounted :ro into a container that reads it
        # as root, and no service in compose.yml declares a `user:`.
        # The mode is set at creation, not after: write_bytes() then chmod()
        # leaves a private key at the umask default for the width of a syscall.
        mode = 0o600
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
        # Through the guard as well as past the `live` skip above: the skip
        # compares what glob() returned against a resolved symlink target, and a
        # state directory reached through a symlinked path makes those two
        # spellings of the same directory differ.
        _rmtree_not_live(old)
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
    surface stays free of protocol names -- `protocol on` must not grow a branch
    per protocol. It is not on `Protocol` because a field there would have to be
    a callable reaching back into this module for the .env read, which is the
    dependency the pure registry does not take: render imports protocols, never
    the other way round. One case is also not a pattern yet; the second protocol
    to need deployment config before it can be enabled is what would pay for
    generalising this, and it can be generalised then without moving anything a
    caller can see.
    """
    if proto.name == dnstt.NAME and not dnstt_zone():
        return dnstt.NO_ZONE
    return None


def render_all() -> tuple[dict[str, bytes], list[protocols.Protocol]]:
    """Build the tree for the current state. Does not write anything."""
    users = users_store.load()
    enabled = state.enabled_protocols()
    return build_tree(snapshot(), users, enabled), enabled
