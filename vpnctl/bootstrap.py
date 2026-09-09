"""Day-0 generation of the keyring, driven entirely by the registry.

This used to also hand-write the config fragments, which is why bootstrap
--force could leave a live server with an empty users array: it wrote config
and never rendered. Now it only produces secrets; the config is always the
output of `render`, so there is no second source of truth to fall out of sync.
"""

from __future__ import annotations

from vpnctl import protocols, secrets_store
from vpnctl.paths import SECRETS_DIR


def bootstrap_keyring(force: bool = False) -> tuple[bool, str]:
    """Generate any missing secrets, a whole protocol at a time.

    Never overwrites without force. force=True regenerates every key: the
    REALITY keypair, the Hysteria2 cert and obfs password, and the IPsec PSK.
    Every already-exported client profile stops working. There is no undo.
    """
    # load() drops zero-length files, so a secret truncated by an interrupted
    # write does not count as present and gets regenerated here.
    existing = secrets_store.load()
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    SECRETS_DIR.chmod(0o700)

    written: list[str] = []
    kept: list[str] = []
    partial: list[str] = []
    for proto in protocols.ordered():
        # Called even when the answer turns out to be "skip": what a protocol's
        # bootstrap produces is listed nowhere else. secret_names is a
        # different set -- it is what render needs, so it omits reality.pub and
        # includes dnstt.server.key, which prepare() makes.
        produced = proto.bootstrap()
        have = [n for n in produced if existing.has(n)]
        if have and not force:
            # The skip is per protocol, not per secret name. Per name, a server
            # holding reality.key but not reality.pub kept the old private half
            # and got the *new* keypair's public half written beside it -- both
            # files present, config renders, every share link silently
            # unusable. Same shape for hysteria2: a lost .key alone got a fresh
            # key under the surviving .crt.
            kept.extend(have)
            gaps = [n for n in produced if not existing.has(n)]
            if gaps:
                partial.append(f"{proto.name} (missing {', '.join(gaps)})")
            continue
        for name, content in produced.items():
            secrets_store.write(name, content)
            written.append(name)

    note = ""
    if partial:
        note = (
            "NOT refilled: " + "; ".join(partial) + ". A half-present set is left "
            "alone rather than topped up: filling the gap pairs a fresh half with "
            "the stale one that survived, which renders, serves, and fails on every "
            "client. Restore the missing file from a backup, or `--force` to "
            "regenerate the whole set -- that invalidates every exported profile."
        )

    if not written:
        if partial:
            return False, note
        return False, (
            f"keyring already complete ({len(kept)} secrets), nothing generated. "
            "Use --force to regenerate -- that invalidates every exported profile."
        )
    msg = f"generated {len(written)} secret(s): {', '.join(sorted(written))}"
    if kept:
        msg += f" (kept {len(kept)} existing)"
    if note:
        msg += "\n" + note
    return True, msg


def missing_secrets(enabled: list[protocols.Protocol]) -> dict[str, list[str]]:
    """Which enabled protocols cannot be rendered yet, and what they lack."""
    have = secrets_store.load()
    gaps: dict[str, list[str]] = {}
    for proto in enabled:
        lacking = [n for n in proto.secret_names if not have.has(n)]
        if lacking:
            gaps[proto.name] = lacking
    return gaps
