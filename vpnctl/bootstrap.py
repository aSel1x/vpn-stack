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
    """Generate any missing secrets. Never overwrites without force.

    force=True regenerates every key: the REALITY private key, the Hysteria2
    cert and obfs password, and the IPsec PSK. Every already-exported client
    profile stops working. There is no undo.
    """
    existing = secrets_store.load()
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    SECRETS_DIR.chmod(0o700)

    written: list[str] = []
    skipped: list[str] = []
    for proto in protocols.ordered():
        produced = proto.bootstrap()
        for name, content in produced.items():
            if existing.has(name) and not force:
                skipped.append(name)
                continue
            secrets_store.write(name, content)
            written.append(name)

    if not written:
        return False, (
            f"keyring already complete ({len(skipped)} secrets), nothing generated. "
            "Use --force to regenerate -- that invalidates every exported profile."
        )
    msg = f"generated {len(written)} secret(s): {', '.join(sorted(written))}"
    if skipped:
        msg += f" (kept {len(skipped)} existing)"
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
