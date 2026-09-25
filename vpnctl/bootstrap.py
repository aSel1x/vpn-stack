"""Day-0 generation of the keyring, driven entirely by the registry.

This used to also hand-write the config fragments, which is why bootstrap
--force could leave a live server with an empty users array: it wrote config
and never rendered. Now it only produces secrets; the config is always the
output of `render`, so there is no second source of truth to fall out of sync.
"""

from __future__ import annotations

from typing import Callable, Mapping

from vpnctl import protocols, secrets_store
from vpnctl.paths import SECRETS_DIR

# A function of the keyring that SURVIVED, producing one of a protocol's
# bootstrap outputs. The distinction that makes this safe is that the result is
# not a new credential: it is another face of one that is already on disk and
# already in every client's hands.
Derivation = Callable[[secrets_store.Secrets], bytes]


class KeyringRefused(RuntimeError):
    """A protocol's secret set is half present, so it was left alone.

    Raised rather than returned because the two things a caller wants to do
    with it -- exit non-zero and print the remedy -- are what every other
    typed error in this package already gets for free in cli.main. It used to
    be a sentence inside the success message, which meant `bootstrap` reported
    ok=true and exited 0 on the one outcome that demands a decision, and the
    CLI had to recognise it by matching a literal prefix of the prose.
    """

    def __init__(self, message: str, refused: tuple[str, ...]) -> None:
        super().__init__(message)
        # The protocols, so a caller can act on them without parsing English.
        self.refused = refused


def _derivable(proto: protocols.Protocol) -> Mapping[str, Derivation]:
    """Which of this protocol's bootstrap outputs can be rebuilt, not minted.

    Declared on the Protocol, beside the bootstrap() that mints the pair, so the
    derivation and the minting cannot drift apart. A protocol that declares
    nothing keeps the refuse-and-name behaviour for every gap.
    """
    return proto.derivable or {}


def _heal(
    derivable: Mapping[str, Derivation], gaps: list[str], have: secrets_store.Secrets
) -> list[str]:
    """Rebuild the gaps that are derivable; report which ones were.

    A derivation that raises leaves its gap a gap. That happens when the
    material it reads is itself missing or no longer parses -- reality.key gone
    while reality.short_id survived, say -- which is a damaged keyring, and the
    refusal below already knows how to name one. Letting the exception out
    would answer a repairable keyring with a traceback instead.
    """
    healed: list[str] = []
    for name in gaps:
        derive = derivable.get(name)
        if derive is None:
            continue
        try:
            content = derive(have)
        except Exception:
            continue
        secrets_store.write(name, content)
        healed.append(name)
    return healed


def bootstrap_keyring(force: bool = False) -> tuple[bool, str]:
    """Generate any missing secrets, a whole protocol at a time.

    Returns (a new credential was minted, what happened). A gap REBUILT from
    surviving material is not a new credential and does not set the flag: see
    the return below.

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
    derived: list[str] = []
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
            # The one exception, and it is as narrow as the reason for the
            # refusal. Filling a gap is forbidden because it pairs a FRESH half
            # with the stale survivor; a derived half is not fresh, it is the
            # same key's other face, so the pair still agrees and every profile
            # already issued keeps working. Anything not derivable stays a gap.
            healed = _heal(_derivable(proto), gaps, existing)
            derived.extend(healed)
            gaps = [n for n in gaps if n not in healed]
            if gaps:
                partial.append(f"{proto.name} (missing {', '.join(gaps)})")
            continue
        for name, content in produced.items():
            secrets_store.write(name, content)
            written.append(name)

    if partial:
        # Raised even when another protocol's keys WERE written: the write is not
        # the verdict. Those secrets are already on disk and a re-run is a no-op
        # for them, so failing here loses nothing and stops a half-present set
        # from being reported as a completed bootstrap.
        raise KeyringRefused(
            "NOT refilled: " + "; ".join(partial) + ". A half-present set is left "
            "alone rather than topped up: filling the gap pairs a fresh half with "
            "the stale one that survived, which renders, serves, and fails on every "
            "client. Restore the missing file from a backup, or `--force` to "
            "regenerate the whole set -- that invalidates every exported profile.",
            tuple(partial),
        )

    if not written and not derived:
        return False, (
            f"keyring already complete ({len(kept)} secrets), nothing generated. "
            "Use --force to regenerate -- that invalidates every exported profile."
        )
    parts = []
    if written:
        parts.append(
            f"generated {len(written)} secret(s): {', '.join(sorted(written))}"
        )
    if derived:
        # Said out loud and kept separate from "generated", because the whole
        # point is that nothing a client holds has changed: these were rebuilt
        # from material already on disk, so no profile needs re-exporting.
        parts.append(
            f"rebuilt {len(derived)} secret(s) from surviving material: "
            f"{', '.join(sorted(derived))} -- no client credential changed"
        )
    msg = "; ".join(parts)
    if kept:
        msg += f" (kept {len(kept)} existing)"
    # The bool answers "was a NEW credential minted", not "did anything get
    # written", and the difference is the whole point of the derivable carve-out.
    # cmd_bootstrap re-renders on it and then tells the operator that credentials
    # are new and every profile must be re-exported -- which for a derived half
    # is false twice over: reality.pub is not a new key, and nothing rendered
    # reads it (render takes reality.key; only share() prefers the stored public
    # half). Returning True here sent an operator whose only gap was reality.pub
    # off to reissue every profile on the box.
    return bool(written), msg


def missing_secrets(enabled: list[protocols.Protocol]) -> dict[str, list[str]]:
    """Which enabled protocols cannot be rendered yet, and what they lack."""
    have = secrets_store.load()
    gaps: dict[str, list[str]] = {}
    for proto in enabled:
        lacking = [n for n in proto.secret_names if not have.has(n)]
        if lacking:
            gaps[proto.name] = lacking
    return gaps
