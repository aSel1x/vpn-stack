"""bootstrap_keyring -- generation is per protocol, never per secret name.

Per name, a server holding reality.key but not reality.pub kept the old private
half and got the *new* keypair's public half written beside it: both files
present, config renders, every share link silently unusable. Same shape for
hysteria2, where a lost .key alone got a fresh key under the surviving .crt.

The one gap that is filled rather than refused is a DERIVED one. reality.pub is
a deterministic function of reality.key, so rebuilding it pairs the survivor
with itself instead of with something fresh -- and that is the only way a
keyring minted before the field existed can reach the invariant that share()
never touches the private key, short of --force and reissuing every profile.
"""

from __future__ import annotations

import pytest

from vpnctl import bootstrap, protocols, secrets_store
from vpnctl.paths import SECRETS_DIR
from vpnctl.reality_key import derive_public_key

# What a complete keyring holds. dnstt is absent on purpose: its Noise keypair
# is the dnstt-server binary's own format, so it is prepare()'s job, at
# `protocol on`, not every fresh server's.
FULL = {
    "reality.key",
    "reality.pub",
    "reality.short_id",
    "hysteria2.crt",
    "hysteria2.key",
    "hysteria2.obfs",
    "ipsec.psk",
    "ipsec.primary_user",
    "ipsec.primary_password",
}


def names() -> set[str]:
    return set(secrets_store.load().values)


def test_a_fresh_keyring_gets_everything() -> None:
    changed, message = bootstrap.bootstrap_keyring()
    assert changed
    assert names() == FULL
    assert all(name in message for name in FULL)
    assert SECRETS_DIR.stat().st_mode & 0o777 == 0o700


def test_bootstrap_generates_no_dnstt_key() -> None:
    # ~800 MB of Go toolchain for a protocol that ships disabled; prepare()
    # pays for it at `protocol on` instead.
    bootstrap.bootstrap_keyring()
    assert not any(n.startswith("dnstt.") for n in names())
    assert protocols.get("dnstt").prepare is not None


def test_a_complete_keyring_generates_nothing() -> None:
    bootstrap.bootstrap_keyring()
    before = secrets_store.load().values
    changed, message = bootstrap.bootstrap_keyring()
    assert not changed
    assert "already complete" in message
    assert "--force" in message
    assert secrets_store.load().values == before


def test_one_missing_file_refuses_the_whole_protocol() -> None:
    # hysteria2, because nothing about a private key can be recovered from the
    # certificate that survived it. This is the ordinary case: a gap that is not
    # derivable is named and left alone.
    bootstrap.bootstrap_keyring()
    survivor = secrets_store.load().raw("hysteria2.crt")
    (SECRETS_DIR / "hysteria2.key").unlink()

    with pytest.raises(bootstrap.KeyringRefused) as refusal:
        bootstrap.bootstrap_keyring()
    message = str(refusal.value)
    assert refusal.value.refused == ("hysteria2 (missing hysteria2.key)",)
    assert "NOT refilled" in message
    # The surviving certificate is untouched, and the gap stays a gap: a fresh
    # key beside a stale certificate renders, serves, and fails on every client.
    assert secrets_store.load().raw("hysteria2.crt") == survivor
    assert not (SECRETS_DIR / "hysteria2.key").exists()
    assert "backup" in message


def test_a_refusal_does_not_stop_an_untouched_protocol() -> None:
    bootstrap.bootstrap_keyring()
    survivor = secrets_store.load().raw("hysteria2.crt")
    (SECRETS_DIR / "hysteria2.key").unlink()
    for name in ("reality.key", "reality.pub", "reality.short_id"):
        (SECRETS_DIR / name).unlink()

    # The refusal is raised even though vless-reality's keys WERE written: the
    # write is not the verdict. Those secrets are on disk, and a re-run is a
    # no-op for them, so the untouched protocol is not held back by it.
    with pytest.raises(bootstrap.KeyringRefused) as refusal:
        bootstrap.bootstrap_keyring()
    assert refusal.value.refused == ("hysteria2 (missing hysteria2.key)",)
    assert secrets_store.load().raw("hysteria2.crt") == survivor
    assert names() == FULL - {"hysteria2.key"}


def test_a_truncated_file_does_not_count_as_present() -> None:
    # An interrupted write leaves a zero-length file; load() drops it, so the
    # protocol looks half-present and is refused rather than topped up.
    bootstrap.bootstrap_keyring()
    (SECRETS_DIR / "reality.key").write_bytes(b"")
    with pytest.raises(bootstrap.KeyringRefused) as refusal:
        bootstrap.bootstrap_keyring()
    assert refusal.value.refused == ("vless-reality (missing reality.key)",)
    assert (SECRETS_DIR / "reality.key").read_bytes() == b""


def test_a_wholly_truncated_protocol_is_regenerated() -> None:
    # Nothing survives to be paired with, so there is nothing to protect.
    bootstrap.bootstrap_keyring()
    for name in ("reality.key", "reality.pub", "reality.short_id"):
        (SECRETS_DIR / name).write_bytes(b"")
    changed, message = bootstrap.bootstrap_keyring()
    assert changed
    assert "NOT refilled" not in message
    assert secrets_store.load().raw("reality.key")


def test_force_regenerates_every_key() -> None:
    bootstrap.bootstrap_keyring()
    before = secrets_store.load().values
    changed, message = bootstrap.bootstrap_keyring(force=True)
    assert changed
    after = secrets_store.load().values
    assert set(after) == FULL
    assert all(after[name] != before[name] for name in FULL)
    assert "generated 9 secret(s)" in message


def test_force_repairs_a_half_present_set() -> None:
    # The escape hatch the refusal points at, when there is no backup.
    bootstrap.bootstrap_keyring()
    (SECRETS_DIR / "hysteria2.key").unlink()
    before = secrets_store.load().raw("hysteria2.crt")
    changed, _ = bootstrap.bootstrap_keyring(force=True)
    assert changed
    values = secrets_store.load()
    assert set(values.values) == FULL
    # Both halves are new. That is the difference between --force and the
    # derivation below: this one issues a fresh certificate and every exported
    # profile stops working, which is why it is never the automatic answer.
    assert values.raw("hysteria2.crt") != before


def test_a_keyring_without_reality_pub_heals_from_the_private_half() -> None:
    """The one gap that is filled, and the reason the refusal can stay strict.

    A server bootstrapped before reality.pub existed has the private half and
    nothing else, and no command could add the file: `bootstrap` refused the
    whole protocol (rightly -- a fresh public half beside a stale private one
    fails on every client) and `--force` meant reissuing every profile. So the
    invariant share() rests on -- that the pure seam never sees the private
    X25519 key -- was unreachable on exactly the servers that predate it.

    A derived half is not a fresh half. It is the same key's other face, so the
    pair still agrees and nothing a client holds changes.
    """
    bootstrap.bootstrap_keyring()
    before = secrets_store.load()
    private, short_id = before.raw("reality.key"), before.raw("reality.short_id")
    (SECRETS_DIR / "reality.pub").unlink()

    minted, message = bootstrap.bootstrap_keyring()
    # NOT "minted": the flag answers whether a new credential was created, and a
    # derived half is the same key's other face. cmd_bootstrap re-renders on this
    # flag and then tells the operator that credentials are new and every profile
    # must be re-exported -- which here would be false twice over, since nothing
    # rendered even reads reality.pub (render takes reality.key; only share()
    # prefers the stored public half).
    assert not minted
    assert names() == FULL
    after = secrets_store.load()
    assert after.text("reality.pub") == derive_public_key(after.text("reality.key"))
    # Byte-identical survivors: the private half was read, never rewritten, and
    # the sibling secret that shares the protocol was not touched either.
    assert after.raw("reality.key") == private
    assert after.raw("reality.short_id") == short_id
    # Reported as a rebuild rather than a generation, because no profile needs
    # re-exporting and the message is the only thing that says so.
    assert "reality.pub" in message
    assert "NOT refilled" not in message
    assert "no client credential changed" in message


def test_a_gap_is_only_filled_when_what_it_derives_from_survived() -> None:
    # reality.pub is derivable from reality.key, not from thin air. With the
    # private half gone too, the pair cannot be reconstructed and both names go
    # back to being a refusal -- the derivation must not quietly mint a keypair.
    bootstrap.bootstrap_keyring()
    short_id = secrets_store.load().raw("reality.short_id")
    (SECRETS_DIR / "reality.key").unlink()
    (SECRETS_DIR / "reality.pub").unlink()

    with pytest.raises(bootstrap.KeyringRefused) as refusal:
        bootstrap.bootstrap_keyring()
    assert refusal.value.refused == (
        "vless-reality (missing reality.key, reality.pub)",
    )
    assert names() == FULL - {"reality.key", "reality.pub"}
    assert secrets_store.load().raw("reality.short_id") == short_id


def test_a_derived_half_is_written_with_the_keyrings_own_permissions() -> None:
    # It goes through secrets_store.write like everything else: created 0600 and
    # os.replace'd, never a growing world-readable file in the keyring.
    bootstrap.bootstrap_keyring()
    (SECRETS_DIR / "reality.pub").unlink()
    bootstrap.bootstrap_keyring()
    assert (SECRETS_DIR / "reality.pub").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("proto", protocols.ordered(), ids=lambda p: p.name)
def test_every_secret_render_needs_is_produced_by_bootstrap_or_prepare(proto) -> None:
    produced = set(proto.bootstrap())
    if proto.prepare is not None:
        # prepare() shells out to docker; what it produces is asserted from the
        # registry's own declaration instead of by running it.
        produced |= {"dnstt.server.key", "dnstt.server.pub"}
    assert set(proto.secret_names) <= produced


def test_missing_secrets_names_what_is_lacking() -> None:
    bootstrap.bootstrap_keyring()
    assert bootstrap.missing_secrets(protocols.ordered(["vless-reality"])) == {}
    # dnstt is the one whose secret bootstrap deliberately does not make.
    assert bootstrap.missing_secrets(protocols.ordered(["dnstt"])) == {
        "dnstt": ["dnstt.server.key"]
    }
    (SECRETS_DIR / "hysteria2.key").unlink()
    assert bootstrap.missing_secrets(protocols.ordered()) == {
        "hysteria2": ["hysteria2.key"],
        "dnstt": ["dnstt.server.key"],
    }
