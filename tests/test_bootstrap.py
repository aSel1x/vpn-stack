"""bootstrap_keyring -- generation is per protocol, never per secret name.

Per name, a server holding reality.key but not reality.pub kept the old private
half and got the *new* keypair's public half written beside it: both files
present, config renders, every share link silently unusable. Same shape for
hysteria2, where a lost .key alone got a fresh key under the surviving .crt.
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
    bootstrap.bootstrap_keyring()
    survivor = secrets_store.load().raw("reality.key")
    (SECRETS_DIR / "reality.pub").unlink()

    changed, message = bootstrap.bootstrap_keyring()
    assert not changed
    assert "NOT refilled" in message
    assert "vless-reality (missing reality.pub)" in message
    # The surviving private half is untouched, and the gap stays a gap: a fresh
    # public half beside a stale private one renders, serves, and fails on
    # every client.
    assert secrets_store.load().raw("reality.key") == survivor
    assert not (SECRETS_DIR / "reality.pub").exists()
    assert "backup" in message


def test_a_refusal_does_not_stop_an_untouched_protocol() -> None:
    bootstrap.bootstrap_keyring()
    survivor = secrets_store.load().raw("reality.key")
    (SECRETS_DIR / "reality.pub").unlink()
    for name in ("hysteria2.crt", "hysteria2.key", "hysteria2.obfs"):
        (SECRETS_DIR / name).unlink()

    changed, message = bootstrap.bootstrap_keyring()
    assert changed
    assert "hysteria2.crt" in message
    assert "NOT refilled" in message and "vless-reality" in message
    assert secrets_store.load().raw("reality.key") == survivor
    assert names() == FULL - {"reality.pub"}


def test_a_truncated_file_does_not_count_as_present() -> None:
    # An interrupted write leaves a zero-length file; load() drops it, so the
    # protocol looks half-present and is refused rather than topped up.
    bootstrap.bootstrap_keyring()
    (SECRETS_DIR / "reality.key").write_bytes(b"")
    changed, message = bootstrap.bootstrap_keyring()
    assert not changed
    assert "vless-reality (missing reality.key)" in message
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
    (SECRETS_DIR / "reality.pub").unlink()
    changed, _ = bootstrap.bootstrap_keyring(force=True)
    assert changed
    values = secrets_store.load()
    assert values.text("reality.pub") == derive_public_key(values.text("reality.key"))


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
