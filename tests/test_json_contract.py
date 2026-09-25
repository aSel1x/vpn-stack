"""The `--json` payloads, written down once and read by both sides.

app/README.md gives as a reason for the Flutter client living in this
repository that a breaking change to `--json` should not be able to land
without the app's tests running against it. That was not bought: the Dart
fixtures were hand-typed transcriptions of what somebody remembered cli.py
printing, nothing compared the two, and renaming `enabled_protocols` left both
suites green while every phone refused to parse `apply`. Three of those
transcriptions were already wrong -- `failed: ["hysteria2"]` on an export
(only a share_via_container protocol can land in `failed`, and hysteria2 is
not one), IKEv2 bundles named `kate.p12` instead of `kate-ikev2.p12` (the
suffix `bundle_label` matches on), and a dnstt card with four fields when
share() emits two cards of five and three.

So the fixtures are generated here instead, by calling the real `cmd_*`
functions, and checked in under app/test/fixtures/. This test asserts cli.py
still prints exactly those bytes; the Dart tests parse the same files. Neither
side can move alone: one commit has to change both, which is the entire point.

Deliberately NOT a regex over app/lib/control/models.dart. app/README.md
rejects that option by name -- a parser for Dart written in Python is a second
thing to get wrong, and it would pass on a model that compiles and refuses
every real payload. The shared artifact is the payload itself.

Determinism, because an equality assertion needs it:

  * The keyring is seeded from CONTRACT_SECRETS below rather than minted, so
    the REALITY public key, the short id, the obfs password and both Hysteria2
    certificate pins come out byte-identical on every run.
  * Users come from conftest.make_user, whose credentials are a digest of the
    name rather than uuid4/token_hex, with the three credential fields
    overridden to realistic *lengths* -- the app reports a refused field as
    `hysteria2_password: string(32)`, so a 10-character stand-in would have
    made that message a fiction.
  * What is left volatile is redacted by _redact below: the candidate
    directory name (a clock plus mkdtemp randomness) and the state directory
    (a pytest tmpdir). Both keep their KEY and lose only their VALUE -- the key
    set is the whole thing under test.

Nothing here needs Docker, root or the network. `apply` shells out to
scripts/check.sh, i.e. Docker, which conftest.py says this suite must never
need, so the machine is faked at exactly the seams test_apply.py already fakes
it at -- FakeServer is imported from there rather than reimplemented, so the
two cannot drift into two different ideas of what a converge answers.
"""

from __future__ import annotations

import json
import os
from argparse import Namespace
from pathlib import Path

import pytest

from conftest import DNSTT_KEY, DNSTT_PUB, make_user
from test_apply import FakeServer
from vpnctl import bootstrap, cli, protocols, secrets_store, state, users_store
from vpnctl.paths import STATE_DIR
from vpnctl.reality_key import derive_public_key

FIXTURES = Path(__file__).resolve().parent.parent / "app" / "test" / "fixtures"

UPDATE_ENV = "UPDATE_CONTRACT"

# Every file this module owns. The directory is asserted to hold exactly these
# (see the last test): a fixture left behind by a command that no longer exists
# is a payload the Dart side may still be parsing, and nothing else would say
# so.
FIXTURE_NAMES = frozenset(
    {
        "status.json",
        "user-list.json",
        "user-list-secrets.json",
        "protocol-list.json",
        "user-export.json",
        "user-export-partial.json",
        "apply.json",
        "user-add.json",
        "user-rm.json",
        "user-enable.json",
        "user-disable.json",
        "protocol-on.json",
        "protocol-off.json",
        "protocol-unchanged.json",
        "apply-missing-secrets.json",
        "user-export-no-such-user.json",
        "bootstrap.json",
        "ikev2-list-clients.json",
    }
)

# ----------------------------------------------------------- the seeded keyring

# A self-signed certificate for hysteria2's masquerade name, checked in whole
# rather than minted, because ECDSA signatures are randomised: a certificate
# built here from a fixed key would still carry different bytes every run, and
# `pinSHA256` hashes the whole DER.
#
# Its private half is deliberately NOT here. Nothing in this file's path reads
# it -- render() copies `hysteria2.key` through verbatim and share() computes
# both pins from the certificate alone, which is the property
# test_protocols_share.py asserts separately -- so the placeholder below stands
# in for it, and loudly.
#
# The key inside it is the SECP256R1 point for private scalar 3. That is not an
# accident twice over: it cannot be mistaken for a live certificate by anyone
# who looks, and its SubjectPublicKeyInfo hash base64s to a string containing
# both `+` and `/`. Those two characters are the reason app/lib/config/
# share_uri.dart refuses to use `Uri.queryParameters` -- form decoding turns a
# `+` into a space, so a pin that survives a round trip here is a pin no
# client can silently corrupt. A fixture whose every value happened to be
# `[A-Za-z0-9]` would never have exercised it.
CONTRACT_CERT = b"""-----BEGIN CERTIFICATE-----
MIIBPzCB56ADAgECAggBI0VniavN7zAKBggqhkjOPQQDAjATMREwDwYDVQQDDAhi
aW5nLmNvbTAeFw0yNjAxMDEwMDAwMDBaFw0zNTEyMzAwMDAwMDBaMBMxETAPBgNV
BAMMCGJpbmcuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXsvk0aYzCkTI
9++VHUvxZebGtyHvramF+0FmG8bn/WyHNGQMSZj/fjdLBs4aZKLs2CqwNjhPuD2a
ebEnon1QMqMlMCMwEwYDVR0RBAwwCoIIYmluZy5jb20wDAYDVR0TAQH/BAIwADAK
BggqhkjOPQQDAgNHADBEAiB+WgaeK4kKr2+i5f+UDnUIbhvST+tqh04td/Y4VBFO
tgIgdX+R+DkSIKD6k+Fu9rOTIvsVfo5Y+u8S4k7nEL3lgSM=
-----END CERTIFICATE-----
"""

# sing-box's own encoding for an X25519 private key: 32 raw bytes, unpadded
# base64url. This one is bytes 0x18,0x01,0x02..0x1f, chosen because its public
# half carries both `-` and `_` -- the two characters that separate base64url
# from base64, and the ones vless_reality.dart's `_checkPublicKey` exists to
# accept. The public half is derived rather than written out: deriving it is
# what proves the pair in the fixture agrees, and bootstrap() derives it the
# same way.
CONTRACT_REALITY_KEY = "GAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

CONTRACT_SECRETS: dict[str, bytes] = {
    "reality.key": CONTRACT_REALITY_KEY.encode(),
    "reality.pub": derive_public_key(CONTRACT_REALITY_KEY).encode(),
    # secrets.token_hex(8) is 16 hex characters; this is that shape.
    "reality.short_id": b"0123456789abcdef",
    "hysteria2.crt": CONTRACT_CERT,
    "hysteria2.key": b"-- placeholder: nothing on this path reads the key --\n",
    "hysteria2.obfs": b"d41d8cd98f00b204e9800998ecf8427e",
    "ipsec.psk": b"5f4dcc3b5aa765d61d8327deb882cf99",
    "ipsec.primary_user": b"unused0000000000",
    "ipsec.primary_password": b"6c1ed99f0f6e2b2a6d72f42e43d0e1a7",
    # dnstt's own on-disk shape: hex plus a newline. Shared with conftest so
    # there is one answer to "what does a dnstt keypair look like in a test".
    "dnstt.server.key": DNSTT_KEY,
    "dnstt.server.pub": DNSTT_PUB,
}

# ------------------------------------------------------------------- the users

# Two people, in the two states `user list` has to distinguish, with the
# credential lengths a real record carries: a uuid4, and two token_hex(16).
# `created_at` is fixed because the payload prints it verbatim.
CONTRACT_USERS = (
    {
        "name": "asel1x",
        "vless_uuid": "6f1d2c3b-4a59-4e87-9c10-2b7f5d0e8a41",
        "hysteria2_password": "4f9c1e2a7b3d8055c6a1e4f70b2d9a13",
        "l2tp_password": "0b7e5a1c9d34f8621ae0cc73b45d19f2",
        "dnstt_password": "Wq4tPlum2zRt",
        "ikev2_provisioned": True,
        "enabled": True,
        "created_at": "2026-09-06T09:14:02Z",
    },
    {
        "name": "guest.phone",
        "vless_uuid": "b0a91e77-3d55-4c12-8f0a-6e2d47b91c83",
        "hysteria2_password": "c7a2f01b9e8d4356a0b1c2d3e4f50617",
        "l2tp_password": "1a2b3c4d5e6f70819293a4b5c6d7e8f9",
        "dnstt_password": "Kt8zQuin4vBn",
        "ikev2_provisioned": False,
        "enabled": False,
        "created_at": "2026-09-07T18:41:55Z",
    },
)

HOST = "203.0.113.10"

# What `ikev2.sh --listclients` prints, in the two-column shape
# ikev2ctl.parse_clients reads: a header row, then one row per client. Copied
# from a live instance; the CLI contract belongs to an image this repo does not
# own, which is why it is written down rather than invented.
LISTCLIENTS = "Client  Status\nasel1x  valid\noldphone  revoked\n"

# Three bundles, because `ikev2.sh --exportclient` writes three for every
# client. The filenames are ikev2ctl's own `-ikev2.<ext>` spellings -- the
# suffix `bundle_label` matches on to say which platform a file is for, and the
# thing the hand-typed Dart fixture got wrong. The contents are placeholders
# shaped like the real thing (a DER header, strongSwan's JSON, Apple's XML) and
# short on purpose: a real .p12 is an unprotected private key, and this file is
# checked in.
IKEV2_BUNDLES = {
    "kate-ikev2.p12": b"\x30\x82\x01\x00",
    "kate-ikev2.sswan": b'{"uuid": "placeholder"}',
    "kate-ikev2.mobileconfig": b"<?xml",
}


# ------------------------------------------------------------------- redaction


def _redact(payload: dict) -> dict:
    """Replace the values no two runs agree on. Keys are never touched.

    Two of them, and both are artefacts of where the test runs rather than of
    anything a command decided:

      the candidate name   render.write_candidate names it from the clock at
                           one-second resolution plus mkdtemp's randomness.
      the state directory  conftest points STATE_DIR at a per-run pytest
                           tmpdir; a server prints /etc/vpn-stack.

    The state directory is substituted wherever it appears in any string, at
    any depth, rather than only under `state_dir`. It leaks further than that:
    `protocol list`'s dnstt `notes` names ENV_FILE, which is STATE_DIR/.env, so
    a payload built by a fixed rule over a fixed key list would have baked one
    machine's tmpdir into a checked-in file and gone red on the next run
    anywhere else.

    Every placeholder keeps its value's shape, so the app parses it exactly as
    it parses the real thing, and no key is ever removed -- the key set is the
    whole thing under test.
    """
    tmpdir = str(STATE_DIR)

    def walk(value):
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, str):
            return value.replace(tmpdir, "/etc/vpn-stack")
        return value

    out = walk(payload)
    if out.get("rendered") is not None:
        out["rendered"] = "rendered-20260101T000000Z-fixture"
    return out


# -------------------------------------------------------------------- fixtures


@pytest.fixture
def contract_keyring(state_dir) -> None:
    """The seeded keyring on disk, in place of conftest's minted one."""
    for name, content in CONTRACT_SECRETS.items():
        secrets_store.write(name, content)


@pytest.fixture
def seeded(monkeypatch, contract_keyring) -> FakeServer:
    """A server with the contract keyring, the contract users and a live tree.

    The live tree matters: `config_changed` is null until there is a previous
    generation to diff against, and null is the shape that means "converged
    everything blindly". Every real server has applied at least once, so the
    fixtures are generated against one that has.
    """
    monkeypatch.setenv("VPN_ALLOW_CONVERGE", "1")
    monkeypatch.setattr(cli, "_JSON", True)
    users_store.save([make_user(**u) for u in CONTRACT_USERS])
    state.save(
        state.State(
            enabled=[p.name for p in protocols.ordered() if p.default_enabled],
            # A revocation that could not run when it was asked for. Seeded so
            # `status`'s list is not empty in the fixture: an always-empty list
            # proves nothing about whether the app can read a full one, and
            # this is the field that tells an operator somebody's certificate
            # may still work.
            revoke_pending=["oldphone"],
        )
    )
    fake = FakeServer()
    fake.install(monkeypatch)
    # docker inspect, reached by `status` and by apply's forwarding reconcile.
    monkeypatch.setattr(cli.ikev2ctl, "is_running", lambda: fake.ikev2_running)
    cli.apply(quiet=True)
    return fake


@pytest.fixture
def contract(capsys):
    """Run a command, redact, and hold the result to the checked-in file.

    Regeneration is opt-in rather than automatic, because a test that rewrites
    its own expectation cannot fail: `UPDATE_CONTRACT=1` is the reviewer's
    signal that the payload change is the point of the commit.
    """

    def run(name: str, command) -> dict:
        assert name in FIXTURE_NAMES, (
            f"{name} is not in FIXTURE_NAMES, so the orphan check below cannot "
            "see it. Add it there."
        )
        capsys.readouterr()
        command()
        out = capsys.readouterr().out
        assert out, f"{name}: the command printed nothing on stdout"
        payload = _redact(json.loads(out))
        path = FIXTURES / name
        # Serialised once, and the comparison is on this text rather than on the
        # parsed object. Two dicts compare equal across a reordering, and the
        # order is not free: jsonDecode keeps insertion order, so
        # `payload["protocols"]`'s order IS the order ShareBundle offers a tunnel
        # engine its URIs in, and `emit`'s key order is what an operator reads
        # down. A reordering therefore reached the app while dict equality here
        # stayed green -- measured, not feared: moving `users_enabled` above
        # `users` in cmd_status left all 21 of these passing.
        rendered = json.dumps(payload, indent=2) + "\n"
        if os.environ.get(UPDATE_ENV) == "1":
            FIXTURES.mkdir(parents=True, exist_ok=True)
            path.write_text(rendered)
            return payload
        assert path.exists(), (
            f"{path} does not exist. It is generated from cli.py by this test: "
            f"run `{UPDATE_ENV}=1 uv run --frozen --with pytest pytest "
            f"tests/test_json_contract.py` and commit it."
        )
        # splitlines() on both sides for two reasons: the diff pytest prints
        # (a line list names the one changed key, a single 8 KB string prints a
        # wall), and immunity to how the file was checked out -- splitlines
        # treats "\r\n" and "\n" alike, so a CRLF working copy compares equal
        # instead of failing on all 40 lines with nothing visibly different.
        assert rendered.splitlines() == path.read_text().splitlines(), (
            f"`vpnctl --json` no longer prints what {path} holds.\n"
            "That file is the contract between cli.py and the Flutter client: "
            "the app's tests parse it, and its models REFUSE a key they do not "
            "declare (app/lib/control/json.dart's rejectUnknown), so a renamed "
            "or added key here is an app that stops reading this command "
            "entirely. A key that only MOVED matters too: the app decodes into "
            "an order-preserving map, and the order of `protocols` is the order "
            "a tunnel engine is offered the URIs in.\n"
            "If the change is intended, update the app side in the SAME commit "
            f"and regenerate: `{UPDATE_ENV}=1 uv run --frozen --with pytest "
            f"pytest tests/test_json_contract.py`."
        )
        return payload

    return run


# ----------------------------------------------------------- read-only commands


def test_status(seeded, contract) -> None:
    contract("status.json", lambda: cli.cmd_status(Namespace()))


def test_user_list(seeded, contract) -> None:
    contract("user-list.json", lambda: cli.cmd_user_list(Namespace(show_secrets=False)))


def test_user_list_show_secrets(seeded, contract) -> None:
    payload = contract(
        "user-list-secrets.json",
        lambda: cli.cmd_user_list(Namespace(show_secrets=True)),
    )
    # The flag's whole job. Asserted here and not only in the file so that a
    # regeneration cannot quietly accept a payload that stopped carrying them.
    assert payload["users"][0]["hysteria2_password"]


def test_protocol_list(seeded, contract) -> None:
    contract("protocol-list.json", lambda: cli.cmd_protocol_list(Namespace()))


def test_ikev2_list_clients(seeded, contract, monkeypatch) -> None:
    monkeypatch.setattr(cli.ikev2ctl, "list_clients", lambda: (True, LISTCLIENTS))
    contract(
        "ikev2-list-clients.json",
        lambda: cli.cmd_ikev2_list(Namespace()),
    )


# ------------------------------------------------------------------- the export


def _export(**overrides):
    args = {"name": "kate", "protocol": "all", "host": HOST, "qr": False}
    return Namespace(**{**args, **overrides})


@pytest.fixture
def exportable(seeded, monkeypatch) -> FakeServer:
    """A user whose export reaches all three ShareItem shapes.

    dnstt has to be ON for that: it is the only protocol whose share() returns
    `fields`, and picking the wrong shape is not cosmetic -- a `uri` gets a QR
    code and a tappable link, `fields` get a form. ikev2's bundles come from
    the container, so that call is faked; everything else is the real pure
    share().
    """
    users = users_store.load()
    users.append(
        make_user(
            "kate",
            vless_uuid="3f2504e0-4f89-41d3-9a0c-0305e82c3301",
            hysteria2_password="8d2e1f0a7c6b5948372615049382a1b0",
            l2tp_password="e5d4c3b2a1908f7e6d5c4b3a29180716",
            dnstt_password="Qx7yPlum2zRt",
            ikev2_provisioned=True,
        )
    )
    users_store.save(users)
    st = state.load()
    # Registry order, not sorted(): `payload["protocols"]` is built by walking
    # st.enabled, jsonDecode preserves insertion order, and ShareBundle takes
    # that order as the order a tunnel engine is offered the URIs in. A server
    # whose state.json came from state.default() has registry order, which is
    # every server that has never toggled a protocol -- but `protocol on` writes
    # `sorted(...)`, so one toggle makes it alphabetical for good and dnstt's
    # settings card arrives first. Worth knowing before anything derives meaning
    # from the position of a key in here.
    st.enabled = [
        p.name for p in protocols.ordered() if p.name in {*st.enabled, "dnstt"}
    ]
    state.save(st)
    monkeypatch.setattr(
        cli.ikev2ctl,
        "export_client",
        lambda name: (True, "Exported:\n  three bundles", dict(IKEV2_BUNDLES)),
    )
    return seeded


def test_user_export(exportable, contract) -> None:
    payload = contract("user-export.json", lambda: cli.cmd_user_export(_export()))
    # The three shapes, by the key that decides which one the app builds.
    shapes = {
        proto: sorted({k for item in items for k in item})
        for proto, items in payload["protocols"].items()
    }
    assert "uri" in shapes["vless-reality"]
    assert "fields" in shapes["dnstt"]
    assert "filename" in shapes["ikev2"]


def test_user_export_with_a_failed_container_bundle(
    exportable, contract, monkeypatch
) -> None:
    # ok:false at exit 0, with every bundle that DID work still in the payload.
    # Only a share_via_container protocol can land in `failed` -- the pure
    # share()s either return items or raise -- so ikev2 is the only name that
    # can ever appear there, and the hand-typed Dart fixture claiming
    # `["hysteria2"]` described a payload cli.py cannot produce.
    monkeypatch.setattr(
        cli.ikev2ctl,
        "export_client",
        lambda name: (False, "Error: No such container: ipsec-vpn-server", {}),
    )
    payload = contract(
        "user-export-partial.json", lambda: cli.cmd_user_export(_export())
    )
    assert payload["ok"] is False
    assert payload["failed"] == ["ikev2"]
    assert "ikev2" not in payload["protocols"]


# ------------------------------------------------------------------- refusals

# die() is as much of the contract as emit() is: it prints the same envelope
# with `ok: false`, an `error` sentence the app shows verbatim, and whatever
# structured keys the caller attached. The app reads those keys -- `missing` is
# a map of protocol to the secrets it lacks -- so they drift exactly like any
# other payload.


@pytest.fixture
def refusal(contract):
    """Like `contract`, for a command that exits non-zero.

    die() prints its payload and raises SystemExit, so the exit code is part of
    what is asserted: 1 for a refusal, and the app distinguishes it from 75
    (the lock) and 2 (the not-the-server guard, which prints no JSON at all).
    """

    def run(name: str, command, code: int = 1) -> dict:
        captured: dict = {}

        def call() -> None:
            with pytest.raises(SystemExit) as exc:
                command()
            assert exc.value.code == code
            captured["code"] = exc.value.code

        payload = contract(name, call)
        assert payload["ok"] is False
        assert payload["error"]
        return payload

    return run


def test_apply_with_a_gap_in_the_keyring(state_dir, monkeypatch, refusal) -> None:
    # No keyring at all, which is what a damaged state directory looks like.
    # `missing` is why this payload is in here: it is structured, the app reads
    # it as a map of protocol to missing secret names, and deploy.sh
    # deliberately does NOT bootstrap -- so this refusal is the whole message an
    # operator gets, and the app has to be able to render it.
    monkeypatch.setattr(cli, "_JSON", True)
    monkeypatch.setenv("VPN_ALLOW_CONVERGE", "1")
    payload = refusal(
        "apply-missing-secrets.json", lambda: cli.cmd_apply(Namespace(no_restart=False))
    )
    assert set(payload["missing"]) == {"vless-reality", "hysteria2", "ikev2"}


def test_user_export_of_somebody_who_does_not_exist(seeded, refusal) -> None:
    # The plainest refusal there is: an envelope, a sentence, nothing else. It
    # is here so the app's "ok:false with an error" path is tested against a
    # payload cli.py really produced rather than one somebody typed.
    payload = refusal(
        "user-export-no-such-user.json",
        lambda: cli.cmd_user_export(_export(name="ghost")),
    )
    assert set(payload) == {"schema", "ok", "error"}


# -------------------------------------------------------- mutating commands


def test_apply(seeded, contract) -> None:
    # A second user's worth of change, so `config_changed` is a real list and
    # not the empty one every unchanged re-apply produces.
    users = users_store.load()
    users.append(make_user("kate", created_at="2026-09-20T11:02:44Z"))
    users_store.save(users)
    payload = contract("apply.json", lambda: cli.cmd_apply(Namespace(no_restart=False)))
    assert payload["config_changed"]


def test_user_add(seeded, contract) -> None:
    contract("user-add.json", lambda: cli.cmd_user_add(Namespace(name="kate")))


def test_user_rm(seeded, contract) -> None:
    contract("user-rm.json", lambda: cli.cmd_user_rm(Namespace(name="guest.phone")))


def test_user_enable(seeded, contract) -> None:
    contract(
        "user-enable.json",
        lambda: cli.cmd_user_enable(Namespace(name="guest.phone")),
    )


def test_user_disable(seeded, contract) -> None:
    payload = contract(
        "user-disable.json",
        lambda: cli.cmd_user_disable(Namespace(name="asel1x")),
    )
    # `enabled` here is the PERSON; `enabled_protocols` beside it is apply's
    # list. The two collided once inside emit(**result) and made every
    # invocation of this command raise TypeError.
    assert payload["enabled"] is False
    assert isinstance(payload["enabled_protocols"], list)


def test_protocol_on(seeded, contract) -> None:
    contract("protocol-on.json", lambda: cli.cmd_protocol_on(Namespace(name="dnstt")))


def test_protocol_off(seeded, contract) -> None:
    contract("protocol-off.json", lambda: cli.cmd_protocol_off(Namespace(name="ikev2")))


def test_protocol_on_something_already_on(seeded, contract) -> None:
    # The early return, and the only shape of this command that carries no
    # apply result at all. The app has to read `changed: false` and NOT invent
    # one, so the absence is as much a part of the contract as the keys are.
    payload = contract(
        "protocol-unchanged.json",
        lambda: cli.cmd_protocol_on(Namespace(name="vless-reality")),
    )
    assert payload["changed"] is False
    assert "rendered" not in payload


def test_bootstrap(state_dir, monkeypatch, contract) -> None:
    # Day 0 deliberately: no seeded keyring and no users, which is the one
    # bootstrap whose message names every secret it made. Those names are the
    # payload; the values it minted are random and never printed.
    monkeypatch.setattr(cli, "_JSON", True)
    contract("bootstrap.json", lambda: cli.cmd_bootstrap(Namespace(force=False)))
    # The message is a receipt for work that happened, so it has to be true.
    # Only the default-enabled set: dnstt's Noise keypair is prepare()'s job at
    # `protocol on`, deliberately not bootstrap's, so a fresh server is complete
    # without it.
    default = [p for p in protocols.ordered() if p.default_enabled]
    assert not bootstrap.missing_secrets(default)


# --------------------------------------------------------------- housekeeping


def test_the_fixture_directory_holds_exactly_these_payloads() -> None:
    """No orphans, in either direction.

    A fixture for a command that no longer exists is one the Dart side may
    still be parsing, and a command with no fixture is one whose payload can
    change unnoticed -- which is the state this whole file exists to leave.
    """
    on_disk = {p.name for p in FIXTURES.glob("*.json")}
    assert on_disk == set(FIXTURE_NAMES)


def test_every_payload_carries_the_envelope() -> None:
    """schema and ok, on every one of them, at the top level.

    The app refuses a payload whose `schema` it does not recognise before it
    looks at anything else, so a command that stopped emitting it would fail
    in the app with a message about the schema and nothing about the command.
    """
    for name in sorted(FIXTURE_NAMES):
        payload = json.loads((FIXTURES / name).read_text())
        assert payload["schema"] == cli.SCHEMA, name
        assert isinstance(payload["ok"], bool), name


def test_no_fixture_carries_a_key_whose_value_is_a_live_looking_secret() -> None:
    """The checked-in files must not contain anything from a real keyring.

    They are generated from CONTRACT_SECRETS, so this can only fail if
    somebody regenerates them against a state directory that is not the test
    one -- which is the accident guard.py exists for, one level down, and the
    reason CLAUDE.md says a clone must not be able to contain a credential.
    """
    for name in sorted(FIXTURE_NAMES):
        text = (FIXTURES / name).read_text()
        assert "PRIVATE KEY" not in text, name
        assert "/etc/vpn-stack/secrets" not in text, name
        for value in (
            CONTRACT_SECRETS["reality.key"].decode(),
            CONTRACT_SECRETS["ipsec.psk"].decode(),
        ):
            # The private halves are not part of any payload. If one appears,
            # share() started reading a key it is not allowed to need.
            assert value not in text, f"{name} carries {value[:8]}..."
