"""share() for all four protocols.

The vless-reality half of this file exists for one commit: share() now reads
reality.pub out of the keyring and only derives it from reality.key when the
public half is absent. The two paths must agree, or a server bootstrapped
before reality.pub existed hands out links that differ from a fresh one's.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from conftest import DNSTT_PUB, ZONE, make_user

from vpnctl import protocols, secrets_store
from vpnctl.protocols import RenderError, dnstt, hysteria2, ikev2, vless_reality
from vpnctl.reality_key import derive_public_key

HOST = "198.51.100.7"


def _drop(secrets: secrets_store.Secrets, name: str) -> secrets_store.Secrets:
    return secrets_store.Secrets(
        values={k: v for k, v in secrets.values.items() if k != name}
    )


# --------------------------------------------------------- vless-reality: pbk


def test_share_prefers_the_stored_public_key(secrets) -> None:
    (item,) = vless_reality.share(secrets, make_user("alice"), HOST)
    pbk = parse_qs(urlparse(item.uri).query)["pbk"]
    assert pbk == [secrets.text("reality.pub")]


def test_share_falls_back_to_deriving_it(secrets) -> None:
    # The compatibility path: a keyring bootstrapped before reality.pub existed
    # has the private half and nothing else.
    legacy = _drop(secrets, "reality.pub")
    (item,) = vless_reality.share(legacy, make_user("alice"), HOST)
    pbk = parse_qs(urlparse(item.uri).query)["pbk"]
    assert pbk == [derive_public_key(secrets.text("reality.key"))]


def test_both_paths_produce_the_same_uri_for_a_matching_pair(secrets) -> None:
    """The whole point of storing the public half: it changes nothing.

    If these two ever disagree, every client issued before the change stops
    matching the server -- silently, because both links are well-formed.
    """
    user = make_user("alice")
    stored = vless_reality.share(secrets, user, HOST)
    derived = vless_reality.share(_drop(secrets, "reality.pub"), user, HOST)
    assert stored == derived


def test_reality_pub_is_not_required_to_render(secrets, users) -> None:
    # Deliberately absent from secret_names: requiring it would make every
    # pre-change server fail to render instead of quietly carrying on.
    assert "reality.pub" not in vless_reality.PROTOCOL.secret_names
    assert vless_reality.render(_drop(secrets, "reality.pub"), users)


def test_the_stored_half_wins_over_the_private_key(secrets) -> None:
    """Reading, not deriving -- provable only when the two disagree.

    Nothing should ever write a mismatched pair; this asserts which of the two
    share() actually consults, which the matching-pair test cannot.
    """
    other = derive_public_key(vless_reality.generate_private_key())
    mismatched = secrets_store.Secrets(
        values={**secrets.values, "reality.pub": other.encode()}
    )
    (item,) = vless_reality.share(mismatched, make_user("alice"), HOST)
    assert parse_qs(urlparse(item.uri).query)["pbk"] == [other]


def test_the_private_key_never_reaches_a_share_link(secrets) -> None:
    (item,) = vless_reality.share(secrets, make_user("alice"), HOST)
    assert secrets.text("reality.key") not in item.uri


def test_vless_uri_shape(secrets) -> None:
    user = make_user("alice")
    (item,) = vless_reality.share(secrets, user, HOST)
    parsed = urlparse(item.uri)
    assert parsed.scheme == "vless"
    assert parsed.username == user.vless_uuid
    assert (parsed.hostname, parsed.port) == (HOST, 10443)
    assert parsed.fragment == "alice"
    query = parse_qs(parsed.query)
    assert query["sni"] == ["www.apple.com"]
    assert query["flow"] == ["xtls-rprx-vision"]
    assert query["sid"] == [secrets.text("reality.short_id")]


def test_a_name_needing_quoting_is_quoted(secrets) -> None:
    # validate_name would reject this, but share() is also fed names from
    # backups and from an app, and a raw '#' truncates the fragment.
    (item,) = vless_reality.share(secrets, make_user("a b#c"), HOST)
    assert item.uri.endswith("#a%20b%23c")


# ------------------------------------------------------------------ hysteria2


def test_hysteria2_uri_pins_the_certificate_it_renders(secrets) -> None:
    (item,) = hysteria2.share(secrets, make_user("alice"), HOST)
    parsed = urlparse(item.uri)
    assert parsed.scheme == "hysteria2"
    assert (parsed.hostname, parsed.port) == (HOST, 20443)
    assert parsed.username == "hy2-alice"
    pin = parse_qs(parsed.query)["pinSHA256"][0]
    assert pin == hysteria2._fingerprint(secrets.raw("hysteria2.crt"))
    assert len(pin.split(":")) == 32  # SHA-256, colon-separated hex


def test_hysteria2_uri_also_pins_the_public_key_for_sing_box(secrets) -> None:
    """The pin a sing-box client can actually check.

    `pinSHA256` hashes the whole DER certificate, which is the hysteria2
    convention; sing-box's only pinning field hashes the public KEY and encodes
    it base64. Not convertible, so a client built on sing-box could do nothing
    with the pin this server published and had to choose between failing the
    handshake and trusting any certificate. Both are emitted now.
    """
    import base64
    import hashlib

    from cryptography.hazmat.primitives import serialization
    from cryptography.x509 import load_pem_x509_certificate

    (item,) = hysteria2.share(secrets, make_user("alice"), HOST)
    spki = parse_qs(urlparse(item.uri).query)["spki"][0]

    cert = load_pem_x509_certificate(secrets.raw("hysteria2.crt"))
    expected = base64.b64encode(
        hashlib.sha256(
            cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).digest()
    ).decode()
    assert spki == expected
    assert len(base64.b64decode(spki)) == 32
    # It is a hash of a public key. Asserting it is not the certificate hash
    # guards the mistake that would make it useless: emitting the same bytes
    # twice under two names.
    assert spki != hysteria2._fingerprint(secrets.raw("hysteria2.crt"))


# The app's parser REFUSES a parameter it does not know (app/lib/config/
# hysteria2.dart and vless_reality.dart each keep a `_known` set), so adding one
# here without adding it there makes every link unimportable -- and the app's
# fixtures are transcribed by hand, so its tests stay green while the product
# breaks. These two assertions are the cross-reference: change share() and they
# fail, naming the file to change with it.
def test_the_parameter_names_hysteria2_emits_are_the_ones_the_app_knows(
    secrets,
) -> None:
    (item,) = hysteria2.share(secrets, make_user("alice"), HOST)
    assert set(parse_qs(urlparse(item.uri).query)) == {
        "obfs",
        "obfs-password",
        "sni",
        "pinSHA256",
        "spki",
    }, (
        "update `_known` in app/lib/config/hysteria2.dart and the fixture in app/test/config_fakes.dart"
    )


def test_the_parameter_names_vless_emits_are_the_ones_the_app_knows(
    secrets,
) -> None:
    (item,) = vless_reality.share(secrets, make_user("alice"), HOST)
    assert set(parse_qs(urlparse(item.uri).query)) == {
        "encryption",
        "flow",
        "security",
        "sni",
        "fp",
        "pbk",
        "sid",
        "type",
        "headerType",
    }, (
        "update `_known` in app/lib/config/vless_reality.dart and the fixture in app/test/config_fakes.dart"
    )


def test_hysteria2_private_key_never_reaches_a_share_link(secrets) -> None:
    (item,) = hysteria2.share(secrets, make_user("alice"), HOST)
    assert "PRIVATE KEY" not in item.uri


def test_hysteria2_share_needs_no_private_key_at_all(secrets) -> None:
    """Why neither pin is stored, which is the opposite of reality.pub's reason.

    reality.pub exists because deriving it meant reading the private X25519 key,
    and a pure seam that needs a private key is a seam that ships one to a phone.
    A fingerprint and an SPKI hash are functions of the certificate, which is
    public and already in the keyring -- so a caller holding a keyring with the
    private half removed builds the identical link, and there is nothing to
    store that could drift out of step with the certificate it describes.
    """
    public_only = _drop(secrets, "hysteria2.key")
    user = make_user("alice")
    assert hysteria2.share(public_only, user, HOST) == hysteria2.share(
        secrets, user, HOST
    )


# --------------------------------------------------------- ShareItem's shapes


def test_an_item_in_two_shapes_is_refused_where_it_is_built(secrets) -> None:
    """Every layer above branches on which field is set, and in a fixed order.

    cli.cmd_user_export tests `uri` first, so a two-shaped item is not ambiguous
    in practice -- it is silently the wrong one of the two, and the file half
    goes nowhere. Refused at construction so the traceback names the protocol
    module rather than the renderer.
    """
    with pytest.raises(RenderError, match="exactly one"):
        protocols.ShareItem(
            label="both", filename="a.mobileconfig", uri="hysteria2://x", content=b"x"
        )


def test_an_item_in_no_shape_is_refused(secrets) -> None:
    # A labelled empty row on somebody's share page, otherwise.
    with pytest.raises(RenderError, match="exactly one"):
        protocols.ShareItem(label="nothing", filename=None, uri=None)


def test_a_named_file_must_carry_its_content(secrets) -> None:
    # The shape is filename *plus* content: a name with nothing behind it is a
    # download of zero bytes, which reads as a successful export.
    with pytest.raises(RenderError, match="no content"):
        protocols.ShareItem(label="file", filename="client.p12", uri=None)


def test_the_filename_shape_is_documented_as_having_no_consumer() -> None:
    """Kept deliberately, and the docstring is the only record of the catch.

    cli.cmd_user_export prints `uri`, then `fields`, and drops anything else
    without a word -- so a protocol that starts returning a filename-shaped item
    has to add that branch in the same change, or `user export` reports ok with
    the one file the recipient asked for missing from the payload.
    """
    doc = protocols.ShareItem.__doc__
    assert "cli.cmd_user_export" in doc


# ----------------------------------------------------------------------- dnstt


def test_dnstt_shares_fields_not_a_uri(secrets) -> None:
    """A QR of a settings blob is a QR that fails silently in somebody's hands.

    DNSTT-over-SSH has no import format at all, so these are `fields`: a form
    to copy by hand. Every layer above keys off exactly this distinction.
    """
    items = dnstt.share(secrets, make_user("alice"), HOST)
    assert items
    for item in items:
        assert item.uri is None
        assert item.filename is None
        assert item.fields
        assert all(isinstance(k, str) and isinstance(v, str) for k, v in item.fields)


def test_dnstt_fields_carry_this_users_own_login(secrets) -> None:
    phone, laptop = dnstt.share(secrets, make_user("alice"), HOST)
    fields = dict(phone.fields)
    assert fields["Nameserver / domain"] == ZONE
    assert fields["Public key"] == DNSTT_PUB.decode().strip()
    assert fields["SSH username"] == "alice"
    assert fields["SSH password"] == "dnsttalice"
    assert "alice@127.0.0.1" in dict(laptop.fields)["2. SOCKS through it"]


def test_dnstt_says_so_when_a_user_predates_the_field(secrets) -> None:
    phone, _ = dnstt.share(secrets, make_user("carol", dnstt_password=""), HOST)
    assert "none issued" in dict(phone.fields)["SSH password"]


def test_dnstt_says_so_when_the_keypair_was_never_generated(secrets) -> None:
    phone, _ = dnstt.share(_drop(secrets, "dnstt.server.pub"), make_user("alice"), HOST)
    assert dict(phone.fields)["Public key"] == "<not generated>"


def test_dnstt_share_without_a_zone_refuses(secrets) -> None:
    """A settings card naming a zone nobody delegated is worse than an error.

    The zone arrives in the snapshot now, not from module state, so a snapshot
    without it is exactly what a caller that never read .env hands in -- which
    is why this drops the key rather than patching a global.
    """
    with pytest.raises(RenderError, match="VPN_DNSTT_ZONE"):
        dnstt.share(_drop(secrets, dnstt.ZONE_KEY), make_user("alice"), HOST)


def test_dnstt_share_reads_the_zone_from_its_argument_only(
    secrets, monkeypatch
) -> None:
    # The seam a GUI holding (secrets, user, host) renders through: no .env, no
    # environment, no server. A module global read at import broke exactly this.
    monkeypatch.setenv("VPN_DNSTT_ZONE", "somebody-elses.example")
    phone, _ = dnstt.share(secrets, make_user("alice"), HOST)
    assert dict(phone.fields)["Nameserver / domain"] == ZONE


# ------------------------------------------------------------------- registry


def test_ikev2_shares_nothing_purely(secrets) -> None:
    # Its bundles are produced by ikev2.sh inside the container, which is what
    # share_via_container announces -- so the pure seam returns nothing rather
    # than pretending.
    assert ikev2.share(secrets, make_user("alice"), HOST) == []
    assert ikev2.PROTOCOL.share_via_container is True


def test_share_is_a_pure_function_of_its_arguments(secrets) -> None:
    user = make_user("alice")
    for proto in protocols.ordered():
        assert proto.share(secrets, user, HOST) == proto.share(secrets, user, HOST)


def test_dnstt_is_per_user_and_still_shareable(secrets) -> None:
    # per_user governs provisioning, never sharing: filtering `user export` on
    # it made the command silently return nothing for dnstt.
    assert dnstt.PROTOCOL.per_user is True
    assert dnstt.share(secrets, make_user("alice"), HOST)


def test_every_share_item_has_exactly_one_shape(secrets, users) -> None:
    for proto in protocols.ordered():
        for user in users:
            for item in proto.share(secrets, user, HOST):
                shapes = [bool(item.uri), bool(item.filename), bool(item.fields)]
                assert sum(shapes) == 1, f"{proto.name}: {item.label} is ambiguous"
                assert item.label
