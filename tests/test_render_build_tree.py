"""render.build_tree -- the pure half of `apply`.

Everything that reaches the disk in a real apply is decided here, so this is
the cheapest place to catch a protocol that overwrites a sibling's file, a port
collision, or a secret nobody generated.
"""

from __future__ import annotations

import json

import pytest

from vpnctl import protocols, render, secrets_store
from vpnctl.protocols import Kind, Port, Protocol, RenderError
from vpnctl.secrets_store import MissingSecret

ALL = protocols.ordered()

# What a full apply lays down, exactly. Written out rather than derived: this
# list is the contract compose.yml's bind mounts and composectl._CONSUMERS are
# both written against, and a silent addition to it is a file nothing reads.
EXPECTED_TREE = {
    "sing-box/00_base.json",
    "sing-box/90_outbounds.json",
    "sing-box/10_vless-reality.json",
    "sing-box/20_hysteria2.json",
    "sing-box/certs/certificate.pem",
    "sing-box/certs/private.key",
    "ikev2.env",
    "dnstt/server.key",
    "dnstt-sshd/logins",
    "dnstt.env",
}


def test_every_enabled_protocol_contributes(secrets, users) -> None:
    tree = render.build_tree(secrets, users, ALL)
    assert set(tree) == EXPECTED_TREE
    assert all(isinstance(v, bytes) for v in tree.values())


def test_the_untracked_half_comes_from_git(secrets, users) -> None:
    # The structural fragments are read out of the checkout, not generated, so
    # a clone can be diffed against what a server is serving.
    tree = render.build_tree(secrets, users, ALL)
    assert json.loads(tree["sing-box/00_base.json"])["log"]["level"] == "info"
    assert json.loads(tree["sing-box/90_outbounds.json"])["outbounds"]


def test_disabled_protocols_render_nothing(secrets, users) -> None:
    only_vless = protocols.ordered(["vless-reality"])
    tree = render.build_tree(secrets, users, only_vless)
    assert set(tree) == {
        "sing-box/00_base.json",
        "sing-box/90_outbounds.json",
        "sing-box/10_vless-reality.json",
    }


def test_a_disabled_user_appears_in_no_protocol(secrets, users) -> None:
    tree = render.build_tree(secrets, users, ALL)
    blob = b"".join(tree[k] for k in sorted(tree))
    assert b"bob" not in blob
    assert b"l2tp-bob" not in blob
    assert b"hy2-bob" not in blob
    assert b"alice" in blob


def test_two_protocols_writing_one_path_is_refused(secrets, users) -> None:
    # Nothing in the registry does this today; the check exists because a new
    # protocol module is one line away and the loser would be silently dropped.
    clash = Protocol(
        name="clash",
        kind=Kind.SINGBOX,
        order=99,
        ports=(Port(9999, "tcp"),),
        summary="",
        secret_names=(),
        default_enabled=False,
        render=lambda s, u: {"sing-box/10_vless-reality.json": b"{}"},
        share=lambda s, u, h: [],
        bootstrap=dict,
    )
    with pytest.raises(RenderError, match="would overwrite"):
        render.build_tree(secrets, users, [*ALL, clash])


def test_port_conflicts_are_caught_before_anything_renders(secrets, users) -> None:
    squatter = Protocol(
        name="squatter",
        kind=Kind.SINGBOX,
        order=99,
        ports=(Port(10443, "tcp"),),
        summary="",
        secret_names=(),
        default_enabled=False,
        render=lambda s, u: {"sing-box/99.json": b"{}"},
        share=lambda s, u, h: [],
        bootstrap=dict,
    )
    with pytest.raises(RenderError, match="port conflict"):
        render.build_tree(secrets, users, [*ALL, squatter])


def test_a_missing_secret_names_itself_and_the_file(users) -> None:
    with pytest.raises(MissingSecret) as excinfo:
        render.build_tree(secrets_store.Secrets(values={}), users, ALL)
    message = str(excinfo.value)
    assert "reality.key" in message
    assert "vpnctl bootstrap" in message


def test_build_tree_is_deterministic(secrets, users) -> None:
    assert render.build_tree(secrets, users, ALL) == render.build_tree(
        secrets, users, ALL
    )


def test_build_tree_writes_nothing(secrets, users, state_dir) -> None:
    render.build_tree(secrets, users, ALL)
    assert list(state_dir.iterdir()) == []
