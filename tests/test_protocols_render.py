"""render() for all four protocols, plus the purity invariant it rests on."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from conftest import make_user

from vpnctl import protocols, secrets_store
from vpnctl.protocols import dnstt, hysteria2, ikev2, vless_reality


def _drop(secrets: secrets_store.Secrets, name: str) -> secrets_store.Secrets:
    return secrets_store.Secrets(
        values={k: v for k, v in secrets.values.items() if k != name}
    )


def test_vless_inbound_carries_only_enabled_users(secrets, users) -> None:
    body = json.loads(
        vless_reality.render(secrets, users)["sing-box/10_vless-reality.json"]
    )
    (inbound,) = body["inbounds"]
    assert inbound["listen_port"] == 10443
    assert inbound["tls"]["reality"]["private_key"] == secrets.text("reality.key")
    assert [u["name"] for u in inbound["users"]] == ["alice", "carol"]
    assert all(u["flow"] == "xtls-rprx-vision" for u in inbound["users"])


def test_vless_renders_the_private_half_and_never_the_public_one(
    secrets, users
) -> None:
    # sing-box wants the private key; the public half is for share links only.
    blob = vless_reality.render(secrets, users)["sing-box/10_vless-reality.json"]
    assert secrets.text("reality.pub").encode() not in blob


def test_hysteria2_emits_its_certificate_beside_the_config(secrets, users) -> None:
    out = hysteria2.render(secrets, users)
    assert out["sing-box/certs/certificate.pem"] == secrets.raw("hysteria2.crt")
    assert out["sing-box/certs/private.key"] == secrets.raw("hysteria2.key")
    body = json.loads(out["sing-box/20_hysteria2.json"])
    (inbound,) = body["inbounds"]
    # certs/ lives inside the -C directory on purpose: -C merges *.json and
    # does not recurse, so the certificates are invisible to the config loader.
    assert inbound["tls"]["certificate_path"] == "/etc/sing-box/certs/certificate.pem"
    assert [u["password"] for u in inbound["users"]] == ["hy2-alice", "hy2-carol"]


def test_ikev2_env_is_two_space_separated_lists_in_the_same_order(
    secrets, users
) -> None:
    env = ikev2.render(secrets, users)["ikev2.env"].decode()
    lines = dict(line.split("=", 1) for line in env.strip().splitlines())
    assert lines["VPN_ADDL_USERS"].split() == ["alice", "carol"]
    assert lines["VPN_ADDL_PASSWORDS"].split() == ["l2tp-alice", "l2tp-carol"]
    # The primary slot stays the random junk from the keyring: every real user
    # goes through the additional lists, including the first.
    assert lines["VPN_USER"] == secrets.text("ipsec.primary_user")


def test_dnstt_renders_one_login_per_enabled_user_with_a_password(
    secrets, users
) -> None:
    out = dnstt.render(secrets, users)
    # carol predates dnstt_password; bob is disabled. Neither gets a login.
    assert out["dnstt-sshd/logins"] == b"alice:dnsttalice\n"
    assert out["dnstt/server.key"] == secrets.raw("dnstt.server.key")
    env = out["dnstt.env"].decode()
    assert "SSH_PORT=2222" in env
    assert "PERMIT_OPEN=any" in env


def test_dnstt_says_out_loud_who_it_left_out(secrets, users, capsys) -> None:
    # There is deliberately no migration command, so this warning is the whole
    # story a user with no dnstt_password ever gets.
    dnstt.render(secrets, users)
    err = capsys.readouterr().err
    assert "carol" in err
    assert "bob" not in err  # disabled, not broken
    assert "users.json" in err


def test_dnstt_without_a_zone_warns_and_renders_anyway(secrets, users, capsys) -> None:
    """It used to raise, and that bricked every later command on the server.

    Nothing this function renders carries the zone -- compose's `command:` does
    -- so refusing bought nothing and cost an operator who ran `protocol on
    dnstt` before setting it a box where apply, `user add`, `deploy` and the
    systemd boot unit all exited 1. The refusal lives at `protocol on` now,
    where the toggle can still be rolled back.
    """
    out = dnstt.render(_drop(secrets, dnstt.ZONE_KEY), users)
    assert out["dnstt-sshd/logins"] == b"alice:dnsttalice\n"
    assert "VPN_DNSTT_ZONE" in capsys.readouterr().err


def test_no_users_still_renders_a_valid_shape(secrets) -> None:
    for proto in protocols.ordered():
        out = proto.render(secrets, [])
        assert isinstance(out, dict)
    assert (
        ikev2.render(secrets, [])["ikev2.env"]
        .decode()
        .endswith("VPN_ADDL_USERS=\nVPN_ADDL_PASSWORDS=\n")
    )
    assert dnstt.render(secrets, [])["dnstt-sshd/logins"] == b""


def test_render_output_is_bytes_with_relative_paths(secrets, users) -> None:
    for proto in protocols.ordered():
        for rel, content in proto.render(secrets, users).items():
            assert isinstance(content, bytes)
            assert not Path(rel).is_absolute()
            assert ".." not in Path(rel).parts


# --------------------------------------------------------------------- purity

_BANNED = {"open", "eval", "exec", "compile", "input"}
# `sys` is absent on purpose: dnstt.render prints its "no login for X" warning
# to stderr, which is the whole story a user predating dnstt_password gets.
_BANNED_MODULES = {"subprocess", "shutil", "socket", "os", "pathlib", "requests"}


def _function(module, name: str) -> ast.FunctionDef:
    tree = ast.parse(Path(module.__file__).read_text())
    (found,) = [
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name
    ]
    return found


@pytest.mark.parametrize(
    "module", [vless_reality, hysteria2, ikev2, dnstt], ids=lambda m: m.NAME
)
@pytest.mark.parametrize("func", ["render", "share"])
def test_render_and_share_do_no_io(module, func: str) -> None:
    """The seam a future GUI renders share links through, enforced.

    Structural rather than behavioural on purpose: a mock can only prove the
    call did not happen for one input. dnstt.render's print() to stderr is the
    one deliberate exception and is not I/O on the returned value.
    """
    for node in ast.walk(_function(module, func)):
        if isinstance(node, ast.Name):
            assert node.id not in _BANNED, f"{module.NAME}.{func} calls {node.id}()"
            assert node.id not in _BANNED_MODULES, (
                f"{module.NAME}.{func} uses {node.id}"
            )
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            assert node.value.id not in _BANNED_MODULES


def test_render_and_share_ignore_the_process_environment(
    secrets, users, monkeypatch
) -> None:
    # Same seam, from the other side: an env var read inside render() would
    # make a client app and the server disagree about what they generated.
    before = {p.name: p.render(secrets, users) for p in protocols.ordered()}
    monkeypatch.setenv("VPN_DNSTT_ZONE", "somebody-elses.example")
    monkeypatch.setenv("VPN_SERVER_HOST", "203.0.113.9")
    after = {p.name: p.render(secrets, users) for p in protocols.ordered()}
    assert before == after


def test_a_user_with_a_space_in_its_name_misaligns_the_ikev2_lists(secrets) -> None:
    """Why validate_name rejects spaces, demonstrated rather than asserted.

    VPN_ADDL_USERS and VPN_ADDL_PASSWORDS are two space-separated lists the
    hwdsl2 image zips back together by position. One name with a space in it
    makes the lists different lengths, and every user after it is handed
    somebody else's password.
    """
    # The password deliberately has no space of its own: one bad *name* is
    # enough to break the pairing for everyone after it.
    bad = [make_user("alice smith", l2tp_password="l2tp-alice"), make_user("carol")]
    env = ikev2.render(secrets, bad)["ikev2.env"].decode()
    lines = dict(line.split("=", 1) for line in env.strip().splitlines())
    names = lines["VPN_ADDL_USERS"].split()
    passwords = lines["VPN_ADDL_PASSWORDS"].split()
    assert names == ["alice", "smith", "carol"]
    assert passwords == ["l2tp-alice", "l2tp-carol"]
    assert len(names) != len(passwords)
    # The concrete damage: "smith" is handed carol's password, and carol -- the
    # only real second user -- is handed none at all.
    paired = dict(zip(names, passwords))
    assert paired["smith"] == "l2tp-carol"
    assert "carol" not in paired
