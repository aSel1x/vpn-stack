"""render() for all four protocols, plus the purity invariant it rests on."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from conftest import make_user
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate

from vpnctl import paths, protocols, secrets_store, users_store
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
    # dnstt is the exception and has its own tests below: an empty login list is
    # a crash-loop, not an empty file.
    for proto in protocols.ordered():
        if proto.name == dnstt.NAME:
            continue
        out = proto.render(secrets, [])
        assert isinstance(out, dict)
    assert (
        ikev2.render(secrets, [])["ikev2.env"]
        .decode()
        .endswith("VPN_ADDL_USERS=\nVPN_ADDL_PASSWORDS=\n")
    )


# ------------------------------------------------- what render refuses to emit


@pytest.mark.parametrize(
    "users_in",
    [
        [],
        [make_user("bob", enabled=False)],
        [make_user("carol", dnstt_password="")],
    ],
    ids=["no users at all", "everybody disabled", "everybody predating the field"],
)
def test_dnstt_refuses_to_render_an_empty_login_list(secrets, users_in) -> None:
    """The one failure in this stack that nothing downstream can observe.

    dnstt-sshd/entrypoint.sh exits 1 on a list with no logins, on purpose -- an
    sshd with zero accounts looks healthy and answers nobody -- and compose
    restarts it forever. That crash-loop is invisible to both health checks:
    composectl's readiness wait and scripts/smoke.sh watch non-loopback ports,
    and this sshd binds 127.0.0.1 only, while dnstt itself goes on answering
    udp/53 into a tunnel whose far end refuses every login.
    """
    with pytest.raises(protocols.RenderError) as excinfo:
        dnstt.render(secrets, users_in)
    message = str(excinfo.value)
    assert "empty" in message
    # The three ways out, because the operator is holding a failed apply: the
    # candidate tree was never promoted, so nothing is broken yet.
    assert "enable a user" in message and "dnstt off" in message


def test_dnstt_still_renders_when_only_some_users_lack_a_login(
    secrets, users, capsys
) -> None:
    # The partial case stays a warning and must never become fatal: the file it
    # renders is usable by everybody who does have a password, and the refusal
    # above would otherwise turn one stale record into a failed apply.
    assert dnstt.render(secrets, users)["dnstt-sshd/logins"] == b"alice:dnsttalice\n"
    assert "carol" in capsys.readouterr().err


@pytest.mark.parametrize(
    "name", ["alice smith", "al:ice", "alice\nbob", "al ice", "root"]
)
def test_dnstt_refuses_a_name_the_login_file_cannot_hold(secrets, name) -> None:
    """`name:password` per line, read by `while IFS=: read -r name password`.

    A colon or a newline in a name does not fail there -- it silently becomes a
    different account, or two, with the password cut short. The shared validator
    already excludes both, so this asserts that render() consults it rather than
    trusting whatever users.json holds.
    """
    with pytest.raises(protocols.RenderError, match="users.json"):
        dnstt.render(secrets, [make_user(name)])


def test_dnstt_refuses_a_password_that_would_split_the_line(secrets) -> None:
    # The same corruption from the other side: the newline ends the record and
    # the remainder becomes a login line of its own.
    bad = make_user("alice", dnstt_password="first\nmallory:second")
    with pytest.raises(protocols.RenderError) as excinfo:
        dnstt.render(secrets, [bad])
    assert "newline" in str(excinfo.value)
    # A live credential, so the message names the user and not the value.
    assert "mallory:second" not in str(excinfo.value)


def test_a_disabled_user_with_an_unrenderable_name_blocks_nothing(secrets) -> None:
    # Nothing of a disabled user is rendered, by either protocol, so refusing on
    # one would make a name that predates the validator brick every apply with
    # no way to reach the record.
    bad = make_user("alice smith", enabled=False)
    good = make_user("carol")
    assert ikev2.render(secrets, [bad, good])
    assert dnstt.render(secrets, [bad, good])["dnstt-sshd/logins"] == (
        b"carol:dnsttcarol\n"
    )


def test_the_hysteria2_certificate_is_one_a_verifier_can_reason_about(
    secrets, users
) -> None:
    """It carried no extensions at all, which left clients only two choices.

    With no subjectAltName there is nothing for RFC 6125 name matching to match
    -- the CN has not been a name source for a decade -- and with no
    basicConstraints nothing says the leaf is not a CA. So a client could pin the
    certificate or switch verification off entirely, and "off entirely" is what
    people reach for. Pinning still carries this deployment; this is about what
    happens when a client does not.
    """
    cert = load_pem_x509_certificate(secrets.raw("hysteria2.crt"))
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    # The same name three times over: the SAN, the SNI the share link tells
    # clients to send, and the server_name the inbound is rendered with. A SAN
    # naming anything else would verify for nobody.
    assert san.value.get_values_for_type(x509.DNSName) == [hysteria2.MASQUERADE]
    inbound = json.loads(
        hysteria2.render(secrets, users)["sing-box/20_hysteria2.json"]
    )["inbounds"][0]
    assert inbound["tls"]["server_name"] == hysteria2.MASQUERADE
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert (basic.value.ca, basic.value.path_length) == (False, None)
    assert basic.critical is True


def test_sing_box_logs_at_warn(secrets) -> None:
    """A privacy property of this stack decided by a default, until it wasn't.

    At `info` sing-box logs every connection with the authenticated user name
    beside the client's source address and the destination host, so the rolling
    json-file log compose gives that container correlates person <-> residential
    IP <-> site visited -- the record this whole stack exists so that nobody else
    can build. Asserted here because 00_base.json is JSON and cannot say why
    itself; the reasoning is in vpnctl/protocols/__init__.py's docstring, and
    what `warn` gives up is a thin `./vpn logs sing-box` when a client cannot
    connect.
    """
    base = json.loads((paths.SING_BOX_COMMON / "00_base.json").read_bytes())
    assert base["log"]["level"] == "warn"
    # Nothing in vpnctl or scripts/smoke.sh parses these lines -- both assert on
    # bound ports -- so the level is free to be chosen for privacy alone.
    assert base["log"]["disabled"] is False


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


def _module_functions(module) -> dict[str, ast.FunctionDef]:
    tree = ast.parse(Path(module.__file__).read_text())
    return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}


def _reachable(module, name: str) -> list[ast.FunctionDef]:
    """`name` plus every module-local function it calls, transitively.

    Inspecting only the top-level body left a hole the size of the helpers:
    hysteria2 computes both of its pins in _fingerprint/_spki_sha256 and dnstt
    reads the zone through _zone, so an open() moved one call deep passed. One
    level of resolution covers every helper this tree has today; the walk is
    transitive regardless, because a worklist costs three lines and guessing
    wrong costs the invariant being silently unchecked.

    Imported callables are deliberately out of scope -- validate_name belongs to
    users_store, and this test cannot own another module's purity.
    """
    functions = _module_functions(module)
    seen: set[str] = set()
    queue = [name]
    found: list[ast.FunctionDef] = []
    while queue:
        current = queue.pop()
        if current in seen or current not in functions:
            continue
        seen.add(current)
        node = functions[current]
        found.append(node)
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name):
                queue.append(inner.func.id)
    assert found, f"{module.NAME} has no top-level {name}()"
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
    for checked in _reachable(module, func):
        where = f"{module.NAME}.{checked.name} (reached from {func})"
        for node in ast.walk(checked):
            if isinstance(node, ast.Name):
                assert node.id not in _BANNED, f"{where} calls {node.id}()"
                assert node.id not in _BANNED_MODULES, f"{where} uses {node.id}"
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                assert node.value.id not in _BANNED_MODULES, (
                    f"{where} uses {node.value.id}"
                )


def test_the_purity_walk_reaches_the_helpers_and_not_the_whole_import_graph() -> None:
    # The hole this closed, asserted rather than assumed: hysteria2.share does
    # nothing itself, its two pins are computed one call deeper, and dnstt.render
    # reads the zone through _zone.
    reached = {node.name for node in _reachable(hysteria2, "share")}
    assert {"share", "_fingerprint", "_spki_sha256"} <= reached
    assert "_zone" in {node.name for node in _reachable(dnstt, "render")}
    # And it stops at the module edge: nothing here can vouch for users_store.
    assert "validate_name" not in {node.name for node in _reachable(ikev2, "render")}


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


def test_ikev2_refuses_a_name_that_would_misalign_the_lists(secrets) -> None:
    """The damage this replaces, and why the check cannot live at `user add`.

    VPN_ADDL_USERS and VPN_ADDL_PASSWORDS are two space-separated strings the
    hwdsl2 image zips back together by position. Rendered rather than refused,
    `alice smith` made the lists three names against two passwords: "smith" was
    handed carol's password and carol -- the only real second user -- was handed
    none, on an env file that renders, validates and serves. `user add` rejects
    the name, but render() is given whatever users.json holds, and a hand edit,
    an older backup or a rolled-back checkout can all put it there.
    """
    # The password deliberately has no space of its own: one bad *name* was
    # enough to break the pairing for everyone after it.
    bad = [make_user("alice smith", l2tp_password="l2tp-alice"), make_user("carol")]
    with pytest.raises(protocols.RenderError) as excinfo:
        ikev2.render(secrets, bad)
    message = str(excinfo.value)
    assert "alice smith" in message  # which record to go and fix
    assert "user rm" in message  # and how, given apply just failed


def test_ikev2_refuses_a_password_that_would_misalign_the_lists(secrets) -> None:
    # The same misalignment from the password side. `user add` generates
    # token_hex, so only a hand-edited or imported record can do this -- which is
    # exactly the input render() is not allowed to trust.
    bad = [make_user("alice", l2tp_password="two words"), make_user("carol")]
    with pytest.raises(protocols.RenderError) as excinfo:
        ikev2.render(secrets, bad)
    assert "alice" in str(excinfo.value)
    # Never the value: this message is printed and that is a live credential.
    assert "two words" not in str(excinfo.value)


def test_a_reserved_name_does_not_break_every_apply_when_dnstt_is_off(secrets) -> None:
    """ikev2 must enforce the file-format rule and not the dnstt-container one.

    `validate_name` has two halves: characters that would corrupt a rendered file,
    and names that collide with an account inside the dnstt sshd image. ikev2
    render() called the whole thing, so a user legally created before that
    reserved list existed -- `mail`, say, which the old regex accepted -- made
    EVERY apply raise, including the one the systemd boot unit runs, on a box
    with dnstt switched off and ikev2 enabled by default. The remedy would have
    been unreachable from the server itself.

    The file-format half still has to bite here, because it is what stops one
    user being handed another's L2TP password.
    """
    legacy = make_user("mail")
    assert users_store.reserved_name("mail") is not None
    assert users_store.unrenderable_name("mail") is None

    # ikev2 renders it: nothing about `mail` misaligns a space-separated list.
    env = ikev2.render(secrets, [legacy])["ikev2.env"].decode()
    assert "mail" in env

    # dnstt is the protocol whose container cannot serve it, so dnstt refuses --
    # and only when dnstt is enabled, which is what makes the refusal escapable.
    with pytest.raises(protocols.RenderError) as refusal:
        dnstt.render(secrets, [legacy])
    assert "mail" in str(refusal.value)

    # And the format rule still applies to ikev2, or the split would have traded
    # one bug for a worse one.
    with pytest.raises(protocols.RenderError):
        ikev2.render(secrets, [make_user("bad name")])
