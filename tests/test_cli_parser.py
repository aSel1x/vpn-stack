"""The command surface: --json in any position, the lock, and honest exit codes.

`--json` is a public API and the app builds its command lines programmatically,
so `vpnctl --json user export x` and `vpnctl user export x --json` have to mean
the same thing. argparse.SUPPRESS on the shared parent is what makes that work --
without it the subparser's own default overwrites a value already set at the top
level -- and that is a thing that breaks silently, everywhere, at once.

The lock half is here for the deadlock it has to avoid. Every caller already
wraps vpnctl in flock(1), and flock(1) opens its own file description, which the
kernel treats as a different holder: a plain blocking lock taken inside the
process would wait for a lock its own parent never releases. Measured, not
assumed -- `timeout 3 flock LK bash -c 'timeout 2 flock LK echo INNER'` prints
nothing and the inner command is killed at its own timeout.
"""

from __future__ import annotations

import json
import os
from argparse import Namespace

import pytest

from conftest import make_user
from vpnctl import cli, protocols, state, users_store

READ_ONLY = (
    ["status"],
    ["user", "list"],
    ["user", "export", "alice"],
    ["protocol", "list"],
    ["ikev2", "list-clients"],
)

MUTATING = (
    ["apply"],
    ["bootstrap"],
    ["protocol", "on", "dnstt"],
    ["protocol", "off", "dnstt"],
    ["user", "add", "alice"],
    ["user", "rm", "alice"],
    ["user", "enable", "alice"],
    ["user", "disable", "alice"],
    ["ikev2", "reconcile"],
)


def parse(argv: list[str]):
    return cli.build_parser().parse_args(argv)


@pytest.mark.parametrize("argv", [*READ_ONLY, *MUTATING])
def test_json_is_accepted_before_or_after_the_subcommand(argv) -> None:
    assert getattr(parse(["--json", *argv]), "json", False) is True
    assert getattr(parse([*argv, "--json"]), "json", False) is True


@pytest.mark.parametrize("argv", [*READ_ONLY, *MUTATING])
def test_a_command_without_the_flag_reports_false_rather_than_raising(argv) -> None:
    # SUPPRESS means the attribute is genuinely absent, so every reader has to go
    # through getattr with a default -- main() does, and so must anything else.
    args = parse(argv)
    assert getattr(args, "json", False) is False


def test_the_flag_survives_an_option_and_a_positional_between() -> None:
    args = parse(["user", "export", "alice", "--protocol", "ikev2", "--json"])
    assert args.json is True
    assert args.protocol == "ikev2"
    assert args.name == "alice"


@pytest.mark.parametrize("argv", MUTATING)
def test_every_mutating_command_declares_itself_one(argv) -> None:
    # Declared on the subparser rather than matched against a list of names in
    # main(): the list and the parser get edited at different times, and a new
    # mutating subcommand nobody added to the list takes no lock while looking
    # exactly like one that does.
    assert parse(argv).mutates is True


@pytest.mark.parametrize("argv", READ_ONLY)
def test_the_readers_take_no_lock(argv, tmp_path, monkeypatch) -> None:
    # They must not be able to fail because an apply is running: users.json and
    # state.json are written through a temp file and os.replace, so a reader never
    # sees half of one, and the app polls `status` during exactly that window.
    lock = tmp_path / "vpn-stack.lock"
    monkeypatch.setattr(cli, "LOCK_FILE", lock)
    held = cli._acquire_lock(lock)
    try:
        assert cli._lock_if_mutating(parse(argv)) is None
    finally:
        os.close(held)


def test_a_second_holder_is_refused_with_ex_tempfail(tmp_path, capsys) -> None:
    # Non-blocking on purpose. flock(1) inside flock(1) on the same path blocks
    # for ever, so the second answer has to be an error, and 75 is the code
    # `flock -E 75` in the app's wrapper already reserves for "somebody else is
    # mid-apply" -- busy, distinguishable from broken.
    lock = tmp_path / "vpn-stack.lock"
    first = cli._acquire_lock(lock)
    try:
        with pytest.raises(SystemExit) as exc:
            cli._acquire_lock(lock)
        assert exc.value.code == 75
        assert "holds" in capsys.readouterr().err
    finally:
        os.close(first)


def test_the_handshake_keeps_a_wrapped_call_from_deadlocking(
    tmp_path, monkeypatch
) -> None:
    # ./vpn, deploy.sh, install.sh, the boot unit and the app all export this
    # after taking the lock through flock(1). Without honouring it, every one of
    # those call sites would meet a lock its own parent holds.
    lock = tmp_path / "vpn-stack.lock"
    monkeypatch.setattr(cli, "LOCK_FILE", lock)
    monkeypatch.setenv("VPN_STACK_LOCK_HELD", "1")
    outer = cli._acquire_lock(lock)
    try:
        assert cli._lock_if_mutating(parse(["apply"])) is None
    finally:
        os.close(outer)


def test_a_mutating_command_takes_the_lock_when_nobody_else_holds_it(
    tmp_path, monkeypatch
) -> None:
    lock = tmp_path / "vpn-stack.lock"
    monkeypatch.setattr(cli, "LOCK_FILE", lock)
    monkeypatch.delenv("VPN_STACK_LOCK_HELD", raising=False)
    fd = cli._lock_if_mutating(parse(["user", "add", "alice"]))
    try:
        assert fd is not None
        assert lock.exists()
    finally:
        os.close(fd)


def test_an_unopenable_lock_is_loud_and_not_fatal(tmp_path, capsys) -> None:
    # /run is root-only and everything a mutating command does needs root
    # anyway, so this is a test directory or a dev box -- where refusing would
    # break the documented VPN_STATE_DIR escape hatch for no gain.
    assert cli._acquire_lock(tmp_path / "no-such-dir" / "lock") is None
    assert "cannot take" in capsys.readouterr().err


# ------------------------------------------------------ exit codes that told
# the truth about a partial failure, and the two that did not


@pytest.fixture
def as_json(monkeypatch):
    """Make emit() actually emit, the way `--json` does in main()."""
    monkeypatch.setattr(cli, "_JSON", True)

    def payload(capsys) -> dict:
        return json.loads(capsys.readouterr().out)

    return payload


def test_a_failed_client_listing_is_not_an_empty_client_list(monkeypatch) -> None:
    # It reported ok:false and exited 0. The listing IS the answer here, so a
    # caller trusting the exit code reads a failed query as "nobody has a
    # certificate" -- the misreading reconcile_ikev2 aborts rather than make.
    monkeypatch.setattr(cli.ikev2ctl, "is_running", lambda: True)
    monkeypatch.setattr(
        cli.ikev2ctl, "list_clients", lambda: (False, "Error: no such container")
    )

    with pytest.raises(SystemExit) as exc:
        cli.cmd_ikev2_list(parse(["ikev2", "list-clients"]))

    assert exc.value.code == 1


def test_a_successful_listing_says_ok_once(monkeypatch, as_json, capsys) -> None:
    monkeypatch.setattr(cli.ikev2ctl, "is_running", lambda: True)
    monkeypatch.setattr(cli.ikev2ctl, "list_clients", lambda: (True, "alice valid"))

    cli.cmd_ikev2_list(parse(["ikev2", "list-clients"]))

    assert as_json(capsys) == {
        "schema": cli.SCHEMA,
        "ok": True,
        "output": "alice valid",
    }


def test_bootstrap_does_not_report_success_for_a_set_it_refused(monkeypatch) -> None:
    # bootstrap_keyring returns True whenever some OTHER protocol's keys were
    # written, so the bool answers "did anything get written", not "is the
    # keyring sound". A half-present set left alone needs the missing file
    # restored or the whole set regenerated -- the one outcome that demands a
    # decision was the one that looked fine.
    monkeypatch.setattr(
        cli.bootstrap,
        "bootstrap_keyring",
        lambda force: (
            True,
            "generated 3 secret(s): ipsec.psk\n"
            "NOT refilled: hysteria2 (missing hysteria2.key).",
        ),
    )

    with pytest.raises(SystemExit) as exc:
        cli.cmd_bootstrap(parse(["bootstrap"]))

    assert exc.value.code == 1


@pytest.mark.parametrize(
    "answer",
    [
        # Nothing to do is success: a complete keyring is what the command is for.
        (False, "keyring already complete (12 secrets), nothing generated."),
        # So is a gap rebuilt from surviving material -- no client credential moved.
        (
            True,
            "rebuilt 1 secret(s) from surviving material: reality.pub "
            "-- no client credential changed",
        ),
    ],
)
def test_the_other_two_bootstrap_outcomes_exit_zero(
    monkeypatch, as_json, capsys, answer
) -> None:
    monkeypatch.setattr(cli.bootstrap, "bootstrap_keyring", lambda force: answer)

    cli.cmd_bootstrap(parse(["bootstrap"]))

    assert as_json(capsys)["ok"] is True


# ------------------------------------------------- the share shape nothing emitted


def file_protocol(items) -> protocols.Protocol:
    return protocols.Protocol(
        name="fileproto",
        kind=protocols.Kind.SINGBOX,
        order=99,
        ports=(),
        summary="a protocol whose deliverable is a file",
        secret_names=(),
        default_enabled=False,
        render=lambda secrets, users: {},
        share=lambda secrets, user, host: items,
        bootstrap=lambda: {},
    )


def export_args() -> Namespace:
    return Namespace(
        name="alice", protocol="all", host="vpn.example.com", qr=False, json=True
    )


def test_a_file_shaped_share_item_reaches_the_payload(
    monkeypatch, as_json, capsys
) -> None:
    # The loop printed `uri`, then `fields`, and dropped anything else without a
    # word -- so the first protocol whose pure share() returns a file would have
    # reported ok with the one deliverable the recipient needed simply absent.
    # The dict is the shape ikev2's container-produced bundles already use,
    # because to the app both are one ShareFile.
    item = protocols.ShareItem(
        label="iOS/macOS", filename="alice.mobileconfig", uri=None, content=b"PROFILE"
    )
    monkeypatch.setitem(protocols.PROTOCOLS, "fileproto", file_protocol([item]))
    users_store.save([make_user("alice")])
    state.save(state.State(enabled=["fileproto"]))

    cli.cmd_user_export(export_args())

    assert as_json(capsys)["protocols"]["fileproto"] == [
        {
            "filename": "alice.mobileconfig",
            "label": "iOS/macOS",
            "b64": "UFJPRklMRQ==",
        }
    ]


def test_an_export_that_produced_nothing_does_not_report_success(monkeypatch) -> None:
    # ok:true with an empty payload exits 0 and reads as "done", for a command
    # whose entire purpose is to hand somebody a credential.
    monkeypatch.setitem(protocols.PROTOCOLS, "fileproto", file_protocol([]))
    users_store.save([make_user("alice")])
    state.save(state.State(enabled=["fileproto"]))

    with pytest.raises(SystemExit) as exc:
        cli.cmd_user_export(export_args())

    assert exc.value.code == 1
