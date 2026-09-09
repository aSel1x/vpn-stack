"""User-name validation, and the failure it exists to prevent.

render_ikev2_env joins names into VPN_ADDL_USERS and passwords into
VPN_ADDL_PASSWORDS, both space-separated, and the image pairs them by position.
A name with a space in it makes the two lists different lengths and hands one
user another's password. test_protocols_render demonstrates that concretely;
this file asserts the gate.
"""

from __future__ import annotations

from argparse import Namespace

import pytest

from vpnctl import cli, users_store

VALID = [
    "a",
    "alice",
    "Alice",
    "alice.smith",
    "alice_smith",
    "alice-smith",
    "u1",
    "0",
    "a" * 32,
]
INVALID = [
    "alice smith",  # the space-separated env lists misalign
    "alice\tsmith",
    "alice\nsmith",
    "",
    " ",
    "a" * 33,  # 32 is the cap
    ".alice",  # must start with a letter or digit
    "-alice",
    "alice;rm -rf /",
    "alice$USER",
    "alice'",
    'alice"',
    "ali/ce",
    "алиса",
]


@pytest.mark.parametrize("name", VALID)
def test_accepted(name: str) -> None:
    assert users_store.validate_name(name) is None


@pytest.mark.parametrize("name", INVALID, ids=repr)
def test_rejected(name: str) -> None:
    assert users_store.validate_name(name) is not None


def test_the_message_says_why_a_space_is_the_problem() -> None:
    message = users_store.validate_name("alice smith")
    assert "No spaces" in message
    assert "space-separated" in message
    assert "misalign" in message


def test_user_add_refuses_before_touching_the_database(capsys) -> None:
    """The gate is in front of load()/save(), not behind them.

    guard.require_server passes here (VPN_STATE_DIR exists), so this really
    does reach cmd_user_add's own check rather than being stopped earlier.
    """
    with pytest.raises(SystemExit) as excinfo:
        cli.cmd_user_add(Namespace(name="alice smith"))
    assert excinfo.value.code == 1
    assert "misalign" in capsys.readouterr().err
    assert not users_store.USERS_JSON.exists()


def test_user_add_reports_the_refusal_on_stderr_not_stdout(capsys) -> None:
    # --json is a public API: the payload owns stdout, everything else stderr.
    with pytest.raises(SystemExit):
        cli.cmd_user_add(Namespace(name="alice smith"))
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err
