"""The precondition that stops a laptop from becoming a second VPN server.

This is the regression test for the audit's single biggest finding: `vpnctl
user add` on a developer machine did not fail. It SUCCEEDED -- it wrote a local
copy of the same live credentials, rendered a config and started a real
sing-box bound to the laptop's ports. Documentation could not fix that; a
precondition can, and this file is what keeps the precondition honest.

Everything here runs in a subprocess, because paths.py resolves STATE_DIR at
IMPORT time from $VPN_STATE_DIR -- the same reason conftest sets the variable in
its module body rather than in a fixture. There is no in-process way to make an
already-imported vpnctl see a different directory: `from vpnctl.paths import
STATE_DIR` binds the value, so patching the attribute afterwards would test a
mock of the guard instead of the guard. A fresh interpreter with the variable
pointed at a directory that does not exist is the real thing, and it also lets
these tests assert what the CLI wrote -- which must be nothing at all.

The commands exercised below are the ones that stop at the guard and could not
reach Docker even if they got past it. `apply` and `protocol on` are left out on
purpose: if the guard ever regressed, running those here would shell out to
docker compose from the test suite, and this suite must need no daemon.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from vpnctl import paths

# Two lines, each run in its own interpreter: the guard alone, and the whole CLI
# reaching it through a real command. `-c` puts the script in argv[0], so the
# arguments a test passes start at argv[1] for the first and are what argparse
# sees for the second.
GUARD = "import sys; from vpnctl import guard; guard.require_server(sys.argv[1])"
IS_SERVER = "from vpnctl import guard; print(guard.is_server())"
CLI = "from vpnctl.cli import main; main()"

DOCUMENTED_EXIT_CODE = 2


def _run(program: str, *argv: str, state_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", program, *argv],
        env={**os.environ, "VPN_STATE_DIR": str(state_dir)},
        cwd=paths.ROOT,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def absent(tmp_path: Path) -> Path:
    """A state directory that is not there -- i.e. any machine but the server."""
    path = tmp_path / "not-the-server" / "etc" / "vpn-stack"
    assert not path.exists()
    return path


def test_the_guard_refuses_and_names_both_the_action_and_the_path(absent) -> None:
    done = _run(GUARD, "user add", state_dir=absent)
    assert done.returncode == DOCUMENTED_EXIT_CODE
    # Both halves, because the message has to answer "what did I just stop" and
    # "why" at once: an operator who sees only "this is not the VPN server" on a
    # box that IS one has no idea which directory vpnctl went looking for.
    assert "user add" in done.stderr
    assert str(absent) in done.stderr
    # And it says where the command does belong, plus the documented test escape
    # hatch -- otherwise the advice is "run it somewhere else, good luck".
    assert "VPN_STATE_DIR" in done.stderr
    assert done.stdout == ""


def test_the_refusal_goes_to_stderr_so_json_stays_parseable(absent) -> None:
    # --json is a public API: `./vpn share` parses stdout. A refusal printed
    # there would be handed to a JSON parser as the payload.
    done = _run(GUARD, "apply", state_dir=absent)
    assert done.stdout == ""
    assert "apply" in done.stderr


def test_is_server_is_exactly_whether_the_state_directory_is_there(
    absent, tmp_path
) -> None:
    assert _run(IS_SERVER, state_dir=absent).stdout.strip() == "False"
    present = tmp_path / "is-the-server"
    present.mkdir()
    assert _run(IS_SERVER, state_dir=present).stdout.strip() == "True"


# The commands that write. Each one used to run to completion on a laptop.
MUTATING = [
    ("user", "add", "anna"),
    ("user", "rm", "anna"),
    ("user", "enable", "anna"),
    ("user", "disable", "anna"),
    ("bootstrap",),
]


@pytest.mark.parametrize("argv", MUTATING, ids=lambda a: " ".join(a))
def test_a_mutating_command_writes_nothing_off_server(argv, absent) -> None:
    done = _run(CLI, *argv, state_dir=absent)
    assert done.returncode == DOCUMENTED_EXIT_CODE
    # The whole tree, not just the file: paths.py has no fallback to the
    # checkout any more, so a guard that let this through would have created
    # the directory on its way to writing live credentials into it. Inside that
    # process this path IS users_store.USERS_JSON.
    assert not (absent / "users.json").exists()
    assert not (absent / "secrets").exists()
    assert not absent.exists()


def test_the_guard_does_not_stand_in_the_way_of_a_read_only_command(
    absent,
) -> None:
    # `status` reports is_server() as a field instead of refusing: the point of
    # the guard is that mutations cannot happen off-server, not that a laptop
    # may not ask a question. If this starts failing, the guard has been moved
    # somewhere too general.
    done = _run(CLI, "status", "--json", state_dir=absent)
    assert done.returncode == 0
    assert '"is_server": false' in done.stdout
