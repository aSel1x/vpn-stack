"""reconcile_ikev2: the only writer of ikev2_provisioned, and the only drainer
of revoke_pending.

It had no tests, and that is why the worst bug in this repository survived in
it. `user rm alice` with ikev2 down queues the revocation and deletes the record
-- the certificate is deliberately left alone, because the intent is what
outlives the command. `user add alice` afterwards is a DIFFERENT person under a
reused name. Reconcile skipped the queued revocation "because the name is wanted
again", found alice in --listclients so issued nothing, wrote
ikev2_provisioned=True from that observation and emptied the queue: the new
holder's profile was the previous holder's key pair, the previous holder's
exported profile went on working, and --exportclient's .p12 has a verified EMPTY
password, so the file itself is the access.

Nothing here needs Docker. ikev2ctl is faked one function at a time -- the four
calls that reach a container, and nothing else -- so the parse, the two
directions of the diff and the queue arithmetic are all the real code.
"""

from __future__ import annotations

import pytest

from conftest import make_user
from vpnctl import cli, state, users_store
from vpnctl.paths import STATE_JSON, USERS_JSON


def listing(**status: str) -> str:
    """`ikev2.sh --listclients` output, header row and all."""
    rows = "".join(
        f"{name:<22}{state_:<12}Sep 25, 2036\n" for name, state_ in status.items()
    )
    return (
        "Checking for IKEv2 clients...\n\n"
        "Client                Status      Expires\n"
        f"{rows}"
    )


class FakeIkev2:
    """The four calls that reach the container, and a record of each one.

    `fails` holds (op, name) pairs that answer failure, because the interesting
    behaviour is almost all about what happens when one of them does: a
    revocation that fails has to stay queued, and a revocation that succeeds has
    to be the only thing that clears the queue.
    """

    def __init__(
        self,
        clients: str = "",
        running: bool = True,
        list_ok: bool = True,
        fails: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.clients = clients
        self.running = running
        self.list_ok = list_ok
        self.fails = set(fails)
        self.calls: list[tuple[str, str]] = []

    def is_running(self) -> bool:
        return self.running

    def list_clients(self) -> tuple[bool, str]:
        return (
            self.list_ok,
            self.clients if self.list_ok else "Error: no such container",
        )

    def _do(self, op: str, name: str) -> tuple[bool, str]:
        self.calls.append((op, name))
        if (op, name) in self.fails:
            return False, f"{op} {name} failed"
        return True, f"{op} {name} ok"

    def add_client(self, name: str) -> tuple[bool, str]:
        return self._do("add", name)

    def remove_client(self, name: str) -> tuple[bool, str]:
        return self._do("remove", name)

    def delete_client(self, name: str) -> tuple[bool, str]:
        return self._do("delete", name)


@pytest.fixture
def fake(monkeypatch):
    def install(**kwargs) -> FakeIkev2:
        stub = FakeIkev2(**kwargs)
        for name in (
            "is_running",
            "list_clients",
            "add_client",
            "remove_client",
            "delete_client",
        ):
            monkeypatch.setattr(cli.ikev2ctl, name, getattr(stub, name))
        return stub

    return install


def setup_db(users: list[users_store.User], pending: list[str] | None = None) -> None:
    users_store.save(users)
    state.save(state.State(enabled=["ikev2"], revoke_pending=pending or []))


def provisioned() -> dict[str, bool]:
    return {u.name: u.ikev2_provisioned for u in users_store.load()}


def test_a_failed_listing_writes_nothing_at_all(fake) -> None:
    # Reading an empty client list as "nobody is issued" would re-add every
    # user, fail on "already exists", and then record that nobody is provisioned
    # while every certificate kept working. Both files have to be untouched.
    setup_db([make_user("alice", ikev2_provisioned=True)], pending=["bob"])
    before = (USERS_JSON.read_bytes(), STATE_JSON.read_bytes())
    stub = fake(list_ok=True)
    stub.list_ok = False

    result = cli.reconcile_ikev2()

    assert result["skipped"] == "listclients failed"
    assert stub.calls == []
    assert (USERS_JSON.read_bytes(), STATE_JSON.read_bytes()) == before


def test_a_stopped_container_writes_nothing_at_all(fake) -> None:
    setup_db([make_user("alice")], pending=["bob"])
    before = (USERS_JSON.read_bytes(), STATE_JSON.read_bytes())
    stub = fake(running=False)

    assert cli.reconcile_ikev2() == {"skipped": "ikev2 container not running"}
    assert stub.calls == []
    assert (USERS_JSON.read_bytes(), STATE_JSON.read_bytes()) == before


def test_a_queued_revocation_runs_and_leaves_the_queue(fake) -> None:
    setup_db([make_user("alice")], pending=["bob"])
    stub = fake(clients=listing(alice="valid", bob="valid"))

    result = cli.reconcile_ikev2()

    assert ("remove", "bob") in stub.calls
    assert result["revoked"] == ["bob"]
    assert state.load().revoke_pending == []


def test_a_failed_revocation_stays_queued(fake) -> None:
    # The name in revoke_pending is the only record that somebody's certificate
    # still grants access. It may leave the queue when the removal succeeded --
    # never because the attempt was made.
    setup_db([make_user("alice")], pending=["bob"])
    stub = fake(clients=listing(alice="valid", bob="valid"), fails=(("remove", "bob"),))

    result = cli.reconcile_ikev2()

    assert result["failed"] == ["bob"]
    assert result["revoked"] == []
    assert state.load().revoke_pending == ["bob"]
    assert stub.calls == [("remove", "bob")]


def test_a_queued_name_that_is_wanted_again_is_revoked_then_reissued(fake) -> None:
    # The bug, in one test. `alice` is queued (removed while ikev2 was down) and
    # is wanted again -- a different person, or the same name reused. Skipping
    # the revocation left the new holder importing the old holder's key pair.
    setup_db([make_user("alice")], pending=["alice"])
    stub = fake(clients=listing(alice="valid"))

    result = cli.reconcile_ikev2()

    assert stub.calls == [("remove", "alice"), ("add", "alice")]
    assert result["revoked"] == ["alice"]
    assert result["added"] == ["alice"]
    assert state.load().revoke_pending == []
    assert provisioned() == {"alice": True}


def test_a_revocation_that_fails_for_a_wanted_name_issues_nothing(fake) -> None:
    # Half of the fix would be worse than none: re-issuing while the previous
    # certificate is still valid means two people hold a working profile for one
    # name, and the queue would then look drained.
    setup_db([make_user("alice")], pending=["alice"])
    stub = fake(clients=listing(alice="valid"), fails=(("remove", "alice"),))

    result = cli.reconcile_ikev2()

    assert stub.calls == [("remove", "alice")]
    assert result["added"] == []
    assert result["failed"] == ["alice"]
    assert state.load().revoke_pending == ["alice"]
    assert provisioned() == {"alice": True}


def test_a_revoked_certificate_is_not_a_certificate(fake) -> None:
    # A revoked name was counted as present, so a wanted user was never
    # re-issued -- and was recorded provisioned anyway: a profile that cannot
    # connect, written down as one that can. --addclient answers "already
    # exists" until the reserved name is deleted, which is why delete comes
    # first.
    setup_db([make_user("alice")])
    stub = fake(clients=listing(alice="revoked"))

    result = cli.reconcile_ikev2()

    assert stub.calls == [("delete", "alice"), ("add", "alice")]
    assert result["added"] == ["alice"]
    assert provisioned() == {"alice": True}


def test_a_name_that_cannot_be_freed_is_not_reported_as_issued(fake) -> None:
    setup_db([make_user("alice")])
    stub = fake(clients=listing(alice="revoked"), fails=(("delete", "alice"),))

    result = cli.reconcile_ikev2()

    assert stub.calls == [("delete", "alice")]
    assert result == {"added": [], "revoked": [], "failed": ["alice"]}
    assert provisioned() == {"alice": False}


def test_a_queued_name_the_container_does_not_hold_leaves_the_queue(
    fake, capsys
) -> None:
    # A lost volume, or a restore from a backup older than the certificate:
    # there is nothing to revoke, and retrying for ever would put a permanent
    # failure in every apply's payload for a name that exists nowhere.
    setup_db([make_user("alice")], pending=["ghost"])
    stub = fake(clients=listing(alice="valid"))

    result = cli.reconcile_ikev2()

    assert stub.calls == []
    assert result["failed"] == []
    assert state.load().revoke_pending == []
    assert "ghost" in capsys.readouterr().err


def test_an_unwanted_revoked_certificate_is_left_alone(fake) -> None:
    # Nothing to withdraw, and --revokeclient on an already-revoked client
    # fails, which would plant the same failure in every apply from then on.
    setup_db([make_user("alice")])
    stub = fake(clients=listing(alice="valid", bob="revoked"))

    result = cli.reconcile_ikev2()

    assert stub.calls == []
    assert result == {"added": [], "revoked": [], "failed": []}


def test_a_disabled_user_loses_the_certificate_and_the_flag(fake) -> None:
    setup_db(
        [make_user("alice"), make_user("bob", enabled=False, ikev2_provisioned=True)]
    )
    stub = fake(clients=listing(alice="valid", bob="valid"))

    result = cli.reconcile_ikev2()

    assert stub.calls == [("remove", "bob")]
    assert result["revoked"] == ["bob"]
    assert provisioned() == {"alice": True, "bob": False}


def test_provisioned_is_written_from_the_listing_not_from_the_record(fake) -> None:
    # Observed truth, both directions and without touching the container: alice
    # holds a certificate the database denied, bob's record claims one the
    # container does not have and nothing was issued because bob is disabled.
    setup_db(
        [
            make_user("alice", ikev2_provisioned=False),
            make_user("bob", enabled=False, ikev2_provisioned=True),
        ]
    )
    stub = fake(clients=listing(alice="valid"))

    cli.reconcile_ikev2()

    assert stub.calls == []
    assert provisioned() == {"alice": True, "bob": False}


def test_the_standalone_command_does_not_exit_zero_on_a_failed_revocation(
    fake, monkeypatch
) -> None:
    # `ikev2 reconcile` reported ok and exited 0 whatever happened. A name in
    # `failed` after a revocation attempt means a certificate that still grants
    # access -- the one thing the operator who ran this needs to hear about.
    setup_db([make_user("alice")], pending=["bob"])
    fake(clients=listing(alice="valid", bob="valid"), fails=(("remove", "bob"),))

    with pytest.raises(SystemExit) as exc:
        cli.cmd_ikev2_reconcile(None)

    assert exc.value.code == 1


def test_a_skipped_reconcile_is_not_a_failure(fake) -> None:
    # It could not observe the truth and refused to guess, which is the contract
    # the app documents. Reporting that as a failed command would make a box with
    # ikev2 off answer an error to a command that behaved correctly.
    setup_db([make_user("alice")])
    fake(running=False)

    cli.cmd_ikev2_reconcile(None)
