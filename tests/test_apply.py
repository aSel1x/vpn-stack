"""apply(): the only thing that changes the server, and the mark it must leave.

Called by none of the tests before this file, which is how the worst of the bugs
below survived. The one that matters most: `converge_pending` was set in exactly
one place, inside the --no-restart branch, so every failure BETWEEN the symlink
swap and the end of the converge left no mark at all. composectl.up fails
part-way by design (services sort dnstt, dnstt-sshd, ikev2, sing-box, so sing-box
is last and the usual stale victim), and the operator's retry then rendered a
byte-identical tree, diffed it to {}, bounced nothing, passed the readiness wait
because the OLD containers still held the ports, and printed "config unchanged;
nothing restarted" and "OK." with exit 0 while sing-box served the previous keys.
smoke.sh was green.

Docker, ufw and iptables are faked at the narrowest seam: the four composectl
entry points, firewall.reconcile, sbctl.check_config (which shells out to
scripts/check.sh, i.e. Docker) and the two ikev2ctl calls that touch iptables.
Everything else -- render, promote, prune, the diff, the state file -- is real,
under VPN_STATE_DIR. VPN_ALLOW_CONVERGE is set because apply deliberately
refuses to converge under a pointed state directory otherwise.
"""

from __future__ import annotations

from argparse import Namespace

import pytest

from conftest import make_user
from vpnctl import cli, protocols, render, state, users_store
from vpnctl.paths import RENDERED_LINK, STATE_DIR, STATE_JSON

DEFAULT_SET = [p.name for p in protocols.ordered() if p.default_enabled]


class FakeServer:
    """Every seam apply reaches the machine through, and what each one answers.

    Records the `changed` map `up` was handed, because that argument is the whole
    point of the diff: `None` means "recreate everything", and it is what a
    pending mark has to produce.
    """

    def __init__(self) -> None:
        self.check_ok = True
        self.up_ok = True
        self.teardown_ok = True
        self.ready = True
        self.not_running: list[str] | None = []
        self.firewall_ok = True
        self.ikev2_running = True
        self.forwarding_ok = True
        self.up_calls: list[dict[str, str] | None] = []
        self.ensured = 0
        self.removed = 0

    def install(self, monkeypatch) -> None:
        monkeypatch.setattr(
            cli.sbctl, "check_config", lambda path: (self.check_ok, "sing-box says no")
        )
        monkeypatch.setattr(cli.composectl, "up", self._up)
        monkeypatch.setattr(
            cli.composectl,
            "down_disabled",
            lambda enabled: (self.teardown_ok, "nothing to tear down"),
        )
        monkeypatch.setattr(cli.composectl, "wait_ready", self._wait_ready)
        monkeypatch.setattr(
            cli.composectl, "not_running", lambda enabled: self.not_running
        )
        monkeypatch.setattr(
            cli.firewall,
            "reconcile",
            lambda enabled: (self.firewall_ok, ["firewall already matches"]),
        )
        monkeypatch.setattr(cli.ikev2ctl, "is_running", lambda: self.ikev2_running)
        monkeypatch.setattr(
            cli.ikev2ctl, "ensure_ipv4_forwarding", self._ensure_forwarding
        )
        monkeypatch.setattr(
            cli.ikev2ctl, "remove_ipv4_forwarding", self._remove_forwarding
        )
        # reconcile_ikev2 has its own file; here it only has to be reached.
        monkeypatch.setattr(
            cli, "reconcile_ikev2", lambda: {"added": [], "revoked": [], "failed": []}
        )

    def _up(self, enabled, changed=None) -> tuple[bool, str]:
        self.up_calls.append(changed)
        return self.up_ok, "compose output"

    def _wait_ready(self, enabled) -> tuple[bool, list[str]]:
        if self.ready:
            return True, ["all 5 port(s) bound"]
        return False, ["10443/tcp still not bound after 240s"]

    def _ensure_forwarding(self) -> tuple[bool, str]:
        self.ensured += 1
        return self.forwarding_ok, "IKEv2 IPv4 FORWARD rules ensured"

    def _remove_forwarding(self) -> tuple[bool, str]:
        self.removed += 1
        return True, "removed 2 IKEv2 IPv4 FORWARD rule(s)"


@pytest.fixture
def server(monkeypatch, written_keyring) -> FakeServer:
    monkeypatch.setenv("VPN_ALLOW_CONVERGE", "1")
    users_store.save([make_user("alice")])
    state.save(state.State(enabled=DEFAULT_SET))
    fake = FakeServer()
    fake.install(monkeypatch)
    return fake


def generations() -> set[str]:
    return {p.name for p in STATE_DIR.glob("rendered-*") if p.is_dir()}


# ------------------------------------------------------- the validation gate


def test_a_rejected_config_leaves_the_live_tree_and_deletes_the_candidate(
    server,
) -> None:
    cli.apply()
    live = RENDERED_LINK.resolve()
    before = generations()

    server.check_ok = False
    with pytest.raises(SystemExit) as exc:
        cli.apply()

    assert exc.value.code == 1
    assert RENDERED_LINK.resolve() == live
    # The candidate holds every user's credentials at 0600; a rejected one is not
    # left lying beside the live tree waiting for prune to walk past it.
    assert generations() == before
    assert server.up_calls == [None]


# ------------------------------------------------------------------- the mark


def test_a_successful_apply_clears_the_mark(server) -> None:
    result = cli.apply()
    assert result["converge_pending"] is False
    assert state.load().converge_pending is False


def test_a_failed_up_leaves_the_mark_set(server) -> None:
    cli.apply()
    assert state.load().converge_pending is False

    server.up_ok = False
    with pytest.raises(SystemExit):
        cli.apply()

    # The whole bug: without this the retry diffs a byte-identical tree to {},
    # bounces nothing, and reports success while half the containers are stale.
    assert state.load().converge_pending is True


def test_a_failed_readiness_wait_leaves_the_mark_set(server) -> None:
    server.ready = False
    result = cli.apply()

    assert result["ports_ready"] is False
    assert result["converge_pending"] is True
    # A port that never bound means this convergence did not complete, so the
    # next apply has to re-converge rather than diff an unchanged tree. This is
    # what makes the warn-and-carry-on design safe.
    assert state.load().converge_pending is True


def test_a_failed_teardown_or_firewall_does_not_hold_the_mark(server) -> None:
    # Neither is a claim that the containers are running the wrong tree, so
    # neither keeps the mark -- but both are reported.
    server.teardown_ok = False
    server.firewall_ok = False
    result = cli.apply()

    assert result["teardown_ok"] is False
    assert result["firewall_ok"] is False
    assert result["converge_pending"] is False
    assert state.load().converge_pending is False


def test_no_restart_promotes_and_leaves_the_mark_set(server) -> None:
    result = cli.apply(restart=False)

    assert result["restarted"] is False
    assert result["converge_pending"] is True
    assert state.load().converge_pending is True
    assert server.up_calls == []


def test_a_pending_mark_forces_everything_to_be_recreated(server) -> None:
    cli.apply()
    st = state.load()
    st.converge_pending = True
    state.save(st)

    result = cli.apply()

    # The diff compares two directories, never a directory against a running
    # container, so a tree promoted without converging is invisible to it.
    assert result["config_changed"] is None
    assert server.up_calls[-1] is None
    assert state.load().converge_pending is False


def test_an_unchanged_tree_bounces_nothing(server) -> None:
    cli.apply()
    result = cli.apply()

    assert result["config_changed"] == []
    assert server.up_calls == [None, {}]


# ------------------------------------------------------------- the payload


def test_no_result_key_can_collide_with_a_callers_emit(server) -> None:
    # `apply`'s result is splatted into emit() beside the enclosing command's own
    # keys. `enabled_protocols` is spelled the long way because `enabled`
    # collided with the user flag and made `user enable` and `user disable` raise
    # TypeError on every single invocation.
    result = cli.apply()
    assert (
        set(result)
        & {
            "user",
            "enabled",
            "changed",
            "ok",
            "schema",
            "error",
            "message",
            "output",
        }
        == set()
    )


def test_every_converge_step_reports_a_machine_readable_verdict(server) -> None:
    # Beside the prose, not instead of it: everything after `up` warns and falls
    # through (the boot unit needs exit 0), so a caller has to be able to find
    # out whether the server is serving without pattern-matching English.
    result = cli.apply()

    for key in ("ports_ready", "teardown_ok", "firewall_ok", "forwarding_ok"):
        assert result[key] is True, key
    assert result["not_running"] == []
    assert result["ready"] == ["all 5 port(s) bound"]


def test_a_bound_port_is_not_health(server, capsys) -> None:
    # dnstt-sshd listens on loopback only, so it contributes no port to the wait
    # at all while dnstt-server goes on holding 53/udp -- every client then
    # completes a tunnel to a closed door.
    server.not_running = ["dnstt-sshd"]
    result = cli.apply()

    assert result["not_running"] == ["dnstt-sshd"]
    assert "dnstt-sshd" in capsys.readouterr().err


def test_docker_being_unable_to_answer_is_not_a_clean_bill_of_health(
    server, capsys
) -> None:
    server.not_running = None
    result = cli.apply()

    assert result["not_running"] is None
    assert "not proof" in capsys.readouterr().err


# ------------------------------------------------------- the FORWARD rules


def test_the_forward_rules_are_ensured_even_when_the_converge_dies(server) -> None:
    # They used to sit after every step that can die(), so a converge failure
    # skipped them silently -- and they are raw `iptables -I` inserts with no
    # persistence of their own: the difference between an IKEv2 SA that forwards
    # traffic and one that establishes and carries none.
    server.up_ok = False
    with pytest.raises(SystemExit):
        cli.apply()

    assert server.ensured == 1


def test_a_stopped_ikev2_container_is_recorded_rather_than_omitted(server) -> None:
    # An absent key reads as "not applicable" and "succeeded" identically.
    server.ikev2_running = False
    result = cli.apply()

    assert result["ikev2_forwarding"] == "skipped, container not running"
    assert result["forwarding_ok"] is False
    assert "ikev2_reconcile" not in result
    assert server.ensured == 0


def test_turning_ikev2_off_takes_its_forward_rules_with_it(server) -> None:
    state.save(state.State(enabled=[n for n in DEFAULT_SET if n != "ikev2"]))

    result = cli.apply()

    assert server.removed == 1
    assert server.ensured == 0
    assert result["forwarding_ok"] is True
    assert "removed" in result["ikev2_forwarding"]


def test_a_failed_forwarding_ensure_is_a_verdict_not_a_warning_only(server) -> None:
    server.forwarding_ok = False
    result = cli.apply()
    assert result["forwarding_ok"] is False


# --------------------------------------------------------------- housekeeping


def test_old_generations_are_pruned_even_when_the_converge_dies(server) -> None:
    for i in range(7):
        (STATE_DIR / f"rendered-20200101T00000{i}Z-old").mkdir()
    server.up_ok = False

    with pytest.raises(SystemExit):
        cli.apply()

    # The runs that leave a generation behind are exactly the ones that used to
    # skip the prune, because it sat on the fully successful path.
    assert len(generations()) == render.KEEP_GENERATIONS


def test_a_missing_state_file_says_the_default_set_is_in_force(server, capsys) -> None:
    STATE_JSON.unlink()

    cli.apply()

    err = capsys.readouterr().err
    assert "dnstt" in err and "53/udp" in err


def test_a_failed_step_does_not_get_reported_as_ok(server, capsys) -> None:
    # The exit code cannot carry this -- everything after `up` warns and falls
    # through because the boot unit depends on exit 0 -- so the last line a human
    # reads must not say OK over a port that never bound.
    server.ready = False
    cli.cmd_apply(Namespace(no_restart=False))

    out = capsys.readouterr().out
    assert "OK." not in out
    assert "ports_ready" in out

    server.ready = True
    cli.cmd_apply(Namespace(no_restart=False))
    assert "OK." in capsys.readouterr().out


def test_an_unanswerable_liveness_query_is_not_reported_as_ok(server, capsys) -> None:
    server.not_running = None
    cli.cmd_apply(Namespace(no_restart=False))

    out = capsys.readouterr().out
    assert "OK." not in out
    assert "not_running" in out
