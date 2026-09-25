"""composectl: what counts as "bound", and what gets bounced when.

Readiness (`_is_bound`, `wait_ready`): "bound" means bound where the outside
world is. Substring-matching a port number reports dnstt's 53/udp as served on
any stock Ubuntu, because systemd-resolved holds 127.0.0.53:53. Both this and
scripts/smoke.sh parse the address for that reason. Two kinds of test: canned
`ss` output (deterministic, and the only way to exercise lines this machine may
not produce), and a real socket checked through the real `ss` (skipped where ss
is absent).

Convergence (`changed_services`, `_consumer`, `_container_ids`, `up`): the half
that decides whether a container is touched at all. Nothing here needs a Docker
daemon -- `_compose` and `_container_ids` are replaced one attribute at a time,
and that is the only seam the module shells out through.

Teardown and liveness (`down_disabled`, `not_running`): the two questions whose
answers must distinguish "nothing is running" from "I could not find out".
Collapsing the second into the first reports a clean bill of health it has not
earned -- once as `protocol off` succeeding while the protocol served traffic,
and, for liveness, as an `apply` that passes because 53/udp is bound while the
sshd behind the tunnel crash-loops.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
from pathlib import Path

import pytest
from test_render_build_tree import EXPECTED_TREE

from vpnctl import composectl, protocols, render
from vpnctl.paths import ROOT

SS = shutil.which("ss")


# Verbatim from a stock Ubuntu: systemd-resolved's two stub listeners, `%lo`
# scope suffix and all. This exact output is why the check parses the address
# instead of grepping the port number.
RESOLVED = "UNCONN 0 0 127.0.0.54:53 0.0.0.0:*\nUNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n"
SERVED = "UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\n"


class FakeSs:
    """Replaces composectl's `subprocess` module, and nothing else's."""

    def __init__(self, stdout: str = "", returncode: int = 0) -> None:
        self.stdout, self.returncode = stdout, returncode
        self.argv: list[list[str]] = []

    def run(self, argv, **kwargs) -> subprocess.CompletedProcess:
        self.argv.append(argv)
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, "")


def install(monkeypatch, ss: FakeSs) -> FakeSs:
    monkeypatch.setattr(composectl, "subprocess", ss)
    return ss


# ------------------------------------------------------------- canned output


def test_a_wildcard_listener_counts(monkeypatch) -> None:
    install(monkeypatch, FakeSs("LISTEN 0 4096 0.0.0.0:10443 0.0.0.0:*\n"))
    assert composectl._is_bound(10443, "tcp") is True


def test_an_ipv6_wildcard_listener_counts(monkeypatch) -> None:
    install(monkeypatch, FakeSs("LISTEN 0 4096 [::]:10443 [::]:*\n"))
    assert composectl._is_bound(10443, "tcp") is True


def test_a_loopback_listener_does_not(monkeypatch) -> None:
    install(monkeypatch, FakeSs("UNCONN 0 0 127.0.0.1:53 0.0.0.0:*\n"))
    assert composectl._is_bound(53, "udp") is False


def test_systemd_resolved_does_not_pass_for_dnstt(monkeypatch) -> None:
    install(monkeypatch, FakeSs(RESOLVED))
    assert composectl._is_bound(53, "udp") is False


def test_ipv6_loopback_does_not(monkeypatch) -> None:
    install(monkeypatch, FakeSs("UNCONN 0 0 [::1]:53 [::]:*\n"))
    assert composectl._is_bound(53, "udp") is False


def test_a_real_listener_beside_a_loopback_one_counts(monkeypatch) -> None:
    install(monkeypatch, FakeSs(RESOLVED + SERVED))
    assert composectl._is_bound(53, "udp") is True


def test_nothing_listening_is_not_bound(monkeypatch) -> None:
    install(monkeypatch, FakeSs(""))
    assert composectl._is_bound(10443, "tcp") is False


def test_it_asks_ss_for_the_right_transport(monkeypatch) -> None:
    ss = install(monkeypatch, FakeSs(""))
    composectl._is_bound(10443, "tcp")
    composectl._is_bound(53, "udp")
    assert ss.argv[0][:2] == ["ss", "-H"] and "-t" in ss.argv[0]
    assert "-u" in ss.argv[1]
    assert ss.argv[1][-1] == "sport = :53"


def test_a_truncated_line_is_skipped_not_crashed(monkeypatch) -> None:
    install(monkeypatch, FakeSs("LISTEN 0 4096\n"))
    assert composectl._is_bound(10443, "tcp") is False


# ------------------------------------------------------------ real ss, real socket


@pytest.mark.skipif(not SS, reason="ss(8) not installed")
def test_a_real_loopback_socket_is_not_bound() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        assert composectl._is_bound(port, "udp") is False


@pytest.mark.skipif(not SS, reason="ss(8) not installed")
def test_a_real_wildcard_socket_is_bound() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", 0))
        port = sock.getsockname()[1]
        assert composectl._is_bound(port, "udp") is True


@pytest.mark.skipif(not SS, reason="ss(8) not installed")
def test_a_free_port_is_not_bound() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", 0))
        port = sock.getsockname()[1]
    assert composectl._is_bound(port, "udp") is False


# --------------------------------------------------------- the ss-less fallback


def test_without_ss_it_tries_to_bind_the_port_itself(monkeypatch) -> None:
    install(monkeypatch, FakeSs("", returncode=127))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", 0))
        assert composectl._is_bound(sock.getsockname()[1], "udp") is True


def test_without_ss_a_free_port_is_not_bound(monkeypatch) -> None:
    install(monkeypatch, FakeSs("", returncode=127))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", 0))
        port = sock.getsockname()[1]
    assert composectl._is_bound(port, "udp") is False


def test_the_fallback_cannot_tell_a_loopback_listener_apart(monkeypatch) -> None:
    """Documented limitation, asserted so it stays documented.

    Binding 0.0.0.0:P fails while 127.0.0.1:P is held, so the fallback calls a
    loopback-only listener "bound" -- the exact false positive the ss path
    exists to avoid. It only runs when ss is missing.
    """
    install(monkeypatch, FakeSs("", returncode=127))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        assert composectl._is_bound(sock.getsockname()[1], "udp") is True


# ----------------------------------------------------- what wait_ready asks for


class Clock:
    """A fake `time` for composectl. sleep() advances monotonic(), so the
    timeout path is exercised without the test actually waiting."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def test_wait_ready_waits_for_every_port_of_every_enabled_protocol(monkeypatch) -> None:
    asked: list[tuple[int, str]] = []

    def bound(port: int, proto: str) -> bool:
        asked.append((port, proto))
        return True

    monkeypatch.setattr(composectl, "_is_bound", bound)
    ok, notes = composectl.wait_ready(protocols.ordered(), timeout=1)
    assert ok
    assert set(asked) == {
        (10443, "tcp"),
        (20443, "udp"),
        (500, "udp"),
        (4500, "udp"),
        (1701, "udp"),
        (53, "udp"),
    }
    assert notes == ["all 6 port(s) bound"]


def test_wait_ready_names_only_the_ports_that_never_came_up(monkeypatch) -> None:
    # ikev2 needs ~30s to bind and much longer on its first run, so this loop
    # is what stops the smoke test failing on a server that is merely starting.
    monkeypatch.setattr(composectl, "_is_bound", lambda port, proto: port != 53)
    monkeypatch.setattr(composectl, "time", Clock())
    ok, notes = composectl.wait_ready(protocols.ordered(), timeout=10)
    assert not ok
    assert notes == ["53/udp still not bound after 10s"]


# ------------------------------------------- what changed_services decides to bounce
#
# This is the half of composectl that decides whether a container is touched at
# all. `_is_bound` above only reports; these functions act, and one of them --
# the dnstt-sshd row -- is the difference between `user rm` revoking a login
# and `user rm` reporting success while the account keeps working.

BASE_TREE = {
    "sing-box/00_base.json": "{}",
    "sing-box/10_vless-reality.json": '{"inbounds": []}',
    "sing-box/certs/private.key": "pem",
    "dnstt/server.key": "a" * 64,
    "dnstt-sshd/logins": "alice:pw\n",
    "dnstt.env": "SSH_PORT=2222\n",
    "ikev2.env": "VPN_ADDL_USERS=alice\n",
}


def _tree(root: Path, files: dict[str, str]) -> Path:
    for rel, body in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _pair(tmp_path: Path, **changes: str | None) -> tuple[Path, Path]:
    """A live tree and a candidate that differs only in `changes`.

    A value of None deletes the path from the candidate; a path not in
    BASE_TREE is an addition. Both are diffs `apply` really produces -- a
    `protocol off` deletes a fragment, a `protocol on` adds one.
    """
    candidate = {**BASE_TREE}
    for rel, body in changes.items():
        rel = rel.replace("__", "/").replace("_dot_", ".")
        if body is None:
            candidate.pop(rel)
        else:
            candidate[rel] = body
    return (
        _tree(tmp_path / "rendered-old", BASE_TREE),
        _tree(tmp_path / "rendered-new", candidate),
    )


def _in_order(*rels: str):
    """Substitute a fixed iteration order for `_tree_files`' set.

    changed_services walks `_tree_files(previous) | _tree_files(candidate)`,
    and a set's order is whatever hashing gives -- so a precedence test would
    be exercising one interleaving by luck. `dict | dict` merges in insertion
    order and iterating a dict yields its keys, so this pins the order without
    changing the function under test.
    """
    return lambda root: dict.fromkeys(rels)


def test_identical_trees_bounce_nothing(tmp_path) -> None:
    # The common case by a wide margin: every deploy, every boot, every
    # `protocol on` for a protocol whose siblings were left alone. Before the
    # diff existed this recreated every container, so a reboot's `apply` cut
    # every live session for no reason at all.
    previous, candidate = _pair(tmp_path)
    assert composectl.changed_services(previous, candidate) == {}


def test_a_changed_sing_box_fragment_moves_only_sing_box(tmp_path) -> None:
    previous, candidate = _pair(
        tmp_path, **{"sing-box__10_vless-reality_dot_json": '{"inbounds": [1]}'}
    )
    assert composectl.changed_services(previous, candidate) == {
        "sing-box": composectl.MOUNT
    }


def test_a_changed_certificate_still_only_moves_sing_box(tmp_path) -> None:
    # certs/ is a subdirectory, and the table matches by prefix. A rule that
    # only matched the top level would leave a rotated certificate unread.
    previous, candidate = _pair(tmp_path, **{"sing-box__certs__private_dot_key": "new"})
    assert composectl.changed_services(previous, candidate) == {
        "sing-box": composectl.MOUNT
    }


def test_a_changed_ikev2_env_recreates_ikev2(tmp_path) -> None:
    # env_file is read once, at create time. `restart` re-runs the entrypoint
    # with the OLD environment, so a `user add` would render the new user and
    # the container would go on serving the old list.
    previous, candidate = _pair(tmp_path, ikev2_dot_env="VPN_ADDL_USERS=alice bob\n")
    assert composectl.changed_services(previous, candidate) == {
        "ikev2": composectl.RECREATE
    }


def test_a_changed_login_list_recreates_dnstt_sshd_because_its_entrypoint_only_adds(
    tmp_path,
) -> None:
    """MOUNT here would make `user rm` revoke nothing. Do not "simplify" it.

    dnstt-sshd/entrypoint.sh:36 is `id "$name" || adduser`: it only ever ADDS.
    Nothing in it deletes an account that dropped out of `logins`, because its
    correctness rests on the container being recreated -- /etc/passwd is
    rebuilt from the list every time a fresh container starts. Classify this as
    MOUNT and it gets `restart` instead; the writable layer survives, so a
    removed user keeps their account, their group and their password hash, and
    `AllowGroups tunnel` still admits them. `user rm` would print success and
    revoke nothing -- which is the entire reason dnstt has a login per person
    rather than one shared account.
    """
    previous, candidate = _pair(tmp_path, **{"dnstt-sshd__logins": ""})
    assert composectl.changed_services(previous, candidate) == {
        "dnstt-sshd": composectl.RECREATE
    }


def test_dnstt_env_belongs_to_the_sshd_not_to_dnstt(tmp_path) -> None:
    # The name is not the rule: dnstt.env configures dnstt-sshd, and routing it
    # by prefix to `dnstt` would restart the tunnel and leave the sshd stale.
    previous, candidate = _pair(tmp_path, dnstt_dot_env="SSH_PORT=2222\nX=1\n")
    assert composectl.changed_services(previous, candidate) == {
        "dnstt-sshd": composectl.RECREATE
    }


def test_a_file_that_only_the_candidate_has_counts_as_changed(tmp_path) -> None:
    previous, candidate = _pair(tmp_path, **{"sing-box__20_hysteria2_dot_json": "{}"})
    assert composectl.changed_services(previous, candidate) == {
        "sing-box": composectl.MOUNT
    }


def test_a_file_that_only_the_live_tree_has_counts_as_changed(tmp_path) -> None:
    # `protocol off hysteria2` deletes a fragment and nothing else; sing-box
    # has to be told, or it keeps serving the inbound that was turned off.
    previous, candidate = _pair(tmp_path, **{"sing-box__00_base_dot_json": None})
    assert composectl.changed_services(previous, candidate) == {
        "sing-box": composectl.MOUNT
    }


def test_two_services_moving_at_once_are_both_reported(tmp_path) -> None:
    previous, candidate = _pair(
        tmp_path,
        **{"sing-box__00_base_dot_json": '{"log": {}}'},
        ikev2_dot_env="VPN_ADDL_USERS=\n",
    )
    assert composectl.changed_services(previous, candidate) == {
        "sing-box": composectl.MOUNT,
        "ikev2": composectl.RECREATE,
    }


def test_a_path_nothing_claims_falls_back_to_bouncing_everything(tmp_path) -> None:
    # A protocol grew an output and the table did not hear about it. Returning
    # {} here would be a config nothing ever reads; None is the old, slow,
    # never-stale behaviour.
    previous, candidate = _pair(tmp_path, **{"wireguard__wg0_dot_conf": "[Interface]"})
    assert composectl.changed_services(previous, candidate) is None


def test_no_live_tree_cannot_be_diffed(tmp_path) -> None:
    assert composectl.changed_services(None, tmp_path) is None


def test_a_live_symlink_pointing_nowhere_cannot_be_diffed(tmp_path) -> None:
    # First apply on a fresh box: `rendered` does not exist yet.
    _, candidate = _pair(tmp_path)
    assert composectl.changed_services(tmp_path / "rendered-gone", candidate) is None


def test_recreate_beats_mount_when_both_inputs_of_one_service_move(
    tmp_path, monkeypatch
) -> None:
    """A service whose environment moved needs a new container, not a restart.

    No row in the real table pairs a MOUNT and a RECREATE input on one service
    today, so the rule is only reachable through a substituted one -- and it
    has to hold whichever input the loop reaches first, because it walks a set.
    """
    monkeypatch.setattr(
        composectl,
        "_CONSUMERS",
        (
            ("mounted/", "svc", composectl.MOUNT),
            ("svc.env", "svc", composectl.RECREATE),
        ),
    )
    previous = _tree(tmp_path / "old", {"mounted/conf": "a", "svc.env": "A=1\n"})
    candidate = _tree(tmp_path / "new", {"mounted/conf": "b", "svc.env": "A=2\n"})
    for order in (("mounted/conf", "svc.env"), ("svc.env", "mounted/conf")):
        monkeypatch.setattr(composectl, "_tree_files", _in_order(*order))
        assert composectl.changed_services(previous, candidate) == {
            "svc": composectl.RECREATE
        }


# ------------------------------------------------------ the table's own coverage


def test_every_path_build_tree_can_emit_has_a_consumer(secrets, users) -> None:
    """The claim EXPECTED_TREE is written against, checked rather than asserted.

    A protocol that grows an output nothing in _CONSUMERS claims does not fail
    -- changed_services returns None and every container is recreated on every
    apply, forever, silently. That is a performance regression shaped exactly
    like the correct answer, so it has to be caught here.
    """
    tree = render.build_tree(secrets, users, protocols.ordered())
    unrouted = sorted(
        rel for rel in set(tree) | EXPECTED_TREE if composectl._consumer(rel) is None
    )
    assert unrouted == []


def test_consumer_matches_a_directory_by_prefix_and_a_file_exactly() -> None:
    assert composectl._consumer("sing-box/certs/private.key") == (
        "sing-box",
        composectl.MOUNT,
    )
    assert composectl._consumer("ikev2.env") == ("ikev2", composectl.RECREATE)
    assert composectl._consumer("dnstt/server.key") == ("dnstt", composectl.MOUNT)


def test_consumer_does_not_claim_a_path_it_merely_resembles() -> None:
    # "dnstt.env" starts with the same five characters as the "dnstt/" prefix
    # and is not part of it; "ikev2.env.bak" is not "ikev2.env".
    assert composectl._consumer("dnstt.env") == ("dnstt-sshd", composectl.RECREATE)
    assert composectl._consumer("ikev2.env.bak") is None
    assert composectl._consumer("wireguard/wg0.conf") is None


# ---------------------------------------------------------- what up() then does
#
# _compose is the single narrow seam where this module shells out; every test
# below replaces that one attribute and nothing else, so no Docker daemon is
# involved and none is required.


class FakeCompose:
    """Stands in for composectl._compose. Records argv, never runs anything."""

    def __init__(self, fails=lambda args: False) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.fails = fails

    def __call__(
        self, *args: str, profiles: list[str] | None = None
    ) -> tuple[bool, str]:
        self.calls.append(args)
        ok = not self.fails(args)
        return ok, f"{'ok' if ok else 'boom'}: {' '.join(args)}"


class FakeIds:
    """composectl._container_ids, answering `before` then `after`."""

    def __init__(self, before, after=None) -> None:
        self.answers = [before, before if after is None else after]

    def __call__(self):
        return self.answers.pop(0)


ALL_IDS = {
    "sing-box": "c1",
    "ikev2": "c2",
    "dnstt": "c3",
    "dnstt-sshd": "c4",
    "dnstt-socks": "c5",
}


def _fake_up(monkeypatch, ids: FakeIds, fails=lambda args: False) -> FakeCompose:
    compose = FakeCompose(fails)
    monkeypatch.setattr(composectl, "_compose", compose)
    monkeypatch.setattr(composectl, "_container_ids", ids)
    return compose


def test_up_that_changed_nothing_only_starts_what_is_missing(monkeypatch) -> None:
    compose = _fake_up(monkeypatch, FakeIds(ALL_IDS))
    ok, _ = composectl.up(protocols.ordered(), changed={})
    assert ok
    # One call: the idempotent `up`. Nothing is restarted, nothing recreated --
    # which is what makes a boot or a deploy cost zero live sessions.
    assert [c[0] for c in compose.calls] == ["up"]
    # --build or a changed Dockerfile is rsynced and then silently ignored,
    # because compose reuses the image whose tag already exists.
    assert "--build" in compose.calls[0]


def test_a_mount_change_restarts_only_that_service(monkeypatch) -> None:
    compose = _fake_up(monkeypatch, FakeIds(ALL_IDS))
    ok, _ = composectl.up(protocols.ordered(), changed={"sing-box": composectl.MOUNT})
    assert ok
    assert compose.calls[1:] == [("restart", "sing-box")]


def test_a_recreate_change_forces_a_new_container(monkeypatch) -> None:
    compose = _fake_up(monkeypatch, FakeIds(ALL_IDS))
    ok, _ = composectl.up(
        protocols.ordered(), changed={"dnstt-sshd": composectl.RECREATE}
    )
    assert ok
    assert compose.calls[1:] == [
        ("up", "-d", "--no-deps", "--force-recreate", "dnstt-sshd")
    ]


def test_an_undiffable_tree_recreates_every_enabled_service(monkeypatch) -> None:
    # `changed=None` is the fallback, and it has to reproduce exactly what this
    # function did unconditionally before the diff existed.
    compose = _fake_up(monkeypatch, FakeIds(ALL_IDS))
    ok, _ = composectl.up(protocols.ordered(), changed=None)
    assert ok
    assert [c[-1] for c in compose.calls[1:]] == [
        "dnstt",
        "dnstt-socks",
        "dnstt-sshd",
        "ikev2",
        "sing-box",
    ]
    assert all("--force-recreate" in c for c in compose.calls[1:])


def test_a_container_compose_just_replaced_is_not_bounced_twice(monkeypatch) -> None:
    # Compose recreates on its own for a changed image or env_file, and a
    # container it just created is running the new tree by construction.
    ids = FakeIds(ALL_IDS, {**ALL_IDS, "sing-box": "c1-new"})
    compose = _fake_up(monkeypatch, ids)
    ok, _ = composectl.up(protocols.ordered(), changed={"sing-box": composectl.MOUNT})
    assert ok
    assert compose.calls[1:] == []


def test_a_service_that_did_not_exist_before_is_not_bounced(monkeypatch) -> None:
    # Absent from `before` means no container existed, so the one in `after` is
    # one compose created just now and it holds the new tree by construction.
    # This reads correctly only because `before` is `docker compose ps --all`:
    # see the next test for what a running-only listing did.
    started = {k: v for k, v in ALL_IDS.items() if k != "dnstt-sshd"}
    compose = _fake_up(monkeypatch, FakeIds(started, ALL_IDS))
    ok, _ = composectl.up(
        protocols.ordered(), changed={"dnstt-sshd": composectl.RECREATE}
    )
    assert ok
    assert compose.calls[1:] == []


def test_a_stopped_container_is_recreated_not_taken_for_a_fresh_one(
    monkeypatch,
) -> None:
    """A stopped dnstt-sshd must still be recreated, or `user rm` revokes nothing.

    `up -d` STARTS a stopped container -- same id, same writable layer -- it does
    not create one. While `before` came from `ps --status running`, a stopped
    container was absent from it, `up` read that as "compose made this one just
    now", and skipped the --force-recreate. dnstt-sshd/entrypoint.sh:36 is
    `id "$name" || adduser` and never deletes, so the removed account survived in
    /etc/passwd with its hash, `AllowGroups tunnel` still admitted it, and
    `user rm` reported success while revoking nothing. Proven with a real
    password login before the fix.

    Now `before` is `ps --all`, so the container is present with the same id in
    both snapshots and the nudge is not skipped.
    """
    compose = _fake_up(monkeypatch, FakeIds(ALL_IDS, ALL_IDS))
    ok, _ = composectl.up(
        protocols.ordered(), changed={"dnstt-sshd": composectl.RECREATE}
    )
    assert ok
    assert compose.calls[1:] == [
        ("up", "-d", "--no-deps", "--force-recreate", "dnstt-sshd")
    ]


def test_container_ids_asks_for_every_container_not_just_running(monkeypatch) -> None:
    # The flag IS the fix: --status running hid stopped containers and turned a
    # skipped recreate into a live credential. Assert the argv, not the parse.
    seen: list[list[str]] = []

    def fake_run(argv, **kwargs):
        seen.append(argv)

        class R:
            returncode = 0
            stdout = "[]"

        return R()

    monkeypatch.setattr(composectl.subprocess, "run", fake_run)
    composectl._container_ids()
    assert "--all" in seen[0]
    assert "--status" not in seen[0]


def test_a_disabled_protocol_in_the_diff_is_left_to_down_disabled(monkeypatch) -> None:
    # `protocol off ikev2` leaves ikev2.env's disappearance in the diff. Trying
    # to `up` a service whose profile is gone is compose's business, not ours.
    compose = _fake_up(monkeypatch, FakeIds({"sing-box": "c1"}))
    ok, _ = composectl.up(
        protocols.ordered(["vless-reality"]), changed={"ikev2": composectl.RECREATE}
    )
    assert ok
    assert [c[0] for c in compose.calls] == ["up"]


def test_a_failed_up_bounces_nothing(monkeypatch) -> None:
    compose = _fake_up(
        monkeypatch, FakeIds(ALL_IDS), fails=lambda args: "--build" in args
    )
    ok, output = composectl.up(protocols.ordered(), changed=None)
    assert not ok
    assert len(compose.calls) == 1
    assert "boom" in output


def test_a_failed_restart_stops_and_reports(monkeypatch) -> None:
    compose = _fake_up(
        monkeypatch, FakeIds(ALL_IDS), fails=lambda args: args[0] == "restart"
    )
    ok, output = composectl.up(
        protocols.ordered(),
        changed={"sing-box": composectl.MOUNT, "dnstt": composectl.MOUNT},
    )
    assert not ok
    # Sorted, so dnstt is tried first and sing-box is never reached: a half-
    # converged server that says so beats one that reports success.
    assert compose.calls[1:] == [("restart", "dnstt")]
    assert "boom" in output


def test_when_the_id_query_fails_the_service_is_bounced_anyway(monkeypatch) -> None:
    # A needless restart is recoverable; a config nothing has read is not.
    compose = _fake_up(monkeypatch, FakeIds(None, None))
    ok, _ = composectl.up(protocols.ordered(), changed={"sing-box": composectl.MOUNT})
    assert ok
    assert compose.calls[1:] == [("restart", "sing-box")]


# ------------------------------------------------- how _container_ids reads ps
#
# The id is the whole point: it is how up() tells "compose recreated this for
# me" from "this is the same container it was a second ago".

NDJSON = '{"Service": "sing-box", "ID": "abc"}\n{"Service": "dnstt", "ID": "def"}\n'
ARRAY = '[{"Service": "sing-box", "ID": "abc"}, {"Service": "dnstt", "ID": "def"}]'


def test_container_ids_reads_one_object_per_line(monkeypatch) -> None:
    # What Compose v5.3.1 emits, which is what is pinned in compose.yml.
    install(monkeypatch, FakeSs(NDJSON))
    assert composectl._container_ids() == {"sing-box": "abc", "dnstt": "def"}


def test_container_ids_reads_a_single_array(monkeypatch) -> None:
    # What other versions emit. Both shapes, because the pin will move.
    install(monkeypatch, FakeSs(ARRAY))
    assert composectl._container_ids() == {"sing-box": "abc", "dnstt": "def"}


def test_container_ids_says_none_when_the_query_fails(monkeypatch) -> None:
    install(monkeypatch, FakeSs("", returncode=1))
    assert composectl._container_ids() is None


def test_container_ids_says_none_on_output_it_cannot_parse(monkeypatch) -> None:
    # None means "could not tell" and makes up() bounce the changed services
    # regardless. An empty dict would read as "nothing is running", and every
    # service would then look freshly created and be skipped.
    install(monkeypatch, FakeSs("Cannot connect to the Docker daemon\n"))
    assert composectl._container_ids() is None


def test_container_ids_says_none_when_a_row_has_no_service(monkeypatch) -> None:
    install(monkeypatch, FakeSs('{"ID": "abc"}\n'))
    assert composectl._container_ids() is None


# ------------------------------------------- what down_disabled tears down
#
# The mirror image of up(): `up -d --remove-orphans` does NOT stop a container
# whose profile was deactivated (measured on Compose v5.3.1, still true on
# v5.5.1), so without an explicit `rm -sf` "protocol off" leaves the protocol
# serving traffic. Same seam as above: _compose and _running_services are the
# only two things this half shells out through.


def _fake_teardown(monkeypatch, running: set[str] | None) -> FakeCompose:
    compose = FakeCompose()
    monkeypatch.setattr(composectl, "_compose", compose)
    monkeypatch.setattr(composectl, "_running_services", lambda: running)
    return compose


def test_everything_enabled_has_nothing_to_tear_down(monkeypatch) -> None:
    compose = _fake_teardown(monkeypatch, set(ALL_IDS))
    ok, message = composectl.down_disabled(protocols.ordered())
    assert ok
    assert "nothing to tear down" in message
    assert compose.calls == []


def test_nothing_enabled_and_nothing_running_removes_nothing(monkeypatch) -> None:
    # A box whose containers are all down -- after a `docker compose stop`, or
    # before the first apply. Every optional protocol is stale and none of them
    # is running, so there is nothing to do and nothing may be run: `rm -sf` on
    # a service that does not exist is noise that reads like an error.
    compose = _fake_teardown(monkeypatch, set())
    ok, message = composectl.down_disabled([])
    assert ok
    assert "already down" in message
    assert compose.calls == []


def test_a_disabled_dnstt_that_is_running_is_removed_explicitly(monkeypatch) -> None:
    # All three of its services, in one call: the tunnel, the sshd behind it and
    # the SOCKS exit. Leaving any of them up leaves udp/53 answering, or a login
    # reachable through a tunnel the operator believes is off.
    compose = _fake_teardown(monkeypatch, set(ALL_IDS))
    ok, message = composectl.down_disabled(
        protocols.ordered(["vless-reality", "hysteria2", "ikev2"])
    )
    assert ok
    assert compose.calls == [("rm", "-sf", "dnstt", "dnstt-sshd", "dnstt-socks")]
    assert "removed dnstt, dnstt-sshd, dnstt-socks" in message


def test_a_disabled_dnstt_that_is_already_down_is_left_alone(monkeypatch) -> None:
    compose = _fake_teardown(monkeypatch, {"sing-box", "ikev2"})
    ok, message = composectl.down_disabled(
        protocols.ordered(["vless-reality", "hysteria2", "ikev2"])
    )
    assert ok
    assert "already down" in message
    assert compose.calls == []


def test_an_unanswerable_query_removes_nothing_at_all(monkeypatch) -> None:
    """None from _running_services must not be read as "nothing is running".

    This is the case that matters. Guessing in either direction is wrong, but
    the two mistakes are not symmetrical: reading None as the empty set reports
    success while a disabled protocol keeps serving traffic, and reading it as
    "everything is up" issues `rm -sf` against services that may be the ones
    carrying live sessions. So it removes nothing and says the query failed,
    and the caller warns.
    """
    compose = _fake_teardown(monkeypatch, None)
    ok, message = composectl.down_disabled(
        protocols.ordered(["vless-reality", "hysteria2"])
    )
    assert not ok
    assert compose.calls == []
    assert "could not list" in message


# -------------------------------------------------- liveness, which ports are not
#
# `wait_ready` answers "is something listening", and that is not the same
# question. dnstt-sshd binds loopback 2222 and contributes no port at all, so a
# crash-looping sshd is invisible to it while dnstt-server keeps 53/udp bound --
# the tunnel completes and the door behind it is shut. The same shape has caught
# this repo twice: both IKEv2 health checks asserted the L2TP subnet instead of
# the XAUTH pool clients are actually given, and diagnose-ikev2.sh's `probe`
# sent junk to port 500 and read its arrival as "IKE is not blocked".


def test_expected_services_is_sing_box_plus_the_registrys_own() -> None:
    assert composectl.expected_services([]) == ["sing-box"]
    assert set(composectl.expected_services(protocols.ordered())) == set(ALL_IDS)


def test_nothing_is_reported_down_when_everything_is_up(monkeypatch) -> None:
    monkeypatch.setattr(composectl, "_running_services", lambda: set(ALL_IDS))
    assert composectl.not_running(protocols.ordered()) == []


def test_a_crash_looping_sshd_is_reported_even_though_its_ports_are_bound(
    monkeypatch,
) -> None:
    running = set(ALL_IDS) - {"dnstt-sshd"}
    monkeypatch.setattr(composectl, "_running_services", lambda: running)
    assert composectl.not_running(protocols.ordered()) == ["dnstt-sshd"]


def test_a_disabled_protocols_containers_are_not_expected_to_be_up(
    monkeypatch,
) -> None:
    # `protocol off dnstt` means its services SHOULD be down; reporting them
    # here would make every apply on a sing-box-only server warn about three
    # containers nobody asked for.
    monkeypatch.setattr(composectl, "_running_services", lambda: {"sing-box"})
    assert composectl.not_running(protocols.ordered(["vless-reality"])) == []


def test_liveness_cannot_be_answered_says_so_rather_than_all_fine(monkeypatch) -> None:
    # Same rule as down_disabled: an empty list here is a clean bill of health,
    # and a failed `docker compose ps` has not earned one.
    monkeypatch.setattr(composectl, "_running_services", lambda: None)
    assert composectl.not_running(protocols.ordered()) is None


def test_running_services_distinguishes_empty_from_unanswerable(monkeypatch) -> None:
    install(monkeypatch, FakeSs("sing-box\nikev2\n"))
    assert composectl._running_services() == {"sing-box", "ikev2"}
    install(monkeypatch, FakeSs(""))
    assert composectl._running_services() == set()
    install(monkeypatch, FakeSs("", returncode=1))
    assert composectl._running_services() is None


# -------------------------------------- the table's service names, against compose.yml
#
# _CONSUMERS is written by hand (`docker compose config` cannot answer the
# env_file half), so a typo in a service name is not an error: _consumer returns
# that name, up() finds it absent from `services` and skips it as "a protocol
# that was turned off", and the changed config is never read by anything. A
# rendered file silently delivered to nobody -- so the names are checked here.


def _compose_service_names() -> set[str]:
    """compose.yml's top-level service keys, by regex.

    Deliberately not a YAML parse: the suite must run on a bare runner with no
    dependency beyond what the server itself installs, and one anchored regex
    over the two-space keys under `services:` is enough to compare name sets.
    """
    body = (ROOT / "compose.yml").read_text()
    services = body.split("\nservices:\n", 1)[1]
    return set(re.findall(r"^  ([A-Za-z0-9][\w.-]*):$", services, re.MULTILINE))


def test_compose_yml_yields_the_services_this_file_reasons_about() -> None:
    # The regex is the weak link in the two assertions below; if it silently
    # matched nothing they would both pass vacuously.
    assert _compose_service_names() == set(ALL_IDS)


def test_every_consumer_names_a_service_the_registry_knows() -> None:
    from_registry = {s for p in protocols.ordered() for s in p.compose_services}
    for _prefix, service, _how in composectl._CONSUMERS:
        assert service == "sing-box" or service in from_registry, _prefix


def test_every_service_this_module_touches_exists_in_compose_yml() -> None:
    declared = _compose_service_names()
    assert {s for _p, s, _h in composectl._CONSUMERS} <= declared
    assert set(composectl.expected_services(protocols.ordered())) <= declared
