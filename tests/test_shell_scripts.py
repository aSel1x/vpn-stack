"""Invariants of the shell half of this stack.

Every check here is a bug that shipped: a firewall net that could be armed
twice, a hardcoded ssh port that made `./vpn init` unable to finish, an rsync
that never deleted, a backup that left a world-readable plaintext tar of every
secret in /tmp, a vpnctl call with no lock around it. None of them are visible to
`bash -n`, none need a server, and the alternative -- noticing on the box -- has
already been tried on each one.

These scripts converge a live server, so most of what is asserted here is
asserted by READING them; nothing below starts a container, touches ufw or
opens an ssh connection. But a check that only reads is easy to write and easy
to get wrong, and several here were: they matched a string that also appears in
the COMMENT explaining it, or looked in a part of the file the code they guard
does not live in, and stayed green against the exact defect they were written
for. Where reading cannot bite -- a parser, a lookup table, a validator -- the
pure helper is lifted out of the file and RUN instead, with fakes for docker
and ss. A test that cannot fail is worse than none: it reports coverage that
does not exist.

What neither can reach (that the deadman really does disable ufw, that pluto
really binds where the check looks) belongs in scripts/smoke.sh against a real
box.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

import pytest

# The machinery that lifts a shell function out of a file and runs it, rather
# than a third copy of it here. It lives next door because scripts/diagnose-
# ikev2.sh needed it first; the pool derivation it was written for exists in
# that file AND in smoke.sh, so the checks that pin the two together have to be
# able to source either.
from test_diagnose_ikev2 import (
    fake_docker,
    needs_python3,
    run_helpers,
    shell_function,
)

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
SMOKE = SCRIPTS / "smoke.sh"
DIAGNOSE = SCRIPTS / "diagnose-ikev2.sh"


def read(rel: str) -> str:
    return (ROOT / rel).read_text()


def code(rel: str) -> str:
    """The file with its whole-line comments removed.

    These scripts explain themselves by quoting the shape they replaced -- the
    /tmp path a backup used to leave behind, the bare "$VERSION_CODENAME" that
    aborted a stage -- so a plain substring search finds the defect in the
    comment that documents it and calls the fix a regression.
    """
    return "\n".join(
        line for line in read(rel).splitlines() if not line.lstrip().startswith("#")
    )


def prose(rel: str) -> str:
    """The comments as one whitespace-normalised string, comment markers gone,
    so a sentence that wraps across two comment lines still reads as one."""
    return re.sub(
        r"\s+", " ", " ".join(re.sub(r"^\s*#", "", ln) for ln in read(rel).splitlines())
    )


# --------------------------------------------------------------- push.sh
def rsync_argv() -> list[str]:
    """push.sh's rsync invocation, continuations joined, as words.

    Not the file: every flag below is also NAMED in the paragraph above the
    command that explains why it is there, so a search over the text finds
    --delete and --chown=root:root in the prose and passes on a push.sh that no
    longer passes either. Confirmed by mutation -- rewriting the command to a
    plain `exec rsync -az \\` left both of these checks green.
    """
    lines = code("scripts/push.sh").splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("exec rsync"))
    words: list[str] = []
    for ln in lines[start:]:
        words += ln.rstrip().removesuffix("\\").split()
        if not ln.rstrip().endswith("\\"):
            break
    return words


def test_push_deletes_but_never_deletes_excluded() -> None:
    """A file deleted from the repo has to die on the server too.

    scripts/host-bootstrap.sh was removed here and stayed behind, executable, on
    every server pushed before its removal. --delete-excluded is the opposite
    mistake and far worse: it would remove the files the .gitignore filter
    protects -- /opt/vpn-stack/.env, the symlink into the state directory -- from
    the SERVER.
    """
    argv = rsync_argv()
    assert "--delete" in argv
    assert "--delete-excluded" not in argv


def test_push_lands_a_root_owned_tree() -> None:
    """-a preserves the operator's uid, and root executes what lands."""
    assert "--chown=root:root" in rsync_argv()


def test_push_is_executable() -> None:
    """install.sh and deploy.sh call it through bash, but ./scripts/push.sh is
    documented as runnable and lost its mode bit once already."""
    assert os.access(SCRIPTS / "push.sh", os.X_OK)


def test_push_says_each_thing_once() -> None:
    """A paragraph was duplicated verbatim, which is how two copies of a reason
    start disagreeing about what it is."""
    push = read("scripts/push.sh")
    assert push.count("app/ and notes/ are excluded by path") == 1


# ------------------------------------------- install.sh / provision-host.sh
def test_install_does_not_hardcode_the_ssh_port() -> None:
    """22 hardcoded meant `./vpn init` could never finish against an sshd on
    another port: ufw came up with only 22 open, the fresh-connection proof
    failed, the deadman restored access three minutes later, and the identical
    re-run failed identically."""
    install = read("scripts/install.sh")
    assert "ufw allow 22/tcp" not in install


def test_the_deadman_has_one_definition_in_shell() -> None:
    """install.sh had its own copy of the arm and the disarm. The net also
    exists in Dart; a third hand-written copy is how two of them end up behaving
    differently on the one box where it matters."""
    install = read("scripts/install.sh")
    host = read("scripts/provision-host.sh")
    assert "setsid" not in install
    assert "firewall" in install and "firewall-disarm" in install
    for fn in ("deadman_arm()", "deadman_disarm()", "deadman_kill()", "ufw_enable()"):
        assert fn in host


def test_arming_refuses_to_clobber_a_live_predecessor() -> None:
    """Overwriting the pid file left the earlier timer sleeping with nothing
    recording it, and it ran `ufw --force disable` at its own T+180 -- possibly
    after the installer had printed success."""
    host = read("scripts/provision-host.sh")
    arm = host.split("deadman_arm() {", 1)[1].split("\ndeadman_disarm", 1)[0]
    assert "kill -0" in arm and "deadman_kill" in arm


def test_the_disarm_is_observable() -> None:
    """It used to rm the pid file BEFORE killing anything, discard both kills'
    stderr and end in `; true`, so `set -e` could not see a failure -- and if
    the kill had not landed, nothing on the box knew a timer was still counting
    down."""
    host = read("scripts/provision-host.sh")
    disarm = host.split("deadman_disarm() {", 1)[1].split("\n}", 1)[0]
    assert "deadman_kill" in disarm, "the disarm no longer kills through the helper"
    assert "rm -f" in disarm, "the disarm no longer removes the pid file"
    assert disarm.index("deadman_kill") < disarm.index("rm -f")
    assert "; true" not in disarm


def test_boot_unit_waits_for_what_it_orders_itself_after() -> None:
    """network-online.target is passive: ordering after it without wanting it
    orders this unit after a target nothing reaches. And `docker info` answers
    later than docker.service goes active, so the apply raced the socket."""
    unit = read("scripts/provision-host.sh")
    assert "Wants=docker.service network-online.target" in unit
    assert "ExecStartPre=" in unit and "docker info" in unit
    assert "Restart=on-failure" in unit


def test_os_release_without_a_codename_fails_by_name() -> None:
    """Under `set -u` a bare "$VERSION_CODENAME" aborted the whole base stage
    and named neither the variable nor the file."""
    host = code("scripts/provision-host.sh")
    assert "${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}" in host
    assert '"$VERSION_CODENAME"' not in host


def test_a_changed_server_address_is_reported() -> None:
    """VPN_SERVER_HOST is never overwritten -- every profile already issued was
    issued against it -- but keeping the old value silently let a re-run against
    a moved box render, converge and smoke green while every client dialled an
    address that is gone."""
    host = read("scripts/provision-host.sh")
    assert "existing_host" in host
    assert "re-export" in host


# ------------------------------------------- the deadman, in two languages
# scripts/provision-host.sh holds the one bash definition, with two callers.
# app/lib/provision/commands.dart builds a second one in Dart, because the app
# provisions a box over its own transport and has no checkout to run a script
# from. The net is the only thing standing between `ufw enable` and a server
# nobody can reach again, so the two have to agree on what it does -- and
# nothing was watching them.
#
# The two deliberately differ on ONE point and that is not asserted here: bash
# reaps a live predecessor, Dart refuses to arm on top of one. A pid a previous
# run left behind may have been recycled, and the app cannot know whose process
# group it would be signalling.
DART_COMMANDS = ROOT / "app" / "lib" / "provision" / "commands.dart"

needs_dart_commands = pytest.mark.skipif(
    not DART_COMMANDS.exists(), reason="the app is not in this checkout"
)


def dart_program(name: str) -> str:
    """One `const String <name> = r\'\'\'...\'\'\';` literal, verbatim.

    Reading Dart from here is the narrowest seam available: these constants ARE
    shell, they run on the same box as provision-host.sh, and the alternative --
    asserting the properties twice, once per language, in two suites that never
    see each other -- is how the two copies drifted in the first place.
    """
    body = re.search(
        rf"const String {name} = r\'\'\'\n(.*?)\n\'\'\';",
        DART_COMMANDS.read_text(),
        re.S,
    )
    assert body, f"{name} is not a raw program literal in {DART_COMMANDS.name}"
    return body.group(1)


def _arm_programs() -> dict[str, str]:
    """The arm alone, not the deadman_kill it delegates the reaping to.

    Concatenating the helper would hand every check below a `kill -0` for free
    and make "does this arm test its predecessor for life?" unanswerable --
    measured: deleting that test from deadman_arm left the concatenated version
    green.
    """
    host = SCRIPTS / "provision-host.sh"
    return {
        "provision-host.sh": shell_function("deadman_arm", host),
        "commands.dart": dart_program("_armDeadman"),
    }


def without_messages(program: str) -> str:
    """The program with its human-readable strings blanked out.

    Both disarms end by telling the operator how to kill a survivor by hand,
    and that sentence contains `kill -KILL -$pid` verbatim. Reading the text as
    if it were all instructions therefore finds a kill inside the message
    explaining that no kill worked -- measured: the ordering check below passed
    against a disarm mutated to rm the pid file first.

    Only multi-word strings go. "$pid" and "$DEADMAN_PID_FILE" are operands,
    and dropping whole echo LINES was the other wrong answer: in bash the
    refusal to arm is `echo ... >&2; return 1; }` on one line, so removing the
    line removes the failure path this file then reports as missing.
    """
    # Whole quoted runs, consumed left to right, rather than "a quote, a space
    # and a quote": that shorter pattern starts a match on a CLOSING quote and
    # swallows the code between two operands, which ate the `kill -0` out of
    # `kill -0 -"$pid" || kill -0 "$pid"`.
    return re.sub(
        r'"[^"\n]*"',
        lambda m: '""' if " " in m.group(0)[1:-1] else m.group(0),
        program,
    )


def _disarm_programs() -> dict[str, tuple[str, str]]:
    """(the whole program, the part that fixes the order) per language.

    Two texts because bash splits the disarm across deadman_disarm and the
    deadman_kill it calls: the liveness poll lives in the helper, the decision
    to forget the pid file lives in the caller, and concatenating them would put
    the helper's own kills after the caller's `rm -f` and make the ordering
    check read backwards. The Dart one is a single program and is both.
    """
    host = SCRIPTS / "provision-host.sh"
    disarm = shell_function("deadman_disarm", host)
    dart = dart_program("_disarmDeadman")
    return {
        "provision-host.sh": (disarm + shell_function("deadman_kill", host), disarm),
        "commands.dart": (dart, dart),
    }


@needs_dart_commands
def test_both_arms_record_the_timers_own_pid_and_refuse_to_arm_blind() -> None:
    """`$!` is the wrong pid: setsid forks when the caller is already a
    process-group leader, so the subshell writes its own `$$`. And a pid file
    that never appeared means no record of a timer that is nonetheless counting
    down -- so both refuse to touch ufw rather than proceed."""
    for where, program in _arm_programs().items():
        program = without_messages(program)
        assert "setsid" in program, f"{where} no longer detaches the timer"
        assert "echo $$ >" in program, f"{where} does not record the timer's own pid"
        assert "kill -0" in program, f"{where} does not test its predecessor for life"
        assert "tr -dc '0-9'" in program, f"{where} trusts the pid file's bytes"
        # After the spawn, specifically: a timer that is running with nothing on
        # the box recording it must stop the step, not be shrugged off. The
        # wait loop only tests that the file is non-empty, so this is the whole
        # of "we know which process to kill later".
        assert re.search(r"(?s)setsid.*?\b(exit|return) 1\b", program), (
            f"{where} touches ufw even when the pid file never appeared"
        )


@needs_dart_commands
def test_both_disarms_prove_the_timer_is_gone_before_forgetting_it() -> None:
    """The pid file is the only record on the box that a timer is breathing, so
    removing it while the process is still alive is the one irreversible
    mistake here: `ufw --force disable` then fires at its own T+180, possibly
    after the installer has printed success, and nothing knows why.

    That is what bash's disarm used to do -- rm first, both kills' stderr
    discarded, ending in `; true` so `set -e` could not see a failure.
    """
    for where, (program, _) in _disarm_programs().items():
        prose_free = without_messages(program)
        assert re.search(r'-n "\$\w+"', prose_free), (
            f"{where} does not require a non-empty pid before acting"
        )
        assert "kill -0" in prose_free, (
            f"{where} signals and assumes; nothing polls for the process to go"
        )
        assert re.search(r"\b(exit|return) 1\b", prose_free), (
            f"{where} cannot report a survivor: a caller reads success either way"
        )


@needs_dart_commands
def test_neither_disarm_removes_the_pid_file_before_the_kill() -> None:
    """The pid file is the only record on the box that a timer is breathing."""
    for where, (_, decider) in _disarm_programs().items():
        decider = without_messages(decider)
        kills = [m.start() for m in re.finditer(r"\b(?:deadman_)?kill\b", decider)]
        removals = [m.start() for m in re.finditer(r"\brm -f\b", decider)]
        assert kills, f"{where} never kills anything"
        assert removals, f"{where} never removes the pid file"
        assert max(removals) > max(kills), (
            f"{where} forgets the timer before proving it is dead"
        )


# ------------------------------------------------------------ the lock
def test_every_vpnctl_call_site_takes_the_lock() -> None:
    """CLAUDE.md calls `flock /run/vpn-stack.lock` the entire multi-operator
    story, and a call that skips it is a bug even on the run where it works: two
    applies rendering candidate trees over each other is the one race the atomic
    promote cannot save you from.

    vpnctl takes this same lock itself now, for every mutating command, and that
    does not retire this check. Its own lock covers its own process, while these
    wrappers hold the file across a whole remote command -- the uv sync as well
    as the apply, the cd as well as the forwarded argv -- and vpnctl's is
    non-blocking on purpose, so an unwrapped call that overlaps another operator
    is refused rather than serialised. The handshake the wrappers export,
    VPN_STACK_LOCK_HELD, exists because flock(1) inside flock(1) on the same
    path from a child process opens a second file description: the kernel reads
    that as a different holder and the inner lock waits on its own parent
    forever."""
    unlocked: list[str] = []
    for rel in (
        "vpn",
        "deploy",
        "scripts/install.sh",
        "scripts/deploy.sh",
        "scripts/provision-host.sh",
    ):
        for n, line in enumerate(read(rel).splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            # Not a match inside backticks: the scripts quote `vpnctl apply`
            # at the operator in several messages, and telling somebody what to
            # run is not a call site.
            if (
                re.search(r"(?<!`)\bvpnctl (apply|bootstrap)\b", line)
                and "flock" not in line
            ):
                unlocked.append(f"{rel}:{n}: {line.strip()}")
    assert not unlocked, "vpnctl called without the lock:\n" + "\n".join(unlocked)


# ------------------------------------------------------------------- vpn
def test_backup_leaves_no_plaintext_behind() -> None:
    """Both intermediates were created by shell redirection into /tmp at root's
    umask (0644) in a world-traversable directory, and the `rm -f` ran only if
    the final tar had succeeded. Break the pipe and they stayed indefinitely at
    a predictable path: every user's password on every protocol, the REALITY
    private key, and the NSS CA private key."""
    vpn = code("vpn")
    assert "/tmp/.vpn-state.tgz" not in vpn
    assert "/tmp/.vpn-ikev2.tgz" not in vpn
    stream = vpn.split("backup_stream() {", 1)[1].split("\nREMOTE\n", 1)[0]
    assert "umask 077" in stream
    assert "mktemp -d" in stream
    # HUP as well as EXIT: a dropped connection kills the shell with an
    # untrapped signal, and the EXIT trap alone would not run.
    assert re.search(r"trap 'rm -rf \"\$tmp\"' EXIT HUP", stream)
    assert "2>/dev/null" not in stream


def test_backup_carries_both_volumes_from_one_list() -> None:
    """compose.yml declares two volumes. dnstt-sshd-keys holds the dnstt SSH
    front's host key, and a restore without it hands every dnstt client a
    changed-host-key warning indistinguishable from an attack -- for the one
    protocol whose users have no fallback. The ikev2 name was written out twice,
    which is how a list grows a third entry in one place only."""
    vpn = read("vpn")
    assert "vpn-stack_dnstt-sshd-keys" in vpn
    assert vpn.count("vpn-stack_ikev2-vpn-data") == 1
    assert vpn.count("vpn-stack_dnstt-sshd-keys") == 1


def test_restore_tolerates_a_backup_without_the_newer_volume() -> None:
    """Every backup taken before dnstt-sshd-keys joined the list has the ikev2
    member only, and those are exactly the backups this command exists for."""
    vpn = read("vpn")
    assert 'if [ -f "$tmp/$member" ]' in vpn


def test_backup_to_a_path_never_truncates_the_old_one() -> None:
    """`./vpn backup > f.age` is the SHELL truncating f.age before ssh has said
    a word, so a failed backup destroys the last good one and you find out on a
    rebuilt box. The path form writes .partial and renames on success."""
    vpn = read("vpn")
    assert '"$out.partial"' in vpn
    assert 'mv -- "$out.partial" "$out"' in vpn


def test_no_remote_command_interpolates_an_unquoted_path_or_argv() -> None:
    """remote() spells out why: `$*` and a bare $REMOTE_PATH are re-split and
    glob-expanded by the remote shell. `logs` was splicing operator-typed
    arguments in raw."""
    vpn = read("vpn")
    assert "cd $REMOTE_PATH" not in vpn
    assert "${*:-sing-box}" not in vpn


# -------------------------------------------------------------- smoke.sh
def smoke_section(title: str) -> str:
    """One `echo "== <title> =="` block of smoke.sh, whole-line comments gone.

    The container and listener checks are top-level script rather than
    functions, so what pins them is WHERE the text sits and not that the text
    exists somewhere: a helper the script has stopped calling still defines
    every name, and so does the paragraph explaining it. Confirmed by mutation
    -- replacing the whole container block with a literal CONTAINERS="sing-box"
    left the old file-wide search green while the check verified nothing.
    """
    after = code("scripts/smoke.sh").split(f'echo "== {title} ', 1)
    assert len(after) == 2, f"smoke.sh has no == {title} == section"
    return after[1].split('\necho "== ', 1)[0]


def test_smoke_checks_every_enabled_protocols_containers() -> None:
    """It checked `sing-box` alone, so a crash-looping dnstt-sshd -- the
    container that holds every dnstt login -- passed every check while nobody
    could log in."""
    section = smoke_section("containers")
    assert "protocol_containers" in section, "the container list is back to a literal"
    assert "for proto in $ENABLED" in section, (
        "the list no longer follows protocol on/off"
    )
    assert "check_container" in section
    # RestartCount separates a container that has been up for a week from one
    # that starts, dies and is restarted -- both of which `docker ps` calls
    # running, because `restart: always` means the second one IS running again.
    # Sampled TWICE and compared, because read once it cannot tell a crash the
    # operator already fixed from a loop still going round, and failing on any
    # nonzero count is a smoke test that cries wolf after every repair.
    body = shell_function("check_container", SMOKE)
    assert body.count("RestartCount") == 2, "the restart count is not sampled twice"
    assert '-gt "$restarts"' in body, "a count that is merely nonzero is not a loop"


@pytest.mark.parametrize(
    "proto,containers",
    [
        ("vless-reality", ["sing-box"]),
        ("hysteria2", ["sing-box"]),
        ("ikev2", ["ipsec-vpn-server"]),
        ("dnstt", ["dnstt-server", "dnstt-sshd", "dnstt-socks"]),
    ],
)
def test_the_container_table_is_run_not_read(
    tmp_path: Path, proto: str, containers: list[str]
) -> None:
    """compose.yml renames three services with container_name, and this table
    restates the mapping because `vpnctl --json protocol list` does not carry
    it yet. Executed rather than grepped: the names appear in the comment above
    the case statement too, so reading the file cannot tell a live branch from
    a deleted one."""
    out = run_helpers(
        tmp_path,
        f"protocol_containers {proto}",
        source=SMOKE,
        names=("protocol_containers",),
    )
    assert out.split() == containers


def test_no_protocol_in_the_registry_is_missing_from_that_table(
    tmp_path: Path,
) -> None:
    """A protocol is a new module plus one line in PROTOCOLS, and nothing in
    Python knows this file exists. The script says so loudly at runtime; this
    says so before the deploy."""
    from vpnctl import protocols

    for name in protocols.PROTOCOLS:
        out = run_helpers(
            tmp_path,
            f"protocol_containers {name}",
            source=SMOKE,
            names=("protocol_containers",),
        )
        assert out.split(), f"smoke.sh knows no containers for {name}"


def test_smoke_asserts_the_loopback_services_separately() -> None:
    """served() ignores 127.0.0.0/8 because systemd-resolved holds
    127.0.0.53:53 on every stock Ubuntu, so it can never see dnstt's two
    loopback back-ends. A second helper, so neither reasoning leaks into the
    other."""
    smoke = read("scripts/smoke.sh")
    assert "loopback_bind" in smoke
    assert "2222 tcp dnstt-sshd" in smoke
    assert "7300 tcp dnstt-socks" in smoke


def test_smoke_validates_the_ikev2_pool_as_an_address(tmp_path: Path) -> None:
    """The regex was shape-only: 192.168.256.0/24 matched it, is not an address,
    and made `iptables -C` fail indistinguishably from "the rule is missing" --
    the exact confusion the validation exists to prevent.

    Run, not read. The old check searched for "ipaddress" anywhere in the file
    and for the retired regex only AFTER `ikev2_pool() {`, about a hundred lines
    below valid_net's own definition -- so reverting valid_net to the shape-only
    regex left the suite green, which is the failure this whole file is about.
    """
    out = run_helpers(
        tmp_path,
        "valid_net 192.168.256.0/24 && echo UNREACHABLE\n"
        'echo "normalised=$(valid_net 192.168.43.10/24)"',
        source=SMOKE,
        names=("valid_net",),
    )
    assert "UNREACHABLE" not in out
    assert "normalised=192.168.43.0/24" in out


# ----------------------------------- the IKEv2 pool derivation, in three copies
# vpnctl.ikev2ctl writes the FORWARD accepts; scripts/smoke.sh and
# scripts/diagnose-ikev2.sh each assert them. When the three disagreed on which
# subnet that was -- the L2TP pool, hardcoded -- every rule protected addresses
# no IKEv2 client is ever given and BOTH health checks reported green inside the
# failure they exist to catch.
#
# They drifted again on the fix for exactly that: diagnose-ikev2.sh grew a
# `command -v python3` guard and a whitespace-tolerant entry match, smoke.sh was
# rewritten afterwards and got neither, so on a box without python3 smoke.sh's
# covering_net failed silently, the pool fell through to the image default, and
# the report blamed the CONTAINER for a missing tool. Nothing was watching the
# two, which is why these are here.
POOL_HELPERS = ("valid_net", "covering_net", "ikev2_pool")


@pytest.mark.parametrize("name", POOL_HELPERS)
def test_the_two_shell_copies_of_the_pool_lookup_are_identical(name: str) -> None:
    """Identical text, not merely identical behaviour on the cases anyone
    thought to probe: these run on a live server, under whatever that box
    happens to have installed, and the drift above was in a branch no probe set
    written from the other copy would have contained."""
    assert shell_function(name, SMOKE) == shell_function(name, DIAGNOSE), (
        f"{name}() has drifted between smoke.sh and diagnose-ikev2.sh"
    )


@needs_python3
@pytest.mark.parametrize(
    "entry",
    [
        "192.168.43.10-192.168.43.250",
        "192.168.43.10-192.168.44.250",
        "192.168.43.0/24",
        "192.168.43.77",
        "10.0.0.5-10.0.3.200",
        " 192.168.43.10 - 192.168.43.250 ",
    ],
)
def test_all_three_copies_cover_the_same_range(tmp_path: Path, entry: str) -> None:
    """The Python one is the reference: it is the copy that reaches iptables."""
    from vpnctl import ikev2ctl

    reference = ikev2ctl._covering_net(entry)
    for source in (SMOKE, DIAGNOSE):
        got = run_helpers(
            tmp_path,
            f'covering_net "{entry}"',
            source=source,
            names=("valid_net", "covering_net"),
        ).strip()
        assert got == reference, f"{source.name} says {got}, ikev2ctl says {reference}"


@needs_python3
@pytest.mark.parametrize(
    "conf,xauth,net",
    [
        # The stock pool, beside the image's own IPv6 range.
        (
            "192.168.43.10-192.168.43.250,"
            "fddd:500:500:500::1000-fddd:500:500:500::1fff",
            "",
            "192.168.43.0/24",
        ),
        # Straddling two /24s: the case `${first%.*}.0/24` got wrong.
        ("192.168.43.10-192.168.44.250", "", "192.168.40.0/21"),
        # ipsec.conf tolerates padding around the '=' and around each entry.
        ("  192.168.43.10 - 192.168.43.250  ", "", "192.168.43.0/24"),
        # rightaddresspool outranks VPN_XAUTH_NET, and the order does not
        # commute: run.sh writes its firewall rules from the net while ikev2.sh
        # builds the pool from XAUTH_POOL, so the two can be set apart.
        ("192.168.43.10-192.168.43.250", "192.168.99.0/24", "192.168.43.0/24"),
        # No IPv4 pool at all: fall through to the net.
        ("fddd:500:500:500::1000-fddd:500:500:500::1fff", "10.9.0.0/24", "10.9.0.0/24"),
        # Shape-only garbage is not an address, and a container that answers
        # with one must not be believed.
        ("", "192.168.256.0/24", "192.168.43.0/24"),
        # Nothing answered.
        ("", "", "192.168.43.0/24"),
    ],
)
def test_all_three_copies_pick_the_same_pool(
    tmp_path: Path, conf: str, xauth: str, net: str
) -> None:
    """Same question, same answer, whichever of the three is asked.

    Only the network is compared, not the provenance: ikev2ctl spells its
    fallback "image default -- why" and the shell pair "image default, why".
    That difference is cosmetic and goes to a human; the network goes to
    `iptables`.
    """
    from vpnctl import ikev2ctl

    conf_text = f"conn ikev2-cp\n  rightaddresspool={conf}\n" if conf else ""
    assert ikev2ctl.pool_network(conf_text or None, xauth or None)[0] == net

    fake_docker(tmp_path, conf=conf, xauth=xauth)
    for source in (SMOKE, DIAGNOSE):
        out = run_helpers(tmp_path, "ikev2_pool", source=source, names=POOL_HELPERS)
        assert out.partition("|")[0] == net, f"{source.name} answered {out!r}"


@pytest.mark.parametrize("source", [SMOKE, DIAGNOSE], ids=lambda p: p.name)
def test_a_box_without_python3_blames_the_missing_tool(
    tmp_path: Path, source: Path
) -> None:
    """Both copies shell out to python3 to validate, and an unvalidated value is
    what makes `iptables -C` fail as though the rule were missing. Without the
    guard the pool silently falls through to the image default and the report
    says the CONTAINER was unreadable -- sending whoever reads it at a container
    that answered perfectly well."""
    # A PATH with bash on it and nothing else, so `command -v python3` genuinely
    # fails. Shadowing python3 with a failing shim would not do: the guard asks
    # whether the tool is THERE, and a shim is.
    sandbox = tmp_path / "nopython"
    sandbox.mkdir()
    (sandbox / "bash").symlink_to(shutil.which("bash") or "/bin/bash")
    out = run_helpers(
        tmp_path,
        "ikev2_pool",
        source=source,
        names=POOL_HELPERS,
        env={"PATH": str(sandbox)},
    )
    assert out.startswith("192.168.43.0/24|image default, python3 absent")


# ---------------------------------------------------------------- deploy
def test_deploy_describes_the_converge_it_actually_runs() -> None:
    """The file claimed composectl.up() always passes --force-recreate, so
    every apply drops every session. It diffs the trees and bounces only what
    changed; the claim stopped being true and was still being read."""
    dep = read("deploy")
    assert "always passes --force-recreate" not in dep
    assert "changed_services" in dep


def test_no_commit_hash_in_prose() -> None:
    """A hash does not survive a history rewrite: the one this file cited became
    unresolvable and was still there to be copied into a published document.
    The commit subject survives."""
    dep = prose("deploy")
    assert not re.search(r"\bcommit [0-9a-f]{7,40}\b", dep)
    assert "Drop CI: deploy-on-push cost more than it bought" in dep


def _embedded_python(rel: str, first_line: str, last_prefix: str) -> str:
    """One of the python3 -c programs these scripts embed, lifted out to be run.

    Reading the text is enough for most invariants here, but not for a parser:
    the whole point of the two below is which argv shapes they accept, and that
    is a behaviour, not a spelling. So this pulls the program out and the tests
    execute it -- still touching no server and starting no container.
    """
    lines = read(rel).splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == first_line)
    end = next(
        i for i, line in enumerate(lines[start:], start) if line.startswith(last_prefix)
    )
    return "\n".join(lines[start : end + 1])


def _dnstt_zone_of(argv_json: str) -> str:
    import subprocess

    program = _embedded_python(
        "scripts/smoke.sh", "import json, sys", "print(positional[0]"
    )
    # The last line ends with the shell's own `' 2>/dev/null)`; drop it.
    program = program.rsplit("'", 1)[0]
    done = subprocess.run(
        ["python3", "-c", program], input=argv_json, capture_output=True, text=True
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


def test_smoke_reads_the_dnstt_zone_by_parsing_argv_not_by_indexing_it() -> None:
    """A dropped zone must not be mistaken for the -privkey-file value.

    An unset ${VPN_DNSTT_ZONE} does not arrive as an empty argument: it drops out
    of the command entirely, so argv is one shorter and the second-to-last
    element silently becomes /keys/server.key -- which has a dot in it and passes
    any domain-shaped test. That is the bug this check exists to catch, so a
    check that indexes argv reports the broken server as healthy.

    The zone-present case is the real command line off this stack's own server.
    """
    present = (
        '["-udp","62.60.152.48:53","-privkey-file","/keys/server.key",'
        '"tun.example.net","127.0.0.1:2222"]'
    )
    assert _dnstt_zone_of(present) == "tun.example.net"

    dropped = (
        '["-udp","62.60.152.48:53","-privkey-file","/keys/server.key","127.0.0.1:2222"]'
    )
    assert _dnstt_zone_of(dropped) == "MISSING"

    # An explicitly empty value, which is what an operator writing
    # `VPN_DNSTT_ZONE=` rather than leaving it unset would produce.
    empty = '["-udp","1.2.3.4:53","-privkey-file","/k","","127.0.0.1:2222"]'
    assert _dnstt_zone_of(empty) == "MISSING"

    # A flag added later must not shift the positionals.
    extra_flag = (
        '["-udp","1.2.3.4:53","-mtu","1200","-privkey-file","/k",'
        '"tun.example.net","127.0.0.1:2222"]'
    )
    assert _dnstt_zone_of(extra_flag) == "tun.example.net"

    assert _dnstt_zone_of("[]") == "MISSING"
    assert _dnstt_zone_of("not json at all") == "UNREADABLE"


def test_smoke_fails_rather_than_warns_on_a_zoneless_dnstt() -> None:
    """Because every other check in the file passes on that server.

    dnstt-server binds 53/udp with or without a zone, `docker ps` says running,
    and both loopback back-ends are up -- so the only thing separating "serving"
    from "answering for a zone nobody can resolve" is this assertion.
    """
    smoke = code("scripts/smoke.sh")
    assert "dnstt_zone" in smoke
    # The MISSING and UNREADABLE branches must both be failures, not notices.
    missing_branch = smoke.split("MISSING)", 1)[1].split(";;", 1)[0]
    assert "bad dnstt_zone" in missing_branch
    unreadable_branch = smoke.split("UNREADABLE|''", 1)[1].split(";;", 1)[0]
    assert "bad dnstt_zone" in unreadable_branch


# --------------------------------------------- the sing-box pin three readers share


def test_the_sing_box_pin_keeps_the_tag_form_its_three_readers_require() -> None:
    """A digest pin here breaks check.sh and both libbox jobs at once.

    hwdsl2/ipsec-vpn-server IS digest-pinned, and the three dnstt images gained
    digests this session, so reaching for `@sha256:` here is the obvious next
    move -- and every reader of this line requires `sing-box:<tag>` and exits
    non-zero otherwise. They fail loudly rather than validating against the wrong
    binary, which is why this is small; but compose.yml only *says* the tag form
    is load-bearing, and a claim nothing checks is the thing this repository
    keeps having to relearn.
    """
    import re
    import subprocess

    compose = read("compose.yml")
    pins = re.findall(
        r"^[ \t]*image:[ \t]*(ghcr\.io/sagernet/sing-box[^\s]*)$", compose, re.M
    )
    assert len(pins) == 1, f"expected exactly one sing-box pin, found {pins}"
    image = pins[0]
    assert ":" in image.removeprefix("ghcr.io/"), image
    assert "@sha256:" not in image, (
        f"{image} is digest-pinned, and scripts/check.sh plus both libbox jobs in "
        ".github/workflows/app.yml read this line with a sed that requires "
        "`sing-box:<tag>`. Digest-pinning it needs all three taught the new shape "
        "in the same commit -- see the note at the pin."
    )

    # And the readers really do produce that tag, run as they are written.
    sed = r"s|^[[:space:]]*image:[[:space:]]*ghcr\.io/sagernet/sing-box:\(.*\)$|\1|p"
    out = subprocess.run(
        ["sed", "-n", sed, str(ROOT / "compose.yml")],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert out == [image.split(":")[-1]], (out, image)
