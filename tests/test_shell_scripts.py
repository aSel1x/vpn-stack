"""Invariants of the shell half of this stack, asserted by reading it.

Every check here is a bug that shipped: a firewall net that could be armed
twice, a hardcoded ssh port that made `./vpn init` unable to finish, an rsync
that never deleted, a backup that left a world-readable plaintext tar of every
secret in /tmp, a vpnctl call with no lock around it. None of them are visible to
`bash -n`, none need a server, and the alternative -- noticing on the box -- has
already been tried on each one.

Reading the text rather than running it is deliberate: these scripts converge a
live server, so the only thing a test may do with them is look. What cannot be
asserted this way (that the deadman actually dies, that the pool parser accepts
the addresses it should) belongs in scripts/smoke.sh against a real box.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"


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
def test_push_deletes_but_never_deletes_excluded() -> None:
    """A file deleted from the repo has to die on the server too.

    scripts/host-bootstrap.sh was removed here and stayed behind, executable, on
    every server pushed before its removal. --delete-excluded is the opposite
    mistake and far worse: it would remove the files the .gitignore filter
    protects -- /opt/vpn-stack/.env, the symlink into the state directory -- from
    the SERVER.
    """
    push = read("scripts/push.sh")
    assert "--delete " in push or "--delete\\" in push
    assert "--delete-excluded" not in re.sub(r"(?m)^#.*$", "", push)


def test_push_lands_a_root_owned_tree() -> None:
    """-a preserves the operator's uid, and root executes what lands."""
    assert "--chown=root:root" in read("scripts/push.sh")


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


# ------------------------------------------------------------ the lock
def test_every_vpnctl_call_site_takes_the_lock() -> None:
    """CLAUDE.md calls `flock /run/vpn-stack.lock` the entire multi-operator
    story, and vpnctl takes no lock of its own: a call that skips it is a bug
    even on the run where it works. Two applies rendering candidate trees over
    each other is the one race the atomic promote cannot save you from."""
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
def test_smoke_checks_every_enabled_protocols_containers() -> None:
    """It checked `sing-box` alone, so a crash-looping dnstt-sshd -- the
    container that holds every dnstt login -- passed every check while nobody
    could log in."""
    smoke = read("scripts/smoke.sh")
    assert "protocol_containers" in smoke
    assert "dnstt-sshd" in smoke and "ipsec-vpn-server" in smoke
    assert "RestartCount" in smoke


def test_smoke_asserts_the_loopback_services_separately() -> None:
    """served() ignores 127.0.0.0/8 because systemd-resolved holds
    127.0.0.53:53 on every stock Ubuntu, so it can never see dnstt's two
    loopback back-ends. A second helper, so neither reasoning leaks into the
    other."""
    smoke = read("scripts/smoke.sh")
    assert "loopback_bind" in smoke
    assert "2222 tcp dnstt-sshd" in smoke
    assert "7300 tcp dnstt-socks" in smoke


def test_smoke_validates_the_ikev2_pool_as_an_address() -> None:
    """The regex was shape-only: 192.168.256.0/24 matched it, is not an address,
    and made `iptables -C` fail indistinguishably from "the rule is missing" --
    the exact confusion the validation exists to prevent."""
    smoke = code("scripts/smoke.sh")
    assert "ipaddress" in smoke
    assert "valid_net" in smoke
    assert "^[0-9]+(\\.[0-9]+){3}/[0-9]+$" not in smoke.split("ikev2_pool() {", 1)[1]


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
