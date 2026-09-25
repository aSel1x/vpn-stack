"""Invariants of scripts/diagnose-ikev2.sh, the IKEv2 localisation tool.

Every check here is a bug that shipped in this one file: a subnet parser whose
validation was shape-only, a listener check that called a wildcard bind
"loopback only", a port grep that matched the image's own IPv6 pool, a capture
verdict read off a tcpdump that never started, and survey modes that exited 0
having looked at nothing. None of them are visible to `bash -n`.

The pure helpers are extracted and RUN, with a fake `docker` and a fake `ss` on
PATH -- that is the whole point of a parser that asks the container: it can be
asked to parse anything without one. Nothing here needs Docker, root or the
network, and nothing runs a mode of the script that would capture or send.
What cannot be exercised this way (that tcpdump really does fail this way, that
pluto really binds where the check looks) is read out of the text instead, and
belongs on a live box in scripts/smoke.sh.

shell_function() and run_helpers() take the file to lift from, because the pool
derivation exists here AND in scripts/smoke.sh and the two drifted once:
tests/test_shell_scripts.py imports them to pin the copies together rather than
growing a third one of its own.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "diagnose-ikev2.sh"

needs_python3 = pytest.mark.skipif(
    shutil.which("python3") is None, reason="the pool parser shells out to python3"
)


def text() -> str:
    return SCRIPT.read_text()


def code() -> str:
    """The file with its whole-line comments removed.

    This script explains itself by quoting the shape it replaced -- the junk
    'DIAGPROBE-<host>' datagram, the hardcoded 192.168.42.0/24 -- so a plain
    substring search finds the defect in the comment that documents it and calls
    the fix a regression.
    """
    return "\n".join(
        line for line in text().splitlines() if not line.lstrip().startswith("#")
    )


def shell_function(name: str, source: Path = SCRIPT) -> str:
    """One top-level `name() { ... }` block of a shell file, verbatim.

    `source` because the pool derivation exists in two of these scripts and has
    to keep answering identically; pinning that means lifting the same function
    out of both.
    """
    body = re.search(rf"^{name}\(\) \{{\n.*?^\}}$", source.read_text(), re.S | re.M)
    assert body, f"{name} is not a top-level function in {source.name}"
    return body.group(0)


def run_helpers(
    tmp_path: Path,
    script: str,
    *,
    env: dict[str, str] | None = None,
    source: Path = SCRIPT,
    names: tuple[str, ...] = ("udp_bind", "valid_net", "covering_net", "ikev2_pool"),
) -> str:
    """Run `script` with `source`'s pool/listener helpers sourced.

    The helpers are pure -- they shell out to docker, ss and python3 and touch
    nothing -- so a fake docker and a fake ss in tmp_path are enough to drive
    every branch.
    """
    fns = tmp_path / "fns.sh"
    fns.write_text("\n".join(shell_function(n, source) for n in names))
    proc = subprocess.run(
        ["bash", "-c", f'set -uo pipefail\nsource "{fns}"\n{script}'],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}",
            **(env or {}),
        },
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def fake_docker(tmp_path: Path, *, conf: str = "", xauth: str = "") -> None:
    """A `docker` that answers the two questions ikev2_pool asks, and nothing else.

    ikev2_pool reads `conn ikev2-cp`'s rightaddresspool out of ikev2.conf and
    VPN_XAUTH_NET out of the environment; both go through `docker exec`.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    shim = bin_dir / "docker"
    shim.write_text(
        "#!/bin/bash\n"
        'case "$*" in\n'
        f"  *rightaddresspool*) printf '%s\\n' {conf!r} ;;\n"
        f"  *printenv*) printf '%s\\n' {xauth!r} ;;\n"
        "esac\n"
    )
    shim.chmod(0o755)


def fake_ss(tmp_path: Path, *rows: str) -> None:
    """An `ss` printing canned `-H -lun` rows: State Recv-Q Send-Q Local Peer."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    shim = bin_dir / "ss"
    body = "".join("printf '%s\\n' {!r}\n".format(r) for r in rows)
    shim.write_text("#!/bin/bash\n" + body)
    shim.chmod(0o755)


# ------------------------------------------------------- the XAUTH pool parser
@needs_python3
def test_pool_validation_is_not_shape_only(tmp_path: Path) -> None:
    """192.168.256.0/24 matches the old regex and is not an address.

    Handing it to `iptables -C` fails in a way indistinguishable from "the rule
    is missing", so the validation that exists to stop a healthy box being
    reported broken was the thing reporting it.
    """
    out = run_helpers(
        tmp_path,
        "valid_net 192.168.256.0/24 && echo UNREACHABLE\n"
        'echo "normalised=$(valid_net 192.168.43.10/24)"',
    )
    assert "UNREACHABLE" not in out
    assert "normalised=192.168.43.0/24" in out


@needs_python3
def test_a_shape_only_xauth_net_falls_back_and_says_why(tmp_path: Path) -> None:
    fake_docker(tmp_path, xauth="192.168.256.0/24")
    out = run_helpers(tmp_path, "ikev2_pool")
    net, _, provenance = out.strip().partition("|")
    assert net == "192.168.43.0/24"
    assert "VPN_XAUTH_NET=192.168.256.0/24" in provenance
    assert "image default" in provenance


@needs_python3
def test_the_pool_is_derived_from_both_ends(tmp_path: Path) -> None:
    """A pool wider than a /24 must not be read as one.

    `${first%.*}.0/24` is a guess about the prefix, and for a pool that spans
    two /24s it installs rules for addresses clients are never handed -- the
    original 192.168.42.0/24 bug with a different constant.
    """
    fake_docker(tmp_path, conf="192.168.43.10-192.168.44.250")
    assert run_helpers(tmp_path, "ikev2_pool").startswith("192.168.40.0/21|")


@needs_python3
def test_the_stock_pool_still_reads_as_the_image_default(tmp_path: Path) -> None:
    """The one answer all three copies of this lookup must agree on.

    vpnctl.ikev2ctl and scripts/smoke.sh resolve the stock pool to
    192.168.43.0/24; three copies that disagree is the failure this repo has
    already paid for once.
    """
    fake_docker(
        tmp_path,
        conf="192.168.43.10-192.168.43.250,fddd:500:500:500::1000-fddd:500:500:500::1fff",
    )
    assert (
        run_helpers(tmp_path, "ikev2_pool").strip()
        == "192.168.43.0/24|conn ikev2-cp rightaddresspool"
    )


@needs_python3
def test_rightaddresspool_outranks_xauth_net(tmp_path: Path) -> None:
    """The order does not commute, and this is the direction that matters.

    run.sh uses XAUTH_NET for the firewall rules it writes while ikev2.sh builds
    the pool from XAUTH_POOL, so the two can be set apart; rightaddresspool is
    literally what pluto assigns.
    """
    fake_docker(tmp_path, conf="192.168.43.10-192.168.43.250", xauth="192.168.99.0/24")
    assert run_helpers(tmp_path, "ikev2_pool").startswith(
        "192.168.43.0/24|conn ikev2-cp rightaddresspool"
    )


@needs_python3
def test_an_unreadable_container_is_named_as_such(tmp_path: Path) -> None:
    """A fallback must not read as a real answer."""
    fake_docker(tmp_path)
    out = run_helpers(tmp_path, "ikev2_pool")
    assert out.strip() == "192.168.43.0/24|image default, container unreadable"


@needs_python3
def test_an_unusable_pool_is_distinguished_from_an_absent_one(tmp_path: Path) -> None:
    fake_docker(tmp_path, conf="fddd:500:500:500::1000-fddd:500:500:500::1fff")
    out = run_helpers(tmp_path, "ikev2_pool")
    assert "conn ikev2-cp gave an unusable pool" in out


def test_the_pool_is_not_assembled_by_string_surgery() -> None:
    """The image default is a stated constant; a parsed pool must not become one."""
    body = shell_function("ikev2_pool")
    assert "${first%.*}" not in body, "the prefix is being guessed, not derived"
    assert "%s.0/24|conn" not in body
    assert "^[0-9]+(\\.[0-9]+){3}/[0-9]+$" not in body, "shape-only validation is back"


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
def test_the_shell_and_the_python_answer_identically(
    tmp_path: Path, entry: str
) -> None:
    """The invariant three copies of this lookup exist to satisfy.

    vpnctl.ikev2ctl writes the FORWARD rules; this script and scripts/smoke.sh
    assert them. When the three disagreed on which subnet that was, every rule
    protected addresses no client is given and both checks reported green inside
    the failure they exist to catch. So the shell asks python3 the same question
    the Python side asks itself, and this pins them to the same answer.
    """
    from vpnctl import ikev2ctl

    shell = run_helpers(tmp_path, f'covering_net "{entry}"').strip()
    assert shell == ikev2ctl._covering_net(entry)


@needs_python3
def test_an_ipv6_entry_is_refused_by_both(tmp_path: Path) -> None:
    from vpnctl import ikev2ctl

    entry = "fddd:500:500:500::1000-fddd:500:500:500::1fff"
    assert ikev2ctl._covering_net(entry) is None
    assert run_helpers(tmp_path, f'covering_net "{entry}" || echo REFUSED').strip() == (
        "REFUSED"
    )


# ----------------------------------------------------------- listener checking
@pytest.mark.parametrize(
    "row,expected",
    [
        ("UNCONN 0 0 0.0.0.0:500 0.0.0.0:*", "wildcard 0.0.0.0"),
        ("UNCONN 0 0 *:500 *:*", "wildcard *"),
        ("UNCONN 0 0 [::]:500 [::]:*", "wildcard [::]"),
        ("UNCONN 0 0 203.0.113.9:500 0.0.0.0:*", "public 203.0.113.9"),
        ("UNCONN 0 0 127.0.0.1:500 0.0.0.0:*", "loopback"),
        ("UNCONN 0 0 127.0.0.53%lo:500 0.0.0.0:*", "loopback"),
    ],
)
def test_a_wildcard_bind_is_served_not_loopback(
    tmp_path: Path, row: str, expected: str
) -> None:
    """A socket on 0.0.0.0:500 answers every global address.

    Demanding the literal address out of `ip addr` reported it as "bound, but
    NOT on any global address (loopback only)" -- a healthy box called broken,
    which teaches people to ignore the check.
    """
    fake_ss(tmp_path, row)
    assert run_helpers(tmp_path, "udp_bind 500").strip() == expected


def test_no_listener_is_absent_and_not_loopback(tmp_path: Path) -> None:
    fake_ss(tmp_path)
    assert run_helpers(tmp_path, "udp_bind 500").strip() == "absent"


def test_the_port_is_asked_of_ss_not_grepped_out_of_it() -> None:
    """hwdsl2's own IPv6 pool is fddd:500:500:500::/64.

    A grep for ":500\\b" over `ss -lunp` matches a socket bound to that address
    on some completely different port, and announces udp/500 as served when
    charon never bound it -- the same substring trap that reported dnstt's
    53/udp as served because systemd-resolved holds 127.0.0.53:53.
    """
    body = code()
    assert 'ss -H -lun "sport = :$1"' in shell_function("udp_bind")
    assert 'grep -qE ":$p' not in body
    assert "grep -qE ':1701" not in body


# ------------------------------------------- verdicts, and what may produce one
def test_a_capture_that_never_ran_is_not_a_verdict() -> None:
    """tcpdump's exit status decides whether the counts mean anything.

    An empty capture from a tcpdump that failed to start is byte-identical to
    one from a path that dropped everything, and reading it as "NOTHING arrived"
    manufactures hypothesis (A)/(B) out of a measurement that never happened.
    124 is timeout doing its job; 0 is -c 200 filling up; anything else is not a
    measurement.
    """
    body = code()
    assert "rc=${PIPESTATUS[0]}" in body
    assert "rc != 0 && rc != 124" in body
    assert "2>/dev/null | tee" not in body, "tcpdump's own complaint is being discarded"


def test_the_capture_is_not_left_world_readable() -> None:
    """-A means the file holds the payload of every datagram on those ports."""
    assert "( umask 077;" in code()


def test_a_finding_does_not_exit_zero() -> None:
    """`listen` and `local` report a survey, and $? is all a wrapper sees.

    Both exited 0 unconditionally, including from the branch that says NOTHING
    arrived at the interface and from a run that could not read iptables at all.
    """
    body = code()
    assert "c_bad()  { FAILED=1;" in body
    assert re.search(r"if \(\( FAILED \)\); then\n  exit 1", body)
    assert re.search(r"elif \(\( INCONCLUSIVE \)\); then\n  exit 2", body)


def test_unreadable_iptables_is_inconclusive_not_clean() -> None:
    body = code()
    skipped = body.split("cannot read iptables", 1)[1].split("return", 1)[0]
    assert "INCONCLUSIVE=1" in skipped


def test_probe_sends_the_genuine_packet_first() -> None:
    """The filter is stateful and the first datagram of a flow decides.

    Priming a tuple with junk and then sending the byte-identical IKE_SA_INIT
    down it got the IKE through and pluto answered in full -- so a probe that
    sent the control first would report a healthy path on the exact network
    where every real client fails.
    """
    loop = (
        text().split("    for port in (500, 4500):", 1)[1].split("\n    print()", 1)[0]
    )
    assert loop.index("sa_init(ike_tag)") < loop.index("junk(junk_tag,")


def test_probe_still_sends_a_genuine_ike_sa_init_and_a_marked_control() -> None:
    """The defect this file exists to correct: a junk datagram is not a proxy."""
    body = code()
    assert "DIAGPROBE" not in body, "the junk-only probe is back"
    assert 'ike_tag = ("DIAGIKE-%s" % host_tag).encode()' in body
    assert 'junk_tag = ("DIAGJUNK-%s" % host_tag).encode()' in body
    assert "expect_spi=spi" in body


def test_a_reply_outranks_a_control_that_could_not_be_sent() -> None:
    """A reply is positive proof; the control only calibrates `listen`."""
    verdict = text().split("    print()\n", 1)[1]
    assert verdict.index("if ike_reply:") < verdict.index("if unsent:")


def test_port_unreachable_from_the_destination_is_not_a_reject() -> None:
    """Both arrive as ICMP type 3, and conflating them blamed a middlebox.

    A server whose ikev2 container is simply down answers port-unreachable from
    its own address: that is proof the IKE arrived, and reporting it as "rejected
    upstream, nothing on the server can change it" sends the operator away from
    the one place the fault is.
    """
    body = text()
    assert "if ic_code == ICMP_PORT_UNREACH and ip == dest:" in body
    assert 'return ip, "closed"' in body
    assert "server-side fault" in body


def test_path_refuses_ipv6_on_the_resolved_family() -> None:
    """A ':' in the argument is not how you learn a target is IPv6.

    hop_at_ttl reads ICMP off the IPv4 error queue only, so a name with nothing
    but an AAAA record drew no ICMP at all and printed twenty empty hops: a walk
    that never happened, presented as one that found nothing.
    """
    body = code()
    assert "if family != socket.AF_INET:" in body
    assert 'if ":" in host:' not in body


def test_a_missing_ss_is_not_a_finding_about_the_listeners() -> None:
    """udp_bind's only source is ss, so without it every port reads as absent."""
    body = code()
    guard = body.split('c_head "Listeners"', 1)[1].split("for p in 500 4500", 1)[0]
    assert "command -v ss >/dev/null" in guard
    assert "INCONCLUSIVE=1" in guard


def test_an_unreadable_ufw_is_not_reported_as_inactive() -> None:
    """`ufw status` needs root, and that is a third answer, not the harmless one.

    Folded into one condition with the active test, an installed and running ufw
    that simply could not be read printed "ufw inactive or absent" -- in the mode
    documented as runnable without sudo.
    """
    body = code()
    assert "ufw status >/dev/null 2>&1" in body
    assert "ufw inactive or absent" not in body


def test_the_walk_stops_on_the_resolved_address() -> None:
    assert 'if a and a == dest and akind != "reject":' in code()
