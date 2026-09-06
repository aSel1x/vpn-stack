"""Bring the enabled set of containers up, and the disabled set down.

The subtle part is teardown. Verified on Docker Compose v5.3.1: removing a
service's profile from COMPOSE_PROFILES and running `up -d --remove-orphans`
leaves that container RUNNING. Explicit `rm -sf <service>` does stop it, because
Compose auto-enables a named service's own profile. Relying on --remove-orphans
here would mean "protocol off" quietly leaves the protocol serving traffic.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time

from vpnctl import protocols
from vpnctl.paths import ROOT, STATE_DIR


def _env() -> dict[str, str]:
    """compose.yml interpolates ${VPN_STATE}; make it follow STATE_DIR.

    Without this, VPN_STATE_DIR=<dir> moves the Python side to a test directory
    while compose keeps bind-mounting /etc/vpn-stack -- so the documented test
    escape hatch would quietly operate on live state.
    """
    return {**os.environ, "VPN_STATE": str(STATE_DIR)}


def _compose(*args: str, profiles: list[str] | None = None) -> tuple[bool, str]:
    env_args: list[str] = []
    for name in profiles or []:
        env_args += ["--profile", name]
    result = subprocess.run(
        ["docker", "compose", *env_args, *args],
        cwd=ROOT,
        env=_env(),
        capture_output=True,
        text=True,
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def up(enabled: list[protocols.Protocol], recreate: bool = True) -> tuple[bool, str]:
    """Start sing-box plus every enabled container-level protocol."""
    profiles = [p.compose_profile for p in enabled if p.compose_profile]
    services = ["sing-box"]
    for proto in enabled:
        services.extend(proto.compose_services)
    args = ["up", "-d", "--no-deps"]
    if recreate:
        args.append("--force-recreate")
    return _compose(*args, *services, profiles=profiles)


def down_disabled(enabled: list[protocols.Protocol]) -> tuple[bool, str]:
    """Explicitly remove containers for protocols that are no longer enabled."""
    enabled_services = {s for p in enabled for s in p.compose_services}
    stale = [
        s
        for p in protocols.ordered()
        for s in p.compose_services
        if s not in enabled_services
    ]
    if not stale:
        return True, "nothing to tear down"

    running = _running_services()
    if running is None:
        return False, "could not list running services; left them alone"
    to_remove = [s for s in stale if s in running]
    if not to_remove:
        return True, f"already down: {', '.join(stale)}"
    ok, output = _compose("rm", "-sf", *to_remove)
    return ok, f"removed {', '.join(to_remove)}\n{output}".strip()


def _running_services() -> set[str] | None:
    """Which compose services are up, or None if we could not find out.

    The difference matters: an empty set means "nothing is running, nothing to
    tear down", and returning that on a failed query made `protocol off` report
    success while the protocol kept serving traffic.
    """
    result = subprocess.run(
        ["docker", "compose", "ps", "--services", "--status", "running"],
        cwd=ROOT,
        env=_env(),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def wait_ready(enabled: list[protocols.Protocol], timeout: float = 240.0) -> tuple[bool, list[str]]:
    """Block until every enabled protocol's ports are bound, or time out.

    `docker compose up` returns as soon as the container starts, but
    hwdsl2/ipsec-vpn-server needs ~30s to generate its config and bring pluto
    and xl2tpd up. Returning before that makes the smoke test that runs next
    fail on a server that is merely still starting -- a false alarm that trains
    people to ignore the smoke test.

    The ceiling is generous because the *first* run is much slower than a
    restart: it also builds the NSS database and issues the IKEv2 CA and server
    certificates, on whatever small VPS this is. Waiting longer costs nothing
    when things are healthy -- the loop returns the moment the last port binds.
    """
    wanted = [(port.number, port.proto) for proto in enabled for port in proto.ports]
    deadline = time.monotonic() + timeout
    pending = list(wanted)
    while pending and time.monotonic() < deadline:
        pending = [p for p in pending if not _is_bound(*p)]
        if pending:
            time.sleep(2)
    if pending:
        return False, [f"{n}/{pr} still not bound after {timeout:.0f}s" for n, pr in pending]
    return True, [f"all {len(wanted)} port(s) bound"]


def _is_bound(port: int, proto: str) -> bool:
    """Is this port served to the outside world?

    Loopback listeners do not count, and that is the whole point of parsing the
    address rather than grepping for the number: systemd-resolved holds
    127.0.0.53:53 and 127.0.0.54:53 on every stock Ubuntu, so a substring match
    reports dnstt's udp/53 as bound on a server where dnstt is not running.
    """
    result = subprocess.run(
        ["ss", "-H", "-ln", "-t" if proto == "tcp" else "-u", f"sport = :{port}"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        # Fall back to trying to bind it ourselves: if we can, nothing else has
        # it. This cannot tell a loopback listener from a real one, but it only
        # runs when ss is unavailable.
        family = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, family) as probe:
            try:
                probe.bind(("0.0.0.0", port))
                return False
            except OSError:
                return True

    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        addr = fields[3].rsplit(":", 1)[0].split("%")[0]
        if addr.startswith("127.") or addr in ("[::1]", "::1"):
            continue
        return True
    return False
