"""Bring the enabled set of containers up, and the disabled set down.

Two subtleties, both measured rather than assumed, on Compose v5.3.1.

Teardown: removing a service's profile from COMPOSE_PROFILES and running
`up -d --remove-orphans` leaves that container RUNNING. Explicit `rm -sf
<service>` does stop it, because Compose auto-enables a named service's own
profile. Relying on --remove-orphans here would mean "protocol off" quietly
leaves the protocol serving traffic.

Pickup: `up -d` recreates a container whose *definition* changed, and an
env_file is part of the definition -- Compose reads its contents at project
load and folds them into `environment` before hashing it. It is blind to the
rendered tree, though: the bind mount source is the same string either side of
a `rendered` symlink swap, so the hash is unchanged and the container keeps the
directory it resolved when it started. That blindness is why this used to pass
--force-recreate unconditionally, and why dropping the flag without replacing
it would leave `user add` rendering a config that nothing ever reads.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path

from vpnctl import protocols
from vpnctl.paths import ROOT, STATE_DIR

# Which service consumes each rendered path, and how it reaches the process.
#
#   MOUNT     bind-mounted, and the container derives nothing from it that
#             outlives a restart. Docker re-resolves the mount source every time
#             the container starts, so `restart` lands it on the new tree --
#             verified by swapping the symlink under a running container: the old
#             contents survive an `up -d`, the new ones appear after a restart.
#   RECREATE  a restart is not enough; only a new container is. Two reasons, and
#             both are here: an env_file is read once at create time, so a
#             restart re-runs the entrypoint with the OLD environment; and a
#             container that builds state from its input at create time keeps
#             that state across a restart, because the writable layer survives.
#             dnstt-sshd is the second kind and the reason this distinction is
#             not cosmetic -- see its entry below.
#
# Written out by hand because `docker compose config` can only answer half of
# it: the volumes are in there, the env_file provenance is not (it becomes
# `environment` and the path is forgotten). Nor is the name a rule -- dnstt.env
# is dnstt-sshd's file, not dnstt's.
MOUNT = "mount"
RECREATE = "recreate"

_CONSUMERS: tuple[tuple[str, str, str], ...] = (
    ("sing-box/", "sing-box", MOUNT),
    ("dnstt/", "dnstt", MOUNT),
    # RECREATE, not MOUNT, even though the logins file is a plain bind mount.
    # dnstt-sshd/entrypoint.sh:36 is `id "$name" || adduser` -- it only ever
    # ADDS. Nothing deletes an account that dropped out of the list, and the
    # entrypoint says so itself: the container is disposable and /etc/passwd
    # resets with it. Restart it instead and the writable layer survives, so a
    # removed user keeps their account, their group and their hash, and
    # AllowGroups tunnel still lets them in. `user rm` would report success and
    # revoke nothing -- which is the whole reason dnstt has a login per person.
    ("dnstt-sshd/", "dnstt-sshd", RECREATE),
    ("dnstt.env", "dnstt-sshd", RECREATE),
    ("ikev2.env", "ikev2", RECREATE),
)


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


def changed_services(previous: Path | None, candidate: Path) -> dict[str, str] | None:
    """Which services' inputs differ between the live tree and the candidate.

    `{}` means nothing changed and nothing has to be bounced -- the case that
    matters, because it covers every `deploy`, every boot and every `protocol
    on` for a protocol whose siblings were left alone. `None` means "could not
    tell" (no live tree yet, or a rendered file this table does not know), and
    the caller falls back to recreating everything.
    """
    if previous is None or not previous.is_dir():
        return None

    changed: dict[str, str] = {}
    for rel in _tree_files(previous) | _tree_files(candidate):
        old, new = previous / rel, candidate / rel
        if old.is_file() and new.is_file() and old.read_bytes() == new.read_bytes():
            continue
        consumer = _consumer(rel)
        if consumer is None:
            # A protocol grew an output and this table did not hear about it.
            # Bouncing everything is the old behaviour: slow, never stale.
            return None
        service, how = consumer
        # A service that also needs new environment needs a new container, so
        # RECREATE wins over MOUNT when both of its inputs moved.
        if changed.get(service) != RECREATE:
            changed[service] = how
    return changed


def _tree_files(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}


def _consumer(rel: str) -> tuple[str, str] | None:
    for prefix, service, how in _CONSUMERS:
        if rel == prefix or (prefix.endswith("/") and rel.startswith(prefix)):
            return service, how
    return None


def expected_services(enabled: list[protocols.Protocol]) -> list[str]:
    """Every container that has to be up for this set of protocols.

    sing-box is unconditional: it carries every Kind.SINGBOX inbound, has no
    compose profile to deactivate, and is the one service `protocol off` never
    stops. Everything else comes from the registry, so a protocol that grows a
    second container is counted here without this module being edited.
    """
    services = ["sing-box"]
    for proto in enabled:
        services.extend(proto.compose_services)
    return services


def not_running(enabled: list[protocols.Protocol]) -> list[str] | None:
    """Which services that should be up are not. None means "could not tell".

    A bound port is not health, and the gap is not hypothetical: dnstt-sshd
    listens on loopback 2222, so it contributes no port to `wait_ready` at all,
    and the tunnel's own 53/udp goes on being bound by dnstt-server while the
    sshd behind it crash-loops under `restart: always`. Every dnstt client then
    completes a DNS tunnel to a closed door, and `apply` reports success
    because every port it knows about is bound.

    This repo has been caught by exactly that shape twice. Both health checks
    asserted the L2TP subnet while IKEv2 clients were handed addresses from the
    XAUTH pool, so they reported green in the one failure they existed to catch.
    And `diagnose-ikev2.sh probe` sent a junk datagram to port 500 and read its
    arrival as "IKE is not being blocked" -- a test that could not fail in the
    way anyone cared about. A check has to be able to observe the failure.

    None is its own outcome and must not be read as "all fine": `docker compose
    ps` failing is the same query failure `_running_services` documents, and
    reporting an empty list there would turn an unanswerable question into a
    clean bill of health -- which is how `protocol off` once reported success
    while the protocol kept serving traffic.
    """
    running = _running_services()
    if running is None:
        return None
    return sorted({s for s in expected_services(enabled) if s not in running})


def up(
    enabled: list[protocols.Protocol], changed: dict[str, str] | None = None
) -> tuple[bool, str]:
    """Start sing-box plus every enabled container-level protocol.

    `changed` is what `changed_services` found. Only those services get
    bounced, so a `user add` no longer tears down the containers it did not
    touch -- dnstt keeps its tunnel up while sing-box and the sshd take the new
    user list, and an `apply` that changed nothing (deploy, boot) drops no
    session at all. `None` means the diff could not be taken; then every
    service is recreated, which is what this function always used to do.
    """
    profiles = [p.compose_profile for p in enabled if p.compose_profile]
    services = expected_services(enabled)

    before = _container_ids()
    # --build, or a change to a Dockerfile or an entrypoint script is rsynced
    # to the server and then silently ignored: compose reuses the existing
    # image because the tag already exists. Cheap when nothing changed.
    #
    # What makes that cheapness safe is that the three dnstt Dockerfiles pin
    # what they fetch. While they said `go install ...@latest` and `git clone
    # --depth 1`, this flag meant every apply on a dnstt server -- including
    # the one vpn-stack.service runs at boot, unattended -- rebuilt them from
    # whatever upstream had published since, on a live box, with nothing
    # recording what the previous build was. The flag is load-bearing; the pins
    # are what keep it from being a rolling deployment of somebody else's HEAD.
    ok, output = _compose(
        "up", "-d", "--no-deps", "--build", *services, profiles=profiles
    )
    if not ok:
        return ok, output

    # Everything compose noticed for itself -- a new image, a changed
    # definition, a changed env_file -- it has already recreated, and a
    # container it just created is running the new tree by construction. So
    # compare identities and nudge only what is left: the same container, still
    # holding the directory the old symlink pointed at. Identity, not liveness:
    # a container that was merely stopped keeps its id across `up -d`, and
    # reading that as "freshly created" is what left a removed dnstt login
    # working. See _container_ids.
    after = _container_ids()
    # An undiffable tree gets the strongest nudge on everything, which is what
    # this function used to do unconditionally.
    pending = changed if changed is not None else {s: RECREATE for s in services}
    notes = [output]
    for service, how in sorted(pending.items()):
        if service not in services:
            continue  # protocol was turned off; down_disabled deals with it
        if (
            before is not None
            and after is not None
            and (service not in before or before[service] != after.get(service))
        ):
            continue  # compose just gave it a fresh container; already current
        if how == RECREATE:
            ok, out = _compose(
                "up", "-d", "--no-deps", "--force-recreate", service, profiles=profiles
            )
        else:
            ok, out = _compose("restart", service, profiles=profiles)
        notes.append(
            f"{service}: {'recreated' if how == RECREATE else 'restarted'}\n{out}".strip()
        )
        if not ok:
            return False, "\n".join(notes)
    return True, "\n".join(n for n in notes if n)


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


def _container_ids() -> dict[str, str] | None:
    """service -> container id, for every container that EXISTS, running or not.

    The id is the whole point: it is how `up` tells "compose recreated this for
    me" from "this is the same container it was a second ago". None means the
    query failed, and the caller then bounces the changed services anyway -- a
    needless restart is recoverable, a config nothing has read is not.

    `--all`, and not `--status running`, because the difference is a credential
    left working. A stopped container is absent from a running-only listing, so
    `up` read "service not in before" as "compose created this one just now,
    it already holds the new tree" and skipped the nudge. But `up -d` does not
    create a stopped container, it STARTS it: same id, same writable layer. So a
    `user rm` while dnstt-sshd happened to be down left the removed account in
    /etc/passwd -- proven with a real password login -- and `user rm` reported
    success. Ask for every container and the test means what it says.
    """
    result = subprocess.run(
        ["docker", "compose", "ps", "--all", "--format", "json"],
        cwd=ROOT,
        env=_env(),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    payload = result.stdout.strip()
    try:
        # v5.3.1 emits one object per line; other versions emit a single array.
        rows = (
            json.loads(payload)
            if payload.startswith("[")
            else [json.loads(line) for line in payload.splitlines() if line.strip()]
        )
        return {row["Service"]: row["ID"] for row in rows}
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


def wait_ready(
    enabled: list[protocols.Protocol], timeout: float = 240.0
) -> tuple[bool, list[str]]:
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
        return False, [
            f"{n}/{pr} still not bound after {timeout:.0f}s" for n, pr in pending
        ]
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
        capture_output=True,
        text=True,
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
