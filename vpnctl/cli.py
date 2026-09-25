"""vpnctl -- the server-side agent.

Runs on the VPN server, as root, and is the only thing that touches Docker,
iptables, ufw and the state directory. `./vpn` on a laptop forwards here over
SSH; a future GUI app does the same thing with `--json`.

Every subcommand accepts --json and emits {"schema": 1, "ok": bool, ...}. That
shape is a public API from day one: the app parses it, so it is versioned
rather than free to drift.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import shutil
import sys
from pathlib import Path

from vpnctl import (
    bootstrap,
    composectl,
    export,
    firewall,
    guard,
    ikev2ctl,
    protocols,
    render,
    sbctl,
    secrets_store,
    state,
    users_store,
)
from vpnctl.export import ExportError
from vpnctl.paths import (
    DEFAULT_STATE_DIR,
    ENV_FILE,
    RENDERED_LINK,
    REPO_ENV_LINK,
    STATE_DIR,
    STATE_JSON,
)

SCHEMA = 1
_JSON = False
_PAYLOAD: dict = {}


# --------------------------------------------------------------------- output


def say(message: str) -> None:
    if not _JSON:
        print(message)


def warn(message: str) -> None:
    print(message, file=sys.stderr)


def emit(ok: bool = True, **data) -> None:
    if _JSON:
        print(json.dumps({"schema": SCHEMA, "ok": ok, **data}, indent=2))


def die(message: str, code: int = 1, **data) -> None:
    """Report a refusal and stop. `code` is 1 unless the caller can use better.

    The one other value in use is 75 (EX_TEMPFAIL), for the lock: it is what
    `flock -E 75` in the app's wrapper already reserves for "somebody else is
    mid-apply", so a client can tell busy from broken without reading English.
    """
    if _JSON:
        print(
            json.dumps(
                {"schema": SCHEMA, "ok": False, "error": message, **data}, indent=2
            )
        )
    else:
        warn(message)
    raise SystemExit(code)


# ------------------------------------------------------------------- the lock

# The one serialisation on the server. CLAUDE.md calls it "the entire
# multi-operator story", and every caller wraps vpnctl in it already -- ./vpn,
# scripts/deploy.sh, scripts/install.sh, the boot unit, the app. This is the
# same lock taken from inside, so that correctness stops being a property of
# each caller.
LOCK_FILE = Path("/run/vpn-stack.lock")

# Held for the life of the process; the kernel drops it when we exit. Kept in a
# global so it is visibly never closed: closing the descriptor releases the lock,
# and releasing it halfway through an apply is the same as never taking it.
_LOCK_FD: int | None = None


def _acquire_lock(path: Path) -> int | None:
    """Take `path` exclusively, without blocking, or refuse with EX_TEMPFAIL.

    Non-blocking is not a nicety. A plain blocking lock here deadlocks against
    every caller that already holds this file through flock(1), because flock(1)
    opens its own file description and the kernel treats that as a different
    holder: `timeout 3 flock LK bash -c 'timeout 2 flock LK echo INNER'` prints
    nothing and the inner command dies at its own timeout. Measured, not
    assumed. VPN_STACK_LOCK_HELD is the handshake those callers export and the
    first line of defence; LOCK_NB is the second, so a caller that forgets the
    handshake gets a refusal rather than a process that never returns.
    """
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as exc:
        # /run is root-only, and everything a mutating command does needs root
        # anyway (docker, iptables, ufw), so this is a test directory or a dev
        # box -- where there is no live state to serialise against and the
        # documented VPN_STATE_DIR escape hatch has to keep working. Loud, not
        # fatal; on the real server the wrappers hold the real lock too.
        warn(f"warning: cannot take {path} ({exc}); running unserialised")
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        die(
            f"another vpn-stack command holds {path}. Two writers that "
            "read-modify-write users.json or state.json lose one of the two "
            "writes, and two `apply` runs promote each other's candidate tree. "
            "Nothing was changed; try again when the other one finishes.",
            code=75,
        )
    return fd


def _lock_if_mutating(args) -> int | None:
    """Serialise the commands that write; leave the readers alone.

    `status`, `user list`, `user export` and `protocol list` take no lock at
    all. users.json and state.json are written through a temp file and
    os.replace, so a reader never sees half of one, and a reader that could fail
    during an apply would leave nobody able to observe the apply -- the app
    polls `status` in exactly that window. `user export` is a reader for this
    purpose even though it shells into the ikev2 container: it hands out
    credentials that already exist, and the app's wrapper locks it regardless.
    """
    if not getattr(args, "mutates", False):
        return None
    if os.environ.get("VPN_STACK_LOCK_HELD"):
        return None
    return _acquire_lock(LOCK_FILE)


# ----------------------------------------------------------------- the engine


def _ensure_env_link() -> None:
    """Keep ROOT/.env pointing at the real one in the state directory.

    `docker compose` reads .env from the project directory, and the real file
    lives in /etc/vpn-stack so a checkout cannot contain it. Re-established on
    every apply rather than only at install: if the link goes missing,
    ${VPN_SERVER_HOST} expands to an empty string instead of failing, and dnstt
    binds the wildcard :53 -- straight into systemd-resolved's stub listener.
    """
    if not ENV_FILE.exists():
        return
    if REPO_ENV_LINK.is_symlink():
        if REPO_ENV_LINK.resolve() == ENV_FILE.resolve():
            return
        REPO_ENV_LINK.unlink()
    elif REPO_ENV_LINK.exists():
        # A real file here is somebody's hand-made config. Refuse to delete it.
        warn(f"warning: {REPO_ENV_LINK} is a regular file, not a link to {ENV_FILE}")
        return
    REPO_ENV_LINK.symlink_to(ENV_FILE)


def _warn_if_defaulted(defaulted: bool) -> None:
    """Say it out loud when the protocol set was invented rather than read.

    A missing state.json cannot be an error -- a freshly provisioned box has
    none -- but the default set is not the empty set and not necessarily the set
    this server was running. dnstt is default_enabled=False, so the first
    converging apply after the file disappears removes its three containers and
    deletes 53/udp from ufw exactly as if the operator had asked for it. dnstt
    is also the last-resort protocol people fall back to when nothing else gets
    through, which makes it the worst possible thing to turn off silently.
    """
    if not defaulted:
        return
    warn(
        f"warning: {STATE_JSON} does not exist, so the DEFAULT protocol set is "
        "in force -- which is not necessarily the set this server was running. "
        "dnstt in particular is OFF by default: if it was on, converging now "
        "removes its three containers and deletes 53/udp from ufw. Check "
        "`vpnctl protocol list` first, or restore state.json from a backup."
    )


def apply(restart: bool = True, quiet: bool = False) -> dict:
    """Render -> validate -> promote -> converge containers, firewall, certs.

    The live tree is never mutated. A candidate is built alongside it and only
    becomes live if sing-box accepts it, so a bad config cannot take the server
    down and there is nothing to roll back.
    """
    guard.require_server("apply")

    # VPN_STATE_DIR moves the state directory but not the Docker daemon, the
    # firewall or the host's ports. Left alone, `user add` against a test
    # directory would start a real sing-box on real ports -- the exact failure
    # guard.py exists to prevent, one level down. A pointed state directory
    # therefore renders and validates, and stops there.
    if STATE_DIR != DEFAULT_STATE_DIR and os.environ.get("VPN_ALLOW_CONVERGE") != "1":
        if restart:
            warn(
                f"note: VPN_STATE_DIR={STATE_DIR} -- rendering and validating only.\n"
                "      Containers, firewall and certificates are untouched. "
                "Set VPN_ALLOW_CONVERGE=1 to override."
            )
        restart = False

    _ensure_env_link()

    st, defaulted = state.load_or_default()
    _warn_if_defaulted(defaulted)

    enabled = state.enabled_protocols(st)
    gaps = bootstrap.missing_secrets(enabled)
    if gaps:
        die(
            "cannot render: missing secrets for "
            + "; ".join(f"{k} ({', '.join(v)})" for k, v in gaps.items())
            + ". Run `vpnctl bootstrap`.",
            missing=gaps,
        )

    tree, enabled = render.render_all()
    candidate = render.write_candidate(tree)
    promoted = False
    try:
        try:
            ok, output = sbctl.check_config(candidate / "sing-box")
            if not ok:
                die(f"sing-box rejected the new config; nothing changed.\n{output}")

            # Read before the swap: afterwards `rendered` points at the candidate
            # and there is nothing left to compare it against. This is what
            # decides which containers get bounced -- a `user add` used to
            # recreate every one of them, including the protocols whose rendered
            # output was byte-identical.
            previous = RENDERED_LINK.resolve() if RENDERED_LINK.exists() else None

            # The mark this apply inherited, read before it lays down its own. A
            # tree promoted by an earlier --no-restart is live on disk and in
            # nothing else: the containers still run the tree from before it, and
            # the diff cannot see that -- it compares two directories, never a
            # directory against a running container. So `bootstrap --force`
            # followed by a plain `apply` found the two trees identical, bounced
            # nothing, and left sing-box serving the OLD REALITY key and the OLD
            # Hysteria2 certificate for good, every port bound and smoke green,
            # while every re-exported profile failed.
            st = state.load()
            inherited_pending = st.converge_pending

            render.promote(candidate)
            promoted = True

            # The mark goes down HERE, immediately after the swap, and exactly
            # one place clears it: the end of a converge that reported every
            # step. It used to be set only in the --no-restart branch, so every
            # failure BETWEEN the promote and the clear left no mark at all --
            # and composectl.up fails part-way by design, with sing-box last in
            # the service order and so the usual stale victim. The operator's
            # retry then rendered a byte-identical tree, diffed it to {},
            # bounced nothing, passed the readiness wait because the OLD
            # containers still held the ports, and printed "config unchanged;
            # nothing restarted" and "OK." with exit 0. smoke.sh was green. Any
            # exit from here on -- a die(), a Ctrl-C, an SSH drop during a long
            # --build -- now forces the next apply to recreate everything.
            st.converge_pending = True
            state.save(st)
        finally:
            if not promoted:
                # A candidate that never became live is a directory nothing
                # points at, holding every user's credentials at 0600 until
                # prune eventually walks past it. One disposal site for both
                # reasons it can happen: sing-box rejected it, or the promote
                # itself failed. (A candidate abandoned *inside* write_candidate
                # has no name to delete here; prune bounds that one.)
                shutil.rmtree(candidate, ignore_errors=True)

        changed = composectl.changed_services(previous, candidate)
        if inherited_pending:
            changed = None

        result = {
            "rendered": candidate.name,
            "enabled_protocols": [p.name for p in enabled],
            "restarted": restart,
            "config_changed": None if changed is None else sorted(changed),
            # True until a converge earns the right to clear it, and the value
            # in the payload says which of those two happened.
            "converge_pending": True,
        }
        if not quiet:
            say(
                f"rendered {candidate.name}: "
                f"{', '.join(p.name for p in enabled) or 'nothing'}"
            )

        if not restart:
            say(
                "note: NOT applied (--no-restart). Containers still run the previous config,\n"
                "      so a convergence is now PENDING: the next `vpnctl apply` recreates\n"
                "      every service, whether or not the rendered tree changes again."
            )
            return result

        try:
            ok, output = composectl.up(enabled, changed)
            if not ok:
                die(f"could not converge the containers:\n{output}")
            if not quiet:
                say(
                    "  "
                    + (
                        "no live config to compare against; converged everything"
                        if changed is None
                        else f"config changed: {', '.join(sorted(changed))}"
                        if changed
                        else "config unchanged; nothing restarted"
                    )
                )

            ok, output = composectl.down_disabled(enabled)
            # Every step past `up` warns and falls through rather than dying:
            # the boot unit needs exit 0, and the payload carries each failure
            # in full. What makes that safe is that the failures are also
            # MACHINE-readable -- one boolean per step, beside the prose -- so a
            # caller does not have to pattern-match English to find out whether
            # the server is serving.
            result["teardown"] = output
            result["teardown_ok"] = ok
            if not ok:
                warn(f"warning: could not tear down disabled services:\n{output}")

            ready, notes = composectl.wait_ready(enabled)
            result["ready"] = notes
            result["ports_ready"] = ready
            if not ready:
                warn("warning: some ports never came up:\n  " + "\n  ".join(notes))
            elif not quiet:
                say(f"  {notes[0]}")

            # A bound port is not health. dnstt-sshd listens on loopback only, so
            # it contributes no port to the wait at all, and dnstt-server goes on
            # holding 53/udp while the sshd behind it crash-loops -- every dnstt
            # client then completes a tunnel to a closed door while `apply`
            # reports success. None is "docker could not tell", which is not a
            # clean bill of health and must not be read as one.
            stopped = composectl.not_running(enabled)
            result["not_running"] = stopped
            if stopped is None:
                warn(
                    "warning: could not ask docker which services are running; "
                    "a port being bound is not proof the service behind it is up"
                )
            elif stopped:
                warn(
                    "warning: expected services are not running: " + ", ".join(stopped)
                )

            ok, actions = firewall.reconcile(enabled)
            result["firewall"] = actions
            result["firewall_ok"] = ok
            if not ok:
                warn(
                    "warning: firewall reconciliation failed:\n  "
                    + "\n  ".join(actions)
                )
            elif not quiet:
                for line in actions:
                    say(f"  ufw: {line}")

            if any(p.name == "ikev2" for p in enabled) and ikev2ctl.is_running():
                result["ikev2_reconcile"] = reconcile_ikev2()
        finally:
            _reconcile_ikev2_forwarding(enabled, result)

        st = state.load()
        st.last_applied = [p.name for p in enabled]
        # The readiness wait is the one warn-only step that still holds the mark
        # down: a port that never bound means this convergence did not complete,
        # so the next apply has to re-converge instead of diffing an unchanged
        # tree and bouncing nothing. A teardown or firewall failure is not a
        # claim that the containers are running the wrong tree, so neither keeps
        # it set.
        if result["ports_ready"]:
            st.converge_pending = False
            result["converge_pending"] = False
        state.save(st)
        return result
    finally:
        # On the way out whatever happened: the runs that leave a generation
        # behind are exactly the ones that used to skip this, because it sat on
        # the fully successful path. Its own failure must not turn a successful
        # apply into a failed one -- nor print a second JSON object after die()
        # has already printed one, which would leave --json unparseable.
        try:
            render.prune()
        except Exception as exc:  # noqa: BLE001 - tidying up is never the verdict
            warn(f"warning: could not prune old rendered generations: {exc}")


def _reconcile_ikev2_forwarding(
    enabled: list[protocols.Protocol], result: dict
) -> None:
    """Make FORWARD match the enabled set, and always record what happened.

    Called from `apply`'s finally, for two reasons. It used to sit at the end,
    after every step that can die(), so a converge failure skipped it entirely
    -- and these are raw `iptables -I` inserts with no persistence of their own,
    which are the difference between an IKEv2 SA that forwards traffic and one
    that establishes and silently carries none. And when the container was not
    running the key was simply absent from the payload, where "not applicable"
    and "succeeded" read identically.

    After firewall.reconcile, which the finally guarantees: `ufw allow` reloads
    ufw's own rules, so the raw inserts have to come last.

    Nothing else removes the pair, so `protocol off ikev2` left it behind for
    ever. The removal is here rather than beside down_disabled so that one
    function owns the whole question "do the FORWARD rules match the enabled
    set", and so a converge failure cannot skip that direction either.
    """
    try:
        if not any(p.name == "ikev2" for p in enabled):
            ok, output = ikev2ctl.remove_ipv4_forwarding()
        elif not ikev2ctl.is_running():
            ok, output = False, "skipped, container not running"
        else:
            ok, output = ikev2ctl.ensure_ipv4_forwarding()
    except OSError as exc:
        # A missing docker or iptables binary raises out of subprocess, and this
        # runs in a finally: letting it out would replace the converge failure
        # that got us here with a traceback -- and, under --json, print a second
        # payload after die() has already printed one.
        ok, output = False, f"could not reconcile the FORWARD rules: {exc}"
    result["ikev2_forwarding"] = output
    result["forwarding_ok"] = ok
    if not ok:
        warn(f"warning: IKEv2 IPv4 FORWARD rules not reconciled: {output}")


def reconcile_ikev2() -> dict:
    """Make the container's certificate set match the enabled users.

    Repairs both directions from observed truth rather than remembered intent,
    and drains revoke_pending -- revocations that could not run when they were
    asked for, because the container was down. Without that queue, a `user rm`
    with ikev2 stopped leaves a certificate that still grants access and no
    record that it should not.

    Three states a name can be in, kept apart because collapsing any two of them
    hands somebody a credential:

    A queued name that is WANTED again is revoked and then re-issued, never
    skipped. `user rm alice` with ikev2 down queues the intent and deletes the
    record, certificate untouched; `user add alice` afterwards is a different
    person under a reused name. Skipping the revocation left `alice` in
    --listclients, so the add direction issued nothing, and the new holder
    imported the PREVIOUS holder's key pair -- and --exportclient's .p12 has a
    verified EMPTY password, so that file is the access. The removed holder's own
    exported profile went on working too, and the queue was emptied on the way.

    A name that is only REVOKED is not present: it has no working certificate.
    Counting it as present meant a user who was revoked and is wanted again was
    never re-issued, and was recorded ikev2_provisioned=True -- a profile that
    cannot connect, written down as provisioned.

    A queued name the container does not hold at all (a lost volume, a restore
    from a backup older than the certificate) has nothing to revoke and leaves
    the queue. Retrying it for ever would put a permanent failure in every
    apply's payload for a name that exists nowhere.

    A name therefore leaves revoke_pending only when its own removal succeeded,
    or when there was nothing left to remove -- never because it became wanted.
    """
    if not ikev2ctl.is_running():
        return {"skipped": "ikev2 container not running"}

    st = state.load()
    users = users_store.load()
    wanted = {u.name for u in users if u.enabled}

    ok, listing = ikev2ctl.list_clients()
    if not ok:
        # Proceeding would read an empty client list as "nothing is issued":
        # it would try to re-add every user, fail on "already exists", and then
        # rewrite ikev2_provisioned to False for everyone -- turning a
        # transient docker error into a database that says nobody has a
        # certificate while the certificates keep working. Nothing is written.
        warn(f"warning: could not list IKEv2 clients, skipping reconcile:\n{listing}")
        return {"skipped": "listclients failed", "error": listing}

    # `valid` is what a client can actually connect with; `reserved` is a name
    # the IPsec database still holds for a certificate that cannot. Both are
    # updated as this function acts, so what is written down at the end is what
    # the container was observed to hold plus what we just did to it.
    valid, reserved = ikev2ctl.parse_clients(listing)
    added: list[str] = []
    withdrawn: list[str] = []
    revoke_failed: list[str] = []
    add_failed: list[str] = []

    # Every queued intent, plus every working certificate nobody wants any more.
    # An already-revoked certificate that nobody wants is deliberately left
    # alone: there is nothing to withdraw, and --revokeclient on it fails, which
    # would plant a permanent failure in every apply from then on.
    for name in sorted(set(st.revoke_pending) | (valid - wanted)):
        if name in valid:
            rok, output = ikev2ctl.remove_client(name)
        elif name in reserved:
            # Already revoked; what is left is the reservation, and that is the
            # thing --addclient trips over if the name ever comes back.
            rok, output = ikev2ctl.delete_client(name)
        else:
            warn(
                f"note: dropping the pending IKEv2 revocation for {name!r} -- the "
                "container holds no certificate by that name (a lost volume, or a "
                "restore from a backup older than the certificate). There is "
                "nothing left to revoke."
            )
            continue
        if not rok:
            revoke_failed.append(name)
            warn(f"warning: could not revoke IKEv2 client {name!r}: {output}")
            continue
        withdrawn.append(name)
        valid.discard(name)
        reserved.discard(name)

    for name in sorted(wanted - valid):
        if name in reserved:
            # Revoked, so the certificate is dead but the name is still taken:
            # --addclient answers "already exists" until it is deleted. The same
            # ordering remove_client documents, one step of it.
            dok, output = ikev2ctl.delete_client(name)
            if not dok:
                add_failed.append(name)
                warn(
                    f"warning: could not free the reserved IKEv2 name {name!r}, "
                    f"so no certificate could be issued: {output}"
                )
                continue
            reserved.discard(name)
        aok, output = ikev2ctl.add_client(name)
        if not aok:
            add_failed.append(name)
            warn(f"warning: could not issue IKEv2 client {name!r}: {output}")
            continue
        added.append(name)
        valid.add(name)

    st.revoke_pending = [n for n in st.revoke_pending if n in revoke_failed]
    state.save(st)

    for user in users:
        user.ikev2_provisioned = user.name in valid
    users_store.save(users)

    return {
        "added": added,
        "revoked": withdrawn,
        "failed": sorted(set(revoke_failed) | set(add_failed)),
    }


# -------------------------------------------------------------------- commands


def cmd_bootstrap(args) -> None:
    guard.require_server("bootstrap")
    ok, message = bootstrap.bootstrap_keyring(force=args.force)
    say(message)
    if ok and users_store.load():
        say("existing users found -- re-rendering them into the new keyring")
        apply(restart=False, quiet=True)
        say("credentials are NEW: re-export every profile for every user.")
        say(
            "nothing was restarted, so run `vpnctl apply` BEFORE exporting anything: "
            "until it converges, the containers still serve the old keys and every "
            "freshly exported profile fails to connect."
        )
    # Both remaining outcomes are success. "Nothing to generate" is what a
    # complete keyring looks like, and a gap HEALED from surviving material
    # (reality.pub from reality.key) changes nothing a client holds. The third
    # outcome -- a half-present set left alone -- raises KeyringRefused and is
    # turned into exit 1 by main(), which is the point: it needs the missing file
    # restored from a backup or the whole set regenerated, and it used to be a
    # sentence inside this message, so the one outcome demanding a decision was
    # the one that reported ok=true.
    emit(ok=True, message=message)


# The converge steps whose verdict a human is entitled to see in the last line.
_VERDICTS = ("teardown_ok", "ports_ready", "firewall_ok", "forwarding_ok")


def _say_verdict(result: dict, done: str) -> None:
    """Say what happened, and refuse to say "OK." over a step that failed.

    Everything after `up` warns and falls through on purpose -- the boot unit
    needs exit 0 -- so the exit code cannot carry this, and the booleans in the
    payload are for callers. Printing "OK." underneath a warning that a port
    never bound is the human half of the same lie.
    """
    trouble = [key for key in _VERDICTS if result.get(key) is False]
    # None is "docker could not tell", and that is not a clean bill of health
    # either -- reading it as one is how `protocol off` once reported success
    # while the protocol kept serving traffic.
    stopped = result.get("not_running", [])
    if stopped is None or stopped:
        trouble.append("not_running")
    if not trouble:
        say(f"{done} OK.")
        return
    say(
        f"{done} NOT OK: {', '.join(trouble)}. Read the warnings above -- this "
        "server may not be serving. Nothing here exits non-zero because the boot "
        "unit depends on that; the payload carries each failure in full."
    )


def cmd_apply(args) -> None:
    result = apply(restart=not args.no_restart)
    _say_verdict(result, "Applied.")
    emit(ok=True, **result)


def cmd_protocol_list(args) -> None:
    st = state.load()
    rows = []
    for proto in protocols.ordered():
        on = proto.name in st.enabled
        rows.append(
            {
                "name": proto.name,
                "enabled": on,
                "ports": [str(p) for p in proto.ports],
                "kind": proto.kind.value,
                "summary": proto.summary,
                "notes": proto.notes,
            }
        )
        say(
            f"{proto.name:<15} {'on ' if on else 'off'}  "
            f"{' '.join(str(p) for p in proto.ports):<28} {proto.summary}"
        )
        if proto.notes and not on:
            say(f"{'':<20}({proto.notes})")
    emit(ok=True, protocols=rows)


def _prepare_secrets(proto: protocols.Protocol, st: state.State) -> None:
    """Fill in secrets that only this protocol knows how to make.

    Runs at `protocol on` rather than at bootstrap because the one case that
    needs it -- dnstt's Noise keypair -- costs a Go image build. If it fails,
    the enable is rolled back: leaving the protocol on with no key would make
    every subsequent `apply`, including the one systemd runs at boot, die on a
    missing secret with no hint about how it got that way.
    """
    if not bootstrap.missing_secrets([proto]) or proto.prepare is None:
        return
    say(f"  generating {proto.name} keys (first time -- this builds an image)")
    try:
        produced = proto.prepare()
    except Exception as exc:  # noqa: BLE001 - any failure must roll the toggle back
        st.enabled = [n for n in st.enabled if n != proto.name]
        state.save(st)
        die(f"could not prepare {proto.name}, left it disabled:\n{exc}")
    for name, content in produced.items():
        secrets_store.write(name, content)
    say(f"  wrote {', '.join(sorted(produced))}")


def _set_protocol(name: str, on: bool) -> None:
    guard.require_server("protocol on/off")
    proto = protocols.get(name)
    st = state.load()
    if on and proto.name in st.enabled:
        say(f"{proto.name} is already on.")
        emit(ok=True, changed=False)
        return
    if not on and proto.name not in st.enabled:
        say(f"{proto.name} is already off.")
        emit(ok=True, changed=False)
        return

    # Before state.json is written and before _prepare_secrets pays for an
    # ~800 MB image build. `protocol on dnstt` with no zone used to save the
    # toggle first: the operator then had dnstt enabled, a tunnel answering for
    # an empty zone, and nothing naming the variable that was missing. Same
    # footing as _prepare_secrets' rollback, one step earlier -- nothing
    # written is nothing to roll back.
    if on:
        gap = render.missing_deployment_config(proto)
        if gap:
            die(gap)

    st.enabled = (
        sorted(set(st.enabled) | {proto.name})
        if on
        else [n for n in st.enabled if n != proto.name]
    )
    state.save(st)
    say(f"{'enabled' if on else 'disabled'} {proto.name}")
    if not on:
        say(
            "  secrets are kept, so turning it back on restores every existing profile."
        )

    if on:
        _prepare_secrets(proto, st)

    result = apply()
    _say_verdict(result, "Applied.")
    emit(ok=True, changed=True, **result)


def cmd_protocol_on(args) -> None:
    _set_protocol(args.name, True)


def cmd_protocol_off(args) -> None:
    _set_protocol(args.name, False)


def cmd_user_add(args) -> None:
    guard.require_server("user add")
    error = users_store.validate_name(args.name)
    if error:
        die(error)
    users = users_store.load()
    if users_store.find(users, args.name):
        die(f"User {args.name!r} already exists.")
    user = users_store.new_user(args.name)
    users.append(user)
    users_store.save(users)
    result = apply()
    _say_verdict(result, f"Added user {args.name!r}.")
    emit(ok=True, user=args.name, **result)


def cmd_user_rm(args) -> None:
    guard.require_server("user rm")
    users = users_store.load()
    user = users_store.find(users, args.name)
    if not user:
        die(f"No such user: {args.name!r}")
    # The revocation intent has to outlive the record, or a removal performed
    # while ikev2 is down leaves a working certificate and nothing to retry it.
    if user.ikev2_provisioned:
        st = state.load()
        if user.name not in st.revoke_pending:
            st.revoke_pending.append(user.name)
            state.save(st)
    users_store.save([u for u in users if u.name.lower() != args.name.lower()])
    result = apply()
    _say_verdict(result, f"Removed user {args.name!r}.")
    emit(ok=True, user=args.name, **result)


def _set_enabled(args, enabled: bool) -> None:
    guard.require_server("user enable/disable")
    users = users_store.load()
    user = users_store.find(users, args.name)
    if not user:
        die(f"No such user: {args.name!r}")
    if not enabled and user.ikev2_provisioned:
        st = state.load()
        if user.name not in st.revoke_pending:
            st.revoke_pending.append(user.name)
            state.save(st)
    user.enabled = enabled
    users_store.save(users)
    if enabled:
        say(
            f"note: re-enabling issues a NEW IKEv2 certificate for {args.name!r} -- "
            "any previously imported IKEv2 profile stops working and needs re-exporting."
        )
    result = apply()
    _say_verdict(result, f"{'Enabled' if enabled else 'Disabled'} user {args.name!r}.")
    emit(ok=True, user=args.name, enabled=enabled, **result)


def cmd_user_enable(args) -> None:
    _set_enabled(args, True)


def cmd_user_disable(args) -> None:
    _set_enabled(args, False)


def cmd_user_list(args) -> None:
    users = users_store.load()
    rows = []
    for u in users:
        row = {
            "name": u.name,
            "enabled": u.enabled,
            "ikev2_provisioned": u.ikev2_provisioned,
            "created_at": u.created_at,
        }
        line = (
            f"{u.name:20s} {'enabled' if u.enabled else 'disabled':9s} "
            f"ikev2={'yes' if u.ikev2_provisioned else 'no':3s} created={u.created_at}"
        )
        if args.show_secrets:
            row |= {
                "vless_uuid": u.vless_uuid,
                "hysteria2_password": u.hysteria2_password,
                "l2tp_password": u.l2tp_password,
            }
            line += (
                f" uuid={u.vless_uuid} hysteria2_password={u.hysteria2_password}"
                f" l2tp_password={u.l2tp_password}"
            )
        rows.append(row)
        say(line)
    if not users:
        say("No users.")
    emit(ok=True, users=rows)


def cmd_user_export(args) -> None:
    users = users_store.load()
    user = users_store.find(users, args.name)
    if not user:
        die(f"No such user: {args.name!r}")

    st = state.load()
    names = st.enabled if args.protocol == "all" else [args.protocol]
    try:
        host = export.resolve_host(args.host)
    except ExportError as e:
        die(str(e))

    # The keyring plus the deployment config share() is a pure function of.
    # Built once, at the edge: reading it inside a protocol module is what made
    # share() unusable to any caller that is not this process.
    keyring = render.snapshot()
    payload: dict[str, list[dict]] = {}
    failures: list[str] = []
    notes: list[str] = []
    for name in names:
        proto = protocols.get(name)
        if proto.share_via_container:
            if not user.ikev2_provisioned:
                warn(
                    f"[{name}] no certificate provisioned for {user.name!r}; skipping."
                )
                notes.append(f"{name}: no certificate provisioned")
                continue
            ok, message, bundles = ikev2ctl.export_client(user.name)
            say(f"\n[{name}]\n{message}")
            if not ok:
                # Silently reporting ok:true with no files is how a share link
                # ends up missing the one profile the recipient asked for.
                warn(f"[{name}] export failed: {message}")
                failures.append(name)
                notes.append(f"{name}: export failed")
                continue
            payload[name] = [
                {"filename": fn, "label": ikev2ctl.bundle_label(fn), "b64": _b64(blob)}
                for fn, blob in bundles.items()
            ]
            continue

        items = proto.share(keyring, user, host)
        payload[name] = []
        for item in items:
            say(f"\n[{name}] {item.label}")
            if item.uri:
                say(item.uri)
                if args.qr and not _JSON:
                    export.print_ascii_qr(item.uri)
                payload[name].append(
                    {
                        "label": item.label,
                        "uri": item.uri,
                        "png_b64": _b64(export.png_bytes(item.uri)),
                    }
                )
            elif item.fields:
                # Settings for a form. No QR: there is nothing to scan them
                # with, and a QR of a settings blob is a QR that fails
                # silently in somebody's hands.
                width = max(len(k) for k, _ in item.fields)
                for key, value in item.fields:
                    say(f"  {key:<{width}}  {value}")
                payload[name].append(
                    {"label": item.label, "fields": [list(f) for f in item.fields]}
                )
            elif item.filename:
                # The same {filename, label, b64} the ikev2 branch above emits,
                # because to the app both are one ShareFile. The branch was
                # missing: the loop printed `uri`, then `fields`, and dropped
                # anything else without a word -- so the first protocol whose
                # pure share() returns a file would have reported ok with the one
                # deliverable the recipient needed simply absent from the
                # payload. ShareItem.__post_init__ guarantees the content.
                say(f"  {item.filename} ({len(item.content or b'')} bytes)")
                payload[name].append(
                    {
                        "filename": item.filename,
                        "label": item.label,
                        "b64": _b64(item.content or b""),
                    }
                )
            else:
                # Unreachable from the registry -- ShareItem.__post_init__ admits
                # exactly one shape and refuses a file with no content. It raises
                # here anyway because reaching it SILENTLY is the failure the
                # branch above exists to fix, and a fourth shape would arrive the
                # same way the third did.
                raise protocols.RenderError(
                    f"[{name}] share item {item.label!r} is in no shape this "
                    "command knows how to emit"
                )

    if not any(payload.values()):
        # ok:true with an empty payload is the same lie the ikev2 branch already
        # refuses to tell: this command exists to hand somebody a credential, and
        # a receipt with no credential in it exits 0 and reads as "done". Every
        # reason is collected above rather than inferred here, because "no
        # certificate provisioned" and "the export failed" need different fixes.
        detail = "; ".join(notes) if notes else "no protocol is enabled"
        die(f"nothing to export for {user.name!r}: {detail}")

    emit(ok=not failures, user=user.name, host=host, protocols=payload, failed=failures)


def _b64(blob: bytes) -> str:
    import base64

    return base64.b64encode(blob).decode()


def cmd_ikev2_list(args) -> None:
    if not ikev2ctl.is_running():
        die("ikev2 container isn't running.")
    ok, output = ikev2ctl.list_clients()
    if not ok:
        # ok:false with exit 0 was the shape here, and the listing IS the whole
        # answer: a caller that trusts the exit code reads a failed query as an
        # empty client list, which is precisely the misreading reconcile_ikev2
        # aborts rather than make.
        die(f"could not list IKEv2 clients:\n{output}")
    say(output)
    emit(ok=True, output=output)


def cmd_ikev2_reconcile(args) -> None:
    guard.require_server("ikev2 reconcile")
    result = reconcile_ikev2()
    say(json.dumps(result, indent=2))
    # A name in `failed` is one of two things, and both are the operator's
    # problem right now: a revocation that did not run, so somebody's
    # certificate still grants access, or a certificate that was not issued, so
    # somebody has no profile. Exiting 0 on that is the same lie `list-clients`
    # told. A `skipped` reconcile is deliberately NOT a failure -- it could not
    # observe the truth and so refused to guess, which is the documented
    # contract the app reads.
    if result.get("failed"):
        die(
            "IKEv2 reconciliation is incomplete for: "
            + ", ".join(result["failed"])
            + ". A failed revocation means that certificate still works; it "
            "stays in revoke_pending and is retried on the next apply.",
            **result,
        )
    emit(ok=True, **result)


def cmd_status(args) -> None:
    st, defaulted = state.load_or_default()
    _warn_if_defaulted(defaulted)
    users = users_store.load()
    info = {
        "state_dir": str(STATE_DIR),
        "is_server": guard.is_server(),
        "rendered": RENDERED_LINK.resolve().name if RENDERED_LINK.exists() else None,
        "enabled": st.enabled,
        "revoke_pending": st.revoke_pending,
        "users": len(users),
        "users_enabled": sum(1 for u in users if u.enabled),
        "ikev2_running": ikev2ctl.is_running(),
    }
    for key, value in info.items():
        say(f"{key:18} {value}")
    emit(ok=True, **info)


# --------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    # --json is accepted in ANY position: `vpnctl --json user list` and
    # `vpnctl user list --json` both work. A caller building a command line
    # programmatically should not have to know where argparse wants the flag.
    # SUPPRESS is what makes this work -- without it the subparser's own
    # default would overwrite a value already set at the top level.
    # `mutates` is declared per subcommand rather than matched against a list of
    # names in main(): the list and the parser are edited at different times, and
    # a new mutating subcommand that nobody remembered to add to the list takes
    # no lock while looking exactly like one that does.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="emit a machine-readable result",
    )

    p = argparse.ArgumentParser(
        prog="vpnctl", description="VPN server agent", parents=[common]
    )
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser(
        "status", help="what this server is currently running", parents=[common]
    )
    c.set_defaults(func=cmd_status)

    c = sub.add_parser(
        "bootstrap", help="generate any missing secrets", parents=[common]
    )
    c.add_argument(
        "--force",
        action="store_true",
        help="regenerate EVERY key -- invalidates every exported profile, no undo",
    )
    c.set_defaults(func=cmd_bootstrap, mutates=True)

    c = sub.add_parser(
        "apply", help="render, validate and converge the server", parents=[common]
    )
    c.add_argument("--no-restart", action="store_true", help="render and validate only")
    c.set_defaults(func=cmd_apply, mutates=True)

    pr = sub.add_parser("protocol", help="turn protocols on and off", parents=[common])
    pr_sub = pr.add_subparsers(dest="protocol_command", required=True)
    c = pr_sub.add_parser("list", parents=[common])
    c.set_defaults(func=cmd_protocol_list)
    c = pr_sub.add_parser("on", parents=[common])
    c.add_argument("name")
    c.set_defaults(func=cmd_protocol_on, mutates=True)
    c = pr_sub.add_parser("off", parents=[common])
    c.add_argument("name")
    c.set_defaults(func=cmd_protocol_off, mutates=True)

    u = sub.add_parser("user", help="manage users", parents=[common])
    u_sub = u.add_subparsers(dest="user_command", required=True)
    for name, fn, helptext in (
        ("add", cmd_user_add, "add a user with fresh credentials for every protocol"),
        ("rm", cmd_user_rm, "permanently delete a user"),
        ("enable", cmd_user_enable, "re-enable (re-issues the IKEv2 certificate)"),
        ("disable", cmd_user_disable, "disable without deleting"),
    ):
        c = u_sub.add_parser(name, help=helptext, parents=[common])
        c.add_argument("name")
        c.set_defaults(func=fn, mutates=True)
    c = u_sub.add_parser("list", parents=[common])
    c.add_argument("--show-secrets", action="store_true")
    c.set_defaults(func=cmd_user_list)
    c = u_sub.add_parser(
        "export", help="share links and client bundles", parents=[common]
    )
    c.add_argument("name")
    c.add_argument("--protocol", default="all")
    c.add_argument("--host")
    c.add_argument("--qr", action="store_true", help="print an ASCII QR code")
    c.set_defaults(func=cmd_user_export)

    ik = sub.add_parser("ikev2", help="IKEv2 certificate operations", parents=[common])
    ik_sub = ik.add_subparsers(dest="ikev2_command", required=True)
    c = ik_sub.add_parser("list-clients", parents=[common])
    c.set_defaults(func=cmd_ikev2_list)
    c = ik_sub.add_parser(
        "reconcile", help="make certificates match the enabled users", parents=[common]
    )
    c.set_defaults(func=cmd_ikev2_reconcile, mutates=True)

    return p


def main() -> None:
    global _JSON, _LOCK_FD
    args = build_parser().parse_args()
    _JSON = getattr(args, "json", False)
    _LOCK_FD = _lock_if_mutating(args)
    try:
        args.func(args)
    except protocols.RenderError as e:
        die(str(e))
    except secrets_store.MissingSecret as e:
        die(str(e))
    except users_store.UsersError as e:
        # The database being unreadable is an operator problem with a stated
        # remedy, not a bug. A traceback here buries the one sentence that
        # says what to do.
        die(str(e))
    except bootstrap.KeyringRefused as e:
        # A half-present secret set. Here rather than in cmd_bootstrap because
        # `apply` reaches bootstrap_keyring too, through the install path, and a
        # refusal there deserves the same one sentence and the same exit code.
        die(str(e))
    except state.StateError as e:
        # Beside users_store for the same reason, and with a wider blast radius:
        # every command reads state.json, `status` included, so an unhandled
        # decode error here is not one broken command but a server with no
        # working command surface, answering a traceback that names neither the
        # file nor the remedy.
        die(str(e))


if __name__ == "__main__":
    main()
