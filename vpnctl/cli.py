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
import json
import os
import shutil
import sys

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


def die(message: str, **data) -> None:
    if _JSON:
        print(json.dumps({"schema": SCHEMA, "ok": False, "error": message, **data}, indent=2))
    else:
        warn(message)
    raise SystemExit(1)


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

    enabled = state.enabled_protocols()
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

    ok, output = sbctl.check_config(candidate / "sing-box")
    if not ok:
        shutil.rmtree(candidate, ignore_errors=True)
        die(f"sing-box rejected the new config; nothing changed.\n{output}")

    render.promote(candidate)
    result = {
        "rendered": candidate.name,
        "enabled_protocols": [p.name for p in enabled],
        "restarted": restart,
    }
    if not quiet:
        say(f"rendered {candidate.name}: {', '.join(p.name for p in enabled) or 'nothing'}")

    if not restart:
        say("note: NOT applied (--no-restart). Containers still run the previous config.")
        return result

    ok, output = composectl.up(enabled)
    if not ok:
        die(f"docker compose up failed:\n{output}")
    ok, output = composectl.down_disabled(enabled)
    if not ok:
        warn(f"warning: could not tear down disabled services:\n{output}")
    result["teardown"] = output

    ready, notes = composectl.wait_ready(enabled)
    result["ready"] = notes
    if not ready:
        warn("warning: some ports never came up:\n  " + "\n  ".join(notes))
    elif not quiet:
        say(f"  {notes[0]}")

    ok, actions = firewall.reconcile(enabled)
    result["firewall"] = actions
    if not ok:
        warn("warning: firewall reconciliation failed:\n  " + "\n  ".join(actions))
    elif not quiet:
        for line in actions:
            say(f"  ufw: {line}")

    if any(p.name == "ikev2" for p in enabled) and ikev2ctl.is_running():
        fw_ok, fw_out = ikev2ctl.ensure_ipv4_forwarding()
        result["ikev2_forwarding"] = fw_out
        if not fw_ok:
            warn(f"warning: IKEv2 FORWARD rules not applied: {fw_out}")
        result["ikev2_reconcile"] = reconcile_ikev2()

    st = state.load()
    st.last_applied = [p.name for p in enabled]
    state.save(st)
    render.prune()
    return result


def reconcile_ikev2() -> dict:
    """Make the container's certificate set match the enabled users.

    Repairs both directions from observed truth rather than remembered intent,
    and drains revoke_pending -- revocations that could not run when they were
    asked for, because the container was down. Without that queue, a `user rm`
    with ikev2 stopped leaves a certificate that still grants access and no
    record that it should not.
    """
    if not ikev2ctl.is_running():
        return {"skipped": "ikev2 container not running"}

    users = users_store.load()
    st = state.load()
    wanted = {u.name for u in users if u.enabled}

    ok, listing = ikev2ctl.list_clients()
    if not ok:
        # Proceeding would read an empty client list as "nothing is issued":
        # it would try to re-add every user, fail on "already exists", and then
        # rewrite ikev2_provisioned to False for everyone -- turning a
        # transient docker error into a database that says nobody has a
        # certificate while the certificates keep working.
        warn(f"warning: could not list IKEv2 clients, skipping reconcile:\n{listing}")
        return {"skipped": "listclients failed", "error": listing}

    present = set()
    if ok:
        for line in listing.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] in ("valid", "revoked") and parts[0] != "Client":
                present.add(parts[0])

    added, removed, failed = [], [], []

    for name in sorted(set(st.revoke_pending) | (present - wanted)):
        if name in wanted:
            continue
        rok, out = ikev2ctl.remove_client(name)
        (removed if rok else failed).append(name)
        if not rok:
            warn(f"warning: could not revoke IKEv2 client {name!r}: {out}")

    for name in sorted(wanted - present):
        aok, out = ikev2ctl.add_client(name)
        (added if aok else failed).append(name)
        if not aok:
            warn(f"warning: could not issue IKEv2 client {name!r}: {out}")

    st.revoke_pending = [n for n in st.revoke_pending if n in failed]
    state.save(st)

    users = users_store.load()
    for user in users:
        user.ikev2_provisioned = user.name in ((present | set(added)) - set(removed))
    users_store.save(users)

    return {"added": added, "revoked": removed, "failed": failed}


# -------------------------------------------------------------------- commands


def cmd_bootstrap(args) -> None:
    guard.require_server("bootstrap")
    ok, message = bootstrap.bootstrap_keyring(force=args.force)
    say(message)
    if ok and users_store.load():
        say("existing users found -- re-rendering them into the new keyring")
        apply(restart=False, quiet=True)
        say("credentials are NEW: re-export every profile for every user.")
    emit(ok=True, message=message)


def cmd_apply(args) -> None:
    result = apply(restart=not args.no_restart)
    say("OK.")
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

    st.enabled = (
        sorted(set(st.enabled) | {proto.name})
        if on
        else [n for n in st.enabled if n != proto.name]
    )
    state.save(st)
    say(f"{'enabled' if on else 'disabled'} {proto.name}")
    if not on:
        say("  secrets are kept, so turning it back on restores every existing profile.")

    if on:
        _prepare_secrets(proto, st)

    result = apply()
    say("OK.")
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
    say(f"Added user {args.name!r}.")
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
    say(f"Removed user {args.name!r}.")
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
    say(f"{'Enabled' if enabled else 'Disabled'} user {args.name!r}.")
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

    payload: dict[str, list[dict]] = {}
    failures: list[str] = []
    for name in names:
        proto = protocols.get(name)
        if proto.share_via_container:
            if not user.ikev2_provisioned:
                warn(f"[{name}] no certificate provisioned for {user.name!r}; skipping.")
                continue
            ok, message, bundles = ikev2ctl.export_client(user.name)
            say(f"\n[{name}]\n{message}")
            if not ok:
                # Silently reporting ok:true with no files is how a share link
                # ends up missing the one profile the recipient asked for.
                warn(f"[{name}] export failed: {message}")
                failures.append(name)
                continue
            payload[name] = [
                {"filename": fn, "label": ikev2ctl.bundle_label(fn), "b64": _b64(blob)}
                for fn, blob in bundles.items()
            ]
            continue

        items = proto.share(secrets_store.load(), user, host)
        payload[name] = []
        for item in items:
            say(f"\n[{name}] {item.label}")
            if item.uri:
                say(item.uri)
                if args.qr and not _JSON:
                    export.print_ascii_qr(item.uri)
                payload[name].append(
                    {"label": item.label, "uri": item.uri, "png_b64": _b64(export.png_bytes(item.uri))}
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
    emit(ok=not failures, user=user.name, host=host,
         protocols=payload, failed=failures)


def _b64(blob: bytes) -> str:
    import base64

    return base64.b64encode(blob).decode()


def cmd_ikev2_list(args) -> None:
    if not ikev2ctl.is_running():
        die("ikev2 container isn't running.")
    ok, output = ikev2ctl.list_clients()
    say(output)
    emit(ok=ok, output=output)


def cmd_ikev2_reconcile(args) -> None:
    guard.require_server("ikev2 reconcile")
    result = reconcile_ikev2()
    say(json.dumps(result, indent=2))
    emit(ok=True, **result)


def cmd_status(args) -> None:
    st = state.load()
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

    c = sub.add_parser("status", help="what this server is currently running", parents=[common])
    c.set_defaults(func=cmd_status)

    c = sub.add_parser("bootstrap", help="generate any missing secrets", parents=[common])
    c.add_argument(
        "--force",
        action="store_true",
        help="regenerate EVERY key -- invalidates every exported profile, no undo",
    )
    c.set_defaults(func=cmd_bootstrap)

    c = sub.add_parser("apply", help="render, validate and converge the server", parents=[common])
    c.add_argument("--no-restart", action="store_true", help="render and validate only")
    c.set_defaults(func=cmd_apply)


    pr = sub.add_parser("protocol", help="turn protocols on and off", parents=[common])
    pr_sub = pr.add_subparsers(dest="protocol_command", required=True)
    c = pr_sub.add_parser("list", parents=[common])
    c.set_defaults(func=cmd_protocol_list)
    c = pr_sub.add_parser("on", parents=[common])
    c.add_argument("name")
    c.set_defaults(func=cmd_protocol_on)
    c = pr_sub.add_parser("off", parents=[common])
    c.add_argument("name")
    c.set_defaults(func=cmd_protocol_off)

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
        c.set_defaults(func=fn)
    c = u_sub.add_parser("list", parents=[common])
    c.add_argument("--show-secrets", action="store_true")
    c.set_defaults(func=cmd_user_list)
    c = u_sub.add_parser("export", help="share links and client bundles", parents=[common])
    c.add_argument("name")
    c.add_argument("--protocol", default="all")
    c.add_argument("--host")
    c.add_argument("--qr", action="store_true", help="print an ASCII QR code")
    c.set_defaults(func=cmd_user_export)

    ik = sub.add_parser("ikev2", help="IKEv2 certificate operations", parents=[common])
    ik_sub = ik.add_subparsers(dest="ikev2_command", required=True)
    c = ik_sub.add_parser("list-clients", parents=[common])
    c.set_defaults(func=cmd_ikev2_list)
    c = ik_sub.add_parser("reconcile", help="make certificates match the enabled users", parents=[common])
    c.set_defaults(func=cmd_ikev2_reconcile)

    return p


def main() -> None:
    global _JSON
    args = build_parser().parse_args()
    _JSON = getattr(args, "json", False)
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


if __name__ == "__main__":
    main()
