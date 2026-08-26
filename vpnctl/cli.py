import argparse
import sys

from vpnctl import export, ikev2ctl, render, sbctl, users_store
from vpnctl.export import ExportError
from vpnctl.paths import HYSTERIA2_CONFIG, USERS_JSON, VLESS_CONFIG

FRAGMENT_FILES = [VLESS_CONFIG, HYSTERIA2_CONFIG]


def _snapshot() -> dict:
    return {p: (p.read_bytes() if p.exists() else None) for p in FRAGMENT_FILES}


def _restore(snapshot: dict) -> None:
    for path, content in snapshot.items():
        if content is not None:
            path.write_bytes(content)


def validate_and_apply(*, restart: bool = True) -> None:
    """Render config from users.json, validate with sing-box, then apply.

    Rolls back the rendered fragment files (not users.json) on validation
    failure, so a running server is never disrupted by a bad edit.
    """
    snapshot = _snapshot()
    render.render_all()

    ok, output = sbctl.check_config()
    if not ok:
        _restore(snapshot)
        print("sing-box check failed, changes rolled back:", file=sys.stderr)
        print(output, file=sys.stderr)
        sys.exit(1)

    if restart:
        ok, output = sbctl.apply()
        if not ok:
            print("docker compose up failed:", file=sys.stderr)
            print(output, file=sys.stderr)
            sys.exit(1)

        if ikev2ctl.is_running():
            ok, output = ikev2ctl.apply_env()
            if not ok:
                print("warning: ikev2/.env updated but recreating the ikev2 "
                      "container failed:", file=sys.stderr)
                print(output, file=sys.stderr)
        else:
            print("note: ikev2/.env updated, but the ikev2 container isn't "
                  "running -- L2TP/Cisco changes will apply once you start it "
                  "(`docker compose up -d ikev2`).")
    print("OK.")


def _sync_ikev2_client(user: users_store.User, *, provisioned: bool) -> None:
    """Best-effort add/remove of a user's IKEv2 client certificate.

    Never aborts the calling command -- vless/hysteria2/l2tp already applied
    by the time this runs, so an IKEv2-side failure is surfaced as a warning,
    not a hard error.
    """
    if not ikev2ctl.is_running():
        print("note: ikev2 container isn't running, skipping IKEv2 cert "
              f"{'provisioning' if provisioned else 'revocation'} for {user.name!r}.")
        return

    action = ikev2ctl.add_client if provisioned else ikev2ctl.remove_client
    ok, output = action(user.name)
    if not ok:
        print(f"warning: IKEv2 {'add' if provisioned else 'remove'}client "
              f"failed for {user.name!r}:", file=sys.stderr)
        print(output, file=sys.stderr)
        return

    users = users_store.load()
    current = users_store.find(users, user.name)
    if current is not None:
        current.ikev2_provisioned = provisioned
        users_store.save(users)


def cmd_migrate(args: argparse.Namespace) -> None:
    import json

    if USERS_JSON.exists():
        print(f"{USERS_JSON} already exists, refusing to overwrite.", file=sys.stderr)
        sys.exit(1)

    vless = json.loads(VLESS_CONFIG.read_text())["inbounds"][0]["users"][0]
    hy2 = json.loads(HYSTERIA2_CONFIG.read_text())["inbounds"][0]["users"][0]
    if vless["name"] != hy2["name"]:
        print(
            f"User name mismatch between VLESS ({vless['name']!r}) and "
            f"Hysteria2 ({hy2['name']!r}) configs — fix manually before migrating.",
            file=sys.stderr,
        )
        sys.exit(1)

    from datetime import datetime, timezone

    _, _, l2tp_password = users_store.generate_credentials()
    user = users_store.User(
        name=vless["name"],
        vless_uuid=vless["uuid"],
        hysteria2_password=hy2["password"],
        l2tp_password=l2tp_password,
        ikev2_provisioned=False,
        enabled=True,
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    users_store.save([user])
    print(f"Migrated existing user {user.name!r} into {USERS_JSON}.")
    validate_and_apply(restart=False)


def cmd_render(args: argparse.Namespace) -> None:
    validate_and_apply(restart=not args.no_restart)


def cmd_user_add(args: argparse.Namespace) -> None:
    users = users_store.load()
    if users_store.find(users, args.name):
        print(f"User {args.name!r} already exists.", file=sys.stderr)
        sys.exit(1)
    new_user = users_store.new_user(args.name)
    users.append(new_user)
    users_store.save(users)
    validate_and_apply()
    _sync_ikev2_client(new_user, provisioned=True)
    print(f"Added user {args.name!r}.")


def cmd_user_rm(args: argparse.Namespace) -> None:
    users = users_store.load()
    user = users_store.find(users, args.name)
    if not user:
        print(f"No such user: {args.name!r}", file=sys.stderr)
        sys.exit(1)
    users = [u for u in users if u.name.lower() != args.name.lower()]
    users_store.save(users)
    validate_and_apply()
    _sync_ikev2_client(user, provisioned=False)
    print(f"Removed user {args.name!r}.")


def _set_enabled(args: argparse.Namespace, enabled: bool) -> None:
    users = users_store.load()
    user = users_store.find(users, args.name)
    if not user:
        print(f"No such user: {args.name!r}", file=sys.stderr)
        sys.exit(1)
    user.enabled = enabled
    users_store.save(users)
    validate_and_apply()
    if enabled:
        print("note: re-enabling issues a *new* IKEv2 client certificate "
              f"for {args.name!r} -- any previously imported IKEv2 profile "
              "for this user will stop working and needs re-exporting.")
    _sync_ikev2_client(user, provisioned=enabled)
    print(f"{'Enabled' if enabled else 'Disabled'} user {args.name!r}.")


def cmd_user_enable(args: argparse.Namespace) -> None:
    _set_enabled(args, True)


def cmd_user_disable(args: argparse.Namespace) -> None:
    _set_enabled(args, False)


def cmd_user_list(args: argparse.Namespace) -> None:
    users = users_store.load()
    if not users:
        print("No users.")
        return
    for u in users:
        status = "enabled" if u.enabled else "disabled"
        ikev2 = "yes" if u.ikev2_provisioned else "no"
        line = f"{u.name:20s} {status:9s} ikev2={ikev2:3s} created={u.created_at}"
        if args.show_secrets:
            line += (
                f" uuid={u.vless_uuid} hysteria2_password={u.hysteria2_password}"
                f" l2tp_password={u.l2tp_password}"
            )
        print(line)


def cmd_user_export(args: argparse.Namespace) -> None:
    users = users_store.load()
    user = users_store.find(users, args.name)
    if not user:
        print(f"No such user: {args.name!r}", file=sys.stderr)
        sys.exit(1)

    protocols = ["vless", "hysteria2"] if args.protocol == "both" else [args.protocol]

    host = None
    if any(p in ("vless", "hysteria2") for p in protocols):
        try:
            host = export.resolve_host(args.host)
        except ExportError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    for protocol in protocols:
        if protocol == "ikev2":
            if not user.ikev2_provisioned:
                print(f"\n[ikev2] no IKEv2 client provisioned for {user.name!r} yet "
                      "(needs the ikev2 container running at the time of "
                      "`user add`/`user enable`).", file=sys.stderr)
                continue
            ok, message, _ = ikev2ctl.export_client(user.name)
            print(f"\n[ikev2]")
            print(message)
            if not ok:
                sys.exit(1)
            continue

        uri = (
            export.build_vless_uri(user, host)
            if protocol == "vless"
            else export.build_hysteria2_uri(user, host)
        )
        print(f"\n[{protocol}]")
        print(uri)
        if args.qr:
            export.print_ascii_qr(uri)
        if args.png:
            path = export.save_qr_png(uri, user.name, protocol)
            print(f"Saved QR to {path}")


def cmd_ikev2_list_clients(args: argparse.Namespace) -> None:
    if not ikev2ctl.is_running():
        print("ikev2 container isn't running.", file=sys.stderr)
        sys.exit(1)
    ok, output = ikev2ctl.list_clients()
    print(output)
    if not ok:
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vpnctl", description="sing-box VPN user automator")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("migrate", help="bootstrap users.json from the existing hand-written config (one-time)")
    p.set_defaults(func=cmd_migrate)

    p = sub.add_parser("render", help="regenerate config from users.json, validate, and restart")
    p.add_argument("--no-restart", action="store_true", help="validate and write config but don't restart the container")
    p.set_defaults(func=cmd_render)

    user = sub.add_parser("user", help="manage users")
    user_sub = user.add_subparsers(dest="user_command", required=True)

    p = user_sub.add_parser("add", help="add a new user with freshly generated credentials")
    p.add_argument("name")
    p.set_defaults(func=cmd_user_add)

    p = user_sub.add_parser("rm", help="permanently delete a user (credentials gone for good)")
    p.add_argument("name")
    p.set_defaults(func=cmd_user_rm)

    p = user_sub.add_parser("enable", help="re-enable a disabled user (credentials preserved)")
    p.add_argument("name")
    p.set_defaults(func=cmd_user_enable)

    p = user_sub.add_parser("disable", help="temporarily disable a user without deleting it")
    p.add_argument("name")
    p.set_defaults(func=cmd_user_disable)

    p = user_sub.add_parser("list", help="list users")
    p.add_argument("--show-secrets", action="store_true")
    p.set_defaults(func=cmd_user_list)

    p = user_sub.add_parser("export", help="print share link(s) and optionally render a QR code")
    p.add_argument("name")
    p.add_argument("--protocol", choices=["vless", "hysteria2", "ikev2", "both"], default="both")
    p.add_argument("--host", help="server hostname/IP (defaults to VPN_SERVER_HOST in .env)")
    p.add_argument("--qr", action="store_true", help="print an ASCII QR code to the terminal")
    p.add_argument("--png", action="store_true", help="also save a QR code PNG under exports/")
    p.set_defaults(func=cmd_user_export)

    ikev2 = sub.add_parser("ikev2", help="IKEv2 diagnostics")
    ikev2_sub = ikev2.add_subparsers(dest="ikev2_command", required=True)
    p = ikev2_sub.add_parser("list-clients", help="raw `ikev2.sh --listclients` output")
    p.set_defaults(func=cmd_ikev2_list_clients)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
