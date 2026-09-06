"""Turn a user into things you can hand to a device.

All protocol knowledge lives in the registry; this module only decides how to
present it. Nothing is written to the server: credentials are printed or
streamed back to the caller, so no directory of live client bundles
accumulates on the box (the old exports/ did, indefinitely).
"""

from __future__ import annotations

import qrcode

from vpnctl import protocols, secrets_store
from vpnctl.dotenv import read as read_env
from vpnctl.paths import ENV_FILE
from vpnctl.protocols import ShareItem
from vpnctl.users_store import User


class ExportError(Exception):
    pass


def resolve_host(explicit_host: str | None) -> str:
    if explicit_host:
        return explicit_host
    host = read_env(ENV_FILE).get("VPN_SERVER_HOST")
    if not host:
        raise ExportError(
            "No server host known. Pass --host <ip-or-domain>, or set "
            f"VPN_SERVER_HOST=... in {ENV_FILE}."
        )
    return host


def items_for(user: User, host: str, names: list[str]) -> dict[str, list[ShareItem]]:
    """Registry-driven: {protocol name: share items}. Pure apart from the keyring read."""
    secrets = secrets_store.load()
    out: dict[str, list[ShareItem]] = {}
    for proto in protocols.ordered(names):
        if not proto.per_user:
            continue
        out[proto.name] = proto.share(secrets, user, host)
    return out


def print_ascii_qr(uri: str) -> None:
    qr = qrcode.QRCode(border=1)
    qr.add_data(uri)
    qr.make(fit=True)
    qr.print_ascii(invert=True)


def png_bytes(uri: str) -> bytes:
    """PNG for a share URI, as bytes -- the caller decides where it lands."""
    import io

    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format="PNG")
    return buf.getvalue()
