"""Turn a user into things you can hand to a device.

All protocol knowledge lives in the registry; this module only decides how to
present it. Nothing is written to the server: credentials are printed or
streamed back to the caller, so no directory of live client bundles
accumulates on the box (the old exports/ did, indefinitely).

Two things a caller building share items has to get right, both learned the
hard way, and written here because this is the file anyone exporting opens:

  * Never filter the protocol list on `per_user`. A protocol whose credential
    is not per-person still has connection parameters the person needs, and
    that filter made `user export` return nothing at all for dnstt back when
    dnstt was one shared login. dnstt is per_user=True now; the filter stays
    gone, because the next protocol of that shape would hit the same wall.
  * Hand share() a `render.snapshot()`, not a `secrets_store.load()`. The
    snapshot is the impure edge where deployment config the pure layer needs --
    dnstt's zone, which lives in .env and not in the keyring -- is folded in.
    Reading the keyring alone handed share() a snapshot with no zone, so dnstt
    refused to build a link on a server where the zone had been set all along.
"""

from __future__ import annotations

import qrcode

from vpnctl.dotenv import read as read_env
from vpnctl.paths import ENV_FILE


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
