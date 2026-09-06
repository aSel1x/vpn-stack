"""Refuse to mutate live state from a machine that isn't the server.

The audit's single biggest finding was that `vpnctl user add` on a laptop does
not fail -- it succeeds, rewriting a local copy of the same live credentials
and starting a real sing-box bound to the laptop's ports. Documentation cannot
fix that; a precondition can.
"""

import sys

from vpnctl.paths import STATE_DIR


class NotTheServer(RuntimeError):
    pass


def is_server() -> bool:
    return STATE_DIR.is_dir()


def require_server(action: str = "this command") -> None:
    """Exit non-zero unless the state directory is really here."""
    if is_server():
        return
    print(
        f"Refusing to run {action}: this does not look like the VPN server.\n"
        f"  {STATE_DIR} does not exist.\n"
        "\n"
        "Mutating commands act on live containers, the host firewall and the\n"
        "real user database. Run them on the server (`./vpn ...` forwards over\n"
        "SSH), or set VPN_STATE_DIR=<dir> to point at a test state directory.",
        file=sys.stderr,
    )
    raise SystemExit(2)
