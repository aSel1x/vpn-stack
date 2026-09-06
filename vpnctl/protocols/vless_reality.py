"""VLESS + REALITY over TCP with XTLS-Vision.

Structural constants live here, in git. Before the registry the only record of
them was bootstrap.py, which by its own design cannot affect a running server.
"""

from __future__ import annotations

import json
import secrets as pysecrets
from urllib.parse import quote

from vpnctl.protocols import Kind, Port, Protocol, ShareItem
from vpnctl.reality_key import derive_public_key, generate_private_key
from vpnctl.secrets_store import Secrets
from vpnctl.users_store import User

NAME = "vless-reality"
PORT = 10443
# REALITY masquerades as a real, always-up TLS site; the handshake is proxied
# to it, so this must be a host that tolerates being fronted.
MASQUERADE = "www.apple.com"
TAG = "vless-in"


def render(secrets: Secrets, users: list[User]) -> dict[str, bytes]:
    inbound = {
        "type": "vless",
        "tag": TAG,
        "listen": "::",
        "listen_port": PORT,
        "users": [
            {"name": u.name, "uuid": u.vless_uuid, "flow": "xtls-rprx-vision"}
            for u in users
            if u.enabled
        ],
        "tls": {
            "enabled": True,
            "server_name": MASQUERADE,
            "reality": {
                "enabled": True,
                "handshake": {"server": MASQUERADE, "server_port": 443},
                "private_key": secrets.text("reality.key"),
                "short_id": [secrets.text("reality.short_id")],
            },
        },
    }
    body = json.dumps({"inbounds": [inbound]}, indent=2) + "\n"
    return {"sing-box/10_vless-reality.json": body.encode()}


def share(secrets: Secrets, user: User, host: str) -> list[ShareItem]:
    # The public key is derived, never stored: the private key stays the single
    # source of truth and no rotation is needed for share links to keep working.
    pbk = derive_public_key(secrets.text("reality.key"))
    uri = (
        f"vless://{user.vless_uuid}@{host}:{PORT}"
        f"?encryption=none&flow=xtls-rprx-vision&security=reality"
        f"&sni={MASQUERADE}&fp=chrome&pbk={pbk}"
        f"&sid={secrets.text('reality.short_id')}&type=tcp&headerType=none"
        f"#{quote(user.name)}"
    )
    return [ShareItem(label="VLESS + REALITY", filename=None, uri=uri)]


def bootstrap() -> dict[str, bytes]:
    return {
        "reality.key": generate_private_key().encode(),
        "reality.short_id": pysecrets.token_hex(8).encode(),
    }


PROTOCOL = Protocol(
    name=NAME,
    kind=Kind.SINGBOX,
    order=10,
    ports=(Port(PORT, "tcp"),),
    summary="VLESS+REALITY (TCP, XTLS-Vision)",
    secret_names=("reality.key", "reality.short_id"),
    default_enabled=True,
    render=render,
    share=share,
    bootstrap=bootstrap,
)
