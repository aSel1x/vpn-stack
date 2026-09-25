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
    # The public half is stored, so this seam never touches the private key.
    # It used to be derived, which meant the pure seam CLAUDE.md advertises --
    # a client app building its own share links, no server round-trip -- could
    # only be handed the private X25519 key, and whoever holds that can stand
    # up a server this one's clients cannot tell apart.
    #
    # The fallback is the compatibility path, and only that: a keyring
    # bootstrapped before reality.pub existed has the private half and nothing
    # else. Deliberately not in secret_names -- requiring it would make every
    # such server fail to render instead of quietly carrying on.
    pbk = (
        secrets.text("reality.pub")
        if secrets.has("reality.pub")
        else derive_public_key(secrets.text("reality.key"))
    )
    uri = (
        f"vless://{user.vless_uuid}@{host}:{PORT}"
        f"?encryption=none&flow=xtls-rprx-vision&security=reality"
        f"&sni={MASQUERADE}&fp=chrome&pbk={pbk}"
        f"&sid={secrets.text('reality.short_id')}&type=tcp&headerType=none"
        f"#{quote(user.name)}"
    )
    return [ShareItem(label="VLESS + REALITY", filename=None, uri=uri)]


def bootstrap() -> dict[str, bytes]:
    # One keypair, both halves written together. Derived here rather than in
    # share() so the two cannot disagree: they come out of the same call.
    private = generate_private_key()
    return {
        "reality.key": private.encode(),
        # Not a secret -- every client carries it in its share link -- and it
        # sits in the keyring beside its private half exactly like
        # dnstt.server.pub, so the two cannot drift apart.
        "reality.pub": derive_public_key(private).encode(),
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
    # An X25519 public key is a deterministic function of its private half, so
    # a keyring that has reality.key and no reality.pub is repairable rather
    # than damaged. That matters because `share()` prefers the stored public
    # half precisely so it never has to read the private one, and before this
    # existed no command could add the file to a server bootstrapped earlier:
    # the only route was `--force`, which re-mints the whole set and
    # invalidates every profile ever issued.
    derivable={
        "reality.pub": lambda have: derive_public_key(have.text("reality.key")).encode()
    },
)
