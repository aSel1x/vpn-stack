"""DNS tunnel (dnstt) -- last resort for networks that allow only DNS.

Not per-user: a single fixed tunnel whose exit is the host's own sshd, with a
loopback-only SOCKS5 (dnstt-socks) as the internet exit. Access control is a
dedicated non-root host account, not anything vpnctl renders.

Ships disabled: it needs a delegated DNS zone, which a fresh server does not
have, and binding udp/53 on a box that hasn't got one is pure attack surface.
"""

from __future__ import annotations

from vpnctl.protocols import Kind, Port, Protocol, RenderError, ShareItem
from vpnctl.secrets_store import Secrets
from vpnctl.users_store import User

NAME = "dnstt"
ZONE = "tun.example.net"
IMAGE = "dnstt-server:latest"
SOCKS_ADDR = "127.0.0.1:7300"
# The decoded stream is handed to the host's sshd; clients run SSH over the
# tunnel and ride its forwarding. There is no bespoke proxy protocol.
EXIT = "127.0.0.1:22"


def render(secrets: Secrets, users: list[User]) -> dict[str, bytes]:
    return {"dnstt/server.key": secrets.raw("dnstt.server.key")}


def share(secrets: Secrets, user: User, host: str) -> list[ShareItem]:
    # Same parameters for everyone -- what varies is the client's resolver,
    # which only the client can discover.
    pub = secrets.text("dnstt.server.pub").strip() if secrets.has("dnstt.server.pub") else "<not generated yet>"
    return [
        ShareItem(
            label="dnstt (DNS tunnel)",
            filename=None,
            uri=(
                f"dnstt-client -udp <your-resolver>:53 -pubkey {pub} "
                f"{ZONE} 127.0.0.1:<local-port>"
            ),
        )
    ]


def bootstrap() -> dict[str, bytes]:
    # Nothing here on purpose. The Noise keypair is the dnstt-server binary's
    # own format, so producing it means building the image -- see prepare().
    return {}


def prepare() -> dict[str, bytes]:
    """Build the image and have dnstt-server emit its own keypair.

    Deliberately not part of `bootstrap`: a fresh server would spend a Go
    toolchain build and ~800 MB of disk on a protocol that ships disabled and
    additionally needs a delegated DNS zone before it can serve anything.
    """
    import subprocess
    import tempfile
    from pathlib import Path

    from vpnctl.paths import ROOT

    build = subprocess.run(
        ["docker", "build", "-t", IMAGE, str(ROOT / "dnstt")],
        capture_output=True, text=True,
    )
    if build.returncode != 0:
        raise RenderError(
            "could not build the dnstt image:\n" + (build.stdout + build.stderr).strip()[-2000:]
        )

    with tempfile.TemporaryDirectory() as tmp:
        gen = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{tmp}:/out", IMAGE,
             "-gen-key", "-privkey-file", "/out/server.key",
             "-pubkey-file", "/out/server.pub"],
            capture_output=True, text=True,
        )
        if gen.returncode != 0:
            raise RenderError(
                "dnstt-server -gen-key failed:\n" + (gen.stdout + gen.stderr).strip()[-2000:]
            )
        key = Path(tmp, "server.key")
        pub = Path(tmp, "server.pub")
        if not key.is_file() or not pub.is_file():
            raise RenderError("dnstt-server -gen-key wrote no key files")
        return {
            "dnstt.server.key": key.read_bytes(),
            # The public key is not a secret -- it goes to every client -- but
            # it lives with its private half so the two cannot drift apart.
            "dnstt.server.pub": pub.read_bytes(),
        }


PROTOCOL = Protocol(
    name=NAME,
    kind=Kind.COMPOSE,
    order=40,
    ports=(Port(53, "udp"),),
    summary="DNS tunnel (dnstt -> sshd -> SOCKS5)",
    secret_names=("dnstt.server.key",),
    default_enabled=False,
    render=render,
    share=share,
    bootstrap=bootstrap,
    prepare=prepare,
    compose_profile="dnstt",
    compose_services=("dnstt", "dnstt-socks"),
    per_user=False,
    notes=(
        f"Needs a delegated zone ({ZONE}) pointing NS at this host, and "
        "ufw allow 53/udp. See dnstt/SETUP.md."
    ),
)
