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
# Delegated at the registrar: tun.example.net NS ns-tun.example.net, and
# ns-tun.example.net A <this server>. compose.yml repeats these two literals
# because a compose `command:` cannot read them from anywhere; this module is
# the canonical copy.
ZONE = "tun.example.net"
IMAGE = "dnstt-server:latest"
SOCKS_ADDR = "127.0.0.1:7300"
# The decoded stream goes to an sshd running in its own container, not to the
# host's. iOS clients speak DNSTT -> SSH and need a login; keeping that login
# out of the host means no real account, no edit to the host's sshd_config, and
# nothing to recreate by hand after a rebuild.
EXIT = "127.0.0.1:2222"
SSH_USER = "dnstt"


def render(secrets: Secrets, users: list[User]) -> dict[str, bytes]:
    password = secrets.text("dnstt.ssh_password")
    env = (
        f"SSH_USER={SSH_USER}\n"
        f"SSH_PASSWORD={password}\n"
        f"SSH_PORT={EXIT.rsplit(':', 1)[1]}\n"
        f"SOCKS_EXIT={SOCKS_ADDR}\n"
    )
    return {
        "dnstt/server.key": secrets.raw("dnstt.server.key"),
        "dnstt.env": env.encode(),
    }


def share(secrets: Secrets, user: User, host: str) -> list[ShareItem]:
    # Identical for everyone. What varies is the resolver, and only the client
    # can discover that: it is the blocked network's own DNS server, which on
    # a phone means reading it with a network-info app. See dnstt/SETUP.md.
    pub = secrets.text("dnstt.server.pub") if secrets.has("dnstt.server.pub") else "<not generated>"
    password = secrets.text("dnstt.ssh_password") if secrets.has("dnstt.ssh_password") else "<not generated>"
    return [
        ShareItem(
            label="dnstt — mobile app (DNSTT → SSH)",
            filename=None,
            uri=(
                f"zone={ZONE} pubkey={pub} "
                f"ssh-user={SSH_USER} ssh-password={password} "
                "resolver=<the blocked network's own DNS, plain UDP :53>"
            ),
        ),
        ShareItem(
            label="dnstt — laptop (dnstt-client, then SSH through it)",
            filename=None,
            uri=(
                f"dnstt-client -udp <resolver>:53 -pubkey {pub} {ZONE} 127.0.0.1:7000 "
                f"&& ssh -N -D 1080 -p 7000 {SSH_USER}@127.0.0.1"
            ),
        ),
    ]


def bootstrap() -> dict[str, bytes]:
    # The SSH front's password is ordinary randomness, so it is made here.
    # The Noise keypair is the dnstt-server binary's own format and needs the
    # image built, which is too much to spend on a protocol that ships off --
    # that one lives in prepare().
    import secrets as _secrets

    return {"dnstt.ssh_password": (_secrets.token_urlsafe(18) + "\n").encode()}


def prepare() -> dict[str, bytes]:
    """Build the image and have dnstt-server emit its own Noise keypair.

    Deliberately not part of `bootstrap`: a fresh server would spend a Go
    toolchain build and ~800 MB of disk on a protocol that ships disabled and
    additionally needs a delegated DNS zone before it can serve anything.

    `-gen-key` prints both halves as hex on stdout, which is what is parsed
    here. The alternative -- `-privkey-file` into a bind-mounted directory --
    writes them as root, so nothing but root can read them back, and the
    temporary directory then fails to clean up. Found by doing it that way.
    """
    import re
    import subprocess

    from vpnctl.paths import ROOT

    build = subprocess.run(
        ["docker", "build", "-t", IMAGE, str(ROOT / "dnstt")],
        capture_output=True, text=True, timeout=900,
    )
    if build.returncode != 0:
        raise RenderError(
            "could not build the dnstt image:\n" + (build.stdout + build.stderr).strip()[-2000:]
        )

    gen = subprocess.run(
        ["docker", "run", "--rm", IMAGE, "-gen-key"],
        capture_output=True, text=True, timeout=120,
    )
    if gen.returncode != 0:
        raise RenderError(
            "dnstt-server -gen-key failed:\n" + (gen.stdout + gen.stderr).strip()[-2000:]
        )

    found = dict(re.findall(r"^(privkey|pubkey)\s+([0-9a-f]{64})$", gen.stdout, re.M))
    if {"privkey", "pubkey"} - found.keys():
        raise RenderError(f"could not parse -gen-key output:\n{gen.stdout.strip()[:500]}")

    return {
        # dnstt reads -privkey-file as hex text, which is what it printed.
        "dnstt.server.key": (found["privkey"] + "\n").encode(),
        # Not a secret -- every client pins it -- but it lives beside its
        # private half so the two cannot drift apart.
        "dnstt.server.pub": (found["pubkey"] + "\n").encode(),
    }


PROTOCOL = Protocol(
    name=NAME,
    kind=Kind.COMPOSE,
    order=40,
    ports=(Port(53, "udp"),),
    summary="DNS tunnel (dnstt -> containerised sshd -> SOCKS5)",
    secret_names=("dnstt.server.key", "dnstt.ssh_password"),
    default_enabled=False,
    render=render,
    share=share,
    bootstrap=bootstrap,
    prepare=prepare,
    compose_profile="dnstt",
    compose_services=("dnstt", "dnstt-sshd", "dnstt-socks"),
    per_user=False,
    notes=(
        f"Needs a delegated zone ({ZONE}) pointing NS at this host, and "
        "ufw allow 53/udp. See dnstt/SETUP.md."
    ),
)
