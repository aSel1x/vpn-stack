"""DNS tunnel (dnstt) -- last resort for networks that allow only DNS.

One shared tunnel, but a login per person. The Noise key belongs to the
server and encrypts the transport before anyone authenticates, so it cannot be
personal; the sshd behind it can, and is. That is what makes `user rm` and
`user disable` actually cut dnstt access -- with one shared account, removing
somebody left their tunnel working and nothing to revoke.

Ships disabled: it needs a delegated DNS zone, which a fresh server does not
have, and binding udp/53 on a box that hasn't got one is pure attack surface.
"""

from __future__ import annotations

import sys

from vpnctl.paths import ENV_FILE, USERS_JSON
from vpnctl.protocols import Kind, Port, Protocol, RenderError, ShareItem
from vpnctl.secrets_store import Secrets
from vpnctl.users_store import User, reserved_name, unrenderable_name

NAME = "dnstt"

# The delegated zone is deployment config and never a constant in git: it used
# to be the author's own, hardcoded here and repeated verbatim in compose.yml,
# so a stranger who cloned this repo and ran `protocol on dnstt` served the
# *author's* zone and their clients resolved a domain somebody else controls.
#
# One operator-facing source of truth -- VPN_DNSTT_ZONE in .env, which compose
# interpolates into the container's `command:`. Python reaches it the way
# export.py reaches VPN_SERVER_HOST: the impure caller reads it and passes it
# in. Here the caller is render.snapshot(), which folds it into the Secrets
# snapshot under ZONE_KEY, so render() and share() stay pure functions of their
# arguments and a GUI holding a snapshot builds share links with no server
# round-trip. Held in a module global read at import instead, share() raised
# for exactly the caller the purity rule exists for.
#
# The trade-off, stated: Secrets stops being only the keyring and becomes "the
# immutable input the pure layer is given", and a caller that skips the edge
# gets no zone. The alternative -- a fourth `settings` argument -- changes the
# signature of all four protocols and every call site for a value only this one
# has ever wanted.
ZONE_VAR = "VPN_DNSTT_ZONE"
ZONE_KEY = "dnstt.zone"
NO_ZONE = (
    f"dnstt has no zone. Set {ZONE_VAR}=<your delegated zone> in {ENV_FILE} "
    "-- compose.yml reads the same variable -- and delegate that zone NS to "
    "this host. See dnstt/SETUP.md."
)
IMAGE = "dnstt-server:latest"
SOCKS_ADDR = "127.0.0.1:7300"
# What the SSH front may forward to. The clients use SSH *dynamic* forwarding,
# so the destination is a different address for every site and no fixed list
# can ever match. Proven twice from the server's own log: first 17 refusals of
# the DoT resolver, then, once that was allowed, refusals of twenty-odd web
# hosts on :443 -- Apple, Google, Fastly, IPv6 among them.
#
# Less of a loss than it looks. The other three protocols on this server
# already hand unrestricted network access to anyone holding their
# credentials; restricting the last-resort protocol alone would buy nothing
# and would leave the people in the most locked-down networks with the least
# useful of the four. What this reaches on the host's loopback is either
# already public (sshd on 22, open in ufw) or loopback-by-design (microsocks).
#
# The narrowing that would actually help is a smaller blast radius on the
# credential, not a shorter list: the password is random, the sshd binds
# loopback only, and the sole route to it is a tunnel that already requires
# the pinned Noise key.
PERMIT_OPEN = ("any",)
# The decoded stream goes to an sshd running in its own container, not to the
# host's. iOS clients speak DNSTT -> SSH and need a login; keeping that login
# out of the host means no real account, no edit to the host's sshd_config, and
# nothing to recreate by hand after a rebuild.
EXIT = "127.0.0.1:2222"


def _zone(secrets: Secrets) -> str:
    """The zone as the snapshot carries it. Absent and empty are the same thing."""
    return secrets.text(ZONE_KEY) if secrets.has(ZONE_KEY) else ""


def render(secrets: Secrets, users: list[User]) -> dict[str, bytes]:
    # Nothing rendered here carries the zone -- compose's `command:` does -- so
    # a missing one is said out loud, not raised. Raising bricked the server:
    # `protocol on dnstt` before the zone was set wrote dnstt into state.json
    # and then apply, `user add`, `deploy` and the systemd boot unit all exited
    # 1, with users.json already written and diverging from the served config.
    # A warning does not brick a boot. The hard refusal belongs at `protocol
    # on`, which is the last point that can still roll the toggle back.
    if not _zone(secrets):
        print(
            f"warning: dnstt is enabled with no zone -- set {ZONE_VAR} in {ENV_FILE} "
            "(compose.yml reads the same variable) and delegate that zone NS to "
            "this host, or the tunnel answers for a zone nobody can reach",
            file=sys.stderr,
        )

    # One login per enabled user, so `user rm` and `user disable` actually cut
    # dnstt access. They did not before: everyone shared one account, so
    # removing somebody left their tunnel working with nothing to revoke.
    #
    # A user predating the field has no password and gets no login. Not
    # invented here: `render` is pure and must not mint a credential, and
    # `apply` handing out a password nobody has been told is worse than a gap.
    # Said out loud rather than skipped quietly -- there is no migration
    # command, so this warning is the whole story.
    missing = [u.name for u in users if u.enabled and not u.dnstt_password]
    if missing:
        print(
            f"warning: no dnstt login for {', '.join(missing)} "
            "(created before dnstt became per-user); set dnstt_password in "
            "users.json, or re-add the user",
            file=sys.stderr,
        )
    issued = [u for u in users if u.enabled and u.dnstt_password]

    # The file's own format is `name:password`, one per line, read by
    # dnstt-sshd/entrypoint.sh with `while IFS=: read -r name password` and fed
    # straight to adduser and chpasswd. A name carrying a colon or a newline
    # therefore does not fail -- it silently becomes a *different* account, or
    # two, with the password cut at the colon. The shared validator in
    # users_store already excludes both (and every shell metacharacter with
    # them), so this is the same one check ikev2.render makes, for a different
    # file format and the same reason: `user add` validates what it creates, and
    # render() is handed whatever a hand edit, an old backup or a rolled-back
    # tree left in the file.
    for user in issued:
        # Both halves here, unlike ikev2: this protocol's own container is the
        # one that cannot serve a reserved name -- it refuses to start on one
        # rather than crash-loop -- so refusing at render is what turns a
        # crash-loop into a sentence. Only reached when dnstt is enabled.
        error = unrenderable_name(user.name) or reserved_name(user.name)
        if error:
            raise RenderError(
                f"{USERS_JSON} names a user this cannot render into the dnstt "
                f"login list. {error} Remove and re-add that user: `user rm` "
                "writes users.json before it applies, so the command that fixes "
                "this is not blocked by it."
            )
        # A newline in the password is the same corruption from the other side:
        # it ends the record and turns the rest into a login line of its own.
        # Named without its value, because the value is a live credential and
        # this message is printed.
        if "\n" in user.dnstt_password or "\r" in user.dnstt_password:
            raise RenderError(
                f"{USERS_JSON}: the dnstt password for {user.name!r} contains a "
                "newline, which would split one login line into two. Re-add the "
                "user."
            )

    logins = "".join(f"{u.name}:{u.dnstt_password}\n" for u in issued)
    # An empty list is not a degraded dnstt, it is a crash-loop nothing reports.
    # entrypoint.sh exits 1 on a list with no logins -- deliberately, because an
    # sshd with zero accounts looks healthy and answers nobody -- and compose
    # restarts that container forever. Neither composectl's readiness wait nor
    # scripts/smoke.sh can see it: that sshd binds loopback only, so there is no
    # non-loopback port to watch, and dnstt itself keeps answering udp/53 into a
    # tunnel whose far end refuses every login. So the refusal belongs here,
    # before the candidate tree is promoted, where it costs the operator one
    # sentence instead of an evening.
    #
    # Unlike the missing zone this is safe to raise on: every route out of it
    # writes users.json before it applies -- `user add`, `user enable`, setting
    # dnstt_password by hand -- and `protocol off dnstt` does not render dnstt at
    # all. Refusing here cannot lock the operator out of the fix.
    if not logins:
        raise RenderError(
            "dnstt is enabled but no enabled user has a dnstt login, so the "
            "rendered login list would be empty -- dnstt-sshd exits 1 on that and "
            "compose restarts it forever, unseen, because it binds loopback only. "
            f"Add or enable a user, set dnstt_password in {USERS_JSON} for one who "
            "predates the field, or turn dnstt off."
        )
    env = (
        f"SSH_PORT={EXIT.rsplit(':', 1)[1]}\n"
        f"SOCKS_EXIT={SOCKS_ADDR}\n"
        f"PERMIT_OPEN={' '.join(PERMIT_OPEN)}\n"
    )
    return {
        "dnstt/server.key": secrets.raw("dnstt.server.key"),
        "dnstt-sshd/logins": logins.encode(),
        "dnstt.env": env.encode(),
    }


def share(secrets: Secrets, user: User, host: str) -> list[ShareItem]:
    """Settings for a form, not a link.

    DNSTT-over-SSH has no import format -- no URI scheme, nothing to scan.
    The apps have a form and that is the entire interface, so these are
    emitted as fields. They used to be crammed into a `uri`, which made every
    layer treat them as one: a QR code nothing can read, a tappable link on
    the share page that imports nothing.
    """
    # Still a hard failure, unlike render(): the zone IS the connection
    # parameter here, and a settings card naming a zone nobody delegated is an
    # hour of somebody's debugging handed out as if it worked.
    zone = _zone(secrets)
    if not zone:
        raise RenderError(NO_ZONE)
    pub = (
        secrets.text("dnstt.server.pub")
        if secrets.has("dnstt.server.pub")
        else "<not generated>"
    )
    # Zone and pubkey are the transport and identical for everyone. The login
    # is this person's own, which is what makes revoking one of them possible.
    password = user.dnstt_password or "<none issued -- see dnstt/SETUP.md>"
    return [
        ShareItem(
            label="dnstt — phone (HTTP Injector / AnyBridge, mode DNSTT → SSH)",
            filename=None,
            uri=None,
            fields=(
                ("Nameserver / domain", zone),
                ("Public key", pub),
                ("DNS resolver", "the blocked network's OWN resolver, :53, plain UDP"),
                ("SSH username", user.name),
                ("SSH password", password),
            ),
        ),
        ShareItem(
            label="dnstt — laptop (two commands)",
            filename=None,
            uri=None,
            fields=(
                (
                    "1. open the tunnel",
                    f"dnstt-client -udp <resolver>:53 -pubkey {pub} {zone} 127.0.0.1:7000",
                ),
                (
                    "2. SOCKS through it",
                    f"ssh -N -D 1080 -p 7000 {user.name}@127.0.0.1",
                ),
                ("then", "point the browser at socks5://127.0.0.1:1080"),
            ),
        ),
    ]


def bootstrap() -> dict[str, bytes]:
    # Nothing server-wide to make. The SSH logins are per person and live in
    # users.json; the Noise keypair is the dnstt-server binary's own format
    # and needs the image built, so that is prepare()'s job.
    return {}


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
        capture_output=True,
        text=True,
        timeout=900,
    )
    if build.returncode != 0:
        raise RenderError(
            "could not build the dnstt image:\n"
            + (build.stdout + build.stderr).strip()[-2000:]
        )

    gen = subprocess.run(
        ["docker", "run", "--rm", IMAGE, "-gen-key"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if gen.returncode != 0:
        raise RenderError(
            "dnstt-server -gen-key failed:\n"
            + (gen.stdout + gen.stderr).strip()[-2000:]
        )

    found = dict(re.findall(r"^(privkey|pubkey)\s+([0-9a-f]{64})$", gen.stdout, re.M))
    if {"privkey", "pubkey"} - found.keys():
        raise RenderError(
            f"could not parse -gen-key output:\n{gen.stdout.strip()[:500]}"
        )

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
    secret_names=("dnstt.server.key",),
    default_enabled=False,
    render=render,
    share=share,
    bootstrap=bootstrap,
    prepare=prepare,
    compose_profile="dnstt",
    compose_services=("dnstt", "dnstt-sshd", "dnstt-socks"),
    per_user=True,
    notes=(
        # Names the variable, not the value: this string is built at import
        # and `protocol list` is most often read on a box where the zone is
        # not set yet, where the value is the one thing that says nothing.
        f"Needs a delegated zone ({ZONE_VAR} in {ENV_FILE}) pointing NS at "
        "this host, and ufw allow 53/udp. See dnstt/SETUP.md."
    ),
)
