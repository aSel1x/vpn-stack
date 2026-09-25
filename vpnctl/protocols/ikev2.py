"""IKEv2 + L2TP/IPsec + Cisco IPsec, via hwdsl2/ipsec-vpn-server.

Two auth mechanisms in one container, and they behave differently:

  L2TP / Cisco IPsec  declarative -- rendered into the env file from users.json,
                      exactly like a sing-box inbound.
  IKEv2               imperative -- per-client certificates issued by ikev2.sh
                      inside the container. Its share bundles therefore cannot
                      be a pure function of the keyring (share_via_container).

Recreating this container drops every active session it serves -- L2TP, Cisco
IPsec and IKEv2 alike. Certificates survive, in the ikev2-vpn-data volume.
"""

from __future__ import annotations

import secrets as pysecrets

from vpnctl.paths import USERS_JSON
from vpnctl.protocols import Kind, Port, Protocol, RenderError, ShareItem
from vpnctl.secrets_store import Secrets
from vpnctl.users_store import User, unrenderable_name

NAME = "ikev2"


def render(secrets: Secrets, users: list[User]) -> dict[str, bytes]:
    # Every real user goes through the additional-users lists, including the
    # first: the image's primary VPN_USER slot stays random junk nobody uses,
    # so add/remove behaves uniformly regardless of who happens to be first.
    enabled = [u for u in users if u.enabled]

    # users.json is validated at `user add`, and render() is handed whatever the
    # file actually holds -- a hand edit, a restore from an older backup, or a
    # stale checkout rsynced over a newer database. The two lists below are one
    # space-separated string each, zipped back together by position inside the
    # container, so a single name containing whitespace makes them different
    # lengths and hands every user after it somebody else's password, on a config
    # that renders, validates and serves. Refusing here is the last moment at
    # which nothing has been promoted and nobody has been given the wrong
    # credential; the same check at `user add` cannot see a record it did not
    # create.
    #
    # `unrenderable_name` and NOT the whole shared validator, which is what this
    # called at first. The other half of that validator refuses names colliding
    # with an account inside the dnstt sshd container -- a fact about one
    # protocol's image, not about whether this file can be written. ikev2 is
    # enabled by default and dnstt is not, so enforcing it here meant a user
    # legally created before that list existed made EVERY apply fail, the
    # systemd boot unit included, on a box where dnstt was switched off. That is
    # precisely the trap dnstt.render's own comment describes: a refusal in
    # render that the operator cannot get out from under.
    for user in enabled:
        error = unrenderable_name(user.name)
        if error:
            raise RenderError(
                f"{USERS_JSON} names a user this cannot render. {error} "
                "Remove and re-add that user: `user rm` writes users.json before "
                "it applies, so the command that fixes this is not blocked by it."
            )

    # The password half of the pairing is space-separated too, and a password is
    # not validated anywhere: `user add` generates token_hex, but a hand-edited
    # record or an import can carry anything. One space in a password misaligns
    # the lists exactly as a space in a name does. The message names the user and
    # never the value -- a RenderError is printed, and this one is a live
    # credential.
    for user in enabled:
        if len(user.l2tp_password.split()) != 1:
            raise RenderError(
                f"{USERS_JSON}: the L2TP password for {user.name!r} contains "
                "whitespace (or is empty). VPN_ADDL_USERS and VPN_ADDL_PASSWORDS "
                "are two space-separated lists paired by position, so this would "
                "hand every later user somebody else's password. Re-add the user."
            )

    # Both of these end up in the container's environment, which means every
    # user's L2TP/Cisco password and the shared PSK are readable with a single
    # `docker inspect ipsec-vpn-server` by anything that can reach the docker socket. There
    # is no way around it -- the hwdsl2 image is configured by environment and
    # nothing else -- so "nothing else on this host gets the docker socket" is a
    # written invariant of this deployment rather than an accident of it: no
    # container mounts /var/run/docker.sock, and adding one that does hands it
    # every IPsec credential on the box.
    lines = [
        f"VPN_IPSEC_PSK={secrets.text('ipsec.psk')}",
        f"VPN_USER={secrets.text('ipsec.primary_user')}",
        f"VPN_PASSWORD={secrets.text('ipsec.primary_password')}",
        "VPN_ADDL_USERS=" + " ".join(u.name for u in enabled),
        "VPN_ADDL_PASSWORDS=" + " ".join(u.l2tp_password for u in enabled),
    ]
    return {"ikev2.env": ("\n".join(lines) + "\n").encode()}


def share(secrets: Secrets, user: User, host: str) -> list[ShareItem]:
    # Placeholder: the real bundles are copied out of the container by
    # ikev2ctl.export_client. See share_via_container.
    return []


def bootstrap() -> dict[str, bytes]:
    return {
        "ipsec.psk": pysecrets.token_hex(16).encode(),
        "ipsec.primary_user": pysecrets.token_hex(8).encode(),
        "ipsec.primary_password": pysecrets.token_hex(16).encode(),
    }


PROTOCOL = Protocol(
    name=NAME,
    kind=Kind.COMPOSE,
    order=30,
    ports=(Port(500, "udp"), Port(4500, "udp"), Port(1701, "udp")),
    summary="IKEv2 / L2TP / Cisco IPsec",
    secret_names=("ipsec.psk", "ipsec.primary_user", "ipsec.primary_password"),
    default_enabled=True,
    render=render,
    share=share,
    bootstrap=bootstrap,
    compose_profile="ikev2",
    compose_services=("ikev2",),
    share_via_container=True,
    notes=(
        "Diagnosed 2026-09-05: the server side is correct end to end and no "
        "client IKE has ever reached it. The drop is on the client's network. "
        "See scripts/diagnose-ikev2.sh."
    ),
)
