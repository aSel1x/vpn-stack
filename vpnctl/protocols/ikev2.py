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

from vpnctl.protocols import Kind, Port, Protocol, ShareItem
from vpnctl.secrets_store import Secrets
from vpnctl.users_store import User

NAME = "ikev2"


def render(secrets: Secrets, users: list[User]) -> dict[str, bytes]:
    # Every real user goes through the additional-users lists, including the
    # first: the image's primary VPN_USER slot stays random junk nobody uses,
    # so add/remove behaves uniformly regardless of who happens to be first.
    enabled = [u for u in users if u.enabled]
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
