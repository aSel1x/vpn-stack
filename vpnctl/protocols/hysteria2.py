"""Hysteria2 over QUIC with Salamander obfuscation.

Emits its own certificate into the rendered tree. The certs sit in a
subdirectory of the sing-box config dir on purpose: `-C` merges `*.json` from
a directory and does not recurse, so a `certs/` subdirectory is invisible to
the config loader while still being inside the one mount.
"""

from __future__ import annotations

import datetime
import json
import secrets as pysecrets
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID

from vpnctl.protocols import Kind, Port, Protocol, ShareItem
from vpnctl.secrets_store import Secrets
from vpnctl.users_store import User

NAME = "hysteria2"
PORT = 20443
MASQUERADE = "bing.com"
TAG = "hysteria2-in"
UP_MBPS = 100
DOWN_MBPS = 100

# Path as the container sees it: the rendered sing-box dir is mounted at
# /etc/sing-box, and certs/ rides along inside it.
_CERT_IN_CONTAINER = "/etc/sing-box/certs/certificate.pem"
_KEY_IN_CONTAINER = "/etc/sing-box/certs/private.key"


def render(secrets: Secrets, users: list[User]) -> dict[str, bytes]:
    inbound = {
        "type": "hysteria2",
        "tag": TAG,
        "listen": "::",
        "listen_port": PORT,
        "up_mbps": UP_MBPS,
        "down_mbps": DOWN_MBPS,
        "ignore_client_bandwidth": False,
        "obfs": {"type": "salamander", "password": secrets.text("hysteria2.obfs")},
        "users": [
            {"name": u.name, "password": u.hysteria2_password}
            for u in users
            if u.enabled
        ],
        "tls": {
            "enabled": True,
            "server_name": MASQUERADE,
            "certificate_path": _CERT_IN_CONTAINER,
            "key_path": _KEY_IN_CONTAINER,
        },
        "masquerade": f"https://www.{MASQUERADE}",
    }
    body = json.dumps({"inbounds": [inbound]}, indent=2) + "\n"
    return {
        "sing-box/20_hysteria2.json": body.encode(),
        "sing-box/certs/certificate.pem": secrets.raw("hysteria2.crt"),
        "sing-box/certs/private.key": secrets.raw("hysteria2.key"),
    }


def _fingerprint(cert_pem: bytes) -> str:
    digest = load_pem_x509_certificate(cert_pem).fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def share(secrets: Secrets, user: User, host: str) -> list[ShareItem]:
    # Self-signed, so the client pins it by fingerprint -- recomputed here
    # rather than stored, for the same reason as the REALITY public key.
    uri = (
        f"hysteria2://{user.hysteria2_password}@{host}:{PORT}"
        f"?obfs=salamander&obfs-password={secrets.text('hysteria2.obfs')}"
        f"&sni={MASQUERADE}&pinSHA256={_fingerprint(secrets.raw('hysteria2.crt'))}"
        f"#{quote(user.name)}"
    )
    return [ShareItem(label="Hysteria2", filename=None, uri=uri)]


def bootstrap() -> dict[str, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, MASQUERADE)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return {
        "hysteria2.crt": cert.public_bytes(serialization.Encoding.PEM),
        "hysteria2.key": key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        "hysteria2.obfs": pysecrets.token_hex(16).encode(),
    }


PROTOCOL = Protocol(
    name=NAME,
    kind=Kind.SINGBOX,
    order=20,
    ports=(Port(PORT, "udp"),),
    summary="Hysteria2 (QUIC, Salamander obfs)",
    secret_names=("hysteria2.crt", "hysteria2.key", "hysteria2.obfs"),
    default_enabled=True,
    render=render,
    share=share,
    bootstrap=bootstrap,
)
