"""Generate the hand-owned base config vpnctl otherwise never creates.

render.py only ever rewrites the "users" array of an *existing*
10_vless_reality_tcp.json / 20_hysteria2.json -- ports, the REALITY private
key, the Hysteria2 cert/obfs password, and ikev2/.env's PSK/VPN_USER/
VPN_PASSWORD are all hand-owned and were previously only ever produced by
copying them from another deployment or hand-authoring the JSON. This is the
one-time "day 0" step that fills that gap.
"""

import datetime
import json
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from vpnctl import reality_key
from vpnctl.paths import (
    CERTS_DIR,
    HYSTERIA2_CONFIG,
    HYSTERIA2_DIR,
    IKEV2_DIR,
    IKEV2_ENV_FILE,
    VLESS_CONFIG,
    VLESS_DIR,
)

VLESS_PORT = 10443
HYSTERIA2_PORT = 20443
REALITY_MASQUERADE = "www.apple.com"
HYSTERIA2_MASQUERADE_DOMAIN = "bing.com"


def _write_json(path, data) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n")


def _generate_hysteria2_cert(common_name: str) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
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
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


def bootstrap_sing_box(force: bool = False) -> tuple[bool, str]:
    """Generate a fresh REALITY keypair and a self-signed Hysteria2 cert.

    Refuses to touch anything if either config already exists, unless
    force=True -- both hold a live key that every already-exported client
    profile depends on.
    """
    if not force and (VLESS_CONFIG.exists() or HYSTERIA2_CONFIG.exists()):
        return False, (
            f"{VLESS_CONFIG} or {HYSTERIA2_CONFIG} already exists, skipped "
            "(pass force=True / --force to regenerate -- this invalidates "
            "every already-exported vless/hysteria2 profile)"
        )

    VLESS_DIR.mkdir(parents=True, exist_ok=True)
    HYSTERIA2_DIR.mkdir(parents=True, exist_ok=True)
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    private_key = reality_key.generate_private_key()
    short_id = secrets.token_hex(8)
    _write_json(VLESS_CONFIG, {
        "inbounds": [{
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": VLESS_PORT,
            "users": [],
            "tls": {
                "enabled": True,
                "server_name": REALITY_MASQUERADE,
                "reality": {
                    "enabled": True,
                    "handshake": {"server": REALITY_MASQUERADE, "server_port": 443},
                    "private_key": private_key,
                    "short_id": [short_id],
                },
            },
        }],
    })

    cert_pem, key_pem = _generate_hysteria2_cert(HYSTERIA2_MASQUERADE_DOMAIN)
    (CERTS_DIR / "certificate.pem").write_bytes(cert_pem)
    key_path = CERTS_DIR / "private.key"
    key_path.write_bytes(key_pem)
    key_path.chmod(0o600)

    obfs_password = secrets.token_hex(16)
    _write_json(HYSTERIA2_CONFIG, {
        "inbounds": [{
            "type": "hysteria2",
            "tag": "hysteria2-in",
            "listen": "::",
            "listen_port": HYSTERIA2_PORT,
            "up_mbps": 100,
            "down_mbps": 100,
            "ignore_client_bandwidth": False,
            "obfs": {"type": "salamander", "password": obfs_password},
            "users": [],
            "tls": {
                "enabled": True,
                "server_name": HYSTERIA2_MASQUERADE_DOMAIN,
                "certificate_path": "/etc/sing-box/hysteria2/certs/certificate.pem",
                "key_path": "/etc/sing-box/hysteria2/certs/private.key",
            },
            "masquerade": f"https://www.{HYSTERIA2_MASQUERADE_DOMAIN}",
        }],
    })
    return True, f"generated REALITY keypair (port {VLESS_PORT}) and Hysteria2 cert+obfs (port {HYSTERIA2_PORT})"


def bootstrap_ikev2_env(force: bool = False) -> tuple[bool, str]:
    """Generate ikev2/.env's PSK and the image's required primary user slot.

    VPN_ADDL_USERS/VPN_ADDL_PASSWORDS are left for `vpnctl render` to fill in
    from users.json -- this only creates the hand-owned fields.
    """
    if not force and IKEV2_ENV_FILE.exists():
        return False, f"{IKEV2_ENV_FILE} already exists, skipped (pass force=True / --force to regenerate)"

    IKEV2_DIR.mkdir(parents=True, exist_ok=True)
    psk = secrets.token_hex(16)
    vpn_user = secrets.token_hex(8)
    vpn_password = secrets.token_hex(16)
    IKEV2_ENV_FILE.write_text(
        f"VPN_IPSEC_PSK={psk}\nVPN_USER={vpn_user}\nVPN_PASSWORD={vpn_password}\n"
    )
    IKEV2_ENV_FILE.chmod(0o600)
    return True, f"generated {IKEV2_ENV_FILE}"
