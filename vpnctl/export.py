import json
from datetime import datetime, timezone
from urllib.parse import quote

import qrcode
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate

from vpnctl import users_store
from vpnctl.dotenv import read as read_env
from vpnctl.paths import CERTS_DIR, ENV_FILE, EXPORTS_DIR, HYSTERIA2_CONFIG, VLESS_CONFIG
from vpnctl.reality_key import derive_public_key


class ExportError(Exception):
    pass


def resolve_host(explicit_host: str | None) -> str:
    if explicit_host:
        return explicit_host
    host = read_env(ENV_FILE).get("VPN_SERVER_HOST")
    if not host:
        raise ExportError(
            "No server host known yet. Pass --host <ip-or-domain>, or set "
            "VPN_SERVER_HOST=... in .env once the server is deployed."
        )
    return host


def _cert_fingerprint_sha256() -> str:
    cert_path = CERTS_DIR / "certificate.pem"
    cert = load_pem_x509_certificate(cert_path.read_bytes())
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def build_vless_uri(user: users_store.User, host: str) -> str:
    cfg = json.loads(VLESS_CONFIG.read_text())["inbounds"][0]
    port = cfg["listen_port"]
    sni = cfg["tls"]["server_name"]
    reality = cfg["tls"]["reality"]
    pbk = derive_public_key(reality["private_key"])
    sid = reality["short_id"][0]
    name = quote(user.name)
    return (
        f"vless://{user.vless_uuid}@{host}:{port}"
        f"?encryption=none&flow=xtls-rprx-vision&security=reality"
        f"&sni={sni}&fp=chrome&pbk={pbk}&sid={sid}&type=tcp&headerType=none"
        f"#{name}"
    )


def build_hysteria2_uri(user: users_store.User, host: str) -> str:
    cfg = json.loads(HYSTERIA2_CONFIG.read_text())["inbounds"][0]
    port = cfg["listen_port"]
    sni = cfg["tls"]["server_name"]
    obfs_password = cfg["obfs"]["password"]
    fingerprint = _cert_fingerprint_sha256()
    name = quote(user.name)
    return (
        f"hysteria2://{user.hysteria2_password}@{host}:{port}"
        f"?obfs=salamander&obfs-password={obfs_password}"
        f"&sni={sni}&pinSHA256={fingerprint}"
        f"#{name}"
    )


def print_ascii_qr(uri: str) -> None:
    qr = qrcode.QRCode(border=1)
    qr.add_data(uri)
    qr.make(fit=True)
    qr.print_ascii(invert=True)


def save_qr_png(uri: str, user_name: str, protocol: str) -> str:
    EXPORTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = EXPORTS_DIR / f"{user_name}-{protocol}-{timestamp}.png"
    img = qrcode.make(uri)
    img.save(path)
    return str(path)
