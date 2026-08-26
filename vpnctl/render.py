import json

from vpnctl import users_store
from vpnctl.dotenv import set_key
from vpnctl.paths import HYSTERIA2_CONFIG, IKEV2_ENV_FILE, VLESS_CONFIG


def _write_json(path, data) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n")


def render_vless(users: list[users_store.User]) -> None:
    data = json.loads(VLESS_CONFIG.read_text())
    data["inbounds"][0]["users"] = [
        {"name": u.name, "uuid": u.vless_uuid, "flow": "xtls-rprx-vision"}
        for u in users
        if u.enabled
    ]
    _write_json(VLESS_CONFIG, data)


def render_hysteria2(users: list[users_store.User]) -> None:
    data = json.loads(HYSTERIA2_CONFIG.read_text())
    data["inbounds"][0]["users"] = [
        {"name": u.name, "password": u.hysteria2_password}
        for u in users
        if u.enabled
    ]
    _write_json(HYSTERIA2_CONFIG, data)


def render_ikev2_env(users: list[users_store.User]) -> None:
    """Regenerate VPN_ADDL_USERS/VPN_ADDL_PASSWORDS for L2TP/Cisco IPsec.

    VPN_IPSEC_PSK and the primary VPN_USER/VPN_PASSWORD slot (required by the
    hwdsl2 image, unused by any real person) are left untouched -- every real
    vpnctl user goes through the additional-users lists instead, so add/remove
    behaves uniformly regardless of who's "first".
    """
    l2tp_users = [u for u in users if u.enabled]
    set_key(IKEV2_ENV_FILE, "VPN_ADDL_USERS", " ".join(u.name for u in l2tp_users))
    set_key(IKEV2_ENV_FILE, "VPN_ADDL_PASSWORDS", " ".join(u.l2tp_password for u in l2tp_users))


def render_all() -> list[users_store.User]:
    users = users_store.load()
    render_vless(users)
    render_hysteria2(users)
    render_ikev2_env(users)
    return users
