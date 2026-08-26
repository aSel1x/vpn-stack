from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SING_BOX_DIR = ROOT / "sing-box"
COMMON_DIR = SING_BOX_DIR / "common"
VLESS_DIR = SING_BOX_DIR / "vless-reality"
HYSTERIA2_DIR = SING_BOX_DIR / "hysteria2"
CERTS_DIR = HYSTERIA2_DIR / "certs"

DATA_DIR = ROOT / "data"
EXPORTS_DIR = ROOT / "exports"

USERS_JSON = ROOT / "users.json"
ENV_FILE = ROOT / ".env"

VLESS_CONFIG = VLESS_DIR / "10_vless_reality_tcp.json"
HYSTERIA2_CONFIG = HYSTERIA2_DIR / "20_hysteria2.json"
CLASH_API_CONFIG = COMMON_DIR / "05_clash_api.json"

IKEV2_DIR = ROOT / "ikev2"
IKEV2_ENV_FILE = IKEV2_DIR / ".env"
IKEV2_CONTAINER_NAME = "ipsec-vpn-server"
