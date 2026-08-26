import json
import secrets
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from vpnctl.paths import USERS_JSON

SCHEMA_VERSION = 1


@dataclass
class User:
    name: str
    vless_uuid: str
    hysteria2_password: str
    l2tp_password: str
    ikev2_provisioned: bool
    enabled: bool
    created_at: str


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_credentials() -> tuple[str, str, str]:
    return str(uuid.uuid4()), secrets.token_hex(16), secrets.token_hex(16)


def load() -> list[User]:
    if not USERS_JSON.exists():
        raise FileNotFoundError(
            f"{USERS_JSON} not found. Run 'vpnctl migrate' first to bootstrap it "
            "from the existing hand-written config."
        )
    data = json.loads(USERS_JSON.read_text())
    users = []
    schema_changed = False
    for u in data["users"]:
        if "l2tp_password" not in u:
            u["l2tp_password"] = secrets.token_hex(16)
            schema_changed = True
        if "ikev2_provisioned" not in u:
            u["ikev2_provisioned"] = False
            schema_changed = True
        users.append(User(**u))
    if schema_changed:
        save(users)
    return users


def save(users: list[User]) -> None:
    data = {
        "schema_version": SCHEMA_VERSION,
        "users": [asdict(u) for u in users],
    }
    USERS_JSON.write_text(json.dumps(data, indent=2) + "\n")


def find(users: list[User], name: str) -> User | None:
    for u in users:
        if u.name.lower() == name.lower():
            return u
    return None


def new_user(name: str) -> User:
    vless_uuid, hy2_password, l2tp_password = generate_credentials()
    return User(
        name=name,
        vless_uuid=vless_uuid,
        hysteria2_password=hy2_password,
        l2tp_password=l2tp_password,
        ikev2_provisioned=False,
        enabled=True,
        created_at=_now(),
    )
