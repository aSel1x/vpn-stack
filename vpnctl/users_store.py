import json
import os
import re
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
    # The dnstt tunnel itself has no notion of a user -- its Noise key belongs
    # to the server and encrypts the transport before anyone authenticates.
    # What can be personal is the SSH login behind it, and that is this.
    # Empty means "predates this field": dnstt simply issues them no login
    # until `vpnctl bootstrap` fills it in. Never invented on read.
    dnstt_password: str = ""


# render_ikev2_env joins names into a single space-separated VPN_ADDL_USERS and
# passwords into VPN_ADDL_PASSWORDS. A name containing whitespace silently
# misaligns the two lists, handing one user another's password; other shell
# metacharacters end up in a .env file the hwdsl2 image sources. Keep names to
# one plain word.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")


def validate_name(name: str) -> str | None:
    """Return an error message if `name` is unsafe to render, else None."""
    if not _NAME_RE.match(name):
        return (
            f"Invalid user name {name!r}. Use 1-32 characters: letters, digits, "
            "'.', '_' or '-', starting with a letter or digit. No spaces -- the "
            "L2TP/Cisco user list is space-separated and a space would misalign "
            "every user's password."
        )
    return None


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_credentials() -> tuple[str, str, str]:
    return str(uuid.uuid4()), secrets.token_hex(16), secrets.token_hex(16)


class UsersError(RuntimeError):
    pass


def load() -> list[User]:
    """Read the database. Never writes -- not even to backfill.

    It used to mint a fresh l2tp_password for any record missing one and save
    it, which meant a plain `user list` could silently rotate a live
    credential. Absent booleans get a default because that is derivable;
    an absent *secret* is a damaged database and says so.
    """
    if not USERS_JSON.exists():
        return []
    data = json.loads(USERS_JSON.read_text())
    users = []
    for u in data["users"]:
        u.setdefault("ikev2_provisioned", False)
        u.setdefault("enabled", True)
        # Not a rotation risk: absent means never issued, so a default of
        # "none yet" is the truth. Filled in by `bootstrap`, never here.
        u.setdefault("dnstt_password", "")
        if "l2tp_password" not in u:
            raise UsersError(
                f"{USERS_JSON}: user {u.get('name')!r} has no l2tp_password. "
                "Inventing one would hand out a credential nobody holds; "
                "restore from a backup instead."
            )
        users.append(User(**u))
    return users


def save(users: list[User]) -> None:
    """Write atomically, at 0600, with the mode set before any content exists.

    The state directory is 0700, so this is defence in depth -- but a backup
    unpacked somewhere else keeps these bits, and the file is every user's
    password for every protocol. write_text() truncates in place, so an
    interrupted save used to be able to leave an empty user database.
    """
    data = {
        "schema_version": SCHEMA_VERSION,
        "users": [asdict(u) for u in users],
    }
    USERS_JSON.parent.mkdir(parents=True, exist_ok=True)
    tmp = USERS_JSON.with_name(USERS_JSON.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(data, indent=2) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, USERS_JSON)
    finally:
        tmp.unlink(missing_ok=True)


def find(users: list[User], name: str) -> User | None:
    for u in users:
        if u.name.lower() == name.lower():
            return u
    return None


def new_dnstt_password() -> str:
    # Goes into a container's chpasswd and into a share card people retype on
    # a phone, so: no shell metacharacters, no colon (the chpasswd separator),
    # no ambiguity between similar glyphs.
    return secrets.token_urlsafe(16).replace("-", "x").replace("_", "y")


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
        dnstt_password=new_dnstt_password(),
    )


def backfill(users: list[User]) -> list[str]:
    """Give pre-existing users the fields added since they were created.

    Only ever *adds* a credential that was never issued; it does not rotate
    one that exists, which is why `load()` may not do this and an operator
    command must.
    """
    filled = []
    for u in users:
        if not u.dnstt_password:
            u.dnstt_password = new_dnstt_password()
            filled.append(u.name)
    return filled
