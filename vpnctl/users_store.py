import json
import os
import re
import secrets
import uuid
from dataclasses import MISSING, asdict, dataclass, fields
from datetime import datetime, timezone

from vpnctl.paths import USERS_JSON

# 1: the original record -- one credential per protocol, dnstt still shared.
# 2: dnstt_password, a per-person login behind the shared Noise key.
#
# Bumped when a field is added, which it was not when dnstt_password arrived --
# so every file written since then claims to be schema 1 and the "predates this
# field" reading of an empty dnstt_password was an assumption rather than
# something the file said. It still has to be an assumption for those files;
# from here on it is a fact, because a record written at schema 2 has the field.
SCHEMA_VERSION = 2


@dataclass
class User:
    name: str
    vless_uuid: str
    hysteria2_password: str
    l2tp_password: str
    ikev2_provisioned: bool
    enabled: bool
    created_at: str
    # Schema 2. The dnstt tunnel itself has no notion of a user -- its Noise key
    # belongs to the server and encrypts the transport before anyone
    # authenticates. What can be personal is the SSH login behind it, and that
    # is this. Empty means "written at schema 1, before this field": dnstt issues
    # them no login and says so. Never invented on read -- that would rotate a
    # live credential.
    dnstt_password: str = ""


# render_ikev2_env joins names into a single space-separated VPN_ADDL_USERS and
# passwords into VPN_ADDL_PASSWORDS. A name containing whitespace silently
# misaligns the two lists, handing one user another's password; other shell
# metacharacters end up in a .env file the hwdsl2 image sources. Keep names to
# one plain word.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")

# Names that already exist as an account or a group inside the dnstt-sshd image,
# read out of `alpine:3.20` (its base) with openssh-server installed, plus the
# `tunnel` group its entrypoint creates. A few names that are not in this
# particular image but are standard adduser reservations elsewhere are included
# on purpose: the base image tag can move, and a name being rejected costs one
# person one retry while the failure it prevents is silent.
#
# The failure: dnstt-sshd/entrypoint.sh does `id "$name" || adduser -D -H -G
# tunnel "$name"` and then chpasswd *unconditionally*. For a colliding name the
# `id` succeeds, so the `-G tunnel` membership is never granted -- and the
# chpasswd still runs, setting the container's own system account to that
# person's dnstt password. `AllowGroups tunnel` then refuses the login: the
# credential is issued, printed on a share card, and can never work, while the
# only visible symptom is one person saying "it says wrong password".
_RESERVED_NAMES = frozenset(
    {
        # alpine:3.20 /etc/passwd
        "root",
        "bin",
        "daemon",
        "lp",
        "sync",
        "shutdown",
        "halt",
        "mail",
        "news",
        "uucp",
        "cron",
        "ftp",
        "sshd",
        "games",
        "ntp",
        "guest",
        "nobody",
        # alpine:3.20 /etc/group -- busybox adduser resolves a name against both
        "sys",
        "adm",
        "tty",
        "disk",
        "kmem",
        "wheel",
        "floppy",
        "audio",
        "cdrom",
        "dialout",
        "input",
        "tape",
        "video",
        "netdev",
        "kvm",
        "shadow",
        "www-data",
        "users",
        "abuild",
        "utmp",
        "ping",
        "nogroup",
        # the group the entrypoint creates and AllowGroups keys on
        "tunnel",
        # not in this image, reserved by adduser elsewhere
        "operator",
        "man",
        "postmaster",
        "at",
        "squid",
        "xfs",
        "cyrus",
        "vpopmail",
        "nut",
        "smmsp",
    }
)


def unrenderable_name(name: str) -> str | None:
    """Return an error message if `name` would corrupt a rendered file, else None.

    This half is about FILE FORMATS and nothing else, which is why every
    protocol's render() may enforce it: `render_ikev2_env` pairs two
    space-separated lists by position, and dnstt's login list is `name:password`
    per line read with `IFS=:`. A name that breaks either one cannot be served by
    anybody, so refusing before the candidate tree is promoted is strictly better
    than serving it.

    Kept apart from `reserved_name` deliberately. The two used to be one check,
    and ikev2.render() called it -- so a user legally created before the reserved
    list existed made EVERY apply fail, the systemd boot unit included, with
    dnstt switched off and ikev2 enabled by default. That is the shape
    dnstt.render's own comment warns about at length: a refusal in render that
    the operator cannot get out from under.
    """
    if not _NAME_RE.match(name):
        return (
            f"Invalid user name {name!r}. Use 1-32 characters: letters, digits, "
            "'.', '_' or '-', starting with a letter or digit. No spaces -- the "
            "L2TP/Cisco user list is space-separated and a space would misalign "
            "every user's password."
        )
    return None


def reserved_name(name: str) -> str | None:
    """Return an error message if `name` collides with a dnstt-container account.

    A fact about ONE protocol's container image, not about whether a name can be
    rendered -- so only `user add` and dnstt's own render enforce it. ikev2 must
    not: its render is reached on every apply whether or not dnstt is on.
    """
    # Case-folded, because `find()` already treats names case-insensitively: a
    # person is known by one name regardless of case, so allowing `Root` would
    # only be allowing the same collision with a different spelling.
    if name.lower() in _RESERVED_NAMES:
        return (
            f"Reserved user name {name!r}. Every user gets a login inside the "
            "dnstt sshd container, and this name already exists there as a "
            "system account or group -- the login would be created without the "
            "'tunnel' group, the system account's password would be overwritten "
            "with this user's, and `AllowGroups tunnel` would then refuse a "
            "credential that had already been handed out. Pick another name."
        )
    return None


def validate_name(name: str) -> str | None:
    """Both halves, which is what `user add` owes a name it is about to create."""
    return unrenderable_name(name) or reserved_name(name)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_credentials() -> tuple[str, str, str]:
    return str(uuid.uuid4()), secrets.token_hex(16), secrets.token_hex(16)


class UsersError(RuntimeError):
    pass


# The fields with no dataclass default. Absent from a record, each one used to
# reach the operator as `TypeError: User.__init__() missing 1 required positional
# argument`, which is the very error this module exists to replace -- only
# l2tp_password had been given a sentence of its own, and the other four were
# still one stale deploy away from an unguessable traceback. Derived rather than
# listed so a new required field cannot be forgotten here.
_REQUIRED_FIELDS = tuple(
    f.name
    for f in fields(User)
    if f.default is MISSING and f.default_factory is MISSING
)


def load() -> list[User]:
    """Read the database. Never writes -- not even to backfill.

    It used to mint a fresh l2tp_password for any record missing one and save
    it, which meant a plain `user list` could silently rotate a live
    credential. Absent booleans get a default because that is derivable;
    an absent *secret* is a damaged database and says so.

    Every way this file can be wrong ends in a UsersError naming the file and a
    remedy. A traceback out of here is not one broken command: `load()` is the
    first thing nearly every command does, so it is the whole command surface
    replaced by a stack trace that names neither users.json nor what to do.
    """
    if not USERS_JSON.exists():
        return []
    try:
        data = json.loads(USERS_JSON.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise UsersError(
            f"{USERS_JSON} is not readable JSON ({exc}). Restore from a backup "
            "-- this file is the only record of who has access. Nothing was "
            "changed."
        ) from None
    if not isinstance(data, dict) or not isinstance(data.get("users"), list):
        # A wrong-shaped file used to surface as `KeyError: 'users'`, which
        # reads like a bug in vpnctl rather than a damaged file.
        raise UsersError(
            f"{USERS_JSON} is not a users.json: expected a JSON object with a "
            '"users" list. Restore from a backup. Nothing was changed.'
        )

    # Rolling the code back is easy -- push.sh will happily rsync an older
    # checkout over a newer one -- while the database only moves forward. That
    # combination used to surface as `TypeError: User.__init__() got an
    # unexpected keyword argument`, from which the cause is unguessable.
    #
    # Refuse rather than drop the unknown fields: ignoring them would let the
    # next save() write the record back without them, quietly destroying a
    # credential this code is simply too old to know about.
    version = data.get("schema_version", SCHEMA_VERSION)
    if not isinstance(version, int) or version > SCHEMA_VERSION:
        raise UsersError(
            f"{USERS_JSON} has schema {version!r}, this vpnctl understands "
            f"{SCHEMA_VERSION}. The database is newer than the code -- deploy "
            "the matching version. Nothing was changed."
        )

    known = {f.name for f in fields(User)}
    users = []
    for u in data["users"]:
        if not isinstance(u, dict):
            raise UsersError(
                f'{USERS_JSON}: one entry in "users" is {type(u).__name__}, '
                "not an object. Restore from a backup. Nothing was changed."
            )
        unknown = sorted(set(u) - known)
        if unknown:
            raise UsersError(
                f"{USERS_JSON}: user {u.get('name')!r} has fields this vpnctl "
                f"does not know ({', '.join(unknown)}). The database is newer "
                "than the code -- deploy the matching version. Nothing was "
                "changed."
            )
        u.setdefault("ikev2_provisioned", False)
        u.setdefault("enabled", True)
        # Not a rotation risk: absent means never issued, so a default of
        # "none yet" is the truth. Filled in by `bootstrap`, never here.
        u.setdefault("dnstt_password", "")
        # After the defaults, so the two derivable booleans are already filled
        # and what is left missing is genuinely missing.
        for required in _REQUIRED_FIELDS:
            if required not in u:
                raise UsersError(
                    f"{USERS_JSON}: user {u.get('name')!r} has no {required}. "
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
