"""users_store: the three refusals, and the promise that load() never writes.

Code can roll back; the database cannot. push.sh will happily rsync an older
checkout over a newer one, and did -- a stale tree over a users.json that had
grown a field killed every vpnctl command with an unguessable TypeError.
"""

from __future__ import annotations

import json
import os
import stat

import pytest
from conftest import make_user

from vpnctl import users_store
from vpnctl.users_store import UsersError

COMPLETE = {
    "name": "alice",
    "vless_uuid": "00000000-0000-4000-8000-000000000001",
    "hysteria2_password": "hy2",
    "l2tp_password": "l2tp",
    "ikev2_provisioned": True,
    "enabled": True,
    "created_at": "2026-01-01T00:00:00Z",
    "dnstt_password": "dnstt",
}


NO_L2TP = {k: v for k, v in COMPLETE.items() if k != "l2tp_password"}


def write_db(records: list[dict], schema: int = users_store.SCHEMA_VERSION) -> None:
    payload = {"schema_version": schema, "users": records}
    users_store.USERS_JSON.parent.mkdir(parents=True, exist_ok=True)
    users_store.USERS_JSON.write_text(json.dumps(payload, indent=2) + "\n")


def fingerprint() -> tuple:
    st = users_store.USERS_JSON.stat()
    return (
        users_store.USERS_JSON.read_bytes(),
        st.st_mtime_ns,
        st.st_ino,
        stat.S_IMODE(st.st_mode),
        sorted(p.name for p in users_store.USERS_JSON.parent.iterdir()),
    )


def test_no_database_is_no_users() -> None:
    assert not users_store.USERS_JSON.exists()
    assert users_store.load() == []


def test_a_round_trip_preserves_every_field() -> None:
    users_store.save([make_user("alice"), make_user("bob", enabled=False)])
    assert users_store.load() == [make_user("alice"), make_user("bob", enabled=False)]


# ------------------------------------------------------------- the refusals


def test_a_newer_schema_is_refused_by_name() -> None:
    write_db([COMPLETE], schema=users_store.SCHEMA_VERSION + 1)
    with pytest.raises(UsersError) as excinfo:
        users_store.load()
    message = str(excinfo.value)
    assert str(users_store.USERS_JSON) in message
    assert "newer than the code" in message
    assert "Nothing was changed" in message


def test_an_unknown_field_is_refused_and_named() -> None:
    """Refused rather than dropped: ignoring the field would let the next
    save() write the record back without it, destroying a credential this code
    is merely too old to know about."""
    write_db([{**COMPLETE, "wireguard_privkey": "secret"}])
    with pytest.raises(UsersError) as excinfo:
        users_store.load()
    message = str(excinfo.value)
    assert "wireguard_privkey" in message
    assert "'alice'" in message


def test_a_missing_secret_is_a_damaged_database() -> None:
    write_db([NO_L2TP])
    with pytest.raises(UsersError) as excinfo:
        users_store.load()
    assert "restore from a backup" in str(excinfo.value)


def test_derivable_fields_get_defaults_instead() -> None:
    # Booleans and "never issued" are derivable, so they are filled in rather
    # than refused. A missing *secret* is not.
    derivable = ("enabled", "ikev2_provisioned", "dnstt_password")
    lean = {k: v for k, v in COMPLETE.items() if k not in derivable}
    write_db([lean])
    (user,) = users_store.load()
    assert user.enabled is True
    assert user.ikev2_provisioned is False
    assert user.dnstt_password == ""


# ------------------------------------------------------- load() never writes


@pytest.mark.parametrize(
    "records",
    [
        pytest.param([COMPLETE], id="complete"),
        pytest.param(
            [{k: v for k, v in COMPLETE.items() if k != "dnstt_password"}],
            id="missing-dnstt_password",
        ),
        pytest.param(
            [{k: v for k, v in COMPLETE.items() if k != "enabled"}],
            id="missing-enabled",
        ),
    ],
)
def test_load_never_writes(records) -> None:
    """It used to mint a fresh l2tp_password for any record missing one and
    save it, so a plain `user list` could silently rotate a live credential."""
    write_db(records)
    before = fingerprint()
    for _ in range(3):
        users_store.load()
    assert fingerprint() == before


@pytest.mark.parametrize(
    "records,schema",
    [
        ([{**COMPLETE, "future_field": 1}], users_store.SCHEMA_VERSION),
        ([COMPLETE], users_store.SCHEMA_VERSION + 1),
        ([NO_L2TP], users_store.SCHEMA_VERSION),
    ],
    ids=["unknown-field", "newer-schema", "missing-secret"],
)
def test_a_refusal_changes_nothing_either(records, schema) -> None:
    write_db(records, schema=schema)
    before = fingerprint()
    with pytest.raises(UsersError):
        users_store.load()
    assert fingerprint() == before


def test_save_writes_at_0600_and_leaves_no_temporary() -> None:
    # The state directory is 0700, so this is defence in depth -- but a backup
    # unpacked elsewhere keeps these bits, and the file is every user's
    # password for every protocol.
    users_store.save([make_user("alice")])
    mode = stat.S_IMODE(users_store.USERS_JSON.stat().st_mode)
    assert mode == 0o600
    tmp = users_store.USERS_JSON.with_name(users_store.USERS_JSON.name + ".tmp")
    assert not tmp.exists()


def test_save_replaces_rather_than_truncating_in_place() -> None:
    # write_text() truncates first, so an interrupted save could leave an empty
    # user database. os.replace swaps the inode instead.
    users_store.save([make_user("alice")])
    first = os.stat(users_store.USERS_JSON).st_ino
    users_store.save([make_user("alice"), make_user("bob")])
    assert os.stat(users_store.USERS_JSON).st_ino != first
    assert len(users_store.load()) == 2


def test_find_is_case_insensitive() -> None:
    users = [make_user("Alice")]
    assert users_store.find(users, "alice").name == "Alice"
    assert users_store.find(users, "nobody") is None


def test_new_user_mints_a_credential_for_every_protocol() -> None:
    user = users_store.new_user("alice")
    assert user.vless_uuid and user.hysteria2_password and user.l2tp_password
    assert user.dnstt_password
    # The dnstt password is retyped on a phone and fed to chpasswd, whose
    # separator is ':'. No shell metacharacters, no colon.
    assert ":" not in user.dnstt_password
    assert user.dnstt_password.isalnum()
    assert users_store.new_user("alice").vless_uuid != user.vless_uuid


# ------------------------------------- the other ways this file can be wrong


def test_a_truncated_database_names_itself_instead_of_a_traceback() -> None:
    # load() is the first thing nearly every command does, so a bare
    # JSONDecodeError here replaces the whole command surface with a stack trace
    # that names neither users.json nor a remedy.
    users_store.USERS_JSON.parent.mkdir(parents=True, exist_ok=True)
    users_store.USERS_JSON.write_text('{"schema_version": 1, "users": [{"name": "al')
    with pytest.raises(UsersError) as excinfo:
        users_store.load()
    message = str(excinfo.value)
    assert str(users_store.USERS_JSON) in message
    assert "Restore from a backup" in message


@pytest.mark.parametrize(
    "body",
    [
        pytest.param('["alice"]\n', id="top-level-list"),
        pytest.param('{"schema_version": 1}\n', id="no-users-key"),
        pytest.param('{"users": {"alice": {}}}\n', id="users-is-an-object"),
    ],
)
def test_a_wrong_shaped_file_says_it_is_not_a_users_json(body) -> None:
    # `KeyError: 'users'` reads like a bug in vpnctl rather than a damaged file.
    users_store.USERS_JSON.parent.mkdir(parents=True, exist_ok=True)
    users_store.USERS_JSON.write_text(body)
    with pytest.raises(UsersError) as excinfo:
        users_store.load()
    assert "not a users.json" in str(excinfo.value)


@pytest.mark.parametrize(
    "record",
    [
        pytest.param("alice", id="string"),
        pytest.param(7, id="int"),
        pytest.param(["alice"], id="list"),
        pytest.param(None, id="null"),
    ],
)
def test_a_record_that_is_not_an_object_is_refused(record) -> None:
    """And says THAT, rather than arriving as some other refusal.

    A bare `pytest.raises(UsersError)` here asserted nothing about the guard it
    was written for: a string record falls through to `set(u) - known`, which
    over "alice" yields the letters and raises the unknown-field refusal -- so
    the check passed against the code with no isinstance guard at all, telling
    the operator the database is newer than vpnctl when it is simply damaged.
    An int does not even get that far: set(7) is a TypeError, which is the
    traceback this module exists to replace.
    """
    write_db([record])
    with pytest.raises(UsersError) as excinfo:
        users_store.load()
    message = str(excinfo.value)
    assert "not an object" in message
    assert type(record).__name__ in message
    assert "newer than the code" not in message


@pytest.mark.parametrize(
    "missing",
    ["name", "vless_uuid", "hysteria2_password", "l2tp_password", "created_at"],
)
def test_every_required_field_is_named_when_absent(missing) -> None:
    """Only l2tp_password had a sentence of its own.

    The other four still reached the operator as `TypeError: User.__init__()
    missing 1 required positional argument`, which is the exact error this
    module exists to replace.
    """
    write_db([{k: v for k, v in COMPLETE.items() if k != missing}])
    with pytest.raises(UsersError) as excinfo:
        users_store.load()
    message = str(excinfo.value)
    assert missing in message
    assert "restore from a backup" in message


def test_the_required_set_is_derived_from_the_dataclass() -> None:
    # Listed by hand, a new required field would be forgotten here and go back
    # to raising TypeError.
    assert set(users_store._REQUIRED_FIELDS) == {
        "name",
        "vless_uuid",
        "hysteria2_password",
        "l2tp_password",
        "ikev2_provisioned",
        "enabled",
        "created_at",
    }


# ------------------------------------------------------------- schema version


def test_a_schema_1_database_still_loads_with_no_dnstt_password() -> None:
    """dnstt_password arrived without a bump, so files claiming 1 may have it.

    Either way a schema 1 record must load: an operator upgrading from before
    the field existed cannot be asked to edit users.json first.
    """
    lean = {k: v for k, v in COMPLETE.items() if k != "dnstt_password"}
    write_db([lean], schema=1)
    (user,) = users_store.load()
    assert user.dnstt_password == ""
    assert users_store.SCHEMA_VERSION >= 2


def test_save_stamps_the_current_schema() -> None:
    users_store.save([make_user("alice")])
    written = json.loads(users_store.USERS_JSON.read_text())
    assert written["schema_version"] == users_store.SCHEMA_VERSION


# -------------------------------------------------------------- name validation


def test_a_plain_name_is_accepted() -> None:
    assert users_store.validate_name("anna.anatolievna") is None
    assert users_store.validate_name("govomes") is None


@pytest.mark.parametrize("name", ["anna anatolievna", "", "a" * 33, ".leading", "a;b"])
def test_an_unrenderable_name_is_refused(name) -> None:
    # The L2TP/Cisco user list is space-separated: a space misaligns names
    # against passwords and hands one user another's credential.
    assert "Invalid user name" in (users_store.validate_name(name) or "")


@pytest.mark.parametrize("name", ["root", "sshd", "nobody", "tunnel", "Root", "ADM"])
def test_a_name_that_collides_inside_the_dnstt_sshd_container_is_refused(name) -> None:
    """The collision issues a credential that can never work.

    dnstt-sshd/entrypoint.sh does `id "$name" || adduser -D -H -G tunnel
    "$name"` and then chpasswd unconditionally. For a name the base image already
    has, `id` succeeds, so the `-G tunnel` membership is never granted while the
    container's own system account gets that person's dnstt password.
    `AllowGroups tunnel` then refuses the login: the share card is printed, the
    password is real, and it can never work.
    """
    message = users_store.validate_name(name) or ""
    assert "Reserved user name" in message
    assert "tunnel" in message


def test_the_reserved_set_covers_the_base_image_accounts() -> None:
    # Read out of `alpine:3.20` (dnstt-sshd's base) with openssh-server
    # installed: /etc/passwd plus /etc/group, which busybox adduser resolves
    # against too.
    for name in (
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
    ):
        assert users_store.validate_name(name) is not None, name
