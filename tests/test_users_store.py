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
