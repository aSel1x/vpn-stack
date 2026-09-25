"""state.json: the fields that carry intent past the command that formed it.

Both of the interesting ones exist because an intention outlived its command
and had nowhere to live: `revoke_pending` (a revocation that could not run
because the container was down) and `converge_pending` (a tree promoted to disk
without bouncing anything). Neither is derivable from the tree, which is the
whole reason they are written down.

Which is also why the *store* is tested here and not only the fields: the two
intents are worth nothing if the file holding them can be truncated by an
interrupted save, or read back as a traceback.
"""

from __future__ import annotations

import json
import stat

import pytest

from vpnctl import state
from vpnctl.paths import STATE_JSON


def test_converge_pending_survives_a_write_and_a_read() -> None:
    state.save(state.State(enabled=["vless-reality"], converge_pending=True))
    assert state.load().converge_pending is True


def test_a_state_file_written_before_the_field_existed_is_not_pending() -> None:
    # Fails open on purpose: an older state.json means nobody promised a
    # convergence, and inventing one would force-recreate every service on the
    # first apply after an upgrade.
    STATE_JSON.parent.mkdir(parents=True, exist_ok=True)
    STATE_JSON.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "enabled": ["vless-reality"],
                "revoke_pending": [],
                "last_applied": ["vless-reality"],
            }
        )
        + "\n"
    )
    assert state.load().converge_pending is False


def test_every_protocol_disabled_is_not_mistaken_for_a_pending_converge() -> None:
    """The reason converge_pending is its own field and not `not last_applied`.

    `apply` writes `last_applied = [p.name for p in enabled]`, which is `[]` on a
    server with every protocol off -- indistinguishable from "promoted, never
    converged" if emptiness is the signal. That server then force-recreated
    sing-box on every apply, every deploy and every boot, for ever.
    """
    state.save(state.State(enabled=[], last_applied=[], converge_pending=False))
    loaded = state.load()
    assert loaded.last_applied == []
    assert loaded.converge_pending is False


def test_revoke_pending_is_carried_verbatim() -> None:
    state.save(state.State(enabled=[], revoke_pending=["alice"]))
    assert state.load().revoke_pending == ["alice"]


def test_save_writes_at_0600_and_replaces_rather_than_truncating() -> None:
    """The same discipline users_store.save and secrets_store.write apply.

    This was the one store without it: write_text then chmod, so an interrupted
    save could leave a state.json that parses as nothing -- and an unreadable
    state.json is a `revoke_pending` nobody retries and a `converge_pending`
    nobody clears, both of which are failures you cannot see.
    """
    state.save(state.State(enabled=["vless-reality"], revoke_pending=["alice"]))
    assert stat.S_IMODE(STATE_JSON.stat().st_mode) == 0o600
    first = STATE_JSON.stat().st_ino
    state.save(state.State(enabled=[]))
    assert STATE_JSON.stat().st_ino != first
    assert not STATE_JSON.with_name(STATE_JSON.name + ".tmp").exists()


# ------------------------------------------------- every unreadable shape


def test_a_truncated_state_file_names_itself_instead_of_a_traceback() -> None:
    """Every command reads this file, `status` included.

    An unhandled JSONDecodeError here is not one broken command: it is a server
    with no working command surface, reporting a stack trace that names neither
    the file nor what to do about it.
    """
    STATE_JSON.parent.mkdir(parents=True, exist_ok=True)
    STATE_JSON.write_text('{"schema_version": 1, "enabled": ["vles')
    with pytest.raises(state.StateError) as excinfo:
        state.load()
    message = str(excinfo.value)
    assert str(STATE_JSON) in message
    assert "default protocol set" in message


def test_a_state_file_that_is_not_an_object_is_refused() -> None:
    STATE_JSON.parent.mkdir(parents=True, exist_ok=True)
    STATE_JSON.write_text('["vless-reality"]\n')
    with pytest.raises(state.StateError):
        state.load()


def test_a_newer_schema_is_refused_by_name() -> None:
    # Written since the first version and read by nothing, so a state.json from
    # a newer vpnctl loaded fine and lost whatever field this code does not know
    # on the next save(). Code rolls back; the file only moves forward.
    STATE_JSON.parent.mkdir(parents=True, exist_ok=True)
    STATE_JSON.write_text(
        json.dumps({"schema_version": state.SCHEMA_VERSION + 1, "enabled": []}) + "\n"
    )
    with pytest.raises(state.StateError) as excinfo:
        state.load()
    message = str(excinfo.value)
    assert str(STATE_JSON) in message
    assert "newer than the code" in message
    assert "Nothing was changed" in message


def test_a_state_file_with_no_schema_version_still_loads() -> None:
    # Every file written before the field was read claims nothing; refusing
    # those would brick every server that has ever run this code.
    STATE_JSON.parent.mkdir(parents=True, exist_ok=True)
    STATE_JSON.write_text(json.dumps({"enabled": ["hysteria2"]}) + "\n")
    assert state.load().enabled == ["hysteria2"]


# --------------------------------------- a missing file is a default, loudly


def test_a_missing_state_file_defaults_and_says_so() -> None:
    """The default set is not the empty set, and that is the danger.

    dnstt is `default_enabled=False`, so a lost state.json makes the next apply
    remove its three containers and delete 53/udp from ufw exactly as if the
    operator had asked -- and dnstt is the protocol people fall back to when
    nothing else gets through. It cannot be an error either, because a
    freshly-provisioned box genuinely has no state.json and `bootstrap` has to
    run before anything writes one. So: default, and tell the caller.
    """
    assert not STATE_JSON.exists()
    loaded, defaulted = state.load_or_default()
    assert defaulted is True
    assert loaded == state.default()
    assert "dnstt" not in loaded.enabled


def test_a_state_file_that_exists_is_not_reported_as_a_default() -> None:
    state.save(state.State(enabled=["dnstt"]))
    loaded, defaulted = state.load_or_default()
    assert defaulted is False
    assert loaded.enabled == ["dnstt"]


def test_load_still_returns_a_bare_state_for_existing_callers() -> None:
    # Additive on purpose: cli.py calls load() in a dozen places.
    assert isinstance(state.load(), state.State)
