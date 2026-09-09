"""state.json: the fields that carry intent past the command that formed it.

Both of the interesting ones exist because an intention outlived its command
and had nowhere to live: `revoke_pending` (a revocation that could not run
because the container was down) and `converge_pending` (a tree promoted to disk
without bouncing anything). Neither is derivable from the tree, which is the
whole reason they are written down.
"""

from __future__ import annotations

import json

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
