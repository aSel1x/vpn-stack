"""state.json -- which protocols are on, and what still needs undoing.

Separate from users.json on purpose: users.json answers "who has access",
state.json answers "what is this server currently running". They change for
different reasons and at different times.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field

from vpnctl import protocols
from vpnctl.paths import STATE_JSON

SCHEMA_VERSION = 1


class StateError(RuntimeError):
    pass


@dataclass
class State:
    enabled: list[str] = field(default_factory=list)
    # Revocations that could not be executed when they were requested (the
    # container was down). The intent has to outlive the deleted user record,
    # or a `user rm` with ikev2 stopped silently leaves a working certificate.
    revoke_pending: list[str] = field(default_factory=list)
    # A record of what the last `apply` brought up, for humans reading the file
    # and for `--json` consumers. Nothing derives behaviour from it: teardown
    # comes from the registry instead -- `composectl.down_disabled` subtracts
    # the enabled set from `protocols.ordered()` and asks compose what is
    # actually running. That is deliberate, because this field is a tree-side
    # belief about containers and can be wrong in both directions: stale after a
    # crash between converge and save, and wrong about a service somebody
    # stopped by hand. `converge_pending` exists precisely because a written
    # record like this one cannot be trusted as the answer to "is the running
    # config the promoted one".
    last_applied: list[str] = field(default_factory=list)
    # A tree was promoted to disk without bouncing anything (`apply
    # --no-restart`, or `bootstrap --force`), so the containers are still
    # running the previous config and no directory diff can tell: the diff
    # compares two trees, never a tree against a container. Same shape as
    # revoke_pending -- an intent that must outlive the command that formed it,
    # survive a reboot into the boot unit's own apply, and be cleared only by a
    # converge that succeeded. A separate field rather than `not last_applied`,
    # which is also empty when every protocol is disabled and left that server
    # force-recreating on every apply, for ever.
    converge_pending: bool = False


def default() -> State:
    return State(enabled=[p.name for p in protocols.ordered() if p.default_enabled])


def load() -> State:
    """The current state, or the default set if there is no file at all.

    A missing file cannot be an error: a box that has just been provisioned
    genuinely has none, and `bootstrap` has to be able to run before anything
    has ever written one. It is not harmless either -- see load_or_default.
    """
    state, _ = load_or_default()
    return state


def load_or_default() -> tuple[State, bool]:
    """(state, defaulted) -- whether that state was read or invented.

    A *lost* state.json is indistinguishable from a fresh box to load(), and the
    default set is not the empty set: dnstt is `default_enabled=False`, so the
    next `apply` after the file disappears removes its three containers and
    deletes 53/udp from ufw, exactly as if the operator had asked for that. The
    protocol that is off by default is also the last-resort one people fall back
    to when nothing else gets through, so this is the worst possible thing to
    turn off silently.

    Erroring instead would brick a fresh install, so the file's absence stays a
    default and the caller is told it happened -- the same split as
    `_running_services` returning None: "I do not know" is not "nothing".
    """
    if not STATE_JSON.exists():
        return default(), True

    try:
        data = json.loads(STATE_JSON.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        # Every command reads this file, `status` included, so an unhandled
        # decode error here is not one broken command: it is a server with no
        # working command surface at all, reporting a traceback that names
        # neither the file nor the remedy. Truncation is the realistic cause --
        # save() is atomic now, but a full disk or a restored-by-hand file is
        # not.
        raise StateError(
            f"{STATE_JSON} is not readable JSON ({exc}). Repair it or delete "
            "it -- deleting it falls back to the default protocol set, which "
            "is not the set you had: check `protocol list` afterwards."
        ) from None
    if not isinstance(data, dict):
        raise StateError(
            f"{STATE_JSON} does not contain a JSON object. This is not a "
            "state.json; nothing was changed."
        )

    # Written since the first version and read by nothing until now, which meant
    # a state.json from a newer vpnctl loaded silently and lost whatever field
    # this code does not know -- on the next save(). Same reasoning as
    # users_store: code rolls back (push.sh will rsync an older checkout over a
    # newer one), the file only moves forward.
    version = data.get("schema_version", SCHEMA_VERSION)
    if not isinstance(version, int) or version > SCHEMA_VERSION:
        raise StateError(
            f"{STATE_JSON} has schema {version!r}, this vpnctl understands "
            f"{SCHEMA_VERSION}. The state file is newer than the code -- deploy "
            "the matching version. Nothing was changed."
        )

    return (
        State(
            enabled=data.get("enabled", []),
            revoke_pending=data.get("revoke_pending", []),
            last_applied=data.get("last_applied", []),
            converge_pending=data.get("converge_pending", False),
        ),
        False,
    )


def save(state: State) -> None:
    """Write atomically, at 0600, with the mode set before any content exists.

    The same discipline as users_store.save and secrets_store.write, and for a
    sharper reason: this file holds the two intents that must outlive the
    command that formed them. `write_text` truncates in place, so an interrupted
    save left a file that parses as nothing -- and a state.json that cannot be
    read is a `revoke_pending` nobody retries (a certificate stays valid after a
    `user rm` reported success) and a `converge_pending` nobody clears (sing-box
    serves the old keys while every port is bound and `smoke` passes). Losing
    the file entirely is survivable and loud; losing its *contents* is neither.
    """
    payload = {"schema_version": SCHEMA_VERSION, **asdict(state)}
    STATE_JSON.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_JSON.with_name(STATE_JSON.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(payload, indent=2) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, STATE_JSON)
    finally:
        tmp.unlink(missing_ok=True)


def enabled_protocols(state: State | None = None) -> list[protocols.Protocol]:
    st = state or load()
    return protocols.ordered([n for n in st.enabled if n in protocols.PROTOCOLS])
