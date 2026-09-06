"""state.json -- which protocols are on, and what still needs undoing.

Separate from users.json on purpose: users.json answers "who has access",
state.json answers "what is this server currently running". They change for
different reasons and at different times.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from vpnctl import protocols
from vpnctl.paths import STATE_JSON

SCHEMA_VERSION = 1


@dataclass
class State:
    enabled: list[str] = field(default_factory=list)
    # Revocations that could not be executed when they were requested (the
    # container was down). The intent has to outlive the deleted user record,
    # or a `user rm` with ikev2 stopped silently leaves a working certificate.
    revoke_pending: list[str] = field(default_factory=list)
    # What `apply` last actually brought up, so it can diff and explicitly tear
    # down what is no longer enabled -- `--remove-orphans` does not do this.
    last_applied: list[str] = field(default_factory=list)


def default() -> State:
    return State(enabled=[p.name for p in protocols.ordered() if p.default_enabled])


def load() -> State:
    if not STATE_JSON.exists():
        return default()
    data = json.loads(STATE_JSON.read_text())
    return State(
        enabled=data.get("enabled", []),
        revoke_pending=data.get("revoke_pending", []),
        last_applied=data.get("last_applied", []),
    )


def save(state: State) -> None:
    payload = {"schema_version": SCHEMA_VERSION, **asdict(state)}
    STATE_JSON.parent.mkdir(parents=True, exist_ok=True)
    STATE_JSON.write_text(json.dumps(payload, indent=2) + "\n")
    STATE_JSON.chmod(0o600)


def enabled_protocols(state: State | None = None) -> list[protocols.Protocol]:
    st = state or load()
    return protocols.ordered([n for n in st.enabled if n in protocols.PROTOCOLS])
