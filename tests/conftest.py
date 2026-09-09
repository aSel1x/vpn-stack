"""Fixtures, and the one thing that keeps this suite off a real server.

paths.py resolves STATE_DIR **at import**, once, from $VPN_STATE_DIR. So the
variable has to be set before anything imports vpnctl -- which is why it
happens in this module's body rather than in a fixture. Get that wrong and the
suite does not fail, it succeeds against /etc/vpn-stack: the same shape as the
bug guard.py exists to stop, one level down.

Nothing here needs Docker, root or the network. The few functions that shell
out are faked in the test that needs them, at the narrowest seam available and
only inside the module under test -- ufw through firewall._ufw, ss through
composectl's own `subprocess` binding.
"""

from __future__ import annotations

import atexit
import hashlib
import os
import shutil
import tempfile
from pathlib import Path

_STATE_ROOT = Path(tempfile.mkdtemp(prefix="vpn-stack-tests-")).resolve()
os.environ["VPN_STATE_DIR"] = str(_STATE_ROOT)
# A zone nobody has delegated, on purpose. dnstt no longer reads this itself --
# render.dnstt_zone() does, at the edge -- but anything exercising that edge
# (render.snapshot, render.missing_deployment_config) needs it set, and the
# state directory has no .env for it to fall back to.
ZONE = "tests.invalid"
os.environ["VPN_DNSTT_ZONE"] = ZONE
atexit.register(shutil.rmtree, _STATE_ROOT, True)

import pytest  # noqa: E402
from vpnctl import paths, secrets_store, users_store  # noqa: E402
from vpnctl.protocols import dnstt, hysteria2, ikev2, vless_reality  # noqa: E402

STATE_ROOT = _STATE_ROOT

# A Noise keypair in dnstt's own on-disk shape (hex + newline), fixed so share
# links are comparable across runs. Not generated: minting one needs the
# dnstt-server binary, which needs Docker, which this suite must not need.
DNSTT_KEY = b"a" * 64 + b"\n"
DNSTT_PUB = b"b" * 64 + b"\n"


@pytest.fixture(autouse=True)
def state_dir() -> Path:
    """An empty state directory per test, and a re-check that it is not live.

    Asserted every test rather than once per session: a test that reassigns a
    path constant would otherwise poison every test after it, silently.
    """
    assert paths.STATE_DIR == STATE_ROOT
    assert paths.STATE_DIR != paths.DEFAULT_STATE_DIR
    shutil.rmtree(STATE_ROOT, ignore_errors=True)
    STATE_ROOT.mkdir(parents=True)
    STATE_ROOT.chmod(0o700)
    return STATE_ROOT


@pytest.fixture(scope="session")
def secret_values() -> dict[str, bytes]:
    """A complete keyring, as bytes, built by the protocols' own bootstrap().

    Session-scoped because hysteria2's bootstrap issues a real certificate.
    Handed out as a copy so no test can mutate another's input.
    """
    values: dict[str, bytes] = {}
    for proto in (vless_reality, hysteria2, ikev2):
        values |= proto.bootstrap()
    values["dnstt.server.key"] = DNSTT_KEY
    values["dnstt.server.pub"] = DNSTT_PUB
    return values


@pytest.fixture
def secrets(secret_values: dict[str, bytes]) -> secrets_store.Secrets:
    """What render()/share() are handed: in memory, no files at all.

    The keyring plus dnstt's zone, because the snapshot carries both -- that is
    render.snapshot()'s job on a server, and the reason share() can be a pure
    function of its arguments. Kept out of secret_values so written_keyring
    does not lay deployment config down as a file in the keyring.
    """
    return secrets_store.Secrets(
        values={**secret_values, dnstt.ZONE_KEY: ZONE.encode()}
    )


@pytest.fixture
def written_keyring(secret_values: dict[str, bytes], state_dir: Path) -> Path:
    """The same keyring, on disk under the test state directory."""
    for name, content in secret_values.items():
        secrets_store.write(name, content)
    return paths.SECRETS_DIR


def _digest(name: str) -> str:
    # hash() is salted per process; two runs must render the same bytes.
    return hashlib.blake2s(name.encode()).hexdigest()[:12]


def make_user(name: str, **overrides) -> users_store.User:
    """A user record with fixed credentials -- no uuid4, no token_hex.

    Rendered output has to be comparable between two calls; generate_credentials
    makes that impossible.
    """
    fields = {
        "name": name,
        "vless_uuid": "00000000-0000-4000-8000-" + _digest(name),
        "hysteria2_password": f"hy2-{name}",
        "l2tp_password": f"l2tp-{name}",
        "ikev2_provisioned": False,
        "enabled": True,
        "created_at": "2026-01-01T00:00:00Z",
        "dnstt_password": f"dnstt{name}",
    }
    return users_store.User(**{**fields, **overrides})


@pytest.fixture
def users() -> list[users_store.User]:
    """Three shapes that matter: enabled, disabled, and pre-dnstt_password."""
    return [
        make_user("alice"),
        make_user("bob", enabled=False),
        make_user("carol", dnstt_password=""),
    ]


ALL_PROTOCOLS = (vless_reality, hysteria2, ikev2, dnstt)
