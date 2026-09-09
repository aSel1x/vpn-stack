"""Proof that the suite cannot touch the live state directory.

Not a test of vpnctl so much as a test of the tests: every other file here
writes through the module-level path constants, and those were frozen at import
from $VPN_STATE_DIR. If one of them is still rooted at /etc/vpn-stack, the
suite runs green while editing a real server's credentials.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import STATE_ROOT

from vpnctl import paths, render, secrets_store, state, users_store
from vpnctl.protocols import dnstt

# Every constant that names live state. Listed by hand: a loop over dir(paths)
# would also pick up the ROOT-based ones, which are supposed to be in the
# checkout, and pass by not noticing.
LIVE = [
    paths.STATE_DIR,
    paths.SECRETS_DIR,
    paths.USERS_JSON,
    paths.STATE_JSON,
    paths.RENDERED_LINK,
    paths.ENV_FILE,
    secrets_store.SECRETS_DIR,
    users_store.USERS_JSON,
    state.STATE_JSON,
]


@pytest.mark.parametrize("path", LIVE, ids=str)
def test_live_paths_are_inside_the_temporary_state_dir(path: Path) -> None:
    assert path.is_relative_to(STATE_ROOT)
    assert not path.is_relative_to(paths.DEFAULT_STATE_DIR)


def test_modules_that_import_the_constants_got_the_test_value() -> None:
    # `from vpnctl.paths import X` binds the value, not the module attribute,
    # so patching paths.STATE_DIR later would fix nothing. This asserts the
    # bindings agree, which is the reason conftest sets the env var at import.
    assert users_store.USERS_JSON == paths.USERS_JSON
    assert secrets_store.SECRETS_DIR == paths.SECRETS_DIR
    assert state.STATE_JSON == paths.STATE_JSON


def test_code_paths_stay_in_the_checkout() -> None:
    assert paths.SING_BOX_COMMON.is_relative_to(paths.ROOT)
    assert paths.SCRIPTS_DIR.is_relative_to(paths.ROOT)


def test_dnstt_zone_came_from_the_environment_not_a_live_env_file() -> None:
    # render.dnstt_zone() consults os.environ before ENV_FILE, deliberately
    # (that is compose's own precedence). The suite relies on it: no .env here.
    assert render.dnstt_zone() == "tests.invalid"
    assert not paths.ENV_FILE.exists()
    # And the read happens there, at the edge, not in the protocol module: a
    # module global resolved at import is what made share() unusable to any
    # caller holding only (secrets, user, host).
    assert not hasattr(dnstt, "ZONE")
    assert render.snapshot().text(dnstt.ZONE_KEY) == "tests.invalid"
