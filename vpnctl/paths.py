"""Every path constant. Nothing else in vpnctl builds a path inline.

Two roots, deliberately separate:

  ROOT       the git checkout -- code, and only code. A clone therefore
             structurally cannot contain a credential.
  STATE_DIR  live state: secrets, users.json, state.json, the rendered config.
             0700 root, outside the repo, never synced by anything.

STATE_DIR is /etc/vpn-stack, or $VPN_STATE_DIR for tests. There is no fallback
to ROOT: falling back meant that running a mutating command in a checkout wrote
live credentials into the repo instead of failing, which is exactly what
guard.py exists to prevent. If the directory is not there, this is not the
server, and vpnctl says so.
"""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DEFAULT_STATE_DIR = Path("/etc/vpn-stack")


def _resolve_state_dir() -> Path:
    explicit = os.environ.get("VPN_STATE_DIR")
    return Path(explicit).resolve() if explicit else DEFAULT_STATE_DIR


STATE_DIR = _resolve_state_dir()

# --- live state (STATE_DIR) -------------------------------------------------

SECRETS_DIR = STATE_DIR / "secrets"
USERS_JSON = STATE_DIR / "users.json"
STATE_JSON = STATE_DIR / "state.json"
RENDERED_LINK = STATE_DIR / "rendered"

# `.env` must stay readable by `docker compose` from the project directory, so
# ROOT/.env is a symlink to this file rather than a second copy.
ENV_FILE = STATE_DIR / ".env"
REPO_ENV_LINK = ROOT / ".env"

# --- code (ROOT) ------------------------------------------------------------

SING_BOX_COMMON = ROOT / "sing-box" / "common"
SCRIPTS_DIR = ROOT / "scripts"

# --- containers -------------------------------------------------------------

IKEV2_CONTAINER_NAME = "ipsec-vpn-server"
COMPOSE_PROJECT = "vpn-stack"


def rendered_dir() -> Path:
    """The live rendered tree (follows the atomic symlink)."""
    return RENDERED_LINK
