#!/bin/bash
# The single deploy path, called by `./vpn deploy` and nothing else.
#
#   scripts/deploy.sh <user@host>
#
# Deliberately does NOT bootstrap. On a server whose state directory has been
# damaged, generating fresh secrets would silently invalidate every profile
# already handed out; `vpnctl apply` fails loudly instead and tells you to run
# `vpnctl bootstrap` or restore a backup. Only install.sh bootstraps.
set -euo pipefail

TARGET="${1:?usage: deploy.sh <user@host>}"
SSH_OPTS="${SSH_OPTS:--o StrictHostKeyChecking=accept-new}"
REPO_PATH="${REPO_PATH:-/opt/vpn-stack}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# A deploy is not an install, and it should say so. Against a rebuilt server
# this used to rsync the code and then die on `uv: command not found` -- exit
# 127, five lines deep, explaining nothing. Checked before the rsync, so a bare
# box is not left with a half-populated /opt/vpn-stack either.
# shellcheck disable=SC2086
missing=$(ssh $SSH_OPTS "$TARGET" '
  PATH="/usr/local/bin:/root/.local/bin:$PATH"
  [ -x /usr/local/bin/vpnctl ] || echo "  /usr/local/bin/vpnctl"
  [ -d /etc/vpn-stack ]        || echo "  /etc/vpn-stack (secrets, users)"
  command -v uv >/dev/null     || echo "  uv"' 2>/dev/null) || true
if [[ -n "$missing" ]]; then
  {
    echo "$TARGET is not provisioned. Missing:"
    echo "$missing"
    echo
    echo "deploy only updates an existing install. Run this once, from a"
    echo "checkout, to set the server up:"
    echo "    ./vpn init $TARGET"
  } >&2
  exit 1
fi

echo "==> syncing code to $TARGET:$REPO_PATH"
SSH_OPTS="$SSH_OPTS" bash "$HERE/push.sh" "$TARGET" "$REPO_PATH"

echo "==> validating and converging"
# `uv` lives in /root/.local/bin, which a non-interactive SSH session does not
# have on its PATH. install.sh symlinks it into /usr/local/bin; this is the
# belt to that braces, so a server provisioned some other way still deploys.
# shellcheck disable=SC2086
ssh $SSH_OPTS "$TARGET" bash -s -- "$REPO_PATH" <<'REMOTE'
set -euo pipefail
REPO_PATH="$1"
export PATH="/usr/local/bin:/root/.local/bin:$PATH"
cd "$REPO_PATH"
uv sync --frozen
vpnctl apply
REMOTE

echo "==> smoke test"
# shellcheck disable=SC2086
ssh $SSH_OPTS "$TARGET" "cd $REPO_PATH && bash scripts/smoke.sh"
