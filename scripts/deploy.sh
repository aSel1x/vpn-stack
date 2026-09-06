#!/bin/bash
# The single deploy path. CI calls it, `./vpn deploy` calls it, and because
# there is only one, the manual route cannot drift from the automated one.
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
