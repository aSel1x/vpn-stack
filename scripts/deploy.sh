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
# --no-dev: uv syncs the `dev` group by DEFAULT, so a plain `uv sync` installs
# pytest and its transitive deps onto the VPN server. The server runs vpnctl;
# it has no business carrying a test runner. Sync makes the environment match,
# so this also removes one a previous deploy left behind.
uv sync --frozen --no-dev
# Under the lock every other call site takes (./vpn's remote(), the boot unit,
# install.sh). A deploy that overlapped an operator's `./vpn user add` had two
# processes rendering candidate trees over each other -- the one race the atomic
# promote downstream cannot save you from, because both halves are valid, they
# are just from different inputs.
#
# vpnctl now takes this same lock itself for every mutating command, and this
# one still earns its place: it is held across the whole remote script above --
# the uv sync as well as the apply -- while vpnctl's own window is just its
# process, and vpnctl's is non-blocking, so overlapping runs would be refused
# rather than serialised.
#
# VPN_STACK_LOCK_HELD is what stands that inner lock down, and it is not
# optional: flock(1) inside flock(1) on the same path from a child process opens
# a second file description and blocks forever -- measured, not assumed -- so
# the inner lock has to be able to see that the outer one is already held.
export VPN_STACK_LOCK_HELD=1
flock /run/vpn-stack.lock vpnctl apply
REMOTE

echo "==> smoke test"
# Single-quoted on the far side: REPO_PATH comes from the environment, and an
# unquoted path with a space in it is re-split by the remote shell into two
# arguments -- the hazard ./vpn's remote() spells out at length.
# shellcheck disable=SC2086
ssh $SSH_OPTS "$TARGET" "cd '$REPO_PATH' && bash scripts/smoke.sh"
