#!/bin/bash
# The single definition of "what gets sent to the server".
#
#   scripts/push.sh <user@host> [remote-path]
#
# Both install.sh and deploy.sh call this and nothing else transfers code, so
# the one dangerous flag combination in this repo exists in exactly one place.
#
# Why rsync instead of `git clone` on the server: this sends the WORKING TREE,
# uncommitted changes included. A clone can only deliver what has already been
# pushed to GitHub, so trying a one-line fix on the real box would mean
# committing it first -- and taking it back would mean committing again.
#
# Not because the repo is private: it went public on 2026-09-11, and the app
# provisions a server by cloning it with no credential at all.
set -euo pipefail

TARGET="${1:?usage: push.sh <user@host> [remote-path]}"
REPO_PATH="${2:-${REPO_PATH:-/opt/vpn-stack}}"
SSH_OPTS="${SSH_OPTS:--o StrictHostKeyChecking=accept-new}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --filter=':- .gitignore' is NOT optional. Without it a developer checkout
# pushes its own users.json, .env, rendered fragments and certs over the
# server's live ones.
#
# --delete, and the pairing with that filter is the whole point. Without it a
# file deleted from the repo lives on every server that was ever pushed to:
# scripts/host-bootstrap.sh was removed here and is still sitting in
# /opt/vpn-stack on boxes pushed before it went, executable, and one `bash
# scripts/host-bootstrap.sh` away from re-running a provisioning step that no
# longer matches anything.
#
# NOT --delete-excluded, which is a different flag with an opposite meaning:
# --delete removes what the sender no longer has *and does not send*, while
# --delete-excluded additionally removes everything the filter excluded -- so it
# would delete from the SERVER the very files that filter exists to protect:
# /opt/vpn-stack/.env (the symlink into /etc/vpn-stack), any rendered fragment,
# any cert. Excluding means "do not send", never "remove there".
#
# app/ and notes/ are excluded by path and not left to .gitignore, because the
# filter only knows what git ignores and the app is tracked. A VPN server has no
# use for ten thousand lines of Dart, and after one local `flutter build` the
# payload would grow a whole build tree and carry it over SSH onto the VPS.
#
# mkdir over ssh rather than rsync --mkpath: --mkpath needs rsync >= 3.2.3 and
# this has to work from whatever the operator's laptop happens to ship.
# shellcheck disable=SC2086
ssh $SSH_OPTS "$TARGET" "mkdir -p '$REPO_PATH'"

# --chown=root:root, because -a preserves the *operator's* uid and gid and this
# lands a tree that root executes: on a laptop whose user is 1000, /opt/vpn-stack
# came out owned by uid 1000, which on the server is either nobody or some other
# account entirely -- and that account can then rewrite the code `vpnctl` runs as
# root. push.sh always connects as root (install.sh and deploy.sh both take
# root@host), so there is nothing to lose by saying so.
# shellcheck disable=SC2086
exec rsync -az --delete --chown=root:root \
  --filter=':- .gitignore' \
  --exclude '.git/' --exclude '.github/' --exclude '.venv/' \
  --exclude 'app/' --exclude 'notes/' \
  -e "ssh $SSH_OPTS" \
  "$HERE/" "$TARGET:$REPO_PATH/"
