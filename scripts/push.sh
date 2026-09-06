#!/bin/bash
# The single definition of "what gets sent to the server".
#
#   scripts/push.sh <user@host> [remote-path]
#
# Both install.sh and deploy.sh call this and nothing else transfers code, so
# the one dangerous flag combination in this repo exists in exactly one place.
#
# Why rsync a working tree instead of `git clone` on the server: the repo is
# private, and a bare box has no credential for it. Requiring a deploy token
# just to install would make "type your IP and press go" impossible -- and the
# future app ships its own copy of this tree anyway, it does not clone GitHub.
set -euo pipefail

TARGET="${1:?usage: push.sh <user@host> [remote-path]}"
REPO_PATH="${2:-${REPO_PATH:-/opt/vpn-stack}}"
SSH_OPTS="${SSH_OPTS:--o StrictHostKeyChecking=accept-new}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --filter=':- .gitignore' is NOT optional. Without it a developer checkout
# pushes its own users.json, .env, rendered fragments and certs over the
# server's live ones.
#
# NOT --delete-excluded: that would delete the very files the filter protects
# (users.json, .env, secrets) from the SERVER. Excluding means "do not send",
# never "remove there".
# mkdir over ssh rather than rsync --mkpath: --mkpath needs rsync >= 3.2.3 and
# this has to work from whatever the operator's laptop happens to ship.
# shellcheck disable=SC2086
ssh $SSH_OPTS "$TARGET" "mkdir -p '$REPO_PATH'"

# shellcheck disable=SC2086
exec rsync -az \
  --filter=':- .gitignore' \
  --exclude '.git/' --exclude '.github/' --exclude '.venv/' \
  -e "ssh $SSH_OPTS" \
  "$HERE/" "$TARGET:$REPO_PATH/"
