#!/bin/bash
# The single definition of "is this sing-box config valid?".
#
# Called by vpnctl before promoting a candidate tree, and by deploy.sh before
# restarting anything. Previously this command existed in three places that had
# to be kept in sync (compose.yml, sbctl.py, the CI workflow); it now lives here.
#
#   scripts/check.sh <sing-box-config-dir>
#
# Takes a directory so it can validate a *candidate* tree that is not live yet.
set -euo pipefail

DIR="${1:?usage: check.sh <sing-box-config-dir>}"

# Read the tag out of compose.yml rather than restating it. Two literals drift,
# and the drift is invisible: the config validates against one binary and is
# then served by a different one. A comment saying "keep these in sync" is not
# a mechanism.
if [[ -z "${SING_BOX_IMAGE:-}" ]]; then
  SING_BOX_IMAGE="$(sed -n 's|^[[:space:]]*image:[[:space:]]*\(ghcr\.io/sagernet/sing-box:.*\)$|\1|p' \
                     "$(dirname "$0")/../compose.yml" | head -1)"
fi
[[ -n "$SING_BOX_IMAGE" ]] || {
  echo "check.sh: no sing-box image found in compose.yml" >&2; exit 2; }
IMAGE="$SING_BOX_IMAGE"

[[ -d "$DIR" ]] || { echo "check.sh: no such directory: $DIR" >&2; exit 2; }

# `docker run` rather than `docker compose run`: this must be able to validate an
# arbitrary directory, including one the compose file knows nothing about.
exec docker run --rm \
  -v "$(readlink -f "$DIR")":/etc/sing-box:ro \
  --entrypoint sing-box \
  "$IMAGE" check -C /etc/sing-box
