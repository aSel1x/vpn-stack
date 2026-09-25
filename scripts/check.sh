#!/bin/bash
# The single definition of "is this sing-box config valid?".
#
# One caller: vpnctl/sbctl.py, on the candidate tree, before `apply` promotes
# it. Nothing else. This header used to name deploy.sh as a second caller, which
# it never was -- deploy.sh reaches this only through the `vpnctl apply` it runs
# on the server, and CI does not run it at all (it has no keyring to render a
# tree from). That matters when reading a deploy's output: nothing local
# validated anything. Previously the command itself existed in three places that
# had to be kept in sync (compose.yml, sbctl.py, the CI workflow); the command
# now lives here, which is the part that was true.
#
#   scripts/check.sh <sing-box-config-dir>
#
# Takes a directory so it can validate a *candidate* tree that is not live yet.
#
# Its scope is the sing-box tree and nothing else, which is a real gap and not a
# simplification: `sing-box check` reads *.json out of one -C directory, so
# ikev2.env, dnstt.env and dnstt-sshd/logins are promoted with nothing having
# looked at them. A malformed logins line is found by the dnstt-sshd entrypoint
# at container start, i.e. after the symlink swap, which is the wrong side of the
# "the live tree was never touched" guarantee. Whatever validates those belongs
# in the renderer that produces them, not here.
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
