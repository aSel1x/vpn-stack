#!/bin/bash
# Bare Ubuntu VPS -> serving VPN, in one command. Idempotent; safe to re-run.
#
#   scripts/install.sh root@<ip>
#
# This is the laptop path, and the single definition of one: orchestration over
# SSH, plus the firewall proof. Everything the server can do to itself lives in
# scripts/provision-host.sh, which the app runs too -- a second copy of those
# steps would drift, and the drift only shows up on a box nobody has yet. Keep
# every step re-runnable: an install that fails halfway must be fixable by
# running it again, not by hand-editing the server.
#
# It runs in several separate SSH sessions rather than one long heredoc. That is
# deliberate, and the count is not the point -- it moves whenever the steps do:
# the firewall step has to be able to prove a *fresh* connection still works
# before it disarms its own safety net, and it cannot do that from inside the
# connection it might be about to sever.
set -euo pipefail

TARGET="${1:?usage: install.sh <user@host>}"; shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    # Accepted and ignored: install.sh used to clone from GitHub. It now pushes
    # the checkout it lives in, so there is no URL to point anywhere.
    --repo) echo "note: --repo is obsolete; the local checkout is pushed" >&2; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

HOST="${TARGET#*@}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Single-quoted wherever it is spliced into a remote command below: it comes
# from the environment, and an unquoted path with a space in it becomes two
# arguments on the far side of ssh -- the same re-splitting `./vpn`'s remote()
# exists to prevent.
REPO_PATH="${VPN_REMOTE_PATH:-/opt/vpn-stack}"
DEADMAN_SECONDS=180

ssh_opts=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15)
[[ -n "${VPN_SSH_KEY:-}" ]] && ssh_opts+=(-i "$VPN_SSH_KEY")

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

on()   { ssh "${ssh_opts[@]}" "$TARGET" "$@"; }

# --------------------------------------------------------------- 0. a key
# Five sessions follow. Without a key that is five password prompts, and the
# deadman verification below cannot run in BatchMode at all.
if ! ssh "${ssh_opts[@]}" -o BatchMode=yes "$TARGET" true 2>/dev/null; then
  KEY="${VPN_SSH_KEY:-$HOME/.ssh/vpn-stack_ed25519}"
  step "installing an SSH key ($KEY)"
  [[ -f "$KEY" ]] || ssh-keygen -t ed25519 -f "$KEY" -N '' -C "vpn-stack operator"
  ssh-copy-id -i "$KEY.pub" -o StrictHostKeyChecking=accept-new "$TARGET"
  ssh_opts+=(-i "$KEY")
fi

# ---------------------------------------------------------------- 1. the host
# scripts/provision-host.sh is the single definition of the server-local half,
# shared with the app so the two cannot drift. Piped in rather than called by
# path: this is the stage that installs git and rsync, so neither delivery
# mechanism has run yet and there is nothing on the box to call.
step "provisioning $HOST"
on bash -s -- base "$HOST" < "$HERE/provision-host.sh"

# ---------------------------------------------------------------- 2. the code
step "pushing the checkout to $REPO_PATH"
SSH_OPTS="${ssh_opts[*]}" bash "$HERE/push.sh" "$TARGET" "$REPO_PATH"

# ------------------------------------------------- 3. vpnctl, and the keyring
# The same script's second stage, now that there is a checkout to run it from.
# It ends in `vpnctl bootstrap`, which never overwrites an existing secret
# without --force -- so a re-run of a half-finished install cannot invalidate a
# profile already handed out.
step "installing vpnctl and generating the keyring"
on "bash '$REPO_PATH/scripts/provision-host.sh' code '$REPO_PATH'"

# ------------------------------------------------------------- 4. the firewall
# This is the step that locks people out, so it is the only one with a safety
# net: a detached timer that disables ufw unconditionally, armed *before* the
# first `ufw enable` and disarmed only after a brand-new SSH connection -- one
# that had to pass through the new rules -- succeeds.
#
# Arming, opening ssh and disarming are all in provision-host.sh: the net also
# exists in Dart (app/lib/provision/firewall.dart), and a third hand-written
# copy here is how two of them end up behaving differently on the one box where
# it matters. Piped in over stdin exactly like the `base` stage, not called by
# path, so this step depends on no checkout having arrived and can be moved
# between the stages -- which is where the app runs its own equivalent.
#
# Which port to open is a question only the server can answer, and it is asked
# there: 22 was hardcoded, so against an sshd on 2222 ufw came up with only 22
# open, the proof below failed, this script exited 1, the deadman restored
# access three minutes later, and the identical re-run failed identically with
# nothing in the output mentioning the port.
step "firewall (armed with a ${DEADMAN_SECONDS}s deadman)"
on bash -s -- firewall "$DEADMAN_SECONDS" < "$HERE/provision-host.sh"

# A fresh connection: new TCP handshake, evaluated by the rules just installed.
# Reusing the session above would prove nothing -- an established conntrack
# entry survives a firewall that would reject every new one.
step "verifying SSH still works through the new rules"
if ssh "${ssh_opts[@]}" -o ControlMaster=no -o ControlPath=none \
       -o BatchMode=yes "$TARGET" true; then
  echo "  fresh connection accepted -- disarming the deadman"
  # Exits non-zero if the timer is still breathing afterwards, and `set -e`
  # stops the install there: finishing while an armed deadman counts down would
  # hand back a box whose firewall turns itself off minutes later.
  on bash -s -- firewall-disarm < "$HERE/provision-host.sh"
else
  echo
  echo "  A fresh SSH connection FAILED after enabling ufw." >&2
  echo "  Leaving the deadman armed: ufw disables itself within" >&2
  echo "  ${DEADMAN_SECONDS}s of it being enabled. Wait, then re-run." >&2
  exit 1
fi

# ------------------------------------------------------------- 5. bring it up
step "rendering and converging"
# Under the lock, like every other call site: vpnctl takes none of its own, and
# an apply that interleaves with somebody's `./vpn user add` has two candidate
# trees rendering over each other -- the one thing the atomic promote downstream
# cannot save you from. VPN_STACK_LOCK_HELD is the handshake for the day vpnctl
# locks internally: an flock(1) inside an flock(1) on the same path from a child
# process opens a second file description and blocks forever (measured), so the
# inner lock has to be able to see that the outer one is already held.
on "VPN_STACK_LOCK_HELD=1 flock /run/vpn-stack.lock vpnctl apply"

step "smoke test"
on "cd '$REPO_PATH' && bash scripts/smoke.sh"

cat <<DONE

Done. Next:

  ./vpn user add <name>
  ./vpn user export <name> --qr     # QR in your terminal
  ./vpn share <name>                # one-shot page for a phone on your LAN
DONE
