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
# It runs in five separate SSH sessions rather than one long heredoc. That is
# deliberate: the firewall step has to be able to prove a *fresh* connection
# still works before it disarms its own safety net, and it cannot do that from
# inside the connection it might be about to sever.
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
on "bash $REPO_PATH/scripts/provision-host.sh code $REPO_PATH"

# ------------------------------------------------------------- 4. the firewall
# This is the step that locks people out, so it is the only one with a safety
# net: a detached timer that disables ufw unconditionally, armed *before* the
# first `ufw enable` and disarmed only after a brand-new SSH connection -- one
# that had to pass through the new rules -- succeeds.
step "firewall (armed with a ${DEADMAN_SECONDS}s deadman)"
on bash -s -- "$DEADMAN_SECONDS" <<'REMOTE'
set -euo pipefail
SECONDS_TO_LIVE="$1"
# The subshell records its *own* pid: `$!` is unreliable here because setsid
# forks when the caller is already a process-group leader. setsid also makes it
# a group leader, so a negative-pid kill takes the sleep down with it.
setsid sh -c "echo \$\$ > /run/vpn-stack.deadman
              sleep $SECONDS_TO_LIVE
              ufw --force disable
              rm -f /run/vpn-stack.deadman" </dev/null >/dev/null 2>&1 &
# Give it a moment to write the pid file, or the disarm below finds nothing.
for _ in 1 2 3 4 5 6 7 8 9 10; do [[ -s /run/vpn-stack.deadman ]] && break; sleep 0.2; done
[[ -s /run/vpn-stack.deadman ]] || { echo "deadman failed to arm; refusing to touch ufw" >&2; exit 1; }

ufw allow 22/tcp comment 'vpn-stack:ssh' >/dev/null
if ufw status 2>/dev/null | grep -q '^Status: active'; then
  echo "   ufw was already active; added 22/tcp and left your rules alone"
else
  echo "   ufw was inactive; enabling it (existing rules are kept, not reset)"
  ufw --force enable >/dev/null
fi
ufw status | head -1
REMOTE

# A fresh connection: new TCP handshake, evaluated by the rules just installed.
# Reusing the session above would prove nothing -- an established conntrack
# entry survives a firewall that would reject every new one.
step "verifying SSH still works through the new rules"
if ssh "${ssh_opts[@]}" -o ControlMaster=no -o ControlPath=none \
       -o BatchMode=yes "$TARGET" true; then
  echo "  fresh connection accepted -- disarming the deadman"
  on 'pid=$(cat /run/vpn-stack.deadman 2>/dev/null || true)
      [[ -n "$pid" ]] && { kill -TERM -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null; }
      rm -f /run/vpn-stack.deadman; true'
else
  echo
  echo "  A fresh SSH connection FAILED after enabling ufw." >&2
  echo "  Leaving the deadman armed: ufw disables itself within" >&2
  echo "  ${DEADMAN_SECONDS}s of it being enabled. Wait, then re-run." >&2
  exit 1
fi

# ------------------------------------------------------------- 5. bring it up
step "rendering and converging"
on "vpnctl apply"

step "smoke test"
on "cd $REPO_PATH && bash scripts/smoke.sh"

cat <<DONE

Done. Next:

  ./vpn user add <name>
  ./vpn user export <name> --qr     # QR in your terminal
  ./vpn share <name>                # one-shot page for a phone on your LAN
DONE
