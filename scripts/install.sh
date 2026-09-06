#!/bin/bash
# Bare Ubuntu VPS -> serving VPN, in one command. Idempotent; safe to re-run.
#
#   scripts/install.sh root@<ip> [--dry-run]
#
# --dry-run prints every command it would run, on both sides, and touches
# nothing. Read it before you trust it.
#
# This script is also the future app's entire deploy path: "type your IP and
# your root password" is this file executed over SSH. Keep it self-contained,
# and keep every step re-runnable -- an install that fails halfway must be
# fixable by running it again, not by hand-editing the server.
#
# It runs in five separate SSH sessions rather than one long heredoc. That is
# deliberate: the firewall step has to be able to prove a *fresh* connection
# still works before it disarms its own safety net, and it cannot do that from
# inside the connection it might be about to sever.
set -euo pipefail

TARGET="${1:?usage: install.sh <user@host>}"; shift || true
DRY="${VPN_DRY_RUN:-0}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--dry-run) DRY=1; shift ;;
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

# Every remote call goes through on(); under --dry-run it prints the script it
# would have piped in, indented, and runs nothing.
on() {
  if [[ "$DRY" == 1 ]]; then
    printf '\033[2m    ssh %s %s\033[0m\n' "$TARGET" "$*"
    if [[ ! -t 0 ]]; then sed 's/^/      | /'; fi
    return 0
  fi
  ssh "${ssh_opts[@]}" "$TARGET" "$@"
}

# --------------------------------------------------------------- 0. a key
# Five sessions follow. Without a key that is five password prompts, and the
# deadman verification below cannot run in BatchMode at all.
if [[ "$DRY" != 1 ]] && ! ssh "${ssh_opts[@]}" -o BatchMode=yes "$TARGET" true 2>/dev/null; then
  KEY="${VPN_SSH_KEY:-$HOME/.ssh/vpn-stack_ed25519}"
  step "installing an SSH key ($KEY)"
  [[ -f "$KEY" ]] || ssh-keygen -t ed25519 -f "$KEY" -N '' -C "vpn-stack operator"
  ssh-copy-id -i "$KEY.pub" -o StrictHostKeyChecking=accept-new "$TARGET"
  ssh_opts+=(-i "$KEY")
fi

# ---------------------------------------------------------------- 1. the host
step "provisioning $HOST"
on bash -s -- "$HOST" <<'REMOTE'
set -euo pipefail
HOST="$1"
export DEBIAN_FRONTEND=noninteractive

have() { command -v "$1" >/dev/null 2>&1; }
note() { printf '   %s\n' "$*"; }

# Docker's apt repository, not `curl https://get.docker.com | sh`. Same
# packages, but signed, upgradable with the rest of the system, and auditable
# before it runs -- which a piped shell script is not.
install_docker() {
  echo "-- installing docker from Docker's own apt repository"
  apt-get update -qq || true
  apt-get install -y -qq ca-certificates curl

  # The repository is behind CloudFront, which answers 403 to some IPv4 ranges
  # while serving the same bytes over IPv6. Choose a family that works instead
  # of failing three layers down with a bare 403 and no explanation.
  local family
  if curl -4 -fsS -m 15 -o /dev/null https://download.docker.com/linux/ubuntu/gpg 2>/dev/null; then
    family=4
  elif curl -6 -fsS -m 15 -o /dev/null https://download.docker.com/linux/ubuntu/gpg 2>/dev/null; then
    family=6
    note "IPv4 to download.docker.com is refused from this host; using IPv6"
  else
    echo "Cannot reach download.docker.com over IPv4 or IPv6." >&2
    echo "Install docker however you like and re-run: if docker is already on" >&2
    echo "PATH this script leaves it completely alone." >&2
    return 1
  fi

  install -m 0755 -d /etc/apt/keyrings
  curl -"$family" -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  . /etc/os-release
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$(dpkg --print-architecture)" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list

  if [[ "$family" == 6 ]]; then
    # Persisted rather than passed once: without it *your* next `apt update`
    # fails on this repository too. Named after the project so it is obvious
    # who put it there, and safe to delete the day IPv4 starts working.
    cat > /etc/apt/apt.conf.d/99-vpn-stack-ipv6 <<'APTCONF'
// download.docker.com (CloudFront) returns 403 to this host over IPv4 and
// serves the same files over IPv6. Without this, apt fails on the docker
// repository. Delete this file if IPv4 to Docker ever starts working.
Acquire::ForceIPv6 "true";
APTCONF
    if ! apt-get update -qq 2>/dev/null; then
      # The system's own mirror may have no IPv6. Do not leave apt broken.
      rm -f /etc/apt/apt.conf.d/99-vpn-stack-ipv6 /etc/apt/sources.list.d/docker.list
      apt-get update -qq || true
      echo "Docker's repository needs IPv6 from this host, but the system's" >&2
      echo "apt mirror is not reachable over IPv6. Reverted; install docker" >&2
      echo "yourself and re-run." >&2
      return 1
    fi
  else
    apt-get update -qq
  fi

  apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
                         docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
}

if have docker; then
  note "docker: already installed ($(docker --version 2>/dev/null | awk '{print $3}' | tr -d ,)) -- left alone"
else
  install_docker
fi
docker compose version >/dev/null 2>&1 || {
  echo "docker is present but 'docker compose' is not." >&2
  echo "Install the plugin (docker-compose-plugin, or Ubuntu's" >&2
  echo "docker-compose-v2) and re-run." >&2
  exit 1; }

for pkg in git rsync ufw iptables; do
  have "$pkg" || { echo "-- installing $pkg"; apt-get install -y -qq "$pkg"; }
done

if have uv; then
  note "uv: already installed ($(uv --version 2>/dev/null | awk '{print $2}')) at $(command -v uv) -- left alone"
else
  echo "-- installing uv"
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi

# systemd units and non-interactive SSH get a minimal PATH that does not
# include /root/.local/bin, where uv installs itself. Put a link where they
# will look -- but never replace a binary somebody else put there.
uv_path="$(command -v uv || true)"
[[ -n "$uv_path" ]] || { echo "uv is still not on PATH" >&2; exit 1; }
case "$uv_path" in
  /usr/local/bin/*|/usr/bin/*|/bin/*) ;;
  *)
    if [[ -e /usr/local/bin/uv ]]; then
      note "uv: /usr/local/bin/uv already exists -- left alone"
    else
      ln -s "$uv_path" /usr/local/bin/uv
      note "uv: linked /usr/local/bin/uv -> $uv_path (so systemd can find it)"
    fi ;;
esac

echo "-- state directory"
install -d -m 700 /etc/vpn-stack /etc/vpn-stack/secrets /etc/vpn-stack/data
grep -q '^VPN_SERVER_HOST=' /etc/vpn-stack/.env 2>/dev/null \
  || echo "VPN_SERVER_HOST=$HOST" >> /etc/vpn-stack/.env
chmod 600 /etc/vpn-stack/.env

# Said out loud because one of these is a loosening, not a hardening:
# rp_filter=0 is required by IPsec (the reply to a client arrives on a
# different path than strict reverse-path filtering expects). If you have
# hardened this box, this file is numbered 99 and wins.
echo "-- sysctls: ip_forward=1, rp_filter=0 (IPsec needs it), ip_no_pmtu_disc=1"
cat > /etc/sysctl.d/99-vpn-stack.conf <<'SYSCTL'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv6.conf.all.forwarding = 1
# MTU/MSS fix for mobile L2TP/IPsec and IKEv2 clients.
net.ipv4.ip_no_pmtu_disc = 1
SYSCTL
sysctl --system >/dev/null

# The image's IKEv2 mode needs /dev/ppp to exist at container-create time, and
# on a freshly booted kernel the module is not loaded until something asks.
# Without this, `docker compose up ikev2` fails with a device error.
echo "-- ppp module"
modprobe ppp_generic 2>/dev/null || true
echo ppp_generic > /etc/modules-load.d/vpn-stack.conf

echo "-- boot unit (FORWARD rules do not survive a reboot on their own)"
cat > /etc/systemd/system/vpn-stack.service <<'UNIT'
[Unit]
Description=vpn-stack: render config, converge containers and firewall
After=docker.service network-online.target
Wants=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/vpnctl apply

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable vpn-stack.service >/dev/null
REMOTE

# ---------------------------------------------------------------- 2. the code
step "pushing the checkout to $REPO_PATH"
VPN_DRY_RUN="$DRY" SSH_OPTS="${ssh_opts[*]}" bash "$HERE/push.sh" "$TARGET" "$REPO_PATH"

step "installing vpnctl"
on bash -s -- "$REPO_PATH" <<'REMOTE'
set -euo pipefail
REPO_PATH="$1"
cd "$REPO_PATH"
ln -sfn /etc/vpn-stack/.env "$REPO_PATH/.env"
uv sync --frozen

# The shim prepends uv's own directory rather than trusting the caller's PATH:
# systemd and non-interactive ssh both invoke this with a minimal environment.
cat > /usr/local/bin/vpnctl <<SHIM
#!/bin/sh
PATH="/usr/local/bin:/root/.local/bin:\$PATH"
export PATH
cd "$REPO_PATH" && exec uv run vpnctl "\$@"
SHIM
chmod 755 /usr/local/bin/vpnctl
vpnctl --help >/dev/null
REMOTE

# -------------------------------------------------------------- 3. the keyring
step "generating the keyring"
on "vpnctl bootstrap"

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
if [[ "$DRY" == 1 ]]; then
  printf '\033[2m    ssh -o ControlMaster=no -o ControlPath=none %s true\033[0m\n' "$TARGET"
  printf '\033[2m    (on success) kill the deadman; on failure, leave it armed\033[0m\n'
elif ssh "${ssh_opts[@]}" -o ControlMaster=no -o ControlPath=none \
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

[[ "$DRY" == 1 ]] && { echo; echo "(--dry-run: nothing above was executed)"; exit 0; }

cat <<DONE

Done. Next:

  ./vpn user add <name>
  ./vpn user export <name> --qr     # QR in your terminal
  ./vpn share <name>                # one-shot page for a phone on your LAN
DONE
