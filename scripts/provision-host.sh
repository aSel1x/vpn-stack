#!/bin/bash
# The server-local half of an install: everything a box can do to itself, in one
# place, so install.sh and the app share one definition of how a host is
# prepared rather than keeping two that drift.
#
#   scripts/provision-host.sh base <server-host>
#   scripts/provision-host.sh code <repo-path>
#   scripts/provision-host.sh firewall <deadman-seconds>
#   scripts/provision-host.sh firewall-disarm
#
# Four stages, because the callers have to cut this apart at three different
# points and every cut lands here:
#
#   base   apt packages, docker, uv, /etc/vpn-stack, sysctls, /dev/ppp and the
#          boot unit. Needs no repository -- and has to run BEFORE one arrives,
#          because git and rsync are what deliver the code by either route and
#          this is what installs them. install.sh therefore pipes this stage in
#          over ssh (`bash -s -- base <host>`): there is nothing on the box to
#          call yet. The boot unit's ExecStart is /usr/local/bin/vpnctl, so it
#          needs no repo path either and belongs here, not with the code.
#   code   the .env symlink, `uv sync`, the /usr/local/bin/vpnctl shim, and the
#          keyring. Runs from the checkout, however it got there -- rsynced by
#          install.sh or cloned by the app.
#   firewall / firewall-disarm
#          arm the deadman, open ssh, enable ufw -- and, after somebody else has
#          proved a fresh connection survives, kill the timer. The *proving* is
#          deliberately not here and cannot be: a process on this box cannot
#          show from inside one connection that a *different* one would be
#          accepted. install.sh does that between the two calls, and the app
#          does its own equivalent.
#
# The arm/disarm pair lives here rather than inline in install.sh because it
# also exists in Dart (app/lib/provision/firewall.dart), and a safety net with
# three implementations is a safety net whose behaviour nobody knows. This is
# the shell definition; install.sh pipes this file in over stdin for it, exactly
# as it does for `base`, so the step keeps no dependency on a checkout having
# landed yet and can be moved between the stages without breaking.
#
# Every stage is idempotent: an install that fails halfway has to be fixable by
# running it again, not by hand-editing the server. That includes the firewall
# one -- arming over a timer that is still alive is the failure it guards.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
# uv installs itself into /root/.local/bin, and a non-interactive SSH session
# does not have that on PATH. Set it before anything looks for uv, so both a
# fresh install and a uv left over from an earlier run are found. /usr/local/bin
# is here for the vpnctl shim that `code` writes and then calls.
export PATH="/usr/local/bin:/root/.local/bin:$PATH"

have() { command -v "$1" >/dev/null 2>&1; }

# Not $0: install.sh pipes this stage in over ssh, where $0 is "bash".
usage() {
  cat >&2 <<'USAGE'
usage: provision-host.sh base <server-host>   # host setup; needs no checkout
       provision-host.sh code <repo-path>     # vpnctl and the keyring, from one
       provision-host.sh firewall <seconds>   # arm the deadman, then enable ufw
       provision-host.sh firewall-disarm      # kill the timer, after the proof
USAGE
}

# Where the armed timer records itself. One path, because it is the only thing
# on the box that knows a countdown is running: anything that loses track of it
# has lost the ability to stop `ufw --force disable` from firing later.
DEADMAN_PID_FILE=/run/vpn-stack.deadman

# Docker's own apt repository rather than `curl get.docker.com | sh`: signed,
# upgradable with the rest of the system, and readable before it runs.
install_docker() {
  echo "-- installing docker (apt, from download.docker.com)"
  apt-get update -qq || true
  apt-get install -y -qq ca-certificates curl

  # CloudFront fronts that repository and answers 403 to some IPv4 ranges while
  # serving the same bytes over IPv6. Pick a family that works, instead of
  # failing three layers down with a bare 403 and no explanation.
  # Debian and Ubuntu have separate Docker repositories, and the codename is only
  # valid in its own. Hardcoding ubuntu made `apt-get update` fail on a Debian
  # box with an unknown-codename line -- and `set -euo pipefail` then killed the
  # whole stage. The app's preflight accepts Debian, so the two disagreed about
  # what they supported. Verified on Ubuntu only; Debian is untested here.
  . /etc/os-release
  # Under `set -u` a bare "$VERSION_CODENAME" aborts the whole base stage on an
  # os-release that does not carry it -- some derivatives set only
  # UBUNTU_CODENAME -- and the abort names neither the variable nor the file.
  # Docker's repository is per codename, so there is no default to fall back on.
  local codename="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
  [[ -n "$codename" ]] || {
    echo "/etc/os-release names no VERSION_CODENAME or UBUNTU_CODENAME, so the" >&2
    echo "docker repository line cannot be written (it is per codename)." >&2
    echo "Install docker yourself and re-run: if it is present, this leaves" >&2
    echo "it completely alone." >&2
    return 1; }
  local distro=ubuntu
  case "${ID:-}" in
    debian) distro=debian ;;
    ubuntu) distro=ubuntu ;;
    *) case " ${ID_LIKE:-} " in
         *" debian "*) distro=debian ;;
       esac ;;
  esac
  local key="https://download.docker.com/linux/$distro/gpg" family=
  for f in 4 6; do
    if curl -"$f" -fsS -m 15 -o /dev/null "$key" 2>/dev/null; then family=$f; break; fi
  done
  [[ -n "$family" ]] || {
    echo "download.docker.com is unreachable over IPv4 and IPv6." >&2
    echo "Install docker yourself and re-run: if it is present, this leaves" >&2
    echo "it completely alone." >&2
    return 1; }
  [[ "$family" == 6 ]] && echo "   IPv4 to download.docker.com refused; using IPv6"

  install -m 0755 -d /etc/apt/keyrings
  curl -"$family" -fsSL "$key" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
    "$(dpkg --print-architecture)" "$distro" "$codename" > /etc/apt/sources.list.d/docker.list

  # Persisted, not passed once: otherwise *your* next `apt update` fails on
  # this repository too. Reverted rather than left behind if it turns out the
  # system's own mirror has no IPv6.
  [[ "$family" == 6 ]] && echo 'Acquire::ForceIPv6 "true";' > /etc/apt/apt.conf.d/99-vpn-stack-ipv6
  apt-get update -qq || {
    rm -f /etc/apt/apt.conf.d/99-vpn-stack-ipv6 /etc/apt/sources.list.d/docker.list
    apt-get update -qq || true
    echo "apt could not read the docker repository; reverted, nothing left behind." >&2
    return 1; }

  apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
                         docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
}

# ------------------------------------------------------------------ firewall
# TERM the process group, wait for it to actually be gone, then KILL. Used by
# both the arm (reaping a predecessor) and the disarm, so there is one answer to
# "is that timer dead?" rather than two.
#
# Under root a signal to a process of our own cannot be refused, so this is
# defence in depth rather than a failure anybody has seen. What it really buys
# is observability: the old disarm removed the pid file BEFORE killing anything,
# sent both kills' stderr to /dev/null and ended in `; true`, so `set -e` could
# not see a failure -- and if the kill had not landed, nothing was left on the
# box that knew a timer was still counting down towards disabling the firewall.
deadman_kill() {
  local pid="$1" _i
  kill -TERM -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  # Negative pid first so the `sleep` dies with its leader; the plain pid is the
  # fallback for a group the kernel has already torn down.
  for _i in $(seq 1 25); do
    kill -0 -"$pid" 2>/dev/null || kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -KILL -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
  for _i in $(seq 1 10); do
    kill -0 -"$pid" 2>/dev/null || kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  return 1
}

# The safety net: a detached timer that disables ufw unconditionally after N
# seconds, armed BEFORE the first `ufw enable` and disarmed only once somebody
# has proved a brand-new connection survives the new rules.
deadman_arm() {
  local ttl="$1" pid
  [[ "$ttl" =~ ^[0-9]+$ && "$ttl" -gt 0 ]] || {
    echo "deadman: <seconds> must be a positive integer, got: $ttl" >&2; return 1; }
  have ufw || {
    echo "ufw is not installed; the base stage was supposed to install it." >&2; return 1; }

  # A live predecessor is reaped, never clobbered. Overwriting the pid file left
  # the earlier timer sleeping with nothing recording it: run A arms pid 100,
  # its connection proof fails, the operator re-runs, run B writes pid 200 over
  # the file, the disarm kills group 200 -- and 100 wakes up at its own T+180
  # and runs `ufw --force disable`, possibly after the installer has printed
  # success. An unattended firewall-off is exactly what this net exists to be
  # the *only* cause of.
  if [[ -s "$DEADMAN_PID_FILE" ]]; then
    pid=$(tr -dc '0-9' < "$DEADMAN_PID_FILE")
    if [[ -n "$pid" ]] && { kill -0 -"$pid" 2>/dev/null || kill -0 "$pid" 2>/dev/null; }; then
      echo "   a deadman from an earlier run is still armed (pid $pid); reaping it"
      deadman_kill "$pid" || {
        echo "A deadman from an earlier run (pid $pid) survived TERM and KILL." >&2
        echo "It will run \`ufw --force disable\` when its timer expires, so this" >&2
        echo "refuses to arm a second one on top of it. Kill it by hand:" >&2
        echo "    kill -KILL -$pid" >&2
        return 1; }
    fi
    rm -f "$DEADMAN_PID_FILE"
  fi

  # The pid file and the timeout go in as positional parameters rather than
  # spliced into the body: the body is single-quoted and a quoted word inside a
  # quoted word does not nest, it ends it. `sh -c BODY NAME ARGS` sets $0 to
  # NAME, which is what "deadman" is doing there.
  #
  # The subshell records its OWN pid: `$!` is unreliable because setsid forks
  # when the caller is already a process-group leader. setsid also makes it a
  # group leader, which is what lets a negative-pid kill take the sleep with it.
  setsid sh -c 'echo $$ > "$1"
                sleep "$2"
                ufw --force disable
                rm -f "$1"' deadman "$DEADMAN_PID_FILE" "$ttl" </dev/null >/dev/null 2>&1 &
  # Give it a moment to write the pid file, or the disarm finds nothing.
  for _ in 1 2 3 4 5 6 7 8 9 10; do [[ -s "$DEADMAN_PID_FILE" ]] && break; sleep 0.2; done
  [[ -s "$DEADMAN_PID_FILE" ]] || {
    echo "deadman failed to arm; refusing to touch ufw" >&2; return 1; }
  echo "   deadman armed: pid $(cat "$DEADMAN_PID_FILE"), ufw off in ${ttl}s unless disarmed"
}

deadman_disarm() {
  local pid
  # Fatal, not a shrug. Either the timer already fired -- in which case ufw is
  # off right now and the operator has to know -- or it was never armed, in
  # which case whatever enabled the firewall did so with no net under it.
  [[ -s "$DEADMAN_PID_FILE" ]] || {
    echo "no deadman pid file at $DEADMAN_PID_FILE." >&2
    echo "Either its timer already expired (ufw is off: check \`ufw status\`) or" >&2
    echo "nothing ever armed it. Neither is a state to continue an install from." >&2
    return 1; }
  pid=$(tr -dc '0-9' < "$DEADMAN_PID_FILE")
  [[ -n "$pid" ]] || {
    echo "$DEADMAN_PID_FILE holds no pid; cannot tell what to kill." >&2; return 1; }
  deadman_kill "$pid" || {
    echo "deadman pid $pid survived TERM and KILL. It will run" >&2
    echo "\`ufw --force disable\` when its timer expires. Kill it by hand:" >&2
    echo "    kill -KILL -$pid" >&2
    echo "$DEADMAN_PID_FILE is left in place -- it is the only record of it." >&2
    return 1; }
  # Only now, and only because the process is provably gone: the pid file is the
  # single record of a live timer, so removing it while the timer breathes is
  # the one irreversible mistake available here.
  rm -f "$DEADMAN_PID_FILE"
  echo "   deadman disarmed (pid $pid)"
}

# Which ports sshd is actually reachable on, asked rather than assumed. This
# hardcoded 22, so `./vpn init` could never finish against an sshd on another
# port: ufw came up with only 22 open, the fresh-connection proof failed, the
# installer exited 1, the deadman restored access three minutes later and the
# identical re-run failed identically with nothing in the output naming the
# port. Mirrors scripts/smoke.sh's ssh_ports, and the app's own sshPort.
ssh_ports_to_allow() {
  local p out bin ports=""
  # The port this session came in on. Nothing is more direct: it is the port
  # that has to keep working, and it just demonstrably did.
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    p=$(awk '{print $4}' <<< "$SSH_CONNECTION")
    [[ "$p" =~ ^[0-9]+$ ]] && ports="$p"
  fi
  # Plus every port the effective config names -- `sshd -T` sees a Port in an
  # Include or an sshd_config.d drop-in, which grepping sshd_config does not.
  # Every one of them, not the first: an operator whose sshd answers on two
  # ports must not lose one to a firewall we enabled.
  bin=$(command -v sshd || true); [[ -n "$bin" ]] || bin=/usr/sbin/sshd
  if [[ -x "$bin" ]]; then
    out=$("$bin" -T 2>/dev/null | awk '$1=="port" && $2 ~ /^[0-9]+$/ {print $2}' || true)
    ports="$ports $out"
  fi
  # 22 only as a last resort: this runs over ssh, so there is always a real
  # answer unless both sources were unreadable.
  ports=$(printf '%s\n' $ports | sort -un | tr '\n' ' ')
  ports=${ports% }
  [[ -n "$ports" ]] || ports=22
  printf '%s' "$ports"
}

# Existing rules are kept, not reset, and only rules carrying a `vpn-stack:`
# comment are added -- the same contract firewall.reconcile honours.
ufw_enable() {
  local ports p
  ports=$(ssh_ports_to_allow)
  for p in $ports; do
    ufw allow "$p"/tcp comment 'vpn-stack:ssh' >/dev/null
  done
  echo "   allowed ssh on: $ports"
  if ufw status 2>/dev/null | grep -q '^Status: active'; then
    echo "   ufw was already active; your other rules were left alone"
  else
    echo "   ufw was inactive; enabling it (existing rules are kept, not reset)"
    ufw --force enable >/dev/null
  fi
  # `|| true`, because this line is a courtesy to the operator and nothing more:
  # under pipefail a SIGPIPE from head closing the pipe would otherwise become
  # the exit status of the whole firewall stage, and an install that aborted
  # there would leave the deadman armed over a firewall that is perfectly fine.
  ufw status | head -1 || true
}

stage_firewall() {
  deadman_arm "$1"
  ufw_enable
}

# ---------------------------------------------------------------------- base
stage_base() {
  local HOST="$1"

  # Everything below is guarded: what is already installed is reported and left
  # alone, so bringing your own docker (or uv) is a supported way to run this.
  if have docker; then echo "   docker: $(docker --version) -- left alone"
  else install_docker; fi
  docker compose version >/dev/null 2>&1 || {
    echo "docker is here but 'docker compose' is not; install the plugin." >&2; exit 1; }

  # git and rsync are the two delivery mechanisms for the code itself -- the
  # app's clone and install.sh's push.sh -- so this stage has to precede the
  # checkout, not run from it.
  for pkg in git rsync ufw iptables; do
    have "$pkg" || { echo "-- installing $pkg"; apt-get install -y -qq "$pkg"; }
  done

  if have uv; then echo "   uv: $(command -v uv) -- left alone"
  else
    echo "-- installing uv"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    have uv || { echo "uv installed but not where expected" >&2; exit 1; }
  fi

  # systemd units and non-interactive SSH get a PATH without /root/.local/bin,
  # where uv installs itself. Link it where they look -- but never over a file
  # somebody else put there.
  local uv_path
  uv_path="$(command -v uv || true)"
  [[ -n "$uv_path" ]] || { echo "uv is not on PATH" >&2; exit 1; }
  case "$uv_path" in
    /usr/local/bin/*|/usr/bin/*|/bin/*) ;;
    *) [[ -e /usr/local/bin/uv ]] || ln -s "$uv_path" /usr/local/bin/uv ;;
  esac

  echo "-- state directory"
  install -d -m 700 /etc/vpn-stack /etc/vpn-stack/secrets /etc/vpn-stack/data
  # Never overwritten: VPN_SERVER_HOST is the address every profile already
  # handed out was issued against, and rewriting it here would change what the
  # next `user export` produces without changing anything already on a phone.
  # But keeping the old value SILENTLY is its own trap -- a re-run of `./vpn
  # init` against a rebuilt box on a new address then renders, converges and
  # smoke-tests green while every client still dials the address that is gone.
  # So the mismatch is reported, with both values and what to do about it.
  local existing_host=""
  if [[ -f /etc/vpn-stack/.env ]]; then
    existing_host=$(sed -n 's/^VPN_SERVER_HOST=//p' /etc/vpn-stack/.env | head -1)
  fi
  if [[ -z "$existing_host" ]]; then
    echo "VPN_SERVER_HOST=$HOST" >> /etc/vpn-stack/.env
  elif [[ "$existing_host" != "$HOST" ]]; then
    echo "   VPN_SERVER_HOST is already $existing_host, not $HOST -- kept."
    echo "   Every profile issued so far points at $existing_host. If this box"
    echo "   really moved, edit /etc/vpn-stack/.env, run \`vpnctl apply\`, and"
    echo "   re-export every user: the old profiles will not connect." >&2
  fi
  # dnstt's zone belongs to whoever runs this box, so it is deployment config
  # here rather than a literal in git -- a shipped default would have every
  # install serving somebody else's domain. Left commented: this script cannot
  # know the zone, but the variable name belongs in the file it has to be set
  # in, not only in dnstt/SETUP.md. No trailing comment on the value line --
  # vpnctl's .env reader does not strip one, so uncommenting would set the zone
  # to the comment.
  grep -q 'VPN_DNSTT_ZONE' /etc/vpn-stack/.env 2>/dev/null || cat >> /etc/vpn-stack/.env <<'ENV'
# dnstt only, and there is no default. Set YOUR delegated zone here before
# `vpn protocol on dnstt`; see dnstt/SETUP.md.
#VPN_DNSTT_ZONE=tun.example.com
ENV
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

  # Its ExecStart is the shim, not a path inside the checkout, which is what
  # lets the unit be written before any code has arrived.
  echo "-- boot unit (FORWARD rules do not survive a reboot on their own)"
  cat > /etc/systemd/system/vpn-stack.service <<'UNIT'
[Unit]
Description=vpn-stack: render config, converge containers and firewall
# Wants=, not only After=: network-online.target is a passive target that
# nothing pulls in on its own, so ordering after it without wanting it orders
# this unit after a target that never gets reached -- i.e. after nothing at all.
After=docker.service network-online.target
Wants=docker.service network-online.target
# Type=oneshot forbids Restart=always; on-failure is allowed and is what is
# wanted anyway. At boot `docker info` can answer long after docker.service is
# "active", and an apply that raced it used to leave the box with the FORWARD
# rules unapplied and containers down until somebody ran it by hand.
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=oneshot
RemainAfterExit=yes
# The socket, not the unit: dockerd accepts connections a little after systemd
# calls it started, and `vpnctl apply` talks to the socket on its first line.
ExecStartPre=/bin/sh -c 'for i in $(seq 1 60); do docker info >/dev/null 2>&1 && exit 0; sleep 2; done; echo "docker did not answer within 120s" >&2; exit 1'
# Under the same lock as every other call site. Nothing stops an operator's
# `./vpn user add` from landing during boot, and two candidate trees rendering
# over each other is exactly what the atomic promote cannot save you from.
# Absolute path because ExecStart demands one; /usr/bin/flock is util-linux's
# on both 22.04 and 24.04 (/bin is a symlink to /usr/bin there).
ExecStart=/usr/bin/flock /run/vpn-stack.lock /usr/local/bin/vpnctl apply
# Set at every wrapped call site, unread for now: the day vpnctl takes this lock
# itself it has to be able to tell that an outer flock(1) already holds it, or a
# blocking inner lock on the same path -- a second file description, so a
# different holder as far as the kernel is concerned -- waits on its own parent
# forever. Measured.
Environment=VPN_STACK_LOCK_HELD=1
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable vpn-stack.service >/dev/null
}

# ---------------------------------------------------------------------- code
stage_code() {
  local REPO_PATH="$1"
  # Named here rather than four layers down in uv, whose "No `pyproject.toml`
  # found" says neither which path it was handed nor who handed it over.
  [[ -f "$REPO_PATH/pyproject.toml" ]] || {
    echo "$REPO_PATH is not a vpn-stack checkout (no pyproject.toml)" >&2
    echo "Run the base stage and deliver the code first." >&2
    exit 1; }

  cd "$REPO_PATH"
  # docker compose reads .env from the project directory, and the real one lives
  # outside the repo so a clone can never contain a credential.
  ln -sfn /etc/vpn-stack/.env "$REPO_PATH/.env"
  # --no-dev: uv syncs the `dev` group by DEFAULT, and a fresh VPN server has no
  # business carrying pytest and its transitive deps.
  uv sync --frozen --no-dev

  # The shim prepends uv's own directory rather than trusting the caller's PATH:
  # systemd and non-interactive ssh both invoke this with a minimal environment.
  # --no-dev again, not just on the sync above: `uv run` re-syncs the environment
  # on every invocation and includes the dev group by default, so the very first
  # `vpnctl` call -- the one on the next line, or the one systemd runs at boot --
  # would put pytest straight back and undo it.
  cat > /usr/local/bin/vpnctl <<SHIM
#!/bin/sh
PATH="/usr/local/bin:/root/.local/bin:\$PATH"
export PATH
cd "$REPO_PATH" && exec uv run --no-dev vpnctl "\$@"
SHIM
  chmod 755 /usr/local/bin/vpnctl
  vpnctl --help >/dev/null

  # The keyring, last, because nothing before it can run without the shim.
  # bootstrap never overwrites an existing secret without --force, so re-running
  # this stage cannot invalidate a profile already handed out.
  #
  # Under the lock, like every other vpnctl call site. vpnctl takes no lock of
  # its own, so a bootstrap that overlapped an operator's `./vpn user add` would
  # have two processes writing the keyring and users.json with nothing
  # serialising them -- and the app can run this stage while somebody else is
  # already using the box.
  VPN_STACK_LOCK_HELD=1 flock /run/vpn-stack.lock vpnctl bootstrap
}

stage="${1:-}"
case "$stage" in
  -h|--help) usage; exit 0 ;;
  '') echo "provision-host.sh needs a stage" >&2; usage; exit 2 ;;
  base|code|firewall|firewall-disarm) ;;
  *) echo "unknown stage: $stage" >&2; usage; exit 2 ;;
esac
shift

# No argument has a default. base's is VPN_SERVER_HOST, the address every
# profile is issued against, and this box cannot work it out -- behind NAT, or
# reached through a jump host, the address clients need is not one it can see.
# code's is where the checkout landed, which differs between the rsync and the
# clone. firewall's is how long the operator is prepared to be locked out for,
# which is the caller's policy and not this script's. firewall-disarm is the one
# stage with nothing to pass: what to kill is in the pid file, because that file
# is the only durable record of the timer. Checked before the root test below so
# a usage error reads as one to whoever ran it.
arg="${1:-}"
if [[ -z "$arg" && "$stage" != firewall-disarm ]]; then
  case "$stage" in
    base) echo "base needs the address clients will connect to" >&2 ;;
    code) echo "code needs the path of the checkout" >&2 ;;
    firewall) echo "firewall needs the deadman's lifetime in seconds" >&2 ;;
  esac
  usage; exit 2
fi

# Every stage writes /etc, drives systemd, or reconfigures the firewall. Without
# this the first failure is a permission denied out of apt-get or ufw, which does
# not say whose fault it is.
[[ "$(id -u)" == 0 ]] || { echo "provision-host.sh must run as root" >&2; exit 1; }

case "$stage" in
  base) stage_base "$arg" ;;
  code) stage_code "$arg" ;;
  firewall) stage_firewall "$arg" ;;
  firewall-disarm) deadman_disarm ;;
esac
