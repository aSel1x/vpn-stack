#!/bin/bash
# The server-local half of an install: everything a box can do to itself, in one
# place, so install.sh and the app share one definition of how a host is
# prepared rather than keeping two that drift.
#
#   scripts/provision-host.sh base <server-host>
#   scripts/provision-host.sh code <repo-path>
#
# Two stages, because the two callers have to cut this in half at two different
# points and both cuts land here:
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
#
# The firewall is deliberately NOT here. Enabling ufw is only safe if something
# proves a brand-new connection survives the new rules, and a process on this
# box cannot: it cannot show from inside one connection that a *different* one
# would be accepted. install.sh does that, and the app does its own equivalent.
# The split exists so the prover can run between the stages -- the app arms its
# deadman and proves the firewall after `base` and before `code`, which is why
# the keyring is minted by `code` and not in a stage of its own.
#
# Both stages are idempotent: an install that fails halfway has to be fixable by
# running it again, not by hand-editing the server.
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
USAGE
}

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
    "$(dpkg --print-architecture)" "$distro" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list

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
  grep -q '^VPN_SERVER_HOST=' /etc/vpn-stack/.env 2>/dev/null \
    || echo "VPN_SERVER_HOST=$HOST" >> /etc/vpn-stack/.env
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
  vpnctl bootstrap
}

stage="${1:-}"
case "$stage" in
  -h|--help) usage; exit 0 ;;
  '') echo "provision-host.sh needs a stage" >&2; usage; exit 2 ;;
  base|code) ;;
  *) echo "unknown stage: $stage" >&2; usage; exit 2 ;;
esac
shift

# Neither argument has a default. base's is VPN_SERVER_HOST, the address every
# profile is issued against, and this box cannot work it out -- behind NAT, or
# reached through a jump host, the address clients need is not one it can see.
# code's is where the checkout landed, which differs between the rsync and the
# clone. Checked before the root test below so a usage error reads as one
# whoever ran it.
arg="${1:-}"
[[ -n "$arg" ]] || {
  case "$stage" in
    base) echo "base needs the address clients will connect to" >&2 ;;
    code) echo "code needs the path of the checkout" >&2 ;;
  esac
  usage; exit 2; }

# Both stages write /etc and drive systemd. Without this the first failure is a
# permission denied out of apt-get, which does not say whose fault it is.
[[ "$(id -u)" == 0 ]] || { echo "provision-host.sh must run as root" >&2; exit 1; }

case "$stage" in
  base) stage_base "$arg" ;;
  code) stage_code "$arg" ;;
esac
