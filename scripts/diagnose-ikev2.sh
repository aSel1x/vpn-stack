#!/bin/bash
# Read-only IKEv2 reachability diagnostic. Changes nothing, starts nothing,
# writes nothing outside /tmp. Safe to run on the live server.
#
# WHY THIS EXISTS
# ---------------
# CLAUDE.md documents an unresolved IKEv2 problem: clients establish nothing
# because packets never arrive at this host's interface. Three configurations
# were already ruled out (privileged container, non-privileged container, full
# bare-metal hwdsl2 install), which eliminates everything *on* the box.
#
# What was never separated is the two remaining hypotheses, which need opposite
# fixes and look identical from the server:
#
#   (A) inbound UDP 500/4500 is dropped BEFORE this host -- hosting provider's
#       edge firewall / security group. Fix: open it in the provider panel.
#   (B) outbound UDP 500/4500 is dropped at the CLIENT's network -- many mobile
#       carriers and corporate NATs block IKE outright. Fix: none server-side;
#       IKEv2 is simply unusable from that network, and the answer is to lean on
#       VLESS/Hysteria2, which is what this stack already does well.
#
# A tcpdump on the server sees "no packets" in both cases. The discriminator is
# a probe from a THIRD network you control: if a packet sent from a rented VPS
# arrives, the provider is not blocking, and the client's network is (B). If it
# does not arrive either, it is (A).
#
# USAGE
#   On the VPN server:     sudo bash scripts/diagnose-ikev2.sh listen
#   Then, from any other   bash scripts/diagnose-ikev2.sh probe <server-ip>
#   host (a $4 VPS, a
#   friend's box, a laptop
#   on a different ISP)
#
#   Local state only:      bash scripts/diagnose-ikev2.sh local
#
# Run `listen` first and leave it running; it captures for 90s by default.

set -uo pipefail

MODE="${1:-}"
CONTAINER_UP=0
CAPTURE_SECONDS="${CAPTURE_SECONDS:-90}"
IKEV2_PORTS="500 4500 1701"

c_head() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
c_ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
c_bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; }
c_warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
c_info() { printf '    %s\n' "$1"; }

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "This mode needs root (tcpdump, iptables, ss -p). Re-run with sudo." >&2
    exit 1
  fi
}

# ---------------------------------------------------------------- local state

check_local() {
  c_head "Container"
  if ! command -v docker >/dev/null; then
    c_bad "docker not found -- wrong host?"
    return
  fi
  local state
  state=$(docker inspect -f '{{.State.Status}}' ipsec-vpn-server 2>/dev/null | tr -d '\n')
  CONTAINER_UP=0
  if [[ "$state" == "running" ]]; then
    CONTAINER_UP=1
    c_ok "ipsec-vpn-server is running"
  elif [[ -z "$state" ]]; then
    c_bad "no ipsec-vpn-server container exists on this host"
    c_info "if you meant to run this on the VPN server, you are on the wrong host"
  else
    c_bad "ipsec-vpn-server is '$state' -- nothing can arrive at a stopped container"
    c_info "start it: docker compose up -d ikev2"
  fi

  c_head "Listeners"
  # network_mode: host, so the sockets belong to the container's charon/pluto
  # but appear in the host's namespace.
  local globals
  globals=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
  for p in 500 4500; do
    if ss -lunp 2>/dev/null | grep -qE ":$p\b"; then
      # Bound is not enough -- bound *on a globally routable address* is. A
      # daemon listening only on 127.0.0.1 can never answer a real client.
      local on_global=0 a
      for a in $globals; do
        ss -lunp 2>/dev/null | grep -qE "(^|[[:space:]])$a:$p\b" && on_global=1
      done
      if (( on_global )); then
        c_ok "udp/$p is bound on a public address"
      else
        c_bad "udp/$p is bound, but NOT on any global address (loopback only)"
      fi
      ss -lunp 2>/dev/null | grep -E ":$p\b" | tr -s ' ' | sed 's/^/      /'
    elif (( CONTAINER_UP )); then
      c_bad "udp/$p has NO listener -- the container runs but charon did not bind"
    else
      c_bad "udp/$p has no listener (expected: the container is not running)"
    fi
  done
  if ss -lunp 2>/dev/null | grep -qE ':1701\b'; then
    c_ok "udp/1701 is bound (L2TP)"
  else
    c_warn "udp/1701 has no listener -- L2TP will not work (IKEv2 does not need it)"
  fi

  c_head "Host firewall"
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    for p in $IKEV2_PORTS; do
      if ufw status 2>/dev/null | grep -qE "^$p/udp\s+ALLOW"; then
        c_ok "ufw allows $p/udp"
      else
        c_bad "ufw does NOT allow $p/udp"
        c_info "fix: ufw allow $p/udp"
      fi
    done
  else
    c_warn "ufw inactive or absent -- not the blocker, but check iptables below"
  fi

  c_head "iptables INPUT (would a packet that arrives be accepted?)"
  local pol
  pol=$(iptables -S INPUT 2>/dev/null | awk '/^-P INPUT/{print $3}')
  if [[ -z "$pol" ]]; then
    c_warn "cannot read iptables (needs root) -- skipping INPUT and FORWARD checks"
    return
  fi
  c_info "INPUT policy: $pol"
  # Match across the WHOLE ruleset, not just the INPUT chain: INPUT jumps into
  # ufw-* sub-chains, and ports are often expressed as `-m multiport --dports`.
  local all_rules
  all_rules=$(iptables -S 2>/dev/null)
  for p in 500 4500; do
    if grep -qE -- "(--dport $p|--dports [0-9,]*\b$p\b)[^!]*-j ACCEPT" <<<"$all_rules"; then
      c_ok "an ACCEPT rule covers dport $p"
      grep -E -- "(--dport $p|--dports [0-9,]*\b$p\b).*ACCEPT" <<<"$all_rules" | sed 's/^/      /'
    elif [[ "$pol" == "ACCEPT" ]]; then
      c_ok "no explicit rule, but INPUT policy is ACCEPT"
    else
      c_bad "no ACCEPT anywhere for dport $p and INPUT policy is $pol"
    fi
  done

  c_head "IKEv2 IPv4 FORWARD rules (the documented silent-no-traffic failure)"
  local iface
  iface=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
  c_info "default interface: ${iface:-unknown}"
  if [[ -n "${iface:-}" ]]; then
    local a=0 b=0
    iptables -C FORWARD -i "$iface" -d 192.168.42.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null && a=1
    iptables -C FORWARD -s 192.168.42.0/24 -o "$iface" -j ACCEPT 2>/dev/null && b=1
    if (( a && b )); then
      c_ok "both FORWARD accepts for 192.168.42.0/24 are present"
    else
      c_bad "FORWARD accepts MISSING (inbound=$a outbound=$b)"
      c_info "this alone makes clients connect and carry no traffic"
      c_info "fix: sysctl --system  (scripts/install.sh writes /etc/sysctl.d/99-vpn-stack.conf)"
    fi
  fi

  c_head "Sysctls"
  for s in net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_redirects; do
    c_info "$s = $(sysctl -n "$s" 2>/dev/null || echo '?')"
  done
  if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" != "1" ]]; then
    c_bad "ip_forward is off -- nothing routes"
  fi

  c_head "strongSwan's own view"
  if docker exec ipsec-vpn-server ipsec status 2>/dev/null | head -20; then :; else
    c_warn "could not query ipsec status inside the container"
  fi
}

# --------------------------------------------------------------- listen mode

do_listen() {
  need_root
  command -v tcpdump >/dev/null || { echo "tcpdump not installed: apt install -y tcpdump" >&2; exit 1; }

  check_local

  local pub
  pub=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)

  c_head "Capturing for ${CAPTURE_SECONDS}s"
  cat <<EOF
    Listening on ALL interfaces for udp/500, udp/4500, udp/1701 and ESP.
    This host's global IPv4: ${pub:-unknown}

    While this runs, do BOTH of these:
      1. try to connect the failing IKEv2 client
      2. from another network, run:
             bash scripts/diagnose-ikev2.sh probe ${pub:-<this-ip>}

    Anything that reaches this host's NIC shows up below, even if a firewall
    would later drop it -- tcpdump taps before netfilter's INPUT chain.

EOF

  local out=/tmp/ikev2-diag-$$.txt
  # -A prints payload as ASCII: required, or the DIAGPROBE marker below is
  # invisible and the probe/real-client discriminator never fires.
  timeout "$CAPTURE_SECONDS" tcpdump -nni any -A -c 200 \
    '(udp port 500 or udp port 4500 or udp port 1701 or proto 50)' 2>/dev/null | tee "$out"

  c_head "Verdict"
  local ike probe
  ike=$(grep -cE '\.(500|4500) *[:>]' "$out" 2>/dev/null || true)
  probe=$(grep -c 'DIAGPROBE' "$out" 2>/dev/null || true)
  ike=${ike:-0}; probe=${probe:-0}

  if (( probe > 0 )); then
    c_ok "the external probe ARRIVED -- your hosting provider is NOT blocking inbound UDP 500/4500"
    if (( ike > 0 )); then
      c_ok "real IKE packets also arrived -- the problem is past the network path; re-check strongSwan config and the FORWARD rules above"
    else
      c_bad "but NOT ONE packet from the real client"
      c_info "=> hypothesis (B): the client's own network blocks outbound IKE."
      c_info "   Nothing on this server can fix that. Confirm by trying the same"
      c_info "   client on a different network (home Wi-Fi vs cellular)."
      c_info "   If it is the carrier: keep IKEv2 off and use VLESS/Hysteria2."
    fi
  elif (( ike > 0 )); then
    c_warn "client packets arrived but the probe did not -- probe likely not run, or run from a blocked network"
  else
    c_bad "NOTHING arrived at this interface at all"
    c_info "=> hypothesis (A): inbound UDP 500/4500 is dropped upstream of this host."
    c_info "   Check the hosting provider's edge firewall / security group for"
    c_info "   this VPS. Many providers block IPsec by default on cheap plans."
    c_info "   (Re-run and make sure the probe really was sent -- a probe that"
    c_info "    never left its own host proves nothing.)"
  fi
  c_info ""
  c_info "raw capture kept at $out"
}

# ---------------------------------------------------------------- probe mode

do_probe() {
  local target="${2:-}"
  [[ -n "$target" ]] || { echo "usage: $0 probe <server-ip>" >&2; exit 1; }

  c_head "Probing $target"
  local sent=0
  for p in 500 4500; do
    # A marked payload so the listener can tell our probe apart from real IKE
    # and from internet background scanning, which hits udp/500 constantly.
    if printf 'DIAGPROBE-%s' "$(hostname)" > /dev/udp/"$target"/"$p" 2>/dev/null; then
      c_ok "sent a marked UDP datagram to $target:$p"
      sent=$((sent + 1))
    else
      c_bad "could not send to $target:$p -- THIS host's network blocks outbound UDP $p"
      c_info "that is itself a finding: pick a probe host on a different network"
    fi
  done

  if (( sent > 0 )); then
    printf '\n  Now read the verdict in the `listen` window on the server.\n'
    printf '  Arrived     -> provider is fine; the failing client is the problem (B).\n'
    printf '  Not arrived -> the provider drops inbound UDP 500/4500 (A).\n\n'
  fi
}

case "$MODE" in
  listen) do_listen ;;
  probe)  do_probe "$@" ;;
  local)  check_local ;;
  *)
    cat <<EOF
IKEv2 reachability diagnostic (read-only).

  sudo bash $0 listen            on the VPN server; captures ${CAPTURE_SECONDS}s
  bash $0 probe <server-ip>      from a DIFFERENT network, while listen runs
  bash $0 local                  local state only, no capture

Separates "the provider drops inbound IKE" from "the client's carrier drops
outbound IKE" -- the two hypotheses left after container config was ruled out.
EOF
    exit 1
    ;;
esac
