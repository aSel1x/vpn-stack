#!/bin/bash
# Post-deploy assertions. Answers "is the thing actually serving?", not
# "did the command exit 0?" -- every check here corresponds to a failure mode
# that has really happened on this stack.
#
#   scripts/smoke.sh [--json]
#
# --json puts one object on stdout and every human line on stderr. Its check
# names are a public API, like vpnctl's: derived from what the check is, never
# renumbered when checks are added, so a caller can watch one across releases.
set -uo pipefail

JSON=0
for arg in "$@"; do
  case "$arg" in
    --json) JSON=1 ;;
    *) echo "usage: smoke.sh [--json]" >&2; exit 2 ;;
  esac
done

STATE="${VPN_STATE:-/etc/vpn-stack}"
FAIL=0
DONE=0
CHECKS=()

# fd 3 carries the payload; under --json fd 1 becomes stderr, so every echo, ✓
# and ✗ below lands there untouched instead of being individually redirected --
# and nothing added later can accidentally print into the object.
if [[ $JSON -eq 1 ]]; then exec 3>&1 1>&2; else exec 3>&1; fi

# Minimal escaper: every detail here is built from paths, port numbers,
# container statuses and iptables nets, not from free text. The colour codes
# live in ok/bad's printf and never reach a detail string.
json_str() {
  local s=${1//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/ }; s=${s//$'\r'/ }
  printf '"%s"' "$s"
}

# name, ok, detail, extra-fields -- \x1f-separated because details contain
# spaces and paths. Recorded in both modes; only --json reads it back.
record() { CHECKS+=("$1"$'\x1f'"$2"$'\x1f'"$3"$'\x1f'"${4:-}"); }

ok()  { printf '  \033[32m✓\033[0m %s\n' "$2"; record "$1" true "$2" "${3:-}"; }
bad() { printf '  \033[31m✗\033[0m %s\n' "$2"; FAIL=1; record "$1" false "$2" "${3:-}"; }

# A truncated object is worse than a failed check: the caller cannot tell the
# two apart. So the payload is written from an EXIT trap -- an unbound
# variable, a docker that hangs and is killed, any death before the last line
# still yields one valid object, with the early exit as a failed check rather
# than as a missing brace.
emit() {
  local rc=$? sep='' rec name okv detail extra
  [[ $JSON -eq 1 ]] || exit "$rc"
  [[ $DONE -eq 1 ]] || record smoke_completed false \
    "smoke.sh exited early (status $rc) -- the checks after this point never ran"
  {
    [[ $rc -eq 0 ]] && printf '{"schema":1,"ok":true,"checks":[' \
                    || printf '{"schema":1,"ok":false,"checks":['
    for rec in "${CHECKS[@]}"; do
      IFS=$'\x1f' read -r name okv detail extra <<< "$rec"
      printf '%s{"name":%s,"ok":%s,"detail":%s' \
        "$sep" "$(json_str "$name")" "$okv" "$(json_str "$detail")"
      [[ -n "$extra" ]] && printf ',%s' "$extra"
      printf '}'
      sep=','
    done
    printf ']}\n'
  } >&3
  exit "$rc"
}
trap emit EXIT

# Is this a real network, and what is its canonical form? The check used to be
# a regex, and a regex is shape-only: "192.168.256.0/24" matches
# ^[0-9]+(\.[0-9]+){3}/[0-9]+$ perfectly, is not an address, and makes
# `iptables -C` fail in a way indistinguishable from "the rule is missing" --
# which is the exact confusion the validation exists to prevent, arrived at
# through the validation itself. python3 is already a hard dependency here (the
# port enumeration below parses vpnctl's JSON with it) and ipaddress is what
# vpnctl.ikev2ctl uses, so this accepts and normalises the same values the
# Python side does, host bits included: 192.168.43.10/24 -> 192.168.43.0/24.
valid_net() {
  [[ -n "$1" ]] || return 1
  python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1], strict=False))' \
    "$1" 2>/dev/null
}

# The smallest network covering a `first-last` pool, byte-identical to
# vpnctl.ikev2ctl._covering_net and to the copy in scripts/diagnose-ikev2.sh.
#
# It has to be all three copies or none. This one used to take `${first%.*}.0/24`
# -- the /24 containing the pool's FIRST address -- which is right for the image
# default (192.168.43.10-192.168.43.250) and wrong for any pool that straddles a
# boundary: 192.168.43.10-192.168.44.250 makes vpnctl install its FORWARD accepts
# for 192.168.40.0/21 while this file went looking for a rule on 192.168.43.0/24,
# found none, and called a healthy box broken. Three copies of a derivation that
# silently disagree is the failure this repo already paid for once, when the
# subnet was hardcoded as the L2TP pool and BOTH health checks asserted the same
# wrong value and reported green.
#
# Wider than the pool is the safe direction: an address inside the covering
# network but outside the pool is one pluto never assigns. A bare CIDR is
# accepted too, because rightaddresspool takes one.
covering_net() {
  [[ -n "$1" ]] || return 1
  python3 -c '
import ipaddress, sys
bounds = [b.strip() for b in sys.argv[1].split("-") if b.strip()]
if not bounds:
    raise SystemExit(1)
try:
    if len(bounds) == 1 and "/" in bounds[0]:
        block = ipaddress.ip_network(bounds[0], strict=False)
        first, last = block.network_address, block.broadcast_address
    else:
        first = ipaddress.ip_address(bounds[0])
        last = ipaddress.ip_address(bounds[-1])
except ValueError:
    raise SystemExit(1)
if first.version != 4 or last.version != 4 or last < first:
    raise SystemExit(1)
covering = next(ipaddress.summarize_address_range(first, last))
while covering.broadcast_address < last:
    covering = covering.supernet()
print(covering)
' "$1" 2>/dev/null
}

# Which containers each protocol needs, and the name docker knows them by.
# Two authorities, and this file can read neither: protocols.compose_services
# names the compose services, and compose.yml renames three of them with
# container_name (ikev2 -> ipsec-vpn-server, dnstt -> dnstt-server). `vpnctl
# --json protocol list` exposes no service list yet, so the mapping is restated
# here; fold it back into the enumeration the moment that JSON carries it, for
# the reason check.sh reads the sing-box tag out of compose.yml.
protocol_containers() {
  case "$1" in
    # Both sing-box inbounds, one process.
    vless-reality|hysteria2) printf 'sing-box' ;;
    ikev2)                   printf 'ipsec-vpn-server' ;;
    dnstt)                   printf 'dnstt-server dnstt-sshd dnstt-socks' ;;
    *)                       printf '' ;;
  esac
}

container_fields() {
  printf '"status":%s,"restart_count":%s' "$(json_str "$1")" "${2:-0}"
}

# Running is not the same as healthy. Every one of these services carries
# `restart: always`, so a container that starts, dies and is restarted looks
# exactly like one that has been up for a week: `docker ps` shows it running,
# because it is running again. RestartCount is the only thing that separates
# them, and only over time -- read once it cannot tell a crash the operator
# already fixed from a loop still going round, so a nonzero count is sampled
# twice and only a count that GROWS is a failure.
check_container() {
  local c="$1" info status restarts started again
  info=$(docker inspect -f '{{.State.Status}} {{.RestartCount}} {{.State.StartedAt}}' "$c" 2>/dev/null \
         | tr -d '\r' | head -1)
  read -r status restarts started <<< "$info"
  if [[ "$status" != running ]]; then
    bad "container_$c" "$c is '${status:-absent}'" "$(container_fields "${status:-absent}" "${restarts:-0}")"
    return
  fi
  if [[ "$restarts" =~ ^[0-9]+$ && "$restarts" -gt 0 ]]; then
    sleep 3
    again=$(docker inspect -f '{{.RestartCount}}' "$c" 2>/dev/null | tr -d '\r' | head -1)
    if [[ "$again" =~ ^[0-9]+$ && "$again" -gt "$restarts" ]]; then
      bad "container_$c" "$c is crash-looping (restarts $restarts -> $again in 3s)" \
          "$(container_fields crash-looping "$again")"
      return
    fi
    ok "container_$c" "$c running since $started ($restarts restarts, not climbing)" \
       "$(container_fields running "$restarts")"
    return
  fi
  ok "container_$c" "$c running" "$(container_fields running "${restarts:-0}")"
}

# The pool IKEv2 clients are actually assigned from, asked of the container
# rather than hardcoded. `conn ikev2-cp`'s rightaddresspool is authoritative (it
# is what pluto hands out); VPN_XAUTH_NET is only a fallback, because run.sh
# uses the net for the firewall rules *it* writes while ikev2.sh builds the pool
# from XAUTH_POOL, so preferring the net would reproduce the very bug this
# replaced for anyone who set only one of the two. Both are validated before
# use: an unparseable value handed to `iptables -C` fails in a way
# indistinguishable from "the rule is missing".
#
# Byte-identical to scripts/diagnose-ikev2.sh's copy, and answering the same
# question as vpnctl.ikev2ctl.pool_network -- not by convention but pinned by a
# test that extracts all three and runs them over the same probe set. The two
# shell copies drifted once already, on the fix for this very function: one grew
# the python3 guard and the whitespace-tolerant entry match and the other did
# not, so on a box without python3 this file blamed the container for a missing
# tool. Three copies of a derivation that silently disagree is the failure this
# repo has already paid for, when the subnet was hardcoded as the L2TP pool and
# BOTH health checks asserted the same wrong value and reported green.
#
# Emits "net|provenance": a value that came from the hardcoded default must not
# read as a real answer, and the provenance names WHY the fallback was reached,
# so "image default, container unreadable" is distinguishable from a container
# that answered with something unusable.
ikev2_pool() {
  local line entry v net why="container unreadable"
  # Without python3 nothing below can be validated, and an unvalidated value is
  # what makes `iptables -C` fail as though the rule were missing. Say so in the
  # provenance rather than blaming the container for a tool that is absent.
  if ! command -v python3 >/dev/null; then
    printf '192.168.43.0/24|image default, python3 absent so nothing could be validated'
    return
  fi
  line=$(docker exec ipsec-vpn-server \
           sed -n 's/^[[:space:]]*rightaddresspool=//p' /etc/ipsec.d/ikev2.conf 2>/dev/null | head -1)
  if [[ -n "$line" ]]; then
    # First IPv4 entry of a comma-separated list that also carries the image's
    # IPv6 range, with any padding around it dropped -- ipsec.conf tolerates
    # whitespace after the '=' and around each entry, and python3 below will
    # refuse anything that survives this and is still not an address.
    entry=$(printf '%s' "$line" | tr ',' '\n' | grep -m1 -E '^[[:space:]]*[0-9]+(\.[0-9]+){3}' || true)
    entry=${entry//[[:space:]]/}
    net=$(covering_net "$entry") && {
      printf '%s|conn ikev2-cp rightaddresspool' "$net"; return; }
    why="conn ikev2-cp gave an unusable pool"
  fi
  v=$(docker exec ipsec-vpn-server printenv VPN_XAUTH_NET 2>/dev/null | tr -d '\r' | head -1)
  if [[ -n "$v" ]]; then
    net=$(valid_net "$v") && { printf '%s|VPN_XAUTH_NET' "$net"; return; }
    why="VPN_XAUTH_NET=$v does not parse as a network"
  fi
  printf '192.168.43.0/24|image default, %s' "$why"
}

# The pool query's answer as fields, not as English inside the detail: a caller
# has to be able to see that the net came from the image default -- i.e. that
# the container never answered -- without parsing a sentence.
pool_fields() {
  printf '"xauth_net":%s,"xauth_net_source":%s' "$(json_str "$1")" "$(json_str "$2")"
}

# Which port sshd is actually reachable on, asked rather than assumed. This
# check hardcoded 22, so on a box whose sshd listens on 2222 it announced an
# imminent lockout on a firewall that is exactly right -- the same shape of bug
# as the IKEv2 pool constant in the check below. Emits "ports|provenance": an
# assumed 22 must not read as an observed answer.
ssh_ports() {
  local p out bin
  # The port this session came in on. Nothing is more direct: it is the port
  # that has to keep working, and it just demonstrably did.
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    p=$(awk '{print $4}' <<< "$SSH_CONNECTION")
    [[ "$p" =~ ^[0-9]+$ ]] && { printf '%s|the port this session arrived on' "$p"; return; }
  fi
  # Run from the console instead. `sshd -T` is the *effective* config, so a Port
  # in an Include or an sshd_config.d drop-in counts and grepping sshd_config
  # sees neither. Every port it names, not the first: one sshd answers on and
  # ufw drops is a lockout waiting for whoever uses that one.
  bin=$(command -v sshd || true); [[ -n "$bin" ]] || bin=/usr/sbin/sshd
  if [[ -x "$bin" ]]; then
    out=$("$bin" -T 2>/dev/null | awk '$1=="port" && $2 ~ /^[0-9]+$/ {print $2}' | sort -un | tr '\n' ' ')
    out=${out% }
    [[ -n "$out" ]] && { printf '%s|sshd -T' "$out"; return; }
    printf '22|sshd -T unreadable, assuming the default'; return
  fi
  # No sshd at all: a box administered from its console has no ssh access to be
  # locked out of, and a false alarm here teaches people to ignore smoke tests.
  printf '|no sshd on this box'
}

# The port query's answer as fields, for the same reason the pool's is: a caller
# has to be able to see that 22 was a guess without parsing a sentence.
ssh_fields() {
  printf '"ssh_ports":%s,"ssh_ports_source":%s' "$(json_str "$1")" "$(json_str "$2")"
}

# `ufw allow 2222/tcp` prints "2222/tcp", `ufw allow 2222` prints a bare "2222",
# and each has a "(v6)" twin. Matching one form only would call a firewall that
# allows ssh perfectly well a lockout.
ufw_allows_tcp() {
  ufw status 2>/dev/null | grep -qE "^$1(/tcp)?( \(v6\))?[[:space:]]+ALLOW"
}

echo "== rendered config =="
[[ -L "$STATE/rendered" ]] && ok rendered_symlink "rendered is a symlink -> $(readlink "$STATE/rendered")" \
                           || bad rendered_symlink "$STATE/rendered is not a symlink (promotion never ran)"
[[ -f "$STATE/rendered/sing-box/00_base.json" ]] && ok rendered_singbox_tree "sing-box tree present" \
                                                 || bad rendered_singbox_tree "sing-box tree missing"

# One enumeration, read by both the container loop and the port loop, so both
# follow `protocol on/off` automatically. The protocol name rides along because
# the check names are per protocol port: port_hysteria2_20443_udp says what
# broke without a lookup table. If the enumeration itself fails we FAIL rather
# than skip: a check that silently verifies nothing and still reports PASS is
# worse than no check.
PLIST=$(vpnctl --json protocol list 2>/dev/null \
        | python3 -c 'import sys,json
d=json.load(sys.stdin)
for p in d.get("protocols",[]):
    if p["enabled"]:
        print("proto", p["name"])
        for x in p["ports"]:
            n,_,pr=x.partition("/"); print("port", p["name"], n, pr)' 2>/dev/null) || PLIST=""
ENABLED=$(awk '$1=="proto" {printf "%s ", $2}' <<< "$PLIST")
PORTS=$(awk '$1=="port" {print $2, $3, $4}' <<< "$PLIST")

echo "== containers =="
# Driven from the enabled set, not from a literal list. This checked `sing-box`
# alone, so a crash-looping dnstt-sshd -- the container that holds every dnstt
# login, and the one whose recreation is what makes `user rm` revoke anything --
# passed every check on this page while nobody could log in.
#
# sing-box is unconditional because composectl.up starts it unconditionally: it
# is the process both sing-box-level protocols live in, and it is up even with
# both of them somehow off.
CONTAINERS="sing-box"
if [[ -z "$ENABLED" ]]; then
  bad container_enumeration \
      "could not enumerate enabled protocols (is vpnctl on PATH?) -- only sing-box is checked below"
else
  for proto in $ENABLED; do
    extra=$(protocol_containers "$proto")
    if [[ -z "$extra" ]]; then
      # A protocol the registry grew and this table did not hear about. Loud,
      # for the reason the port enumeration is loud: the alternative is a green
      # smoke test that checked nothing for that protocol.
      bad "container_enumeration_$proto" \
          "$proto is enabled and protocol_containers() does not know its containers"
    else
      CONTAINERS="$CONTAINERS $extra"
    fi
  done
fi
for c in $(printf '%s\n' $CONTAINERS | sort -u); do check_container "$c"; done

echo "== listeners (a container can run and still bind nothing) =="

if [[ -z "$PORTS" ]]; then
  bad port_enumeration "could not enumerate expected ports (is vpnctl on PATH?) -- failing, not skipping"
else
  # Loopback listeners do not count. systemd-resolved holds 127.0.0.53:53 on
  # every stock Ubuntu, so "is :53 in the output" says yes on a server where
  # nothing of ours is serving DNS at all.
  served() {
    local port="$1" flag
    [[ "$2" == tcp ]] && flag=-ltn || flag=-lun
    ss -H $flag "sport = :$port" 2>/dev/null | awk '
      { a = $4; sub(/:[0-9]+$/, "", a); sub(/%.*/, "", a)
        if (a !~ /^127\./ && a != "[::1]" && a != "::1") found = 1 }
      END { exit !found }'
  }
  while read -r pname port proto; do
    [[ -z "$port" ]] && continue
    served "$port" "$proto" && ok "port_${pname}_${port}_${proto}" "$port/$proto bound" \
                            || bad "port_${pname}_${port}_${proto}" "$port/$proto NOT bound"
  done <<< "$PORTS"
fi

# The other half of dnstt, and deliberately the opposite assertion. Its two
# back-end services bind LOOPBACK on purpose -- dnstt-sshd on 127.0.0.1:2222 is
# the only exit from the tunnel, dnstt-socks on 127.0.0.1:7300 is reachable only
# through an authenticated SSH forward -- so served() above, which ignores
# 127.0.0.0/8, can never see them: it ignores loopback because systemd-resolved
# holds 127.0.0.53:53 on every stock Ubuntu and a loopback match would report
# dnstt's own 53/udp as served on a box serving no DNS at all. Two separate
# helpers rather than a flag, so neither piece of reasoning can leak into the
# other. Without this, dnstt-server binding :53 was the whole test, and a tunnel
# whose sshd was not listening passed it.
#
# A non-loopback bind is a FAILURE here, not a pass: these two admit anyone who
# reaches them, and the credential's small blast radius is the entire argument
# for PermitOpen any and a password login behind the Noise key.
loopback_bind() {
  local port="$1" flag
  [[ "$2" == tcp ]] && flag=-ltn || flag=-lun
  ss -H $flag "sport = :$port" 2>/dev/null | awk '
    { a = $4; sub(/:[0-9]+$/, "", a); sub(/%.*/, "", a)
      if (a ~ /^127\./ || a == "[::1]" || a == "::1") lo = 1; else pub = a }
    END { if (pub != "") { print "public " pub }
          else if (lo)   { print "loopback" }
          else           { print "absent" } }'
}

if [[ " $ENABLED " == *" dnstt "* ]]; then
  while read -r port proto svc what; do
    [[ -z "$port" ]] && continue
    case "$(loopback_bind "$port" "$proto")" in
      loopback)
        ok "loopback_${svc}_${port}_${proto}" "$svc on 127.0.0.1:$port ($what)" ;;
      public\ *)
        bad "loopback_${svc}_${port}_${proto}" \
            "$svc is bound on a non-loopback address -- $what, and it must be reachable only through the tunnel" ;;
      *)
        bad "loopback_${svc}_${port}_${proto}" \
            "$svc NOT listening on 127.0.0.1:$port -- $what, so dnstt clients get a tunnel that exits nowhere" ;;
    esac
  done <<'LOOPBACK'
2222 tcp dnstt-sshd every dnstt login lands here
7300 tcp dnstt-socks the SOCKS exit those logins forward into
LOOPBACK

  # Is dnstt-server answering for a zone that exists?
  #
  # Every other check here can be green while this one is wrong, and that is not
  # hypothetical -- it was found on this stack's own server. The zone used to be
  # a literal in compose.yml and is now ${VPN_DNSTT_ZONE}, interpolated bare
  # rather than as ${VPN_DNSTT_ZONE:?} for a measured reason (Compose v5.3.1
  # fails project LOAD on the :? form even with dnstt's profile inactive, which
  # would break every compose command the moment the protocol was turned off).
  # Bare means an unset variable becomes the EMPTY STRING, so a container
  # recreated on a box whose .env never gained the variable starts
  # dnstt-server with no zone argument at all: it binds 53/udp, `docker ps`
  # says running, the loopback checks above pass, and it answers for nothing any
  # client can resolve. render() only warns about this -- deliberately, because
  # raising bricked a server once, taking apply, `user add`, `deploy` and the
  # boot unit down with it -- so a warning on stderr during one apply is the
  # whole of the existing signal, and the boot unit has no stderr anybody reads.
  #
  # Read from the RUNNING container rather than from .env, because that is the
  # question: not "is the variable set now" but "what is this process serving".
  # A container created before the variable existed carries the old literal and
  # is fine until something recreates it.
  # argv is parsed, not indexed. `cmd[-2]` looks right and is the trap: an unset
  # ${VPN_DNSTT_ZONE} DROPS OUT of argv rather than arriving as an empty string,
  # so the list is one shorter and cmd[-2] silently becomes the -privkey-file
  # VALUE -- /keys/server.key, which has a dot in it and passes a domain-shaped
  # test. Measured on the real argv from this stack's own server. So: consume the
  # flags that take a value, then require exactly the two positionals
  # dnstt-server's usage defines (`dnstt-server [flags] DOMAIN UPSTREAMADDR`).
  zone=$(docker inspect dnstt-server --format '{{json .Config.Cmd}}' 2>/dev/null \
         | tr -d '\r' \
         | python3 -c '
import json, sys
try:
    argv = json.load(sys.stdin)
    if not isinstance(argv, list):
        raise ValueError
except Exception:
    print("UNREADABLE")
    raise SystemExit(0)
VALUED = {"-udp", "-listen", "-privkey-file", "-pubkey-file", "-mtu"}
positional, skip = [], False
for arg in (str(a) for a in argv):
    if skip:
        skip = False
        continue
    if arg in VALUED:
        skip = True
        continue
    if arg.startswith("-"):
        continue
    positional.append(arg)
# DOMAIN UPSTREAMADDR, in that order. Anything else -- and an empty first
# positional, which is what an explicitly-empty VPN_DNSTT_ZONE would leave --
# means the zone is not there.
print(positional[0] if len(positional) == 2 and positional[0] else "MISSING")' 2>/dev/null)
  case "$zone" in
    UNREADABLE|'')
      bad dnstt_zone \
        "could not read dnstt-server's command line, so the zone it serves is unknown" \
        '"zone":null' ;;
    MISSING)
      bad dnstt_zone \
        "dnstt-server is running with NO zone argument -- it binds 53/udp, looks healthy to every other check here, and answers for nothing a client can resolve. An unset VPN_DNSTT_ZONE interpolates to nothing and drops out of the command; set it in $STATE/.env and apply" \
        '"zone":null' ;;
    *.*)
      ok dnstt_zone "dnstt-server serving zone $zone" \
        "$(printf '"zone":%s' "$(json_str "$zone")")" ;;
    *)
      bad dnstt_zone \
        "dnstt-server's zone '$zone' is not a domain name -- a delegated zone needs at least one dot" \
        "$(printf '"zone":%s' "$(json_str "$zone")")" ;;
  esac
fi

echo "== firewall =="
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
  ok ufw_active "ufw active"
  # Still named ufw_ssh_allowed, and still exists so nobody enables a firewall
  # that locks them out. What changed is that it asks which port that is: the
  # app provisions boxes whose sshd is on 2222 and opens 2222, and this check
  # then failed at the last step of nine on a server that was serving perfectly.
  SSHINFO=$(ssh_ports); SSHP=${SSHINFO%%|*}; SSHSRC=${SSHINFO#*|}
  if [[ -z "$SSHP" ]]; then
    ok ufw_ssh_allowed "$SSHSRC; no ssh access to lock out of" "$(ssh_fields "" "$SSHSRC")"
  else
    read -ra want <<< "$SSHP"
    allowed=""; blocked=""
    for p in "${want[@]}"; do
      if ufw_allows_tcp "$p"; then allowed="${allowed:+$allowed }$p/tcp"
      else blocked="${blocked:+$blocked }$p/tcp"; fi
    done
    if [[ -z "$blocked" ]]; then
      ok ufw_ssh_allowed "$allowed still allowed ($SSHSRC)" "$(ssh_fields "$SSHP" "$SSHSRC")"
    else
      bad ufw_ssh_allowed "$blocked NOT allowed ($SSHSRC) -- you are about to be locked out" \
          "$(ssh_fields "$SSHP" "$SSHSRC")"
    fi
  fi
else
  bad ufw_active "ufw is not active"
fi

echo "== IKEv2 forwarding (silent-no-traffic failure) =="
if docker inspect -f '{{.State.Running}}' ipsec-vpn-server 2>/dev/null | grep -q true; then
  IF=$(ip route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
  # This asserted 192.168.42.0/24 until 2026-09-08 -- the L2TP pool, which no
  # IKEv2 client is ever given -- so it reported green while verifying nothing.
  # Both directions are checked now: one accept without the other still means
  # no traffic, and checking only the outbound one hid that too.
  POOLINFO=$(ikev2_pool); NET=${POOLINFO%%|*}; NETSRC=${POOLINFO#*|}
  fwd_in=0; fwd_out=0
  iptables -C FORWARD -d "$NET" -i "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null && fwd_in=1
  iptables -C FORWARD -s "$NET" -o "$IF" -j ACCEPT 2>/dev/null && fwd_out=1
  if [[ $fwd_in -eq 1 && $fwd_out -eq 1 ]]; then
    ok ikev2_forward_rules "FORWARD accepts present for $NET ($NETSRC)" "$(pool_fields "$NET" "$NETSRC")"
  else
    bad ikev2_forward_rules "FORWARD accepts MISSING for $NET from $NETSRC (inbound=$fwd_in outbound=$fwd_out) -- IKEv2 clients would connect and carry no traffic" \
        "$(pool_fields "$NET" "$NETSRC")"
  fi
else
  ok ikev2_forward_rules "ikev2 not running, forwarding rules not required"
fi

echo
[[ $FAIL -eq 0 ]] && echo "smoke: PASS" || echo "smoke: FAIL"
DONE=1
exit $FAIL
