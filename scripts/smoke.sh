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

# The /24 IKEv2 clients are actually assigned from, asked of the container
# rather than hardcoded. Mirrors vpnctl.ikev2ctl._ikev2_ipv4_net exactly:
# `conn ikev2-cp`'s rightaddresspool is authoritative (it is what pluto hands
# out); VPN_XAUTH_NET is only a fallback, and is validated before use because
# an unparseable value handed to `iptables -C` fails in a way that is
# indistinguishable from "the rule is missing". Emits "net|provenance", since
# a value that came from the hardcoded default must not read as a real answer.
ikev2_pool() {
  local line entry first v net why="container unreadable"
  line=$(docker exec ipsec-vpn-server \
           sed -n 's/^[[:space:]]*rightaddresspool=//p' /etc/ipsec.d/ikev2.conf 2>/dev/null | head -1)
  if [[ -n "$line" ]]; then
    entry=$(printf '%s' "$line" | tr ',' '\n' | grep -m1 -E '^[0-9]+(\.[0-9]+){3}' || true)
    first=${entry%%-*}
    net=$(valid_net "${first%.*}.0/24") && {
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
