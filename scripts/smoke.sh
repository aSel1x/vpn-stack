#!/bin/bash
# Post-deploy assertions. Answers "is the thing actually serving?", not
# "did the command exit 0?" -- every check here corresponds to a failure mode
# that has really happened on this stack.
set -uo pipefail

STATE="${VPN_STATE:-/etc/vpn-stack}"
FAIL=0
ok()  { printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { printf '  \033[31m✗\033[0m %s\n' "$1"; FAIL=1; }

echo "== rendered config =="
[[ -L "$STATE/rendered" ]] && ok "rendered is a symlink -> $(readlink "$STATE/rendered")" \
                           || bad "$STATE/rendered is not a symlink (promotion never ran)"
[[ -f "$STATE/rendered/sing-box/00_base.json" ]] && ok "sing-box tree present" \
                                                 || bad "sing-box tree missing"

echo "== containers =="
for c in sing-box; do
  s=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null | tr -d '\n')
  [[ "$s" == "running" ]] && ok "$c running" || bad "$c is '${s:-absent}'"
done

echo "== listeners (a container can run and still bind nothing) =="
# Enumerated from the registry, so this follows `protocol on/off` automatically.
# If the enumeration itself fails we FAIL rather than skip: a check that
# silently verifies nothing and still reports PASS is worse than no check.
PORTS=$(vpnctl --json protocol list 2>/dev/null \
        | python3 -c 'import sys,json
d=json.load(sys.stdin)
for p in d.get("protocols",[]):
    if p["enabled"]:
        for x in p["ports"]:
            n,_,pr=x.partition("/"); print(n,pr)' 2>/dev/null) || PORTS=""

if [[ -z "$PORTS" ]]; then
  bad "could not enumerate expected ports (is vpnctl on PATH?) -- failing, not skipping"
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
  while read -r port proto; do
    [[ -z "$port" ]] && continue
    served "$port" "$proto" && ok "$port/$proto bound" || bad "$port/$proto NOT bound"
  done <<< "$PORTS"
fi

echo "== firewall =="
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
  ok "ufw active"
  ufw status 2>/dev/null | grep -qE '^22/tcp\s+ALLOW' && ok "22/tcp still allowed" \
                                                      || bad "22/tcp NOT allowed -- you are about to be locked out"
else
  bad "ufw is not active"
fi

echo "== IKEv2 forwarding (silent-no-traffic failure) =="
if docker inspect -f '{{.State.Running}}' ipsec-vpn-server 2>/dev/null | grep -q true; then
  IF=$(ip route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
  if iptables -C FORWARD -s 192.168.42.0/24 -o "$IF" -j ACCEPT 2>/dev/null; then
    ok "FORWARD accepts present"
  else
    bad "FORWARD accepts MISSING -- IKEv2 clients would connect and carry no traffic"
  fi
else
  ok "ikev2 not running, forwarding rules not required"
fi

echo
[[ $FAIL -eq 0 ]] && echo "smoke: PASS" || echo "smoke: FAIL"
exit $FAIL
