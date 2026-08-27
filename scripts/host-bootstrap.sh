#!/bin/bash
# One-time (idempotent) host setup for this VPN stack. Run once on the
# server as root before the first `docker compose up`, and safe to re-run.
#
# Exists because network_mode: host means containers share the host's
# network namespace, so Docker refuses `sysctls:` in compose for it --
# these have to be set on the host directly instead. Required by the
# ikev2 (hwdsl2/ipsec-vpn-server) service, which otherwise needs
# `privileged: true`; see compose.yml.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

SYSCTL_FILE=/etc/sysctl.d/99-vpn-stack.conf
cat > "$SYSCTL_FILE" <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv6.conf.all.forwarding = 1
# MTU/MSS fix for mobile (Android/iOS) L2TP/IPsec and IKEv2 clients.
net.ipv4.ip_no_pmtu_disc = 1
EOF
sysctl --system

if command -v ufw >/dev/null; then
  ufw allow 22/tcp comment 'ssh'
  ufw allow 10443/tcp comment 'vless-reality'
  ufw allow 20443/udp comment 'hysteria2'
  ufw allow 500/udp comment 'ikev2/ipsec ike'
  ufw allow 4500/udp comment 'ikev2/ipsec nat-t'
  ufw allow 1701/udp comment 'l2tp'
  ufw --force enable
  ufw status verbose
else
  echo "ufw not found, skipping firewall setup" >&2
fi
