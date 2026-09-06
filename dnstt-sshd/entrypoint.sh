#!/bin/sh
# Create one login per person and start sshd on loopback only.
#
# Runs on every start and is idempotent. The container is disposable, and that
# is load-bearing: /etc/passwd resets with it, so a login that has been removed
# from the rendered list is gone on the next `apply` with nothing to clean up.
# The one thing that must outlive the container is the host key, which lives in
# a volume -- baking it into the image would give every deployment the same
# one, and making a fresh one per start would warn or fail on every client at
# every restart.
set -eu

SSH_PORT="${SSH_PORT:-2222}"
SOCKS_EXIT="${SOCKS_EXIT:-127.0.0.1:7300}"
# Where these logins may forward. See vpnctl/protocols/dnstt.py for why the
# default is "any": the clients use SSH *dynamic* forwarding, so every site is
# a fresh destination and no fixed list can ever match. Narrow it by rendering
# a different PERMIT_OPEN; the log names every destination it refuses.
PERMIT_OPEN="${PERMIT_OPEN:-any}"
LOGINS="${LOGINS:-/conf/logins}"
HOST_KEY=/host-keys/ssh_host_ed25519_key
GROUP=tunnel

mkdir -p /host-keys
[ -f "$HOST_KEY" ] || ssh-keygen -t ed25519 -N '' -f "$HOST_KEY" >/dev/null
chmod 600 "$HOST_KEY"

addgroup -S "$GROUP" 2>/dev/null || true

# `name:password` per line, rendered from users.json. Only enabled people with
# an issued password are in it.
[ -f "$LOGINS" ] || { echo "no login list at $LOGINS" >&2; exit 1; }
count=0
while IFS=: read -r name password; do
  [ -n "$name" ] || continue
  id "$name" >/dev/null 2>&1 || adduser -D -H -G "$GROUP" -s /bin/sh "$name"
  printf '%s:%s\n' "$name" "$password" | chpasswd >/dev/null
  count=$((count + 1))
done < "$LOGINS"

if [ "$count" -eq 0 ]; then
  # Refuse rather than start an sshd nobody can log into: a running container
  # with zero accounts looks healthy and answers nothing.
  echo "login list is empty -- add a user, or turn dnstt off" >&2
  exit 1
fi
echo "dnstt-sshd: $count login(s), forwarding to: $PERMIT_OPEN"

cat > /etc/ssh/sshd_config <<CONF
Port $SSH_PORT
# Loopback only. The single way in is the dnstt tunnel, which hands the decoded
# stream to this port; nothing on the network can reach it.
ListenAddress 127.0.0.1
HostKey $HOST_KEY

PermitRootLogin no
AllowGroups $GROUP
PasswordAuthentication yes
KbdInteractiveAuthentication no

# These logins exist to forward, and for nothing else: no agent, no X11, no tun
# device, and they cannot bind a port for anybody else.
AllowTcpForwarding yes
AllowAgentForwarding no
X11Forwarding no
GatewayPorts no
PermitTunnel no

Match Group $GROUP
    PermitOpen $PERMIT_OPEN
CONF

exec /usr/sbin/sshd -D -e
