#!/bin/sh
# Create the tunnel login and start sshd on loopback only.
#
# Runs on every start and is idempotent: the container is disposable, and the
# one thing that must outlive it is the host key, which lives in a volume.
# Baking a key into the image would give every deployment the same one; making
# a fresh one per start would warn or fail on the client at every restart.
set -eu

: "${SSH_USER:?SSH_USER is required}"
: "${SSH_PASSWORD:?SSH_PASSWORD is required}"
SSH_PORT="${SSH_PORT:-2222}"
# Where this login may forward. See dnstt.py for why the default is "any":
# the clients use SSH *dynamic* forwarding, so every site is a fresh
# destination and no fixed list can ever match. Narrow it by rendering a
# different PERMIT_OPEN; the log names every destination it refuses.
PERMIT_OPEN="${PERMIT_OPEN:-any}"
HOST_KEY=/host-keys/ssh_host_ed25519_key

mkdir -p /host-keys
[ -f "$HOST_KEY" ] || ssh-keygen -t ed25519 -N '' -f "$HOST_KEY" >/dev/null
chmod 600 "$HOST_KEY"

id "$SSH_USER" >/dev/null 2>&1 || adduser -D -s /bin/sh "$SSH_USER"
printf '%s:%s\n' "$SSH_USER" "$SSH_PASSWORD" | chpasswd >/dev/null

cat > /etc/ssh/sshd_config <<CONF
Port $SSH_PORT
# Loopback only. The single way in is the dnstt tunnel, which hands the decoded
# stream to this port; nothing on the network can reach it.
ListenAddress 127.0.0.1
HostKey $HOST_KEY

PermitRootLogin no
AllowUsers $SSH_USER
PasswordAuthentication yes
KbdInteractiveAuthentication no

# This login exists to forward, and nothing else: no shell worth having, no
# agent, no X11, no tun device, and it cannot bind a port for anybody else.
AllowTcpForwarding yes
AllowAgentForwarding no
X11Forwarding no
GatewayPorts no
PermitTunnel no

Match User $SSH_USER
    PermitOpen $PERMIT_OPEN
CONF

exec /usr/sbin/sshd -D -e
