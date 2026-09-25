#!/bin/sh
# Create one login per person and start sshd on loopback only.
#
# Runs on every start and is idempotent. The container is disposable, and that
# is load-bearing: /etc/passwd resets with it, so a login that has been removed
# from the rendered list is gone on the next `apply` with nothing to clean up.
# It is also why composectl classifies this service RECREATE and not MOUNT --
# nothing below ever deletes an account, so the reset comes entirely from the
# container being new. Restart it instead and a removed user keeps their
# account, their group and their hash.
#
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
# Every account the image ships with, captured at build time by the Dockerfile.
# Recorded rather than derived, because the two questions this file has to tell
# apart -- "this name belongs to a system account" and "this name is an account
# a previous start of this same container created" -- are indistinguishable from
# /etc/passwd alone once the writable layer has been written to once. Guessing
# from the uid range would be a heuristic; this is the actual list.
RESERVED=/etc/dnstt-sshd.reserved

mkdir -p /host-keys
[ -f "$HOST_KEY" ] || ssh-keygen -t ed25519 -N '' -f "$HOST_KEY" >/dev/null
chmod 600 "$HOST_KEY"

addgroup -S "$GROUP" 2>/dev/null || true

# `name:password` per line, rendered from users.json. Only enabled people with
# an issued password are in it.
[ -f "$LOGINS" ] || { echo "no login list at $LOGINS" >&2; exit 1; }
[ -f "$RESERVED" ] || {
  echo "no reserved-account list at $RESERVED -- this image was not built from" >&2
  echo "dnstt-sshd/Dockerfile. Rebuild it: \`vpnctl apply\` passes --build." >&2
  exit 1
}

# Validate the whole list before touching a single account, and refuse the
# start rather than skip a record.
#
# Refusing is the safer half of a genuine trade-off, so here is the argument.
# The loop below is `id || adduser`: it only ever ADDS. So when a name collides
# with an account the image already ships -- root, sshd, nobody, ftp, mail,
# news, uucp, cron, games, guest and seven more, the real list being whatever
# /etc/passwd holds in this base image -- the adduser is skipped, `-G tunnel` is
# never granted, AllowGroups refuses the login, and the chpasswd that followed
# went ahead unconditionally and set that system account's password to the
# person's dnstt password. Measured against the old file: `mail` came out of it
# with a real hash in /etc/shadow, a group list of `mail` alone, and no way in.
# A skipped record would fix only the second half and would hand somebody a
# credential that silently does not work; and this container's entire revocation
# story is /etc/passwd being rebuilt from this file at every start, so a list it
# cannot serve faithfully is not a list to serve partially. Refusing is loud,
# lands at `apply` time where composectl's not_running can see it, and names the
# record to fix.
#
# users_store.validate_name rejects these names at the source, which is where
# the fix belongs. This is the depth: the file arrives from a restore of an
# older backup, a hand-edited users.json or a rolled-back tree, none of which
# that validator ever saw.
nl='
'
seen=""
count=0
# `|| [ -n "$name" ]` because a final line with no trailing newline leaves
# `read` returning 1 with the record already assigned, so the plain form drops
# the last login silently -- one person with no access and nothing said.
while IFS=: read -r name password || [ -n "$name" ]; do
  [ -n "$name" ] || continue
  bad=""
  case "$name" in
    # A leading dash is read as an option by adduser, addgroup and id, so the
    # name would not be a name at all. validate_name's character class permits
    # it, which makes this the one shape it lets through that this file cannot.
    -*) bad="starts with '-', which adduser would read as an option" ;;
    *[!A-Za-z0-9._-]*) bad="contains a character outside [A-Za-z0-9._-]" ;;
  esac
  if [ -z "$bad" ] && [ "${#name}" -gt 32 ]; then
    bad="is longer than 32 characters"
  fi
  if [ -z "$bad" ] && cut -d: -f1 "$RESERVED" | grep -qxF -- "$name"; then
    bad="collides with an account this image already ships"
  fi
  if [ -z "$bad" ] && printf '%s' "$seen" | grep -qxF -- "$name"; then
    # Two records, one account: the second chpasswd wins and the first person's
    # password stops working, with both believing they have access.
    bad="appears twice in the login list"
  fi
  # An empty password field: busybox chpasswd accepts it and writes an empty
  # hash, and sshd's default PermitEmptyPasswords no then refuses the login. So
  # it lands in the same place as the collision -- a person with no access and
  # no explanation -- and it comes from the same place, a list nobody validated.
  if [ -z "$bad" ] && [ -z "$password" ]; then
    bad="has no password"
  fi
  if [ -n "$bad" ]; then
    echo "dnstt-sshd: refusing to start -- the login '$name' $bad." >&2
    echo "No account was created or modified by this start. Remove or rename" >&2
    echo "that user in users.json and apply again, or turn dnstt off." >&2
    exit 1
  fi
  seen="$seen$name$nl"
  count=$((count + 1))
done < "$LOGINS"

if [ "$count" -eq 0 ]; then
  # Refuse rather than start an sshd nobody can log into: a running container
  # with zero accounts looks healthy and answers nothing. This stays as the
  # last line of defence only -- dnstt.render refuses to produce an empty list
  # in the first place, so the operator gets one sentence at apply time instead
  # of a crash-loop that binds no non-loopback port for anything to notice.
  echo "login list is empty -- add a user, or turn dnstt off" >&2
  exit 1
fi

while IFS=: read -r name password || [ -n "$name" ]; do
  [ -n "$name" ] || continue
  id "$name" >/dev/null 2>&1 || adduser -D -H -G "$GROUP" -s /bin/sh "$name"
  # Membership is what AllowGroups tests, and `adduser -G` grants it only on
  # the run that creates the account. A plain `docker restart` -- a reboot, a
  # dockerd restart -- reuses the writable layer and re-runs this loop against
  # accounts that already exist, so assert the membership instead of assuming
  # it: without it sshd refuses the login and logs nothing that names the cause.
  # busybox addgroup is a no-op on an existing member and exits 0.
  id -Gn "$name" | grep -qw "$GROUP" || addgroup "$name" "$GROUP"
  # The password reaches chpasswd on stdin and never an argv: printf is a shell
  # builtin, so no process is spawned to carry it, and chpasswd takes the pair
  # from the pipe. Measured rather than assumed -- 200 iterations sampled
  # against `ps -o args` in a loop produced zero hits on the password. The
  # confirmation chpasswd prints goes to stderr and names the user only, so the
  # container log ends up a record of which logins were set this start and
  # carries no secret.
  printf '%s:%s\n' "$name" "$password" | chpasswd
done < "$LOGINS"

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
