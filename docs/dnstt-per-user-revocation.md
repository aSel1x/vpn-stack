# A DNS tunnel with per-person revocation

How `vpn-stack` runs dnstt as a transport of last resort where access can be taken away from one
person without taking it away from everybody. Written from what is in the repository and what was
measured on it; every number here traces to `CLAUDE.md`, to `dnstt/SETUP.md`, to the code, or to the
one experiment this document carries its own recipe for, and the things that were never measured are
named as such at the end.

The central claim is that a container whose accounts are built from its input at create time cannot be
restarted to revoke one of them. That is not presented as an argument. [Reproducing the bypass, in
about ten minutes](#reproducing-the-bypass-in-about-ten-minutes) is the whole thing in one throwaway
container built from this repository's own Dockerfile — build, revoke a user, restart, watch the
revoked user log in.

## What this is not

A DNS tunnel is the worst transport in the stack and it is meant to be. Every byte is encoded into
DNS queries for a delegated subdomain, handed to a resolver that belongs to somebody else, and
recursed to the authoritative server. `dnstt/SETUP.md` records that a negotiated MTU of roughly
130–930 bytes is normal on this path and not a bug. Throughput and latency were never benchmarked
here, so no figure for either appears in this document.

It is not a replacement for the everyday path. In this stack that path is VLESS+REALITY on
`10443/tcp` and Hysteria2 on `20443/udp`, and they were unaffected on the same network where the
observations below were taken. dnstt ships **off** (`default_enabled=False` in
`vpnctl/protocols/dnstt.py`) and stays off unless somebody has a reason: it needs a DNS zone
delegated to the server, which a fresh box has not got, and `udp/53` bound on a box without one is
pure attack surface.

The reason to build it anyway is the case where nothing else is left.

## When it matters

Two observations motivated it. Both come from one vantage point, which is the main limitation of
this whole document.

**An egress whitelist that permits only the carrier's own resolver.** `dnstt/SETUP.md` §7a records
that on the mobile network this was built for, public resolvers (`8.8.8.8`, `1.1.1.1`) and DoH/DoT
on `:443`/`:853` were dropped, and only the carrier's own resolver on `:53`, plain UDP, got through.
The repository does not record a date for that measurement. A tunnel whose only outbound requirement
is "the network's own resolver answers port 53" is exactly shaped for that network.

**A filter that drops a protocol by payload shape, not by port.** Measured 2026-09-08 from one
subscriber line on one Russian ISP (Rostelecom), while investigating why IKEv2 clients could never
connect. This is an observation from a single line on a single date; it is not a statement about that
company's policy, and one vantage point cannot support one.

The measurement set **TTL=3** as a ceiling on every probe, identical for both shapes, so nothing sent
could reach the destination, and varied only the destination address:

| destination | genuine `IKE_SA_INIT` | same-size junk |
| --- | --- | --- |
| the server under test (hosted in Sweden) | 0/3 | 3/3 |
| `8.8.8.8`, `1.1.1.1`, `9.9.9.9`, `185.199.108.153` | 0/3 each | 3/3 each |
| `194.87.49.94` (Timeweb, RU-owned) | 3/3 | 3/3 |
| `77.88.8.8`, `213.180.204.242` (Yandex) | 3/3 | 3/3 |

Read the table by what came *back*, because that is where the two shapes part. The junk reached a
router that dropped it for expiry and said so, which is the 3/3. The genuine `IKE_SA_INIT` to the
same address produced no report at all, which is the 0/3 — it was discarded inside those same few
hops by a device that returned nothing. Google, Cloudflare, Quad9 and GitHub do not run IKE filters,
and in any case never saw either packet, so the decision was being taken on the client side of the
path, keyed on payload shape times destination. Three properties followed. It is stateful and the first
packet of a flow decides: 200 retransmits of a real `IKE_SA_INIT` drew zero replies, while priming
the same 5-tuple with one junk datagram first let the byte-identical `IKE_SA_INIT` through and
`pluto` answered it in full. It is destination-port-independent: IKE payloads were dropped on 53,
443, 1701, 12345 and 51820 alike while same-size junk arrived on every one, so moving IKEv2 to
another port cannot help. And it applied identically over IPv6, so it is not a NAT artifact.

To repeat it, from the failing client's own network:

```bash
bash scripts/diagnose-ikev2.sh probe <ip>   # sends a real IKE_SA_INIT plus a marked junk control
bash scripts/diagnose-ikev2.sh path  <ip>   # walks TTLs with both shapes, interleaved
bash scripts/diagnose-ikev2.sh local        # local state only
sudo bash scripts/diagnose-ikev2.sh listen  # on the server; captures for 90s by default
```

`path` is the one that localises the drop without a second host: if IKE stops earning ICMP
time-exceeded at a hop where same-size junk still earns it, the filter is at that hop, upstream of
the destination. Run it a second time against a host you know answers IKE — that is the control, and
it is what shows the filter is keyed on destination rather than simply present. `listen` reports
*which shape* arrived, which matters because an earlier version of this script sent only a plain
`DIAGPROBE-<host>` datagram: that is precisely the shape such a filter passes, so it reported "not
blocked" in exactly the case it exists to detect. A junk datagram on port 500 is not a proxy for IKE.

The port sweep and the priming result were separate measurements and are not what that command
reproduces.

## The tension this design exists to resolve

dnstt's transport is Noise-encrypted and the client pins the server's public key. That key belongs to
the **server**. It has to: it encrypts the transport before anybody has authenticated to anything, so
there is nothing yet to tell one person from another. It cannot be per-person, and rotating it
revokes everybody at once, because every client has pinned it.

The first version of this took the obvious next step and gave the tunnel one shared account behind
it. That is a revocation hole with a user database in front of it. `user rm alice` removed Alice's
record, reissued nothing, and left her tunnel working — the credential she actually held was the
shared one, and there was nothing personal to revoke.

The fix is to put the per-person boundary one layer up, in the sshd that the decoded stream exits
into. `vpnctl/protocols/dnstt.py` renders exactly three files:

```
dnstt/server.key        the Noise private half   (0600)
dnstt-sshd/logins       name:password per line, one line per enabled user
dnstt.env               SSH_PORT, SOCKS_EXIT, PERMIT_OPEN
```

`logins` holds one line per **enabled** user who has a `dnstt_password`. `dnstt-sshd/entrypoint.sh`
reads it at container start, validates the whole list before it touches a single account, creates the
accounts, asserts each one's membership of the `tunnel` group, and writes `/etc/ssh/sshd_config`
itself. So `/etc/passwd` inside that container is a function of `users.json`, rebuilt from it every
time, and a name that has dropped out of the list has no account to log into. The transport stays
shared; the login does not. The repository records this as verified: after a `user disable`, that
person's own password was refused while everyone else's still worked.

Three things in that entrypoint are there because their absence cost something, and all three are
about the same gap — `user add` validates what it writes, while the entrypoint is handed whatever a
hand edit, a restore of an older backup or a rolled-back tree left in the file.

**The list is validated whole, and a list this container cannot serve faithfully is refused rather
than served partially.** A name that collides with an account the base image ships used to skip the
`adduser`, and with it the `-G tunnel` grant that `AllowGroups` tests, while the `chpasswd` that
followed ran anyway — setting *that system account's* password to the person's dnstt password.
Measured against the old file: a user named `mail` came out with a real hash in `/etc/shadow`, a group
list of `mail` alone, and no way in. The image snapshots its own accounts at build time into
`/etc/dnstt-sshd.reserved`, because once the writable layer has been written to, `/etc/passwd` cannot
tell a baked-in system account from an account a previous start of the same container created — and
that difference decides whether a name is a collision to refuse or a login to reuse. A leading `-`
(which `adduser` would read as an option, and which `users_store.validate_name`'s character class
lets through), a character outside `[A-Za-z0-9._-]`, a name over 32 characters, a duplicate record
and an empty password field are refused on the same footing, each naming the record to fix.
`users_store.validate_name` rejects the same reserved names at `user add`, which is where the fix
belongs; this is the depth behind it.

**Group membership is asserted on every start, not assumed.** `adduser -G` grants it only on the run
that creates the account, so a plain `docker restart` — a reboot, a `dockerd` restart — re-ran the
loop against accounts that already existed and sshd then refused every login while logging nothing
that named the cause.

**The password never reaches an argv.** `printf` is a shell builtin, so no process is spawned to carry
it, and `chpasswd` takes the pair from the pipe; 200 sampled iterations against `ps -o args` produced
zero hits. The confirmation `chpasswd` prints names the user only, so the container log is a record of
which logins were set this start and carries no secret.

The same shape appears elsewhere in the stack — IKEv2 certificates are reconciled against the enabled
user list on every apply rather than remembered — and the principle is the same. Derive the live state
from the database; do not trust a record of what you once did.

## Why the container must be recreated, not restarted

This is the part worth copying, and the part that bit.

The entrypoint only ever **adds**. The account loop is the second of its two passes over the login
list (`dnstt-sshd/entrypoint.sh:131`), and the whole of its account creation is:

```sh
id "$name" >/dev/null 2>&1 || adduser -D -H -G "$GROUP" -s /bin/sh "$name"
```

`grep -n 'deluser\|userdel' dnstt-sshd/entrypoint.sh` returns nothing, and that is deliberate — the
file says so in its own header. Everything the rewrite above added validates, asserts or refuses;
none of it deletes.

Its correctness rests entirely on the container being **new**: `/etc/passwd` resets with the container,
so a login that dropped out of the rendered list is gone with nothing to clean up.

`vpnctl/composectl.py` decides how each rendered path reaches the process that consumes it. The table
is hand-written, because `docker compose config` can answer only half of it:

```python
("dnstt/",      "dnstt",      MOUNT),
("dnstt-sshd/", "dnstt-sshd", RECREATE),
("dnstt.env",   "dnstt-sshd", RECREATE),
```

`dnstt-sshd/logins` is a plain bind mount, and a bind mount is the textbook case for `MOUNT` — Docker
re-resolves the mount source on start, so `restart` lands the new file. It was classified that way
once. The result is a revocation bug, not a latency bug: `restart` reuses the container's writable
layer, so the removed user keeps their account, their group and their password hash, `AllowGroups
tunnel` still admits them, and `user rm` prints success having revoked nothing. Caught in review, and
now held by a test named after the reason:

```
tests/test_composectl.py::test_a_changed_login_list_recreates_dnstt_sshd_because_its_entrypoint_only_adds
```

There was a second instance of the same trap, one level down. `composectl.up` compares container ids
from before and after `docker compose up -d`, and skips its own `--force-recreate` nudge for any
service compose has already replaced. The "before" snapshot came from `docker compose ps --status
running`, so a **stopped** `dnstt-sshd` was absent from it; `up -d` then *started* that same container
— same id, same writable layer — and the diff read the new appearance as "compose created this one
just now" and skipped the recreate, so the removed account survived again. The snapshot is now
`ps --all`, guarded by `test_a_stopped_container_is_recreated_not_taken_for_a_fresh_one` and by a
second test that asserts the argv rather than the parse, because the flag *is* the fix.
`_container_ids`' own docstring states the stake in one clause: `--all`, not `--status running`,
"because the difference is a credential left working."

### Reproducing the bypass, in about ten minutes

That the revoked account still authenticates is not a deduction. It was reproduced during review of
the change, and re-run on **2026-09-11** (Docker 29.6.2, the `alpine:3.20` base the `dnstt-sshd` image
is built from) to produce the output quoted below. `entrypoint.sh` has been rewritten since that run
— it validates the whole list first, asserts group membership on every start and refuses a reserved
name — and none of that touches the mechanism under test: the recipe's two names pass validation, and
nothing added deletes an account. The quoted lines are from the earlier run; re-run it rather than
trusting that sentence. Nothing here needs a state
directory, a DNS zone, `vpnctl`, or a server: the whole mechanism lives in one container's writable
layer, so a throwaway container built from this repository's own `dnstt-sshd/Dockerfile` and
`entrypoint.sh` is the entire apparatus. `docker restart` stands in for `docker compose restart`, and
`docker rm -f` plus a fresh `run` for `up -d --force-recreate`, because what is under test is the
writable layer rather than anything compose does. Run it from the repository root.

```bash
docker build -t dnstt-sshd-probe dnstt-sshd/
printf 'alice:pw-alice\nbob:pw-bob\n' > /tmp/logins
docker run -d --name probe -v /tmp/logins:/conf/logins:ro dnstt-sshd-probe

docker exec probe id bob                     # uid=1001(bob) gid=101(tunnel)
docker exec probe grep '^bob:' /etc/shadow   # keep this line to compare against

printf 'alice:pw-alice\n' > /tmp/logins      # bob revoked, exactly as `render` would emit it
docker restart probe                         # the classification under test

docker exec probe cat /conf/logins           # alice only -- the new file DID arrive
docker logs probe | tail -2                  # "dnstt-sshd: 1 login(s)" -- it agrees bob is gone
docker exec probe id bob                     # uid=1001(bob) gid=101(tunnel) -- still there
docker exec probe grep '^bob:' /etc/shadow   # byte-identical to the line kept above

docker exec probe apk add -q --no-cache openssh-client sshpass
docker exec probe sshpass -p pw-bob ssh -p 2222 -o StrictHostKeyChecking=no \
    bob@127.0.0.1 'id -un; id -Gn'           # bob / tunnel
docker logs probe | grep 'Accepted password for bob'

docker rm -f probe                           # == up -d --force-recreate: a new writable layer
docker run -d --name probe -v /tmp/logins:/conf/logins:ro dnstt-sshd-probe
docker exec probe id bob                     # id: unknown user bob
docker exec probe id alice                   # alice untouched throughout
docker rm -f probe && rm /tmp/logins
```

The middle of that run is the finding, and it is sharper than "the restart did not pick up the new
file" — the restart **did** pick it up. The container re-read the bind mount, logged
`dnstt-sshd: 1 login(s), forwarding to: any`, and by its own account had one user. Meanwhile:

```
$ docker exec probe id bob
uid=1001(bob) gid=101(tunnel) groups=101(tunnel),101(tunnel)
$ docker logs probe | grep 'Accepted password for bob'
Accepted password for bob from 127.0.0.1 port 38768 ssh2
```

So the mount classification was right about the mount and wrong about the container. The file arrived;
the account it was supposed to remove did not leave, because `/etc/passwd` and `/etc/shadow` live in
the writable layer that `restart` keeps, and the entrypoint's only account operation is an `adduser`
behind an `id` guard. `AllowGroups tunnel` still matched, the old hash still verified, and a `user rm`
would have reported success.

Two details to read correctly. The password check is genuine rather than an sshd that accepts
anything — the same command with a wrong password returns `Permission denied (publickey,password)`,
which is worth running as the control. And `adduser -H` gives these accounts no home directory, so the
session prints `Could not chdir to home directory /home/bob` before it runs the command; that is
cosmetic. The `Accepted password` line is the result, because authentication is the thing that was
supposed to have been revoked.

After the recreate, `id bob` reports `unknown user bob` and `/etc/shadow` has no line for him, while
alice is unaffected — which is what makes `RECREATE` the fix rather than a precaution.

The general rule this yields: **a container whose state is derived from its input at create time can
never be classified as restartable.** Whatever the mount looks like. The cost of over-recreating is
seconds of downtime; the cost of under-recreating is a credential you believe you revoked. When in
doubt, recreate.

## Why the sshd is in a container

iOS clients for this path (HTTP Injector, AnyBridge, in mode `DNSTT → SSH`) run SSH on top of the
tunnel, so dnstt has to hand the decoded stream to an sshd. It hands it to `127.0.0.1:2222`, which is
an Alpine container with `openssh-server`, nothing mounted but its host-key volume and the read-only
login list, and not the host's sshd.

On the host, the same feature would be a real account in `/etc/passwd` plus an edit to
`/etc/ssh/sshd_config`. Neither is captured by `vpn backup`, which tars the state directory and the
IKEv2 volume; both would have to be recreated by hand after every rebuild, which is the kind of step
that is remembered once. In a container the login's blast radius is an empty Alpine, the config is
generated from the rendered `dnstt.env` on every start, and the whole thing is reproducible from
`users.json`.

One piece of state must outlive the container: the host key. It lives in the `dnstt-sshd-keys` volume.
Baking it into the image would give every deployment the same key; generating a fresh one per start
would warn or fail on every client at every restart — and since the user list legitimately recreates
this container, that would be often.

The generated config is narrow in every direction except one:

```
Port 2222                          # SSH_PORT, from the rendered dnstt.env
ListenAddress 127.0.0.1            # the tunnel is the only route in
HostKey /host-keys/ssh_host_ed25519_key
PermitRootLogin no
AllowGroups tunnel
PasswordAuthentication yes
KbdInteractiveAuthentication no
AllowTcpForwarding yes             # the entire point of the login
AllowAgentForwarding no
X11Forwarding no
GatewayPorts no
PermitTunnel no
Match Group tunnel
    PermitOpen any
```

It also refuses to start with an empty login list (`login list is empty -- add a user, or turn dnstt
off`), rather than running an sshd nobody can log into, which would look healthy and answer nothing.
That is the last line of defence and not the first: `dnstt.render` raises rather than emit an empty
list, so the operator meets one sentence at `apply` time — before the candidate tree is promoted —
instead of a crash-loop. Safe to raise on, unlike the missing zone, because every route out of it
writes `users.json` before it applies (`user add`, `user enable`, setting `dnstt_password` by hand)
and `protocol off dnstt` does not render dnstt at all, so the refusal cannot block its own fix.

`sshd` runs as `sshd -D -e`, so everything it has to say — which logins were set this start, every
`Accepted password`, every destination `PermitOpen` refused — goes to stderr and therefore to
`docker logs dnstt-sshd`. None of it appears in the host's `/var/log/auth.log`; the host's sshd never
sees these sessions.

## `PermitOpen any`, and why a list is not a workable alternative

These clients use SSH **dynamic** forwarding. Every site is a fresh destination, which means no fixed
list can match. That is not a deduction from the protocol; the server's own log proved it twice, in
two steps. Both excerpts below are quoted from `dnstt/SETUP.md` §4, which is where this
deployment recorded them when it happened; they are not reconstructed here.

With only the SOCKS exit permitted, every session died at its first name lookup, having never touched
the SOCKS:

```
Accepted password for dnstt from 127.0.0.1
Received request ... to connect to host 1.1.1.1 port 853, but the request was denied.   ×17
```

(`dnstt` there is the shared account of the time — these lines predate the per-person logins. The count
of 17 is the figure `CLAUDE.md` and the module comment in `vpnctl/protocols/dnstt.py` both record.)

The apps resolve over DNS-over-TLS *through* the tunnel before they open anything. Allowing that
resolver moved the failure exactly one step along, to twenty-odd web hosts on `:443`. Three of those
refusals are the example lines `dnstt/SETUP.md` keeps:

```
to connect to host 17.248.213.67 port 443, but the request was denied.
to connect to host 142.251.156.119 port 443, but the request was denied.
to connect to host 2a01:b740:1361:101::c port 443, but the request was denied.
```

That is three lines out of twenty-odd, one of them an IPv6 destination. The module comment
characterises the whole set as "Apple, Google, Fastly, IPv6 among them" — a description of all of it,
not a caption for these three, and no per-address attribution is made here. What the sample shows is
the only thing the argument needs: the destinations are ordinary web hosts, they are not the same
twice, and there is no finite list of them. Hence `PERMIT_OPEN = ("any",)`.

**What this concedes.** Whoever holds one of these passwords can open a TCP connection from the server
to anywhere, including the server's own loopback. On this host that loopback reaches `sshd` on 22,
which is world-open in ufw anyway, and `microsocks` on `127.0.0.1:7300`, which is loopback by design
— but that is this host's inventory today, not a guarantee, and anything else an operator binds to
loopback becomes reachable through this login by default. Read that as the actual trade and judge it
against your own box.

**Why the answer is not a shorter list.** What bounds the risk here is the credential's blast radius,
not the destination set: the password is random (`secrets.token_urlsafe(16)`, with `-` and `_`
substituted so the value carries no shell metacharacter, no colon — `chpasswd`'s own separator — and
no glyph that is easily confused when retyped on a phone), the sshd binds loopback only, there is
exactly one route to it, and that route already requires the pinned Noise key. The other three
protocols on this server already hand unrestricted network access to whoever holds their credentials;
restricting the last-resort protocol alone would buy nothing and would leave the people in the most
locked-down networks with the least useful of the four.

Narrowing it is one rendered value if you have a reason —
`PERMIT_OPEN="*:443 *:80 1.1.1.1:853"` keeps browsing while blocking mail relay and port scanning —
and `docker logs dnstt-sshd` names every destination it refuses, which is how both observations above
were obtained. Just do not mistake a list for the thing that is holding this up.

## Operational consequences

**Changing the user list drops live dnstt sessions.** The container is recreated, so every tunnel it
serves goes with it. The same is already true of IKEv2, where recreating the container drops L2TP,
Cisco IPsec and IKEv2 sessions alike. It is the price of deriving `/etc/passwd` from the database, and
it is the right side of the trade: the alternative is the revocation bug above. An `apply` that changes
nothing — every deploy, every boot — bounces nothing, because `changed_services` diffs the promoted
tree against the candidate first. The one thing that diff cannot see is a tree that was promoted and
then *not* converged, since the next render is byte-identical to it and diffs to nothing; so `apply`
writes `converge_pending` into `state.json` immediately after the symlink swap and lifts it only when
the readiness wait passed, because a port that never bound means the convergence did not finish. (A
teardown or firewall failure does not hold it down: neither is a claim that the containers are running
the wrong tree.) Without that mark, a `composectl.up` that died part-way left the operator's retry
rendering the same tree, bouncing nothing, passing the port wait because the *old* containers still
held the ports, and printing "config unchanged; nothing restarted" then "OK." — with `smoke.sh` green.

**A user predating the field gets no login, loudly.** `users.json` grew `dnstt_password` after dnstt
was already shared, so a record created before that has none. `render` emits no line for that person
and warns on stderr, naming them:

```
warning: no dnstt login for <names> (created before dnstt became per-user);
set dnstt_password in users.json, or re-add the user
```

There is deliberately no migration command for a one-record problem: set the field or re-add the user.

**Neither the renderer nor the loader may mint that password.** `render` and `share` are pure — no
`open()`, no `subprocess`, no globals — because they are the seam a GUI renders share links through
with no server round-trip. A pure function cannot mint a credential, and `apply` quietly minting one
would be handing out a password nobody had been told. `users_store.load()` must not do it either: an
earlier version minted a missing `l2tp_password` and saved it, so a plain `user list` could rotate a
live credential. Booleans get defaults because they are derivable; a missing *secret* is a damaged
database and says so. Minting belongs in `user add` and nowhere else.

**The zone is deployment config, not a constant.** `VPN_DNSTT_ZONE` lives in `/etc/vpn-stack/.env`
and is read twice: `compose.yml` interpolates it into dnstt's `command:`, and `render.snapshot()`
folds it into the `Secrets` snapshot under `dnstt.zone` so the pure layer receives it as an argument.
It used to be hardcoded in both the module and `compose.yml` — which meant a stranger who cloned the
repository and ran `protocol on dnstt` served the author's zone, with their clients resolving a domain
somebody else controlled. Delegate your own and point NS at the box:

```
ns-tun.example.net.   A    203.0.113.10
tun.example.net.      NS   ns-tun.example.net.
```

`dig +short NS tun.example.net` confirms it, then
`echo 'VPN_DNSTT_ZONE=tun.example.net' >> /etc/vpn-stack/.env`. `compose.yml` uses the
bare `${VPN_DNSTT_ZONE}` form and **not** `${VPN_DNSTT_ZONE:?}`, because on Compose v5.3.1 the `:?`
form fails *project load* even with dnstt's profile inactive — which would break every compose command
on a server where dnstt is merely switched off. And dnstt binds `${VPN_SERVER_HOST}:53` explicitly,
never wildcard `:53`, because `systemd-resolved` already holds `127.0.0.53:53`. For the same reason
"bound" means bound on a non-loopback address in both `composectl` and `scripts/smoke.sh`: substring
-matching the port number reports `53/udp` as served on any stock Ubuntu.

Two consequences of that bare form, and both were paid for. **An unset variable does not arrive as an
empty string; the argument drops out of the command entirely**, so a container recreated on a box whose
`.env` never gained the variable runs `dnstt-server` with no zone at all — it binds 53/udp, `docker ps`
says running, both loopback back-ends are up, and it answers for nothing a client can resolve.
`render` only warns about that, deliberately: raising bricked a server once, taking `apply`, `user
add`, `deploy` and the boot unit down together after `protocol on dnstt` had already written
`state.json`, and the boot unit has no stderr anybody reads. So `scripts/smoke.sh` grew a check named
`dnstt_zone` that reads the running container's argv — not `.env`, because the question is what this
process is serving — and *parses* it rather than indexing it: `cmd[-2]` looks right and is the trap,
since a dropped zone makes argv one shorter and `cmd[-2]` becomes the `-privkey-file` value,
`/keys/server.key`, which has a dot in it and passes any domain-shaped test.

And the two readers have to agree on the same bytes. `vpnctl/dotenv.py` now strips one matching pair
of wrapping quotes, as compose does, plus a leading `export`. Before that,
`VPN_DNSTT_ZONE="tun.example.net"` handed the container `tun.example.net` and every share link the
literal `"tun.example.net"`, a zone no resolver answers for, with nothing reporting the mismatch. A
trailing comment is deliberately *not* stripped, because compose does not strip one either — and
`scripts/provision-host.sh`, which writes the commented `#VPN_DNSTT_ZONE=` hint into that file, says
so where it writes it.

**The Noise keypair is produced at enable time, not at install.** `prepare()` builds the Go image and
runs `dnstt-server -gen-key`, because the key format is the binary's own. Doing that in `bootstrap`
would make every fresh server pay a Go toolchain build and roughly 800 MB of disk for a protocol that
ships disabled. `-gen-key` prints both halves as 64 hex characters on stdout and that is what is
parsed; the `-privkey-file` route was tried and writes root-owned files that nothing but root can read
back, leaving a temp directory that then fails to clean up. If `prepare()` fails, the enable is
**rolled back**, because leaving the protocol on with no key makes every later `apply` — including the
one systemd runs at boot — die on a missing secret with no clue how it got there. `protocol on dnstt`
with no zone refuses earlier still, before `state.json` is written and before the image build is paid
for: nothing written is nothing to roll back. Turning dnstt off keeps the secrets, so turning it back
on restores every profile already handed out.

**The rendered login list is plaintext, and its mode is now a default rather than a guess.**
`dnstt-sshd/logins` holds every enabled user's dnstt password in the clear, because `chpasswd` in the
entrypoint needs it that way. `write_candidate` writes **everything** in the candidate tree at 0600,
chosen by default and not by filename, and `tests/test_render_build_tree.py::test_every_rendered_file_is_0600`
asserts it over the whole tree rather than over a list of names — so a new credential-bearing output is
covered the day it is added.

It is worth keeping the defect that motivated that, because the shape recurs. The mode used to be
`0600 if the name ends in .key or .env, else 0644`, and `dnstt-sshd/logins` ends in neither — so the
plaintext list of every user's dnstt password was rendered world-readable, contained only by the 0700
root-owned state directory it sat in. Nothing was wrong with the rule as written; it was wrong as a
*default*. A filename-matching rule covers the credentials somebody remembered to name, and the next
credential arrives under a name nobody extended the list for. The same reasoning moved `.gitignore` in
this repo from exact paths to directory-wide entries. Nothing needed the wider mode in any case: every
rendered path is bind-mounted read-only into a container that reads it as root, and no service in
`compose.yml` declares a `user:`. The mode is also passed to `os.open` at creation rather than
applied by a `write_bytes()` then `chmod()` pair, which would leave a private key at the umask default
for the width of a syscall; the `chmod` that follows is still there, because `O_CREAT`'s mode argument
is itself masked by the umask and the explicit call is not.

**The three dnstt images are built here, and every input they fetch is pinned.** This was the weakest
point in the protocol's supply chain: `dnstt/Dockerfile` did `go install …/dnstt-server@latest`,
`dnstt-socks/Dockerfile` did `git clone --depth 1` of whatever microsocks' HEAD happened to be, and all
three floated on `alpine:3.20` and `golang:1.23-alpine`. `composectl.up` passes `--build`, and `apply`
runs from `user add`, `user rm`, `protocol on`, `protocol off`, `deploy` and the `vpn-stack.service`
boot unit — so each of those was a re-resolution of upstream on a live server at a moment nobody chose,
unattended, at boot, whenever the BuildKit cache missed, with nothing recording what the previous build
was. That is the same class of accident the candidate tree in `apply` exists to prevent, and it was the
one hole left in it.

What they are pinned to lives in each Dockerfile as an `ARG` with a default, because these are built
and not pulled and so have no `image:` tag to pin: `DNSTT_VERSION=v1.20260501.0`; microsocks by
`MICROSOCKS_VERSION` **and** `MICROSOCKS_COMMIT`, where the clone asks for the tag and then asserts the
sha, so a moved tag fails the build loudly rather than substituting something else; and both base
images by multi-arch index digest, so the pin still resolves on a server of another architecture. Each
image carries the same values as `org.opencontainers.image` labels, so
`docker inspect dnstt-server:latest` answers "what is actually running" on a box whose checkout has
since moved. `compose.yml` deliberately
does not restate any of it — `scripts/check.sh` reads sing-box's tag out of `compose.yml` precisely so
that one version is not written twice, and copying these up would recreate the drift that rule exists
to prevent. What still moves is `openssh` inside the `alpine:3.20` branch: the digest fixes the base
filesystem, not `apk`'s view of the network.

The same change stripped these three down to what they each need. `dnstt-socks` runs as uid 10300 with
an empty capability set and a read-only rootfs — it binds one high loopback port and opens outbound
sockets, and needs nothing else. `dnstt-server` keeps `NET_BIND_SERVICE` and nothing else, because it
binds udp/53 in the host's namespace, and its filesystem is read-only: a public-facing parser on udp/53
should not be able to leave anything behind in its own filesystem. `dnstt-sshd` keeps root and a
writable filesystem, and that is argued rather than assumed — rewriting `/etc/passwd`, `/etc/shadow`
and `/etc/group` from the rendered list on every start is the entire revocation story above.

Settings for a client are a form, not a link. DNSTT-over-SSH has no URI scheme and nothing to scan, so
`share()` emits `fields` rather than a `uri` — they were crammed into a `uri` once, and every layer
duly treated them as one, producing a QR code nothing could read and a tappable link that imported
nothing:

```bash
./vpn user export <name> --protocol dnstt
```

## Where this fits

The panel I checked does not ship a DNS-tunnel inbound, and the ask there has a history worth stating
in full, because anyone who opens the thread finds it in the first comment. In `MHSanaei/3x-ui`, as read
on **2026-09-11**:

| issue | asks for | state |
| --- | --- | --- |
| **#3903** | DNSTT specifically (MultiDNS integration) | closed **completed**, 2026-05-29 |
| **#4389** | DNS tunnelling generally (MasterDnsVPN / StormDNS) | closed **not planned**, 2026-06-01 |
| **#6438** | DNSTT as an emergency inbound for whitelist lockdowns | open, `enhancement`, filed 2026-09-09 |

The one that needs care is #3903: closed as *completed*, yet a code search of that repository for
`dnstt` returns nothing, while a control search for `mtproto` returns the sidecar's files. What can be
concluded from that is only this — there is no DNSTT code on the default branch to read. What cannot be
concluded is why it was closed that way. "Completed" may record a comment answering the request, a
superseded plan, or housekeeping; the state reason is not a design statement, and I will not read one
into it. #4389's *not planned* is a clearer signal but is about two different products. Taken together,
the three say the ask recurs and that nothing in the panel answers it today — not that anybody decided
it should not exist.

**What is not new here.** #6438 already carries two comments, both 2026-09-09, and the analysis in them
(from a `github-actions` analyst bot, which the issue author then agreed with) independently states two
of the load-bearing facts above: that upstream `dnstt-server` has a single server keypair and no
per-client credential, so a panel's per-client quota and expiry have nothing to bind to; and that no
dnstt URI scheme exists that any downstream client parses, so there is nothing for a subscription
generator to emit. This document must not present either as a discovery. It does add one thing to the
first: that comment marks the upstream-keypair point as inference from the panel side, explicitly
unable to read upstream dnstt — here it is not inference, it is the constraint the design is built
around, visible in `vpnctl/protocols/dnstt.py` shipping exactly one `dnstt.server.key`.

**What is new is the part after that.** Granting that the keypair cannot be per-person, the remaining
question is where the per-person boundary goes instead, and what it costs. The answer in this
repository — a login per person in a containerised sshd behind the shared transport, rendered from the
same `users.json` as everything else — is unremarkable. The two things worth taking are the ones that
only show up once you build it: that such a container **cannot be classified as restartable**, because
its `/etc/passwd` is derived from its input at create time; and that getting that one classification
wrong produces a revocation bug rather than a staleness bug, with `user rm` reporting success over a
credential that still authenticates. That is reproducible in ten minutes, above. The thread's
suggestion — point dnstt at a loopback inbound and let the inner protocol carry identity — is a
reasonable different answer to the same question, and it moves this same recreate problem to whatever
rebuilds that inbound's account list.

That is one panel's issue tracker, not a survey. I have not audited the others, and the absence of a
feature is harder to prove than its presence — treat the claim as "no DNS-tunnel inbound in the panel I
checked, on the date I checked it."

Nothing here claims novelty in the tunnel itself. dnstt is David Fifield's work
(`www.bamsoftware.com/software/dnstt`), and this repository does not modify it: `dnstt/Dockerfile` is a
`go install` of the upstream `dnstt-server` and an Alpine to run it in. Everything above is the
arrangement around it, and that arrangement is small. It is also the difference between a user database
that revokes access and one that only looks like it does.

## What was not measured

Named here rather than buried, because this is the honest part of the report.

- **Connecting from a different ISP.** Expected to work outright for IKEv2, and never tried: there was
  no third vantage point. It is the single most load-bearing untested claim in the IKEv2 diagnosis
  above, and the whole filtering conclusion rests on one subscriber line.
- **Throughput and latency of the tunnel.** Not benchmarked. The only quantitative statement the
  repository makes about tunnel performance is that an MTU of roughly 130–930 bytes is normal.
- **The date of the whitelist observation.** `dnstt/SETUP.md` records what passed and what did not on
  that mobile network, but not when.
- **Whether other panels lack a DNS-tunnel inbound.** Inferred from one panel's issue tracker — three
  requests, and a code search finding no `dnstt` on its default branch — not from a survey of panels.
  Nor do I know why #3903 was closed as completed; see above for what that does and does not support.
- **The bypass outside the throwaway container.** The reproduction above is the `dnstt-sshd` image by
  itself, driven with a hand-written logins file and an SSH client in the same container. It was not
  run end to end through a real dnstt tunnel from a phone, and it does not need to be: the bug is in
  the container's writable layer, which the tunnel never touches. But that is the scope — the recipe
  demonstrates the revocation failure, not a full client path.
- **The crash-loop case.** Reading the code rather than a measurement, and it is now three refusals
  deep rather than one. With dnstt on and every user disabled or lacking a password, `dnstt.render`
  raises before the candidate tree is promoted; were a hand-written or restored `logins` to be empty
  anyway, the entrypoint exits 1 under `restart: always`. What that used to reach was a blind spot:
  `wait_ready` watches `53/udp` for dnstt and not the sshd's loopback `2222`, so `apply` reported
  success while the sshd restarted forever. `composectl.not_running` now answers which expected
  services are not running — with `None` kept distinct from the empty list, because "docker could not
  tell" is not a clean bill of health — `dnstt-sshd` and `dnstt-socks` carry healthchecks, and
  `scripts/smoke.sh` asserts both loopback binds plus a restart count sampled twice. None of that has
  been watched happening on a live box.
- **Everything attributed to one ISP.** One subscriber line, 2026-09-08, one hosting location. Repeat it
  with `scripts/diagnose-ikev2.sh` before treating any of it as general.
