# dnstt — DNS-tunnel bypass setup

Smuggle a VPN out of an **egress-only-DNS** network: one where every destination is blocked *except* DNS to the network's own resolver. dnstt encodes a TCP stream into DNS queries for a subdomain you own; the blocked network forwards them to the carrier resolver, which recurses to *your* authoritative server, which decodes the stream and hands it to an exit.

```
laptop/phone ──base32 DNS──▶ carrier :53 ──recursion──▶ your dnstt-server :53
                                                              │ decoded TCP
                                                              ▼
                                                     SSH → SOCKS ──▶ internet
```

The tunnel is Noise-encrypted and the client pins the server's public key — the resolver in the middle sees only opaque DNS. The Noise key belongs to the *server*: it encrypts the transport before anybody has authenticated to anything, so it cannot be per-person. The per-person boundary is the sshd behind it, one login per enabled user — see § 4, and `docs/dnstt-per-user-revocation.md` for why that placement is the whole design.

## Prerequisites

- A server this stack has already been installed on (`./vpn init` or `scripts/install.sh`), with `/etc/vpn-stack` and Docker on it. Nothing below is run by hand on the box.
- A domain you control (`example.com`) — you'll delegate `tun.example.com` to the server. **Yours, not this repo's:** there is no default zone anywhere in the code, and deliberately not one, because a shipped default would have every deployment serving somebody else's domain.
- `udp/53` free and world-reachable on the box (nothing else public may hold port 53).

---

## 1. Delegate a subdomain, and tell the server its name

Two records at your DNS provider — a nameserver host pointing at the box, then delegate the child zone to it:

```
ns-tun.example.com.   A    SERVER_IP
tun.example.com.      NS   ns-tun.example.com.
```

Verify once propagated: `dig +short NS tun.example.com` → `ns-tun.example.com`.

Then set the zone. This is deployment config, not code — it lives in `/etc/vpn-stack/.env`, the file `docker compose` reads from the project directory (`./.env` on the server is a symlink to it) and the same place `VPN_SERVER_HOST` lives:

```bash
echo 'VPN_DNSTT_ZONE=tun.example.com' >> /etc/vpn-stack/.env
```

`scripts/provision-host.sh` already appended a commented `#VPN_DNSTT_ZONE=tun.example.com` line to that file, so you can uncomment and edit it instead. Two rules about how you write the value:

- **Quoted or unquoted, but not both halves of a quote.** `vpnctl/dotenv.py` strips one *matching* pair of wrapping quotes exactly as compose does, so `VPN_DNSTT_ZONE="tun.example.com"` and the bare form now mean the same thing. They did not before: the quotes survived into every share link, naming a zone no resolver will ever answer for, from a file the operator had filled in correctly. A lone quote is data and is left alone.
- **No trailing comment on the value line.** `# like this` is *not* stripped — compose does not strip one either, and the reader in `dotenv.py` stays literal to match it. `VPN_DNSTT_ZONE=tun.example.com  # ours` sets the zone to a string ending in `# ours`.

One variable, read twice: compose interpolates it into the `dnstt` container's `command:`, and `vpnctl` reads it (`render.dnstt_zone()`, environment first and then the file, which is compose's own precedence) for the settings it hands to clients. Unset, `protocol on dnstt` refuses before it writes anything or builds anything, and names the variable. If dnstt is already on and the variable later goes missing, `render` warns on stderr and still renders — a boot must not die on it — but `user export` refuses, because a share card naming a zone nobody delegated is an hour of somebody's debugging handed out as if it worked.

**An unset variable is not an empty string.** `compose.yml` interpolates it bare, as `${VPN_DNSTT_ZONE}` and deliberately not `${VPN_DNSTT_ZONE:?}`: measured on Compose v5.3.1, the `:?` form fails project *load* even when dnstt's profile is inactive, so `config`, `ps` and even `up sing-box` all die on a box where dnstt is merely switched off. Bare means the argument **drops out of `dnstt-server`'s command line entirely**. The container then binds 53/udp, `docker ps` says running, both loopback back-ends are up, every other check passes — and it answers for nothing any client can resolve. That was found on this stack's own server.

`scripts/smoke.sh` has a check named `dnstt_zone` for exactly that, and it reads the argv of the **running container** rather than `.env`, because the question is not "is the variable set now" but "what is this process serving": a container created before the variable existed carries whatever it was created with and stays that way until something recreates it. It *parses* argv rather than indexing it — `cmd[-2]` looks right and is the trap, because a dropped zone makes argv one shorter and `cmd[-2]` silently becomes the `-privkey-file` value, `/keys/server.key`, which has a dot in it and passes any domain-shaped test.

So after setting the variable on a server where dnstt is already on, run `./vpn deploy` (or any `apply`) and then `./vpn smoke`, and read the `dnstt_zone` line. If the container is still carrying the old command line, `./vpn protocol off dnstt && ./vpn protocol on dnstt` recreates it; turning it off keeps the secrets, so the keypair is not reminted and no profile already handed out stops working.

## 2. Turn it on

```bash
./vpn protocol on dnstt
```

That is the whole of it, and it is the only supported way to produce the Noise keypair. In order, `vpnctl`:

1. refuses outright if `VPN_DNSTT_ZONE` is unset — *before* `state.json` is written and before the image build is paid for, because nothing written is nothing to roll back;
2. writes the toggle, then builds `dnstt-server:latest` and runs `dnstt-server -gen-key` in it, storing both halves in `/etc/vpn-stack/secrets/dnstt.server.key` and `.pub` at 0600. If that fails the enable is **rolled back**: dnstt left on with no key would make every later `apply`, including the one `vpn-stack.service` runs at boot, die on a missing secret with no clue how it got there;
3. applies — renders the candidate tree, validates it, promotes it by atomic symlink swap, brings the three dnstt containers up, and reconciles ufw, which is where `53/udp` gets opened with the comment `vpn-stack:dnstt`. There is no `ufw allow` for you to run; `firewall.reconcile` only ever touches rules carrying that tag.

The keypair costs a Go toolchain build and roughly 800 MB, which is why it is here and not in `bootstrap`: a fresh server should not pay that for a protocol that ships disabled and additionally needs a delegated zone before it can serve anything.

**`-gen-key` prints both halves as 64 hex characters on stdout, and that is what `prepare()` parses.** The obvious alternative, `-privkey-file` into a bind-mounted directory, was tried: it writes the files as root, so nothing but root can read them back, and the temporary directory then fails to clean up.

**Nothing writes a key into this checkout, and you should not either.** The checkout is code; live state is `/etc/vpn-stack`, 0700 and root-owned, outside the tree. `scripts/push.sh` rsyncs the working tree to the server with `--delete` and `--chown=root:root`, so a file you leave in `dnstt/keys/` is a credential travelling to every server you deploy to, and one a later deploy can silently remove. This document used to walk the reader through `dnstt-server -gen-key -privkey-file dnstt/keys/server.key` inside the checkout, and `.gitignore` still carries `dnstt/keys/*` because of that — directory-wide, with no allowlisted exception. It is belt and braces for a hand-run command now, not a step anybody is asked to take.

The public half is not written down in this file, on purpose. Read it, together with everything else a client needs, from:

```bash
./vpn user export <name> --protocol dnstt
```

An earlier deployment's pubkey *was* recorded here, and in a `dnstt/keys/server.pub`; both outlived the private half by one server rebuild, and a pinned key that no longer exists is worse than no key at all.

## 3. What is now running

Three containers, all `network_mode: host`, all under the `dnstt` compose profile so they exist only while the protocol is on:

| container | what it is | binds |
| --- | --- | --- |
| `dnstt-server` | the tunnel. `-udp ${VPN_SERVER_HOST}:53 -privkey-file /keys/server.key <zone> 127.0.0.1:2222` | `SERVER_IP:53/udp` |
| `dnstt-sshd` | the SSH front the decoded stream exits into, one login per enabled user | `127.0.0.1:2222` |
| `dnstt-socks` | microsocks, the SOCKS5 exit those logins forward through | `127.0.0.1:7300` |

and three rendered files, written at 0600 into the state directory and bind-mounted read-only:

```
rendered/dnstt/server.key        the Noise private half        -> /keys       (dnstt-server)
rendered/dnstt-sshd/logins       name:password, one per line   -> /conf       (dnstt-sshd)
rendered/dnstt.env               SSH_PORT, SOCKS_EXIT, PERMIT_OPEN            (dnstt-sshd)
```

> **#1 mistake:** bind `SERVER_IP:53`, **not** wildcard `:53`. `systemd-resolved` already owns `127.0.0.53:53`, so a wildcard bind dies with *"address already in use."* That is why `compose.yml` interpolates `${VPN_SERVER_HOST}` and never leaves the address off — and it is the same trap one level up in every health check here, which is why "bound" means *bound on a non-loopback address* in `composectl` and `scripts/smoke.sh`: substring-matching the number 53 reports dnstt as serving on a stock Ubuntu that serves no DNS at all.

**All three images are pinned, and a bump is a deliberate edit.** They are built here rather than pulled, so there is no `image:` tag to pin — `compose.yml` says so and does not restate the versions, because two literals drift. What they are pinned to lives in each Dockerfile as an `ARG`: `DNSTT_VERSION=v1.20260501.0`; microsocks by `MICROSOCKS_VERSION=v1.0.5` **and** `MICROSOCKS_COMMIT`, where the clone asks for the tag and then asserts the sha, so a moved tag fails the build loudly rather than substituting something else; and `alpine:3.20` / `golang:1.23-alpine` by multi-arch index digest, so the pin still resolves on another architecture. Each image carries the same values as `org.opencontainers.image` labels, so `docker inspect dnstt-server:latest` answers "what is actually running" on a box whose checkout has since moved.

To bump: change the `ARG`, rebuild, prove the tunnel still comes up, and only then let it reach a server people are using. The reason this matters more here than it looks is `composectl.up`, which passes `--build`, and `apply`, which runs from `user add`, `user rm`, `protocol on`, `protocol off`, `deploy` and the boot unit. While these Dockerfiles said `go install …@latest` and `git clone --depth 1`, every one of those was a re-resolution of upstream on a live server at a moment nobody chose — unattended, at boot, whenever the BuildKit cache missed, with nothing recording what the previous build was.

## 4. The exit: an sshd in a container, with one login per person

dnstt is pure transport: it forwards the decoded stream to one `host:port`. Here that is `127.0.0.1:2222`, an sshd **in a container**, not the host's — because the iOS clients for this path (HTTP Injector, AnyBridge) run SSH *on top* of the tunnel and need a login. On the host that would be a real account in `/etc/passwd` plus an edit to `/etc/ssh/sshd_config`, neither captured by `vpn backup` and both to be redone by hand after every rebuild. In a container the login's blast radius is an Alpine with nothing in it but `openssh-server`, its host-key volume and the read-only login list, and the credentials are rendered from `users.json` like every other secret.

(For a laptop you can skip SSH entirely and point dnstt at the SOCKS directly — `… <zone> 127.0.0.1:7300` — which makes the client's local port a plain SOCKS5 proxy with no login at all. That is not what this deployment renders, and `microsocks` is never reached by the mobile path except through an SSH forward.)

**Each person gets their own login.** The username is their vpn user name and the password is the `dnstt_password` generated when they were added, so `user disable` and `user rm` genuinely cut dnstt access: `vpnctl/protocols/dnstt.py` renders one `name:password` line per **enabled** user, `dnstt-sshd/entrypoint.sh` rebuilds `/etc/passwd`, `/etc/shadow` and `/etc/group` from that file on every start, and a name that is no longer in it has no account to log into. Verified: after a `disable`, that person's own password is refused while everyone else's still works.

The cost is that changing the user list **recreates** the container and drops live dnstt sessions, exactly as it already does for IKEv2. That recreation is load-bearing rather than incidental: the entrypoint's account loop is `id "$name" || adduser`, it only ever *adds*, and nothing in it deletes an account that dropped out of the list — so the reset comes entirely from the container being new. `composectl` classifies `dnstt-sshd/` as `RECREATE` for that reason, even though the logins file is a plain bind mount. It was briefly classified `MOUNT`, which is a `restart`, and a restart reuses the writable layer: the removed user kept their account, their group and their password hash, `AllowGroups tunnel` still admitted them, and `user rm` reported success having revoked nothing. `docs/dnstt-per-user-revocation.md` reproduces that in about ten minutes.

What the entrypoint does on every start, and why each part is there:

- **It validates the whole list before touching a single account**, and refuses the start rather than skipping a record. A name that collides with an account the base image ships used to skip the `adduser` — and with it the `-G tunnel` grant that `AllowGroups` tests — while the `chpasswd` that followed ran anyway and set *that system account's* password to the person's dnstt password. Measured against the old file: a user named `mail` came out with a real hash in `/etc/shadow`, a group list of `mail` alone, and no way in. The image snapshots its own accounts at build time (`/etc/dnstt-sshd.reserved`), because once the writable layer has been written to, `/etc/passwd` cannot tell a baked-in system account from one a previous start created — and that difference decides whether a name is a collision to refuse or a login to reuse. A leading `-`, a character outside `[A-Za-z0-9._-]`, a name over 32 characters, a duplicate and an empty password are refused the same way, each naming the record to fix. `users_store.validate_name` rejects the same reserved names at `user add`, which is where the fix belongs; the container check is the depth, for a file that arrives from a hand edit, a restore of an older backup or a rolled-back tree.
- **It asserts group membership rather than assuming it.** `adduser -G` grants the group only on the run that creates the account, so a plain `docker restart` re-ran the loop against existing accounts and sshd refused every login while logging nothing that named the cause.
- **It refuses an empty login list** (`login list is empty -- add a user, or turn dnstt off`) rather than running an sshd nobody can log into. That is the last line of defence only: `render` refuses to produce an empty list in the first place, so the operator gets one sentence at apply time instead of a crash-loop that binds no non-loopback port for anything to notice.
- **The host key lives in the `dnstt-sshd-keys` volume**, so it does not change under clients on restart — and since the user list legitimately recreates this container, that would otherwise be often. `./vpn backup` captures that volume, so a restore onto a rebuilt box does not reintroduce a changed-host-key warning for the protocol whose users have no fallback.
- **The password never reaches an argv.** `printf` is a shell builtin and `chpasswd` takes the pair from the pipe; the confirmation it prints names the user only. So the container log is a record of which logins were set this start and carries no secret.

A user created before `dnstt_password` existed has none, gets no login, and `render` says so on stderr, naming them. There is deliberately no migration command for a one-record problem: set the field in `users.json`, or re-add the user. `render` must not mint it — it is pure, and `apply` would be handing out a password nobody had been told — and `load` must not, because that rotates a live credential on every read.

There is no link to import. DNSTT-over-SSH has no URI scheme and nothing to scan, so `share()` emits **fields** rather than a `uri`; they were crammed into a `uri` once and every layer duly treated them as one, producing a QR code nothing could read and a tappable link that imported nothing. Get them with `./vpn user export <name> --protocol dnstt`, or put the same table on a one-shot LAN page with `./vpn share <name>`.

### `PERMIT_OPEN` is `any`, and a fixed list is not a workable alternative

The server's own log proved it in two steps. First, with only the SOCKS exit permitted, every session died at its first name lookup, having never touched the SOCKS:

```
Accepted password for dnstt from 127.0.0.1
Received request ... to connect to host 1.1.1.1 port 853, but the request was denied.   ×17
```

(`dnstt` there is the shared account of the time; these lines predate the per-person logins.) The apps resolve over DNS-over-TLS *through* the tunnel before they open anything. Allowing that resolver moved the failure exactly one step along, to twenty-odd web hosts on `:443`:

```
to connect to host 17.248.213.67 port 443, but the request was denied.
to connect to host 142.251.156.119 port 443, but the request was denied.
to connect to host 2a01:b740:1361:101::c port 443, but the request was denied.
```

That is SSH **dynamic** forwarding: every site is a fresh destination, so no list can match.

This concedes less than it reads. The other three protocols on this server already give unrestricted network access to whoever holds their credentials; restricting the last-resort protocol alone would buy nothing while leaving the people in the most locked-down networks with the least useful of the four. What keeps it safe is the credential's blast radius: a random password, an sshd bound to loopback, one route in, and that route already requires the pinned Noise key. What it does reach on the host's loopback is either already public (the host's own sshd, which ufw allows on whatever port it listens on) or loopback-by-design (`microsocks`) — that is this host's inventory, not a guarantee, so judge anything else you bind to loopback against it.

Narrow it if you have a reason to: the value is the `PERMIT_OPEN` tuple in `vpnctl/protocols/dnstt.py`, rendered into `dnstt.env` and read by the entrypoint, so `("*:443", "*:80", "1.1.1.1:853")` keeps browsing while blocking mail relay and port scanning. Read `docker logs dnstt-sshd` to see exactly what gets refused — that log is where both observations above came from.

## 5. Check that it is actually serving

`apply` already opened the firewall, waited for the ports, and brought the containers up. What is worth running is the assertion:

```bash
./vpn smoke
```

Its dnstt checks, each of which exists because something passed without it:

- `container_dnstt-server`, `container_dnstt-sshd`, `container_dnstt-socks` — running, and their restart count sampled twice, because `restart: always` makes a container that starts and dies look exactly like one that has been up for a week;
- `port_dnstt_53_udp` — bound on a **non-loopback** address;
- `loopback_dnstt-sshd_2222_tcp` and `loopback_dnstt-socks_7300_tcp` — bound, and bound on loopback *only*; a public bind here is a failure, not a pass;
- `dnstt_zone` — the zone in the running container's argv, per § 1.

By hand on the server, ask `ss` for the port rather than grepping its output for the number — `ss -H -lun "sport = :53"` — for the `127.0.0.53` reason above. `./vpn logs dnstt` (the compose service is `dnstt`; `compose.yml` gives it `container_name: dnstt-server`, which is what `docker logs` wants) shows `begin session` / `begin stream` when the tunnel is in use, and `./vpn logs dnstt-sshd` shows each login being set at start, every `Accepted password`, and every destination `PermitOpen` refuses.

## 6. Connect a laptop

`./vpn user export <name> --protocol dnstt` prints these two commands filled in. `dnstt-client` listens locally and rides the tunnel out through whatever resolver the blocked network permits (often its own gateway or relay):

```bash
dnstt-client -udp RESOLVER_IP:53 -pubkey <64-hex-pubkey> tun.example.com 127.0.0.1:7000
ssh -N -D 1080 -p 7000 <name>@127.0.0.1
```

The first line makes `127.0.0.1:7000` the mouth of the tunnel; the second logs in through it with that person's own name and `dnstt_password` and makes `127.0.0.1:1080` a SOCKS5 proxy. Point the browser at `socks5://127.0.0.1:1080`.

## 7. Connect the phone (iOS)

iOS has no maintained native dnstt client, so use a **DNSTT → SSH** app (HTTP Injector or AnyBridge). Two parts: find the right resolver, then fill in the app.

### 7a. Find the carrier resolver IP (Network Analyzer)

The single thing that makes or breaks the phone. Stock iOS **hides** the cellular DNS — no Settings screen, no public API, no Shortcuts action. Read it with a network-info app:

1. Install **Network Analyzer** (or **Network Analyzer Pro**) by Techet — alternatives: iNetTools, NetUtils.
2. Turn **WiFi OFF** so cellular is the only active interface. (With WiFi on you'll read the *router's* DNS, not the carrier's.)
3. Open the app's **Info** / **LAN** page and read the **"DNS server(s)"** entry. That IP — e.g. `10.219.250.1` — is the carrier resolver. Write it down.
   - On an IPv6-only / NAT64 carrier it may be an **IPv6** address — use that. (A `192.0.0.1` you might see is the CLAT/NAT64 address, *not* the resolver.)
   - You **cannot** read it from a tethered laptop: DHCP there hands out `172.20.10.1` (the phone's own DNS proxy), which hides the real upstream.

> **The resolver that wastes an evening:** do **not** use `172.20.10.1` on the phone. That's the iPhone's own Personal-Hotspot gateway — it exists only for devices tethered *to* the phone, not for the phone's own stack. From the phone itself there's no route to it, so queries vanish and the server sees **zero** packets.

| ✕ tethered-only | ✓ phone's own stack |
|---|---|
| `172.20.10.1` — hotspot bridge gateway, valid only for a laptop tethered to the phone | `10.219.250.1` (example) — the carrier resolver on the cellular PDP context, the one the whitelist permits |

On the mobile network this was built for, public resolvers (`8.8.8.8`, `1.1.1.1`) and DoH/DoT (`:443`/`:853`) were dropped by the IP whitelist — **only** the carrier's own resolver on `:53` got through. Keep the app's DNS transport on plain UDP.

### 7b. Configure the app

Field names vary slightly; the mapping is the same. Set the DNS resolver from 7a; everything else is what `./vpn user export <name> --protocol dnstt` printed, and the SSH credentials are **that person's own**, not a shared account.

**HTTP Injector** — Tunnel Type `DNS (DNSTT) → SSH`:

| Field | Value |
|---|---|
| Nameserver / DNS Server | `tun.example.com` (the delegated zone) |
| Public Key | the pubkey from `user export` (64 hex characters) |
| DNS Resolver | `<carrier-IP>:53` — custom IP, plain UDP (**not** a preset, **not** `172.20.10.1`) |
| SSH user | the person's vpn user name |
| SSH password | their `dnstt_password` |

**AnyBridge** — mode `DNSTT → SSH`:

| Field | Value |
|---|---|
| Server / domain | `tun.example.com` |
| Public key | the pubkey from `user export` |
| DNS server — transport | **Standard (udp)** (not DoH/DoT) |
| DNS server — address | `<carrier-IP>:53` |
| SSH user | the person's vpn user name |
| SSH password | their `dnstt_password` |

The app opens SSH *through* the tunnel automatically — dnstt hands the decoded stream to the sshd on `127.0.0.1:2222` — so there is no SSH host to set, just the username and password. After connecting, cross-check on the server: a `begin session` in `docker logs dnstt-server` and an `Accepted password for <name> from 127.0.0.1` in `docker logs dnstt-sshd` mean the whole chain is up. That sshd runs in a container, so nothing about this appears in the host's `/var/log/auth.log`.

---

## Gotchas that cost real time

- **An unset `VPN_DNSTT_ZONE` is not an empty zone, it is no argument at all** — the container comes up healthy and answers for nothing. `./vpn smoke`'s `dnstt_zone` check reads the running container's argv; see § 1.
- **Bind an explicit IP, never `:53`** — `systemd-resolved` holds loopback :53; a wildcard bind fails *address already in use*.
- **A user name that collides with an Alpine system account is refused**, at `user add` and again by the container. It used to be issued, without the `tunnel` group that `AllowGroups` requires, after setting that system account's password to the person's own.
- **`172.20.10.1` is a phone trap** — hotspot gateway, valid only for tethered clients. A tethered laptop works through it; the phone itself needs the carrier's real cellular resolver.
- **`illegal base32` in logs is noise** — internet scanners hit any live zone. Only worry when a log line's session id matches *yours*.
- **SSH denies forwards by default** — without `AllowTcpForwarding yes` plus a `PermitOpen` covering the exit, the app connects but every request is *"request denied"* and no traffic flows. The rendered config sets both; if you narrow `PERMIT_OPEN`, `docker logs dnstt-sshd` names what it refused.
- **A tiny MTU (~130–930) is normal** — DNS payloads are small; it's not a bug and not why a handshake stalls.
- **Changing the user list drops live dnstt sessions** — the container is recreated on purpose, because that is what makes a removed login actually gone.

## Security notes

- The SSH front is a login handed to closed-source apps, so it is kept non-root, group-gated (`AllowGroups tunnel`), password-only with a random password, and bound to loopback. It may forward anywhere (`PermitOpen any`) for the measured reason in § 4; the bound on the risk is the credential, not the destination list.
- The SOCKS proxy binds **loopback only** — reachable solely through the authenticated tunnel, never from the internet. It runs as uid 10300 with an empty capability set and a read-only filesystem; `dnstt-server` keeps `NET_BIND_SERVICE` and nothing else, because it binds udp/53 in the host's namespace. `dnstt-sshd` keeps root and a writable filesystem, and that is argued rather than assumed: rewriting `/etc/passwd` from the rendered list on every start is the entire revocation story.
- `dnstt-sshd` and `dnstt-socks` carry healthchecks, because they bind loopback only — nothing else in this stack can see them fail, while `dnstt-server` goes on answering udp/53 into a tunnel whose far end refuses every login. They report and do nothing else: compose's `restart: always` reacts to a process exiting, not to health, so a false negative prints `unhealthy` in `docker compose ps` where `composectl.not_running` is already looking.
- The private Noise key lives at `/etc/vpn-stack/secrets/dnstt.server.key`, 0600, on the server only, and rides in `./vpn backup`. Rotating it invalidates every client's pinned key.
- Only the intended `udp/53` should be world-open — don't leave test HTTP servers or extra firewall holes behind. `firewall.reconcile` owns exactly the rules tagged `vpn-stack:`.

---

*dnstt — Noise-encrypted DNS tunnel by David Fifield (www.bamsoftware.com/software/dnstt). This repository does not modify it: `dnstt/Dockerfile` is a pinned `go install` of the upstream `dnstt-server` and an Alpine to run it in. Authorized use only: run against networks and infrastructure you own or are cleared to test.*

*This stack's shape: zone from `VPN_DNSTT_ZONE` (yours, delegated as in § 1 — no zone is recorded here, because a zone written into the repo is one every clone would serve). Exit is dnstt → **containerised** sshd on `127.0.0.1:2222` → microsocks on `127.0.0.1:7300`, with one login per enabled user.*
