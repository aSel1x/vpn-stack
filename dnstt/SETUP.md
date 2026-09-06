# dnstt — DNS-tunnel bypass setup

Smuggle a VPN out of an **egress-only-DNS** network: one where every destination is blocked *except* DNS to the network's own resolver. dnstt encodes a TCP stream into DNS queries for a subdomain you own; the blocked network forwards them to the carrier resolver, which recurses to *your* authoritative server, which decodes the stream and hands it to an exit.

```
laptop/phone ──base32 DNS──▶ carrier :53 ──recursion──▶ your dnstt-server :53
                                                              │ decoded TCP
                                                              ▼
                                                     SSH → SOCKS ──▶ internet
```

The tunnel is Noise-encrypted and the client pins the server's public key — the resolver in the middle sees only opaque DNS.

## Prerequisites

- A VPS with a static public IP (`SERVER_IP`) and Docker.
- A domain you control (`example.com`) — you'll delegate `tun.example.com` to the box.
- `udp/53` free and world-reachable on the box (nothing else public may hold port 53).

---

## 1. Delegate a subdomain to the server

Two records at your DNS provider — a nameserver host pointing at the box, then delegate the child zone to it:

```
ns-tun.example.com.   A    SERVER_IP
tun.example.com.      NS   ns-tun.example.com.
```

Verify once propagated: `dig +short NS tun.example.com` → `ns-tun.example.com`.

## 2. Generate the server keypair

Noise keypair. The **public** key is pinned by clients; the **private** key stays on the server.

```bash
dnstt-server -gen-key -privkey-file dnstt/keys/server.key -pubkey-file dnstt/keys/server.pub
chmod 600 dnstt/keys/server.key
cat dnstt/keys/server.pub          # pin this on clients
```

> `server.key` is a live secret — `chmod 600`, gitignore it, back it up. Rotating it invalidates every client's pinned key.

## 3. Run dnstt-server (Docker)

`dnstt/Dockerfile`:

```dockerfile
FROM golang:1.23-alpine AS build
RUN go install www.bamsoftware.com/git/dnstt.git/dnstt-server@latest
FROM alpine:3.20
COPY --from=build /go/bin/dnstt-server /usr/local/bin/dnstt-server
ENTRYPOINT ["/usr/local/bin/dnstt-server"]
```

`compose.yml` service:

```yaml
  dnstt:
    build: ./dnstt
    container_name: dnstt-server
    restart: always
    network_mode: host
    volumes:
      - ./dnstt/keys:/keys:ro
    command: >-
      -udp ${VPN_SERVER_HOST}:53
      -privkey-file /keys/server.key
      tun.example.com 127.0.0.1:2222
```

> **#1 mistake:** bind `SERVER_IP:53`, **not** wildcard `:53`. `systemd-resolved` already owns `127.0.0.53:53`, so a wildcard bind dies with *"address already in use."* An explicit public IP sidesteps it.

The last argument is the **exit** — where the decoded stream goes (step 4).

## 4. Give the tunnel an exit

dnstt is pure transport: it forwards the decoded stream to one `host:port`. Pick the exit that matches your client.

### Variant A — direct SOCKS (simplest; best for a laptop)

Point dnstt straight at a loopback SOCKS5. A client's local port then *is* a SOCKS proxy — no SSH, no login user. Set dnstt's last arg to `... tun.example.com 127.0.0.1:1080`.

`dnstt-socks/Dockerfile` (microsocks from source — not packaged in Alpine):

```dockerfile
FROM alpine:3.20 AS build
RUN apk add --no-cache git build-base \
 && git clone --depth 1 https://github.com/rofl0r/microsocks /src \
 && make -C /src
FROM alpine:3.20
COPY --from=build /src/microsocks /usr/local/bin/microsocks
ENTRYPOINT ["/usr/local/bin/microsocks"]
```

```yaml
  dnstt-socks:
    build: ./dnstt-socks
    container_name: dnstt-socks
    restart: always
    network_mode: host
    command: -i 127.0.0.1 -p 1080
```

### Variant B — SSH front (needed for iOS "SSH-over-DNSTT" apps) — **what this deployment uses**

Mobile apps (HTTP Injector, AnyBridge) run SSH *on top* of the tunnel, so dnstt hands off to an sshd.

**The sshd runs in a container, not on the host** (`dnstt-sshd/`). A host account would mean a real user plus an edit to `/etc/ssh/sshd_config`, neither of which `vpn backup` captures and both of which have to be recreated by hand after every rebuild. In a container the login's blast radius is an empty Alpine with nothing mounted, and the credentials are rendered from the keyring like every other secret.

So dnstt's last argument is `127.0.0.1:2222`, and the container:

- listens on **loopback only** — the sole way in is the tunnel;
- allows exactly one user, password auth, and forwards only to what `PERMIT_OPEN` lists;
- keeps its host key in the `dnstt-sshd-keys` volume, so it does not change under clients on restart.

**Each person gets their own login.** The username is their vpn user name and the password is generated when they are added, so `user disable` and `user rm` actually revoke dnstt access — the container rebuilds `/etc/passwd` from the rendered list on every start, and a name that is no longer in it cannot log in. Verified: after a `disable`, that person's own password is refused while everyone else's still works. The trade is that changing the user list recreates the container and drops live sessions, as it already does for IKEv2.

Get the login, with the zone and pubkey, from:

```bash
./vpn user export <name> --protocol dnstt
```

`PERMIT_OPEN` defaults to `any`, and a fixed list is not a workable alternative. The server's own log proves it in two steps. First, with only the SOCKS exit permitted, every session died at its first name lookup, having never touched the SOCKS:

```
Accepted password for dnstt from 127.0.0.1
Received request ... to connect to host 1.1.1.1 port 853, but the request was denied.   ×17
```

The apps resolve over DNS-over-TLS *through* the tunnel. Allowing that resolver moved the failure one step along, to this:

```
to connect to host 17.248.213.67 port 443, but the request was denied.
to connect to host 142.251.156.119 port 443, but the request was denied.
to connect to host 2a01:b740:1361:101::c port 443, but the request was denied.
```

That is SSH **dynamic** forwarding: every site is a fresh destination, so no list can match. `microsocks` is never used by this path at all — it stays for the laptop variant.

This is a smaller concession than it reads. The other three protocols on this server already give unrestricted network access to whoever holds their credentials; restricting the last-resort protocol alone would buy nothing while making it the least useful of the four for the people in the most restricted networks. What actually keeps this safe is the credential's blast radius: a random password, an sshd bound to loopback, and one route in — a tunnel that already requires the pinned Noise key.

Narrow it if you have a reason to (`PERMIT_OPEN="*:443 *:80 1.1.1.1:853"` keeps browsing while blocking mail relay and port scanning), and read `docker logs dnstt-sshd` to see exactly what gets refused.

## 5. Firewall & bring up

```bash
ufw allow 53/udp comment dnstt
docker compose up -d --build dnstt dnstt-socks
ss -lunp | grep ':53'          # dnstt-server should own SERVER_IP:53
```

## 6. Connect the laptop

`dnstt-client` listens locally and rides the tunnel out through whatever resolver the blocked network permits (often its own gateway/relay):

```bash
dnstt-client -udp RESOLVER_IP:53 -pubkey <server.pub> tun.example.com 127.0.0.1:1080
```

- **Variant A:** `127.0.0.1:1080` is now a SOCKS5 proxy — point the browser at it.
- **Variant B:** `ssh -N -D 9090 tunuser@127.0.0.1 -p 1080` — SOCKS via the SSH front.

## 7. Connect the phone (iOS)

iOS has no maintained native dnstt client, so use a **DNSTT → SSH** app (HTTP Injector or AnyBridge) against Variant B. Two parts: find the right resolver, then fill in the app.

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

Public resolvers (`8.8.8.8`, `1.1.1.1`) and DoH/DoT (`:443`/`:853`) are dropped by the IP-whitelist — **only** the carrier's own resolver on `:53` gets through. Keep the app's DNS transport on plain UDP.

### 7b. Configure the app

Field names vary slightly; the mapping is the same. Set the DNS resolver from 7a, everything else from your server.

**HTTP Injector** — Tunnel Type `DNS (DNSTT) → SSH`:

| Field | Value |
|---|---|
| Nameserver / DNS Server | `tun.example.com` (the delegated zone) |
| Public Key | `<contents of server.pub>` |
| DNS Resolver | `<carrier-IP>:53` — custom IP, plain UDP (**not** a preset, **not** `172.20.10.1`) |
| SSH user / password | the `tunuser` login |

**AnyBridge** — mode `DNSTT → SSH`:

| Field | Value |
|---|---|
| Server / domain | `tun.example.com` |
| Public key | `<contents of server.pub>` |
| DNS server — transport | **Standard (udp)** (not DoH/DoT) |
| DNS server — address | `<carrier-IP>:53` |
| SSH user / password | the `tunuser` login |

The app connects SSH *through* the tunnel automatically (dnstt exits into the host sshd), so you don't set an SSH host — just the `tunuser` username and password. After connecting, cross-check on the server (§ Verify): a `begin session` in `dnstt-server` logs and a `session opened for tunuser` in `auth.log` mean the whole chain is up.

---

## Gotchas that cost real time

- **Bind an explicit IP, never `:53`** — `systemd-resolved` holds loopback :53; a wildcard bind fails *address already in use*.
- **`172.20.10.1` is a phone trap** — hotspot gateway, valid only for tethered clients. A tethered laptop works through it; the phone itself needs the carrier's real cellular resolver.
- **`illegal base32` in logs is noise** — internet scanners hit any live zone. Only worry when a log line's session id matches *yours*.
- **SSH denies forwards by default** — without `AllowTcpForwarding yes` + a `PermitOpen` covering the exit, the app connects but every request is *"request denied"* and no traffic flows.
- **A tiny MTU (~130–930) is normal** — DNS payloads are small; it's not a bug and not why a handshake stalls.

## Verify end-to-end

```bash
docker logs -f dnstt-server                    # in use → begin session / begin stream
tcpdump -ni any udp port 53 and host SERVER_IP # prove DNS is arriving at all
grep tunuser /var/log/auth.log                 # Variant B: "session opened" = SSH up
                                               # "connect to ... denied" → fix PermitOpen
```

**Working looks like:** a `begin session` + `begin stream` that persists, the SSH login in `auth.log`, and a page loading over the SOCKS proxy. If the server sees **zero** packets, the problem is client-side — almost always the wrong resolver.

## Security notes

- The SSH front is a login handed to closed-source apps — keep it non-root, scope `PermitOpen` to exactly the exit (+ DoT resolver), strong password.
- The SOCKS proxy binds **loopback only** — reachable solely through the authenticated tunnel, never from the internet.
- `server.key`: `600`, gitignored, on-server only.
- Only the intended `udp/53` should be world-open — don't leave test HTTP servers or extra firewall holes behind.

---

*dnstt — Noise-encrypted DNS tunnel by David Fifield (www.bamsoftware.com/software/dnstt). Authorized use only: run against networks and infrastructure you own or are cleared to test.*

*This deployment: zone `tun.example.net`, delegated as `tun.example.net NS ns-tun.example.net` with `ns-tun.example.net A 203.0.113.10`. Exit is Variant B: dnstt → **containerised** sshd on `127.0.0.1:2222` → microsocks `127.0.0.1:7300`.*

*The pubkey is **not** written down here. It is generated per deployment by `vpnctl protocol on dnstt` and read back with `./vpn user export <name> --protocol dnstt`. An earlier one was recorded in this file and in `dnstt/keys/server.pub`, and both outlived the private half by a server rebuild — a pinned key that no longer exists is worse than no key at all.*
