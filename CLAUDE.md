# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A personal VPN server plus the CLI that operates it. Four protocols, one user database, one command surface:

- **`sing-box`** — VLESS+REALITY (`10443/tcp`) and Hysteria2 (`20443/udp`), the everyday path.
- **`hwdsl2/ipsec-vpn-server`** — IKEv2 / L2TP/IPsec / Cisco IPsec (`500`, `4500`, `1701` udp).
- **`dnstt` + `dnstt-sshd` + `dnstt-socks`** — DNS-tunnel last resort (`53/udp`), for networks that allow nothing else. One shared tunnel, **a login per person**: the Noise key belongs to the server and encrypts the transport before anyone authenticates, so it cannot be personal, but the sshd behind it can. That is what makes `user rm` and `user disable` cut dnstt access at all — with one shared account, removing somebody left their tunnel working and nothing to revoke. Verified: after a `disable`, that person's own password is refused while everyone else's still works.

  The logins are rendered from `users.json` into `rendered/dnstt-sshd/logins` and created at container start, so `/etc/passwd` is rebuilt from the list every time and a removed account cannot linger. The cost is that changing the user list recreates the container and drops live dnstt sessions, the same way it already does for IKEv2 — and that recreation is **load-bearing, not incidental**. `dnstt-sshd/entrypoint.sh:36` is `id "$name" || adduser`: it only ever *adds*. Nothing deletes an account that dropped out of the list, so the reset comes entirely from the container being new. `composectl._CONSUMERS` therefore classifies `dnstt-sshd/` as `RECREATE` even though the logins file is a plain bind mount. It was briefly classified as `MOUNT` — a `restart` — and that reuses the writable layer, so a removed user kept their account, their group and their password hash while `AllowGroups tunnel` still let them in: `user rm` reported success and revoked nothing. A user created before the field existed has no `dnstt_password`, gets no login, and `render` says so on stderr. There is deliberately no migration command for a one-record problem: set the field in `users.json` or re-add the user. `render` must not mint it (it is pure, and `apply` would be handing out a password nobody had been told), and `load` must not (that rotates a live credential on every read). Off by default; `protocol on dnstt` builds the image and has `dnstt-server -gen-key` mint the Noise keypair, because that format is the binary's own. The zone is **deployment config, not a constant**: set `VPN_DNSTT_ZONE=<your delegated zone>` in `/etc/vpn-stack/.env`, which `compose.yml` interpolates into the dnstt command. It was hardcoded here and repeated verbatim in `compose.yml` until a stranger cloning this repo would have served the author's zone, with their clients resolving a domain somebody else controls. `compose.yml` uses the bare `${VPN_DNSTT_ZONE}` form and **not** `${VPN_DNSTT_ZONE:?}` — measured on Compose v5.3.1, the `:?` form fails *project load* even when dnstt's profile is inactive, which is the same trap `ikev2.env` already documents.

  The decoded stream exits into an sshd **in a container**, not the host's. iOS clients speak DNSTT→SSH and need a login; on the host that would be a real account plus an `/etc/ssh/sshd_config` edit, neither captured by `vpn backup` and both to be redone after every rebuild. The container listens on loopback only and admits one account per enabled user, gated by `AllowGroups tunnel`. (It did allow exactly one, shared; that is the arrangement this replaced, and the sentence outlived it.) `PermitOpen` is **`any`**, and a list is not a workable alternative: the clients use SSH *dynamic* forwarding, so every site is a fresh destination. The log proved it twice — 17 refusals of `1.1.1.1:853` (they resolve over DoT through the tunnel before opening anything), then, once that was allowed, refusals of twenty-odd web hosts on `:443`. `microsocks` is never touched by this path; it stays for the laptop variant. This concedes less than it looks: the other three protocols already give unrestricted access to whoever holds their credentials, and what keeps this safe is the credential's blast radius — random password, loopback-only sshd, one route in, and that route already requires the pinned Noise key. Its host key lives in a volume so it does not change under clients on restart.

  `-gen-key` prints both halves as hex on stdout, and that is what `prepare()` parses. Writing them with `-privkey-file` into a bind mount produces root-owned files that nothing but root can read back, and a temp directory that then fails to clean up.

A deployment is a checkout at `/opt/vpn-stack` and state at `/etc/vpn-stack`; the target itself lives in `.vpn-host` (gitignored) or `VPN_HOST=`, never in the tree.

## Where things run

**`./vpn` on your machine. `vpnctl` on the server. Never the reverse.**

`./vpn` is a stateless bash wrapper at the repo root. It holds no config, no cache, no secrets: anything it doesn't recognise is forwarded verbatim over SSH to `vpnctl` on the server, under `flock /run/vpn-stack.lock` (which is the entire multi-operator story). The server is the only place that touches Docker, iptables, ufw and the user database.

```bash
./vpn status                       # what the server is running
./vpn user add <name>
./vpn user export <name> --qr      # ASCII QR in YOUR terminal
./vpn protocol list | on <x> | off <x>
./vpn deploy                       # sync code, validate, converge
./vpn smoke                        # assert it is actually serving
./vpn backup > f.age               # encrypted here, never on the server
./vpn restore f.age                # onto a rebuilt box
./vpn init root@<ip>               # bare Ubuntu -> serving VPN, one command
```

Set the target once with `.vpn-host` (gitignored) or `VPN_HOST=`; the key with `VPN_SSH_KEY=` (it lives in `~/.ssh/`, never in this tree).

**`vpnctl` refuses to mutate anything off-server** (`vpnctl/guard.py`). Before that guard existed, `vpnctl user add` on a laptop did not fail — it *succeeded*, rewriting a local copy of live credentials and starting a real sing-box bound to the laptop's ports.

`VPN_STATE_DIR=<dir>` is the test escape hatch, and it moves the whole blast radius, not just the Python: `apply` renders and validates but **does not converge** under a pointed state directory, because Docker, ufw and the host's ports are not relocated by an env var. Otherwise the escape hatch reproduced the exact bug the guard exists to stop, one level down. `VPN_ALLOW_CONVERGE=1` overrides.

There is no fallback to the repo directory any more. If `/etc/vpn-stack` is not there, this is not the server and `vpnctl` says so, instead of quietly writing live credentials into a checkout.

## Secrets live outside the repo

`/etc/vpn-stack`, mode 0700, root-owned:

```
/etc/vpn-stack/
├── secrets/        0600 each: reality.{key,pub}, reality.short_id, hysteria2.{crt,key,obfs},
│                   ipsec.{psk,primary_user,primary_password}, dnstt.server.{key,pub}
├── users.json      who has access, across every protocol
├── state.json      which protocols are on; revoke_pending; last_applied
├── .env            VPN_SERVER_HOST (the repo's ./.env is a symlink to this,
│                   because docker compose reads .env from the project directory)
├── data/           sing-box runtime state
└── rendered -> rendered-<ts>/    generated config, atomic symlink
```

Keeping them here means no *generated* credential is ever written into the checkout, and `rsync` cannot clobber a live key. `users.json` is written through a temp file created at 0600 and `os.replace`d, so an interrupted write cannot leave an empty user database or a world-readable one; the keyring is written the same way, and a zero-length file is not counted as a secret (otherwise `bootstrap` would skip regenerating it).

**That is not the same as "a clone cannot contain a credential", which this file used to claim and which was false.** Nothing stops an *operator* from putting one there, and `README.md` used to tell them to: `./vpn backup > vpn-$(date +%F).age` from the repo root. One such tar — the whole state directory plus the IKEv2 volume, so every secret, every user's password on every protocol, and the CA private key, under one passphrase — was committed in `d1a9613` and pushed. `.gitignore` now carries `*.age`, `*.p12`, `*.mobileconfig` and `*.sswan` extension-wide, and the README points at a path outside the tree; neither undoes a blob already in history, which takes `git filter-repo` plus rotating everything the blob held.

`.gitignore` is belt-and-braces where the secret is generated and load-bearing where the operator is, and it is directory-wide for the two sing-box fragment directories (`sing-box/vless-reality/`, `sing-box/hysteria2/`) so a new credential-bearing sibling is covered by default. It also carries `dnstt/keys/*`, which is now vestigial — that directory does not exist in the tree and dnstt's keys live in the state directory like everything else. This file previously described that rule as `dnstt/keys/*` **with `!server.pub`**; there is no such negation in `.gitignore`, and there never was. An invariant a reader cannot verify from the file stops being a check.

Backups: `./vpn backup` tars `/etc/vpn-stack` **and** the `vpn-stack_ikev2-vpn-data` volume — the latter holds `cert9.db`/`key4.db`, the NSS database with the IKEv2 CA private key. Omit it and every certificate is unrecoverable. The stream is encrypted by `age -r` on your machine, to the identity `./vpn backup-key` writes at `~/.config/vpn-stack/backup.key` (override with `VPN_BACKUP_KEY`); the key never reaches the server and the plaintext never lands on either disk. It used to be `age -p`, and the whole security of every secret on the box plus the IKEv2 CA key was then one passphrase a human had to be able to type — which is also why one committed `.age` was an incident rather than a shrug. An identity is high-entropy by construction and never typed. The trade-off points the other way and has to be said out loud: a passphrase cannot be lost with a laptop, so that file belongs in a password manager, and `backup-key` refuses to replace an existing one because every backup already taken is encrypted to it. `restore` sniffs the age header — `-> scrypt` means the old passphrase scheme — so backups from before the change still restore with no flag. The sniff uses `grep -a`: the header is ASCII but the payload after it is not, so without it grep calls the stream binary, exits 1 without looking, and sends every passphrase-era backup down the identity branch to fail on a rebuilt box — the only occasion anyone runs restore. `rendered-*` is excluded — it is derived, and `apply` rebuilds it.

`./vpn restore` is the other half, and it has been exercised: restoring the stream into a clean directory reproduced every secret bit-identically, brought `cert9.db`/`key4.db` back into the volume, and regenerated a client's VLESS URI **byte-identical** to the one issued before. It refuses to run against a server that already has users unless you pass `--force`, and stops `ipsec-vpn-server` first, because `pluto` holds the NSS database open.

## The protocol registry

`vpnctl/protocols/` — one module per protocol, each exporting a single `Protocol`. It owns everything protocol-specific: ports, required secrets, how to render config, how to build a share link, whether it is a sing-box inbound or its own container.

A `ShareItem` is one of three shapes, and picking the wrong one is not cosmetic: a `uri` gets a QR code and a tappable link, a `filename` gets a download, and `fields` get a form to copy by hand. DNSTT-over-SSH has no import format at all — no URI scheme, nothing to scan — so its settings were crammed into a `uri` and every layer duly treated them as one, producing a QR nothing could read and a link that imported nothing. Hence `fields`.

```python
render(secrets, users) -> {relative path: bytes}      # pure
share(secrets, user, host) -> [ShareItem]             # pure
bootstrap() -> {secret name: bytes}                   # cheap, at install time
prepare()   -> {secret name: bytes}                   # optional, expensive
```

**`share()` must not need a private key.** `vless_reality.share()` used to derive the REALITY public key from `reality.key` on every call, so the pure seam a future app renders links through would have meant shipping the private X25519 key to a phone. `bootstrap()` now stores the derived `reality.pub` beside it — public halves in the keyring is established practice here, `dnstt.server.pub` was already one — and `share()` prefers it, falling back to deriving it only for a keyring made before the field existed. `reality.pub` is deliberately **not** in `secret_names`, or an existing server would fail to render.

That change forced a second one. `bootstrap_keyring` used to skip per *secret name*, so on a server that had `reality.key` but no `reality.pub` a plain `bootstrap` would mint a whole new keypair, skip the existing private half, and write the **new** key's public half — every share link silently unusable afterwards. The same latent bug already existed for hysteria2: losing `hysteria2.key` alone made bootstrap mint a fresh key that did not match the surviving `hysteria2.crt`. So the skip is now **per protocol**: a half-present set is refused and named rather than topped up, because filling the gap pairs a fresh half with a stale one, which renders, serves, and fails on every client. Restore the missing file, or `--force` the whole set.

`prepare` exists for one reason: dnstt's Noise keypair is the `dnstt-server` binary's own format, so producing it means building a Go image. Doing that in `bootstrap` would make every fresh server pay ~800 MB for a protocol that ships disabled. It runs at `protocol on` instead, and a failure rolls the toggle back — leaving it enabled with no key would make every later `apply`, including the one systemd runs at boot, die on a missing secret with no clue how it got there.

`render` and `share` are pure — no `open()`, no `subprocess`, no globals. That is deliberate and load-bearing: it is the seam a future GUI app renders share links through with no server round-trip. Keep it that way.

**Adding a protocol is a new module plus one line in `PROTOCOLS`. It changes no command line.** The `-C` directory list that used to be hardcoded in three places is gone: everything renders into one directory.

Three things verified against the real binaries, which the design depends on:

- **Two files in one `-C` directory concatenate their `inbounds`.** So the old three-sibling layout bought exactly one thing (drop a protocol by dropping a flag) and cost a triply-duplicated list. Now: `-C /etc/sing-box`, permanently. `certs/` sits inside that directory because `-C` merges `*.json` and does **not** recurse.
- **`sing-box check` exits 0 on two inbounds sharing a `listen_port`.** It catches a duplicate *tag*, not a duplicate port. `protocols.assert_ports_disjoint` exists because of this and is not decorative.
- **`docker compose up -d --remove-orphans` does not stop a service whose profile was deactivated** (Compose v5.3.1, still true on v5.5.1). Explicit `docker compose rm -sf <service>` does. `composectl.down_disabled` diffs and removes explicitly — relying on `--remove-orphans` would mean "protocol off" leaves the protocol serving traffic.
- **Compose resolves `env_file` when it loads the project, not when it starts the service.** `ikev2.env` only exists while ikev2 is on, so a plain path there made *every* compose command fail the moment you turned the protocol off — including the ones that bring sing-box up, and including the `rm -sf` meant to stop ikev2 itself. It uses the `required: false` long form. Verified by turning the protocol off and back on.

The two pulled images are pinned, sing-box by tag and `hwdsl2/ipsec-vpn-server` by digest. **The three dnstt services are not**, and that is a live instance of exactly the hazard this paragraph is about: `dnstt/Dockerfile` does `go install …/dnstt-server@latest` and `dnstt-socks/Dockerfile` does `git clone --depth 1`, while `composectl.up` passes `--build` — so an upstream change lands on the next `apply`, on a live server, with nothing recording what the previous build was. `latest` means the next `apply` on any box can pull a release that dropped a config key or renamed a flag, and the failure lands on a live server — the exact class of accident the candidate-tree design exists to prevent. `ikev2ctl` hard-codes that image's CLI contract, so it gets a digest. `scripts/check.sh` reads the sing-box tag **out of compose.yml** rather than restating it: two literals drift, and the drift is invisible — the config validates against one binary and is then served by another.

## The apply pipeline

`vpnctl apply` is the only thing that changes the server:

1. Render the whole config into `rendered-<ts>/` **beside** the live tree.
2. `scripts/check.sh` validates that candidate in a throwaway container.
3. On failure: delete the candidate, exit 1. **The live tree was never touched, so there is nothing to roll back.**
4. On success: `os.replace` the `rendered` symlink — atomic, so a reader sees the old tree or the new one, never a mixture.
5. Converge: bring up the enabled set, explicitly remove the disabled set, **wait for every expected port to bind**, reconcile ufw, reconcile IKEv2 certificates.

**Converge bounces only what changed.** `composectl.changed_services` diffs the promoted tree against the candidate and maps each rendered path to the service that consumes it, and to *how* it reaches that process — `MOUNT` (bind-mounted; Docker re-resolves the mount source on start, so `restart` lands it) or `RECREATE` (only a new container will do). Before this, every `user add` unconditionally `--force-recreate`d everything, so adding one person dropped every live session on the box. The table is written by hand because `docker compose config` can only answer half of it — the volumes are in there, the `env_file` provenance is not.

Two failure modes this design has to keep closed, both of which it fell into once. First, **`up -d` alone does not restart a container whose bind-mounted file changed** but whose service definition did not — so dropping the flag without replacing it with a restart means config that silently never applies, which is worse than the downtime it saves. Second, a `RECREATE` service classified as `MOUNT` is a *revocation* bug, not a latency bug: see dnstt-sshd above. When in doubt, `RECREATE`; the cost is seconds of downtime, and the cost of the other mistake is a credential you believe you revoked.

Because the diff compares trees rather than asking what a container is *running*, a tree promoted without converging has to leave a mark that outlives the command — the same reasoning as `revoke_pending`. `bootstrap --force` and `apply --no-restart` both promote without bouncing, and without that mark the next `apply` would see an unchanged tree, bounce nothing, and leave sing-box serving the old keys forever while `smoke` passed because the ports were bound.

The readiness wait matters: `docker compose up` returns immediately but `hwdsl2/ipsec-vpn-server` needs ~30s to bind, and much longer on its *first* run, when it also builds the NSS database and issues the CA. Without the wait, the smoke test that runs next fails on a server that is merely still starting — a false alarm that teaches people to ignore smoke tests.

"Bound" means bound on a non-loopback address, in both `composectl` and `scripts/smoke.sh`. Substring-matching the port number reports dnstt's `53/udp` as served on any stock Ubuntu, because `systemd-resolved` holds `127.0.0.53:53`.

**A deploy is not an install.** `deploy.sh` updates code on a server that `init` already provisioned; it checks for `vpnctl`, `/etc/vpn-stack` and `uv` *before* the rsync and stops with that list if any is absent. Against a rebuilt box it used to rsync the code and then die on `uv: command not found`, exit 127, explaining nothing.

`scripts/check.sh` is the single definition of validity. `scripts/push.sh` is the single definition of *what gets sent* — the one dangerous rsync flag combination in this repo exists in one place, and both `install.sh` and `deploy.sh` call it. `scripts/deploy.sh` is the single deploy path, and `./vpn deploy` is the only thing that calls it. `deploy.sh` deliberately does **not** bootstrap: on a server whose state directory has been damaged, generating fresh secrets would silently invalidate every profile already handed out, so `apply` fails loudly instead and points at `bootstrap` or a backup.

## Users

`users.json` is the source of truth across all protocols. `user add` validates the name (`[A-Za-z0-9._-]`, 1–32 chars): `render_ikev2_env` joins names and passwords into two **space-separated** env vars, so a name with a space would misalign the lists and hand one user another's password.

```bash
./vpn user add <name>        # fresh credentials for every protocol
./vpn user rm <name>         # permanent
./vpn user enable|disable <name>
./vpn user list [--show-secrets]
./vpn user export <name> [--protocol <p>] [--qr]
```

**IKEv2 is reconciled, not remembered.** `vpnctl ikev2 reconcile` diffs `ikev2.sh --listclients` against the enabled users on every apply and repairs both directions, writing `ikev2_provisioned` from observed truth. If `--listclients` *fails*, reconcile aborts rather than reading the empty result as "nobody has a certificate" — that reading would try to re-issue every user, fail on "already exists", and then record that nobody is provisioned while the certificates kept working. When a revocation can't run because the container is down, the name goes into `state.json`'s `revoke_pending` — the intent outlives the deleted user record, so a `user rm` with ikev2 stopped can't leave a working certificate behind with nothing to retry it.

Hard-won IKEv2 facts: there is no `--removeclient`. `--deleteclient` alone does not stop a certificate working (the image says so itself); `--revokeclient` does, but leaves the name reserved so a later `--addclient` fails with "already exists". `remove_client` does both, in that order, each with `-y` or they block on a prompt. Re-enabling a user issues a **brand-new certificate** — the old profile stops working and needs re-exporting.

`--exportclient` writes three bundles: `.p12` (Windows/Linux), `.sswan` (Android/strongSwan), `.mobileconfig` (iOS/macOS, a complete ready-to-import profile). It writes them into `/etc/ipsec.d`, which is the persistent volume — so they survive restarts *and ride along in every backup*. `export_client` reads them out as bytes and then deletes them, which is what makes the old `exports/` problem actually go away rather than move. **Verified: the `.p12` has an empty password** — it is an unprotected private key, so whoever holds the file has VPN access. That is why `vpn share` is single-use, LAN-only and short-lived.

Recreating the ikev2 container drops **every** session it serves — L2TP, Cisco IPsec and IKEv2 alike. Certificates survive (they're in the volume); tunnels don't.

## IKEv2 client connectivity: the client's ISP filters IKE by payload shape

Clients cannot connect, and **it is not the server**. Privileged mode was tried and reverted (`59ab7e4`/`7ae4c2d`); a full bare-metal `hwdsl2/setup-ipsec-vpn` install was also tried. Re-measured properly on 2026-09-08, and the mechanism is now known exactly.

**A DPI middlebox inside the client's ISP (Rostelecom) drops UDP datagrams whose payload parses as an ISAKMP header, when they are addressed to a foreign destination.** Domestic destinations are exempt. It is not the hosting provider, not `pluto`, and not anything in this repo.

The measurement that settles it, and the one to repeat if this is ever doubted — send probes with **TTL=3**, so they expire inside the ISP core and *cannot* have reached the destination, then vary only the destination address:

| destination | genuine `IKE_SA_INIT` | same-size junk |
| --- | --- | --- |
| this server (SE) | **0/3 — dies before hop 3** | 3/3 |
| `8.8.8.8`, `1.1.1.1`, `9.9.9.9`, `185.199.108.153` | **0/3 each** | 3/3 each |
| `194.87.49.94` (Timeweb, RU-owned) | 3/3 | 3/3 |
| `77.88.8.8`, `213.180.204.242` (Yandex) | 3/3 | 3/3 |

Google, Cloudflare, Quad9 and GitHub plainly do not run IKE filters, and could not have dropped a packet that expired ten hops short of them. So the decision is made on the *client* side, keyed on payload shape × destination. `bash scripts/diagnose-ikev2.sh path <ip>` reproduces the localisation for one destination; run it a second time against a host you know answers IKE to show the filter is keyed on destination. The port sweep and the priming result below were separate measurements, not something that command reproduces.

Three properties that decide what is and is not worth trying:

- **It is stateful, and the first packet of a flow decides.** A real client's first packet *is* the `IKE_SA_INIT`, so it is dropped and that 5-tuple is then poisoned — 200 retransmits produced zero replies. Prime the same tuple with one junk datagram first and the byte-identical `IKE_SA_INIT` sails through and `pluto` answers it in full. That is why `docker logs ipsec-vpn-server` contains **zero** IKE negotiations ever and `ipsec trafficstatus` is empty: the server has never been allowed to hear a client, not once.
- **It is destination-port-independent.** IKE payloads are dropped on 53, 443, 1701, 12345 and 51820 alike, while same-size junk arrives on every one. **Moving IKEv2 to a non-standard port cannot work** — do not spend time on it.
- **It applies identically over IPv6.** Not a NAT or CGNAT artifact.

What actually helps: connect from a different ISP (expected to work outright, and the one claim still untested — there was no third vantage point); or use VLESS-REALITY / Hysteria2, which are unaffected on this same network and are what this stack already does well; or move the endpoint to a prefix the filter does not act on, which is precisely why a comparison box on Timeweb answers IKE while this one does not.

**Why the old conclusion said "settled" and pointed at the client anyway.** It reached the right suspect for the wrong reason, on evidence that could not support it. `scripts/diagnose-ikev2.sh probe` sent a plain `DIAGPROBE-<host>` datagram — junk, the exact shape this filter passes — and its arrival was read as "the provider is not blocking, so blame the client". Against a provider that really did block inbound IKE, that same test would have said the same thing and been flatly wrong. **A junk datagram on port 500 is not a proxy for IKE.** `probe` now sends a real `IKE_SA_INIT` plus a separately-marked junk control, so `listen` reports *which shape* arrived, and `path` localises the drop without needing a second host at all.

**The FORWARD rules** (`ikev2ctl.ensure_ipv4_forwarding`) are a separate, real failure mode. IKEv2 IPv4 clients are assigned from the image's `XAUTH_POOL` (`192.168.43.10-192.168.43.250` by default, inside `XAUTH_NET` — *not* from `L2TP_NET`, `192.168.42.0/24`) and, unlike L2TP, have no ppp interface, so without a `net0`↔`net0` accept pair the SA establishes and no traffic forwards, silently. `run.sh` does add that pair, but its idempotence guard tests a rule in the **nat** table while the accepts live in **filter**, so anything clearing filter alone loses them with nothing to restore them. This is why `vpnctl` needs root, and why `vpn-stack.service` (oneshot, `After=docker.service`) re-applies them at boot — raw `iptables -I` inserts with no persistence of their own.

That subnet was hardcoded as `192.168.42.0/24` until 2026-09-08, which is the L2TP pool: every rule `vpnctl` installed protected addresses no IKEv2 client is ever given, and **both** health checks (`scripts/smoke.sh`, `scripts/diagnose-ikev2.sh`) asserted the same wrong subnet, reporting green in exactly the failure they exist to catch. All three now ask the container which pool it hands out — `conn ikev2-cp`'s own `rightaddresspool` first, because that is literally what `pluto` assigns, then `VPN_XAUTH_NET`, then the image default — rather than trusting a constant. The order matters: `run.sh` uses `XAUTH_NET` for its *firewall* rules while `ikev2.sh` builds the pool from `XAUTH_POOL`, so preferring the net would reproduce this very bug for anyone who set only one of them. Same principle as IKEv2 certificates: reconcile from observed truth. The two shell copies validate the value before handing it to `iptables`, because an unparseable address makes `iptables -C` fail in a way indistinguishable from "the rule is missing" — which would report a healthy box as broken.

## Deployment

`./vpn deploy` → `scripts/deploy.sh root@<host>`. **CI never deploys, deliberately** — `.github/workflows/ci.yml` runs ruff, the test suite and `bash -n`, holds no secrets, has no ssh step and cannot reach a server. That is the actual invariant; "no CI at all" was the older, blunter version of it. Deploy-on-push bought nothing here — one operator, one laptop, one command — and cost a standing credential with root on the VPN server held by GitHub, plus a live server mutated by every `git push`. That is not a theoretical objection: a push did exactly that to a server that had just been deliberately wiped. The rsync (in `scripts/push.sh`) uses `--filter=':- .gitignore'` and **not** `--delete-excluded` (which would delete the very files the filter protects, from the server). Then `uv sync --frozen`, `vpnctl apply`, `scripts/smoke.sh`.

`scripts/install.sh` takes a bare Ubuntu 22.04/24.04 box to a serving VPN in one command, in five separate SSH sessions rather than one long heredoc — the firewall step has to prove a *fresh* connection still works before disarming its own safety net, and it cannot do that from inside the connection it might be about to sever.

**It pushes this checkout; it does not clone.** The repo is private and a bare box holds no credential for it, so a clone would need a deploy token just to install — and the future app ships its own copy of the tree anyway. One transfer mechanism (`push.sh`), used by install and deploy alike.

The ufw **deadman** is real, not decorative: a detached `setsid` timer that disables ufw unconditionally after 180s, armed before the first `ufw enable`, disarmed only after a brand-new SSH connection — one that had to pass through the new rules — succeeds. It records its own pid rather than trusting `$!` (setsid forks when the caller is already a process-group leader) and is killed by process group, so the `sleep` goes with it.

Two things a fresh box needs that an established one hides: `uv` installs to `/root/.local/bin`, which is **not** on the PATH of a non-interactive SSH session or a systemd unit, so it is symlinked into `/usr/local/bin` (only when nothing is already there) and the `vpnctl` shim sets its own PATH; and `/dev/ppp` must exist at container-create time.

Docker is installed from **Docker's own apt repository**, not `curl https://get.docker.com | sh`: same packages, but signed, upgradable with the rest of the system, and readable before it runs. That repository is behind CloudFront, which returns **403 over IPv4** to some ranges while serving the same bytes over IPv6 — observed on this host. `install_docker` probes both families, uses whichever answers, and when it has to use IPv6 it persists `Acquire::ForceIPv6` in `/etc/apt/apt.conf.d/99-vpn-stack-ipv6`, because otherwise the operator's own next `apt update` fails on that repository. If the system mirror turns out to have no IPv6, it reverts both files rather than leaving apt broken. (Note the asymmetry: `ghcr.io`, where sing-box comes from, answers over IPv4 and *not* IPv6. Both families are load-bearing.)

**Everything already installed is left alone.** docker, git, rsync, ufw, iptables and uv are each guarded by `command -v`, and the script says so rather than staying silent. If you install docker yourself it touches neither the daemon, `/etc/docker/daemon.json`, nor apt. ufw is only `enable`d when it was inactive, and `firewall.reconcile` only ever reads and writes rules carrying a `vpn-stack:` comment.

### Verified end to end on a bare box

Ubuntu 24.04.1, 2026-09-06, from `docker`-only to serving: install, `user add` (IKEv2 certificate issued by reconcile), export of all three bundles, `protocol off ikev2` → `on` (certificate survived the volume), `deploy`, **reboot** (boot unit re-applied the FORWARD rules, both containers returned, ufw persisted), and a backup/restore round trip. From outside, `10443/tcp` presents a genuine `www.apple.com` EV certificate and a port ufw does not allow is filtered.

## Conventions

- `paths.py` owns every path. Don't build one inline.
- **Everything `render` writes is 0600**, decided by default rather than by filename. The mode used to be `0600 if the name ends in .key or .env else 0644`, and `dnstt-sshd/logins` ends in neither — so the plaintext list of every user's dnstt password was rendered world-readable, contained only by the 0700 parent. Same failure shape as an exact-path `.gitignore` rule. Nothing needs the wider mode: every rendered path is bind-mounted `:ro` into a container that reads it as root, and no service declares a `user:`.
- **A commit hash written into prose does not survive a history rewrite.** This file cited `c04b19c`/`6e7f66e` for the privileged-mode experiment; both became unresolvable, and the citation was still there to be copied into a published document. Prefer the commit *subject*, which survives.
- Structural constants (ports, SNI, masquerade domains, bandwidth caps) live in the protocol modules, in git. They are no longer trapped in a gitignored file.
- `composectl.up` passes `--build`. Without it a changed Dockerfile or entrypoint is rsynced to the server and then silently ignored, because compose reuses the image whose tag already exists — so a fix appears to deploy and changes nothing.
- **Code can roll back; the database cannot.** `push.sh` will happily rsync an older checkout over a newer one, and it happened: deploying a stale tree onto a `users.json` that had grown a field killed every vpnctl command with `TypeError: User.__init__() got an unexpected keyword argument`. `load()` now refuses, by name, on an unknown field or a higher `schema_version`, and says the code is older than the database. It refuses rather than dropping the field, because ignoring it would let the next `save()` write the record back without a credential this code is merely too old to know about.
- `per_user` says whether a protocol issues a distinct credential per person. It must not gate *sharing*: filtering `user export` on it made the command silently return nothing for dnstt back when dnstt was shared. dnstt is `per_user=True` now, but the filter is still gone, and should stay gone.
- No device/connection limiting anywhere. sing-box has no native per-user cap (`SagerNet/sing-box#2579`, closed "not planned"); deliberately skipped at solo-user scale.
- `docker compose down -v` destroys `ikev2-vpn-data` — every IKEv2 certificate, unrecoverable. Prefer `stop`/`restart`.
- `--json` is a public API and must stay parseable: it goes to stdout, everything else to stderr, and it is accepted in **any** position (`user export x --json` as well as `--json user export x`). `--qr` is suppressed under `--json` for the same reason — ASCII art in the middle of the payload broke `./vpn share`.
- `apply` returns `enabled_protocols`, not `enabled`. The two collided in `emit(**result)` and made `user enable`/`user disable` raise `TypeError` on every single invocation.
- **Tests live in `tests/` and need no server, no Docker and no root.** They cover the pure layer — `render`/`share` for all four protocols, `assert_ports_disjoint`, `users_store.load()`'s three refusals and its never-writes property, `firewall.reconcile`'s diff, `_is_bound` skipping loopback, the bootstrap set rule, and `changed_services`' consumer table. They use `VPN_STATE_DIR` and `tmp_path`, so nothing reaches `/etc/vpn-stack`. Anything that needs a real container belongs in `scripts/smoke.sh`, which asserts against a live server; the two are not substitutes.
- Licensed **AGPL-3.0** (`LICENSE`). Not GPL: the nearest neighbours in this space are GPL-3.0 panels with paid hosted forks sold on top, and the network-use clause is the whole difference for server software.
- `users_store.load()` never writes. It used to mint a fresh `l2tp_password` for any record missing one and save it, so a plain `user list` could silently rotate a live credential. Booleans get defaults because those are derivable; a missing *secret* is a damaged database and says so.
