# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A personal VPN server plus the CLI that operates it. Four protocols, one user database, one command surface:

- **`sing-box`** — VLESS+REALITY (`10443/tcp`) and Hysteria2 (`20443/udp`), the everyday path.
- **`hwdsl2/ipsec-vpn-server`** — IKEv2 / L2TP/IPsec / Cisco IPsec (`500`, `4500`, `1701` udp).
- **`dnstt` + `dnstt-sshd` + `dnstt-socks`** — DNS-tunnel last resort (`53/udp`), for networks that allow nothing else. Off by default; `protocol on dnstt` builds the image and has `dnstt-server -gen-key` mint the Noise keypair, because that format is the binary's own. The zone `tun.example.net` is already delegated (`NS ns-tun.example.net`, `A` this server).

  The decoded stream exits into an sshd **in a container**, not the host's. iOS clients speak DNSTT→SSH and need a login; on the host that would be a real account plus an `/etc/ssh/sshd_config` edit, neither captured by `vpn backup` and both to be redone after every rebuild. The container listens on loopback only, allows one user, and `PermitOpen 127.0.0.1:7300` — verified: that forward carries traffic, any other is refused *administratively prohibited*. Its host key lives in a volume so it does not change under clients on restart.

  `-gen-key` prints both halves as hex on stdout, and that is what `prepare()` parses. Writing them with `-privkey-file` into a bind mount produces root-owned files that nothing but root can read back, and a temp directory that then fails to clean up.

Live deployment: `root@203.0.113.10`, checkout at `/opt/vpn-stack`, state at `/etc/vpn-stack`.

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
├── secrets/        0600 each: reality.key, reality.short_id, hysteria2.{crt,key,obfs},
│                   ipsec.{psk,primary_user,primary_password}, dnstt.server.{key,pub}
├── users.json      who has access, across every protocol
├── state.json      which protocols are on; revoke_pending; last_applied
├── .env            VPN_SERVER_HOST (the repo's ./.env is a symlink to this,
│                   because docker compose reads .env from the project directory)
├── data/           sing-box runtime state
└── rendered -> rendered-<ts>/    generated config, atomic symlink
```

A `git clone` therefore *cannot* contain a credential, and `rsync` cannot clobber a live key. `users.json` is written through a temp file created at 0600 and `os.replace`d, so an interrupted write cannot leave an empty user database or a world-readable one; the keyring is written the same way, and a zero-length file is not counted as a secret (otherwise `bootstrap` would skip regenerating it). `.gitignore` is now belt-and-braces rather than load-bearing — and it is directory-wide (`sing-box/vless-reality/`, `sing-box/hysteria2/`, `dnstt/keys/*` with `!server.pub`), so a new credential-bearing sibling is covered by default.

Backups: `./vpn backup` tars `/etc/vpn-stack` **and** the `vpn-stack_ikev2-vpn-data` volume — the latter holds `cert9.db`/`key4.db`, the NSS database with the IKEv2 CA private key. Omit it and every certificate is unrecoverable. The stream is encrypted by `age -p` on your machine; the passphrase never reaches the server and the plaintext never lands on either disk. `rendered-*` is excluded — it is derived, and `apply` rebuilds it.

`./vpn restore` is the other half, and it has been exercised: restoring the stream into a clean directory reproduced all 8 secrets bit-identically, brought `cert9.db`/`key4.db` back into the volume, and regenerated a client's VLESS URI **byte-identical** to the one issued before. It refuses to run against a server that already has users unless you pass `--force`, and stops `ipsec-vpn-server` first, because `pluto` holds the NSS database open.

## The protocol registry

`vpnctl/protocols/` — one module per protocol, each exporting a single `Protocol`. It owns everything protocol-specific: ports, required secrets, how to render config, how to build a share link, whether it is a sing-box inbound or its own container.

```python
render(secrets, users) -> {relative path: bytes}      # pure
share(secrets, user, host) -> [ShareItem]             # pure
bootstrap() -> {secret name: bytes}                   # cheap, at install time
prepare()   -> {secret name: bytes}                   # optional, expensive
```

`prepare` exists for one reason: dnstt's Noise keypair is the `dnstt-server` binary's own format, so producing it means building a Go image. Doing that in `bootstrap` would make every fresh server pay ~800 MB for a protocol that ships disabled. It runs at `protocol on` instead, and a failure rolls the toggle back — leaving it enabled with no key would make every later `apply`, including the one systemd runs at boot, die on a missing secret with no clue how it got there.

`render` and `share` are pure — no `open()`, no `subprocess`, no globals. That is deliberate and load-bearing: it is the seam a future GUI app renders share links through with no server round-trip. Keep it that way.

**Adding a protocol is a new module plus one line in `PROTOCOLS`. It changes no command line.** The `-C` directory list that used to be hardcoded in three places is gone: everything renders into one directory.

Three things verified against the real binaries, which the design depends on:

- **Two files in one `-C` directory concatenate their `inbounds`.** So the old three-sibling layout bought exactly one thing (drop a protocol by dropping a flag) and cost a triply-duplicated list. Now: `-C /etc/sing-box`, permanently. `certs/` sits inside that directory because `-C` merges `*.json` and does **not** recurse.
- **`sing-box check` exits 0 on two inbounds sharing a `listen_port`.** It catches a duplicate *tag*, not a duplicate port. `protocols.assert_ports_disjoint` exists because of this and is not decorative.
- **`docker compose up -d --remove-orphans` does not stop a service whose profile was deactivated** (Compose v5.3.1, still true on v5.5.1). Explicit `docker compose rm -sf <service>` does. `composectl.down_disabled` diffs and removes explicitly — relying on `--remove-orphans` would mean "protocol off" leaves the protocol serving traffic.
- **Compose resolves `env_file` when it loads the project, not when it starts the service.** `ikev2.env` only exists while ikev2 is on, so a plain path there made *every* compose command fail the moment you turned the protocol off — including the ones that bring sing-box up, and including the `rm -sf` meant to stop ikev2 itself. It uses the `required: false` long form. Verified by turning the protocol off and back on.

Both images are pinned, sing-box by tag and `hwdsl2/ipsec-vpn-server` by digest. `latest` means the next `apply` on any box can pull a release that dropped a config key or renamed a flag, and the failure lands on a live server — the exact class of accident the candidate-tree design exists to prevent. `ikev2ctl` hard-codes that image's CLI contract, so it gets a digest. `scripts/check.sh` reads the sing-box tag **out of compose.yml** rather than restating it: two literals drift, and the drift is invisible — the config validates against one binary and is then served by another.

## The apply pipeline

`vpnctl apply` is the only thing that changes the server:

1. Render the whole config into `rendered-<ts>/` **beside** the live tree.
2. `scripts/check.sh` validates that candidate in a throwaway container.
3. On failure: delete the candidate, exit 1. **The live tree was never touched, so there is nothing to roll back.**
4. On success: `os.replace` the `rendered` symlink — atomic, so a reader sees the old tree or the new one, never a mixture.
5. Converge: bring up the enabled set, explicitly remove the disabled set, **wait for every expected port to bind**, reconcile ufw, reconcile IKEv2 certificates.

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

## IKEv2 client connectivity: settled, do not re-open

Clients cannot connect, and **it is not the server**. Privileged mode was tried and reverted (`c04b19c`/`6e7f66e`); a full bare-metal `hwdsl2/setup-ipsec-vpn` install was also tried. Settled 2026-09-05 with `scripts/diagnose-ikev2.sh`:

- A marked UDP datagram from an unrelated network **arrived** at `net0` on both 500 and 4500. The hosting provider does not block inbound IKE.
- The box is green end to end: `pluto` bound on the public IP, `-A INPUT -p udp -m multiport --dports 500,4500 -j ACCEPT` present, ufw allowing all three ports, both `192.168.42.0/24` FORWARD accepts in place, `ip_forward=1`, `rp_filter=0`.
- `docker logs ipsec-vpn-server` contains **zero** IKE negotiation attempts, ever. `ipsec trafficstatus` is empty.

Arbitrary UDP reaches the server while no client's IKE ever has: the drop is on the **client's** network. Have the client try a different network before spending any time here. Re-run with `sudo bash scripts/diagnose-ikev2.sh listen` plus `probe <ip>` from elsewhere.

**The missing FORWARD rule** (`ikev2ctl.ensure_ipv4_forwarding`) is a separate, real failure: the image's `run.sh` never adds a `net0`↔`net0` accept for its own `L2TP_NET` pool, and IKEv2 IPv4 clients have no ppp interface, so without it the SA establishes and no traffic forwards, silently. This is why `vpnctl` needs root. `vpn-stack.service` (oneshot, `After=docker.service`) re-applies it at boot — these are raw `iptables -I` inserts with no persistence of their own.

## Deployment

`./vpn deploy` → `scripts/deploy.sh root@<host>`. **There is no CI, deliberately.** Deploy-on-push bought nothing here — one operator, one laptop, one command — and cost a standing credential with root on the VPN server held by GitHub, plus a live server mutated by every `git push`. That is not a theoretical objection: a push did exactly that to a server that had just been deliberately wiped. The rsync (in `scripts/push.sh`) uses `--filter=':- .gitignore'` and **not** `--delete-excluded` (which would delete the very files the filter protects, from the server). Then `uv sync --frozen`, `vpnctl apply`, `scripts/smoke.sh`.

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
- Structural constants (ports, SNI, masquerade domains, bandwidth caps) live in the protocol modules, in git. They are no longer trapped in a gitignored file.
- `per_user=False` on a protocol means it issues no distinct credential per person. It does **not** mean "do not share it": dnstt has one login for everyone and they still need it. Filtering `user export` on that flag made the command silently return nothing for dnstt.
- No device/connection limiting anywhere. sing-box has no native per-user cap (`SagerNet/sing-box#2579`, closed "not planned"); deliberately skipped at solo-user scale.
- `docker compose down -v` destroys `ikev2-vpn-data` — every IKEv2 certificate, unrecoverable. Prefer `stop`/`restart`.
- `--json` is a public API and must stay parseable: it goes to stdout, everything else to stderr, and it is accepted in **any** position (`user export x --json` as well as `--json user export x`). `--qr` is suppressed under `--json` for the same reason — ASCII art in the middle of the payload broke `./vpn share`.
- `apply` returns `enabled_protocols`, not `enabled`. The two collided in `emit(**result)` and made `user enable`/`user disable` raise `TypeError` on every single invocation.
- `users_store.load()` never writes. It used to mint a fresh `l2tp_password` for any record missing one and save it, so a plain `user list` could silently rotate a live credential. Booleans get defaults because those are derivable; a missing *secret* is a damaged database and says so.
