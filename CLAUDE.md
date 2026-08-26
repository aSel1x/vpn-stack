# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A personal VPN server deployment plus a small automation CLI around it. Core proxy layer is `sing-box` (https://sing-box.sagernet.org), deployed via Docker Compose, providing VLESS+REALITY and Hysteria2 inbound proxies. `vpnctl` (Python, in `vpnctl/`) manages users on top of that: it's the only supported way to add/remove/export users — the generated inbound config fragments should not be hand-edited directly (see "Users" below).

The repo root is `/home/asel1x/Code/vpn-stack/` (`compose.yml` lives directly here — no nested subdirectory).

## ⚠️ This directory contains live secrets

Unlike a typical codebase, the config files here hold real credentials: a REALITY `private_key`, per-user VLESS UUIDs, Hysteria2 obfuscation password and per-user passwords, a TLS `private.key`, a Clash API bearer secret, and an IPsec PSK/user/password in `ikev2/.env`. Treat every value in `sing-box/vless-reality/`, `sing-box/hysteria2/`, `sing-box/common/05_clash_api.json`, `users.json`, `.env`, `exports/`, and `ikev2/.env` as a live secret:

- Never echo, log, paste, or transmit these values (including to external tools, issues, or commit messages).
- `.gitignore` already excludes every one of those paths, so a future `git init` + first commit is safe without rotating anything — but double-check `git status` before ever staging files here, since a mistake would put live credentials in history.
- When editing configs, change only what's needed and avoid printing full file contents that include secrets back to the user unless they specifically ask for that value.
- This repo is **not currently a git repository**. That's intentional — nobody has asked for it to be initialized yet.

## Users: use `vpnctl`, not hand-edited JSON

`users.json` (gitignored) is the single source of truth for who has access — across *all* protocols, sing-box and IKEv2/L2TP alike. It holds, per user: `vless_uuid`, `hysteria2_password`, `l2tp_password`, `ikev2_provisioned` (bool), `enabled`, `created_at`. `sing-box/vless-reality/10_vless_reality_tcp.json` and `sing-box/hysteria2/20_hysteria2.json`'s `users` arrays, and `ikev2/.env`'s `VPN_ADDL_USERS`/`VPN_ADDL_PASSWORDS`, are all *generated* from it — any manual edit to those will be silently overwritten the next time `vpnctl` renders. Everything else in those files (ports, REALITY keys, obfs password, TLS paths, masquerade domain, `VPN_IPSEC_PSK`) is still hand-owned and passes through untouched. (Loading an older `users.json` missing the L2TP/IKEv2 fields auto-backfills them in place — no separate migration step needed.)

```bash
uv run vpnctl user add <name>              # generate fresh credentials for every protocol, apply
uv run vpnctl user rm <name>               # hard delete — credentials gone for good
uv run vpnctl user enable <name>           # re-enable; vless/hysteria2/l2tp creds preserved, IKEv2 cert re-issued (new one)
uv run vpnctl user disable <name>          # temporarily remove from active config, keep record
uv run vpnctl user list [--show-secrets]   # secrets hidden unless explicitly asked
uv run vpnctl user export <name> [--protocol vless|hysteria2|ikev2|both] [--host H] [--qr] [--png]
uv run vpnctl render [--no-restart]        # re-render config from users.json without adding/removing anyone
uv run vpnctl migrate                      # one-time bootstrap of users.json from hand-written config; refuses to run twice
uv run vpnctl ikev2 list-clients           # diagnostics — see ikev2/ section below
```

Every mutating subcommand follows the same pattern (`vpnctl/cli.py:validate_and_apply`): render → `docker compose run --rm --no-deps sing-box check` (all three `-C` dirs) → roll back the rendered sing-box fragment files (not `users.json`) on failure → `docker compose up -d --force-recreate --no-deps sing-box` on success, then sync the `ikev2` container **only if it's already running** (see `ikev2/` section — never implicitly started). A bad sing-box edit can't take down the running service.

`user export` needs to know the server's public host — pass `--host`, or set `VPN_SERVER_HOST=...` in `.env` once the server is actually deployed somewhere (nothing bakes in a default). The REALITY public key in the `vless://` link is derived on the fly from the stored `private_key` via X25519 (`vpnctl/reality_key.py`) — it is never stored separately, so the private key stays the single source of truth and never needs rotating for this to work.

## Commands

```bash
uv sync                       # install vpnctl + deps (cryptography, qrcode, pillow) into .venv/
docker compose up -d          # start sing-box + device-limiter
docker compose down           # stop both
docker compose logs -f        # tail logs (device-limiter logs every kick it performs)
```

Config is validated automatically by every `vpnctl` mutating command; to check manually:

```bash
docker compose run --rm --no-deps sing-box check \
  -C /etc/sing-box/common -C /etc/sing-box/vless-reality -C /etc/sing-box/hysteria2
```

## Architecture

`compose.yml` runs two services, both `network_mode: host` (required so the proxy inbounds bind directly to the host's ports/interfaces, and so `device-limiter` can reach sing-box's loopback-only Clash API):

- **`sing-box`** — `./sing-box:/etc/sing-box:ro`, `./data:/var/lib/sing-box`. Config is split into one directory per protocol, passed to sing-box as three separate `-C` flags (confirmed against the real binary: `-C` is a repeatable flag that merges each directory's `*.json` files together, but does **not** recurse into subdirectories — that's why this is three sibling directories, not one directory with subfolders):
  - `sing-box/common/00_base.json` — global `log` settings. Tracked in git. `log.output` points at `/var/lib/sing-box/sing-box.log` (i.e. `./data/sing-box.log`) instead of the console — see `device-limiter` below for why. **`docker compose logs sing-box` shows nothing as a result; use `tail -f data/sing-box.log` on the host instead.**
  - `sing-box/common/05_clash_api.json` — **generated** by `vpnctl render`, gitignored. Binds the experimental Clash API to `127.0.0.1:9090` with a bearer `secret` (from `.env`'s `CLASH_API_SECRET`, auto-generated on first render). Loopback-only bind is deliberate — under `network_mode: host` that's still reachable from other host-network containers (`device-limiter`) but never off-box.
  - `sing-box/common/90_outbounds.json` — `direct` + `block` outbounds. Tracked in git.
  - `sing-box/vless-reality/10_vless_reality_tcp.json` — VLESS inbound, port `10443`, XTLS-Vision flow, REALITY masquerading as `www.apple.com`. `users` array generated; everything else hand-owned. Gitignored (whole file — see trade-off note below).
  - `sing-box/hysteria2/20_hysteria2.json` — Hysteria2 inbound, port `20443`, Salamander obfuscation, TLS via `certs/` in the same directory (self-signed, `CN=bing.com`), masquerading as `bing.com`. `users` array generated. Gitignored.
  - `sing-box/hysteria2/certs/` — `certificate.pem` + `private.key`, self-signed EC cert. Gitignored. Deliberately colocated with `hysteria2/` rather than shared at a higher level — REALITY (VLESS) does its own key exchange and never touches these files, so they're not actually cross-protocol.

- **`device-limiter`** — `python:3.12-slim`, bind-mounts `device-limiter/limiter.py` read-only plus `./data:/var/lib/sing-box` **read-write** (it needs to truncate the log file — see below), no image build step.

  **Important, confirmed against a live 1.13.19 instance:** sing-box's Clash-compatible API's `/connections` endpoint does **not** include a user field in its metadata (only `sourceIP`/`sourcePort`/`host`/`network`/`type`) — despite `adapter.InboundContext` having a `User` field internally, it isn't exposed there. So per-user grouping can't be done from the Clash API alone. The only place the (user, source IP) pairing actually shows up is sing-box's own log output (`[asel1x] inbound connection to ...` right after `inbound connection from 1.2.3.4:5678`, sharing the same bracketed connection ID) — which is *why* `00_base.json` redirects logging to a file instead of the console: `device-limiter` tails `data/sing-box.log` to build a `sourceIP:sourcePort → user` map, then joins that against the Clash API's live `/connections` list (which has the actual connection `id` needed to close one) to know who owns what. This was cross-checked directly against a live client connection — the log parser correctly attributed all active connections to the right user.

  Since `log.output` has no built-in rotation, `device-limiter` also self-truncates `data/sing-box.log` once it exceeds `LOG_MAX_BYTES` (default 10MB) — safe because sing-box writes in append mode, the same mechanism `logrotate --copytruncate` relies on. A truncation-timed write could theoretically be lost, which is acceptable for a best-effort heuristic.

  Polls every `POLL_INTERVAL_SECONDS` (default 5s); if a user has connections from more than one distinct source IP for `HYSTERESIS_POLLS` consecutive polls (default 2), `DELETE`s the connection(s) from every IP except the most recently active one.

  **This is explicitly best-effort, not hard enforcement.** sing-box has no native per-user device cap (upstream issue `SagerNet/sing-box#2579`, closed "not planned") — this daemon is a bolted-on approximation. Known gaps: multiple real devices behind one NAT/CGNAT IP aren't detected; a legitimate fast IP change (mobile handoff) can look like an extra device (the hysteresis window absorbs brief overlaps, not eliminate the risk); nothing stops further-proxying behind one already-admitted device; a connection is only actionable once its log line has appeared (a short unattributed window right after connect).

### `vpnctl/` (the CLI)

- `paths.py` — all path constants, resolved relative to the package location (repo root).
- `users_store.py` — `User` dataclass, `users.json` load/save, credential generation (`uuid.uuid4()`, `secrets.token_hex(16)`).
- `render.py` — regenerates `05_/10_/20_` config fragments from `users.json` + `.env`.
- `reality_key.py` — X25519 public-key derivation from the stored REALITY private key.
- `export.py` — builds `vless://` / `hysteria2://` share URIs and renders QR (terminal ASCII via `qrcode`, optional PNG under gitignored `exports/`).
- `sbctl.py` — wraps `docker compose run .../check` and `docker compose up -d --force-recreate` for the sing-box service.
- `ikev2ctl.py` — wraps `docker exec ipsec-vpn-server ikev2.sh` (add/remove/list/export client certs) plus `docker compose up -d --force-recreate --no-deps ikev2`; see `ikev2/` section below.
- `dotenv.py` — minimal `.env`-file read/write/get-or-create helper; used by `render.py` for `CLASH_API_SECRET` and `ikev2/.env`'s `VPN_ADDL_USERS`/`VPN_ADDL_PASSWORDS`.
- `cli.py` — argparse entry point (`user add/rm/enable/disable/list/export`, `render`, `migrate`, `ikev2 list-clients`), and the validate-then-apply/rollback logic all mutating commands share.

**Known trade-off:** gitignoring `10_`/`20_` wholesale (to keep secrets out of history) also puts their non-secret structural fields (ports, `server_name`, masquerade domain, bandwidth caps) outside version control, since secrets and structure currently share one file. Accepted as a reasonable simplification at solo-user scale — document structural tuning changes in commit messages/notes elsewhere rather than expecting git history to capture them.

### `ikev2/` — L2TP/IPsec, Cisco IPsec, IKEv2 (`hwdsl2/ipsec-vpn-server`)

`compose.yml`'s `ikev2` service runs `hwdsl2/ipsec-vpn-server`, `network_mode: host`, **`privileged: true`** (mandatory per the image — not just extra `cap_add`; verified the host kernel has the needed `esp4`/`ah4`/`xfrm4_tunnel`/`l2tp_*` modules available). Named volume `ikev2-vpn-data:/etc/ipsec.d` persists IKEv2 client certs across container recreation; `/lib/modules:/lib/modules:ro` is required by the image. **Not yet started** — `vpnctl` never brings this container up on its own (see below); someone needs to run `docker compose up -d ikev2` explicitly once, knowingly accepting the privileged container.

This image bundles two genuinely different auth mechanisms, and `vpnctl` drives both from the same `users.json`:

- **L2TP/IPsec + Cisco IPsec** (PSK + username/password) — declarative, like sing-box: `vpnctl` renders `VPN_ADDL_USERS`/`VPN_ADDL_PASSWORDS` in `ikev2/.env` from every *enabled* user's `l2tp_password` field (`render.py:render_ikev2_env`). `VPN_IPSEC_PSK` and the primary `VPN_USER`/`VPN_PASSWORD` slot (required by the image, unused by any real person) are left untouched — every real user goes through the additional-users lists uniformly. **Applying a change recreates the whole container**, which briefly drops *every* active L2TP/Cisco session, not just the one being added/removed — this is a real limitation of the image (no live env reload), not something `vpnctl` can avoid.
- **IKEv2** (per-client certificates) — imperative, unlike everything else in this repo: `vpnctl/ikev2ctl.py` shells out to `docker exec ipsec-vpn-server ikev2.sh --addclient/--removeclient/--listclients/--exportclient`. This is live (no container recreation) and tracked via `users.json`'s `ikev2_provisioned` bool. **Re-enabling a disabled user issues a brand-new certificate** — unlike VLESS/Hysteria2/L2TP, the old IKEv2 profile a client imported stops working and needs re-exporting; there's no "same credentials" story for cert-based auth. `--exportclient`'s exact output filename (`vpnctl` assumes `<name>.p12` under `/etc/ipsec.d/`) hasn't been confirmed against a live instance yet — `vpnctl user export <name> --protocol ikev2` will surface `--listclients` output on failure so this can be corrected on first real run, same pattern used to catch the Clash API assumption earlier.

Every `vpnctl` mutating command (`user add/rm/enable/disable`, `render`) touches all of this automatically, but **only acts on the `ikev2` container if it's already running** (`ikev2ctl.is_running()`) — a `user add` before anyone has started `ikev2` just updates `ikev2/.env` and prints a note, it never implicitly launches a privileged container as a side effect.

No device-limit story for this protocol group: no live connection-listing API exists for it, so the sing-box `device-limiter` approach doesn't carry over without a much larger custom strongSwan/swanctl build.

```bash
uv run vpnctl ikev2 list-clients   # raw `ikev2.sh --listclients` output, for diagnostics
```
