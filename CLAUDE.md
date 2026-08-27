# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A personal VPN server deployment plus a small automation CLI around it. Core proxy layer is `sing-box` (https://sing-box.sagernet.org), deployed via Docker Compose, providing VLESS+REALITY and Hysteria2 inbound proxies. `vpnctl` (Python, in `vpnctl/`) manages users on top of that: it's the only supported way to add/remove/export users — the generated inbound config fragments should not be hand-edited directly (see "Users" below).

The repo root is `/home/asel1x/Code/vpn-stack/` (`compose.yml` lives directly here — no nested subdirectory).

## ⚠️ This directory contains live secrets

Unlike a typical codebase, the config files here hold real credentials: a REALITY `private_key`, per-user VLESS UUIDs, a Hysteria2 obfuscation password and per-user passwords, a TLS `private.key`, and an IPsec PSK/user/password in `ikev2/.env`. Treat every value in `sing-box/vless-reality/`, `sing-box/hysteria2/`, `users.json`, `.env`, `exports/`, and `ikev2/.env` as a live secret:

- Never echo, log, paste, or transmit these values (including to external tools, issues, or commit messages).
- `.gitignore` excludes every one of those paths — but double-check `git status` before ever staging files here, since a mistake would put live credentials in history.
- When editing configs, change only what's needed and avoid printing full file contents that include secrets back to the user unless they specifically ask for that value.

## Users: use `vpnctl`, not hand-edited JSON

`users.json` (gitignored) is the single source of truth for who has access — across *all* protocols, sing-box and IKEv2/L2TP alike. It holds, per user: `vless_uuid`, `hysteria2_password`, `l2tp_password`, `ikev2_provisioned` (bool), `enabled`, `created_at`. `sing-box/vless-reality/10_vless_reality_tcp.json` and `sing-box/hysteria2/20_hysteria2.json`'s `users` arrays, and `ikev2/.env`'s `VPN_ADDL_USERS`/`VPN_ADDL_PASSWORDS`, are all *generated* from it — any manual edit to those will be silently overwritten the next time `vpnctl` renders. Everything else in those files (ports, REALITY keys, obfs password, TLS paths, masquerade domain, `VPN_IPSEC_PSK`) is still hand-owned and passes through untouched. (Loading an older `users.json` missing the L2TP/IKEv2 fields auto-backfills them in place — no separate migration step needed. A missing `users.json` is treated as zero users, not an error — `user add` on a freshly-`bootstrap`ped server just works.)

```bash
uv run vpnctl bootstrap [--force]          # one-time: generate REALITY keypair, Hysteria2 cert+obfs, ikev2/.env PSK (day-0 setup on a fresh checkout)
uv run vpnctl user add <name>              # generate fresh credentials for every protocol, apply
uv run vpnctl user rm <name>               # hard delete — credentials gone for good
uv run vpnctl user enable <name>           # re-enable; vless/hysteria2/l2tp creds preserved, IKEv2 cert re-issued (new one)
uv run vpnctl user disable <name>          # temporarily remove from active config, keep record
uv run vpnctl user list [--show-secrets]   # secrets hidden unless explicitly asked
uv run vpnctl user export <name> [--protocol vless|hysteria2|ikev2|all] [--host H] [--qr] [--png]
uv run vpnctl render [--no-restart]        # re-render config from users.json without adding/removing anyone
uv run vpnctl migrate                      # one-time bootstrap of users.json from an *existing* hand-written single-user config; refuses to run twice
uv run vpnctl ikev2 list-clients           # diagnostics — see ikev2/ section below
```

`bootstrap` and `migrate` solve different problems: `bootstrap` creates the hand-owned secrets from nothing (fresh server, empty `sing-box/vless-reality/` and `sing-box/hysteria2/` — these are gitignored wholesale, so a plain `git clone` never brings them along); `migrate` instead converts an *already-populated* hand-written single-user config (predates `vpnctl` entirely) into `users.json`. On a truly fresh checkout, run `bootstrap` then `user add`, not `migrate`.

Every mutating subcommand follows the same pattern (`vpnctl/cli.py:validate_and_apply`): render → `docker compose run --rm --no-deps sing-box check` (all three `-C` dirs) → roll back the rendered sing-box fragment files (not `users.json`) on failure → `docker compose up -d --force-recreate --no-deps sing-box` on success, then sync the `ikev2` container **only if it's already running** (see `ikev2/` section — never implicitly started). A bad sing-box edit can't take down the running service.

`user export` needs to know the server's public host — pass `--host`, or set `VPN_SERVER_HOST=...` in `.env` once the server is actually deployed somewhere (nothing bakes in a default). The REALITY public key in the `vless://` link is derived on the fly from the stored `private_key` via X25519 (`vpnctl/reality_key.py`) — it is never stored separately, so the private key stays the single source of truth and never needs rotating for this to work.

## Commands

```bash
uv sync                       # install vpnctl + deps (cryptography, qrcode, pillow) into .venv/
docker compose up -d sing-box # start sing-box
docker compose down           # stop it
docker compose logs -f sing-box  # tail logs
```

Config is validated automatically by every `vpnctl` mutating command; to check manually:

```bash
docker compose run --rm --no-deps sing-box check \
  -C /etc/sing-box/common -C /etc/sing-box/vless-reality -C /etc/sing-box/hysteria2
```

## Architecture

`compose.yml`'s `sing-box` service runs `network_mode: host` (required so the proxy inbounds bind directly to the host's ports/interfaces), mounting `./sing-box:/etc/sing-box:ro` and `./data:/var/lib/sing-box`. Config is split into one directory per protocol, passed to sing-box as three separate `-C` flags (confirmed against the real binary: `-C` is a repeatable flag that merges each directory's `*.json` files together, but does **not** recurse into subdirectories — that's why this is three sibling directories, not one directory with subfolders):

- `sing-box/common/00_base.json` — global `log` settings (console output, `info` level). Tracked in git.
- `sing-box/common/90_outbounds.json` — `direct` + `block` outbounds. Tracked in git.
- `sing-box/vless-reality/10_vless_reality_tcp.json` — VLESS inbound, port `10443`, XTLS-Vision flow, REALITY masquerading as `www.apple.com`. `users` array generated; everything else hand-owned. Gitignored (whole file — see trade-off note below).
- `sing-box/hysteria2/20_hysteria2.json` — Hysteria2 inbound, port `20443`, Salamander obfuscation, TLS via `certs/` in the same directory (self-signed, `CN=bing.com`), masquerading as `bing.com`. `users` array generated. Gitignored.
- `sing-box/hysteria2/certs/` — `certificate.pem` + `private.key`, self-signed EC cert. Gitignored. Deliberately colocated with `hysteria2/` rather than shared at a higher level — REALITY (VLESS) does its own key exchange and never touches these files, so they're not actually cross-protocol.

No per-user device/connection limiting is enforced. sing-box has no native per-user device cap (upstream issue `SagerNet/sing-box#2579`, closed "not planned"), and there's no plan to bolt one on — evaluated and deliberately skipped as not worth the complexity/trust trade-off at solo-user scale.

### `vpnctl/` (the CLI)

- `paths.py` — all path constants, resolved relative to the package location (repo root).
- `bootstrap.py` — one-time day-0 generation of the hand-owned base config: REALITY keypair (via `reality_key.generate_private_key`), self-signed Hysteria2 cert/key (`cryptography`'s `ec`/`x509`), obfs password, and `ikev2/.env`'s PSK/primary user slot. Refuses to overwrite existing files unless `force=True`.
- `users_store.py` — `User` dataclass, `users.json` load/save, credential generation (`uuid.uuid4()`, `secrets.token_hex(16)`).
- `render.py` — regenerates `10_/20_` config fragments and `ikev2/.env` from `users.json`.
- `reality_key.py` — X25519 keypair generation and public-key derivation from a stored REALITY private key.
- `export.py` — builds `vless://` / `hysteria2://` share URIs and renders QR (terminal ASCII via `qrcode`, optional PNG under gitignored `exports/`).
- `sbctl.py` — wraps `docker compose run .../check` and `docker compose up -d --force-recreate` for the sing-box service.
- `ikev2ctl.py` — wraps `docker exec ipsec-vpn-server ikev2.sh` (add/remove/list/export client certs) plus `docker compose up -d --force-recreate --no-deps ikev2`; see `ikev2/` section below.
- `dotenv.py` — minimal `.env`-file read/write helper; used by `render.py` to write `ikev2/.env`'s `VPN_ADDL_USERS`/`VPN_ADDL_PASSWORDS`, and by `export.py` to read `VPN_SERVER_HOST`.
- `cli.py` — argparse entry point (`bootstrap`, `user add/rm/enable/disable/list/export`, `render`, `migrate`, `ikev2 list-clients`), and the validate-then-apply/rollback logic all mutating commands share.

**Known trade-off:** gitignoring `10_`/`20_` wholesale (to keep secrets out of history) also puts their non-secret structural fields (ports, `server_name`, masquerade domain, bandwidth caps) outside version control, since secrets and structure currently share one file. Accepted as a reasonable simplification at solo-user scale — document structural tuning changes in commit messages/notes elsewhere rather than expecting git history to capture them.

### `ikev2/` — L2TP/IPsec, Cisco IPsec, IKEv2 (`hwdsl2/ipsec-vpn-server`)

`compose.yml`'s `ikev2` service runs `hwdsl2/ipsec-vpn-server`, `network_mode: host`, **not** `privileged: true` — `cap_add: [NET_ADMIN]` + `devices: ["/dev/ppp:/dev/ppp"]` instead (image's own documented non-privileged mode; confirmed working against a live instance). The image also wants a handful of sysctls that Docker refuses to set via Compose under `network_mode: host` (no separate container netns to set them in) — those are applied once on the host itself by `scripts/host-bootstrap.sh`, not through compose. Named volume `ikev2-vpn-data:/etc/ipsec.d` persists IKEv2 client certs across container recreation; `/lib/modules:/lib/modules:ro` is required by the image.

This image bundles two genuinely different auth mechanisms, and `vpnctl` drives both from the same `users.json`:

- **L2TP/IPsec + Cisco IPsec** (PSK + username/password) — declarative, like sing-box: `vpnctl` renders `VPN_ADDL_USERS`/`VPN_ADDL_PASSWORDS` in `ikev2/.env` from every *enabled* user's `l2tp_password` field (`render.py:render_ikev2_env`). `VPN_IPSEC_PSK` and the primary `VPN_USER`/`VPN_PASSWORD` slot (required by the image, unused by any real person) are left untouched by rendering — every real user goes through the additional-users lists uniformly. **Applying a change recreates the whole container**, which briefly drops *every* active L2TP/Cisco session, not just the one being added/removed — this is a real limitation of the image (no live env reload), not something `vpnctl` can avoid.
- **IKEv2** (per-client certificates) — imperative, unlike everything else in this repo: `vpnctl/ikev2ctl.py` shells out to `docker exec ipsec-vpn-server ikev2.sh --addclient/--revokeclient/--deleteclient/--listclients/--exportclient`. This is live (no container recreation) and tracked via `users.json`'s `ikev2_provisioned` bool. Confirmed against a live instance: there is no `--removeclient` (an earlier version of this code assumed one; it failed loudly on stderr but non-fatally on every disable/remove, so `ikev2_provisioned` never got cleared and the cert was never actually revoked — fixed). Removing a client is actually two steps, both needing `-y` or they block on a confirmation prompt: `--deleteclient` alone isn't enough — the image's own warning says a deleted cert *can still be used to connect*; `--revokeclient` is what actually cuts off access, but leaves the name reserved in the IPsec database, so a later `--addclient` for that same name fails with "already exists" (hit this for real re-adding `asel1x`). `ikev2ctl.remove_client` does both in order: revoke (cuts access immediately) then delete (safe now that it's already revoked; frees the name for reuse). **Re-enabling a disabled user issues a brand-new certificate** — unlike VLESS/Hysteria2/L2TP, the old IKEv2 profile a client imported stops working and needs re-exporting; there's no "same credentials" story for cert-based auth. `--exportclient <name>` writes three files under `/etc/ipsec.d/`: `<name>.p12` (Windows/Linux only), `<name>.sswan` (Android/strongSwan), `<name>.mobileconfig` (iOS/macOS — a complete ready-to-import VPN profile, not just a bare cert). `vpnctl` copies out all three into `exports/`.

Every `vpnctl` mutating command (`user add/rm/enable/disable`, `render`) touches all of this automatically, but **only acts on the `ikev2` container if it's already running** (`ikev2ctl.is_running()`) — a `user add` before anyone has started `ikev2` just updates `ikev2/.env` and prints a note, it never implicitly launches the container as a side effect.

No device/connection limiting is enforced for this protocol group either — consistent with sing-box (see Architecture above).

```bash
uv run vpnctl ikev2 list-clients   # raw `ikev2.sh --listclients` output, for diagnostics
```
