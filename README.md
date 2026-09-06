# vpn-stack

Personal VPN server: VLESS+REALITY and Hysteria2 (`sing-box`), IKEv2/L2TP/Cisco IPsec
(`hwdsl2/ipsec-vpn-server`), and a dnstt DNS tunnel as a last resort — all driven from one CLI.

## From a bare VPS

```bash
git clone git@github.com:aSel1x/vpn-stack.git && cd vpn-stack
./vpn init root@<ip>          # docker, state dir, sysctls, firewall, keys, boot unit
./vpn user add alice
./vpn user export alice --qr  # QR in your terminal; point the phone at the screen
./vpn share alice             # or a one-shot page for a phone on your LAN
```

`init` pushes this checkout to the server; it does not clone, so the repo can stay private
and the box needs no credential of its own. It is idempotent — re-run it after a failure
rather than fixing the server by hand. The one step that can lock you out, enabling the
firewall, runs behind a timer that switches ufw back off unless a **fresh** SSH connection
succeeds first.

## Day to day

Everything runs from your machine; `./vpn` forwards to the server over SSH.

```bash
./vpn status
./vpn user add|rm|enable|disable|list <name>
./vpn user export <name> [--protocol vless-reality|hysteria2|ikev2] [--qr]
./vpn protocol list
./vpn protocol off ikev2      # keeps the keys; turning it back on restores every profile
./vpn deploy                  # sync code, validate, converge
./vpn smoke                   # assert it is actually serving
./vpn backup > vpn-$(date +%F).age
./vpn restore vpn-2026-09-06.age   # onto a rebuilt box
./vpn logs [service]
```

The backup covers `/etc/vpn-stack` **and** the IKEv2 volume, which holds the CA private key —
without it every certificate this server issued is unrecoverable. `age -p` encrypts on your
machine, so the passphrase never reaches the server. Restoring brings back the same keys, so
profiles already on people's phones keep working.

Point it at a server with `.vpn-host` (gitignored) or `VPN_HOST=`; the SSH key with `VPN_SSH_KEY=`.

## Changing code

Edit, commit, push — CI runs `scripts/deploy.sh`, the same script `./vpn deploy` runs, so the
manual and automated paths cannot diverge. Secrets live in `/etc/vpn-stack` on the server and are
never in this repo, so a deploy cannot overwrite them.

`vpnctl` refuses to touch live state from anywhere that is not the server. For local work,
`VPN_STATE_DIR=<dir>` points it at a scratch directory, where it renders and validates but
does not start containers or touch the firewall.

## Diagnostics

```bash
./vpn smoke
./vpn logs sing-box
./vpn ikev2 list-clients
sudo bash scripts/diagnose-ikev2.sh listen      # on the server
bash scripts/diagnose-ikev2.sh probe <ip>       # from a different network
```

## More

`CLAUDE.md` — architecture, the protocol registry, the apply pipeline, and the things that were
learned the hard way. `dnstt/SETUP.md` — building the DNS tunnel from scratch.
