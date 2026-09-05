# vpn-stack

Personal VPN server: `sing-box` (VLESS+REALITY, Hysteria2) + IKEv2/L2TP/Cisco IPsec (`hwdsl2/ipsec-vpn-server`), managed by `vpnctl`; plus `dnstt` (DNS-tunnel last-resort bypass, see `CLAUDE.md`).

Deployed on `vpn-stack` (`ssh vpn-stack`, alias for `203.0.113.10`), repo lives there at `/root/vpn-stack`. Push to `main` deploys via GitHub Actions.

## Users

Run on the server — `users.json` and all live credentials live there, not in git.

```bash
ssh vpn-stack
cd /root/vpn-stack

uv run vpnctl user add <name>              # generate credentials for every protocol
uv run vpnctl user rm <name>               # delete for good
uv run vpnctl user enable <name>           # re-enable (re-issues IKEv2 cert)
uv run vpnctl user disable <name>          # disable without deleting
uv run vpnctl user list [--show-secrets]
uv run vpnctl user export <name> [--protocol vless|hysteria2|ikev2|all] [--qr] [--png]
```

`--protocol all` (default) tries vless + hysteria2 + ikev2; ikev2 is skipped with a note if not provisioned. `--qr` prints an ASCII QR in the terminal, `--png` also saves one under `exports/`.

## Diagnostics

```bash
docker compose ps
docker compose logs -f sing-box
docker compose logs -f ikev2
uv run vpnctl ikev2 list-clients
```

## Changing code/config

Edit locally, commit, push:

```bash
git add -A && git commit -m "..." && git push
```

CI syncs the repo to the server, runs `sing-box check`, and restarts containers. It never touches `users.json` or any gitignored secret — those exist only on the server.

CI recreates only `sing-box` and `ikev2`. The `dnstt`/`dnstt-socks` services are outside that list — after changing their build/config, bring them up by hand:

```bash
ssh vpn-stack "cd /root/vpn-stack && docker compose up -d --build dnstt dnstt-socks"
```

Manual deploy, bypassing CI:

```bash
rsync -az --exclude '.git/' --exclude '.github/' ./ vpn-stack:/root/vpn-stack/
ssh vpn-stack "cd /root/vpn-stack && docker compose up -d --force-recreate sing-box ikev2"
```

## More

See `CLAUDE.md` for architecture, the secrets/gitignore layout, and known trade-offs.
