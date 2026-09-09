# vpn-stack

A personal VPN server and the CLI that operates it. Four protocols, one user database, one
command surface: `user add alice` issues credentials for every protocol at once, `user rm alice`
takes all of them away.

The organising idea is that the server holds all the state and the laptop holds none. `./vpn`
is a stateless SSH wrapper; the keys, the user database and every decision live on the box, in
a directory outside the checkout. That is what makes the checkout disposable and the server
reproducible from a single encrypted backup.

## The four protocols

Each is one module under `vpnctl/protocols/`, and each owns its own ports, secrets, config
rendering and share-link format. Adding a fifth is a new module plus one line in `PROTOCOLS`;
it changes no command line.

- **VLESS+REALITY**, `10443/tcp`, via `sing-box` — the everyday path. From outside, that port
  presents the genuine EV certificate of `www.apple.com`: there is no certificate of your own
  to fingerprint and nothing to distinguish the port from a TLS site you did not set up.
- **Hysteria2**, `20443/udp`, via `sing-box` — QUIC, for lossy or heavily shaped networks where
  a TCP tunnel collapses to nothing. The datagrams carry salamander obfuscation, and the
  certificate is self-signed and pinned by SHA-256 in the share link, so the client checks that
  exact key rather than a CA.
- **IKEv2 / L2TP / Cisco IPsec**, `500`, `4500`, `1701` udp, via `hwdsl2/ipsec-vpn-server` —
  for devices that should not need an app: iOS, macOS and Windows import a profile and dial it
  from the operating system's own VPN settings. Certificates are per user, and reconciled
  against the enabled user list on every apply rather than remembered.
- **dnstt**, `53/udp`, off by default — the last resort, for a network that permits DNS and
  nothing else. It ships disabled because it needs a DNS zone delegated to the server
  (`tun.example.net NS ns-tun.example.net`, `ns-tun.example.net A <server>`), which a fresh box
  does not have, and binding udp/53 without one is pure attack surface. One shared tunnel, a
  login per person: the Noise key encrypts the transport before anyone authenticates, so it
  cannot be personal, but the sshd behind it can — which is what makes `user rm` and
  `user disable` cut dnstt access at all.

## Where things run

**`./vpn` on your machine. `vpnctl` on the server. Never the reverse.**

`./vpn` is a bash wrapper at the repo root with no config file, no cache and no secrets.
Anything it does not recognise is forwarded verbatim over SSH to `vpnctl`, under
`flock /run/vpn-stack.lock` — which is the entire multi-operator story: two people running
`./vpn` at the same time serialise instead of interleaving writes to `users.json`. The server
is the only place that touches Docker, iptables, ufw and the user database.

`vpnctl` refuses to mutate anything from a machine that is not the server. That guard is not
tidiness: before it existed, `vpnctl user add` on a laptop did not fail — it *succeeded*,
rewriting a local copy of live credentials and starting a real sing-box bound to the laptop's
ports. For local work, `VPN_STATE_DIR=<dir>` points it at a scratch directory, where it renders
and validates but does not start containers or touch the firewall.

## From a bare VPS

Ubuntu 22.04 or 24.04, root SSH access, nothing else.

```bash
git clone <this repo> && cd vpn-stack
./vpn init root@203.0.113.10   # docker, state dir, sysctls, firewall, keys, boot unit
./vpn user add alice
./vpn user export alice --qr   # QR in your terminal; point the phone at the screen
./vpn share alice              # or a one-shot page for a phone on your LAN
```

`init` is idempotent — re-run it after a failure rather than repairing the server by hand. The
one step that can lock you out, enabling the firewall, runs behind a detached timer that
switches ufw back off after 180 seconds unless a **fresh** SSH connection, one that had to pass
through the new rules, succeeds first.

It pushes this checkout to the server; it does not clone. So the box needs no git credential of
its own, and what runs there is exactly the tree in front of you, uncommitted edits included.
`scripts/push.sh` is the only thing in this repo that transfers code, and both install and
deploy call it.

Docker comes from Docker's own apt repository — same packages as the convenience script, but
signed, upgradable with the rest of the system, and readable before it runs. Anything already
installed (docker, git, rsync, ufw, iptables, uv) is detected and left alone, out loud.

Point `./vpn` at a server with `.vpn-host` (gitignored, written by `init`) or `VPN_HOST=`; the
SSH key with `VPN_SSH_KEY=`.

## Day to day

```bash
./vpn status
./vpn user add|rm|enable|disable <name>
./vpn user list [--show-secrets]
./vpn user export <name> [--protocol vless-reality|hysteria2|ikev2|dnstt] [--qr]
./vpn protocol list
./vpn protocol on dnstt
./vpn protocol off ikev2      # keeps the keys; turning it back on restores every profile
./vpn deploy                  # sync code, validate, converge
./vpn smoke                   # assert it is actually serving
./vpn logs [service]
```

`user export` gives back whatever each protocol actually has: a URI for the two sing-box
protocols (so a QR code and a tappable link), downloadable bundles for IKEv2 (`.mobileconfig`,
`.sswan`, `.p12`), and plain fields to copy for dnstt, which has no import format at all.
Every command takes `--json`, in any position, and that output is a public interface: the
payload goes to stdout and everything else to stderr.

`./vpn share <name>` serves those credentials from *your* machine to one device on your local
network: the page opens once, and the listener dies two minutes after that first fetch or ten
minutes after it started, whichever comes first. The VPN server never gains a listener and
never learns who you handed the credentials to, and the wrapper refuses to bind an address that
is not private. The transport is plain HTTP on the LAN, which is a bounded trade and documented
as one at the top of `scripts/share.py`.

## Backup and restore

```bash
./vpn backup > ~/vpn-backups/vpn-$(date +%F).age   # outside the checkout, never in it
./vpn restore ~/vpn-backups/vpn-2026-09-06.age     # onto a rebuilt box
```

The backup covers `/etc/vpn-stack` **and** the IKEv2 Docker volume, which holds the CA private
key — without it every certificate this server issued is unrecoverable. `age -p` encrypts on
your machine, so the passphrase never reaches the server and the plaintext never lands on
either disk. Restoring brings back the same keys, so profiles already on people's phones keep
working. `restore` refuses to run against a server that already has users unless you pass
`--force`.

**Write it outside the checkout.** One `.age` did land in a commit, and the earlier version of
this line — `./vpn backup > vpn-$(date +%F).age`, run from the repo root — is how. That tar is
every secret, every user's password across every protocol, and the CA private key, under a
single passphrase; in a commit it is offline-attackable forever, and no later `.gitignore` rule
removes it from history. `*.age` is ignored now, but the path above is the actual fix.

## Where the secrets are

`/etc/vpn-stack` on the server, mode 0700 and root-owned: `secrets/` (one file per key, 0600),
`users.json`, `state.json`, `.env`, sing-box's runtime `data/`, and a `rendered` symlink to the
current generated config. Nothing in that directory lives in the repository, which is what makes
a deploy safe to run repeatedly against a live box: the rsync uses `--filter=':- .gitignore'`,
so it cannot push a developer's local `users.json` over the server's, and deliberately *not*
`--delete-excluded`, which would delete from the server the very files that filter protects.

That is a property of ordinary operation, not a guarantee about the repository. A secret put
into the tree by hand is in the tree — see the backup warning above, which is exactly that
happening.

## Changing code

Edit, then `./vpn deploy` — one deliberate command, from a checkout, aimed at a host you named.

CI (`.github/workflows/ci.yml`) runs on every push and pull request and checks only the code:
`ruff check`, `ruff format --check`, the pytest suite, and `bash -n` on every shell script in
the tree — found by shebang rather than from a list, because a list goes stale silently and
half this repo is bash that nothing exercises until a server runs it. The suite needs no
server, no Docker and no root; anything that would belongs in `scripts/smoke.sh`, which runs
against a real box on purpose.

**The invariant is not "no CI" — it is that CI cannot reach a server.** That workflow has no
`secrets:`, no `environment:`, no ssh, no rsync and no deploy step, and states
`permissions: contents: read` rather than inheriting whatever a settings page says. There is
nothing for it to deploy *with*. The pipeline it replaced did deploy, on every push to `main`,
and the cost was a standing key with root on the VPN server held by GitHub plus a live box
mutated because somebody committed rather than because anybody asked — which is how
`/opt/vpn-stack` reappeared on a server that had just been deliberately wiped. If a change to
that file seems to need a secret, the thing you want is a laptop.

`vpnctl apply` is the only thing that changes the server, and it never edits the live config in
place. It renders the whole configuration into `rendered-<ts>/` *beside* the live tree,
validates that candidate in a throwaway container, and only on success flips the `rendered`
symlink with `os.replace`. A failed apply deletes the candidate and exits — the live tree was
never touched, so there is nothing to roll back. Then it converges: bring up what is enabled,
explicitly remove what is not, wait for every expected port to be bound on a non-loopback
address, reconcile ufw, reconcile IKEv2 certificates.

Deploy *updates* a server; it does not set one up, and it checks for `vpnctl`, `/etc/vpn-stack`
and `uv` before it transfers anything, so a rebuilt box fails with that list rather than
halfway through.

## Diagnostics

```bash
./vpn smoke
./vpn logs sing-box
./vpn ikev2 list-clients
bash scripts/diagnose-ikev2.sh probe <ip>       # from the FAILING client's network
bash scripts/diagnose-ikev2.sh path <ip>        # where does IKE die but junk survive?
sudo bash scripts/diagnose-ikev2.sh listen      # on the server
```

`diagnose-ikev2.sh` exists because IKEv2 clients can fail for a reason that is not on the
server at all: a middlebox on the client's own network dropping UDP whose payload parses as an
ISAKMP header. `probe` therefore sends a real `IKE_SA_INIT` alongside a separately marked junk
datagram, and `listen` reports which shape arrived — an earlier version sent only junk, which
any such filter passes, and would have reported "not blocked" in exactly the case it exists to
detect. `path` localises the drop with a low TTL, so the packet expires inside the network
under suspicion and cannot have reached the destination.

## Status

This is one person's personal VPN server plus the CLI that runs it, published because the
design — the pure protocol registry, the candidate-tree apply, the guards, and the failures
recorded in `CLAUDE.md` that motivated each of them — seemed worth reading. It is not a
product. There is no roadmap, no support commitment, and no undertaking to keep any interface
stable. Run it against a box you are prepared to rebuild.

## Licence

AGPL-3.0. See `LICENSE`.

## More

`CLAUDE.md` — the architecture in full: the protocol registry, the apply pipeline, and the
things learned the hard way, each with the failure that taught it. `dnstt/SETUP.md` — building
the DNS tunnel from scratch, zone delegation included.
