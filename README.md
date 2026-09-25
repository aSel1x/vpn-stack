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
  certificate is self-signed, so a client pins it instead of trusting a CA — and the link carries
  *two* pins, because one was not enough. `pinSHA256` is hysteria2's own convention and hashes the
  whole DER certificate; sing-box's only pinning field hashes the public key and encodes that
  base64. Different preimage, different encoding, not convertible, so a client built on sing-box
  could do nothing with the pin this server published for years and its two options were to fail
  the handshake or to trust any certificate at all. `spki` is the second pin. New keyrings also
  give that certificate a subjectAltName and `basicConstraints`, which it had no extensions to
  carry before.
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
`./vpn` at the same time serialise instead of interleaving writes to `users.json`. `vpnctl` claims
that lock itself for every mutating command as well, without blocking, so a caller that arrives
without a wrapper is refused instead of racing; the wrappers export `VPN_STACK_LOCK_HELD=1` to say
they already hold it, because `flock(1)` inside `flock(1)` on the same path from a child process
opens a second file description and waits for ever — measured, not assumed. The server is the only
place that touches Docker, iptables, ufw and the user database.

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
through the new rules, succeeds first. The rule it opens is for the port the installer actually
reached sshd on: that was hardcoded as 22, so against an sshd on 2222 `init` could never complete
— ufw came up with only 22 open, the fresh-connection proof failed, the deadman restored access
three minutes later, and the identical re-run failed identically with nothing in the output
mentioning the port. Arming the timer also reaps or refuses an earlier one, because a re-run after
a transient failure orphaned the first, which could then disable ufw after the installer had
printed success.

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

A command that produced nothing exits non-zero, and that is a deliberate correction rather than
strictness. `user export` used to report `ok` with an empty payload when every protocol it was
asked about had nothing to give — a receipt with no credential in it, which reads as "done" — so
it now fails and names each reason separately, because "no certificate provisioned" and "the
export failed" need different fixes. `ikev2 list-clients` exits 1 when the listing itself fails,
since the listing *is* the whole answer and a caller trusting exit 0 reads a failed query as an
empty client list. `bootstrap` exits 1 when it refuses a half-present key set, which is the one
outcome that demands a decision and used to be a prefix inside a success message.

`./vpn share <name>` serves those credentials from *your* machine to one device on your local
network: the page opens once, and the listener dies two minutes after that first fetch or ten
minutes after it started, whichever comes first. The VPN server never gains a listener and
never learns who you handed the credentials to, and the wrapper refuses to bind an address that
is not private. The transport is plain HTTP on the LAN, which is a bounded trade and documented
as one at the top of `scripts/share.py`.

## Backup and restore

```bash
./vpn backup ~/vpn-backups/vpn-$(date +%F).age   # outside the checkout, never in it
./vpn restore ~/vpn-backups/vpn-2026-09-06.age   # onto a rebuilt box
```

**Pass the path; do not redirect into it.** With a path, `backup` writes `<path>.partial` and
renames it only once `age` has exited 0, deleting the partial otherwise — so a run that dies half
way leaves the last good backup exactly as it was. `./vpn backup > f.age` cannot do that and never
will: the redirect is the *shell* truncating `f.age` before ssh has said a word, so a backup that
fails half way has already destroyed the one it was replacing, and the occasion you find out is a
rebuilt box. With no path it still streams to stdout, which is the form to pipe somewhere else.

The backup covers `/etc/vpn-stack` **and** both Docker volumes in `compose.yml`, from one list
that `backup` and `restore` share. `ikev2-vpn-data` holds `cert9.db`/`key4.db`, the NSS database
with the IKEv2 CA private key — without it every certificate this server issued is unrecoverable.
`dnstt-sshd-keys` holds the dnstt SSH front's host key, which exists precisely so clients do not
warn about a changed server: leave it out and a restore onto a rebuilt box reintroduces exactly
that warning, indistinguishable from an attack, for the protocol whose users have no fallback.
`restore` treats a member an older backup does not carry as absent rather than as an error.

`age` encrypts on your machine to the identity `./vpn backup-key` made, so the key never reaches
the server and the plaintext never touches this machine's disk. On the server it exists for the
length of the transfer — tar cannot write a member's header without knowing its size — but only
inside a 0700 `mktemp -d` that a trap removes on exit, on a broken pipe and on a dropped
connection alike. Those two intermediate tars used to be built with plain shell redirection at
root's umask, mode 0644 in a world-traversable directory, and removed only if everything
succeeded: break the pipe and every user's password on every protocol, the REALITY private key and
the CA private key persisted in `/tmp` at a predictable path, three lines below a comment claiming
the plaintext never lands on either disk.

Restoring brings back the same keys, so profiles already on people's phones keep working.
`restore` refuses to run against a server that already has users unless you pass `--force`.

**Write it outside the checkout.** One `.age` did land in a commit, and the earlier version of
this line — `./vpn backup > vpn-$(date +%F).age`, run from the repo root — is how. That tar is
every secret, every user's password across every protocol, and the CA private key, under the one
passphrase backups were encrypted with at the time; in a commit it is offline-attackable forever,
and no `.gitignore` rule removes a blob from history — that took a `git filter-repo`, and the
commit no longer resolves. `*.age`, `*.p12`, `*.mobileconfig` and `*.sswan` are ignored
extension-wide now, because a filename-exact rule would not have caught this one. The path above
is the actual fix.

## Where the secrets are

`/etc/vpn-stack` on the server, mode 0700 and root-owned: `secrets/` (one file per key, 0600),
`users.json`, `state.json`, `.env`, sing-box's runtime `data/`, and a `rendered` symlink to the
current generated config. Nothing in that directory lives in the repository, which is what makes
a deploy safe to run repeatedly against a live box: the rsync uses `--filter=':- .gitignore'`,
so it cannot push a developer's local `users.json` over the server's. It pairs that filter with
`--delete`, so a file deleted from the repo stops living on every server ever pushed to, and
deliberately *not* `--delete-excluded`, which means something opposite — it would delete from the
server the very files the filter exists to protect, `/opt/vpn-stack/.env` among them. It also
passes `--chown=root:root`, because `-a` preserves the operator's uid and this lands a tree root
executes: from a laptop whose user is 1000, `/opt/vpn-stack` came out owned by uid 1000, which on
the server is some other account that can then rewrite the code `vpnctl` runs as root. `app/` and
`notes/` are excluded by path rather than left to `.gitignore`, since the client is tracked and a
VPN server has no use for it.

That is a property of ordinary operation, not a guarantee about the repository. A secret put
into the tree by hand is in the tree — see the backup warning above, which is exactly that
happening.

## The client

`app/` is a Flutter client for somebody who has none of what `./vpn` needs — no laptop, no shell,
no SSH key. It implements no part of the server and does three things. It provisions a bare VPS
over SSH, running the same `scripts/provision-host.sh` the installer runs rather than a second
copy of that shell in Dart, from a clone of this repository at a tag: an app-provisioned box then
executes a tree somebody reviewed instead of whatever is on a branch at that instant. It drives
`vpnctl` over SSH and parses `--json`, every call under `flock /run/vpn-stack.lock`, because a
phone is exactly the second operator that lock exists for. And on Android and iOS it carries the
tunnel itself — `VpnService` plus libbox on one, an `NEPacketTunnelProvider` plus
`Libbox.xcframework` on the other, one Dart controller above both. The desktop builds have no
tunnel: a TUN device needs privilege on every desktop platform and the helper is unwritten, so
they are a remote control for the server and nothing more.

It is built only in CI, by `.github/workflows/app.yml`, which produces five artifacts: an APK, an
unsigned `.ipa`, a `ditto` archive of the macOS `.app`, the Windows x64 `Release` directory, and a
Linux `.deb`. `scripts/push.sh` excludes `app/` by path, so none of it is ever sent to a VPN
server.

Two things not to be misled about. **Nothing is signed**, and that is the intended end state and
not a TODO: the APK carries Flutter's debug key, the `.ipa` is built `--no-codesign` and installs
on no device until somebody with a paid Apple membership signs it — and App Store Review Guideline
5.4 admits VPN apps only from developers enrolled as an *organization* — while Gatekeeper and
SmartScreen will both complain about the desktop artifacts. **No packet has crossed the native
layer in anything this repository can show you.** CI compiles and links the Kotlin and the Swift
against a real libbox, built from the sing-box version `compose.yml` pins so that one number
governs the engine at both ends of a configuration; it runs neither. There is no device, no
emulator and no simulator in that pipeline, and the iOS extension in particular has never been
signed, launched, or handed a utun descriptor. What *is* tested is the Dart — 288 tests under
`app/` and 38 in the tunnel package — and the `--json` contract itself, through a fixture corpus
generated from `cli.py` that both suites read. `app/README.md` is the client's own document, and
`app/docs/ios-release.md` is what the iOS path costs.

## Changing code

Edit, then `./vpn deploy` — one deliberate command, from a checkout, aimed at a host you named.

There are two workflows. `.github/workflows/ci.yml` runs on every push and every pull request and
checks only the code, in three jobs: `python` is `ruff check`, `ruff format --check` and the
491-test pytest suite; `shell` is `bash -n` over the 13 shell files in the tree; and `dart` runs
the analyzer and **both** of the client's Dart suites, with no path filter, so a commit that
renames a key in `vpnctl/cli.py` runs them in the same run as the Python tests. The Python suite
needs no server, no Docker and no root; anything that would belongs in `scripts/smoke.sh`, which
runs against a real box on purpose.

The shell finder takes two rules rather than a list, because a list goes stale silently and half
this repo is bash that nothing exercises until a server runs it — every `*.sh` by name, plus
anything whose first line is an `sh` shebang. Either rule alone misses one kind: by shebang only
skips `app/tool/ios_identifiers.sh`, which is sourced and deliberately has none, so the job whose
name promises every shell script never parsed the single definition of the App Group identifier;
by name only skips `vpn` and `deploy`, the two scripts a person actually types. A finder that
matches nothing fails rather than passes, and pytest's exit 5 for "collected nothing" stays a
failure too: a green check that ran no checks is the shape of the wrong-subnet health checks this
repo has already been bitten by.

`.github/workflows/app.yml` is the other one — eleven jobs that build the client and the sing-box
library it links, triggered on `app/**`, on itself, and on `compose.yml`, since bumping the
server's engine must rebuild the client's. It is `app/README.md`'s subject; what matters here is
the property it shares with `ci.yml`.

**The invariant is not "no CI" — it is that CI cannot reach a server.** Neither workflow has
`secrets:`, `environment:`, ssh, rsync or a deploy step, and both state
`permissions: contents: read` rather than inheriting whatever a settings page says. There is
nothing for them to deploy *with*. The pipeline they replaced did deploy, on every push to `main`,
and the cost was a standing key with root on the VPN server held by GitHub plus a live box
mutated because somebody committed rather than because anybody asked — which is how
`/opt/vpn-stack` reappeared on a server that had just been deliberately wiped. If a change to
either file seems to need a secret, the thing you want is a laptop. One loose end neither file can
close: `DEPLOY_HOST` and `DEPLOY_SSH_KEY` outlived the workflow that read them, nothing in this
tree names them, and no workflow can delete a repository secret — that is a settings-page job.

Every `uses:` in both files is pinned to a commit SHA with its tag in a trailing comment. A major
tag is a mutable pointer, and whoever can move it decides what runs on a runner that holds a
checkout of this tree and builds the clients this project hands to humans; the cost is that a SHA
cannot tell you it is stale, which is what `.github/dependabot.yml` is for. Lockfiles are enforced
rather than trusted — `uv sync --frozen` and `flutter pub get --enforce-lockfile` — because a
plain `pub get` resolves whatever satisfies `pubspec.yaml` today, rewrites the lock, and says
nothing, which is the incident the lock was committed for.

`vpnctl apply` is the only thing that changes the server, and it never edits the live config in
place. It renders the whole configuration into `rendered-<stamp>-<rand>/` *beside* the live tree,
validates that candidate in a throwaway container, and only on success flips the `rendered`
symlink with `os.replace`. The random half of that name is not decoration: the stamp is at
one-second resolution and the renderer used to delete whatever already held the name, so two
applies inside one second — a scripted `user add`, or a deploy racing the boot unit — had the
second delete the tree the first had just promoted and the containers were mounted from. A failed
apply deletes the candidate and exits — the live tree was never touched, so there is nothing to
roll back. Then it converges: bring up what is enabled, explicitly remove what is not, wait for
every expected port to be bound on a non-loopback address, ask Docker which expected services are
*not running* — a bound port is not health, and dnstt-server holds 53/udp while the sshd behind it
crash-loops on loopback — reconcile ufw, reconcile IKEv2 certificates.

Converge bounces only the services whose rendered files changed, so adding one person no longer
drops every live session on the box. That diff compares two directories and can never compare a
directory against a running container, so a tree that was promoted without converging has to leave
a mark that outlives the command: `state.json` carries `converge_pending` from the moment the
symlink swaps until a converge reports every step. Without it, `bootstrap --force` or any failure
between the swap and the end of converge left the next apply diffing a byte-identical tree,
bouncing nothing, passing the readiness wait because the *old* containers still held the ports,
and printing "OK." over a sing-box still serving the previous keys.

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

`./vpn smoke` answers "is it serving?", not "did the command exit 0?". Every check is named, the
names are a public interface, and each one corresponds to a failure this server has had: the
enabled protocols are enumerated from `vpnctl --json protocol list` rather than a literal list (so
a crash-looping dnstt-sshd cannot pass a page that only ever checked `sing-box`), a port counts as
served only when something holds it on a non-loopback address, dnstt's two back ends must be on
loopback and nothing else, and `dnstt-server`'s own argv in the running container must name the
zone it answers for. That last one was found on this stack's own server with every other check
green: `${VPN_DNSTT_ZONE}` is interpolated bare, so on a box whose `.env` never gained the
variable a recreated container starts with no zone at all — it binds 53/udp, `docker ps` says
running, and it answers for nothing any client can resolve. The argv is parsed rather than
indexed, because a dropped zone makes it one element shorter and `cmd[-2]` then reads
`/keys/server.key`, which has a dot in it and passes any domain-shaped test.

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
the DNS tunnel from scratch, zone delegation included. `app/README.md` — the client: its layers,
the `--json` contract it is held to, and what it deliberately refuses to reimplement.

Two measurements are written up on their own, because they are the parts most likely to be
useful to somebody who never runs this code:

- `docs/ike-filter-measurement.md` — why IKEv2 clients on one access network cannot reach this
  server, localised with a TTL ceiling so the probes cannot have reached the destination, and
  why the obvious test (a junk datagram on udp/500) would have returned the same answer against
  a provider that really was blocking.
- `docs/dnstt-per-user-revocation.md` — running a DNS tunnel where access is revocable per
  person, given that the tunnel's own key belongs to the server and cannot be, and why the
  container behind it has to be recreated rather than restarted for a revocation to mean
  anything.
