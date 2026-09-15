# The app

A cross-platform client that provisions a server and connects to it. Android, iOS, macOS,
Windows, Linux, one Dart codebase.

It exists for one reason: the CLI in this repository needs a laptop, a shell, an SSH key and
`./vpn`. Somebody who just wants a working tunnel has none of those.

## What it is not

It is not a second implementation of the server. The server keeps every decision it already
owns — which ports, which secrets, how config is rendered, how a share link is built. The app
asks it questions and renders answers.

That line is load-bearing. `render` and `share` in `vpnctl/protocols/` are pure functions, and
the temptation is to port them to Dart so the app can work offline. Don't: two implementations
of a credential format drift, and the drift is invisible until somebody's profile stops
importing. The app talks to `vpnctl` over SSH and parses `--json`, which this repository already
declares a public API — payload on stdout, everything else on stderr, accepted in any argument
position.

## Why it lives in this repository

The app↔`vpnctl --json` contract is the load-bearing interface, and a separate repository would
let one side ship a change the other has not seen. This tree has been bitten by exactly that
twice: `apply` returning `enabled` where the caller wanted `enabled_protocols`, and a stale
checkout rsynced over a `users.json` that had grown a field.

**What CI gives today.** `.github/workflows/ci.yml` runs `flutter analyze` and `flutter test`
on every push and every pull request, with no path filter, beside the Python lint and tests —
so a commit that touches only `vpnctl/` does run the Dart suite, in the same run, and both
halves go green or red together. The five artifact builds in `.github/workflows/app.yml` stay
filtered on `app/**`, because a server-side one-liner should not spend two macOS runners.
That filter used to be the *only* Dart trigger, which meant the contract tests never ran
against the side that breaks them.

**What CI does not give, and what this file used to claim it did.** It said a breaking change
to `--json` "cannot land without the app's tests failing in the same CI run". That is false,
and fixing the trigger does not make it true. The fixtures in `app/test/` are hand-copied from
what `vpnctl/cli.py` emits, and nothing compares the two. Rename `enabled_protocols` to
`enabled` in `cli.py` and the Dart suite stays green: `app/test/control_fakes.dart` still says
`enabled_protocols`, `lib/control/models.dart` still reads `enabled_protocols`, and the two
agree with each other about a payload the server no longer sends. The tests prove the parser
handles the payload the fixtures describe. They do not prove the fixtures describe `vpnctl`.
Until that gap is closed, what one repository buys is one review and one CI run over both
sides — a human noticing, not a machine.

**The missing piece, and where it would live.** Either of these closes it; neither is
implemented, and both live outside `app/lib/`.

- *A golden corpus both sides read.* A Python test in `tests/` invokes each `--json` command
  and writes its payload to, say, `tests/golden/json/<command>.json`, failing if the file on
  disk differs (the usual golden shape: regenerate deliberately, review the diff). The Dart
  tests then load those files instead of the inline strings in `app/test/control_fakes.dart` —
  `flutter test` runs on the Dart VM, with `dart:io` and the package root as its working
  directory, so `../tests/golden/json/apply.json` resolves. A rename changes the golden in the
  same commit, and the Dart parse fails on it. Strongest, and it costs the fixtures their
  readability at the point of use.
- *A key-set diff in Python.* A test such as `tests/test_json_contract.py` runs
  `vpnctl --json <command>` under the `VPN_STATE_DIR` that `tests/conftest.py` already points
  at a seeded temp directory, and compares each payload's top-level key set against the set the
  app declares it reads — `ApplyResult.keys` and its siblings in `lib/control/models.dart`,
  exported to a small checked-in file both sides read rather than scraped out of Dart source
  with a regex, which would go stale silently. Cheaper, and it asserts key *names* only, not
  value shapes.

  One honest caveat for whoever writes it: under a pointed `VPN_STATE_DIR`, `apply` renders and
  validates but does not converge, so its payload is legitimately a subset — everything from
  `teardown` down is absent, exactly as `ApplyResult.keys` documents. The assertion is
  "every emitted key is a declared one, and the unconditional keys are all present",
  not set equality, or the test fails for the wrong reason on day one.

Whichever lands, it runs in `ci.yml` — the `python` job for the diff, the `dart` job for the
golden — which is why that workflow installs Flutter at all.

## The layers

```
lib/control/     talk to vpnctl; every call goes through --json
lib/provision/   bring a bare VPS up to serving, over SSH
lib/transport/   the SSH implementation, dartssh2, behind an interface
lib/config/      turn a share URI into a sing-box client configuration
lib/tunnel/      establish the tunnel on THIS device
lib/ui/
```

Everything except `transport` and `tunnel` is pure Dart, unit-tested with no server and no
network: `control` and `provision` build command lines and parse JSON with the SSH session
injected, and `config` is a parser and a builder. `tunnel` is the only layer that needs platform
code, and it is where the remaining work is.

`config` is the one layer that might look like the duplication this file forbids, and it is not.
The rule is against a second *producer* of a credential format: if the app minted a VLESS URI it
would choose the port, the SNI and the fingerprint independently of the server and the two would
drift. It consumes one. Nobody else can do the job either — sing-box's core has no URI import,
every GUI client writes this itself — and the sing-box schema version belongs to the client's
engine, not to the server's.

### The host key

Nothing can open an SSH connection without deciding about the server's key. `lib/ui/access.dart`
is the only thing that pairs a connector with a policy, its constructor is private, and both
screens that reach a connection go through one helper. An unknown key is shown to the person —
algorithm and `SHA256:` fingerprint — and trusted only on their word; a key that has *changed*
is refused outright, with no accept-anyway button, because a changed host key on the box holding
your VPN credentials is the one case where one tap is too few. The pin lives in the server
record, which is why the secure store carries a schema version and refuses a record written by a
newer one by name.

The check runs during the key exchange, before any credential exists on the wire. That is a
property of dartssh2 and it was read out of its source rather than assumed: `onVerifyHostKey` is
called from `_handleMessageKexReply` before `_sendNewKeys()`, and a false answer closes the
connection there.

## Every vpnctl call takes /run/vpn-stack.lock

`./vpn` never runs `vpnctl` bare. Every command it forwards is

    ssh <host> "cd /opt/vpn-stack && flock /run/vpn-stack.lock /usr/local/bin/vpnctl <args>"

and CLAUDE.md calls that lock "the entire multi-operator story": there is no other
serialisation anywhere on the server. `users.json` and `state.json` are written through a temp
file and `os.replace`d, so no reader ever sees half a file — but two writers that
read-modify-write the same database still lose one of the two writes, and two `apply` runs
interleaved render candidate trees and promote each other's half.

**The app is the second operator.** A phone talking to `vpnctl` without the lock is precisely
the case the lock exists for: somebody on a laptop running `./vpn user add` while the app is
mid-`apply`. So `lib/control/vpnctl.dart` puts it in front of every invocation, mutating or not
— `user export` shells into the ikev2 container and deletes bundles afterwards, so
"read-only command" is not a distinction worth encoding:

    flock -w <seconds> -E 75 /run/vpn-stack.lock /usr/local/bin/vpnctl --json <command>

Two differences from `./vpn`, both deliberate. It waits with a bound where `./vpn` blocks for
ever, because a phone sitting there with nothing on screen is indistinguishable from a crash.
And `-E 75` (EX_TEMPFAIL) makes "somebody else is mid-apply" distinguishable from every exit
`vpnctl` itself produces — 1 for a refusal, 2 for argparse or the not-the-server guard, 127 for
a missing binary — so a screen that polls `status` during an apply can render *busy* instead of
*failed*.

Any future client inherits this. A call that skips the lock is a bug even on the run where it
works.

## Provisioning, and the one step that cannot move to the server

The repository became public, so a server can `git clone` it with no credential. That removes
the reason `install.sh` had to push the tree from the operator's machine, and the app does not
have to ship the tree as an asset.

What does **not** move is the firewall step. `scripts/install.sh` arms a detached deadman that
disables ufw unconditionally after a timeout, enables the firewall, then opens a **brand-new SSH
connection** — new TCP handshake, evaluated by the rules just installed — and only disarms the
deadman if that connection succeeds. A script running on the box cannot do this: it cannot prove
from inside one connection that a *different* connection would survive rules it is about to
install. The prover has to be somewhere else.

So the split is:

- server-local, one SSH command: docker, state directory, sysctls, uv, `/dev/ppp`, the boot
  unit, `bootstrap`, `apply`;
- client-side, in the app: arm the deadman, enable ufw, open a fresh connection, disarm on
  success — and on failure say nothing and let the deadman fire.

`install.sh` remains the single definition of the laptop path. The app and the script share the
server-local half; neither reimplements the other's orchestration.

## Connecting

The engine is `sing-box`, because the server runs `sing-box` and `share()` already emits URIs it
imports. Nothing here invents a config format.

| platform | how the tunnel is established |
| --- | --- |
| Android | `VpnService` + `libbox` (gomobile `.aar`) |
| iOS | `NEPacketTunnelProvider` + `Libbox.xcframework` |
| macOS, Windows, Linux | `sing-box` with a TUN inbound, which needs privilege — a helper service, the way Amnezia does it |

Desktop privilege is the unsolved part, not a detail: a TUN device needs `CAP_NET_ADMIN` on
Linux, an elevated process plus wintun on Windows, and a privileged helper on macOS.

`libbox` is not published anywhere — sing-box's v1.14.0 release carries 167 assets and not one
`.aar` — so CI builds it from source with SagerNet's own pinned gomobile fork. The version comes
out of `compose.yml`, the same line that pins the server's image, so one number governs the
engine at both ends of a configuration. That job takes about nine minutes and is cached on the
version rather than rebuilt for every commit to a Dart file.

Platform code cannot live in `app/android/` or `app/ios/`: those directories are generated by
`flutter create` in CI and are gitignored, so anything written there would be deleted and
regenerated. It lives in a package under `app/packages/`, which is committed.

## What is gated by somebody else

- **iOS.** App Store Review Guideline 5.4 admits VPN apps only from developers enrolled as an
  *organization* — a real legal entity with a D-U-N-S number — and the guideline is applied at
  notarization, so alternative EU marketplaces do not route around it. Separately, a free Apple
  ID has neither Network Extensions nor Personal VPN, so even sideloading a build that actually
  tunnels needs the paid membership. CI can produce an **unsigned** `.ipa`; it installs nowhere
  until somebody signs it.
- **Google Play.** From 2026-09-30 an app that uses `VpnService` needs an Organization account.
  Direct APK distribution is unaffected, which is how this is expected to ship.
- macOS and Windows builds are unsigned too: Gatekeeper and SmartScreen will both complain.

None of this blocks Android or the desktop builds. It blocks the iOS *store* path, and it is
worth knowing before anybody spends a quarter on it.

## Building

Not on a developer's machine by default — in CI, because macOS and iOS artifacts cannot be
produced anywhere else and this repository is public, so the runners are free. The platform
directories (`android/`, `ios/`, `macos/`, `windows/`, `linux/`) are generated by
`flutter create` rather than committed: they are scaffolding, they are large, and a hand-edited
Xcode project is a file nobody can review.
