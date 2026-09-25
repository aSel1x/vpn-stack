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

**What CI gives.** `.github/workflows/ci.yml` runs `flutter analyze` and **both** Dart test suites
— `app/` and the `app/packages/singbox_tunnel` plugin — on every push and every pull request, with
no path filter, beside the Python lint and tests. So a commit that touches only `vpnctl/` does run
the Dart tests, in the same run, and both halves go green or red together. The five artifact
builds in `.github/workflows/app.yml` stay filtered on `app/**`, because a server-side one-liner
should not spend two macOS runners. That filter used to be the *only* Dart trigger, which meant
the contract tests never ran against the side that breaks them. The plugin needed a step of its
own because `flutter test` from `app/` collects `app/test/` and never descends into `packages/`:
38 tests over the state machine that decides when this app may say "Connected" were analysed on
every push and executed by nothing.

**The payload is the shared artifact, and it is generated.** This file used to promise that a
breaking `--json` change "cannot land without the app's tests failing in the same CI run", and
then that the promise was not kept: the Dart fixtures were hand-typed from what somebody
remembered `cli.py` printing, and nothing compared the two. Rename `enabled_protocols` to
`enabled` in `cli.py` and the Dart suite stayed green, because `control_fakes.dart` and
`lib/control/models.dart` agreed with each other about a payload the server no longer sent. Three
of those transcriptions were *already wrong*, and all three parsed: an export fixture carried
`failed: ["hysteria2"]`, where only a `share_via_container` protocol can ever land; the IKEv2
bundles were named `kate.p12` where the container writes `kate-ikev2.p12`, which is the suffix
`bundle_label` matches on; and the dnstt card had four fields where `share()` emits two cards, of
five fields and three. The tests were passing against a payload no server can send.

So the fixtures are no longer transcriptions. `tests/test_json_contract.py` calls cli.py's real
`cmd_*` functions under a seeded `VPN_STATE_DIR` and holds each payload to a file under
`app/test/fixtures/`, and the Dart tests read those same files. Neither side can move alone: the
`python` job fails when cli.py stops printing the committed bytes, and the `dart` job fails when a
regenerated file is one the app cannot parse. Regeneration is opt-in — `UPDATE_CONTRACT=1` —
because a test that rewrites its own expectation cannot fail, and that flag is the reviewer's
signal that the payload change is the point of the commit.

Three details that are the difference between a test and a decoration:

- - **It is deliberately not a regex over `models.dart`**, which is the cheap option this file
  used to sketch. A Dart parser written in Python is a second thing to get wrong, and it would
  pass on a model that compiles and refuses every real payload. Key *names* are not enough either:
  `spki` was added to `hysteria2.share()` and the Dart list of expected values stayed as it was,
  so every test passed while the parser refused every real link. `config_fakes.dart` keeps its
  synthetic builder, because only a builder can drop one parameter at a time for the nine refusal
  tests, and it gained a reader for the real URI out of `user-export.json` beside it.
- - **The comparison is on the serialised text, not the parsed object.** Two maps compare equal
  across a reordering and the order is not free: the app decodes into an order-preserving map, so
  a protocol's position is the order `ShareBundle` offers its URIs to a tunnel engine. Measured —
  moving a key in `cmd_status` left all 21 tests in that file green under dict equality and red on
  the line comparison.
- - **The corpus is walked as well as read per command, on both sides.** Every fixture must be
  given a reader, declared a refusal, or listed with a reason a human wrote; a per-command list
  only reaches the fixtures somebody remembered to name. Python additionally asserts that the
  directory holds exactly the files it generates, that each carries the `schema`/`ok` envelope the
  app checks before anything else, and that none of them contains a value from a real keyring —
  the accident `vpnctl`'s own not-the-server guard exists for, one level down.

`ApplyResult`'s tolerance of unknown keys is untouched, because it is what lets `apply` grow a
field without breaking an installed app — but the test now pins which unknowns are expected, so
the carve-out cannot quietly become a blind spot. The caveat the earlier sketch named is still
true and is why `apply`'s fixture is small: under a pointed `VPN_STATE_DIR`, `apply` renders and
validates but does not converge, so everything from `teardown` down is legitimately absent.

## The layers

```
lib/control/     talk to vpnctl; every call goes through --json
lib/provision/   bring a bare VPS up to serving, over SSH
lib/transport/   the SSH implementation, dartssh2, behind an interface
lib/config/      turn a share URI into a sing-box client configuration
lib/tunnel/      establish the tunnel on THIS device
lib/ui/
```

Everything except `tunnel`'s platform halves is unit-tested with no server, no network and no
device: `control` and `provision` build command lines and parse JSON with the SSH session
injected, `config` is a parser and a builder, `transport` is tested against a fake at its own
seam, and `lib/ui/` — which holds the credential vault, the session state machine and the
changed-host-key refusal — had no tests at all until three files were added for it. What they
assert is what that layer can get catastrophically wrong: a prompt answering "trust" against a
non-null pin still yields a refusal and records nothing; `SecureServerStore` round-trips, refuses
a record written by a newer schema with a sentence naming both numbers, and writes nothing back;
and a transport-level failure drops the cached `Vpnctl` session, which it did not do, so one
dropped SSH connection broke the server screen permanently and every later action failed against a
dead socket with no way back but restarting the app.

`tunnel` is the layer whose platform halves no test here can reach, and it is where the remaining
work is. Its Dart controller is tested in the plugin package (38 tests); the Kotlin and the Swift
are judged by `app.yml` and by nothing else.

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

    ssh <host> "cd /opt/vpn-stack && VPN_STACK_LOCK_HELD=1 flock /run/vpn-stack.lock /usr/local/bin/vpnctl <args>"

and CLAUDE.md calls that lock "the entire multi-operator story": there is no other
serialisation anywhere on the server. `users.json` and `state.json` are written through a temp
file and `os.replace`d, so no reader ever sees half a file — but two writers that
read-modify-write the same database still lose one of the two writes, and two `apply` runs
interleaved render candidate trees and promote each other's half.

`vpnctl` also claims that file itself, for every mutating command and non-blocking, so a caller
that arrives without a wrapper is refused rather than left to race. Non-blocking is not a nicety:
`flock(1)` inside `flock(1)` on the same path from a child process opens a second file
description, which the kernel treats as a different holder, so a blocking inner claim waits on its
own parent for ever — `timeout 3 flock LK bash -c 'timeout 2 flock LK echo INNER'` prints nothing,
measured. `VPN_STACK_LOCK_HELD=1` is the handshake a wrapper uses to say it is already holding the
file, and `./vpn`, `deploy`, `install.sh`, `provision-host.sh` and the boot unit all export it.

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

One gap, named here because it is checkable and open: `lib/provision/commands.dart` builds its
calls as `env VPN_STACK_LOCK_HELD=1 flock …` and `lib/control/vpnctl.dart`'s `argvFor` does not.
Against a server running this `vpnctl`, the outer `flock(1)` succeeds and the inner non-blocking
claim then refuses, so every mutating command from the control layer — `user add`, `protocol on`,
`apply` — exits 75 and arrives in the UI as "another operator holds the lock" on a box where
nobody else is doing anything. The fix is one `env` prefix, in the one place `argvFor` builds that
list.

Any future client inherits this. A call that skips the lock is a bug even on the run where it
works.

## Provisioning, and the one step that cannot move to the server

The repository became public, so a server can `git clone` it with no credential. That removes
the reason `install.sh` had to push the tree from the operator's machine, and the app does not
have to ship the tree as an asset.

What it clones is a **tag**, not a branch (`ProvisionConfig.repoRef`), so an app-provisioned box
runs a tree somebody reviewed rather than whatever was on the default branch while the phone was
fetching it — which is what CLAUDE.md means by "unpinned and unsigned". The default is `v0.2.0`,
and the constant is the one line to change when the app adopts a newer server tree. Two things
follow: the tag has to exist in the public repository before any provision can work, and it has to
name a tree that actually contains `scripts/provision-host.sh`. `main` did not — the script is a
pure addition on this branch — so a provision against it cloned perfectly and then died at exit
127 on its first host stage, on a box whose apt and git had already been touched. The clone step
now asserts the script is present in the fetched ref and names both the ref and the path.

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
`.aar` — so CI builds it from source with SagerNet's own pinned gomobile fork, in two jobs:
`libbox` binds the Android `.aar` on Ubuntu, `libbox_apple` binds `Libbox.xcframework` on a macOS
runner, because `make lib_apple` needs Xcode. Both read the version out of `compose.yml`, the same
line that pins the server's image, so one number governs the engine at both ends of a
configuration — and both assert that the read matched *exactly one* line rather than taking the
first, since two pins arrive as one newline-joined string that is then handed to `git clone
--branch` and to a cache key. Each output is cached on that version plus the gomobile version
rather than rebuilt for every commit to a Dart file. Neither artifact is committed:
`app/tool/unpack_libbox.sh` puts the framework where the extension target links from and checks
its symlinks survived the artifact round trip, which `upload-artifact` does not preserve on its
own.

Platform code cannot live in `app/android/`: that directory is generated by `flutter create` in CI
and is gitignored, so anything written there would be deleted and regenerated. It lives in a
package under `app/packages/`, which is committed — every line of Kotlin and every line of Swift,
both.

`app/ios/` is the exception, and it is committed rather than generated for a reason that applies
to no other platform here: an `NEPacketTunnelProvider` is a **second target**, an app extension
with its own bundle identifier, its own entitlements file and an App Group, and `flutter create`
writes one target with none of those. A regenerated project therefore has no tunnel in it and
nothing to sign — so the directory is in the tree, `.gitignore` carries a comment saying so where
the exclusion used to be, and `Runner.xcodeproj/project.pbxproj` carries the `SingboxTunnel.appex`
target, the App Group and the framework search path.

It is still a generated artefact, which is the shape that drifts from its generator silently, so
two things hold it: `app/tool/ios_project.rb` is what writes that target (over a freshly generated
stock project — merging a template into an edited project is the thing nobody can review), and
`ios_project.rb --check` opens the committed project and compares every setting against the tables
the generate path writes from, reporting all differences rather than the first.
`app/ios/.gitignore` keeps the per-machine files (`Generated.xcconfig`, `ephemeral/`, `Pods/`)
out. The regeneration gesture is one git move: delete `app/ios/` and push — `ios_state` reports it
absent, `ios_project` rebuilds it and uploads the artifact, `ios` stands down for that run, and
`ios_result` fails if neither of the two did anything, because a skipped job renders as neither
red nor green.

## What is gated by somebody else

- **iOS.** App Store Review Guideline 5.4 admits VPN apps only from developers enrolled as an
  *organization* — a real legal entity with a D-U-N-S number — and the guideline is applied at
  notarization, so alternative EU marketplaces do not route around it. Separately, a free Apple
  ID has neither Network Extensions nor Personal VPN, so even sideloading a build that actually
  tunnels needs the paid membership. CI can produce an **unsigned** `.ipa`; it installs nowhere
  until somebody signs it. `docs/ios-release.md` is that whole path written out for whoever would
  hold the membership, including what is registered where and what the identifiers have to be.
- **Google Play.** From 2026-09-30 an app that uses `VpnService` needs an Organization account.
  Direct APK distribution is unaffected, which is how this is expected to ship.
- macOS and Windows builds are unsigned too: Gatekeeper and SmartScreen will both complain.

None of this blocks Android or the desktop builds. It blocks the iOS *store* path, and it is
worth knowing before anybody spends a quarter on it.

## Building

Not on a developer's machine by default — in CI, because macOS and iOS artifacts cannot be
produced anywhere else and this repository is public, so the runners are free. Four of the five
platform directories (`android/`, `macos/`, `windows/`, `linux/`) are generated by `flutter
create` rather than committed: they are scaffolding, they are large, and a hand-edited Xcode
project is a file nobody can review. `ios/` is committed for the reason above — and it is written
by a script for this same reason, not by hand.

The five artifacts are `android-apk`, `ios-ipa-unsigned`, `macos-app`, `windows-x64` and
`linux-deb`, and every one of them waits on the `check` job, which is deliberately the cheap one:
on ubuntu-latest it parses `tool/ios_project.rb`, runs `tool/check_extension.sh sources` over the
identifiers with awk and grep, then the analyzer and both Dart suites. A mismatch between the App
Group in an entitlement and the App Group in an Info.plist is a runtime sandbox denial with no
build-time symptom, so reading those strings for two seconds here beats discovering it behind a
45-minute macOS build — or on a device nobody has.
