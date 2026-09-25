# The iOS half

sing-box on iOS is a `NEPacketTunnelProvider` in an **app extension** — a second
process, with its own bundle identifier, its own entitlements and its own
sandbox — driven from the app through `NETunnelProviderManager`. That is the one
structural fact everything below follows from, and it is the difference from
Android, where the `VpnService` is an object in the same process holding a file
descriptor a few frames away.

```
app process                          extension process
-----------                          -----------------
SingboxTunnelPlugin      MethodChannel / EventChannel with Dart
  NETunnelProviderManager  ---save--> the VPN configuration iOS installs
  NETunnelProviderSession  --start--> PacketTunnelProvider
                                        LibboxSetup
                                        LibboxNewCommandServer
                                        startOrReloadService
                                        LibboxPlatform.openTun
                                          setTunnelNetworkSettings
                                          -> utun file descriptor
  <-- NEVPNStatusDidChange
  <-- App Group: tunnel-status.json (why it stopped)
  --> App Group: tunnel-start.json  (what to start)
```

## What is here and what is not

| directory | target | contents |
| --- | --- | --- |
| `Classes/` | app (via the pod) | `SingboxTunnelPlugin` — the channels, and the manager |
| `Shared/` | app **and** extension | the wire constants, the App Group key names, the two files |
| `Extension/` | extension only | `PacketTunnelProvider`, `LibboxPlatform` |

`singbox_tunnel.podspec` lists `Classes/` and `Shared/` and deliberately not
`Extension/`: a pod is linked into the targets the Podfile names, Flutter's
generated Podfile names `Runner` and nothing else, and compiling the provider
into the app would leave the only target that can run it without it.

## `app/ios/` is committed, and this is what is in it

`app/ios/` is a committed directory, unlike `android/`, `macos/`, `windows/` and
`linux/`, and `.gitignore` says why in the paragraph above the four it does
exclude. Nothing `flutter create` writes would survive as scaffolding here: it
produces one target, no entitlements file, no App Group and no extension, and
**a build somebody can sign needs a stable project**. So the four platform
directories stopped being uniformly scaffolding — which is a change to what
`app/README.md` says about them, not a detail.

`app/tool/ios_project.rb` is what produces that directory, from the identifiers
in `app/tool/ios_identifiers.sh`, and `app/tool/check_extension.sh` asserts
against the same file what was written. Everything below is therefore stated as
a value, not as a shape to invent. `--org io.github.asel1x --project-name
vpn_stack_app` is what `.github/workflows/app.yml` passes, and Flutter's
`createUTIIdentifier` (`create_base.dart:595`) camel-cases the project name, so
the app's identifier is fixed by that pair.

### Targets

| | app | extension |
| --- | --- | --- |
| name | `Runner` | `SingboxTunnel` |
| product type | application | app extension (Network Extension → Packet Tunnel Provider) |
| bundle identifier | `io.github.asel1x.vpnStackApp` | `io.github.asel1x.vpnStackApp.SingboxTunnel` |
| `IPHONEOS_DEPLOYMENT_TARGET` | `15.0` | `15.0` |
| `SWIFT_VERSION` | `5.0` | `5.0` |

The extension's identifier must be the app's with one segment appended: iOS
refuses to install an extension whose identifier is not a prefix-extension of
its container app's, and the failure is at install time with no useful text.

15.0 is not a preference. `build_libbox -target apple` passes `-iosversion=15.0`
(`cmd/internal/build_libbox/main.go:206`), so that is the floor of every slice in
`Libbox.xcframework`; Flutter 3.47.4's own iOS template already writes
`IPHONEOS_DEPLOYMENT_TARGET = 15.0`, so the two agree today and the podspec's
`s.platform = :ios, '15.0'` is what makes a drift in either visible.

### App Group

`group.io.github.asel1x.vpnStackApp`, and it must be registered against the
signing team in the developer portal — an App Group is a real provisioning
artefact, not a string.

It is the only thing the two processes can both open, and both halves need it:
the app writes the configuration to start and the extension writes why it
stopped. Without it, `SharedContainer.directory()` throws and names the missing
key, which is the loud failure — but nothing tunnels.

### Entitlements

`Runner/Runner.entitlements` — **the app needs the Network Extension entitlement
too**, not only the extension. It is what lets `NETunnelProviderManager` save a
configuration naming a custom provider.

```xml
<key>com.apple.developer.networking.networkextension</key>
<array><string>packet-tunnel-provider</string></array>
<key>com.apple.security.application-groups</key>
<array><string>group.io.github.asel1x.vpnStackApp</string></array>
```

`SingboxTunnel/SingboxTunnel.entitlements` — the same two keys, same values.
Nothing else is needed: this build reads no Wi-Fi SSID
(`LibboxPlatform.readWIFIState` returns nil and says why), so
`com.apple.developer.networking.wifi-info` and the location entitlement
sing-box-for-apple carries are deliberately absent.

Both entitlements need a provisioning profile from a **paid** membership
enrolled as an **organization** — App Store Review Guideline 5.4 for
distribution, and a free Apple ID has no Network Extension entitlement at all,
so this is also what gates sideloading. `app/README.md` has the detail; CI's
`.ipa` stays unsigned and installs nowhere.

### Info.plist keys

`Runner/Info.plist`:

```xml
<key>SingboxTunnelAppGroup</key>
<string>group.io.github.asel1x.vpnStackApp</string>
<key>SingboxTunnelProviderBundleIdentifier</key>
<string>io.github.asel1x.vpnStackApp.SingboxTunnel</string>
```

`SingboxTunnel/Info.plist`:

```xml
<key>SingboxTunnelAppGroup</key>
<string>group.io.github.asel1x.vpnStackApp</string>
<key>NSExtension</key>
<dict>
  <key>NSExtensionPointIdentifier</key>
  <string>com.apple.networkextension.packet-tunnel</string>
  <key>NSExtensionPrincipalClass</key>
  <string>$(PRODUCT_MODULE_NAME).PacketTunnelProvider</string>
</dict>
```

Both identifiers are read from the running bundle rather than baked into Swift
because both are chosen by whoever owns the Apple account, and a constant here
would be a value nobody can change without editing this package. Absent, they
are named and refused — `SharedContainer` carries the text.

So what this package holds as constants is the two KEY names, and they are the
pair a checker anchors on: `SharedContainer.appGroupInfoKey` and
`SharedContainer.providerBundleInfoKey`, the first two members of that enum in
`Shared/SharedContainer.swift`, against `APP_GROUP_INFO_KEY` and
`PROVIDER_INFO_KEY` in `app/tool/ios_identifiers.sh`. Those are what
`app/tool/ios_project.rb` writes into both Info.plists, so a third spelling of
either is a nil lookup on the first connect and nothing at build time — the same
class of failure as the App Group value itself disagreeing between an
entitlement and an Info.plist.

`$(PRODUCT_MODULE_NAME).PacketTunnelProvider` is why `PacketTunnelProvider`
keeps that exact name: a Swift class reaches the Objective-C runtime as
`<module>.<class>`, and the principal class is looked up by that string.

### Target membership

- extension: `Extension/PacketTunnelProvider.swift`,
  `Extension/LibboxPlatform.swift`, `Shared/*.swift`
- app: nothing from here — the pod compiles `Classes/` and `Shared/`

`Shared/` is in two targets on purpose. It is compiled twice into two modules
that never meet; what they share is the on-disk format and the four stage
strings, and a second spelling of either would show up as a status the other
side cannot read.

### Libbox.xcframework

Linked by the **extension target only** — the app half talks to
`NetworkExtension` and never to libbox, which is also what keeps
`flutter build ios` from needing an 800 MB Go artefact to compile this pod.

- `FRAMEWORK_SEARCH_PATHS` (extension) →
  `$(SRCROOT)/../packages/singbox_tunnel/ios/Frameworks`
- Link Binary With Libraries → `Libbox.xcframework`, **Do Not Embed**. gomobile
  builds it `-buildmode=c-archive` (`bind_iosapp.go:335`), so every slice is a
  static archive; embedding a static framework produces a bundle the loader
  rejects.

The bytes arrive there in CI. `.github/workflows/app.yml`'s "Download
Libbox.xcframework" step hands the `libbox-apple-<version>` artifact straight to
`app/packages/singbox_tunnel/ios/Frameworks`, in the `ios` job and in
`ios_project` both, and "Unpack Libbox.xcframework" runs `app/tool/unpack_libbox.sh`
over it. One destination and not a staging copy: it is the path
`FRAMEWORK_SEARCH_PATHS` names and the path the file reference in
`Runner.xcodeproj` resolves to, all three spelled once as `PACKAGE_SUBDIR` in
`app/tool/ios_identifiers.sh`.

The build-phase check is there with it — `app/tool/ios_project.rb` adds a "Check
Libbox.xcframework" shell-script phase to the extension target and moves it to
index 0, ahead of Compile Sources. It exists for the reason `android/build.gradle`
gives a whole paragraph to: without the framework the extension still has source
to compile and the project still produces an `.ipa`, which then dies at the first
connect with a missing symbol from inside a Go callback — the least legible
possible place to learn that a build step was skipped. Ahead of Compile Sources
rather than anywhere later, or the check reports the missing framework after the
compile that needed it has already failed on `import Libbox`.

## What this package does not do

It does not build a sing-box configuration: `SingboxTunnel` takes a
`SingBoxConfigBuilder` and hands whatever it returns to the engine verbatim.
`app/lib/config/` is the single definition of that format, and a second one here
is the drift `app/README.md` refuses.

It does not enable on-demand rules. They would make iOS start the tunnel on its
own schedule — a tunnel coming up with a configuration nobody chose, in a UI
that did not ask.

## The credential in the container, and what removes it

`tunnel-start.json` holds the sing-box configuration, and that configuration is
the credential: the VLESS UUID, or the Hysteria2 password and its obfs password,
in plain text. It is written because `startVPNTunnel(options:)` is not the only
way this provider starts — iOS starts one with **no options** from the switch in
Settings and when it relaunches an extension it killed — so the configuration
cannot live only in that dictionary.

Everything about its lifetime follows from those two sentences together.

- **It is deleted on a stop somebody asked for**, in `SingboxTunnelPlugin.stop`
  before the session is torn down, and again in `stopTunnel` for
  `.userInitiated` so that the Settings switch takes it off disk too, with the
  app not running. From the moment there is no tunnel anybody asked for, the
  reason to keep a startable configuration is gone and what is left is a
  credential sitting in a container that whoever holds the switch could spend.
  The cost is named and accepted: after a deliberate stop the switch in Settings
  reports that no configuration is on file and says to connect from the app,
  instead of quietly reopening a tunnel.
- **It survives a stop nobody asked for**, which is the whole point of
  persisting it. A run the system killed at its memory ceiling is relaunched
  with no options and has to find what it was running.
- **It is deleted when the profile goes**, in `stopTunnel` on
  `.configurationRemoved` and in `removeProfile` before anything else.
- **The container is excluded from backups** — `isExcludedFromBackup` on the
  container URL, once per process in `SharedContainer`. A Group Container is
  backed up like the rest of an app's data, so without it every credential this
  device was ever handed rides into a Finder backup and into iCloud, where the
  person who deleted the server in the app has no idea it still is.

`removeProfile` is the other half, and it is reached from Dart — through
`TunnelController.forgetProfile`, which the server list calls when somebody
removes a server. It was not, for a while: the Swift existed, this paragraph
already described it as a method Dart calls, and no Dart file mentioned it, so
every removal left the profile installed. `NETunnelProviderManager` is installed
once, at the first connect, and it **outlives the app's own record of the
server**: without `removeFromPreferences` deleting a server in the app left a row
under Settings > General > VPN & Device Management that started the extension
from `tunnel-start.json` when somebody flipped it — a tunnel to a server the app
no longer knows, on a credential it had stopped showing anybody.

The Dart half stops a running tunnel first — on Android the stop is what deletes
the persisted configuration, and that file is the credential — leaves the device's copy alone when the controller can see it
belongs to a **different** server, and treats a platform that answers
`notImplemented` — Android, which installs no system profile — as a no-op rather
than a failure. A removal this cannot complete does not block the server from
being forgotten; what survived comes back as a sentence the app shows.

**It revokes nothing on the server, and every sentence around it has to keep
saying so.** The credentials in that configuration stay valid until `vpn user rm`
runs on the server; the app's own confirm dialog already tells the person that
removal is local, and this is what makes that true of the phone as well as of the
app's database.

One consequence inside the plugin: iOS reports `NEVPNStatus.invalid` for a
configuration that is gone, which is normally worth reporting as a failure —
somebody deleted the profile under a running app. After a removal this process
performed it is the expected end of that removal, so the plugin remembers it did
the removing and reports `disconnected` with the sentence above instead of
manufacturing a failure out of getting exactly what it asked for.

## The one thing iOS does not give you, and what stands in for it

When a packet-tunnel provider refuses to start, the app gets **nothing**: the
connection goes `connecting` → `disconnected` and `NEVPNStatus` carries no
reason, no error and no text. Reported as-is that is a bare "disconnected",
which is the summarised-into-nothing that `TunnelStatus.message` exists to
prevent — the whole point of that field is that a tunnel which will not come up
is diagnosed from exactly that string.

So the extension writes `tunnel-status.json` into the App Group container on
every transition, and the app reads it when the system says the connection went
down. Each record carries the `startId` of the run that wrote it, because a file
is durable and a run is not: without it the app would read the **last** run's
failure as this one's, which is a worse lie than saying nothing.

The id alone is not enough on a **cold launch**, where the app has issued no
id of its own. Adopting whatever id the file held made a run that ended days
ago into this launch's evidence: the app opened onto `disconnected`, read
`connected` out of the stale record, and published "the tunnel extension
stopped without saying why" for a start that never happened. So an id this
process did not issue is adopted only while `NEVPNStatus` reports a session
that is **live right now** — a live session is what makes an unattributed
record a record about the present — and a record belonging to no run this
process started or saw running is not evidence at all. The record's
`updatedAt` is printed in the failure text and never tested: no threshold
separates a healthy tunnel that has been quiet for a day from one that died
ten minutes ago.

The rules, in `SingboxTunnelPlugin.disconnectedStatus()`:

| file says | iOS says | reported |
| --- | --- | --- |
| nothing, and no run this process issued has been seen live | disconnected | `disconnected` |
| nothing, for a run this process issued and iOS reported live | disconnected | `failed` — the extension never wrote a status at all |
| `failed` | disconnected | `failed`, with its text |
| `disconnected` | disconnected | `disconnected`, with its text |
| `connecting` / `connected` | disconnected | `failed` — it went away without writing a reason |

The last row is the iOS shape of `SingboxVpnService.onDestroy`: a tunnel the
app asked for, that is no longer there, and that the app did not stop.

The second row used to be folded into the first, and that cost the one
diagnostic this platform has. A cold launch with no record is genuinely
disconnected; a start **this process issued**, that iOS reported up and then
down, with no record of its own, is a failure — the extension did not launch, or
it could not open the App Group container. The extension writes `connecting` as
its first act, before anything that can fail, and a run that actually came up
cannot land here because `startBox` needs the same container for libbox's own
paths and throws without it. So the message names both causes and then names the
App Group, because an identifier that disagrees between an Info.plist, an
entitlement and the developer portal is a sandbox refusal at run time and
nothing at all at build time — on a target nobody here can sign, that sentence
is the whole debugging session.

"Seen live" is `NEVPNStatus` reporting anything but disconnected or invalid for
this run, and it is the gate rather than the bare presence of a start id because
`startVPNTunnel` returns before the connection object flips to `connecting`: a
`status` call landing in that window reads disconnected for a start seconds old,
and reporting a failure there would be the spurious alarm that teaches people to
ignore the real one.

## Why `connected` here is evidence and not a guess

`NEVPNStatus.connected` is reported when the provider calls its `startTunnel`
completion handler with no error. `PacketTunnelProvider` calls it only after
`LibboxPlatform.didOpenTun` is true, and that is set only where
`setTunnelNetworkSettings` has already returned successfully and a real utun
file descriptor was recovered. `openTun` refuses a configuration that names no
tun address before it can get there, and that refusal sits **outside** the
`auto_route` branch, where `SingboxVpnService.kt:252` puts the same one: iOS
accepts a `NEPacketTunnelNetworkSettings` carrying neither `ipv4Settings` nor
`ipv6Settings`, so with the check inside the branch an `auto_route: false`
configuration reached `.connected` with nothing routed. Hand this a proxy-only
configuration and sing-box starts cleanly, `openTun` is never called, no packet
is routed — and the start fails instead of reporting a tunnel. Same check as
the Android side's `tunDescriptor == null`, at the same seam, for the same
reason.

One family is attached per family the tun actually has an address in, and never
an empty one. An `NEIPv4Settings` or `NEIPv6Settings` carrying zero addresses is
not "this family is unconfigured" — it is a family declared and left empty, which
Apple documents no behaviour for, so iOS may take it and route that family into
an interface with nowhere to send it. The refusal above is what makes it
impossible for *both* to be skipped, which is the state iOS accepts and carries
nothing on. `app/lib/config/` emits an address in each family today; this is the
boundary check that does not depend on that staying true.

The descriptor itself comes from KVC on `packetFlow`'s private
`socket.fileDescriptor`, falling back to `LibboxGetTunnelFileDescriptor()`
(`experimental/libbox/tun_darwin.go:11`), which scans this process's descriptors
for a `com.apple.net.utun_control` peer. Neither is documented API. If both
fail, `openTun` throws; it does not return a descriptor that is not the
tunnel's.

## Which thread owns what

Three contexts meet in the extension and none of them is the main thread.

- **`PacketTunnelProvider.worker`**, a serial queue, owns `commandServer`,
  `startId` and `reportedFailure`, and the lazy `platform`. Everything iOS calls
  on its own thread — `startTunnel`, `stopTunnel`, `sleep`, `wake` — hops onto it
  first. `startOrReloadService` brings the entire box up inside the call, which
  is seconds, and a `pause()` or a `stop` interleaved with that is a
  use-after-close of the command server.
- **`LibboxPlatform.state`**, an `NSLock`, owns `openedTun`, `appliedSettings`
  and `pathMonitor`. libbox calls this object from its own goroutines and
  gomobile promises nothing about which thread any of them lands on, while
  `didOpenTun` — the single fact `.connected` is reported on — is read from the
  worker queue and `reset()` clears all three from there. A `Bool` written on one
  thread and read on another without a release/acquire pair is not merely stale:
  nothing orders the write against the read, and the answer this build reports
  connected on would be a guess. It is a lock and not the worker queue because
  `openTun` runs *inside* the `startOrReloadService` that queue is blocked on, so
  dispatching there would deadlock the start it is part of.
- **The main queue** owns every property of `SingboxTunnelPlugin`, in the app
  process, where it is also the Flutter platform thread. NetworkExtension answers
  its completion handlers on queues of its own choosing and posts
  `NEVPNStatusDidChange` from one too, so each of those hops before it reads or
  writes anything — which is the same hop a `FlutterResult` and a
  `FlutterEventSink` require anyway, and feeding a sink from an NE queue crashes
  the engine instead of reporting the failure it was carrying.

## The libbox API this is written against

sing-box **v1.14.0**, read at that tag. The Apple binding is the same Go package
as the Android one, through the same gomobile fork (`Makefile`'s `lib_install`
pins `sagernet/gomobile` v0.1.13 for both), so the interface is identical: the
same `PlatformInterface` with 27 methods and the same `CommandServerHandler`
with 7. Objective-C naming is the only translation.

| what | where |
| --- | --- |
| `LibboxSetup(LibboxSetupOptions, &err)` | `experimental/libbox/setup.go:106` |
| `LibboxNewCommandServer(handler, platform, &err)` | `command_server.go:54` |
| `startOrReloadService(_:options:)` | `command_server.go:199` |
| `closeService()` / `close()` | `command_server.go:214` / `:187` |
| `PlatformInterface`, 27 methods | `platform.go:5` |
| `CommandServerHandler`, 7 methods | `command_server.go:43` |
| `TunOptions` handed to `openTun` | `tun.go:18` |
| `LibboxGetTunnelFileDescriptor()` | `tun_darwin.go:11` — Apple only |
| `-iosversion=15.0`, five platforms | `cmd/internal/build_libbox/main.go:198-209` |

**Where sing-box-for-apple disagrees, v1.14.0 wins.** Its
`Library/Network/ExtensionPlatformInterface.swift` (both `main` and `stable`)
implements `usePlatformAutoDetectControl` / `autoDetectControl` and adds
`writeLog` and `systemCertificates`, none of which exist in v1.14.0 — every tag
from v1.10.0 to v1.14.0 and the `testing` branch declare
`UsePlatformAutoDetectInterfaceControl` / `AutoDetectInterfaceControl`. That repo
is built against a libbox this one does not have. The names used here are the
ones the **Android** side already compiles against in CI, from the same tag,
which is the only compiled evidence available on a machine with no Xcode.

Four answers differ from Android's, and each is a property of the platform
rather than a gap:

- `usePlatformAutoDetectInterfaceControl` → **false**. Android needs it so every
  outbound socket goes through `VpnService.protect`; iOS has no protect() and
  needs none, because the system keeps a provider's own traffic out of the
  interface the provider installs.
- `underNetworkExtension` → **true**.
- `localDNSTransport` → **nil**. Android returns a resolver bound to a named
  `Network` so the server's own hostname resolves off-tunnel; iOS exposes no
  such handle, nil is legal (`config.go:31` checks for it), and libbox falls
  back to its own local transport — whose queries leave from the extension
  process, which is outside the tunnel already.
- `getInterfaces` → names, indices and types from `NWPath`; flags, MTU and
  addresses from **`getifaddrs(3)`**, which `NWPath` does not carry. They are
  not decoration: libbox reads `.MTU` and `linkFlags(.Flags)` into a
  `control.Interface` (`service.go:140`, `:143`), and sing's
  `DefaultInterfaceFinder.ByAddr` skips every interface without
  `net.FlagRunning`. Unset they are zero, which reports every interface as down
  with MTU 0 — upstream sing-box-for-apple's own `getInterfaces()` still answers
  that way. Gateways and per-interface DNS servers stay empty, which needs a
  routing-table `sysctl` and a `res_ninit` to fix; what that costs is named in
  `LibboxPlatform.getInterfaces`.
