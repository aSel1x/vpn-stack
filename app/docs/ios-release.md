# Getting this app onto TestFlight

A decision document for the one person who would hold the Apple membership. It answers what
Apple requires, what this repository can and cannot hand over, and which single fact the plan
turns on and could not be established.

Researched 2026-09-16 against Apple's own pages. The App Store Review Guidelines page carries
`Last Updated: June 8, 2026`; App Store Connect Help and Developer Account Help pages carry no
date at all, so "current" for those means "served on 2026-09-16" and nothing stronger. Apple
moves these without notice — re-read §3 before acting on it, because that is the expensive one.

The Apple half of this document held up under an adversarial check. **The half about this repository
has been wrong twice**, in the same direction both times: one draft said there was no iOS tunnel in
Swift at all, and the draft after it said the Swift, the scripts under `app/tool/` and the workflow
jobs were uncommitted work in somebody's working tree that a clone of the branch would not get.
Neither is true now, and the second stopped being true through ordinary commits — `git ls-files
app/ios app/tool` lists 44 files and 4. Two dates and two confidences: the Apple claims below are
citations, the repository claims are checked against the tree as it stands, and the repository half
is the one to re-check with a command rather than by reading. Two commands do most of it:
`bash app/tool/check_extension.sh sources` and `ruby app/tool/ios_project.rb --check`.

## The decision, before the detail

1. **Nothing in this repository can be uploaded to App Store Connect.** The `.ipa` CI produces is
   unsigned by design — `.github/workflows/app.yml`'s header says "NOTHING HERE IS SIGNED, and that
   is the intended end state, not a TODO" — and App Store Connect takes distribution-signed builds
   only. Every artifact from the App ID onward is created under somebody's paid
   membership, on their Mac, and cannot be produced here.
2. **Internal TestFlight needs no Beta App Review.** Verified below from Apple's build-status
   table rather than repeated from folklore. Up to 100 testers, each of whom must be a user on
   your App Store Connect account.
3. **External TestFlight does need Beta App Review**, and Apple describes that review as App
   Review checking the build against the App Store Review Guidelines — the document that
   contains 5.4.
4. **Guideline 5.4 says VPN apps may only be offered by developers enrolled as an organization.**
   That is quoted verbatim in §3. Whether a *beta* reviewer enforces the organization clause is
   **not documented by Apple and I could not establish it.** It is the fact this plan turns on:
   if it is enforced, external TestFlight costs a legal entity with a D-U-N-S number.
5. **Nothing this repository still owes is what blocks a TestFlight build. A paid membership
   enrolled as an organization is.** The iOS tunnel is written, committed and compiled: 2,343 lines
   of Swift under `app/packages/singbox_tunnel/ios/`, a real `NEPacketTunnelProvider` subclass, the
   `NETunnelProviderManager` the app drives it through, an extension **target** committed in
   `app/ios/Runner.xcodeproj/project.pbxproj`, and `app/lib/main.dart` handing iOS the real engine —
   the stub arm is desktop only. What no machine here can produce is a signature: two App IDs
   carrying the Network Extensions capability, an App Group registered against that team, and a
   provisioning profile for each, all created under a membership. §5 is the order.
6. **Nothing in this layer has ever run.** The Swift compiles and links against a real
   `Libbox.xcframework` on a macOS runner, and that is the whole of what CI can prove: zero packets
   have crossed it, no device and no simulator has launched the extension, and `.appex` entitlements
   are validated against a provisioning profile at *install* time, which has never happened. That is
   §7.1, and it is the largest unknown in this document about the code.

Read §5 for the order of operations. Read §7 for everything I could not verify.

## 0. What this repository can hand over

Line numbers into the *jobs* of `.github/workflows/app.yml` are deliberately absent below: that file
moves, and a line number into it is stale the next time somebody adds a step. Job names are stable,
and so is the header comment — which is where the "nothing is signed" sentence quoted below lives,
not at any particular line of it.

| thing | where | state |
| --- | --- | --- |
| Dart source, tests, analysis | `app/` | green — 288 tests in `app/`, 38 in `app/packages/singbox_tunnel`, `flutter analyze` clean with infos and warnings fatal |
| Android tunnel (Kotlin + libbox) | `app/packages/singbox_tunnel/android/` | real, and compiled on every push |
| unsigned `.ipa` | the `ios` job | `flutter build ios --release --no-codesign`, `Runner.app` zipped under `Payload/` |
| iOS tunnel, app half | `…/singbox_tunnel/ios/Classes/SingboxTunnelPlugin.swift`, 801 lines | committed; compiled and linked on a macOS runner |
| iOS tunnel, extension half | `…/singbox_tunnel/ios/Extension/` — `PacketTunnelProvider.swift` 376, `LibboxPlatform.swift` 859 | committed; compiled and linked into `SingboxTunnel.appex` |
| what both processes read | `…/singbox_tunnel/ios/Shared/`, 307 lines | committed; compiled twice, once into each target |
| the extension **target** | `app/ios/Runner.xcodeproj/project.pbxproj` | committed; written by `app/tool/ios_project.rb` and re-asserted by its `--check` |
| the identifiers everything must agree on | `app/tool/ios_identifiers.sh` | one definition; `app/tool/check_extension.sh` asserts the tree against it |
| the Xcode project spec, in prose | `…/singbox_tunnel/ios/README.md` | every identifier, entitlement and Info.plist key, as values |
| `Libbox.xcframework` | built by the `libbox_apple` job; `…/ios/.gitignore` keeps it out of the tree | a build artifact, on purpose |
| a distribution certificate, two App IDs, an App Group, two profiles | nowhere — nothing here can create one | the blocker everything else waits on |

The workflow says it out loud in its header: "NOTHING HERE IS SIGNED, and that is the intended end
state, not a TODO." That artifact exists to prove the iOS target compiles. It installs on no device,
and it cannot be uploaded.

It *is* being produced on every push. The `ios` job builds the committed project and generates
nothing — there is no `flutter create` in it — and it asserts the project before it spends an SDK:
`project.pbxproj` must mention `com.apple.product-type.app-extension`, the extension bundle
identifier and `Libbox.xcframework`; `ruby tool/ios_project.rb --check` must find the committed
project still identical in every setting to what the generator writes; and after the build
`tool/check_extension.sh` must find `Runner.app/PlugIns/SingboxTunnel.appex` with an executable in
it and an **expanded** `NSExtensionPrincipalClass` of `SingboxTunnel.PacketTunnelProvider`. Every
one of those exists because the failure here looks like success: a stock one-target Flutter project
compiles clean, links no libbox, contains no provider, and wraps into a perfectly valid `.ipa` that
cannot tunnel — indistinguishable from a real one until somebody signs and installs it.

## 1. Can an unsigned `.ipa` go to App Store Connect / TestFlight?

**No.** Apple documents the requirement positively rather than as a prohibition, in three places
that agree:

- Distribution certificates exist "to distribute your app or upload it to App Store Connect", and
  the `Apple Distribution` type is for exactly that
  ([Certificates overview](https://developer.apple.com/help/account/certificates/certificates-overview)).
- "For builds to be eligible for TestFlight, they must include application identifiers within the
  provisioning profiles"
  ([TestFlight overview](https://developer.apple.com/help/app-store-connect/test-a-beta-version/testflight-overview)),
  and a build whose profile lacks one gets the build status `Not Available for Testing`
  ([App build statuses](https://developer.apple.com/help/app-store-connect/reference/app-build-statuses)).
  An unsigned `.ipa` has no embedded profile at all.
- Of Xcode's distribution methods, exactly one produces an unsigned artifact — `Copy App`, macOS
  only. Every path that reaches App Store Connect signs
  ([Distributing your app for beta testing and releases](https://developer.apple.com/documentation/xcode/distributing-your-app-for-beta-testing-and-releases)).

In practice the upload fails validation with `ITMS-90035 Invalid Signature` / `ITMS-90034 Missing
or invalid signature`. Those error strings come from developer-forum threads, not from a page
Apple publishes as documentation — treat the error *code* as folklore and the *requirement* as
documented.

### What is actually required, and who must hold it

| # | artifact | who can create it | source |
| --- | --- | --- | --- |
| 1 | Apple Developer Program membership, 99 USD/membership year | the person enrolling becomes Account Holder | [Enroll](https://developer.apple.com/programs/enroll/) |
| 2 | Explicit App ID for the app, and a **second** App ID for the tunnel extension (separate bundle IDs) | Account Holder or Admin | [Enable app capabilities](https://developer.apple.com/help/account/identifiers/enable-app-capabilities) |
| 3 | Network Extensions + App Groups enabled on both App IDs | Account Holder or Admin | same |
| 4 | `Apple Distribution` certificate — one per team | **only Account Holder or Admin**; "if you're enrolled as an individual, you are the Account Holder" | [Certificates overview](https://developer.apple.com/help/account/certificates/certificates-overview) |
| 5 | App Store Connect provisioning profile per App ID (or Xcode automatic signing) | Account Holder or Admin | [Create an App Store Connect provisioning profile](https://developer.apple.com/help/account/provisioning-profiles/create-an-app-store-provisioning-profile) |
| 6 | App record in App Store Connect with the matching bundle ID | Account Holder, Admin, App Manager | [Preparing your app for distribution](https://developer.apple.com/documentation/xcode/preparing-your-app-for-distribution) |
| 7 | the build itself, **built using Xcode 26 or later** for iOS apps and iOS app extensions | whoever has the Mac | [Upload builds](https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds) |
| 8 | the upload (Xcode, Transporter, `xcrun altool`, or the App Store Connect API) | Account Holder, Admin, App Manager, or Developer | same |
| 9 | export compliance answers — a VPN ships encryption | Account Holder, Admin, App Manager | [Provide export compliance information for beta builds](https://developer.apple.com/help/app-store-connect/test-a-beta-version/provide-export-compliance-information-for-beta-builds) |

The distribution certificate "belongs to the team", but its private key lives in the keychain of
whichever Mac generated the CSR. That Mac is the one that can sign. Sharing it across machines is
a deliberate export/import, not a login.

Item 9 is not paperwork you can defer: a build missing it shows `Missing Compliance`, and that
status blocks **internal** testing too, not just external. Apple's
[export compliance overview](https://developer.apple.com/help/app-store-connect/manage-app-information/overview-of-export-compliance)
also points at CCATS classification and at French (ANSSI) controls on "Secure Communications"
apps; answering the questionnaire once and setting `ITSAppUsesNonExemptEncryption` in the
Info.plist stops it being asked per build.

### Could the CI artifact be re-signed instead?

Mechanically an `.ipa` can be unzipped, given an `embedded.mobileprovision` and re-`codesign`ed.
Apple documents no such flow, and it buys nothing here — for a reason that outlives the extension
target landing, which is why it is worth spelling out rather than repeating.

The CI `.app` does contain a packet tunnel extension now — `app/tool/check_extension.sh` fails the
build if it does not — which removes the shallowest objection and leaves the real one. Re-signing
means signing the `.appex` with its **own** provisioning profile
carrying the Network Extension entitlement and the App Group, signing the app with a second, and
embedding both — every one of those artifacts created under the paid membership, and `codesign`
itself runs on macOS only. The machine that could re-sign it is the machine that could have built
it. Do not spend a week on re-signing.

## 2. Internal vs external testing

| | internal | external |
| --- | --- | --- |
| how many | up to **100** | up to **10,000** per app |
| who they must be | App Store Connect **users on your account** holding Account Holder, Admin, App Manager, Developer or Marketing | anyone with an email address, or anyone at all via a public link |
| Beta App Review | **no** | **yes**, for the first build of a version |
| test information / beta app description | not required | **required** |
| how they are invited | added in App Store Connect from your user list | email, CSV import, or public link (public-link joiners show as anonymous) |
| devices | 30 per tester | 30 per tester |
| build lifetime | 90 days | 90 days |

Sources: [TestFlight overview](https://developer.apple.com/help/app-store-connect/test-a-beta-version/testflight-overview),
[Add internal testers](https://developer.apple.com/help/app-store-connect/test-a-beta-version/add-internal-testers),
[Invite external testers](https://developer.apple.com/help/app-store-connect/test-a-beta-version/invite-external-testers),
[TestFlight](https://developer.apple.com/testflight/).

Two constraints that surprise people:

- **You cannot have an external group without an internal group.** "To create an external group for
  external testing, you must first create an internal group for internal testing."
- **An individual enrollment can still have internal testers.** "If you're enrolled in the Apple
  Developer Program as an individual, you can give up to 50 additional users access to your content
  in App Store Connect. These users only access App Store Connect — they're not part of your team"
  ([Add and edit users](https://developer.apple.com/help/app-store-connect/manage-your-team/add-and-edit-users)).
  So the internal ceiling on an individual account is the holder plus 50, not 100.

### Does internal testing really skip Beta App Review? Yes — here is the evidence, not the folklore

Apple never writes the sentence "internal testing skips review", so it has to be assembled. Four
statements, all from Apple, that only fit together one way:

1. Build status **`Ready to Submit`**: "Your build can be distributed to internal testers, or can be
   submitted to TestFlight App Review for external testing or to App Review for distribution to
   customers." Internal distribution happens *from a status that precedes any submission*
   ([App build statuses](https://developer.apple.com/help/app-store-connect/reference/app-build-statuses)).
2. Build status **`Waiting for Review`**: "It will need to be approved before you can begin external
   testing." **`In Beta Review`** says the same. Both name external testing only.
3. [Add internal testers](https://developer.apple.com/help/app-store-connect/test-a-beta-version/add-internal-testers)
   has no submit step anywhere in it: "If you have builds available for testing, the users you
   choose will receive an email inviting them to test the app."
4. [Provide test information](https://developer.apple.com/help/app-store-connect/test-a-beta-version/provide-test-information):
   "When you distribute your app to external testers, you need to enter additional TestFlight test
   information about your app for TestFlight App Review."

**The sentence that causes the confusion**, and why it does not overturn this: the TestFlight
overview says "If you invite external testers, your beta build may require review. When you add the
first build of your app to a group, the build gets sent to App Review to make sure it follows the
App Review Guidelines." Read the second sentence alone and "a group" sounds like any group. It is
conditioned by the first, and the marketing page removes the ambiguity by putting the same claim
under *Invite external testers*: "you'll first create a group in App Store Connect, add the builds
you'd like them to test, and have your first build already approved by App Review for TestFlight.
Your builds are automatically sent for review once they're added to a group."

Mechanics of external review worth knowing before you plan a week around it: the first build of a
version gets a full review and later builds of that version may not; at most six builds can be
submitted to TestFlight App Review per 24 hours; only one build per version can be in review at a
time; approval mails the Admins; a rejected build shows `Rejected` and **cannot be used in
TestFlight at all** — you upload a new one. Appeals go to TestFlight App Review.

## 3. Guideline 5.4 — the organization clause

Current text, quoted in full from
[App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/), page dated
`Last Updated: June 8, 2026`, fetched 2026-09-16:

> **5.4 VPN Apps**
>
> Apps offering VPN services must utilize the NEVPNManager API and may only be offered by developers
> enrolled as an organization. You must make a clear declaration of what user data will be collected
> and how it will be used on an app screen prior to any user action to purchase or otherwise use the
> service. Apps offering VPN services may not sell, use, or disclose to third parties any data for
> any purpose, and must commit to this in their privacy policy. VPN apps must not violate local
> laws, and if you choose to make your VPN app available in a territory that requires a VPN license,
> you must provide your license information in the App Review Notes field. Parental control, content
> blocking, and security apps, among others, from approved providers may also use the NEVPNManager
> API. Apps that do not comply with this guideline will be removed from the App Store and blocked
> from installing via alternative distribution and you may be removed from the Apple Developer
> Program.

So: yes, it says exactly that, and it carries an account-level penalty ("you may be removed from the
Apple Developer Program"), not just a rejection. Note also the last sentence closes the EU
alternative-marketplace route — the guideline is applied at notarization too.

Three obligations in that paragraph land in the *code*, not the paperwork. The tree satisfies one
of them, in source:

- **The `NEVPNManager` API requirement — met.** `NETunnelProviderManager`'s superclass is
  `NEVPNManager`
  ([NETunnelProviderManager](https://developer.apple.com/documentation/networkextension/netunnelprovidermanager)),
  and `Classes/SingboxTunnelPlugin.swift` loads, configures, saves and — since the app stopped
  leaving a profile behind that it told the person it had deleted — *removes* one, through
  `loadAllFromPreferences` and `removeFromPreferences`. Met in compiled source and never in a
  running build: no `NETunnelProviderManager` here has ever saved a configuration on a device — §7.1.
- **A data-collection declaration screen shown *before* any use of the service — absent.** There is
  no such screen under `app/lib/ui/`, and it is a screen somebody has to design, not a checkbox.
- **A privacy policy committing to no third-party disclosure — absent**, and not a code change at
  all: it has to be written and hosted somewhere a reviewer can open it.

### Is 5.4 enforced at Beta App Review, or only at full App Store review?

**I could not establish this, and it is the single fact this plan turns on.** Stating that plainly
rather than guessing:

What Apple does say:

- Guideline **2.2 Beta Testing**: "Any app submitted for beta distribution via TestFlight should be
  intended for public distribution and should comply with the App Review Guidelines." No carve-out,
  no narrower subset — the whole document is named, and 5.4 is in it.
- TestFlight overview: an external build "gets sent to App Review to make sure it follows the App
  Review Guidelines".
- Apple publishes **no** list of what Beta App Review checks and what it skips. There is no
  "beta review scope" page.

What Apple does **not** say anywhere I could find: whether a beta reviewer looks at the enrolling
entity's type. Note that nothing in Apple's *tooling* stops an individual: the Network Extensions
capability is gated on program membership (ADP/ADEP), not on entity type
([Supported capabilities (iOS)](https://developer.apple.com/help/account/reference/supported-capabilities-ios)),
and nothing in App Store Connect Help says an individual cannot create a VPN app record. The
organization rule lives in the guidelines, so it is enforced wherever the guidelines are applied.

Developer-forum reports describe individuals being rejected under 5.4 at *App Store* review and
re-enrolling as a company; I found no first-hand report, and no Apple statement, about the
organization clause at *beta* review. Forum posts are anecdote — cited here only to say the
anecdote points one way and does not settle it.

**Plan for both.** Treat the answer as unknown and order the work so the unknown is tested cheaply:
get to internal TestFlight first (no reviewer involved at all), and only then submit one build for
external review. That submission *is* the experiment; it costs one build and a wait, and it is the
only way to learn the answer.

### What satisfying 5.4 costs

Organization enrollment, from [Enroll](https://developer.apple.com/programs/enroll/):

- a **legal entity** that can contract with Apple — "We do not accept DBAs, fictitious business
  names, trade names, or branches";
- a **D-U-N-S Number** (Dun & Bradstreet; government entities excepted);
- the enroller must have **legal binding authority** — owner/founder, executive, senior project lead,
  or an employee granted it;
- a **work email on the organization's domain**;
- a **public, functional website** on that domain — "Links to social media webpages or websites that
  contain minimal content or display a message from a domain registrar won't be accepted";
- 99 USD per membership year, plus a
  [compliance review](https://developer.apple.com/help/app-store-connect/reference/compliance-review)
  requiring business registration or a certificate of incorporation.

That is the real price of the App Store path for a VPN app. There is no waiver for a personal
project and no Apple-offered route around it — a sideloaded or alternative-marketplace build is
covered by the same guideline's last sentence.

## 4. What a VPN app needs from Apple technically, review aside

| requirement | value | self-serve on a paid account? |
| --- | --- | --- |
| Network Extensions capability | enabled on both App IDs | **yes** — Account Holder or Admin ticks it in Certificates, Identifiers & Profiles, or Xcode's Signing & Capabilities does it |
| `com.apple.developer.networking.networkextension` | array containing `packet-tunnel-provider`, on both targets | yes, comes with the capability |
| extension `NSExtensionPointIdentifier` | `com.apple.networkextension.packet-tunnel` | n/a — Info.plist |
| App Group (`com.apple.security.application-groups`) | `group.io.github.asel1x.vpnStackApp`, registered on the developer site | **yes**, and available even to free accounts |
| Personal VPN (`NEVPNManager` built-in protocols) | not needed here | yes, but irrelevant — sing-box is a custom protocol, so packet tunnel |

**Register these exact strings.** They are not placeholders and they are not spread around the
tree: `app/tool/ios_identifiers.sh` is their single definition, `app/tool/ios_project.rb` writes
them into `app/ios/`, and `app/tool/check_extension.sh` asserts what was written.

| what | value |
| --- | --- |
| app bundle identifier (App ID #1) | `io.github.asel1x.vpnStackApp` |
| extension bundle identifier (App ID #2) | `io.github.asel1x.vpnStackApp.SingboxTunnel` |
| App Group | `group.io.github.asel1x.vpnStackApp` |
| extension target and Swift module | `SingboxTunnel`, principal class `$(PRODUCT_MODULE_NAME).PacketTunnelProvider` |
| deployment target, all six configurations | `15.0` |

The extension identifier is the app's plus **exactly one** component: iOS refuses to install an
extension whose identifier is not a prefix-extension of its container app's, at install time, with
no useful text, and two components deeper is the same refusal. The App Group appears in four places
that iOS compares at *runtime* and no compiler compares at all — both entitlements files, and the
`SingboxTunnelAppGroup` key in each Info.plist, which `Shared/SharedContainer.swift` reads out of
the running bundle rather than from baked-in Swift, because those values belong to whoever owns the
Apple account. Changing the app bundle identifier means re-registering an App ID and an App Group,
so it is not a rename anybody does casually.

Before trusting any of that, and after any change on either side, two commands answer in seconds
whether the tree still agrees with what was registered:

```
bash app/tool/check_extension.sh sources    # plain awk and grep; runs anywhere
ruby app/tool/ios_project.rb --check        # opens the .xcodeproj; needs the xcodeproj gem,
                                            # which arrives with CocoaPods, so: on the Mac
```

The first prints one line per assertion and reports every mismatch rather than stopping at the
first, because these values are derived from one another and one wrong identifier usually breaks
three of them. The second compares every setting in the committed project against the tables the
generator writes from — `app/ios/` is a committed *generated* artefact, which is the shape that
drifts from its generator silently, on settings whose only symptom is a build that succeeds and a
tunnel that does not start.

- **Network Extensions is not available on a free Apple ID.** Apple's capability matrix marks it for
  Apple Developer Program and Apple Developer Enterprise Program members only, blank for the free
  "Apple Developer" column; Personal VPN is the same; App Groups is available to all three
  ([Supported capabilities (iOS)](https://developer.apple.com/help/account/reference/supported-capabilities-ios)).
- **No request to Apple is required for a packet tunnel provider.** "To add this entitlement to an
  App Store app, enable the Network Extensions capability in Xcode"
  ([Network Extensions Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)).
  The contrast is the proof: Apple's
  [TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
  (revised 2025-08-19) explicitly says a content filter needs a Family Controls entitlement request
  and a hotspot provider needs a HotspotHelper request, and says nothing of the kind for the packet
  tunnel table. Capabilities that do need Apple's approval are the "managed" ones, requested by the
  **Account Holder** from an App ID's Capability Requests tab
  ([Capability requests](https://developer.apple.com/help/account/capabilities/capability-requests));
  Network Extensions is not one of them.
- **The App Group is not strictly Apple-mandated for a packet tunnel** — it is how the app and its
  extension share a container and a keychain access group
  ([App Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.application-groups)).
  In practice it is required, because the extension is a separate process that needs the profile,
  the working directory and the logs. sing-box's own Apple client does exactly this: its
  `Extension/Extension.entitlements` carries `packet-tunnel-provider`, an app group, the app
  sandbox, and network client/server.
- **Packaging**: iOS packet tunnel providers are **app extensions**, minimum iOS 9.0 (TN3134). On
  iOS there is no system-extension option and no Developer ID option — App Store or TestFlight or
  ad hoc, nothing else.
- **Per-app VPN mode requires a managed device** (TN3134). Not wanted here; whole-device tunnel is
  the default.

### What this tree still owes, and what it stopped owing

Two drafts of this document were wrong here and the corrections are stated as corrections, because
somebody may have read either. The first said there was no `Libbox.xcframework` job, no extension
target and **no Swift**; the last of those was flatly false. The second said the target was "in
flight" and the committed project the blocker everything waited on; both landed. What is left on
this side of the fence is not a feature and not a file — it is that none of it has run.

- **`Libbox.xcframework` is not in the tree, and is not meant to be — but CI builds it.** sing-box
  builds it: `make lib_apple` at v1.14.0 runs `build_libbox -target apple`, gomobile-binding
  `ios,iossimulator,tvos,tvossimulator,macos` with `-iosversion=15.0`. That needs a macOS runner
  with Xcode, and there is now a **second** libbox job for exactly that. `libbox` builds the
  Android `.aar` on Ubuntu; `libbox_apple` builds the xcframework on `macos-latest`, from the
  sing-box version read out of `compose.yml` by the same `sed` expression the Android job uses —
  one number governs the engine at both ends of a configuration. It runs sing-box's own
  `make lib_install` (which pins the `sagernet/gomobile` fork at v0.1.13), caches the packed
  tarball on version plus gomobile version, and refuses to publish an artifact with no `Info.plist`
  at the bundle root, because an `.xcframework` *is* that file. `app/tool/unpack_libbox.sh` puts it
  where the extension links from and checks the framework's symlinks survived the artifact round
  trip. The earlier claim — "the existing `libbox` job builds the Android `.aar` on Ubuntu and
  cannot produce this" — described the only job that existed when it was written; the `.aar`
  sentence is still true and the conclusion is not.
- **The packet tunnel extension target — written, run, and committed.** `flutter create
  --platforms=ios` generates a single `Runner` target, and a CocoaPods pod is linked only into the
  targets the Podfile names, which is `Runner` and nothing else. That is why
  `singbox_tunnel.podspec` ships `Classes/` and `Shared/` and deliberately **not** `Extension/`:
  compiling the provider into the app would leave the only target that can run it without it. So
  nothing in a stock project can own `Extension/`, and `app/tool/ios_project.rb` is what does —
  bundle identifiers, both entitlements files, the App Group, the framework search path, and the
  Embed App Extensions phase, written over a freshly generated project. It has been run: a macOS
  runner generated the project, built it, and uploaded it as the `ios-project` artifact, which is
  what `app/ios/` in the tree now is. Regeneration is not a dispatch button — there is none, for a
  workflow outside the default branch — it is deleting `app/ios/` and pushing.
- **A committed `app/ios/` — done, and the rule it bends is written down where the exclusion used
  to be.** `.gitignore` no longer excludes the directory; it carries a comment there saying the
  directory is committed and why, and `app/README.md` states the exception rather than the old
  blanket rule. The reason is narrow and does not generalise to the other four platform
  directories: an app extension is a second target with its own bundle identifier, entitlements and
  App Group, and `flutter create` preserves none of that.
- **The Dart wiring — done.** `app/lib/main.dart` hands `SingboxTunnel` to Android *and* iOS and
  `UnimplementedTunnel()` to the desktop platforms, where there is no engine yet. That file also
  used to carry twenty lines arguing that iOS was deliberately not wired, directly above the line
  that wired it; three reviewers tripped over it independently, which is what a stale comment at a
  composition root costs.
- **What is NOT missing**: `Classes/`, `Extension/` and `Shared/` — 2,343 lines of Swift, written
  against sing-box v1.14.0's libbox API read at that tag, with `…/ios/README.md` as the spec for the
  Xcode project, naming every identifier, entitlement key and Info.plist key as a value rather than
  a shape to invent. `app/tool/ios_identifiers.sh` is now the single definition of those
  identifiers, and `app/tool/check_extension.sh sources` compares the four places that must agree
  about them — both Info.plist keys, both entitlements files, the extension's bundle identifier and
  the generator's own tables — with awk and grep, on ubuntu-latest, in about two seconds. A mismatch
  there is a sandbox denial at the first connect with no build-time symptom, so on a target no
  device has ever run that comparison is the cheapest available substitute for a device.

## 5. Division of labour

The repository produces source and an unsigned artifact. Everything below is the colleague's, in
this order — except step 6, which is this repository's and is kept in the table to say so.
"Individual" means an individual Apple Developer Program enrollment is sufficient for that step;
"Organization" means it is not.

| # | step | who does it | individual enough? |
| --- | --- | --- | --- |
| 1 | Get a Mac running **Xcode 26 or later**. Not optional and not rentable around: signing and upload both happen there. | colleague | n/a |
| 2 | Enrol in the Apple Developer Program (99 USD/yr). The enroller becomes Account Holder. | colleague | **yes**, for steps 1-10 |
| 3 | Register two App IDs — `io.github.asel1x.vpnStackApp` and `io.github.asel1x.vpnStackApp.SingboxTunnel` — and tick **Network Extensions** and **App Groups** on both. Register the app group `group.io.github.asel1x.vpnStackApp`. The strings are §4's table, and `app/tool/ios_identifiers.sh` is where the tree keeps them — `bash app/tool/check_extension.sh sources` prints what the tree expects, in two seconds, so it can be read against what was registered. Both App IDs need a provisioning profile too (step 7's automatic signing will create them), because the workflow builds `--no-codesign` on purpose and that `.ipa` installs nowhere. | Account Holder or Admin | yes |
| 4 | Create the `Apple Distribution` certificate (or let Xcode automatic signing do it). | **Account Holder or Admin only** | yes |
| 5 | Create the app record in App Store Connect with the app's bundle ID. Bundle ID is permanent after the first upload. | Account Holder, Admin, App Manager | yes |
| 6 | **Not the colleague's work, and the row stays to correct two earlier drafts that said parts of it were.** The `NEPacketTunnelProvider` subclass, the 27-method libbox `PlatformInterface` behind it, the app-side `NETunnelProviderManager`, the extension target in `app/ios/` and the Dart wiring are written, committed and compiled here; `Libbox.xcframework` is built by CI's `libbox_apple` job, not on that Mac. Nothing on this list waits on an Apple account. What it waits on is a device, which is step 10 — see §7.1. | this repository | n/a |
| 7 | Archive in Xcode, `Distribute App` → `TestFlight & App Store`, automatic signing, upload. | Account Holder, Admin, App Manager, Developer | yes |
| 8 | Answer the export compliance questions, or the build sits at `Missing Compliance` and nobody can install it. | Account Holder, Admin, App Manager | yes |
| 9 | Create an internal group; invite the testers — each must first be added as an App Store Connect user (up to 50 extra on an individual account). | Account Holder, Admin, App Manager, Developer, Marketing | yes |
| 10 | **Internal testing runs here. No reviewer is involved.** | | yes |
| 11 | Write the 5.4 disclosure screen and a privacy policy, fill in Beta App Description and Feedback Email. | colleague | yes |
| 12 | Create an external group, add the build, **Submit for Review**. | Account Holder, Admin, or App Manager | **unknown — this is the experiment in §3** |
| 13 | App Store release. | | **Organization. 5.4, no way around it.** |

Two notes on roles. If the colleague enrols as an individual they *are* the Account Holder and every
"Account Holder or Admin" row is simply them; the roles only start to matter when there is a team.
And a person you add on an individual account gets App Store Connect access only — no certificates,
no profiles, no ability to sign — which is exactly enough to be an internal tester.

## 6. What Apple offers instead of external TestFlight

Not workarounds — documented distribution methods, with their real costs:

- **Ad Hoc.** Sign for named devices and install directly. Up to **100 devices per product family
  per membership year**, reset only at the start of a new membership year, and disabling a device
  does not give the slot back
  ([Devices overview](https://developer.apple.com/help/account/devices/devices-overview)).
  No App Review of any kind. Cost: you need each tester's UDID, and you re-distribute by hand.
- **Development signing** on registered devices — same device pool, for the people building it.
- **Internal TestFlight**, which is the sweet spot for a handful of known people: no review, OTA
  updates, 90-day builds, and the testers do not need to hand over a UDID.

There is no route that puts a VPN app in front of strangers without App Review, and no route that
puts one on the App Store from an individual enrollment. A build signed by a paid membership is the
minimum for a tunnel that runs at all; that is what the capability matrix in §4 means.

## 7. What I could not verify

1. **None of the iOS Swift has ever RUN. It has been compiled, and that is a different claim.**
   The earlier version of this item said zero lines had been through a compiler; that stopped being
   true the moment `app/ios/` existed, and what the compiler found is the reason to be exact about
   it. Three commits are each a real build on a macOS runner, and each found a defect that four
   rounds of reading had not:

   - *"Commit the Xcode project, and fix the four errors the first real compile found"* — four
     errors, every one about a name **gomobile chooses** rather than a name in sing-box's Go source.
     `usePlatformAutoDetectInterfaceControl` and `autoDetectInterfaceControl` do not exist in the
     Apple binding; they are `usePlatformAutoDetectControl` and `autoDetectControl`, while the
     Android binding of the same Go interface keeps `Interface` in both. And `NWPath` is ambiguous —
     Network.framework has one and so does Libbox, and the extension imports both — qualified in
     three places. Those are exactly the symbol-name risk this item used to name as the largest in
     the Swift, and it was real.
   - *"Link UIKit into the extension, because libbox reaches for UIApplication"* — the Swift
     compiled, and the extension then failed to LINK on `_OBJC_CLASS_$_UIApplication` and
     `_UIBackgroundTaskInvalid`. Neither appears anywhere in this repository's Swift: they come out
     of libbox's own Apple binding, and an app extension links no UIKit by default. `-framework
     UIKit` and `-lresolv` sit in `OTHER_LDFLAGS` in the committed project and in the generator, so
     a regeneration does not reintroduce it.
   - *"Embed the extension before Thin Binary, or the build graph has a cycle"* — "Cycle inside
     Runner": the copy of `SingboxTunnel.appex` depended on Flutter's Thin Binary script, which
     reached `ExtractAppIntentsMetadata`, which reached the `[CP] Embed Pods Frameworks` phase
     CocoaPods appends *after* ours, which reached back to the copy.

   What that buys is worth stating exactly, because it is less than it sounds and more than
   nothing. The Swift type-checks against the real SDK; the libbox Objective-C symbol names it was
   written against are the ones `Libbox.xcframework` exports, which was the single largest risk in
   that code since they were derived from Go source and cross-checked only against the Android
   binding; and `check_extension.sh` asserts, against the BUILT bundle rather than the source plist,
   that `PlugIns/SingboxTunnel.appex` exists with an executable in it, declares
   `com.apple.networkextension.packet-tunnel`, and names an **expanded**
   `SingboxTunnel.PacketTunnelProvider` as its principal class.

   It proves nothing whatever about the tunnel working, and that is what to budget for. Nothing has
   run: no device, no simulator, no signing. So the entitlements are never validated against a
   provisioning profile, the App Group container is never opened, `NETunnelProviderManager` never
   saves a configuration, the system approval sheet is never raised, and the two undocumented routes
   to the utun file descriptor — KVC on `packetFlow`'s private `socket.fileDescriptor`, falling back
   to `LibboxGetTunnelFileDescriptor()` — are precisely the kind of thing that compiles and then
   returns nothing on a real phone. **The first genuine test of this code is a signed build on a
   device**, which is step 7 of §5 at the earliest and in practice step 10, when a tester installs
   it. Budget for the iOS tunnel needing real debugging at that point, on the colleague's Mac — and
   note what that debugging looks like: when a packet-tunnel provider refuses to start, iOS hands
   the app an `NEVPNStatus` of "disconnected" with no error and no text, which is why the extension
   writes its own reason into the App Group container, and why a start this process issued for which
   no status record exists now reports *that* — the extension did not launch, or could not open the
   App Group container, which on a target that has never been signed is the most likely failure of
   all and has no build-time symptom (`…/singbox_tunnel/ios/README.md` documents the status file and
   the rules that read it).
2. **Whether Beta App Review enforces 5.4's organization clause.** The central unknown, and
   **the single fact this plan turns on**. Apple publishes no scope for beta review; guideline 2.2
   points the whole guidelines document at beta builds. Everything else about Apple here is
   documented; this is not.
3. **Whether App Store Connect blocks an external beta submission until App Privacy answers exist.**
   The [privacy page](https://developer.apple.com/help/app-store-connect/manage-app-information/manage-app-privacy)
   ties nutrition labels to App Store distribution and does not mention TestFlight; I could not
   confirm either way for the beta path.
4. **The exact upload error for an unsigned `.ipa`.** Requirement documented, error codes
   (`ITMS-90035`/`ITMS-90034`) are forum-sourced, not Apple documentation.
5. **Anything requiring an Apple *account*.** No macOS and no Apple account was available to
   whoever wrote this: what has since been executed was executed by CI's macOS runners, which is
   `make lib_apple`, generating the extension target, and building it. Everything gated on a
   membership — automatic signing, provisioning profiles, the archive, the upload — is still read
   off Apple's documentation and not performed, by anybody, anywhere in this project. Item 1 is the
   expensive special case: a build is not a run.
6. **Whether Apple's account tooling refuses a VPN app record on an individual account.** Nothing in
   the help pages says so, and the capability matrix is keyed on program membership rather than
   entity type — but "documentation does not mention a block" is not "there is no block".
7. **The Apple Developer Program License Agreement** was not read; it is the contract that actually
   governs pre-release distribution, and it may say something the guidelines do not.

## 8. Sources

All fetched 2026-09-16. Only the first carries a date of its own.

- [App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/) — 5.4 and
  2.2. `Last Updated: June 8, 2026`.
- [TestFlight overview](https://developer.apple.com/help/app-store-connect/test-a-beta-version/testflight-overview) — tester counts, 90 days, the ambiguous review sentence.
- [Add internal testers](https://developer.apple.com/help/app-store-connect/test-a-beta-version/add-internal-testers) — 100 internal testers, roles, no review step.
- [Invite external testers](https://developer.apple.com/help/app-store-connect/test-a-beta-version/invite-external-testers) — 10,000, Submit for Review, six builds per 24h, appeals.
- [Provide test information](https://developer.apple.com/help/app-store-connect/test-a-beta-version/provide-test-information) — required for external only.
- [Provide export compliance information for beta builds](https://developer.apple.com/help/app-store-connect/test-a-beta-version/provide-export-compliance-information-for-beta-builds) and [Overview of export compliance](https://developer.apple.com/help/app-store-connect/manage-app-information/overview-of-export-compliance).
- [App build statuses](https://developer.apple.com/help/app-store-connect/reference/app-build-statuses) — the decisive `Ready to Submit` wording.
- [Upload builds](https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds) — upload roles, Xcode 26 requirement.
- [Add and edit users](https://developer.apple.com/help/app-store-connect/manage-your-team/add-and-edit-users) and [Overview of accounts and roles](https://developer.apple.com/help/app-store-connect/manage-your-team/overview-of-accounts-and-roles) — 50 users on an individual account.
- [Role permissions](https://developer.apple.com/help/app-store-connect/reference/role-permissions).
- [Certificates overview](https://developer.apple.com/help/account/certificates/certificates-overview) — only Account Holder or Admin creates distribution certificates.
- [Create an App Store Connect provisioning profile](https://developer.apple.com/help/account/provisioning-profiles/create-an-app-store-provisioning-profile), [Create an ad hoc provisioning profile](https://developer.apple.com/help/account/provisioning-profiles/create-an-ad-hoc-provisioning-profile), [Devices overview](https://developer.apple.com/help/account/devices/devices-overview).
- [Supported capabilities (iOS)](https://developer.apple.com/help/account/reference/supported-capabilities-ios) — Network Extensions: ADP and ADEP only.
- [Capability requests](https://developer.apple.com/help/account/capabilities/capability-requests) and [Provisioning with capabilities](https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities) — what "managed" means.
- [Enable app capabilities](https://developer.apple.com/help/account/identifiers/enable-app-capabilities), [Register an app group](https://developer.apple.com/help/account/identifiers/register-an-app-group).
- [Enroll](https://developer.apple.com/programs/enroll/) — organization requirements, 99 USD; [Compliance review](https://developer.apple.com/help/app-store-connect/reference/compliance-review).
- [Network Extensions Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension), [App Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.application-groups), [NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider), [NETunnelProviderManager](https://developer.apple.com/documentation/networkextension/netunnelprovidermanager), [Packet tunnel provider](https://developer.apple.com/documentation/networkextension/packet-tunnel-provider).
- [TN3134: Network Extension provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment) — revised 2025-08-19.
- [Distributing your app for beta testing and releases](https://developer.apple.com/documentation/xcode/distributing-your-app-for-beta-testing-and-releases), [Preparing your app for distribution](https://developer.apple.com/documentation/xcode/preparing-your-app-for-distribution).
- sing-box v1.14.0 `Makefile` (`lib_apple`), `cmd/internal/build_libbox/main.go` (`-iosversion=15.0`), and `SagerNet/sing-box-for-apple` `Extension/Extension.entitlements` — read at source, for what an Apple packet tunnel for this engine actually declares.
