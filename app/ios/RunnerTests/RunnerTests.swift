// `flutter create` writes this target, and this file is deliberately empty of
// tests. That is a decision, not an omission, and the alternative was tried on
// paper before it was rejected.
//
// Nothing in CI builds this bundle. `flutter build ios --release --no-codesign`
// builds the Runner SCHEME's build action, which lists Runner alone, so a
// compile error here would not turn a single job red -- an XCTest nobody
// compiles is worse than none, because it reads as coverage. Making it run means
// an `xcodebuild test` on a booted simulator, and that drags in the whole of
// Runner plus SingboxTunnel plus Libbox.xcframework's simulator slices and a
// signing identity this repository does not have.
//
// It would also assert the wrong things. The two facts this layer can get
// silently wrong are the identifier set the app and the extension must agree on,
// and the wire literals Dart, Kotlin and Swift each restate. Neither is
// reachable from here:
//
//   - The identifiers live in Info.plists and entitlements, and
//     tool/check_extension.sh already reads them -- from the SOURCES on every
//     push in the cheap ubuntu job, and from the BUILT bundle after the iOS
//     build, where the values are expanded. Restating them in Swift would be a
//     fourth spelling of what tool/ios_identifiers.sh defines once.
//
//   - TunnelWire's channel names and stage strings are pure and are exactly the
//     kind of thing a unit test should pin -- but the assertion that matters is
//     that the SWIFT literal equals the DART one, and a test bundle running on a
//     simulator cannot see lib/src/channels.dart. `TunnelWire` is also `internal`
//     to the pod's `singbox_tunnel` module, so reaching it would mean compiling
//     a third copy of the file into this bundle and then asserting its literals
//     against themselves, which is a tautology wearing a test's clothes. That
//     comparison belongs where all three files are readable at once, which is a
//     check over the repository, not over a device.
//
// What no test in any language can cover is the rest: an App Group iOS refuses
// because it was never registered against a signing team, and a provider iOS
// declines to instantiate. Both are runtime sandbox decisions on a signed build,
// and this target has never been signed or run.
//
// If a Flutter-side integration test is ever wanted, it goes in
// app/integration_test/ and is driven by `flutter test`, not from here.

import XCTest

class RunnerTests: XCTestCase {
}
