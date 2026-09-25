# The identifiers the iOS app, its packet-tunnel extension and their App Group
# are built from — one definition, read by tool/ios_project.rb (which writes
# them into app/ios/) and by tool/check_extension.sh (which asserts what was
# written). The same principle scripts/check.sh applies to the sing-box tag:
# two literals drift, and this drift is invisible, because every one of these
# strings is compared at RUNTIME by iOS and by nothing at build time. A mismatch
# between the App Group in an entitlement and the App Group in an Info.plist is
# a sandbox denial on the first connect, on a target that has never been signed.
#
# Shell syntax, because the checker has to run on ubuntu-latest in the cheap
# `check` job and nothing outside a macOS runner has the xcodeproj gem. Ruby
# reads it with the six-line parser in ios_project.rb, which expands `$NAME`
# against the names already defined above it — so the DERIVED values are stated
# once as the derivation rule they are, rather than twice as literals.
#
# packages/singbox_tunnel/ios/README.md is the spec these are quoted from.
# Changing APP_BUNDLE_ID means re-registering an App ID and an App Group against
# a real Apple team, so it is not a rename anybody does casually.

APP_TARGET=Runner

# The target name, not the directory name: the sources live in Extension/ but
# two things read this string — the bundle identifier below, and
# NSExtensionPrincipalClass, which resolves through $(PRODUCT_MODULE_NAME), the
# target name with non-identifier characters replaced. Renaming the target
# renames the Swift module and breaks the principal-class lookup with no build
# error, only a provider iOS cannot instantiate.
EXT_TARGET=SingboxTunnel

# `flutter create --org io.github.asel1x --project-name vpn_stack_app` derives
# it (createUTIIdentifier, create_base.dart:595); leave --org off and it is
# com.example forever.
APP_BUNDLE_ID=io.github.asel1x.vpnStackApp

# Nested under the app's, because iOS refuses to install an extension whose
# identifier is not a prefix-extension of its container app's, at install time,
# with no useful text. Exactly one component deeper: two components is the same
# refusal.
EXT_BUNDLE_ID=$APP_BUNDLE_ID.$EXT_TARGET

APP_GROUP=group.$APP_BUNDLE_ID

# Read by Shared/SharedContainer.swift out of the running bundle's Info.plist in
# both processes, rather than baked into Swift, because both values belong to
# whoever owns the Apple Developer account. The key NAMES are the contract, and
# they are asserted here because SharedContainer throws on a missing key at the
# first connect and not before.
APP_GROUP_INFO_KEY=SingboxTunnelAppGroup
# The app's Info.plist only. The extension does not look itself up.
PROVIDER_INFO_KEY=SingboxTunnelProviderBundleIdentifier

NE_ENTITLEMENT=com.apple.developer.networking.networkextension
NE_ENTITLEMENT_VALUE=packet-tunnel-provider
GROUPS_ENTITLEMENT=com.apple.security.application-groups

# iOS decides what kind of extension this is from this string alone.
EXTENSION_POINT=com.apple.networkextension.packet-tunnel
PROVIDER_CLASS=PacketTunnelProvider

# 15.0 is libbox's floor, not a preference: build_libbox passes -iosversion=15.0
# (cmd/internal/build_libbox/main.go:206), so that is the minimum of every slice
# in Libbox.xcframework.
DEPLOYMENT_TARGET=15.0
SWIFT_VERSION=5.0

# Where the platform package lives, relative to app/. Here because it is spelled
# three times otherwise: tool/ios_project.rb resolves it against app/ios/ for
# $(SRCROOT), tool/unpack_libbox.sh resolves it against app/ to put the bytes
# there, and the Xcode file reference has to name the same directory as the
# FRAMEWORK_SEARCH_PATHS entry. Three spellings of one path is one path that can
# be moved in two of them.
PACKAGE_SUBDIR=packages/singbox_tunnel/ios
