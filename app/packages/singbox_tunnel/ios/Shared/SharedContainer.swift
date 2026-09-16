// Where the app process and the extension process meet on disk.
//
// On Android the plugin and the VpnService are two objects in one process and
// TunnelState is a plain object between them. On iOS they are two PROCESSES in
// two sandboxes, and the only thing they both can open is the App Group
// container. Everything shared goes through here.
//
// Both identifiers are read from the running bundle's Info.plist rather than
// baked in, because both are chosen by whoever owns the Apple Developer account
// -- an App Group has to be registered against a real team id -- and a constant
// here would be a value nobody can change without editing Swift. Absent, they
// are named and refused: a plugin that silently fell back to a default would
// read one process's container and write another's, and the symptom would be a
// tunnel that starts and reports nothing.

import Foundation

/// A failure with text a person can act on. Every throw in this package
/// carries one of these, because the message is what the UI shows verbatim.
struct TunnelSetupError: LocalizedError {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var errorDescription: String? { message }
}

enum SharedContainer {
    /// Required in the Info.plist of BOTH the app and the extension.
    static let appGroupInfoKey = "SingboxTunnelAppGroup"

    /// Required in the app's Info.plist only. The extension does not look
    /// itself up.
    static let providerBundleInfoKey = "SingboxTunnelProviderBundleIdentifier"

    static func appGroupIdentifier() throws -> String {
        guard let value = Bundle.main.object(forInfoDictionaryKey: appGroupInfoKey) as? String,
              !value.isEmpty
        else {
            throw TunnelSetupError(
                "This build has no \(appGroupInfoKey) in its Info.plist, so the app and the "
                    + "tunnel extension have no shared container and cannot exchange the "
                    + "configuration or the failure text. Add the key with the App Group "
                    + "identifier (group.<your reverse-dns>.vpnstack) to the Info.plist of the "
                    + "app AND of the extension, and add that group to both targets' "
                    + "entitlements. Nothing was started.")
        }
        return value
    }

    static func providerBundleIdentifier() throws -> String {
        guard let value = Bundle.main.object(forInfoDictionaryKey: providerBundleInfoKey) as? String,
              !value.isEmpty
        else {
            throw TunnelSetupError(
                "This build has no \(providerBundleInfoKey) in its Info.plist, so it cannot say "
                    + "which packet-tunnel extension to run. Add the key with the extension "
                    + "target's bundle identifier (<app bundle id>.SingboxTunnel). If this app "
                    + "was produced by `flutter create` alone then there is no extension target "
                    + "at all and no iOS build can tunnel; see "
                    + "packages/singbox_tunnel/ios/README.md. Nothing was started.")
        }
        return value
    }

    static func directory() throws -> URL {
        let group = try appGroupIdentifier()
        guard let url = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: group)
        else {
            throw TunnelSetupError(
                "iOS refused the App Group \"\(group)\": this process has no container for it. "
                    + "The group is declared in Info.plist but not in this target's "
                    + "com.apple.security.application-groups entitlement, or it is not "
                    + "registered against the signing team. Nothing was started.")
        }
        return url
    }
}
