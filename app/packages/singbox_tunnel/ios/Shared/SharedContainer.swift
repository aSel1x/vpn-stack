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
//
// So the two KEY names below are the constants this package owns, and the group
// identifier itself is not one. tool/ios_project.rb writes the group key into
// both Info.plists and the provider key into the app's, from its own
// APP_GROUP_INFO_KEY and PROVIDER_INFO_KEY, and that pair is what a checker holds
// against these two lines: a third spelling of either is a nil lookup at run time
// and nothing at all at build time.

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
        try resolved.get()
    }

    /// Resolved once per process, and that is not only an optimisation.
    ///
    /// Neither answer can change while the process lives: the Info.plist key is
    /// baked into the bundle and `containerURL` maps a sandbox extension the
    /// system hands over at launch. Every read and write of the two shared
    /// files goes through here -- several per status transition -- and the
    /// backup exclusion below is a file-system write that must happen once and
    /// not on every one of them. A Swift static's initialiser runs exactly once,
    /// lazily, under swift_once, which is also what makes this safe from the
    /// goroutines libbox calls the extension on.
    private static let resolved: Result<URL, TunnelSetupError> = {
        () -> Result<URL, TunnelSetupError> in
        let group: String
        do {
            group = try SharedContainer.appGroupIdentifier()
        } catch let error as TunnelSetupError {
            return .failure(error)
        } catch {
            return .failure(TunnelSetupError(error.localizedDescription))
        }
        guard let url = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: group)
        else {
            return .failure(
                TunnelSetupError(
                    "iOS refused the App Group \"\(group)\": this process has no container for it. "
                        + "The group is declared in Info.plist but not in this target's "
                        + "com.apple.security.application-groups entitlement, or it is not "
                        + "registered against the signing team. Nothing was started."))
        }
        SharedContainer.excludeFromBackup(url)
        return .success(url)
    }()

    /// Keeps the container out of Finder and iCloud backups.
    ///
    /// `tunnel-start.json` holds the sing-box configuration, which carries the
    /// VLESS UUID or the Hysteria2 password and its obfs password -- the
    /// credential itself, not a reference to one. A Group Container is backed up
    /// like the rest of the app's data, so without this flag every credential
    /// this device has ever been handed rides into an unencrypted local backup
    /// and into iCloud, where the person who deleted the server in the app has
    /// no idea it still is. Restoring the device would also bring back a
    /// configuration for a server that may since have been rebuilt.
    ///
    /// Best-effort by design: a container that cannot take the flag is still a
    /// container the tunnel has to run out of, and refusing to start over a
    /// backup attribute would trade a working VPN for a hardening measure. The
    /// exclusion covers the directory, so every file this package writes is
    /// under it without each write having to remember.
    private static func excludeFromBackup(_ url: URL) {
        var target = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? target.setResourceValues(values)
    }
}
