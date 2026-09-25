// The wire between Dart and iOS, restated from lib/src/channels.dart.
//
// Two literals, one contract; a mismatch shows up as MissingPluginException on
// the first call rather than as a tunnel that silently does nothing. Kotlin
// restates the same two strings in SingboxTunnelPlugin.kt for the same reason.
//
// Compiled into BOTH targets: the app-process plugin sends these stage strings
// to Dart, and the extension writes them into the shared status file, so a
// third spelling would show up as an unreadable status rather than as a build
// error.

import Foundation

enum TunnelWire {
    static let commandChannel = "io.github.asel1x/singbox_tunnel/commands"
    static let statusChannel = "io.github.asel1x/singbox_tunnel/status"

    /// The os_log subsystem, and the error domain of the two NSErrors this
    /// package has to build by hand. One string, because the extension's log is
    /// read with `log stream --subsystem <this>` and two spellings would hand
    /// somebody half a run.
    static let logSubsystem = "io.github.asel1x.singbox_tunnel"
}

/// The four stages the Dart interface declares. Nothing wider, so a state that
/// exists here but not there cannot be invented.
enum TunnelStage: String {
    case disconnected
    case connecting
    case connected
    case failed
}

struct TunnelStatus {
    let stage: TunnelStage
    let message: String?

    init(_ stage: TunnelStage, _ message: String? = nil) {
        self.stage = stage
        self.message = message
    }

    /// Shaped for `decodeStatus` in lib/src/singbox_tunnel.dart: `stage`
    /// always, `message` only when there is one. The key is omitted rather than
    /// carrying NSNull because Dart reads `event['message']` and treats a
    /// missing key as null already, while NSNull would arrive as a non-String
    /// and be dropped there anyway -- silently, which is the failure mode this
    /// whole layer is written against.
    func toEvent() -> [String: Any] {
        var event: [String: Any] = ["stage": stage.rawValue]
        if let message, !message.isEmpty {
            event["message"] = message
        }
        return event
    }
}
