// The bridge, in the APP process: a MethodChannel for commands, an EventChannel
// for status. Same contract as SingboxTunnelPlugin.kt, different machine
// underneath, and the difference is the whole shape of this file.
//
// On Android the tunnel is a VpnService in THIS process: the plugin starts it
// with an Intent, and the service holds the TUN descriptor a few objects away.
// On iOS the tunnel is a separate PROCESS -- a NEPacketTunnelProvider app
// extension that the system launches, sandboxes and may kill -- and this app
// never touches a packet. What it does instead:
//
//   * Permission is not an Activity result. It is the user approving a VPN
//     configuration, and the only thing that raises that prompt is
//     `saveToPreferences`. So `requestPermission` SAVES -- and iOS publishes no
//     code that means "they declined", so this file reports a permission it
//     could not resolve rather than a no. See isPermissionUnresolved.
//   * `start` launches nothing directly. It writes the configuration, enables
//     it, re-loads it -- an in-memory manager older than the one on disk makes
//     `startVPNTunnel` throw `configurationStale` -- and starts a session.
//   * Status is the system's NEVPNStatusDidChange, not a state object this
//     process owns.
//
// It owns no tunnel state of its own, for the reason the Kotlin gives:
// everything it reports comes from the system's view of the connection plus the
// status file the extension writes, so a screen rebuilt after the engine was
// detached sees what the tunnel knows and not what this object remembers.

import Flutter
import Foundation
import NetworkExtension

public class SingboxTunnelPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let instance = SingboxTunnelPlugin()
        let commands = FlutterMethodChannel(
            name: TunnelWire.commandChannel, binaryMessenger: registrar.messenger())
        registrar.addMethodCallDelegate(instance, channel: commands)
        let status = FlutterEventChannel(
            name: TunnelWire.statusChannel, binaryMessenger: registrar.messenger())
        status.setStreamHandler(instance)
        // Before Dart listens, not on the first listen: loading the preferences
        // is what hands this process its NEVPNConnection objects, and until one
        // exists NEVPNStatusDidChange never fires here at all. A tunnel that was
        // already up when the app launched would otherwise render as
        // disconnected until something happened to change it, which for a
        // healthy tunnel is never.
        instance.resolveManager { _, _ in }
    }

    private var sink: FlutterEventSink?
    private var manager: NETunnelProviderManager?
    private var providerBundleIdentifier: String?

    /// Which run of the extension this process is entitled to read a status
    /// file for. Nil until we start one, or until iOS reports a session that is
    /// live right now and its id is adopted from the file that run is writing.
    private var expectedStartId: String?

    private var lastPublished = TunnelStatus(.disconnected)

    // ---- status ----

    public func onListen(withArguments _: Any?, eventSink events: @escaping FlutterEventSink)
        -> FlutterError?
    {
        sink = events
        NotificationCenter.default.addObserver(
            self, selector: #selector(vpnStatusDidChange(_:)),
            name: .NEVPNStatusDidChange, object: nil)
        // Replayed immediately, then corrected once the preferences come back.
        // currentStatus() and not the last thing published, because `register`'s
        // load has usually returned by now: a screen built while the tunnel is
        // already up must not render as disconnected until something happens to
        // change it, which for a healthy tunnel is never.
        let known = currentStatus()
        lastPublished = known
        events(known.toEvent())
        resolveManager { _, _ in
            self.publish(self.currentStatus())
        }
        return nil
    }

    public func onCancel(withArguments _: Any?) -> FlutterError? {
        NotificationCenter.default.removeObserver(self, name: .NEVPNStatusDidChange, object: nil)
        sink = nil
        return nil
    }

    @objc private func vpnStatusDidChange(_ notification: Notification) {
        guard let connection = notification.object as? NEVPNConnection else {
            return
        }
        // Matched on the provider identifier rather than on object identity:
        // loadAllFromPreferences hands back every configuration this app has
        // ever created, and a status change belonging to some other provider
        // must not be reported as this tunnel's.
        guard let expected = providerBundleIdentifier,
              let proto = connection.manager.protocolConfiguration as? NETunnelProviderProtocol,
              proto.providerBundleIdentifier == expected
        else {
            return
        }
        publish(translate(connection.status))
    }

    private func publish(_ status: TunnelStatus) {
        lastPublished = status
        // FlutterEventSink must be used from the platform thread. NE delivers
        // its completion handlers on queues of its own choosing, so without this
        // hop the first status of a failing start would crash the engine instead
        // of reporting the failure.
        if Thread.isMainThread {
            sink?(status.toEvent())
        } else {
            DispatchQueue.main.async { self.sink?(status.toEvent()) }
        }
    }

    private func currentStatus() -> TunnelStatus {
        guard let manager else {
            // No configuration installed: nothing is running and nothing is
            // broken. Not `failed`, because never having connected is not a
            // failure -- it is the state every fresh install is in.
            return TunnelStatus(.disconnected)
        }
        return translate(manager.connection.status)
    }

    private func translate(_ status: NEVPNStatus) -> TunnelStatus {
        // Anything other than down or invalid means iOS has a session for this
        // configuration right now, and that session is what makes a status file
        // this process did not start evidence about the present. Adopted here
        // rather than inside sharedStatus(), and for every live status and not
        // just the ones that read a message, so that a run already going when
        // the app launched is still attributable after it ends -- otherwise a
        // real crash mid-session would be reported as a clean disconnect.
        if status != .disconnected, status != .invalid {
            adoptRunningStartId()
        }
        switch status {
        case .invalid:
            return TunnelStatus(
                .failed,
                "The VPN configuration this app installed is gone -- removed under Settings > "
                    + "General > VPN & Device Management, or invalidated by the system. Nothing "
                    + "is being tunnelled. Connecting again reinstalls it and asks for approval.")
        case .disconnected:
            return disconnectedStatus()
        case .connecting:
            return TunnelStatus(.connecting, sharedStatus()?.message)
        case .connected:
            // The one place this file says connected, and it is not a guess:
            // iOS reports .connected only after the extension called its
            // startTunnel completion handler with no error, and
            // PacketTunnelProvider does that only after libbox asked for a TUN
            // interface and got one. There is no path here that reports it on a
            // timer or on an assumption.
            return TunnelStatus(.connected)
        case .reasserting:
            return TunnelStatus(
                .connecting, "The network changed and the tunnel is re-establishing.")
        case .disconnecting:
            // Busy, not down. It is not down yet, and saying otherwise here is
            // the one lie disconnect()'s own timeout refuses to tell; the
            // contract has four stages and busy is the only truthful bucket.
            return TunnelStatus(.connecting, "The tunnel is being torn down.")
        @unknown default:
            return TunnelStatus(
                .failed,
                "Unknown NEVPNStatus \(status.rawValue) from iOS. This build and the system "
                    + "disagree about what states a VPN connection has; refusing to guess which "
                    + "one the tunnel is in.")
        }
    }

    /// iOS says the connection is down. What the extension said last decides
    /// whether that was an ending or a failure.
    private func disconnectedStatus() -> TunnelStatus {
        guard let shared = sharedStatus() else {
            // Either nothing has run since this app launched, or the only
            // record on disk belongs to a run this process neither started nor
            // ever saw live. Nothing is running and nothing is known to be
            // broken, which is exactly what a launch onto a stopped tunnel is.
            return TunnelStatus(.disconnected)
        }
        switch shared.stage {
        case TunnelStage.failed.rawValue:
            return TunnelStatus(
                .failed,
                shared.message
                    ?? "The tunnel extension reported failure without saying why. That is a bug "
                    + "in PacketTunnelProvider, which is required to name what broke.")
        case TunnelStage.disconnected.rawValue:
            return TunnelStatus(.disconnected, shared.message)
        default:
            // The extension's last word was connecting or connected and the
            // system says the connection is down: it went away without writing
            // a reason. Reported as a failure and not as a clean disconnect,
            // for the reason SingboxVpnService.onRevoke gives -- the app asked
            // for a tunnel, no longer has one, and did not stop it itself.
            return TunnelStatus(
                .failed,
                "The tunnel extension stopped without saying why: iOS reports the connection "
                    + "down while the extension's own last word, \(Self.age(of: shared)) ago, "
                    + "was \"\(shared.stage)\". The usual cause is the system terminating it "
                    + "-- a network extension is held to a hard memory ceiling -- or a crash. "
                    + "Nothing is being tunnelled.")
        }
    }

    /// The extension's last word about THIS run, or nil.
    ///
    /// Keyed to a run, and never to the file's age. `tunnel-status.json` is
    /// durable while a run is not, and `expectedStartId` is nil on every cold
    /// launch, so adopting whatever id the file happened to hold turned the
    /// LAST run's account into this launch's: after the system killed the
    /// extension, the next launch read `connected` out of a record nobody had
    /// written that day, saw iOS report the connection down, and published
    /// "the tunnel extension stopped without saying why" for a start that had
    /// never happened.
    ///
    /// Of the three ways to tie the record down, this is the session.
    /// `updatedAt` cannot be the gate: no age threshold is derivable, because a
    /// healthy tunnel runs for days without writing a status, so old does not
    /// mean stale and young does not mean this run's. NEVPNStatus already
    /// carries the fact the question is actually about -- whether a session
    /// exists at all -- so an id this process did not issue is adopted only
    /// while iOS reports one live (adoptRunningStartId, from translate), and a
    /// record matching no expected id is not evidence about anything.
    ///
    /// Adopted once, and deliberately never re-adopted on a mismatch: while a
    /// start this process issued is in flight the file still holds the PREVIOUS
    /// run's id, so re-adopting would pull that record back in and rebuild the
    /// bug. The cost is narrow and is the right way round -- a tunnel started
    /// from the Settings switch after an adopted one, inside the same app
    /// launch, carries no message, so its ending reads as a plain disconnect
    /// instead of as a manufactured failure.
    private func sharedStatus() -> SharedTunnelStatus? {
        guard let expectedStartId, let status = try? SharedState.readStatus() else {
            return nil
        }
        return status.startId == expectedStartId ? status : nil
    }

    /// Takes the id of the run iOS says is live, once, so this process can read
    /// that run's status file afterwards.
    private func adoptRunningStartId() {
        guard expectedStartId == nil, let status = try? SharedState.readStatus() else {
            return
        }
        expectedStartId = status.startId
    }

    /// How long ago the extension wrote that record, out of `updatedAt`.
    /// Reported and never tested -- sharedStatus() says why the freshness
    /// decision belongs to the session and not to the clock -- but a human
    /// reading a failure needs to know whether the extension fell over just now
    /// or an hour into the run.
    private static func age(of status: SharedTunnelStatus) -> String {
        // Clamped before the Int conversion, not after. The lower bound is
        // because both halves are wall clock read in two processes and a clock
        // correction between them must not print a negative age; the upper one
        // is because converting a Double outside Int's range TRAPS, and this
        // number arrives from a file on disk.
        let elapsed = Date().timeIntervalSince1970 - status.updatedAt
        guard elapsed.isFinite else {
            return "an unknown time"
        }
        return "\(Int(min(max(elapsed, 0), 3_153_600_000)))s"
    }

    // ---- commands ----

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "prepare":
            prepare(result)
        case "requestPermission":
            requestPermission(result)
        case "status":
            result(currentStatus().toEvent())
        case "start":
            start(call, result)
        case "stop":
            stop(result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    /// True when a VPN configuration for this app's extension already exists.
    ///
    /// The iOS counterpart of `VpnService.prepare() == null`: an installed
    /// configuration is exactly the consent Android records. The third case --
    /// never asking, and starting a session that quietly establishes nothing --
    /// is the one this plugin refuses to have, which is why the absence is
    /// false rather than an optimistic true.
    private func prepare(_ result: @escaping FlutterResult) {
        resolveManager { manager, error in
            if let error {
                result(FlutterError(code: "no_configuration", message: error.message, details: nil))
                return
            }
            result(manager != nil)
        }
    }

    /// Saves the configuration, which is what raises the system's approval
    /// sheet. There is no separate permission API on iOS.
    private func requestPermission(_ result: @escaping FlutterResult) {
        installConfiguration(label: nil) { failure in
            guard let failure else {
                result(true)
                return
            }
            if failure.permissionUnresolved {
                // Neither true nor false, and this used to be false. To Dart
                // `false` is "they declined" and `true` is "go ahead and open a
                // tunnel"; iOS answered with a code that means neither, so the
                // honest channel is the error one. The Android side reserves it
                // for the same thing -- the cases where it could not GET an
                // answer rather than got a no (SingboxTunnelPlugin.kt:129
                // and :139), while its own no is a real RESULT_OK comparison
                // on :156.
                result(
                    FlutterError(
                        code: "permission_unresolved", message: failure.message, details: nil))
                return
            }
            result(FlutterError(code: "save_failed", message: failure.message, details: nil))
        }
    }

    private func start(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let config = arguments["config"] as? String, !config.isEmpty
        else {
            result(
                FlutterError(
                    code: "no_config",
                    message:
                        "start was called without a sing-box configuration. The plugin does not "
                        + "build one -- app/lib/config/ does -- so there is nothing to fall back "
                        + "to.",
                    details: nil))
            return
        }
        let label = (arguments["label"] as? String) ?? ""
        let startId = UUID().uuidString

        installConfiguration(label: label) { failure in
            if let failure {
                self.publish(TunnelStatus(.failed, failure.message))
                result(
                    FlutterError(
                        code: failure.permissionUnresolved
                            ? "permission_unresolved" : "save_failed",
                        message: failure.message, details: nil))
                return
            }
            guard let session = self.manager?.connection as? NETunnelProviderSession else {
                let message =
                    "The saved VPN configuration is not a packet-tunnel session, so there is "
                    + "nothing to start. The extension's bundle identifier in Info.plist names a "
                    + "target that is not a NEPacketTunnelProvider."
                self.publish(TunnelStatus(.failed, message))
                result(FlutterError(code: "no_session", message: message, details: nil))
                return
            }
            do {
                // Persisted as well as passed: iOS starts a provider with no
                // options when the VPN switch in Settings is used, or when it
                // relaunches one it killed, and that start has to find a
                // configuration somewhere or it dies with the switch flipping
                // back and no explanation.
                try SharedState.writeStartOptions(
                    StartOptions(startId: startId, configContent: config, label: label))
            } catch {
                let message =
                    "Could not write the configuration into the App Group container: "
                    + "\(error.localizedDescription). Nothing was started."
                self.publish(TunnelStatus(.failed, message))
                result(FlutterError(code: "no_shared_container", message: message, details: nil))
                return
            }
            self.expectedStartId = startId
            // Set here rather than waiting for the system's first status, so
            // there is no window in which a start has been asked for and the
            // status still reads disconnected.
            self.publish(TunnelStatus(.connecting))
            do {
                try session.startVPNTunnel(options: [
                    StartOptions.startIdKey: startId as NSObject,
                    StartOptions.configContentKey: config as NSObject,
                    StartOptions.labelKey: label as NSObject,
                ])
            } catch {
                let message =
                    "iOS refused to start the tunnel session: \(error.localizedDescription). "
                    + "Nothing is running."
                self.publish(TunnelStatus(.failed, message))
                result(
                    FlutterError(code: "session_start_failed", message: message, details: nil))
                return
            }
            result(nil)
        }
    }

    private func stop(_ result: @escaping FlutterResult) {
        resolveManager { manager, error in
            if let error {
                result(FlutterError(code: "no_configuration", message: error.message, details: nil))
                return
            }
            guard let manager else {
                // Tearing down nothing is not an error, and must not become one
                // by waiting for a status change nobody is going to send.
                self.publish(TunnelStatus(.disconnected))
                result(nil)
                return
            }
            let status = manager.connection.status
            if status == .disconnected || status == .invalid {
                self.publish(TunnelStatus(.disconnected))
                result(nil)
                return
            }
            manager.connection.stopVPNTunnel()
            result(nil)
        }
    }

    // ---- the NETunnelProviderManager ----

    private struct SaveFailure {
        let message: String
        /// The save came back as NEVPNErrorDomain configurationReadWriteFailed,
        /// which is a permission outcome this build cannot resolve either way.
        /// It is NOT "the user said no": see isPermissionUnresolved.
        let permissionUnresolved: Bool
    }

    private func resolveManager(
        _ completion: @escaping (NETunnelProviderManager?, TunnelSetupError?) -> Void
    ) {
        let expected: String
        do {
            expected = try SharedContainer.providerBundleIdentifier()
        } catch {
            completion(nil, TunnelSetupError(error.localizedDescription))
            return
        }
        providerBundleIdentifier = expected
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error {
                completion(
                    nil,
                    TunnelSetupError(
                        "iOS could not read this app's VPN configurations: "
                            + "\(error.localizedDescription). Nothing was started."))
                return
            }
            let mine = (managers ?? []).first { candidate in
                (candidate.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerBundleIdentifier == expected
            }
            self.manager = mine
            completion(mine, nil)
        }
    }

    /// Creates or updates this app's VPN configuration and saves it. The save is
    /// what asks the user, the first time.
    private func installConfiguration(
        label: String?, _ completion: @escaping (SaveFailure?) -> Void
    ) {
        resolveManager { existing, lookupError in
            if let lookupError {
                completion(SaveFailure(message: lookupError.message, permissionUnresolved: false))
                return
            }
            guard let expected = self.providerBundleIdentifier else {
                completion(
                    SaveFailure(
                        message: "No provider bundle identifier; nothing was started.",
                        permissionUnresolved: false))
                return
            }

            let manager = existing ?? NETunnelProviderManager()
            let proto =
                (manager.protocolConfiguration as? NETunnelProviderProtocol)
                ?? NETunnelProviderProtocol()
            proto.providerBundleIdentifier = expected
            // Shown in Settings > VPN as the server, and used to reach nothing:
            // the address the tunnel actually dials comes out of the sing-box
            // configuration, which the app builds and the extension is handed.
            // It is still set, because an empty serverAddress makes the row in
            // Settings unidentifiable when more than one VPN is installed.
            if let label, !label.isEmpty {
                proto.serverAddress = label
                manager.localizedDescription = label
            } else {
                proto.serverAddress = proto.serverAddress ?? "vpn-stack"
                manager.localizedDescription = manager.localizedDescription ?? "vpn-stack"
            }
            manager.protocolConfiguration = proto
            manager.isEnabled = true
            // Never on demand. On-demand rules make iOS start the tunnel on its
            // own schedule, which would mean a tunnel coming up with a
            // configuration the user has not chosen and a UI that did not ask
            // for it -- and the extension would be started with no options,
            // reaching for whatever was last on disk.
            manager.isOnDemandEnabled = false
            manager.onDemandRules = nil

            manager.saveToPreferences { saveError in
                if let saveError {
                    let unresolved = Self.isPermissionUnresolved(saveError)
                    completion(
                        SaveFailure(
                            message: unresolved
                                ? "iOS did not install the VPN configuration for this app: "
                                    + "\(saveError.localizedDescription) (NEVPNErrorDomain "
                                    + "configurationReadWriteFailed). Without it no tunnel can be "
                                    + "started and no traffic is being routed -- but WHY it "
                                    + "refused is not something this build can tell you. That one "
                                    + "code comes back both when somebody taps Don't Allow on the "
                                    + "system's sheet and when this build's VPN entitlement is "
                                    + "missing or wrong, and Apple documents no code for a "
                                    + "declined sheet. Settings > General > VPN & Device "
                                    + "Management shows whether a configuration exists; a refusal "
                                    + "that repeats for every person on every launch is the "
                                    + "entitlement, not a person, and a decline can be reversed by "
                                    + "connecting again and approving."
                                : "iOS refused to save the VPN configuration: "
                                    + "\(saveError.localizedDescription). Nothing was started.",
                            permissionUnresolved: unresolved))
                    return
                }
                // Re-read, always. saveToPreferences leaves this in-memory
                // manager older than the record it just wrote, and
                // startVPNTunnel on a stale manager throws
                // NEVPNError.configurationStale instead of starting anything.
                manager.loadFromPreferences { loadError in
                    if let loadError {
                        completion(
                            SaveFailure(
                                message:
                                    "iOS saved the VPN configuration and then could not read it "
                                    + "back: \(loadError.localizedDescription). Nothing was "
                                    + "started.",
                                permissionUnresolved: false))
                        return
                    }
                    self.manager = manager
                    completion(nil)
                }
            }
        }
    }

    /// Whether iOS answered with the one code that might mean the person
    /// declined -- and might equally mean this build can never install a VPN.
    ///
    /// It is not a denial signal, and this file used to report it as one. Apple
    /// documents NEVPNError.configurationReadWriteFailed as "An error code that
    /// indicates an error occurred while reading or writing the Network
    /// Extension preferences"
    /// (developer.apple.com/documentation/networkextension/nevpnerror/code) and
    /// documents no code at all for a declined approval sheet. What developers
    /// report -- not measured here, this repository has no device to reproduce
    /// it on -- is that a decline comes back as NEVPNErrorDomain code 5, which
    /// is this same case (`NEVPNErrorConfigurationReadWriteFailed = 5` in
    /// NEVPNManager.h), rendered as "permission denied": Apple Developer Forums
    /// 705943. So does a missing or wrong Personal VPN / Network Extension
    /// entitlement, which is what most reports of that code turn out to be
    /// (threads 742777 and 807080), and so does an IPC failure inside the
    /// framework (thread 727592). One code, opposite next moves: approve the
    /// sheet, or rebuild the app with the right entitlement. So it is carried
    /// as unresolved, the caller says exactly that, and nobody is told they
    /// refused something they may never have been asked.
    private static func isPermissionUnresolved(_ error: Error) -> Bool {
        let nsError = error as NSError
        guard nsError.domain == NEVPNErrorDomain else {
            return false
        }
        return nsError.code == NEVPNError.Code.configurationReadWriteFailed.rawValue
    }
}
