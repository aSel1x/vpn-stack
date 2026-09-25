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
//
// THE MAIN QUEUE OWNS EVERY PROPERTY BELOW. On iOS the Flutter platform thread
// IS the main thread, so `handle` and the two stream methods already arrive on
// it; NetworkExtension is the other caller and it answers on queues of its own
// choosing, so every completion handler in this file hops through `onMain`
// before it reads or writes a property -- and so does the status notification.
// That is one rule instead of a lock per field, and it is the same hop the
// FlutterEventSink needs anyway: Flutter requires a result and a sink to be
// invoked on the platform thread, and calling one from an NE queue is a crash
// that looks like the failure it was reporting.

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

    /// Whether iOS has reported a session for `expectedStartId` as live -- any
    /// status other than disconnected or invalid -- since that id was issued.
    ///
    /// It is what separates "the extension has not answered yet" from "the
    /// extension never answered", and there is a real window between them:
    /// `startVPNTunnel` returns before the connection object flips to
    /// `connecting`, so a `status` call landing in that window reads
    /// `disconnected` for a start that is seconds old. Reporting a failure there
    /// would be a spurious one, which is the alarm people learn to ignore.
    private var sessionSeenLive = false

    /// Set when this process removed the VPN profile itself.
    ///
    /// iOS reports `.invalid` for a configuration that is gone, and that is
    /// normally a failure worth naming -- somebody deleted the profile in
    /// Settings under a running app. After `removeProfile` it is the expected
    /// end of a removal the app performed, so it must not be dressed up as one.
    private var profileRemovedByApp = false

    /// Runs `body` on the queue that owns this object's state, immediately when
    /// already there. See the header: the main queue is the Flutter platform
    /// thread, and NetworkExtension's completion handlers are not on it.
    private func onMain(_ body: @escaping () -> Void) {
        if Thread.isMainThread {
            body()
        } else {
            DispatchQueue.main.async(execute: body)
        }
    }

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
        events(currentStatus().toEvent())
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
        // Hopped before anything is read, not just before the sink is fed:
        // NEVPNStatusDidChange is posted on a queue of NE's choosing, and
        // `translate` both reads `providerBundleIdentifier` and writes
        // `expectedStartId` and `sessionSeenLive`.
        onMain {
            // Matched on the provider identifier rather than on object identity:
            // loadAllFromPreferences hands back every configuration this app has
            // ever created, and a status change belonging to some other provider
            // must not be reported as this tunnel's.
            guard let expected = self.providerBundleIdentifier,
                  let proto = connection.manager.protocolConfiguration
                      as? NETunnelProviderProtocol,
                  proto.providerBundleIdentifier == expected
            else {
                return
            }
            self.publish(self.translate(connection.status))
        }
    }

    private func publish(_ status: TunnelStatus) {
        // FlutterEventSink must be used from the platform thread. Every caller
        // in this file is already on it, and the hop stays because a sink fed
        // from an NE queue crashes the engine instead of reporting the failure
        // it was carrying -- the single loudest way to lose a diagnostic here.
        onMain { self.sink?(status.toEvent()) }
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
            sessionSeenLive = true
        }
        switch status {
        case .invalid:
            if profileRemovedByApp {
                // The app removed it, and this is iOS agreeing. Not the failure
                // below: nothing broke, nothing is missing that should be there,
                // and the person asked for exactly this.
                return TunnelStatus(
                    .disconnected,
                    "The VPN profile has been removed from this device. The credentials it "
                        + "carried are still valid on the server until `vpn user rm` runs there.")
            }
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
            return missingRecordStatus()
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

    /// iOS says the connection is down and there is no record of a run to read.
    /// Two very different situations, and collapsing them cost the only
    /// diagnostic this platform has.
    ///
    /// A cold launch onto a stopped tunnel, or a record belonging to a run this
    /// process neither started nor saw live, is plainly `disconnected`: nothing
    /// is running and nothing is known to be broken.
    ///
    /// A run THIS process started, that iOS reported live and then down, with no
    /// status of its own, is a failure and the only evidence of one. The
    /// extension writes `connecting` as its first act, before anything that can
    /// fail, so no record at all means it did not get that far: it never
    /// launched, or it could not open the App Group container. A tunnel that
    /// actually came up cannot land here -- `startBox` takes the same container
    /// for libbox's own paths and throws without it -- so this is not a healthy
    /// run misread.
    private func missingRecordStatus() -> TunnelStatus {
        guard expectedStartId != nil, sessionSeenLive else {
            return TunnelStatus(.disconnected)
        }
        return TunnelStatus(
            .failed,
            "The tunnel extension never wrote a status for this run: it did not launch, or it "
                + "could not open the App Group container. iOS reported the session up and then "
                + "down and says nothing about why, and the extension's own record -- the only "
                + "other account there is -- was never written. The likeliest cause on a build "
                + "that has not been signed for this device is an App Group mismatch: the "
                + "identifier in \(SharedContainer.appGroupInfoKey), in both targets' "
                + "com.apple.security.application-groups entitlements and registered against the "
                + "signing team has to be one string, and a disagreement is a sandbox refusal at "
                + "run time and nothing at all at build time. Nothing is being tunnelled.")
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
        case "removeProfile":
            removeProfile(result)
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
            // Cleared with the id it belongs to: whether iOS has reported THIS
            // run live is the question missingRecordStatus() asks, and a true
            // left over from the previous run would answer it about that one.
            self.sessionSeenLive = false
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
            // The configuration goes first, and before the stop rather than
            // after it: from the moment the person asks for the tunnel to end,
            // nothing on disk should be able to bring it back. iOS starts a
            // provider with no options from the Settings switch and reads
            // whatever is on file, so leaving it there is a tunnel that can come
            // up again, with a credential the app may have been told to forget,
            // without anybody choosing it. The running engine does not need the
            // file -- it has the configuration in memory -- and the extension
            // deletes it too on the same reason code, for the case where this
            // process is not running at all.
            let complaint = self.clearStartOptions()
            guard let manager else {
                // Tearing down nothing is not an error, and must not become one
                // by waiting for a status change nobody is going to send.
                self.publish(TunnelStatus(.disconnected, complaint))
                result(nil)
                return
            }
            let status = manager.connection.status
            if status == .disconnected || status == .invalid {
                self.publish(TunnelStatus(.disconnected, complaint))
                result(nil)
                return
            }
            manager.connection.stopVPNTunnel()
            if let complaint {
                // Published and not returned as an error: the tunnel is coming
                // down, which is what was asked for, and a failure result would
                // say it did not. The sentence still has to reach somebody,
                // because a configuration that would not delete is a credential
                // left in the container.
                self.publish(TunnelStatus(.connecting, complaint))
            }
            result(nil)
        }
    }

    /// Takes this app's VPN profile out of iOS and the configuration out of the
    /// shared container.
    ///
    /// Without this, the `NETunnelProviderManager` installed at the first
    /// connect outlives the app's own record of the server: deleting the server
    /// in the app left a row under Settings > General > VPN & Device Management
    /// that, when somebody flipped it, started the extension from
    /// `tunnel-start.json` -- a tunnel to a server the app no longer knows
    /// about, with a credential it had stopped showing anybody.
    ///
    /// It revokes NOTHING on the server, and the wording everywhere around this
    /// has to keep saying so: the VLESS UUID, the Hysteria2 password and every
    /// other credential in that configuration stay valid until `vpn user rm`
    /// runs on the server. What this removes is this device's copy and this
    /// device's ability to use it unattended. The app's own confirm dialog
    /// already tells the person that removal is local; this is what makes that
    /// true of the phone as well as of the app's database.
    private func removeProfile(_ result: @escaping FlutterResult) {
        resolveManager { manager, error in
            // Unconditionally, and before the profile: the credential is the
            // part that matters, and it has to go even when there is no manager
            // to remove or iOS refuses to remove it.
            let complaint = self.clearStartOptions()
            guard let manager else {
                if let error {
                    result(
                        FlutterError(
                            code: "no_configuration", message: error.message, details: nil))
                    return
                }
                // Nothing installed is the state this method exists to reach.
                self.forgetProfile()
                self.finishRemoval(complaint, result)
                return
            }
            manager.removeFromPreferences { removeError in
                self.onMain {
                    if let removeError {
                        result(
                            FlutterError(
                                code: "remove_failed",
                                message:
                                    "iOS refused to remove this app's VPN profile: "
                                    + "\(removeError.localizedDescription). It is still listed "
                                    + "under Settings > General > VPN & Device Management and can "
                                    + "still be switched on there; the configuration it would "
                                    + "start with has been deleted.",
                                details: nil))
                        return
                    }
                    self.forgetProfile()
                    self.finishRemoval(complaint, result)
                }
            }
        }
    }

    /// Drops everything this process knew about a profile that no longer exists,
    /// so that the `.invalid` iOS is about to report reads as the end of a
    /// removal rather than as a configuration somebody deleted behind the app's
    /// back, and so that no run of the old profile can be attributed to a new one.
    private func forgetProfile() {
        manager = nil
        expectedStartId = nil
        sessionSeenLive = false
        profileRemovedByApp = true
        publish(
            TunnelStatus(
                .disconnected,
                "The VPN profile has been removed from this device. The credentials it carried "
                    + "are still valid on the server until `vpn user rm` runs there."))
    }

    private func finishRemoval(_ complaint: String?, _ result: @escaping FlutterResult) {
        guard let complaint else {
            result(nil)
            return
        }
        // A failure here is the one part of a removal that is not cosmetic: the
        // profile is gone and the credential is not, which is the opposite of
        // what was asked for and has to be said rather than logged.
        result(FlutterError(code: "config_not_deleted", message: complaint, details: nil))
    }

    /// Deletes the persisted configuration, returning what to tell somebody when
    /// it could not be deleted. Nil is success, including "there was none".
    private func clearStartOptions() -> String? {
        do {
            try SharedState.clearStartOptions()
            return nil
        } catch {
            return
                "The sing-box configuration could not be deleted from the App Group container: "
                + "\(error.localizedDescription). It holds this server's credentials, so it is "
                + "worth knowing that it is still there."
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
            self.onMain {
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
                self.onMain {
                    if let saveError {
                        let unresolved = Self.isPermissionUnresolved(saveError)
                        completion(
                            SaveFailure(
                                message: unresolved
                                    ? "iOS did not install the VPN configuration for this app: "
                                        + "\(saveError.localizedDescription) (NEVPNErrorDomain "
                                        + "configurationReadWriteFailed). Without it no tunnel can "
                                        + "be started and no traffic is being routed -- but WHY it "
                                        + "refused is not something this build can tell you. That "
                                        + "one code comes back both when somebody taps Don't Allow "
                                        + "on the system's sheet and when this build's VPN "
                                        + "entitlement is missing or wrong, and Apple documents no "
                                        + "code for a declined sheet. Settings > General > VPN & "
                                        + "Device Management shows whether a configuration exists; "
                                        + "a refusal that repeats for every person on every launch "
                                        + "is the entitlement, not a person, and a decline can be "
                                        + "reversed by connecting again and approving."
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
                        self.onMain {
                            if let loadError {
                                completion(
                                    SaveFailure(
                                        message:
                                            "iOS saved the VPN configuration and then could not "
                                            + "read it back: \(loadError.localizedDescription). "
                                            + "Nothing was started.",
                                        permissionUnresolved: false))
                                return
                            }
                            self.manager = manager
                            // A configuration exists again, so the next
                            // `.invalid` is a configuration that went away and
                            // not the tail of a removal this app performed.
                            self.profileRemovedByApp = false
                            completion(nil)
                        }
                    }
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
