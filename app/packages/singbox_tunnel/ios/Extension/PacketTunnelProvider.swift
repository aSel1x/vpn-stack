// The tunnel, in the EXTENSION process.
//
// iOS gives a packet-tunnel provider its utun interface and gives it to nothing
// else, and libbox wants that file descriptor, so this class and LibboxPlatform
// are where the two meet. The split from Android is deliberate and forced: there
// `SingboxVpnService` is both the VpnService and the PlatformInterface in one
// object because `openTun` and `protect` are methods on the service; here
// `openTun` needs the provider (setTunnelNetworkSettings, packetFlow) but
// nothing else does, so the 27-method interface lives next door and holds a
// back-reference.
//
// Entry points, all read from sing-box v1.14.0 rather than remembered. They are
// the SAME entry points the Android side uses -- the Apple binding of
// experimental/libbox is the same package, bound by the same gomobile fork
// (Makefile lib_install pins sagernet/gomobile v0.1.13 for both) -- with the
// Objective-C naming rules applied:
//
//   * `LibboxSetup(LibboxSetupOptions, &error)` -- setup.go:106. Must run first:
//     it sets the paths `baseContext` hands to the file manager.
//   * `LibboxNewCommandServer(handler, platformInterface, &error)` --
//     command_server.go:54. v1.14.0 has no BoxService; the service lives behind
//     this.
//   * `commandServer.startOrReloadService(_:options:)` -- command_server.go:199.
//     Synchronous, and NOT the proof it looks like: daemon/started_service.go
//     has a branch where an interrupted start clears the instance and returns
//     without surfacing that. The check that a TUN was really opened is below,
//     and it is the thing that lets this file report connected.
//   * `commandServer.closeService()` / `close()` -- command_server.go:214 / :187.
//   * `LibboxGetTunnelFileDescriptor()` -- tun_darwin.go:11, an Apple-only
//     function with no Android counterpart. See LibboxPlatform.openTun.

import Foundation
import Libbox
import NetworkExtension
import os

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = OSLog(subsystem: TunnelWire.logSubsystem, category: "tunnel")

    /// One queue, and everything that touches libbox runs on it.
    /// `startOrReloadService` brings the entire box up inside the call, which is
    /// seconds; interleaving it with a stop is a use-after-close of the command
    /// server.
    ///
    /// IT ALSO OWNS EVERY PROPERTY BELOW -- `commandServer`, `startId`,
    /// `reportedFailure` and the one-shot initialisation of `platform` -- and the
    /// entry points iOS calls on its own thread, startTunnel, stopTunnel, sleep
    /// and wake, hop onto it before touching one. `sleep` reading `commandServer`
    /// while a start is still building it is the same race as a stop interleaved
    /// with a start, and it ends the same way: a pause() or a wake() on a server
    /// that is being replaced underneath it. A `lazy var` is not thread-safe
    /// either, and `platform` is the object holding the tun evidence.
    private let worker = DispatchQueue(label: "\(TunnelWire.logSubsystem).worker")

    private var commandServer: LibboxCommandServer?
    private lazy var platform = LibboxPlatform(self)

    /// Stamped on every status this run writes, so the app can tell this run's
    /// account of itself from the last one's.
    private var startId = ""

    /// Whether this run has already written a `failed` status.
    ///
    /// iOS calls stopTunnel after a start that failed as well as after a healthy
    /// run, and the second write would replace the only account of what broke --
    /// "libbox setup failed: ..." -- with a bland "the tunnel was stopped". The
    /// app has no other channel for that sentence: a provider's start failure
    /// reaches nobody through NEVPNStatus.
    private var reportedFailure = false

    override func startTunnel(
        options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void
    ) {
        worker.async { [self] in
            // Before anything that can fail, so that even a failure to find the
            // configuration is attributable to a run the app is waiting on. A
            // status written under an empty id is one the app is right to
            // ignore, and ignoring it would cost the only account of what went
            // wrong.
            //
            // Taken from `options` alone, and deliberately NOT by reading the
            // file here as well: that record carries the whole sing-box
            // configuration, and decoding all of it for one field -- twice,
            // because resolveStartOptions reads it again below -- is exactly the
            // kind of transient copy that gets a network extension killed at
            // Apple's ceiling, which DTS puts at 50 MiB for iOS 15 and later. A
            // start with no options is one iOS issued by itself, from the switch
            // in Settings or by relaunching a provider it killed, so there is no
            // app waiting on an id for it; resolveStartOptions reuses the
            // persisted one a moment later, which is what re-attributes a
            // relaunch to the run the app is still watching.
            startId = (options?[StartOptions.startIdKey] as? String) ?? ""
            do {
                try startBox(options: options)
                writeStatus(.connected, nil)
                completionHandler(nil)
            } catch {
                // This text reaches the app through the shared file and through
                // nothing else: iOS hands a provider's start failure to nobody.
                writeStatus(.failed, error.localizedDescription)
                releaseEngine()
                completionHandler(error)
            }
        }
    }

    private func startBox(options: [String: NSObject]?) throws {
        let resolved = try resolveStartOptions(options)
        startId = resolved.startId
        writeStatus(.connecting, "Starting sing-box.")

        let directory = try SharedContainer.directory()
        let setup = LibboxSetupOptions()
        setup.basePath = directory.path
        setup.workingPath = directory.appendingPathComponent("working").path
        setup.tempPath = directory.appendingPathComponent("temp").path
        setup.crashReportSource = "singbox_tunnel"
        // The RETAINED log, sized for the process that cannot afford one.
        // libbox keeps the last `logMaxLines` entries in memory and trims the
        // front once the list is longer (daemon/started_service.go:2095-2097);
        // they are replayed to a command client that asks for SavedLog, and
        // nothing in this app connects to that socket. Meanwhile this is the
        // packet-tunnel provider: Apple publishes no memory limit for one, DTS
        // posts 50 MiB for iOS 15 and later against 15 MiB before it and says
        // in the same paragraph not to hard-code the number
        // (developer.apple.com/forums/thread/73148), and libbox takes that
        // figure seriously enough to derive Go's own soft limit from it --
        // oomKillerEnabled on iOS sets debug.SetMemoryLimit to 4/5 of
        // DefaultAppleNetworkExtensionMemoryLimit, 50 MiB at
        // service/oomkiller/policy.go:13 (experimental/libbox/setup.go:92-97).
        // This asked for 3,000 retained entries while
        // SingboxVpnService.setupLibbox() asks for none, so the phone process
        // with a whole app's heap kept nothing and the constrained one hoarded.
        // 100 is noise against that ceiling and is deliberately not zero: zero
        // is what libbox defaults to and it retains nothing at all, so a client
        // that ever does attach would get an empty buffer instead of a short
        // replay. The live log subscription is unaffected by either.
        setup.logMaxLines = 100
        // A network extension is held to a hard memory ceiling and the system
        // kills it without a word when it is crossed. sing-box's own killer at
        // least leaves a report behind, which is the difference between a
        // tunnel that "just drops" and one that says why.
        setup.oomKillerEnabled = true
        var setupError: NSError?
        LibboxSetup(setup, &setupError)
        if let setupError {
            throw TunnelSetupError(
                "libbox setup failed: \(setupError.localizedDescription). Nothing was started.")
        }

        // Deliberately NOT LibboxCheckConfig (config.go:50) first. It builds a
        // second box under a stub platform interface to validate, which is a
        // second parser that can disagree with the one that matters;
        // startOrReloadService parses the same bytes in the real context and its
        // error is the one worth reporting.
        var serverError: NSError?
        guard let server = LibboxNewCommandServer(platform, platform, &serverError) else {
            throw TunnelSetupError(
                "libbox refused to create its command server: "
                    + "\(serverError?.localizedDescription ?? "(no message)"). Nothing was "
                    + "started.")
        }
        commandServer = server
        try server.start()
        try server.startOrReloadService(resolved.configContent, options: LibboxOverrideOptions())

        // The one fact that separates a tunnel from a running process. libbox
        // calls openTun only if the configuration contains a `tun` inbound, and
        // this package deliberately does not read the configuration -- it takes
        // whatever Dart hands it. Hand it a proxy-only config and sing-box
        // starts cleanly, setTunnelNetworkSettings is never called, no packet is
        // routed, and without this check iOS would report .connected and the UI
        // would say Connected. The app's builder does emit a tun inbound today,
        // but that is a convention in another package, and a convention is not a
        // check at the boundary this package says is the boundary.
        guard platform.didOpenTun else {
            throw TunnelSetupError(
                "sing-box started but never asked for a TUN interface, so nothing is being "
                    + "routed. The configuration has no `tun` inbound.")
        }
    }

    /// What to start.
    ///
    /// `options` is nil whenever iOS starts this provider itself -- the VPN
    /// switch in Settings, or the system relaunching an extension it killed --
    /// so the dictionary cannot be the only source. The persisted copy is what
    /// makes those paths work instead of dying on "no configuration" with the
    /// switch flipping back and no explanation.
    private func resolveStartOptions(_ options: [String: NSObject]?) throws -> StartOptions {
        if let options,
           let startId = options[StartOptions.startIdKey] as? String,
           let config = options[StartOptions.configContentKey] as? String,
           !config.isEmpty
        {
            return StartOptions(
                startId: startId, configContent: config,
                label: (options[StartOptions.labelKey] as? String) ?? "")
        }
        guard let persisted = try SharedState.readStartOptions(), !persisted.configContent.isEmpty
        else {
            throw TunnelSetupError(
                "This tunnel was started without a sing-box configuration and none was on file. "
                    + "iOS starts a provider with no options when the VPN switch in Settings is "
                    + "used; connect once from the app first, which is what writes the "
                    + "configuration the switch then reuses.")
        }
        // The persisted startId is reused rather than replaced. The app's own
        // expectation is the id of the configuration it last handed over, and
        // that is exactly the configuration this start is running.
        return persisted
    }

    override func stopTunnel(
        with reason: NEProviderStopReason, completionHandler: @escaping () -> Void
    ) {
        worker.async { [self] in
            // A failure this run already named is left exactly as it stands:
            // see reportedFailure, the specific cause is the whole diagnostic
            // and this is the call that would bury it.
            if !reportedFailure {
                if let failure = Self.failure(for: reason) {
                    writeStatus(.failed, failure)
                } else {
                    writeStatus(.disconnected, "The tunnel was stopped: \(Self.describe(reason)).")
                }
            }
            // The persisted configuration carries the credential -- the VLESS
            // UUID, or the Hysteria2 password and its obfs password -- and it is
            // kept for exactly one reason: so that a provider iOS starts with no
            // options can find what to run. A stop the person asked for and a
            // profile that has been removed both retire that reason, and after
            // either one the file is only a credential sitting in a container
            // that anything holding the switch in Settings could spend. Every
            // other reason leaves it: a run the system killed at its memory
            // ceiling is relaunched with no options and has to find it.
            if reason == .userInitiated || reason == .configurationRemoved {
                do {
                    try SharedState.clearStartOptions()
                } catch {
                    os_log(
                        "could not delete the persisted configuration: %{public}@", log: log,
                        type: .error, error.localizedDescription)
                }
            }
            releaseEngine()
            completionHandler()
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        worker.async { [self] in
            commandServer?.pause()
            completionHandler()
        }
    }

    override func wake() {
        worker.async { [self] in
            commandServer?.wake()
        }
    }

    /// Called by LibboxPlatform.serviceStop(), which is how libbox asks the host
    /// to stop it. cancelTunnelWithError is the only way a provider ends itself;
    /// stopTunnel then runs and does the teardown, so nothing is duplicated here.
    func stopFromEngine(_ error: Error?) {
        cancelTunnelWithError(error)
    }

    func writeStatus(_ stage: TunnelStage, _ message: String?) {
        if stage == .failed {
            reportedFailure = true
        }
        do {
            try SharedState.writeStatus(
                SharedTunnelStatus(
                    startId: startId, stage: stage.rawValue, message: message,
                    updatedAt: Date().timeIntervalSince1970))
        } catch {
            // Logged and not thrown: failing to write the status file must not
            // turn a tunnel that came up into one that reports failure. The cost
            // is that the app sees a bare "disconnected" if this ever happens,
            // which is why the message says where to look.
            os_log(
                "could not write the shared status file: %{public}@", log: log, type: .error,
                error.localizedDescription)
        }
    }

    func writeLog(_ message: String) {
        os_log("%{public}@", log: log, type: .default, message)
    }

    /// Closes the engine and the monitors. Safe to call twice.
    private func releaseEngine() {
        if let commandServer {
            do {
                try commandServer.closeService()
            } catch {
                os_log(
                    "closeService: %{public}@", log: log, type: .error, error.localizedDescription)
            }
            commandServer.close()
        }
        commandServer = nil
        platform.reset()
    }

    /// The text for a stop that is a FAILURE, or nil when it is an ending.
    ///
    /// The four here are the ones where the tunnel went away, the person did not
    /// ask for that, and it is not coming back on its own -- which is the rule
    /// SingboxVpnService.onRevoke follows on the other platform. Reported as a
    /// clean disconnect they arrive in the UI as a tunnel that simply stopped,
    /// and the next thing anybody does is look for a bug in the configuration.
    ///
    /// `.noNetworkAvailable` is deliberately NOT here. It is the one stop with an
    /// obvious external cause and an obvious next move, the tunnel is expected
    /// back with the network, and calling that a failure would put a red screen
    /// in front of somebody walking into a lift.
    private static func failure(for reason: NEProviderStopReason) -> String? {
        switch reason {
        case .providerFailed:
            return
                "iOS stopped the tunnel because this extension failed. Nothing is being tunnelled. "
                + "The usual cause is the system terminating it at its memory ceiling; sing-box's "
                + "own OOM killer leaves a crash report in the App Group container when it gets "
                + "there first."
        case .configurationFailed:
            return
                "iOS stopped the tunnel because the VPN configuration it was started from is not "
                + "usable. Nothing is being tunnelled. That is the profile this app installs, not "
                + "the sing-box configuration inside it: reinstall it by connecting again."
        case .connectionFailed:
            return
                "iOS stopped the tunnel because the connection failed. Nothing is being tunnelled."
        case .unrecoverableNetworkChange:
            return
                "iOS stopped the tunnel after a network change it could not carry the session "
                + "across. Nothing is being tunnelled; connecting again establishes a new session "
                + "on the network the device is on now."
        default:
            return nil
        }
    }

    private static func describe(_ reason: NEProviderStopReason) -> String {
        // Named where the text is worth having and the rest by number, on
        // purpose: NEProviderStopReason gains cases between SDKs, and a switch
        // that enumerates all of them is a build error on the first runner image
        // that ships a newer one.
        switch reason {
        case .userInitiated:
            return "the user turned it off"
        case .providerDisabled:
            return "the configuration was disabled"
        case .configurationDisabled:
            return "the configuration was switched off"
        case .configurationRemoved:
            return "the configuration was removed"
        case .superceded:
            return "another VPN took over"
        case .noNetworkAvailable:
            return "there was no network"
        case .idleTimeout:
            return "it was idle"
        case .sleep:
            return "the device went to sleep"
        case .appUpdate:
            return "the app was updated"
        default:
            return "NEProviderStopReason \(reason.rawValue)"
        }
    }
}
