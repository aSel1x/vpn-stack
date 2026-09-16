// The two files in the App Group container, and why each one exists.
//
// `tunnel-start.json` -- what to start. iOS starts a packet-tunnel provider
// with NO options when the switch in Settings is used, or when the system
// relaunches a provider it killed. `startVPNTunnel(options:)` is not the only
// entry point, so the configuration cannot live only in that dictionary.
//
// `tunnel-status.json` -- why it stopped. This is the one that is not
// optional. iOS hands the app NOTHING when a provider refuses to start: the
// connection goes connecting -> disconnected and NEVPNStatus carries no reason,
// no error and no text. Without a file written by the process that knows, every
// failure in this package would reach the UI as a bare "disconnected", which is
// exactly the summarised-into-nothing that TunnelStatus.message forbids.
//
// Every record carries the startId of the run that wrote it, and the moment it
// was written. The ID is what ties a record to a run: a status file is durable
// and a run is not, so without it the app reads the LAST run's failure as this
// run's -- which it did, until SingboxTunnelPlugin.sharedStatus() stopped
// adopting the id of a run it had never seen live.
//
// `updatedAt` is written for the human and is deliberately NOT a second gate.
// No threshold separates a healthy tunnel that has been quiet for a day from a
// record left behind by a run that died ten minutes ago, so the plugin prints
// it in the failure text ("its last word, 4s ago") and never compares it
// against anything.

import Foundation

struct StartOptions: Codable {
    static let startIdKey = "startId"
    static let configContentKey = "configContent"
    static let labelKey = "label"

    let startId: String
    let configContent: String
    let label: String
}

struct SharedTunnelStatus: Codable {
    let startId: String
    let stage: String
    let message: String?
    /// Seconds since the epoch, wall clock, from the extension process. Read
    /// only to say how long ago that process last spoke; see the header.
    let updatedAt: Double
}

enum SharedState {
    private static let statusFileName = "tunnel-status.json"
    private static let startOptionsFileName = "tunnel-start.json"

    static func writeStatus(_ status: SharedTunnelStatus) throws {
        try write(status, to: statusFileName)
    }

    static func readStatus() throws -> SharedTunnelStatus? {
        try read(SharedTunnelStatus.self, from: statusFileName)
    }

    static func writeStartOptions(_ options: StartOptions) throws {
        try write(options, to: startOptionsFileName)
    }

    static func readStartOptions() throws -> StartOptions? {
        try read(StartOptions.self, from: startOptionsFileName)
    }

    private static func write<T: Encodable>(_ value: T, to name: String) throws {
        let url = try SharedContainer.directory().appendingPathComponent(name)
        let data = try JSONEncoder().encode(value)
        // completeUntilFirstUserAuthentication, not the default: a packet-tunnel
        // provider can be started by the system before the device has been
        // unlocked since boot, and a file written under complete protection is
        // unreadable there -- so the provider would fail to find its own
        // configuration and the app would get no reason why.
        //
        // .atomic as well, for the reason users.json is written through a temp
        // file on the server: a half-written record read by the other process
        // decodes as nothing, and "nothing" is indistinguishable from "no run
        // has happened", which is the wrong answer.
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    private static func read<T: Decodable>(_ type: T.Type, from name: String) throws -> T? {
        let url = try SharedContainer.directory().appendingPathComponent(name)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return nil
        }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(type, from: data)
    }
}
