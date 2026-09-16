// Everything sing-box asks the host for.
//
// The interface is the SAME one the Android side implements --
// `PlatformInterface`, 27 methods, sing-box v1.14.0
// experimental/libbox/platform.go:5, plus `CommandServerHandler`'s 7 from
// command_server.go:43 -- because the Apple binding and the Android binding are
// the same Go package through the same gomobile fork. What differs is the
// naming rules and four of the answers:
//
//   * `usePlatformAutoDetectInterfaceControl` is FALSE here and true there.
//     Android needs it because every outbound socket has to go through
//     `VpnService.protect` or it matches the default route the tunnel just
//     installed and loops back into its own tun. iOS has no protect() and needs
//     none: a NEPacketTunnelProvider's own sockets are excluded from the
//     interface it installs by the system. Returning true would promise a
//     callback that cannot be honoured.
//   * `openTun` does not build an interface, it DESCRIBES one:
//     setTunnelNetworkSettings, and then the file descriptor has to be
//     recovered (see below) rather than returned by the call that created it.
//   * `underNetworkExtension` is true, which is what it is asking.
//   * `localDNSTransport` is nil. Android returns a resolver bound to a named
//     Network so the VPN server's own hostname is resolved off-tunnel; iOS
//     exposes no such handle, nil is legal (config.go:31 checks for it) and
//     libbox falls back to its own local transport, whose queries leave from the
//     extension process -- which the system already keeps out of the tunnel.
//
// Kotlin and Swift both make an implementer provide every method whether or not
// this app's configurations can reach it, so the ones it cannot reach are
// written here, once, either as the honest constant answer or as a throw naming
// what is missing. None of them is a silent default: a method that returns a
// plausible-looking value for a question it cannot answer is how a tunnel comes
// up routing nothing.

import Foundation
import Libbox
import Network
import NetworkExtension
import UserNotifications

final class LibboxPlatform: NSObject, LibboxPlatformInterfaceProtocol,
    LibboxCommandServerHandlerProtocol
{
    private unowned let provider: PacketTunnelProvider

    /// Set by [openTun] and read by PacketTunnelProvider once
    /// `startOrReloadService` has returned. It is the difference between a
    /// tunnel and a process.
    private(set) var didOpenTun = false

    private var networkSettings: NEPacketTunnelNetworkSettings?
    private var pathMonitor: NWPathMonitor?

    init(_ provider: PacketTunnelProvider) {
        self.provider = provider
        super.init()
    }

    func reset() {
        pathMonitor?.cancel()
        pathMonitor = nil
        networkSettings = nil
        didOpenTun = false
    }

    // ---- the two only a packet-tunnel provider can answer ----

    func openTun(_ options: LibboxTunOptionsProtocol?, ret0_: UnsafeMutablePointer<Int32>?) throws {
        guard let options else {
            throw TunnelSetupError("libbox called openTun with no options; no interface was created.")
        }
        guard let ret0_ else {
            throw TunnelSetupError(
                "libbox called openTun with no return pointer; no interface was created.")
        }
        if options.isHTTPProxyEnabled() {
            // Thrown rather than skipped. A configuration that asks for a system
            // HTTP proxy and silently does not get one is a tunnel that looks up
            // and routes the wrong traffic, which is the class of failure this
            // whole file is written against.
            throw TunnelSetupError(
                "The configuration asks for a system HTTP proxy (tun.platform.http_proxy) and "
                    + "this build does not install one. app/lib/config/ emits no http_proxy, so "
                    + "reaching this means the configuration came from somewhere else.")
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = NSNumber(value: options.getMTU())

        // The tun's ADDRESSES, and the throw when there are none, sit OUTSIDE
        // the auto_route branch. SingboxVpnService.openTun counts them at
        // SingboxVpnService.kt:239-252, before its own `if (options.autoRoute)`
        // on :256, and this file used to put both inside -- which cost exactly
        // what that ordering buys: with `auto_route: false` iOS was handed a
        // NEPacketTunnelNetworkSettings carrying neither ipv4Settings nor
        // ipv6Settings, accepted it, didOpenTun went true, the provider's own
        // "sing-box never asked for a TUN" guard passed, NEVPNStatus reached
        // .connected -- and not one packet was routed. That
        // app/lib/config/singbox_config.dart:78 defaults autoRoute to true is
        // the "convention in another package" this file's header refuses to
        // treat as a check.
        var inet4Addresses: [String] = []
        var inet4Masks: [String] = []
        if let iterator = options.getInet4Address() {
            while iterator.hasNext() {
                guard let prefix = iterator.next() else { continue }
                inet4Addresses.append(prefix.address())
                inet4Masks.append(prefix.mask())
            }
        }
        var inet6Addresses: [String] = []
        var inet6Prefixes: [NSNumber] = []
        if let iterator = options.getInet6Address() {
            while iterator.hasNext() {
                guard let prefix = iterator.next() else { continue }
                inet6Addresses.append(prefix.address())
                inet6Prefixes.append(NSNumber(value: prefix.prefix()))
            }
        }
        if inet4Addresses.isEmpty, inet6Addresses.isEmpty {
            throw TunnelSetupError(
                "The configuration gave the tun no address; there is nothing to establish.")
        }

        let ipv4 = NEIPv4Settings(addresses: inet4Addresses, subnetMasks: inet4Masks)
        let ipv6 = NEIPv6Settings(addresses: inet6Addresses, networkPrefixLengths: inet6Prefixes)

        if options.getAutoRoute() {
            var dnsSettings: NEDNSSettings?
            if let mode = options.getDNSMode(), mode.value != LibboxDNSModeDisabled {
                var servers: [String] = []
                let iterator = try options.getDNSServerAddress()
                while iterator.hasNext() {
                    servers.append(iterator.next())
                }
                if !servers.isEmpty {
                    let resolved = NEDNSSettings(servers: servers)
                    settings.dnsSettings = resolved
                    dnsSettings = resolved
                }
            }

            // The route ADDRESSES and the exclusions, not the precomputed route
            // ranges the Android side uses. Android needs the ranges because
            // addRoute/excludeRoute with IpPrefix is API 33 and every device
            // below it would need a second path that reproduces libbox's own
            // subtraction. NEIPv4Settings has excludedRoutes at every version
            // this builds for, so the subtraction stays where libbox put it.
            var inet4Routes: [NEIPv4Route] = []
            if let iterator = options.getInet4RouteAddress() {
                while iterator.hasNext() {
                    guard let prefix = iterator.next() else { continue }
                    inet4Routes.append(
                        NEIPv4Route(destinationAddress: prefix.address(), subnetMask: prefix.mask()))
                }
            }
            if inet4Routes.isEmpty {
                inet4Routes.append(NEIPv4Route.default())
            }
            var inet4Excluded: [NEIPv4Route] = []
            if let iterator = options.getInet4RouteExcludeAddress() {
                while iterator.hasNext() {
                    guard let prefix = iterator.next() else { continue }
                    inet4Excluded.append(
                        NEIPv4Route(destinationAddress: prefix.address(), subnetMask: prefix.mask()))
                }
            }
            ipv4.includedRoutes = inet4Routes
            ipv4.excludedRoutes = inet4Excluded

            var inet6Routes: [NEIPv6Route] = []
            if let iterator = options.getInet6RouteAddress() {
                while iterator.hasNext() {
                    guard let prefix = iterator.next() else { continue }
                    inet6Routes.append(
                        NEIPv6Route(
                            destinationAddress: prefix.address(),
                            networkPrefixLength: NSNumber(value: prefix.prefix())))
                }
            }
            if inet6Routes.isEmpty, !inet6Addresses.isEmpty {
                inet6Routes.append(NEIPv6Route.default())
            }
            var inet6Excluded: [NEIPv6Route] = []
            if let iterator = options.getInet6RouteExcludeAddress() {
                while iterator.hasNext() {
                    guard let prefix = iterator.next() else { continue }
                    inet6Excluded.append(
                        NEIPv6Route(
                            destinationAddress: prefix.address(),
                            networkPrefixLength: NSNumber(value: prefix.prefix())))
                }
            }
            ipv6.includedRoutes = inet6Routes
            ipv6.excludedRoutes = inet6Excluded

            // Without a default route, iOS only sends this tunnel the queries
            // for domains it is told to match, and the DNS servers above would
            // be consulted for nothing.
            let hasDefaultRoute = inet4Routes.contains {
                $0.destinationAddress == "0.0.0.0" && $0.destinationSubnetMask == "0.0.0.0"
            }
            if !hasDefaultRoute {
                dnsSettings?.matchDomains = [""]
                dnsSettings?.matchDomainsNoSearch = true
            }
        } else {
            // Empty and explicit, not left unset. Apple documents includedRoutes
            // as "The IPv4 network traffic that the system routes to the TUN
            // interface" and documents no behaviour for the property's default,
            // so an unset one would leave the routing of this interface to
            // something this build has not read. The configuration asked for no
            // auto-route: an interface with addresses and no system routes is
            // what that means, and it is the same tun Android builds when
            // `options.autoRoute` is false.
            ipv4.includedRoutes = []
            ipv6.includedRoutes = []
        }
        settings.ipv4Settings = ipv4
        settings.ipv6Settings = ipv6

        try applyNetworkSettings(settings)

        // iOS publishes no supported way to get the utun file descriptor a
        // provider was given, and libbox needs exactly that. Two routes, in this
        // order, and a throw when neither works -- because the alternative is
        // returning a descriptor that is not the tunnel's and having sing-box
        // write packets into nothing while everything reports connected.
        //
        // 1. KVC on packetFlow's private `socket.fileDescriptor`. Undocumented,
        //    and what every sing-box, WireGuard and Outline build on this
        //    platform uses.
        // 2. LibboxGetTunnelFileDescriptor() -- tun_darwin.go:11 -- which scans
        //    this process's first 1024 descriptors for one whose peer is a
        //    com.apple.net.utun_control socket. libbox ships it for exactly the
        //    day Apple closes route 1.
        if let fd = provider.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32 {
            ret0_.pointee = fd
            didOpenTun = true
            return
        }
        let scanned = LibboxGetTunnelFileDescriptor()
        if scanned != -1 {
            ret0_.pointee = scanned
            didOpenTun = true
            return
        }
        throw TunnelSetupError(
            "iOS accepted the tunnel network settings but this build could not find the tun file "
                + "descriptor: packetFlow's socket.fileDescriptor is not readable and libbox's "
                + "utun scan found nothing. Nothing is being routed.")
    }

    private func applyNetworkSettings(_ settings: NEPacketTunnelNetworkSettings) throws {
        let semaphore = DispatchSemaphore(value: 0)
        var failure: Error?
        provider.setTunnelNetworkSettings(settings) { error in
            failure = error
            semaphore.signal()
        }
        // Bounded, and the bound is the point. libbox calls openTun from a Go
        // goroutine and blocks it until this returns, so a completion handler
        // that never fires would hang the extension with the UI on "connecting"
        // for ever. A timeout that says what it does not know is the honest end
        // of that; guessing that the settings applied is not.
        if semaphore.wait(timeout: .now() + 30) == .timedOut {
            throw TunnelSetupError(
                "iOS did not answer setTunnelNetworkSettings within 30s. Whether the tunnel "
                    + "interface was installed is unknown, and this build will not claim it was.")
        }
        if let failure {
            throw TunnelSetupError(
                "iOS refused the tunnel network settings: \(failure.localizedDescription). No "
                    + "interface was installed.")
        }
        networkSettings = settings
    }

    // ---- what sing-box uses on this platform ----

    /// False, and that is not a gap. On Android this is what routes every
    /// outbound socket through `VpnService.protect`; iOS has no equivalent and
    /// needs none, because the system keeps the extension's own traffic out of
    /// the interface the extension installs.
    func usePlatformAutoDetectInterfaceControl() -> Bool {
        false
    }

    func autoDetectInterfaceControl(_ fd: Int32) throws {
        throw TunnelSetupError(
            "ios: autoDetectInterfaceControl(\(fd)) was called although "
                + "usePlatformAutoDetectInterfaceControl() is false. There is no protect() on "
                + "this platform, so this cannot be answered; the contract moved.")
    }

    func startDefaultInterfaceMonitor(_ listener: LibboxInterfaceUpdateListenerProtocol?) throws {
        guard let listener else {
            return
        }
        let monitor = NWPathMonitor()
        pathMonitor = monitor
        let firstPath = DispatchSemaphore(value: 0)
        monitor.pathUpdateHandler = { [weak self] path in
            self?.publishDefaultInterface(listener, path)
            firstPath.signal()
        }
        monitor.start(queue: DispatchQueue.global())
        // Waited for, because sing-box starts dialling as soon as this returns
        // and `route.auto_detect_interface` has nothing to detect until the
        // first path arrives. Bounded for the reason above: a wait with no
        // ceiling turns a monitor that never reports into an extension that
        // never answers.
        if firstPath.wait(timeout: .now() + 10) == .timedOut {
            throw TunnelSetupError(
                "NWPathMonitor reported no network path within 10s, so sing-box has no default "
                    + "interface to bind outbound sockets to. Nothing was started.")
        }
    }

    private func publishDefaultInterface(
        _ listener: LibboxInterfaceUpdateListenerProtocol, _ path: NWPath
    ) {
        guard path.status != .unsatisfied, let first = path.availableInterfaces.first else {
            // -1, not the last known interface: reporting a stale one makes
            // sing-box bind to a link that is gone, which fails as a timeout
            // rather than as a network change.
            listener.updateDefaultInterface(
                "", interfaceIndex: -1, isExpensive: false, isConstrained: false)
            return
        }
        listener.updateDefaultInterface(
            first.name, interfaceIndex: Int32(first.index), isExpensive: path.isExpensive,
            isConstrained: path.isConstrained)
    }

    func closeDefaultInterfaceMonitor(_: LibboxInterfaceUpdateListenerProtocol?) throws {
        pathMonitor?.cancel()
        pathMonitor = nil
    }

    /// Every interface the current path offers, with the link flags and the
    /// MTU sing-box decodes.
    ///
    /// `UsePlatformNetworkInterfaces` is hard-coded true in libbox
    /// (service.go:120), so this list is the only thing sing-box's interface
    /// finder can resolve the default interface against, and an empty answer
    /// does not degrade gracefully.
    ///
    /// Name, index, type and metered come from NWPath. Flags, MTU and addresses
    /// cannot: NWInterface carries none of them, and they are not decoration --
    /// libbox reads `.MTU` and `linkFlags(.Flags)` into a `control.Interface`
    /// (service.go:140 and :143), and sing v0.9.0-beta.4's
    /// `DefaultInterfaceFinder.ByAddr` skips every interface that does not
    /// carry `net.FlagRunning` (common/control/bind_finder_default.go:117
    /// and :127). Left unset they are zero, which reports every interface as
    /// DOWN with MTU 0 -- upstream sing-box-for-apple's
    /// `ExtensionPlatformInterface.getInterfaces()` still answers that way, and
    /// that is not evidence the fields are unread. So they are read from
    /// getifaddrs(3) instead, whose `ifa_flags` are already the BSD IFF_* bits
    /// libbox decodes: `linkFlags` is built for every unix including darwin
    /// (link_flags_unix.go), so the bit layout on both sides of the binding is
    /// the same one and nothing is translated. The Android side has to
    /// synthesize Linux flags from NetworkCapabilities (LibboxPlatform.kt:135)
    /// because it starts from a source that has none.
    ///
    /// `dnsServer` and `gateway` stay empty, and that is a gap with a named
    /// cost, not a decision. getifaddrs reports neither: the gateways would
    /// need a `sysctl(NET_RT_DUMP)` walk of the routing table and the resolvers
    /// a `res_ninit`, and neither is reachable from the Swift side without C
    /// interop this package does not have. What that costs: libbox's platform
    /// DNS transport answers `Environment()` from the default interface's
    /// `DNSServers` (dns.go:73), so it gets nothing here and libbox's local
    /// transport falls back to the process's own resolver configuration --
    /// which on iOS is the system's. Nothing in sing-box v1.14.0 reads
    /// `Gateways` back at all; adapter/network.go:82 declares it and
    /// service.go:147 fills it.
    func getInterfaces() throws -> LibboxNetworkInterfaceIteratorProtocol {
        guard let pathMonitor else {
            throw TunnelSetupError(
                "ios: getInterfaces() was called before startDefaultInterfaceMonitor(), so there "
                    + "is no network path to read. Reporting no interfaces would be read as a "
                    + "device with no network, which is a different thing.")
        }
        let path = pathMonitor.currentPath
        if path.status == .unsatisfied {
            return NetworkInterfaceList([])
        }
        let links = Self.readLinks()
        var interfaces: [LibboxNetworkInterface] = []
        for available in path.availableInterfaces {
            let entry = LibboxNetworkInterface()
            entry.name = available.name
            entry.index = Int32(available.index)
            switch available.type {
            case .wifi:
                entry.type = LibboxInterfaceTypeWIFI
            case .cellular:
                entry.type = LibboxInterfaceTypeCellular
            case .wiredEthernet:
                entry.type = LibboxInterfaceTypeEthernet
            default:
                entry.type = LibboxInterfaceTypeOther
            }
            entry.metered = path.isExpensive
            if let link = links[available.name] {
                entry.flags = link.flags
                entry.mtu = link.mtu
                entry.addresses = StringList(link.addresses)
            } else {
                // Still reported, because dropping it would make ByIndex fail
                // for an interface the path says exists -- but said out loud,
                // because with the flags at zero sing-box reads it as down.
                // getifaddrs not listing what NWPath just offered means the two
                // disagree, and a silent zero here is the failure this whole
                // method was rewritten to stop.
                provider.writeLog(
                    "getInterfaces: getifaddrs did not list \(available.name), which NWPath "
                        + "offers. Its flags, MTU and addresses are unknown, so sing-box will read "
                        + "it as down with MTU 0.")
            }
            interfaces.append(entry)
        }
        return NetworkInterfaceList(interfaces)
    }

    private struct Link {
        var flags: Int32 = 0
        var mtu: Int32 = 0
        var addresses: [String] = []
    }

    /// getifaddrs(3), folded by interface name.
    ///
    /// One pass answers all three: `ifa_flags` is repeated on every entry an
    /// interface has, the MTU exists only on its AF_LINK entry (in `if_data`),
    /// and the addresses are its AF_INET and AF_INET6 entries. An empty map is
    /// returned rather than a throw when the call fails: getInterfaces() above
    /// says what is missing per interface, and losing the whole list would be
    /// the "device with no network" answer it refuses to give.
    private static func readLinks() -> [String: Link] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let head else {
            return [:]
        }
        defer { freeifaddrs(head) }
        var links: [String: Link] = [:]
        for cursor in sequence(first: head, next: { $0.pointee.ifa_next }) {
            let entry = cursor.pointee
            let name = String(cString: entry.ifa_name)
            var link = links[name] ?? Link()
            link.flags = Int32(bitPattern: entry.ifa_flags)
            if let address = entry.ifa_addr {
                switch Int32(address.pointee.sa_family) {
                case AF_LINK:
                    if let data = entry.ifa_data?.assumingMemoryBound(to: if_data.self) {
                        link.mtu = Int32(clamping: data.pointee.ifi_mtu)
                    }
                case AF_INET, AF_INET6:
                    if let parsed = prefix(of: address, mask: entry.ifa_netmask) {
                        link.addresses.append(parsed)
                    }
                default:
                    break
                }
            }
            links[name] = link
        }
        return links
    }

    /// "address/length", or nil when the kernel gave something this cannot read.
    ///
    /// The zone is stripped. getnameinfo renders a link-local IPv6 address as
    /// "fe80::1%en0", libbox parses these with `netip.MustParsePrefix`
    /// (service.go:142), and MustParsePrefix PANICS on a zone -- a panic inside
    /// a Go callback takes the extension down with it. The Android side strips
    /// it for the same reason (LibboxPlatform.kt:266).
    private static func prefix(
        of address: UnsafeMutablePointer<sockaddr>, mask: UnsafeMutablePointer<sockaddr>?
    ) -> String? {
        let family = Int32(address.pointee.sa_family)
        guard let bits = maskBits(mask, family: family) else {
            return nil
        }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard
            getnameinfo(
                address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0,
                NI_NUMERICHOST) == 0
        else {
            return nil
        }
        let rendered = String(cString: host)
        let bare = rendered.prefix { $0 != "%" }
        if bare.isEmpty {
            return nil
        }
        return "\(bare)/\(bits)"
    }

    /// The prefix length, counted out of the mask's raw bytes.
    ///
    /// Not read as a sockaddr_in or sockaddr_in6: BSD truncates a netmask
    /// sockaddr to the bytes it needs and does not reliably set sa_family on
    /// one, so the family comes from the ADDRESS beside it and the length from
    /// sa_len. The offsets are the fixed BSD layout -- sin_len, sin_family,
    /// sin_port, then sin_addr; sin6_len, sin6_family, sin6_port, sin6_flowinfo,
    /// then sin6_addr -- and the count is capped at the address size so trailing
    /// padding cannot be read as mask bits.
    private static func maskBits(_ mask: UnsafeMutablePointer<sockaddr>?, family: Int32) -> Int? {
        guard let mask else {
            return nil
        }
        let offset: Int
        let size: Int
        switch family {
        case AF_INET:
            offset = 4
            size = 4
        case AF_INET6:
            offset = 8
            size = 16
        default:
            return nil
        }
        let available = Int(mask.pointee.sa_len) - offset
        if available <= 0 {
            return 0
        }
        let raw = UnsafeRawPointer(mask)
        var bits = 0
        for index in 0 ..< min(available, size) {
            bits += raw.load(fromByteOffset: offset + index, as: UInt8.self).nonzeroBitCount
        }
        return bits
    }

    private final class NetworkInterfaceList: NSObject, LibboxNetworkInterfaceIteratorProtocol {
        private var iterator: IndexingIterator<[LibboxNetworkInterface]>
        private var current: LibboxNetworkInterface?

        init(_ values: [LibboxNetworkInterface]) {
            iterator = values.makeIterator()
            super.init()
        }

        // hasNext() advances and next() returns what it found, which is the
        // shape libbox's own iteratorToArray drives (iterator.go:53): it calls
        // HasNext() and then Next(), once each, per element.
        func hasNext() -> Bool {
            current = iterator.next()
            return current != nil
        }

        func next() -> LibboxNetworkInterface? {
            current
        }
    }

    /// The same hasNext()-advances shape, for the one field that takes a string
    /// iterator.
    ///
    /// `len()` is part of that interface (iterator.go:5) and is answered from
    /// the snapshot rather than as 0, for the reason the Android side's
    /// StringArray gives: Go's own implementation returns a real length, and a
    /// caller that trusted a lie would size a buffer wrongly. Nothing in
    /// experimental/libbox calls it on a host iterator today.
    private final class StringList: NSObject, LibboxStringIteratorProtocol {
        private let values: [String]
        private var iterator: IndexingIterator<[String]>
        private var current = ""

        init(_ values: [String]) {
            self.values = values
            iterator = values.makeIterator()
            super.init()
        }

        func len() -> Int32 {
            Int32(values.count)
        }

        func hasNext() -> Bool {
            guard let value = iterator.next() else {
                current = ""
                return false
            }
            current = value
            return true
        }

        func next() -> String {
            current
        }
    }

    /// True, and it is what it says: this process is a Network Extension.
    func underNetworkExtension() -> Bool {
        true
    }

    /// False. `includeAllNetworks` is a property of the network settings this
    /// build does not set, so claiming it would describe a tunnel that is not
    /// the one installed.
    func includeAllNetworks() -> Bool {
        false
    }

    /// nil, which libbox handles (service.go:181).
    ///
    /// Reading the SSID needs the com.apple.developer.networking.wifi-info
    /// entitlement and location permission. sing-box only wants it for route
    /// rules that match on WIFI SSID, and nothing this app generates emits one,
    /// so asking a VPN user for their location would buy a feature nobody here
    /// uses. Same trade as the Android side.
    func readWIFIState() -> LibboxWIFIState? {
        nil
    }

    /// iOS holds the resolver cache behind the tunnel's own network settings, so
    /// re-applying them is the only flush available. Skipped when nothing has
    /// been applied yet: setting nil settings before there is a tunnel tears
    /// down an interface that does not exist.
    func clearDNSCache() {
        guard let settings = networkSettings else {
            return
        }
        let tunnel = provider
        tunnel.reasserting = true
        tunnel.setTunnelNetworkSettings(nil) { _ in
            tunnel.setTunnelNetworkSettings(settings) { _ in
                tunnel.reasserting = false
            }
        }
    }

    /// No procfs on iOS, and nothing to search if there were.
    func useProcFS() -> Bool {
        false
    }

    func findConnectionOwner(
        _: Int32, sourceAddress _: String?, sourcePort _: Int32, destinationAddress _: String?,
        destinationPort _: Int32
    ) throws -> LibboxConnectionOwner {
        throw TunnelSetupError(
            "ios: process matching is not available inside a network extension -- there is no "
                + "procfs and no privileged helper in this build. A route rule matching a process "
                + "will not match; nothing this app generates emits one.")
    }

    func registerMyInterface(_: String?) {}

    /// No-op, and not a stub. The neighbor table (ARP/NDP) feeds sing-box's
    /// bridge and Tailscale services; reading it needs privileges this build
    /// does not have and does not want. Never emitting an update is the truthful
    /// answer -- this host observes no neighbors -- and it is only reachable
    /// from configurations this app does not generate.
    func startNeighborMonitor(_: LibboxNeighborUpdateListenerProtocol?) throws {}

    func closeNeighborMonitor(_: LibboxNeighborUpdateListenerProtocol?) throws {}

    func send(_ notification: LibboxNotification?) throws {
        guard let notification else {
            return
        }
        let content = UNMutableNotificationContent()
        content.title = notification.title
        content.subtitle = notification.subtitle
        content.body = notification.body
        UNUserNotificationCenter.current().add(
            UNNotificationRequest(
                identifier: notification.identifier, content: content, trigger: nil))
    }

    func cancelNotification(_ identifier: String?, typeID _: Int32) throws {
        guard let identifier else {
            return
        }
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers: [identifier])
        center.removeDeliveredNotifications(withIdentifiers: [identifier])
    }

    /// nil. See the header: iOS has no way to bind a resolver to a chosen
    /// interface, libbox accepts nil (config.go:31) and falls back to its own
    /// local transport, and the extension's own queries are outside the tunnel
    /// already.
    func localDNSTransport() -> LibboxLocalDNSTransportProtocol? {
        nil
    }

    // ---- gated off, and they throw if the gate is ever wrong ----

    func usePlatformShell() -> Bool {
        false
    }

    func checkPlatformShell() throws {
        throw TunnelSetupError(
            "ios: no shell -- usePlatformShell() is false and an app extension cannot spawn one.")
    }

    func openShellSession(
        _: LibboxPlatformUser?, command _: String?, environ _: LibboxStringIteratorProtocol?,
        term _: String?, rows _: Int32, cols _: Int32
    ) throws -> LibboxShellSessionProtocol {
        throw TunnelSetupError("ios: no shell sessions in this build")
    }

    func lookupUser(_: String?) throws -> LibboxPlatformUser {
        throw TunnelSetupError("ios: no user lookup in this build")
    }

    // These two return a bare string with the error as an out parameter rather
    // than throwing, because gomobile maps a Go (string, error) pair that way:
    // NSString is nullable in Objective-C, so the value channel is the return
    // and Swift sees no error convention to import.
    func lookupSFTPServer(_ error: NSErrorPointer) -> String {
        error?.pointee = Self.unavailable("ios: no SFTP server in this build")
        return ""
    }

    func readSystemSSHHostKey(_ error: NSErrorPointer) -> String {
        error?.pointee = Self.unavailable("ios: no system SSH host key in this build")
        return ""
    }

    /// Empty rather than a throw: the Go signature returns a bare string with no
    /// error channel, so there is nowhere to put a failure. Only a Tailscale
    /// endpoint reads it, and this app emits none.
    func tailscaleHostname() -> String {
        ""
    }

    func usePlatformBridge() -> Bool {
        false
    }

    func createBridge(_: LibboxBridgeOptions?) throws -> LibboxBridgeSessionProtocol {
        throw TunnelSetupError("ios: no bridge -- usePlatformBridge() is false")
    }

    // ---- CommandServerHandler (command_server.go:43) ----
    //
    // Reachable only over the gRPC command socket, which nothing in this app
    // connects to yet. Implemented rather than stubbed so that the day something
    // does connect, none of them lies.

    func serviceStop() throws {
        provider.stopFromEngine(nil)
    }

    func serviceReload() throws {
        throw TunnelSetupError(
            "ios: reload is not implemented. The app stops and starts the tunnel with a fresh "
                + "configuration instead, because it builds that configuration on the Dart side.")
    }

    func getSystemProxyStatus() throws -> LibboxSystemProxyStatus {
        let status = LibboxSystemProxyStatus()
        // Available only when the configuration asks for an HTTP proxy inbound,
        // which this app does not emit and openTun refuses above. Both halves
        // false is the accurate answer rather than a placeholder.
        status.available = false
        status.enabled = false
        return status
    }

    func setSystemProxyEnabled(_: Bool) throws {
        throw TunnelSetupError(
            "ios: there is no system proxy to enable; getSystemProxyStatus() reports it "
                + "unavailable")
    }

    func triggerNativeCrash() throws {
        throw TunnelSetupError("ios: the native-crash debug hook is not wired up in this build")
    }

    func writeDebugMessage(_ message: String?) {
        provider.writeLog(message ?? "")
    }

    func connectSSHAgent(_ ret0_: UnsafeMutablePointer<Int32>?) throws {
        // -1, the same answer the Android side gives: no agent, and no
        // descriptor to hand over.
        ret0_?.pointee = -1
    }

    private static func unavailable(_ message: String) -> NSError {
        NSError(
            domain: "io.github.asel1x.singbox_tunnel", code: 1,
            userInfo: [NSLocalizedDescriptionKey: message])
    }
}
