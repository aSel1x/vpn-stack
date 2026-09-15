package io.github.asel1x.singbox_tunnel

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Process
import io.nekohasekai.libbox.BridgeOptions
import io.nekohasekai.libbox.BridgeSession
import io.nekohasekai.libbox.ConnectionOwner
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.LocalDNSTransport
import io.nekohasekai.libbox.NeighborUpdateListener
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.PlatformUser
import io.nekohasekai.libbox.ShellSession
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.WIFIState
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.InterfaceAddress
import java.net.NetworkInterface
import io.nekohasekai.libbox.NetworkInterface as LibboxNetworkInterface

// From linux/if.h, which is exactly what libbox decodes these back into
// (sing-box v1.14.0 experimental/libbox/link_flags_unix.go:8-29). Written out
// rather than read from android.system.OsConstants so the number sing-box sees
// is visible at the point it is produced.
private const val IFF_UP = 0x1
private const val IFF_LOOPBACK = 0x8
private const val IFF_POINTOPOINT = 0x10
private const val IFF_RUNNING = 0x40
private const val IFF_MULTICAST = 0x1000

/**
 * Everything sing-box asks the host for, except the two things only a
 * `VpnService` can answer (`openTun`, `autoDetectInterfaceControl`) and the two
 * that need the service's notification (`sendNotification`,
 * `cancelNotification`).
 *
 * The interface is `io.nekohasekai.libbox.PlatformInterface`, 27 methods, from
 * sing-box v1.14.0 `experimental/libbox/platform.go:5`. Kotlin makes an
 * implementer provide all 27 whether or not this app's configurations can reach
 * them, so the ones it cannot reach are written here, once, either as the
 * honest constant answer or as a throw naming what is missing. None of them is
 * a silent default: a method that returns a plausible-looking value for a
 * question it cannot answer is how a tunnel comes up routing nothing.
 */
interface LibboxPlatform : PlatformInterface {
    val appContext: Context

    val networkMonitor: DefaultNetworkMonitor

    // ---- what sing-box actually uses on this platform ----

    /**
     * True, and load-bearing: it is what routes every outbound socket through
     * [SingboxVpnService.autoDetectInterfaceControl], which calls
     * `VpnService.protect`. Without that, sing-box's own connection to the VPN
     * server is matched by the default route it just installed and goes back
     * into the tun it came out of.
     */
    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    /**
     * Android's own resolver, on a named network.
     *
     * Returning null here is legal (`experimental/libbox/config.go:31` checks
     * for it) and wrong: the configuration's `dns-local` server is what
     * `route.default_domain_resolver` points at, and its only job is resolving
     * the VPN server's own hostname. sing-box's built-in local transport has no
     * way to be told "not through the tunnel"; `Network.getAllByName` does,
     * because the query goes to the network the monitor is tracking.
     */
    override fun localDNSTransport(): LocalDNSTransport = NetworkBoundResolver(networkMonitor)

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener?) {
        networkMonitor.setListener(listener)
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener?) {
        networkMonitor.setListener(null)
    }

    /**
     * Every network the device has, with the Linux interface flags sing-box
     * decodes.
     *
     * `UsePlatformNetworkInterfaces` is hard-coded true in libbox
     * (`experimental/libbox/service.go:120`), so this list is the only thing
     * `InterfaceFinder().ByIndex()` can resolve the default interface against.
     * An empty answer here does not degrade gracefully -- it makes
     * "find updated interface" fail and leaves auto-detection with no interface
     * at all.
     */
    override fun getInterfaces(): NetworkInterfaceIterator {
        val connectivity = appContext.getSystemService(ConnectivityManager::class.java)
            ?: error("android: no ConnectivityManager")

        @Suppress("DEPRECATION")
        val networks = connectivity.allNetworks
        val byName = NetworkInterface.getNetworkInterfaces().toList().associateBy { it.name }
        val result = mutableListOf<LibboxNetworkInterface>()

        for (network in networks) {
            val link = connectivity.getLinkProperties(network) ?: continue
            val capabilities = connectivity.getNetworkCapabilities(network) ?: continue
            val name = link.interfaceName ?: continue
            val nic = byName[name] ?: continue

            val boxInterface = LibboxNetworkInterface()
            boxInterface.name = name
            boxInterface.index = nic.index
            runCatching { boxInterface.mtu = nic.mtu }
            boxInterface.addresses = StringArray(nic.interfaceAddresses.map { it.toPrefix() })
            boxInterface.dnsServer = StringArray(link.dnsServers.mapNotNull { it.hostAddress })
            boxInterface.gateway = StringArray(
                link.routes
                    .filter { it.destination.prefixLength == 0 }
                    .mapNotNull { it.gateway }
                    .filterNot { it.isAnyLocalAddress }
                    .mapNotNull { it.hostAddress },
            )
            boxInterface.type = when {
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Libbox.InterfaceTypeWIFI
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Libbox.InterfaceTypeCellular
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Libbox.InterfaceTypeEthernet
                else -> Libbox.InterfaceTypeOther
            }
            boxInterface.metered =
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)

            var flags = 0
            if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                flags = IFF_UP or IFF_RUNNING
            }
            if (nic.isLoopback) flags = flags or IFF_LOOPBACK
            if (nic.isPointToPoint) flags = flags or IFF_POINTOPOINT
            if (nic.supportsMulticast()) flags = flags or IFF_MULTICAST
            boxInterface.flags = flags

            result.add(boxInterface)
        }
        return InterfaceArray(result)
    }

    // ---- honest constant answers ----

    /**
     * procfs is readable by an app only before Android 10; after that
     * the `/proc/net` files are filtered and a search there finds nothing, which libbox
     * would report as "not found" rather than as "unavailable".
     */
    override fun useProcFS(): Boolean = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q

    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int,
    ): ConnectionOwner {
        // Written as a positive version check rather than an early error so
        // Android Lint's NewApi can see the guard; it does not know that
        // error() never returns.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val connectivity = appContext.getSystemService(ConnectivityManager::class.java)
                ?: error("android: no ConnectivityManager")
            val uid = connectivity.getConnectionOwnerUid(
                ipProtocol,
                InetSocketAddress(sourceAddress, sourcePort),
                InetSocketAddress(destinationAddress, destinationPort),
            )
            if (uid == Process.INVALID_UID) error("android: connection owner not found")
            val owner = ConnectionOwner()
            owner.userId = uid
            // userName and the package list stay empty on purpose: filling them
            // needs QUERY_ALL_PACKAGES, a store-flagged permission this app has
            // no other use for. A route rule matching a package name therefore
            // will not match here -- visibly, not silently, and nothing this app
            // generates emits one.
            return owner
        }
        // useProcFS() said true below Android 10, so libbox resolves this itself
        // and never arrives here. Reaching it means that contract moved.
        error("android: process matching below Android 10 goes through procfs, not this call")
    }

    /** iOS terms. On Android there is no network extension and no per-app VPN. */
    override fun underNetworkExtension(): Boolean = false

    override fun includeAllNetworks(): Boolean = false

    /**
     * Null, which libbox handles (`experimental/libbox/service.go:181`).
     *
     * Reading the SSID on Android 10+ requires ACCESS_FINE_LOCATION and on 11+
     * ACCESS_BACKGROUND_LOCATION. sing-box only needs it for route rules that
     * match on WIFI SSID, which nothing in this app emits, so asking a VPN
     * user for location permission would buy a feature nobody here uses.
     */
    override fun readWIFIState(): WIFIState? = null

    /**
     * No-op, and not a stub: Android exposes no way to flush the platform
     * resolver cache from an app. libbox calls this after a network change;
     * [NetworkBoundResolver] queries a specific `Network` rather than the
     * process-wide resolver, so there is no cache of ours to drop.
     */
    override fun clearDNSCache() {}

    override fun registerMyInterface(name: String?) {}

    /**
     * No-op. The neighbor table (ARP/NDP) feeds sing-box's bridge and Tailscale
     * services; reading it needs root, which this app does not have and does
     * not want. Never emitting an update is the truthful answer -- this host
     * observes no neighbors -- and it is only reachable from configurations
     * this app does not generate.
     */
    override fun startNeighborMonitor(listener: NeighborUpdateListener?) {}

    override fun closeNeighborMonitor(listener: NeighborUpdateListener?) {}

    // ---- gated off, and they throw if the gate is ever wrong ----

    override fun usePlatformShell(): Boolean = false

    override fun checkPlatformShell() {
        error("android: no shell -- usePlatformShell() is false and this app has no root helper")
    }

    override fun openShellSession(
        user: PlatformUser?,
        command: String?,
        environ: StringIterator?,
        term: String?,
        rows: Int,
        cols: Int,
    ): ShellSession = error("android: no shell sessions in this build")

    override fun lookupUser(username: String?): PlatformUser =
        error("android: no user lookup in this build")

    override fun lookupSFTPServer(): String =
        error("android: no SFTP server in this build")

    override fun readSystemSSHHostKey(): String =
        error("android: no system SSH host key in this build")

    /**
     * Empty rather than a throw: the Go signature returns a bare string with no
     * error channel, so a throw here would cross the gomobile boundary as a
     * panic and take the process with it. Only a Tailscale endpoint reads it,
     * and this app emits none.
     */
    override fun tailscaleHostname(): String = ""

    override fun usePlatformBridge(): Boolean = false

    override fun createBridge(options: BridgeOptions?): BridgeSession =
        error("android: no bridge -- usePlatformBridge() is false")

    private fun InterfaceAddress.toPrefix(): String = if (address is Inet6Address) {
        // Re-parsed through getByAddress to drop the scope id: sing-box parses
        // these with netip.MustParsePrefix, which rejects "fe80::1%wlan0".
        "${Inet6Address.getByAddress(address.address).hostAddress}/$networkPrefixLength"
    } else {
        "${address.hostAddress}/$networkPrefixLength"
    }
}
