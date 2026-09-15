package io.github.asel1x.singbox_tunnel

import io.nekohasekai.libbox.ExchangeContext
import io.nekohasekai.libbox.LocalDNSTransport
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * The resolver the tunnel's own server name is looked up with.
 *
 * `Network.getAllByName` resolves on one specific network rather than on
 * whatever the process default is, and that is the whole point: with the tun up
 * and a default route installed, a plain `InetAddress.getAllByName` would send
 * the query into the tunnel that is being brought up to reach the address it is
 * resolving.
 *
 * Registered through `PlatformInterface.LocalDNSTransport()`, which libbox binds
 * to the configuration's `type: local` DNS server
 * (sing-box v1.14.0 experimental/libbox/config.go:31).
 */
class NetworkBoundResolver(private val monitor: DefaultNetworkMonitor) : LocalDNSTransport {
    /**
     * False, so libbox calls [lookup] with a domain rather than [exchange] with
     * a wire-format message. The cost is that only A and AAAA can be answered
     * (libbox says so itself at experimental/libbox/dns.go:114), which is all
     * `route.default_domain_resolver` ever asks for. The benefit is that this
     * needs no DNS parser and no API beyond `Network.getAllByName`.
     */
    override fun raw(): Boolean = false

    override fun exchange(ctx: ExchangeContext, message: ByteArray) {
        error("android: raw() is false, so libbox resolves through lookup() and never calls this")
    }

    override fun lookup(ctx: ExchangeContext, network: String, domain: String) {
        val bound = monitor.defaultNetwork ?: error(
            "android: no default network to resolve $domain on. The device is offline, or the " +
                "network monitor has not seen a network yet -- either way there is nothing to " +
                "dial the VPN server through.",
        )
        // The question name arrives as an FQDN with the root label
        // ("example.com."); getaddrinfo does not want the trailing dot.
        val name = domain.removeSuffix(".")
        val answers: Array<InetAddress> = try {
            bound.getAllByName(name)
        } catch (failure: UnknownHostException) {
            ctx.errorCode(RCODE_NXDOMAIN)
            return
        }
        // libbox asks with "ip4" or "ip6" (experimental/libbox/dns.go:107-112)
        // and builds a fixed A or AAAA response out of what comes back, so
        // handing it the wrong family produces records of the wrong type.
        val wanted: List<InetAddress> = when {
            network.endsWith("6") -> answers.filterIsInstance<Inet6Address>()
            network.endsWith("4") -> answers.filterIsInstance<Inet4Address>()
            else -> answers.toList()
        }
        val addresses = wanted.mapNotNull { it.hostAddress }
        if (addresses.isEmpty()) {
            // NXDOMAIN rather than an empty success: an empty success is a
            // cacheable "this name has no address", which is a stronger claim
            // than "this network returned nothing for this family".
            ctx.errorCode(RCODE_NXDOMAIN)
            return
        }
        ctx.success(addresses.joinToString("\n"))
    }

    private companion object {
        const val RCODE_NXDOMAIN = 3
    }
}
