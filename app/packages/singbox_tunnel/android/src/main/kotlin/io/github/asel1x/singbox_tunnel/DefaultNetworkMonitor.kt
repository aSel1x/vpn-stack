package io.github.asel1x.singbox_tunnel

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import io.nekohasekai.libbox.InterfaceUpdateListener
import java.net.NetworkInterface

/**
 * Which network is underneath the tunnel.
 *
 * `route.auto_detect_interface` is on in the configurations this app ships, and
 * libbox hard-codes `UsePlatformDefaultInterfaceMonitor` to true
 * (sing-box v1.14.0 experimental/libbox/service.go:109), so sing-box has no way
 * of its own to learn which interface to bind outbound sockets to. This is that
 * way. If it never reports an interface, the tunnel establishes and carries no
 * traffic.
 *
 * It also holds the `Network` handle that [NetworkBoundResolver] resolves on --
 * the one query that must not go through the tunnel, because it is the query
 * that finds the tunnel's own server.
 */
class DefaultNetworkMonitor(context: Context) {
    private val connectivity: ConnectivityManager? =
        context.getSystemService(ConnectivityManager::class.java)

    /**
     * Its own thread, not the main looper: [publish] sleeps while waiting for
     * LinkProperties to appear, and libbox's UpdateDefaultInterface runs the
     * whole interface reconciliation synchronously on the calling thread.
     * Either one on the main looper is an ANR.
     */
    private var thread: HandlerThread? = null

    @Volatile
    private var handler: Handler? = null

    @Volatile
    var defaultNetwork: Network? = null
        private set

    @Volatile
    private var listener: InterfaceUpdateListener? = null

    private var callback: ConnectivityManager.NetworkCallback? = null

    private val request = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
        .build()

    fun start() {
        val manager = connectivity ?: error("android: no ConnectivityManager")
        if (callback != null) return
        // Created here rather than held as a field: a HandlerThread cannot be
        // started twice, and this monitor outlives one tunnel if the service is
        // stopped and started again without being destroyed.
        val monitorThread = HandlerThread("singbox-network-monitor")
        thread = monitorThread
        monitorThread.start()
        val threadHandler = Handler(monitorThread.looper)
        handler = threadHandler

        val networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                defaultNetwork = network
                publish(network)
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities,
            ) {
                if (network == defaultNetwork) publish(network)
            }

            override fun onLost(network: Network) {
                if (network != defaultNetwork) return
                defaultNetwork = null
                publish(null)
            }
        }
        callback = networkCallback

        // registerDefaultNetworkCallback started returning the VPN's own
        // interface in Android P, which would point sing-box at the tun it just
        // created. requestNetwork with an explicit request does not, and 31
        // added registerBestMatchingNetworkCallback for exactly this.
        //
        // What makes that true is [request] rather than the choice of call:
        // NetworkRequest.Builder() starts from NetworkCapabilities' defaults,
        // which include NET_CAPABILITY_NOT_VPN, and a VPN network is the one
        // network that does not carry it. So this request cannot match our own
        // tun even while the tun is the app's default network. A future edit
        // that builds the request from a NetworkCapabilities it cleared, or that
        // adds TRANSPORT_VPN, hands sing-box the interface it is routing into.
        when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
                manager.registerBestMatchingNetworkCallback(request, networkCallback, threadHandler)
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.O ->
                manager.requestNetwork(request, networkCallback, threadHandler)
            // The call above says this one reports the VPN's own interface, and
            // this branch still uses it: that behaviour arrived in Android P,
            // which is two releases above this branch's ceiling of 25, so here it
            // reports the underlying network and cannot point sing-box at the tun.
            else ->
                manager.registerDefaultNetworkCallback(networkCallback)
        }
    }

    fun stop() {
        val networkCallback = callback ?: return
        callback = null
        runCatching { connectivity?.unregisterNetworkCallback(networkCallback) }
        listener = null
        defaultNetwork = null
        handler = null
        runCatching { thread?.quitSafely() }
        thread = null
    }

    /**
     * Called by libbox when the box starts and again with null when it stops.
     *
     * The current network is published immediately: the callback only fires on
     * a change, so a tunnel started on an already-connected phone would
     * otherwise wait for one.
     */
    fun setListener(next: InterfaceUpdateListener?) {
        listener = next
        if (next == null) return
        val target = handler
        if (target == null) {
            publish(defaultNetwork)
        } else {
            target.post { publish(defaultNetwork) }
        }
    }

    private fun publish(network: Network?) {
        val target = listener ?: return
        if (network == null) {
            // -1 is libbox's "no default interface"
            // (experimental/libbox/monitor.go:98).
            target.updateDefaultInterface("", -1, false, false)
            return
        }
        val manager = connectivity
        repeat(RESOLVE_ATTEMPTS) {
            val name = manager?.getLinkProperties(network)?.interfaceName
            val index = if (name == null) {
                null
            } else {
                runCatching { NetworkInterface.getByName(name)?.index }.getOrNull()
            }
            if (name != null && index != null) {
                target.updateDefaultInterface(name, index, false, false)
                return
            }
            Thread.sleep(RESOLVE_BACKOFF_MS)
        }
        // Not silently ignored: sing-box is told there is no default interface,
        // which makes the outbound fail loudly, rather than being left pointing
        // at whatever interface it saw last.
        Log.e(TAG, "no interface name or index for the default network after $RESOLVE_ATTEMPTS tries")
        target.updateDefaultInterface("", -1, false, false)
    }

    private companion object {
        const val TAG = "SingboxTunnel"

        // onAvailable can fire before LinkProperties are populated, and
        // NetworkInterface.getByName does not see the interface until the
        // kernel does. One second total, then say so.
        const val RESOLVE_ATTEMPTS = 10
        const val RESOLVE_BACKOFF_MS = 100L
    }
}
