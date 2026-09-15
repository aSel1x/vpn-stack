package io.github.asel1x.singbox_tunnel

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.Notification
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.SetupOptions
import io.nekohasekai.libbox.SystemProxyStatus
import io.nekohasekai.libbox.TunOptions
import java.util.concurrent.Executors

/**
 * The tunnel.
 *
 * Android gives a TUN file descriptor to a `VpnService` and to nothing else, and
 * libbox wants exactly that descriptor, so this class is where the two meet. It
 * is both the `VpnService` and the `PlatformInterface` libbox calls back into --
 * one object, because `openTun` and `protect` are methods on the service and
 * splitting them off would mean holding a reference back to it anyway.
 *
 * Entry points, all read from sing-box v1.14.0 rather than remembered:
 *
 *  * `Libbox.setup(SetupOptions)` -- experimental/libbox/setup.go:106. Must run
 *    before anything else: it is what sets the working paths and the uid that
 *    `baseContext` hands to the file manager (config.go:38).
 *  * `CommandServer(CommandServerHandler, PlatformInterface)` -- the gomobile
 *    binding of `NewCommandServer`, experimental/libbox/command_server.go:54.
 *    In v1.14.0 there is no `BoxService` any more; the service lives behind this.
 *  * `CommandServer.startOrReloadService(String, OverrideOptions)` --
 *    command_server.go:199. Synchronous, but NOT the proof it was once claimed
 *    to be: daemon/started_service.go has a branch where a start that was
 *    interrupted clears the instance and returns without surfacing that, so
 *    "returned without throwing" does not by itself mean a tunnel exists. The
 *    check that a TUN was actually opened is in [startBox], and it is the thing
 *    that lets this file report connected.
 *  * `CommandServer.closeService()` / `close()` -- command_server.go:214 / :187.
 */
class SingboxVpnService : VpnService(), LibboxPlatform, CommandServerHandler {
    override val appContext: Context
        get() = this

    override val networkMonitor: DefaultNetworkMonitor by lazy { DefaultNetworkMonitor(this) }

    private val notification by lazy { TunnelNotification(this) }
    private val mainHandler = Handler(Looper.getMainLooper())

    /**
     * One thread, and everything that touches libbox runs on it.
     * `startOrReloadService` brings the entire box up inside the call, which is
     * seconds; on the main looper that is an ANR, and interleaving it with a
     * stop is a use-after-close of the command server.
     */
    private val worker = Executors.newSingleThreadExecutor()

    private var commandServer: CommandServer? = null

    /**
     * Kept, not detached: libbox dups the descriptor
     * (experimental/libbox/service.go:79) and closes its copy, so this one is
     * what still has to be closed to tear the interface down.
     */
    private var tunDescriptor: ParcelFileDescriptor? = null

    /** Read on the worker thread by [openTun]; written on the main thread. */
    @Volatile
    private var label: String = ""

    @Volatile
    private var boxStarted = false

    override fun onCreate() {
        super.onCreate()
        TunnelState.serviceRunning = true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        label = intent?.getStringExtra(EXTRA_LABEL) ?: label

        val stopping = intent?.action == ACTION_STOP

        // First, unconditionally, and before anything that can fail: Android
        // kills the process if startForegroundService is not answered by a
        // startForeground within five seconds, and a process killed there
        // reports nothing at all.
        notification.show(label, if (stopping) "Stopping" else "Starting")

        if (stopping) {
            shutdown(TunnelStatus(Stage.DISCONNECTED))
            return START_NOT_STICKY
        }

        val config = intent?.getStringExtra(EXTRA_CONFIG)
        if (config.isNullOrEmpty()) {
            shutdown(
                TunnelStatus(
                    Stage.FAILED,
                    "The VPN service was started without a sing-box configuration. Nothing was " +
                        "established. This is a bug in SingboxTunnelPlugin, not something the " +
                        "phone did.",
                ),
            )
            return START_NOT_STICKY
        }

        if (boxStarted) {
            // START_NOT_STICKY plus this guard: a second start must not build a
            // second CommandServer over the first one's tun.
            //
            // Republish the state we are actually in. The plugin already wrote
            // CONNECTING before starting us, so returning silently left the
            // status stuck there until Dart's 45s timeout manufactured `failed`
            // -- reporting a live, traffic-carrying tunnel as broken, and
            // overwriting the true status of the profile that is up. That is the
            // same lie disconnect's own timeout refuses to tell.
            Log.w(TAG, "start ignored: the tunnel is already up")
            TunnelState.set(TunnelState.current)
            return START_NOT_STICKY
        }
        boxStarted = true

        TunnelState.set(TunnelStatus(Stage.CONNECTING))
        worker.execute { startBox(config) }
        return START_NOT_STICKY
    }

    private fun startBox(config: String) {
        try {
            setupLibbox()

            // Deliberately NOT Libbox.checkConfig (experimental/libbox/config.go:50)
            // first. It builds a second box under a stub platform interface to
            // validate, which is a second parser that can disagree with the one
            // that matters; startOrReloadService parses the same bytes in the
            // real context and its error is the one worth reporting.
            networkMonitor.start()

            val server = CommandServer(this, this)
            commandServer = server
            server.start()
            server.startOrReloadService(config, OverrideOptions())
        } catch (failure: Throwable) {
            // Throwable, not Exception: gomobile surfaces a Go panic as an
            // Error, and an Error swallowed here would leave the notification
            // up, the status on "connecting", and nothing running.
            shutdown(
                TunnelStatus(
                    Stage.FAILED,
                    "sing-box did not start: " + (failure.message ?: failure.toString()),
                ),
            )
            return
        }
        // The one fact that separates a tunnel from a running process. libbox
        // calls openTun only if the configuration contains a `tun` inbound, and
        // this package deliberately does not read the configuration -- it takes
        // whatever Dart hands it. Hand it a proxy-only config and sing-box starts
        // cleanly, establish() is never called, no packet is routed, and without
        // this check the UI would say Connected. The app's builder does emit a
        // tun inbound today, but that is a convention in another package, and a
        // convention is not a check at the boundary this package says is the
        // boundary.
        if (tunDescriptor == null) {
            shutdown(
                TunnelStatus(
                    Stage.FAILED,
                    "sing-box started but never asked for a TUN interface, so " +
                        "nothing is being routed. The configuration has no `tun` " +
                        "inbound.",
                ),
            )
            return
        }
        TunnelState.set(TunnelStatus(Stage.CONNECTED))
        mainHandler.post { notification.show(label, "Connected") }
    }

    private fun setupLibbox() {
        // Process-wide and once: Setup writes the paths into package-level
        // variables in Go (experimental/libbox/setup.go:65) and redirects
        // stderr, and doing that again under a running box is not a no-op.
        if (libboxReady) return
        val options = SetupOptions()
        options.basePath = filesDir.absolutePath
        options.workingPath = filesDir.resolve("singbox").absolutePath
        options.tempPath = cacheDir.absolutePath
        // https://github.com/golang/go/issues/68760 -- the stack a Go callback
        // runs on when the JVM called in. SFA sets it per-device; on is the
        // conservative side, since the cost is a goroutine hop per network
        // change and the failure it avoids is a crash inside the callback.
        options.fixAndroidStack = true
        options.crashReportSource = "singbox_tunnel"
        Libbox.setup(options)
        libboxReady = true
    }

    // ---- PlatformInterface: the two methods only a VpnService can answer ----

    /**
     * `VpnService.protect`, which keeps sing-box's own sockets out of the tun it
     * just installed a default route into.
     *
     * A false return is raised rather than logged. An unprotected outbound does
     * not fail; it loops -- packets leave sing-box, match the default route,
     * come back into the tun, and the tunnel looks up while nothing resolves.
     */
    override fun autoDetectInterfaceControl(fd: Int) {
        if (!protect(fd)) {
            error("android: VpnService.protect($fd) failed; that socket would route into our own tun")
        }
    }

    override fun openTun(options: TunOptions): Int {
        // prepare() is null only when consent is on file. Checking again here,
        // after the plugin already checked, is not redundant: consent can be
        // withdrawn in Settings between the two, and establish() would then
        // return null with no explanation.
        if (prepare(this) != null) {
            error("android: VPN permission is not granted, so no TUN interface was created")
        }

        val builder = Builder()
            .setSession(label.ifBlank { "vpn-stack" })
            .setMtu(options.mtu)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        var addresses = 0
        val inet4Address = options.inet4Address
        while (inet4Address.hasNext()) {
            val address = inet4Address.next()
            builder.addAddress(address.address(), address.prefix())
            addresses++
        }
        val inet6Address = options.inet6Address
        while (inet6Address.hasNext()) {
            val address = inet6Address.next()
            builder.addAddress(address.address(), address.prefix())
            addresses++
        }
        if (addresses == 0) {
            error("android: the configuration gave the tun no address; there is nothing to establish")
        }

        if (options.autoRoute) {
            if (options.dnsMode.value != Libbox.DNSModeDisabled) {
                val dnsServerAddress = options.dnsServerAddress
                while (dnsServerAddress.hasNext()) {
                    builder.addDnsServer(dnsServerAddress.next())
                }
            }

            // The *route ranges*, not inet4RouteAddress: libbox computes these
            // from the configuration with BuildAutoRouteRanges
            // (experimental/libbox/service.go:66), which has already subtracted
            // every inet4_route_exclude_address. Using addRoute/excludeRoute
            // with IpPrefix instead would need API 33 and a second code path
            // that has to reproduce that subtraction for everyone below it.
            var routes = 0
            val inet4RouteRange = options.inet4RouteRange
            while (inet4RouteRange.hasNext()) {
                val route = inet4RouteRange.next()
                builder.addRoute(route.address(), route.prefix())
                routes++
            }
            val inet6RouteRange = options.inet6RouteRange
            while (inet6RouteRange.hasNext()) {
                val route = inet6RouteRange.next()
                builder.addRoute(route.address(), route.prefix())
                routes++
            }
            if (routes == 0) {
                error(
                    "android: auto_route is on and libbox computed no routes. Establishing anyway " +
                        "would produce a tunnel that carries nothing while the UI says connected.",
                )
            }

            val includePackage = options.includePackage
            while (includePackage.hasNext()) {
                val name = includePackage.next()
                try {
                    builder.addAllowedApplication(name)
                } catch (missing: PackageManager.NameNotFoundException) {
                    Log.w(TAG, "include_package: $name is not installed", missing)
                }
            }
            val excludePackage = options.excludePackage
            while (excludePackage.hasNext()) {
                val name = excludePackage.next()
                try {
                    builder.addDisallowedApplication(name)
                } catch (missing: PackageManager.NameNotFoundException) {
                    // Loudly: an app that was meant to bypass the tunnel and
                    // cannot be named is an app whose traffic now goes through
                    // it, which is the opposite of what was asked for.
                    Log.e(TAG, "exclude_package: $name is not installed", missing)
                }
            }
        }

        val descriptor = builder.establish() ?: error(
            "android: VpnService.Builder.establish() returned null. Either VPN consent was " +
                "revoked, or another app took over as the active VPN.",
        )
        tunDescriptor = descriptor
        return descriptor.fd
    }

    override fun sendNotification(notification: Notification) {
        this.notification.showEvent(
            notification.identifier,
            notification.typeID,
            notification.typeName,
            notification.title,
            notification.body,
        )
    }

    override fun cancelNotification(identifier: String, typeID: Int) {
        notification.cancelEvent(identifier, typeID)
    }

    // ---- CommandServerHandler (experimental/libbox/command_server.go:43) ----
    //
    // Everything here is reachable only over the gRPC command socket, which
    // nothing in this app connects to yet. They are implemented rather than
    // stubbed so that the day something does connect, none of them lies.

    override fun serviceStop() {
        shutdown(TunnelStatus(Stage.DISCONNECTED))
    }

    override fun serviceReload() {
        error(
            "android: reload is not implemented. The app stops and starts the tunnel with a fresh " +
                "configuration instead, because it builds that configuration on the Dart side.",
        )
    }

    override fun getSystemProxyStatus(): SystemProxyStatus = SystemProxyStatus().also {
        // Available only when the configuration asks for an HTTP proxy inbound,
        // which this app does not emit, so both halves are false and saying so
        // is the accurate answer rather than a placeholder.
        it.available = false
        it.enabled = false
    }

    override fun setSystemProxyEnabled(isEnabled: Boolean) {
        error("android: there is no system proxy to enable; getSystemProxyStatus() reports it unavailable")
    }

    override fun triggerNativeCrash() {
        error("android: the native-crash debug hook is not wired up in this build")
    }

    override fun writeDebugMessage(message: String?) {
        Log.d(TAG, message ?: "")
    }

    override fun connectSSHAgent(): Int = -1

    // ---- lifecycle ----

    /**
     * Android took the tunnel away: consent revoked in Settings, or another VPN
     * app became the active one.
     *
     * Reported as a failure and not as a clean disconnect. The app asked for a
     * tunnel and no longer has one, and it was not the app that stopped it --
     * rendering that as an ordinary "disconnected" would make an interruption
     * look like the user's own tap.
     */
    override fun onRevoke() {
        shutdown(
            TunnelStatus(
                Stage.FAILED,
                "Android revoked this app's VPN permission. Another VPN app became the active " +
                    "one, or the profile was removed under Settings > Network > VPN. Traffic is " +
                    "no longer going through the tunnel.",
            ),
        )
        super.onRevoke()
    }

    override fun onDestroy() {
        TunnelState.serviceRunning = false
        if (TunnelState.current.stage == Stage.CONNECTED ||
            TunnelState.current.stage == Stage.CONNECTING
        ) {
            // The process is going away with the tunnel still marked up. Correct
            // the record before the listener disappears with it.
            TunnelState.set(
                TunnelStatus(
                    Stage.FAILED,
                    "The Android VPN service was destroyed while the tunnel was up -- the system " +
                        "reclaimed the process. Nothing is being tunnelled.",
                ),
            )
        }
        // Tear down for real, not just correct the label. Every teardown used to
        // live in shutdown(), which runs only on an explicit stop, serviceStop()
        // or onRevoke() -- so a destroy arriving by any other route (the system
        // reclaiming the service, an external stopService) left the sing-box
        // instance, its command server and the tun descriptor alive in a process
        // the Flutter engine keeps running. libboxReady is a companion field, so
        // the next start would skip Libbox.setup and build a SECOND CommandServer
        // beside the orphan.
        //
        // Synchronously, on this thread: worker.shutdown() below stops the
        // executor, and work queued onto it here would never run.
        releaseEngine()
        worker.shutdown()
        super.onDestroy()
    }

    /** Closes the engine, the tun and the monitors. Safe to call twice. */
    private fun releaseEngine() {
        runCatching { commandServer?.closeService() }
            .onFailure { Log.e(TAG, "closeService", it) }
        runCatching { commandServer?.close() }
            .onFailure { Log.e(TAG, "close command server", it) }
        commandServer = null

        runCatching { tunDescriptor?.close() }
            .onFailure { Log.e(TAG, "close tun descriptor", it) }
        tunDescriptor = null

        runCatching { networkMonitor.stop() }
            .onFailure { Log.e(TAG, "stop network monitor", it) }

        boxStarted = false
    }

    private fun shutdown(status: TunnelStatus) {
        worker.execute {
            runCatching { commandServer?.closeService() }
                .onFailure { Log.e(TAG, "closeService", it) }
            runCatching { commandServer?.close() }
                .onFailure { Log.e(TAG, "close command server", it) }
            commandServer = null

            runCatching { tunDescriptor?.close() }
                .onFailure { Log.e(TAG, "close tun descriptor", it) }
            tunDescriptor = null

            runCatching { networkMonitor.stop() }
                .onFailure { Log.e(TAG, "stop network monitor", it) }

            boxStarted = false
            TunnelState.serviceRunning = false
            TunnelState.set(status)

            mainHandler.post {
                notification.clear()
                stopSelf()
            }
        }
    }

    companion object {
        const val TAG = "SingboxTunnel"
        const val ACTION_STOP = "io.github.asel1x.singbox_tunnel.STOP"
        const val EXTRA_CONFIG = "config"
        const val EXTRA_LABEL = "label"

        @Volatile
        private var libboxReady = false

        /**
         * The configuration travels in the Intent rather than in a static field:
         * a static would be lost if the process were recycled between the plugin
         * writing it and the service reading it, and a few kilobytes of JSON is
         * nowhere near the Binder transaction limit.
         */
        fun start(context: Context, config: String, label: String) {
            val intent = Intent(context, SingboxVpnService::class.java)
                .putExtra(EXTRA_CONFIG, config)
                .putExtra(EXTRA_LABEL, label)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.startService(
                Intent(context, SingboxVpnService::class.java).setAction(ACTION_STOP),
            )
        }
    }
}
