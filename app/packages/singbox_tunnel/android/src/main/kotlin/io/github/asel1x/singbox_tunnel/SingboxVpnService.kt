package io.github.asel1x.singbox_tunnel

import android.app.PendingIntent
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
import java.io.File
import java.io.FileNotFoundException
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import org.json.JSONObject

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

    /**
     * `@Volatile` because the teardown reads it from a different thread than
     * [startBox] wrote it on -- [onDestroy] runs on the main looper and queues
     * the release, and a `closeService()` against a cached null is an engine
     * left running in a process that believes it stopped one.
     */
    @Volatile
    private var commandServer: CommandServer? = null

    /**
     * Kept, not detached: libbox dups the descriptor
     * (experimental/libbox/service.go:79) and closes its copy, so this one is
     * what still has to be closed to tear the interface down.
     *
     * `@Volatile`, and that is not housekeeping: a non-null descriptor is the
     * ONLY evidence [startBox] accepts that a tunnel exists rather than merely a
     * process, and the two accesses are on different threads. libbox calls
     * `openTun` from whatever goroutine the tun inbound starts on, which
     * `fixAndroidStack` deliberately makes a fresh one, while the check reads it
     * on the worker that called `startOrReloadService`. Without the barrier
     * there is no guarantee the worker sees the write at all: the check this
     * class exists for would report FAILED over a live tunnel, or -- on a second
     * start -- pass on a stale non-null from the previous one.
     */
    @Volatile
    private var tunDescriptor: ParcelFileDescriptor? = null

    /**
     * The name the OS VPN screen and the notification show.
     *
     * Written on the main looper from the Intent, written again on the worker
     * when a system-initiated start adopts the persisted label, and read on
     * whichever thread libbox runs [openTun] on -- three threads, hence the
     * barrier.
     */
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
            // The only stop a person asked for -- the app's disconnect and the
            // notification's Stop action both arrive here -- so it is the only
            // one that forgets the configuration. A failure or a revocation
            // keeps it: the user has not disconnected, and throwing away what
            // they last connected with would break the always-on restart that
            // copy exists for.
            shutdown(TunnelStatus(Stage.DISCONNECTED), forget = true)
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
        // The configuration is resolved on the worker rather than here: reading
        // or writing the persisted copy is file I/O, and this method runs on the
        // main looper. Queueing it also puts the write and the delete on one
        // thread, so a stop cannot race the start that is persisting.
        worker.execute { startBox(intent?.getStringExtra(EXTRA_CONFIG)) }

        // START_NOT_STICKY, with always-on VPN in mind rather than in spite of
        // it. Always-on does not rely on sticky redelivery -- the framework
        // itself starts the configured VPN's service through the
        // `android.net.VpnService` intent-filter and starts it again if it dies
        // -- while a sticky restart would also resurrect a tunnel in the window
        // between a user-initiated stop and the stopSelf that answers it.
        return START_NOT_STICKY
    }

    private fun startBox(intentConfig: String?) {
        val request = resolveStartRequest(intentConfig)
        if (request == null) {
            shutdown(
                TunnelStatus(
                    Stage.FAILED,
                    "This tunnel was started without a sing-box configuration and none was on " +
                        "file. Android starts this service itself for always-on VPN and after " +
                        "reclaiming the process, and those starts carry no extras -- connect once " +
                        "from the app, which is what writes the configuration they reuse.",
                ),
            )
            return
        }
        if (label.isBlank() && request.label.isNotBlank()) {
            // A system-initiated start has no label extra, and the label is what
            // the OS VPN screen and the notification name the tunnel by. Taking
            // it from the persisted copy is what stops always-on rendering as an
            // anonymous tunnel nobody can identify.
            label = request.label
            mainHandler.post { notification.show(label, "Starting") }
        }
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
            server.startOrReloadService(request.config, OverrideOptions())
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

    /** What one start needs: the configuration, and what to call the tunnel. */
    private class StartRequest(val config: String, val label: String)

    /**
     * What to start, from the Intent when there is one and from disk when there
     * is not.
     *
     * The Intent carries a configuration for every start the app asks for. It
     * carries none when ANDROID starts the service: always-on VPN, which the
     * framework starts through this service's `android.net.VpnService`
     * intent-filter with no extras, and a restart after the system reclaimed the
     * process. Both were unserviceable while the configuration existed only in
     * the extras -- a feature the manifest declares and the code could not
     * perform, failing with a message that blamed a plugin bug. The iOS half of
     * this package already persists its start options for the identical reason
     * (the VPN switch in Settings starts a provider with nil options), so this
     * is the same decision on the other platform rather than a new one.
     */
    private fun resolveStartRequest(intentConfig: String?): StartRequest? {
        if (intentConfig.isNullOrEmpty()) return readStartRequest()
        val request = StartRequest(intentConfig, label)
        persistStartRequest(request)
        return request
    }

    /**
     * The last configuration the app asked for, in this app's own files
     * directory, mode 0600.
     *
     * Not encrypted, and that is the threat model rather than an omission.
     * `MODE_PRIVATE` in `filesDir` is readable by this uid and nothing else, and
     * the only attacker past that is root on the device -- who can already read
     * this process's memory, where the same credentials sit as long as the
     * tunnel is up, and the Intent extras they arrived in. A key to decrypt this
     * file would have to live beside it under exactly the same protection, which
     * buys a step and not a defence. What DOES matter is that a disconnect
     * removes it, which [forgetStartRequest] is for.
     *
     * Written through a temp file and renamed: a start interrupted mid-write
     * would otherwise leave a truncated configuration for the next
     * system-initiated start to fail on, reporting a broken configuration where
     * there had only been a broken write. Rename within one directory is atomic.
     */
    private fun persistStartRequest(request: StartRequest) {
        runCatching {
            val json = JSONObject()
                .put(KEY_CONFIG, request.config)
                .put(KEY_LABEL, request.label)
                .toString()
            // openFileOutput rather than File(..).writeText: it is the call that
            // names MODE_PRIVATE, which is where the mode comes from.
            openFileOutput(START_REQUEST_TEMP, Context.MODE_PRIVATE).use { out ->
                out.write(json.toByteArray())
                out.fd.sync()
            }
            val temp = File(filesDir, START_REQUEST_TEMP)
            if (!temp.renameTo(File(filesDir, START_REQUEST_FILE))) {
                temp.delete()
                error("could not rename $START_REQUEST_TEMP onto $START_REQUEST_FILE")
            }
        }.onFailure {
            // Not fatal to THIS start, which has the configuration in hand. What
            // is lost is the next always-on or system-initiated one, so it is
            // logged as the error it will look like then rather than swallowed.
            Log.e(TAG, "could not persist the configuration; a system-initiated start will fail", it)
        }
    }

    private fun readStartRequest(): StartRequest? {
        val raw = runCatching { openFileInput(START_REQUEST_FILE).use { it.readBytes() } }
            .getOrElse { failure ->
                // Absent is the ordinary case -- nobody has connected yet -- and
                // is not worth a log line. Anything else is.
                if (failure !is FileNotFoundException) {
                    Log.e(TAG, "could not read the persisted configuration", failure)
                }
                return null
            }
        return runCatching {
            val json = JSONObject(String(raw))
            val config = json.getString(KEY_CONFIG)
            if (config.isEmpty()) null else StartRequest(config, json.optString(KEY_LABEL))
        }.getOrElse {
            // Left on disk rather than deleted: the next connect overwrites it,
            // and a file that would not parse is the only evidence of why an
            // always-on start failed.
            Log.e(TAG, "the persisted configuration is not readable JSON", it)
            null
        }
    }

    /**
     * Forgets the configuration.
     *
     * A disconnect the person performed must leave nothing behind that a later
     * always-on start could bring back up, and nothing on disk they would be
     * right to believe is gone: this file holds the VLESS and Hysteria2
     * credentials in clear, which is the whole content of a share URI.
     */
    private fun forgetStartRequest() {
        deleteFile(START_REQUEST_FILE)
        deleteFile(START_REQUEST_TEMP)
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
        //
        // It is also what makes a system-initiated start (always-on, or a restart
        // after the process was reclaimed) legitimate rather than a hole. Consent
        // is granted once to the APP and held by the framework -- it is not
        // per-start and not per-Activity, which is why prepare() returns null on
        // a start no Activity was involved in, and why enabling always-on is
        // possible at all: the system's own VPN screen will not offer it for an
        // app that has never been prepared. A start that gets here without
        // consent is the withdrawn case above and fails here, loudly, with no
        // tunnel.
        if (prepare(this) != null) {
            error("android: VPN permission is not granted, so no TUN interface was created")
        }

        val builder = Builder()
            .setSession(label.ifBlank { "vpn-stack" })
            // 9000 when libbox reports nothing: it is sing-box's own documented
            // default for a tun inbound and the value app/lib/config/ emits, so
            // the fallback cannot disagree with the MTU sing-box sized its own
            // buffers to. establish() throws IllegalArgumentException("Bad mtu")
            // on 0, from inside a Go callback, where the stack names neither the
            // configuration nor the missing key.
            .setMtu(if (options.mtu > 0) options.mtu else DEFAULT_MTU)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        // What the system's own VPN dialog opens when the user taps the active
        // profile. It is the only handle on this tunnel outside the app, and on
        // an always-on start there was never a notification tap to have come
        // from. Resolved rather than named, for the reason TunnelNotification
        // resolves it too: this plugin has no business knowing one app's
        // package layout.
        val open = packageManager.getLaunchIntentForPackage(packageName)
        if (open != null) {
            builder.setConfigureIntent(
                PendingIntent.getActivity(this, 0, open, PENDING_INTENT_FLAGS),
            )
        }

        // No setUnderlyingNetworks call, here or on a network change, and that is
        // the documented default rather than an omission: a VpnService that never
        // sets them behaves as if null were set, which means "follow the system
        // default network", which is what a phone moving between wifi and
        // cellular wants. Pinning the array to whatever DefaultNetworkMonitor
        // last saw would be strictly worse -- that monitor answers a NOT_VPN
        // request of its own, so its choice can differ from the system default,
        // and the capabilities Android derives for the VPN network (metered,
        // validated) would then describe a network the traffic is not on.
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
        } else {
            // A VpnService routes exactly what addRoute() was given before
            // establish() and there is no way to add one afterwards, so a tun
            // built with auto_route off receives no packet at all. Establishing
            // it would produce the same lie as a proxy-only configuration: a
            // descriptor exists, the check below passes, and the UI says
            // Connected over an interface nothing reaches.
            error(
                "android: the tun inbound has auto_route off, so no route would be installed and " +
                    "nothing would reach the tunnel. app/lib/config/ emits auto_route: true; a " +
                    "configuration that does not is unusable on Android.",
            )
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
        // ON THE WORKER, and then waited for. The release is a libbox call like
        // every other one, and the worker is the whole reason two of them cannot
        // overlap: run straight from here it would run on the main looper, which
        // is an ANR on its own (closeService stops the box synchronously), and it
        // would run beside a startOrReloadService still in flight -- closing a
        // command server underneath its own start is a use-after-close inside Go,
        // which arrives as a native crash with no Kotlin frame to read.
        //
        // The wait is not belt-and-braces either. `worker.shutdown()` refuses NEW
        // work and returns at once -- it waits for nothing -- so without
        // awaitTermination the process can reach the end of onDestroy with the
        // release still queued behind a start, which is precisely the leak the
        // paragraph above describes, kept alive by the call that looks like it
        // prevents it. Queue order puts the release after the start; the wait is
        // what makes it happen at all.
        try {
            worker.execute { releaseEngine() }
        } catch (rejected: RejectedExecutionException) {
            // The executor is already down, so nothing can be running on it and
            // the main thread is safe to release from. A leaked engine is worse
            // than a slow onDestroy.
            Log.e(TAG, "worker already shut down; releasing on the main thread", rejected)
            releaseEngine()
        }
        worker.shutdown()
        val drained = try {
            worker.awaitTermination(RELEASE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        } catch (interrupted: InterruptedException) {
            // Restored rather than swallowed: onDestroy is not the place to
            // decide that whoever interrupted this thread did not mean it.
            Thread.currentThread().interrupt()
            false
        }
        if (!drained) {
            // Named rather than ignored, and deliberately not followed by
            // shutdownNow(): what is still running is a Go call, which does not
            // observe a thread interrupt, so cancelling would report success over
            // an engine that is still coming down. This line is what identifies
            // a tun descriptor that outlived its service in a later bug report.
            Log.e(
                TAG,
                "libbox did not finish releasing within ${RELEASE_TIMEOUT_SECONDS}s; the engine " +
                    "may still be coming down as this process ends",
            )
        }
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

    /**
     * Stops everything and reports [status].
     *
     * [forget] drops the persisted configuration, and only a stop the person
     * asked for passes it: see [forgetStartRequest]. It runs on the worker beside
     * the write in [persistStartRequest], so a stop arriving while a start is
     * persisting cannot delete the file and then have it reappear.
     *
     * The body is [releaseEngine] and not a second copy of it: two written-out
     * teardowns are how the two grow a difference nobody chose, one of them
     * closing the descriptor the other leaks.
     */
    private fun shutdown(status: TunnelStatus, forget: Boolean = false) {
        try {
            worker.execute {
                releaseEngine()
                if (forget) forgetStartRequest()
                TunnelState.serviceRunning = false
                TunnelState.set(status)

                mainHandler.post {
                    notification.clear()
                    stopSelf()
                }
            }
        } catch (rejected: RejectedExecutionException) {
            // [onDestroy] has already closed the worker, so the engine is down or
            // coming down and there is nothing left to queue. Both entry points
            // that can arrive after a destroy -- libbox's serviceStop() and
            // onRevoke() -- are system callbacks, where an uncaught
            // RejectedExecutionException is a crash in place of a teardown that
            // had already happened. The status is still owed to whoever is
            // listening, and so is the delete: two unlinks on the calling thread
            // is a cheaper price than a credential left on disk.
            Log.w(TAG, "shutdown after the worker closed; reporting status only", rejected)
            if (forget) forgetStartRequest()
            TunnelState.serviceRunning = false
            TunnelState.set(status)
        }
    }

    companion object {
        const val TAG = "SingboxTunnel"
        const val ACTION_STOP = "io.github.asel1x.singbox_tunnel.STOP"
        const val EXTRA_CONFIG = "config"
        const val EXTRA_LABEL = "label"

        /** sing-box's own default tun MTU, for a configuration that names none. */
        private const val DEFAULT_MTU = 9000

        /**
         * How long onDestroy waits for libbox to finish releasing. A service
         * lifecycle callback has about twenty seconds before the system calls it
         * an ANR, and a start still in flight is seconds, so five bounds the wait
         * with room left over rather than trading one hang for another.
         */
        private const val RELEASE_TIMEOUT_SECONDS = 5L

        private const val START_REQUEST_FILE = "start-request.json"
        private const val START_REQUEST_TEMP = "start-request.json.tmp"
        private const val KEY_CONFIG = "config"
        private const val KEY_LABEL = "label"

        /**
         * FLAG_IMMUTABLE is mandatory from API 31 and available from 23; this
         * module's minSdk is 24, so there is no second branch to get wrong.
         */
        private const val PENDING_INTENT_FLAGS =
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE

        @Volatile
        private var libboxReady = false

        /**
         * The configuration travels in the Intent rather than in a static field:
         * a static would be lost if the process were recycled between the plugin
         * writing it and the service reading it, and a few kilobytes of JSON is
         * nowhere near the Binder transaction limit.
         *
         * The service also keeps its own copy on disk, which is a different
         * question -- see [resolveStartRequest]. The Intent is what the app's own
         * starts use; the copy is what the starts Android performs by itself have
         * to read, because those carry no extras at all.
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
