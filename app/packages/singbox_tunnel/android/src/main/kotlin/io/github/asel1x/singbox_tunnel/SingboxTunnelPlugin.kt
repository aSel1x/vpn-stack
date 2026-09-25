package io.github.asel1x.singbox_tunnel

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.util.Log
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.PluginRegistry

/**
 * The bridge: a MethodChannel for commands, an EventChannel for status.
 *
 * It owns no tunnel state of its own. Everything it reports comes from
 * [TunnelState], which [SingboxVpnService] writes -- so a screen rebuilt after
 * the engine was detached and reattached sees what the service knows, not what
 * this object last happened to remember.
 */
class SingboxTunnelPlugin :
    FlutterPlugin,
    MethodChannel.MethodCallHandler,
    EventChannel.StreamHandler,
    ActivityAware,
    PluginRegistry.ActivityResultListener,
    PluginRegistry.RequestPermissionsResultListener {

    private var commands: MethodChannel? = null
    private var statusChannel: EventChannel? = null
    private var context: Context? = null

    private var activityBinding: ActivityPluginBinding? = null

    /** The one in-flight `VpnService.prepare` consent dialog, if any. */
    private var permissionResult: MethodChannel.Result? = null

    /**
     * The POST_NOTIFICATIONS request that is waiting for an answer, if any, and
     * whether there is one at all.
     *
     * Two fields and not one, because this request is also made with nothing to
     * answer -- [start] asks opportunistically and has nobody to report to -- and
     * `null` would then mean both "no request" and "a request nobody is waiting
     * on". Raising a second dialog over the first loses one of the two results.
     */
    private var notificationResult: MethodChannel.Result? = null
    private var notificationRequestInFlight = false

    private var sink: EventChannel.EventSink? = null
    private val statusListener: (TunnelStatus) -> Unit = { status ->
        sink?.success(status.toEvent())
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        commands = MethodChannel(binding.binaryMessenger, COMMAND_CHANNEL).also {
            it.setMethodCallHandler(this)
        }
        statusChannel = EventChannel(binding.binaryMessenger, STATUS_CHANNEL).also {
            it.setStreamHandler(this)
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        commands?.setMethodCallHandler(null)
        statusChannel?.setStreamHandler(null)
        commands = null
        statusChannel = null
        context = null
        // Not stopping the tunnel: the engine going away is the UI going away,
        // and a VPN that drops when the app is swiped out of recents is not a
        // VPN. The service is foreground and outlives this on purpose.
    }

    // ---- status ----

    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        sink = events
        TunnelState.addListener(statusListener)
        // Replayed immediately. A screen built while the tunnel is already up
        // would otherwise render as disconnected until something changed, which
        // for a healthy tunnel is never.
        events?.success(TunnelState.current.toEvent())
    }

    override fun onCancel(arguments: Any?) {
        TunnelState.removeListener(statusListener)
        sink = null
    }

    // ---- commands ----

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "prepare" -> result.success(isPrepared())
            "requestPermission" -> requestPermission(result)
            "notificationPermission" -> result.success(notificationsAllowed())
            "requestNotificationPermission" -> requestNotifications(result)
            "status" -> result.success(TunnelState.current.toEvent())
            "start" -> start(call, result)
            "stop" -> stop(result)
            else -> result.notImplemented()
        }
    }

    /**
     * `VpnService.prepare` returns null when consent is already on file, and an
     * Intent that has to be shown from an Activity otherwise. Both cases are
     * handled; the third -- never asking, and running a service that quietly
     * establishes nothing -- is the one this plugin refuses to have.
     */
    private fun isPrepared(): Boolean {
        val ctx = context ?: return false
        return VpnService.prepare(ctx) == null
    }

    private fun requestPermission(result: MethodChannel.Result) {
        val ctx = context
        if (ctx == null) {
            result.error(
                "no_context",
                "The plugin is not attached to a Flutter engine, so it cannot ask for VPN " +
                    "permission. Nothing was started.",
                null,
            )
            return
        }
        val consent: Intent? = VpnService.prepare(ctx)
        if (consent == null) {
            result.success(true)
            return
        }
        val activity: Activity? = activityBinding?.activity
        if (activity == null) {
            // Not swallowed into "false". Android will only show this dialog
            // from an Activity, so a request made while the app is in the
            // background is a different problem from a user who said no, and
            // telling them apart is the difference between "tap Connect again"
            // and "reinstall the app".
            result.error(
                "no_activity",
                "Android's VPN consent dialog can only be shown from an Activity and this plugin " +
                    "is not attached to one. Bring the app to the foreground and try again; " +
                    "nothing was started.",
                null,
            )
            return
        }
        if (permissionResult != null) {
            result.error(
                "already_requesting",
                "A VPN consent dialog is already open. Nothing was started.",
                null,
            )
            return
        }
        permissionResult = result
        activity.startActivityForResult(consent, REQUEST_VPN_PERMISSION)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        if (requestCode != REQUEST_VPN_PERMISSION) return false
        val pending = permissionResult
        permissionResult = null
        // RESULT_OK is the only answer that means consent. Anything else --
        // cancelled, backed out, a device policy that forbids VPNs -- is a no,
        // and is reported as a no rather than retried.
        pending?.success(resultCode == Activity.RESULT_OK)
        return true
    }

    /**
     * Whether the tunnel's ongoing notification can be shown at all.
     *
     * From API 33 POST_NOTIFICATIONS is a runtime permission and a foreground
     * service's own notification is subject to it: denied, the service still runs
     * and still routes packets, but nothing is drawn -- no state, and no Stop
     * action. Below 33 the permission does not exist, the notification is always
     * shown, and this is true without a dialog ever being raised.
     */
    private fun notificationsAllowed(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true
        val ctx = context ?: return false
        return ctx.checkSelfPermission(POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
    }

    /**
     * Asks for POST_NOTIFICATIONS, and treats every refusal as an outcome rather
     * than an error.
     *
     * The plugin asks, not the host app. `app/android/` is generated by
     * `flutter create` in CI and gitignored, so a request hand-added there is
     * deleted on the next run -- which is the same reason this package carries its
     * own AndroidManifest.xml, and the manifest has declared this permission from
     * the start with nothing anywhere requesting it.
     *
     * Unlike VPN consent, every failure path here answers false instead of
     * raising. VPN consent has to tell "the user said no" from "there was no
     * Activity to ask from", because the first means reinstall-level trouble and
     * the second means bring the app forward and tap again. Here both mean one
     * thing -- no notification, a tunnel that works anyway -- and a caller that
     * had to branch on an error code to learn that would be branching on nothing.
     *
     * [result] is null when nobody is waiting: see [notificationRequestInFlight].
     */
    private fun requestNotifications(result: MethodChannel.Result?) {
        if (notificationsAllowed()) {
            result?.success(true)
            return
        }
        if (notificationRequestInFlight) {
            result?.success(false)
            return
        }
        val activity = activityBinding?.activity
        if (activity == null) {
            Log.w(TAG, "no Activity to request POST_NOTIFICATIONS from; the tunnel will be silent")
            result?.success(false)
            return
        }
        notificationResult = result
        notificationRequestInFlight = true
        // Activity.requestPermissions and not ActivityCompat: androidx.core is
        // not a dependency of this module and adding one to ask a question the
        // framework answers from API 23 -- below this module's minSdk of 24 --
        // would be a dependency for nothing.
        activity.requestPermissions(arrayOf(POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ): Boolean {
        if (requestCode != REQUEST_NOTIFICATIONS) return false
        val pending = notificationResult
        notificationResult = null
        notificationRequestInFlight = false
        // An empty grantResults is Android's documented signal that the request
        // was cancelled, not an edge case worth a separate answer: it is a no,
        // like a denial.
        val granted = grantResults.isNotEmpty() &&
            grantResults[0] == PackageManager.PERMISSION_GRANTED
        pending?.success(granted)
        return true
    }

    private fun start(call: MethodCall, result: MethodChannel.Result) {
        val ctx = context
        if (ctx == null) {
            result.error("no_context", "The plugin is not attached to a Flutter engine.", null)
            return
        }
        val config = call.argument<String>("config")
        if (config.isNullOrEmpty()) {
            result.error(
                "no_config",
                "start was called without a sing-box configuration. The plugin does not build " +
                    "one -- app/lib/config/ does -- so there is nothing to fall back to.",
                null,
            )
            return
        }
        if (!isPrepared()) {
            result.error(
                "no_permission",
                "Android has not granted VPN permission, so no TUN interface can be opened. " +
                    "Nothing was started.",
                null,
            )
            return
        }
        val label = call.argument<String>("label").orEmpty()

        // Asked here as well as on demand from Dart, because a tunnel with no
        // notification on API 33+ has no visible state and no Stop button, and
        // the one moment the user certainly expects a dialog from this app is the
        // moment they tapped Connect. Nothing waits on it and nothing is gated on
        // it: the answer only decides whether the notification appears, and the
        // grant, if it comes, lands before the service posts its CONNECTED one.
        // There is no consent dialog to collide with either -- isPrepared() above
        // is already true, so VpnService.prepare() raised none.
        requestNotifications(null)

        // Set here rather than in the service so there is no window in which a
        // start has been asked for and the status still reads disconnected: the
        // service takes milliseconds to arrive, and a UI polling in between
        // would draw the button as idle.
        TunnelState.set(TunnelStatus(Stage.CONNECTING))
        try {
            SingboxVpnService.start(ctx, config, label)
        } catch (failure: Throwable) {
            val message = "Android refused to start the VPN service: " +
                (failure.message ?: failure.toString())
            TunnelState.set(TunnelStatus(Stage.FAILED, message))
            result.error("service_start_failed", message, null)
            return
        }
        result.success(null)
    }

    private fun stop(result: MethodChannel.Result) {
        val ctx = context
        if (ctx == null) {
            result.error("no_context", "The plugin is not attached to a Flutter engine.", null)
            return
        }
        if (!TunnelState.serviceRunning) {
            // Tearing down nothing is not an error, and must not become one by
            // waiting for a service that was never there to confirm.
            TunnelState.set(TunnelStatus(Stage.DISCONNECTED))
            result.success(null)
            return
        }
        try {
            SingboxVpnService.stop(ctx)
        } catch (failure: Throwable) {
            val message = "Android refused to deliver the stop request: " +
                (failure.message ?: failure.toString())
            TunnelState.set(TunnelStatus(Stage.FAILED, message))
            result.error("service_stop_failed", message, null)
            return
        }
        result.success(null)
    }

    // ---- activity ----

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activityBinding = binding
        binding.addActivityResultListener(this)
        binding.addRequestPermissionsResultListener(this)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        detachActivity()
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activityBinding = binding
        binding.addActivityResultListener(this)
        binding.addRequestPermissionsResultListener(this)
    }

    override fun onDetachedFromActivity() {
        detachActivity()
    }

    private fun detachActivity() {
        activityBinding?.removeActivityResultListener(this)
        activityBinding?.removeRequestPermissionsResultListener(this)
        activityBinding = null
        // A consent dialog whose Activity went away will never deliver a result,
        // and a Dart future waiting on it would hang for ever.
        val pending = permissionResult
        permissionResult = null
        pending?.error(
            "activity_gone",
            "The Activity showing Android's VPN consent dialog was destroyed before it answered. " +
                "Nothing was started.",
            null,
        )

        // The notification request gets false rather than an error: its Activity
        // went away, so the grant did not happen, and "no notification" is a
        // truthful answer to the only question the caller asked. An error here
        // would make a caller handle a failure that costs them nothing.
        val pendingNotifications = notificationResult
        notificationResult = null
        notificationRequestInFlight = false
        pendingNotifications?.success(false)
    }

    private companion object {
        // Restated from lib/src/channels.dart. Two literals, one contract; a
        // mismatch shows up as MissingPluginException on the first call rather
        // than as a tunnel that silently does nothing.
        const val COMMAND_CHANNEL = "io.github.asel1x/singbox_tunnel/commands"
        const val STATUS_CHANNEL = "io.github.asel1x/singbox_tunnel/status"
        const val REQUEST_VPN_PERMISSION = 0x5642
        const val REQUEST_NOTIFICATIONS = 0x5643

        const val TAG = "SingboxTunnel"

        // The literal, not android.Manifest.permission.POST_NOTIFICATIONS: the
        // string has to match AndroidManifest.xml exactly, and this is the form
        // it is written in there. The constant exists only in API 33+ of the SDK
        // while this module declares minSdk 24, so it would also be an inlined
        // constant dressed up as a version-gated one.
        const val POST_NOTIFICATIONS = "android.permission.POST_NOTIFICATIONS"
    }
}
