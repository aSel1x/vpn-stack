package io.github.asel1x.singbox_tunnel

import android.os.Handler
import android.os.Looper
import java.util.concurrent.CopyOnWriteArrayList

/**
 * The four stages the Dart interface declares. Nothing wider, so a state that
 * exists here but not there cannot be invented.
 */
enum class Stage(val wireName: String) {
    DISCONNECTED("disconnected"),
    CONNECTING("connecting"),
    CONNECTED("connected"),
    FAILED("failed"),
}

data class TunnelStatus(val stage: Stage, val message: String? = null) {
    fun toEvent(): Map<String, Any?> = mapOf("stage" to stage.wireName, "message" to message)
}

/**
 * Where the plugin and the VpnService meet.
 *
 * They are two objects in one process -- the service declares no
 * android:process -- and the service is the only thing that knows whether a TUN
 * interface exists, while the plugin is the only thing holding the EventChannel
 * sink. A binder between them would be a second contract to keep honest for no
 * gain inside a single process.
 *
 * Listeners are notified on the main looper because EventChannel.EventSink must
 * be used from the platform thread; libbox calls back from Go goroutines, so
 * without this post the first status from a failing start would crash the
 * engine rather than report the failure.
 */
object TunnelState {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val listeners = CopyOnWriteArrayList<(TunnelStatus) -> Unit>()

    @Volatile
    var current: TunnelStatus = TunnelStatus(Stage.DISCONNECTED)
        private set

    /** True while SingboxVpnService is alive, so `stop` on nothing is not an error. */
    @Volatile
    var serviceRunning: Boolean = false

    fun set(status: TunnelStatus) {
        current = status
        mainHandler.post { listeners.forEach { it(status) } }
    }

    fun addListener(listener: (TunnelStatus) -> Unit) {
        listeners.add(listener)
    }

    fun removeListener(listener: (TunnelStatus) -> Unit) {
        listeners.remove(listener)
    }
}
