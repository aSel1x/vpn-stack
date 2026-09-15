package io.github.asel1x.singbox_tunnel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build

/**
 * The notification without which Android kills a VpnService.
 *
 * It is not decoration. A service that calls startForegroundService and then
 * does not call startForeground within five seconds is killed with
 * ForegroundServiceDidNotStartInTimeException, so this is the first thing
 * [SingboxVpnService.onStartCommand] does -- before the config is even read.
 */
class TunnelNotification(private val service: Service) {
    private val manager: NotificationManager? =
        service.getSystemService(NotificationManager::class.java)

    @Suppress("DEPRECATION")
    fun show(label: String, state: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager?.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    "VPN tunnel",
                    // LOW: ongoing and silent. IMPORTANCE_DEFAULT would make
                    // every reconnect chime.
                    NotificationManager.IMPORTANCE_LOW,
                ),
            )
        }

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(service, CHANNEL_ID)
        } else {
            Notification.Builder(service).setPriority(Notification.PRIORITY_LOW)
        }

        builder
            .setContentTitle(label.ifBlank { "VPN" })
            .setContentText(state)
            .setSmallIcon(R.drawable.ic_singbox_tunnel)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)

        // Whatever the host app's launcher activity is. Naming an Activity class
        // here would couple this plugin to one app's package layout, and the
        // plugin has no business knowing it.
        val open = service.packageManager.getLaunchIntentForPackage(service.packageName)
        if (open != null) {
            builder.setContentIntent(
                PendingIntent.getActivity(service, 0, open, PENDING_FLAGS),
            )
        }

        builder.addAction(
            Notification.Action.Builder(
                Icon.createWithResource(service, R.drawable.ic_singbox_tunnel),
                "Stop",
                PendingIntent.getService(
                    service,
                    0,
                    Intent(service, SingboxVpnService::class.java)
                        .setAction(SingboxVpnService.ACTION_STOP),
                    PENDING_FLAGS,
                ),
            ).build(),
        )

        service.startForeground(NOTIFICATION_ID, builder.build())
    }

    /**
     * Posts something sing-box asked the user to see.
     *
     * Its own channel per type id, because these are events (an authentication
     * challenge, a deprecation warning) and must not be silenced along with the
     * ongoing one above.
     */
    @Suppress("DEPRECATION")
    fun showEvent(identifier: String, typeId: Int, typeName: String, title: String, body: String) {
        val channel = "event-$typeId"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager?.createNotificationChannel(
                NotificationChannel(
                    channel,
                    typeName.ifBlank { "sing-box" },
                    NotificationManager.IMPORTANCE_HIGH,
                ),
            )
        }
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(service, channel)
        } else {
            Notification.Builder(service).setPriority(Notification.PRIORITY_HIGH)
        }
        builder
            .setContentTitle(title)
            .setContentText(body)
            .setSmallIcon(R.drawable.ic_singbox_tunnel)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
        manager?.notify(identifier, typeId, builder.build())
    }

    fun cancelEvent(identifier: String, typeId: Int) {
        manager?.cancel(identifier, typeId)
    }

    fun clear() {
        // STOP_FOREGROUND_REMOVE landed in API 24, which is this module's
        // minSdk, so there is no boolean-overload branch to get wrong.
        service.stopForeground(Service.STOP_FOREGROUND_REMOVE)
    }

    private companion object {
        const val CHANNEL_ID = "singbox-tunnel"
        const val NOTIFICATION_ID = 1

        // FLAG_IMMUTABLE is mandatory from API 31 and available from 23; this
        // module's minSdk is 24, so there is no second branch to get wrong.
        const val PENDING_FLAGS =
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    }
}
