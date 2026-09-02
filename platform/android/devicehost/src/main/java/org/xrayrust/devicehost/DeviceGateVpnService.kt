package org.xrayrust.devicehost

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.system.Os
import android.system.OsConstants
import android.util.Log
import org.json.JSONObject
import org.xrayrust.mobile.XrayCoreException
import org.xrayrust.mobile.XrayTunBackend
import org.xrayrust.mobile.XrayTunRuntimeProfile
import org.xrayrust.mobile.XrayTunStats
import org.xrayrust.mobile.XrayVpnService
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class DeviceGateVpnService : XrayVpnService() {
    private val sampler = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "xray-android-device-sampler").apply { isDaemon = true }
    }
    @Volatile private var lastStats = ZeroStats

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        sampler.scheduleWithFixedDelay(
            { runCatching { emitSample() } },
            0,
            SAMPLE_INTERVAL_SECONDS,
            TimeUnit.SECONDS,
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startFromStoredProfile()
            ACTION_STOP -> stopAndFinish()
            ACTION_RESET_COUNTERS -> resetCounters()
            ACTION_CLOSE_CONNECTIONS -> closeConnections()
            ACTION_RAPID_STOP -> {
                startFromStoredProfile()
                stopAndFinish()
            }
            else -> {
                DeviceGateStatus.write(this, state = "idle", detail = "missing-action")
                stopSelf(startId)
            }
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        DeviceGateStatus.write(this, state = "revoked")
        stopAndFinish()
        super.onRevoke()
    }

    override fun onXrayTunnelStarted() {
        val generation = DeviceGateStatus.incrementGeneration(this)
        lastStats = ZeroStats
        DeviceGateStatus.write(
            this,
            state = "running",
            runtimeGeneration = generation,
        )
        updateNotification("VPN connected")
        Log.i(LOG_TAG, "XRAY_ANDROID_LIFECYCLE state=running generation=$generation")
        emitSample()
    }

    override fun onXrayTunnelStartFailed(error: Throwable) {
        val code = (error as? XrayCoreException)?.code
        val detail = if (code == null) {
            "start-failed-${error.javaClass.simpleName}"
        } else {
            "start-failed-core-$code"
        }
        DeviceGateStatus.write(this, state = "failed", detail = detail)
        Log.e(LOG_TAG, "XRAY_ANDROID_LIFECYCLE state=start-failed kind=$detail")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onXrayTunnelFatalError(error: Throwable) {
        val count = DeviceGateStatus.incrementFatalTunErrors(this)
        DeviceGateStatus.write(
            this,
            state = "fatal",
            detail = error.javaClass.simpleName,
            fatalTunErrors = count,
        )
        Log.e(
            LOG_TAG,
            "XRAY_ANDROID_LIFECYCLE state=fatal fatalTunErrors=$count " +
                "kind=${error.javaClass.simpleName}",
        )
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        sampler.shutdownNow()
        super.onDestroy()
    }

    private fun startFromStoredProfile() {
        startForeground(NOTIFICATION_ID, notification("VPN starting"))
        DeviceGateStatus.write(this, state = "starting")
        val configJson = try {
            EncryptedProfileStore(this).read()
        } catch (error: Throwable) {
            DeviceGateStatus.write(
                this,
                state = "failed",
                detail = "profile-read-${error.javaClass.simpleName}",
            )
            Log.e(
                LOG_TAG,
                "XRAY_ANDROID_LIFECYCLE state=profile-read-failed " +
                    "kind=${error.javaClass.simpleName}",
            )
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        if (configJson == null) {
            DeviceGateStatus.write(this, state = "failed", detail = "profile-missing")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        try {
            startXrayTunnel(
                configJson = configJson,
                tunBackend = XrayTunBackend.FileDescriptor,
                tunRuntimeProfile = XrayTunRuntimeProfile.MobilePlus,
            )
        } catch (error: Throwable) {
            onXrayTunnelStartFailed(error)
        }
    }

    private fun stopAndFinish() {
        runCatching { stopXrayTunnel() }
            .onFailure { error ->
                Log.e(
                    LOG_TAG,
                    "XRAY_ANDROID_LIFECYCLE state=stop-failed " +
                        "kind=${error.javaClass.simpleName}",
                )
            }
        DeviceGateStatus.write(this, state = "stopped")
        emitSample()
        Log.i(LOG_TAG, "XRAY_ANDROID_LIFECYCLE state=stopped")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun resetCounters() {
        val runtime = xrayVpnRuntimeSnapshot()
        if (runtime.running) {
            DeviceGateStatus.write(this, state = "running", detail = "reset-rejected-running")
            Log.w(LOG_TAG, "XRAY_ANDROID_LIFECYCLE state=reset-rejected reason=running")
            return
        } else {
            DeviceGateStatus.resetCounters(this)
            lastStats = ZeroStats
            DeviceGateStatus.write(
                this,
                state = "stopped",
                detail = "counters-reset",
                runtimeGeneration = 0,
                fatalTunErrors = 0,
            )
            Log.i(LOG_TAG, "XRAY_ANDROID_LIFECYCLE state=counters-reset")
        }
        stopSelf()
    }

    private fun closeConnections() {
        val wasRunning = xrayVpnRuntimeSnapshot().running
        val accepted = closeAllXrayVpnConnections()
        Log.i(
            LOG_TAG,
            "XRAY_ANDROID_LIFECYCLE state=connections-close-requested accepted=$accepted",
        )
        emitSample()
        if (!wasRunning) {
            stopSelf()
        }
    }

    private fun emitSample() {
        val runtime = xrayVpnRuntimeSnapshot()
        runtime.tunStats?.let { lastStats = it }
        val status = DeviceGateStatus.read(this)
        val stats = runtime.tunStats ?: lastStats
        val sample = JSONObject()
            .put("runtimeGeneration", status.runtimeGeneration)
            .put("residentMemoryBytes", residentMemoryBytes())
            .put("threadCount", Thread.getAllStackTraces().size)
            .put("activeConnections", runtime.activeConnections)
            .put("tunInboundPackets", stats.inboundPackets)
            .put("tunOutboundPackets", stats.outboundPackets)
            .put("fatalTunErrors", status.fatalTunErrors)
            .put("unrecoveredTransitions", 0)
        Log.i(LOG_TAG, "XRAY_ANDROID_SAMPLE $sample")
    }

    private fun residentMemoryBytes(): Long = runCatching {
        val residentPages = File("/proc/self/statm")
            .readText()
            .trim()
            .split(Regex("\\s+"))[1]
            .toLong()
        residentPages * Os.sysconf(OsConstants._SC_PAGESIZE)
    }.getOrDefault(0L)

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(
                NotificationChannel(
                    NOTIFICATION_CHANNEL,
                    "Xray device gate VPN",
                    NotificationManager.IMPORTANCE_LOW,
                ),
            )
        }
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, notification(text))
    }

    private fun notification(text: String): Notification {
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, NOTIFICATION_CHANNEL)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("Xray Device Gate")
            .setContentText(text)
            .setContentIntent(contentIntent)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_START = "org.xrayrust.devicehost.START"
        const val ACTION_STOP = "org.xrayrust.devicehost.STOP"
        const val ACTION_RESET_COUNTERS = "org.xrayrust.devicehost.RESET_COUNTERS"
        const val ACTION_CLOSE_CONNECTIONS = "org.xrayrust.devicehost.CLOSE_CONNECTIONS"
        const val ACTION_RAPID_STOP = "org.xrayrust.devicehost.RAPID_STOP"
        const val LOG_TAG = "XrayDeviceGate"
        private const val NOTIFICATION_CHANNEL = "xray-device-gate-vpn"
        private const val NOTIFICATION_ID = 5041
        private const val SAMPLE_INTERVAL_SECONDS = 10L

        private val ZeroStats = XrayTunStats(
            inboundPackets = 0,
            outboundPackets = 0,
            droppedPackets = 0,
            udpRemoteOpenEvents = 0,
            udpRemoteUdp443OpenEvents = 0,
            udpRemoteWrittenBytes = 0,
            udpRemoteReadBytes = 0,
            tcpOpenEvents = 0,
            tcpOpenDurationMsTotal = 0,
            tcpOpenDurationMsMax = 0,
            tcpFirstByteEvents = 0,
            tcpFirstByteDurationMsTotal = 0,
            tcpFirstByteDurationMsMax = 0,
            tcp443OpenEvents = 0,
            tcp443OpenDurationMsTotal = 0,
            tcp443OpenDurationMsMax = 0,
            tcp443FirstByteEvents = 0,
            tcp443FirstByteDurationMsTotal = 0,
            tcp443FirstByteDurationMsMax = 0,
        )
    }
}
