package org.xrayrust.devicehost

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import org.xrayrust.mobile.XrayAndroidUidAdmission
import org.xrayrust.mobile.XrayTunAdmissionOptions
import org.xrayrust.mobile.XrayTunFlowAdmission
import java.util.concurrent.atomic.AtomicInteger
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
    @Volatile private var selectedBackend = XrayTunBackend.FileDescriptor
    @Volatile private var probeOnly = false
    @Volatile private var admissionEnabled = false
    private val admissionAllowed = AtomicInteger()
    private val admissionDenied = AtomicInteger()

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
            ACTION_START -> startFromStoredProfile(intent)
            ACTION_STOP -> stopAndFinish()
            ACTION_RESET_COUNTERS -> resetCounters()
            ACTION_CLOSE_CONNECTIONS -> closeConnections()
            ACTION_RAPID_STOP -> {
                startFromStoredProfile(intent)
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
            detail = if (probeOnly) "probe-only" else "",
            runtimeGeneration = generation,
        )
        updateNotification("VPN connected")
        Log.i(
            LOG_TAG,
            "XRAY_ANDROID_LIFECYCLE state=running generation=$generation " +
                "tunBackend=${DeviceGateOptions.backendName(selectedBackend)}",
        )
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

    private fun startFromStoredProfile(intent: Intent) {
        if (xrayVpnRuntimeSnapshot().running) {
            Log.w(LOG_TAG, "XRAY_ANDROID_LIFECYCLE state=start-rejected reason=already-running")
            return
        }
        val backend = try {
            DeviceGateOptions.backend(intent.getStringExtra(DeviceGateOptions.EXTRA_TUN_BACKEND))
        } catch (error: IllegalArgumentException) {
            onXrayTunnelStartFailed(error)
            return
        }
        selectedBackend = backend
        probeOnly = intent.getBooleanExtra("probe-only", false)
        admissionEnabled = intent.getBooleanExtra("tun-admission", false)
        admissionAllowed.set(0)
        admissionDenied.set(0)
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
                tunBackend = backend,
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
            .put("tunBackend", DeviceGateOptions.backendName(selectedBackend))
            .put("probeOnly", probeOnly)
            .put("admissionEnabled", admissionEnabled)
            .put("admissionAllowed", admissionAllowed.get())
            .put("admissionDenied", admissionDenied.get())
            .put("runtimeRunning", runtime.running)
            .put("runtimeGeneration", status.runtimeGeneration)
            .put("residentMemoryBytes", residentMemoryBytes())
            .put("threadCount", processThreadCount())
            .put("processCpuMillis", android.os.Process.getElapsedCpuTime())
            .put("elapsedRealtimeMillis", android.os.SystemClock.elapsedRealtime())
            .put("activeConnections", runtime.activeConnections)
            .put("tunInboundPackets", stats.inboundPackets)
            .put("tunOutboundPackets", stats.outboundPackets)
            .put("tunDroppedPackets", stats.droppedPackets)
            .put("udpRemoteOpenEvents", stats.udpRemoteOpenEvents)
            .put("udpRemoteWrittenBytes", stats.udpRemoteWrittenBytes)
            .put("udpRemoteReadBytes", stats.udpRemoteReadBytes)
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

    private fun processThreadCount(): Int = runCatching {
        File("/proc/self/status").useLines { lines ->
            lines.first { it.startsWith("Threads:") }.substringAfter(':').trim().toInt()
        }
    }.getOrDefault(0)

    override fun tunAdmissionOptions(): XrayTunAdmissionOptions? {
        if (!admissionEnabled) return null
        if (Build.VERSION.SDK_INT < 29) throw UnsupportedOperationException("UID admission requires Android 10+")
        check(probeOnly) { "Device admission test requires probe-only mode" }
        val probePackage = packageName.replace("org.xrayrust.devicehost", "org.xrayrust.deviceprobe")
        val uid = packageManager.getApplicationInfo(probePackage, 0).uid
        val connectivity = getSystemService(ConnectivityManager::class.java)
        val policy = XrayAndroidUidAdmission(connectivity, setOf(uid))
        return XrayTunAdmissionOptions(XrayTunFlowAdmission { flow ->
            val allowed = policy.admit(flow)
            if (allowed) admissionAllowed.incrementAndGet() else {
                admissionDenied.incrementAndGet()
                // Diagnostic only; never change the original denial on a retry.
                val retryUid = runCatching {
                    connectivity.getConnectionOwnerUid(flow.protocol, flow.source, flow.destination)
                }.getOrDefault(-2)
                Log.i(LOG_TAG, "XRAY_ADMISSION_DENIED protocol=${flow.protocol} retryOwnerUid=$retryUid expectedUid=$uid")
            }
            allowed
        }, timeoutMs = 500)
    }

    override fun buildTunnel(): Builder {
        if (!probeOnly) return super.buildTunnel()
        // Same interface as the SDK default, with only the separate probe UID.
        // Fail closed if this campaign's matching probe package is absent.
        return Builder()
            .setSession("xray-rust-device-probe")
            .setMtu(1_500)
            .addAddress("10.7.0.1", 32)
            .addRoute("0.0.0.0", 0)
            .addAddress("fd00:7872::1", 128)
            .addRoute("::", 0)
            .addAllowedApplication(packageName.replace("org.xrayrust.devicehost", "org.xrayrust.deviceprobe"))
    }

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
