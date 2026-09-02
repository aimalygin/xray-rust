package org.xrayrust.deviceprobe

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.SystemClock
import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class ProbeService : Service() {
    private val executor = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "xray-android-device-probe").apply { isDaemon = true }
    }
    private val stressExecutor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "xray-android-device-stress").apply { isDaemon = true }
    }
    private val active = AtomicBoolean()
    private val stressActive = AtomicBoolean()
    private val httpPassed = AtomicLong()
    private val httpFailed = AtomicLong()
    private val udpPassed = AtomicLong()
    private val udpFailed = AtomicLong()
    @Volatile private var scheduled: ScheduledFuture<*>? = null
    @Volatile private var startedElapsedRealtime = 0L

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startProbes(intent)
            ACTION_STOP -> stopProbes()
            ACTION_RESET -> resetCounters()
            ACTION_STRESS -> startStress(intent)
            else -> stopSelf(startId)
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        active.set(false)
        scheduled?.cancel(true)
        executor.shutdownNow()
        stressExecutor.shutdownNow()
        persistStatus(running = false)
        super.onDestroy()
    }

    private fun startProbes(intent: Intent) {
        startForeground(NOTIFICATION_ID, notification("HTTP + UDP probes running"))
        if (!active.compareAndSet(false, true)) {
            return
        }
        val configuration = try {
            ProbeConfiguration.fromIntent(this, intent).also { it.store(this) }
        } catch (error: Throwable) {
            Log.e(LOG_TAG, "XRAY_ANDROID_PROBE state=config-failed kind=${error.javaClass.simpleName}")
            stopProbes()
            return
        }
        val previous = ProbeStatus.read(this)
        httpPassed.set(previous.httpPassed)
        httpFailed.set(previous.httpFailed)
        udpPassed.set(previous.udpPassed)
        udpFailed.set(previous.udpFailed)
        startedElapsedRealtime = SystemClock.elapsedRealtime()
        persistStatus(running = true)
        Log.i(LOG_TAG, "XRAY_ANDROID_PROBE state=started")
        scheduled = executor.scheduleWithFixedDelay(
            { runProbeCycle(configuration) },
            0,
            configuration.intervalSeconds,
            TimeUnit.SECONDS,
        )
    }

    private fun stopProbes() {
        active.set(false)
        scheduled?.cancel(true)
        scheduled = null
        persistStatus(running = false)
        Log.i(LOG_TAG, "XRAY_ANDROID_PROBE state=stopped")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun resetCounters() {
        if (active.get()) {
            Log.w(LOG_TAG, "XRAY_ANDROID_PROBE state=reset-rejected-running")
            return
        }
        httpPassed.set(0)
        httpFailed.set(0)
        udpPassed.set(0)
        udpFailed.set(0)
        ProbeStatus.reset(this)
        Log.i(LOG_TAG, "XRAY_ANDROID_PROBE state=counters-reset")
        stopSelf()
    }

    private fun startStress(intent: Intent) {
        if (!active.get()) {
            Log.w(LOG_TAG, "XRAY_ANDROID_STRESS state=rejected reason=probes-not-running")
            stopSelf()
            return
        }
        if (!stressActive.compareAndSet(false, true)) {
            Log.w(LOG_TAG, "XRAY_ANDROID_STRESS state=rejected reason=already-running")
            return
        }
        val stress = try {
            StressConfiguration.fromIntent(intent)
        } catch (error: Throwable) {
            stressActive.set(false)
            Log.e(
                LOG_TAG,
                "XRAY_ANDROID_STRESS state=config-failed kind=${error.javaClass.simpleName}",
            )
            return
        }
        val endpoints = ProbeConfiguration.read(this)
        stressExecutor.execute {
            try {
                runStressCycle(endpoints, stress)
            } finally {
                stressActive.set(false)
            }
        }
    }

    private fun runStressCycle(
        endpoints: ProbeConfiguration,
        stress: StressConfiguration,
    ) {
        Log.i(
            LOG_TAG,
            "XRAY_ANDROID_STRESS state=started cycle=${stress.cycle} " +
                "httpAttempts=${stress.httpAttempts} udpAttempts=${stress.udpAttempts} " +
                "concurrency=${stress.concurrency}",
        )
        val started = SystemClock.elapsedRealtime()
        val httpPassed = AtomicLong()
        val httpFailed = AtomicLong()
        val udpPassed = AtomicLong()
        val udpFailed = AtomicLong()
        val workers = Executors.newFixedThreadPool(stress.concurrency) { runnable ->
            Thread(runnable, "xray-android-device-stress-worker").apply { isDaemon = true }
        }
        var cancelled = false
        try {
            repeat(stress.httpAttempts) {
                workers.execute {
                    if (executeHttpProbe(endpoints.httpUrl).isSuccess) {
                        httpPassed.incrementAndGet()
                    } else {
                        httpFailed.incrementAndGet()
                    }
                }
            }
            repeat(stress.udpAttempts) {
                workers.execute {
                    if (executeUdpProbe(endpoints.udpHost, endpoints.udpPort).isSuccess) {
                        udpPassed.incrementAndGet()
                    } else {
                        udpFailed.incrementAndGet()
                    }
                }
            }
            workers.shutdown()
            while (!workers.awaitTermination(1, TimeUnit.SECONDS)) {
                if (!active.get() || Thread.currentThread().isInterrupted) {
                    cancelled = true
                    break
                }
            }
        } catch (_: InterruptedException) {
            cancelled = true
            Thread.currentThread().interrupt()
        } finally {
            workers.shutdownNow()
        }
        Log.i(
            LOG_TAG,
            "XRAY_ANDROID_STRESS state=${if (cancelled) "cancelled" else "completed"} " +
                "cycle=${stress.cycle} " +
                "httpPassed=${httpPassed.get()} httpFailed=${httpFailed.get()} " +
                "udpPassed=${udpPassed.get()} udpFailed=${udpFailed.get()} " +
                "durationMillis=${SystemClock.elapsedRealtime() - started}",
        )
    }

    private fun runProbeCycle(configuration: ProbeConfiguration) {
        if (!active.get()) {
            return
        }
        runHttpProbe(configuration.httpUrl)
        if (active.get()) {
            runUdpProbe(configuration.udpHost, configuration.udpPort)
        }
        persistStatus(running = active.get())
    }

    private fun runHttpProbe(url: String) {
        val result = executeHttpProbe(url)
        if (result.isSuccess) {
            val sequence = httpPassed.incrementAndGet()
            logResult("http", "passed", sequence, null)
        } else {
            httpFailed.incrementAndGet()
            logResult("http", "failed", null, safeFailure(result.exceptionOrNull()))
        }
    }

    private fun executeHttpProbe(url: String): Result<Unit> = runCatching {
        val connection = URL(url).openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = PROBE_TIMEOUT_MILLISECONDS
            connection.readTimeout = PROBE_TIMEOUT_MILLISECONDS
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.setRequestProperty("Connection", "close")
            val responseCode = connection.responseCode
            check(responseCode in 200..399) { "http-$responseCode" }
        } finally {
            connection.disconnect()
        }
    }

    private fun runUdpProbe(host: String, port: Int) {
        val result = executeUdpProbe(host, port)
        if (result.isSuccess) {
            val sequence = udpPassed.incrementAndGet()
            logResult("udp", "passed", sequence, null)
        } else {
            udpFailed.incrementAndGet()
            logResult("udp", "failed", null, safeFailure(result.exceptionOrNull()))
        }
    }

    private fun executeUdpProbe(host: String, port: Int): Result<Unit> = runCatching {
        val query = UdpDnsOracle.makeQuery()
        DatagramSocket().use { socket ->
            socket.soTimeout = PROBE_TIMEOUT_MILLISECONDS
            socket.send(
                DatagramPacket(query, query.size, InetAddress.getByName(host), port),
            )
            val response = ByteArray(MAX_UDP_RESPONSE_BYTES)
            val packet = DatagramPacket(response, response.size)
            socket.receive(packet)
            check(UdpDnsOracle.isValidResponse(response.copyOf(packet.length), query)) {
                "udp-response-mismatch"
            }
        }
    }

    private fun logResult(kind: String, result: String, sequence: Long?, errorCode: String?) {
        val sequenceField = sequence?.let { " sequence=$it" } ?: ""
        val errorField = errorCode?.let { " errorCode=$it" } ?: ""
        val elapsed = TimeUnit.MILLISECONDS.toSeconds(
            SystemClock.elapsedRealtime() - startedElapsedRealtime,
        )
        Log.i(
            LOG_TAG,
            "XRAY_ANDROID_PROBE kind=$kind result=$result" +
                "$sequenceField$errorField elapsedSeconds=$elapsed",
        )
    }

    private fun safeFailure(error: Throwable?): String = when (val message = error?.message) {
        null -> error?.javaClass?.simpleName ?: "unknown"
        else -> message.takeIf { it.matches(Regex("(?:http-[1-5][0-9]{2}|udp-response-mismatch)")) }
            ?: error.javaClass.simpleName
    }

    private fun persistStatus(running: Boolean) {
        ProbeStatus.write(
            this,
            ProbeStatus(
                running = running,
                httpPassed = httpPassed.get(),
                httpFailed = httpFailed.get(),
                udpPassed = udpPassed.get(),
                udpFailed = udpFailed.get(),
            ),
        )
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(
                    NOTIFICATION_CHANNEL,
                    "Xray device traffic probes",
                    NotificationManager.IMPORTANCE_LOW,
                ),
            )
        }
    }

    private fun notification(text: String): Notification {
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, ProbeActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, NOTIFICATION_CHANNEL)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("Xray Device Probe")
            .setContentText(text)
            .setContentIntent(contentIntent)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_START = "org.xrayrust.deviceprobe.START"
        const val ACTION_STOP = "org.xrayrust.deviceprobe.STOP"
        const val ACTION_RESET = "org.xrayrust.deviceprobe.RESET"
        const val ACTION_STRESS = "org.xrayrust.deviceprobe.STRESS"
        const val LOG_TAG = "XrayDeviceProbe"
        private const val NOTIFICATION_CHANNEL = "xray-device-probe"
        private const val NOTIFICATION_ID = 5042
        private const val PROBE_TIMEOUT_MILLISECONDS = 5_000
        private const val MAX_UDP_RESPONSE_BYTES = 4096
    }
}
