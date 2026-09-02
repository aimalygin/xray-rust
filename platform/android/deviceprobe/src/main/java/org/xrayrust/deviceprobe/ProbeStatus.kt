package org.xrayrust.deviceprobe

import android.content.Context

internal data class ProbeStatus(
    val running: Boolean,
    val httpPassed: Long,
    val httpFailed: Long,
    val udpPassed: Long,
    val udpFailed: Long,
) {
    companion object {
        private const val PREFERENCES = "device-probe-status"
        private const val RUNNING = "running"
        private const val HTTP_PASSED = "http-passed"
        private const val HTTP_FAILED = "http-failed"
        private const val UDP_PASSED = "udp-passed"
        private const val UDP_FAILED = "udp-failed"

        fun read(context: Context): ProbeStatus {
            val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            return ProbeStatus(
                running = preferences.getBoolean(RUNNING, false),
                httpPassed = preferences.getLong(HTTP_PASSED, 0),
                httpFailed = preferences.getLong(HTTP_FAILED, 0),
                udpPassed = preferences.getLong(UDP_PASSED, 0),
                udpFailed = preferences.getLong(UDP_FAILED, 0),
            )
        }

        fun write(context: Context, status: ProbeStatus) {
            context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(RUNNING, status.running)
                .putLong(HTTP_PASSED, status.httpPassed)
                .putLong(HTTP_FAILED, status.httpFailed)
                .putLong(UDP_PASSED, status.udpPassed)
                .putLong(UDP_FAILED, status.udpFailed)
                .apply()
        }

        fun reset(context: Context) {
            write(context, ProbeStatus(false, 0, 0, 0, 0))
        }
    }
}
