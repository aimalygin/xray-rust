package org.xrayrust.deviceprobe

import android.content.Context
import android.content.Intent

internal data class ProbeConfiguration(
    val httpUrl: String,
    val udpHost: String,
    val udpPort: Int,
    val intervalSeconds: Long,
) {
    init {
        require(httpUrl.startsWith("https://") || httpUrl.startsWith("http://")) {
            "HTTP probe URL must use http or https"
        }
        require(udpHost.isNotBlank()) { "UDP probe host must not be blank" }
        require(udpPort in 1..65535) { "UDP probe port is outside 1..65535" }
        require(intervalSeconds in 1..60) { "probe interval is outside 1..60 seconds" }
    }

    fun store(context: Context) {
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .putString(HTTP_URL, httpUrl)
            .putString(UDP_HOST, udpHost)
            .putInt(UDP_PORT, udpPort)
            .putLong(INTERVAL_SECONDS, intervalSeconds)
            .apply()
    }

    companion object {
        const val EXTRA_HTTP_URL = "http-url"
        const val EXTRA_UDP_HOST = "udp-host"
        const val EXTRA_UDP_PORT = "udp-port"
        const val EXTRA_INTERVAL_SECONDS = "interval-seconds"

        const val DEFAULT_HTTP_URL = "https://www.google.com/generate_204"
        const val DEFAULT_UDP_HOST = "127-0-0-1.sslip.io"
        const val DEFAULT_UDP_PORT = 53054
        const val DEFAULT_INTERVAL_SECONDS = 5L

        private const val PREFERENCES = "device-probe-configuration"
        private const val HTTP_URL = "http-url"
        private const val UDP_HOST = "udp-host"
        private const val UDP_PORT = "udp-port"
        private const val INTERVAL_SECONDS = "interval-seconds"

        fun read(context: Context): ProbeConfiguration {
            val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            return ProbeConfiguration(
                httpUrl = preferences.getString(HTTP_URL, DEFAULT_HTTP_URL) ?: DEFAULT_HTTP_URL,
                udpHost = preferences.getString(UDP_HOST, DEFAULT_UDP_HOST) ?: DEFAULT_UDP_HOST,
                udpPort = preferences.getInt(UDP_PORT, DEFAULT_UDP_PORT),
                intervalSeconds = preferences.getLong(
                    INTERVAL_SECONDS,
                    DEFAULT_INTERVAL_SECONDS,
                ),
            )
        }

        fun fromIntent(context: Context, intent: Intent): ProbeConfiguration {
            val stored = read(context)
            return ProbeConfiguration(
                httpUrl = intent.getStringExtra(EXTRA_HTTP_URL) ?: stored.httpUrl,
                udpHost = intent.getStringExtra(EXTRA_UDP_HOST) ?: stored.udpHost,
                udpPort = intent.getIntExtra(EXTRA_UDP_PORT, stored.udpPort),
                intervalSeconds = intent.getLongExtra(
                    EXTRA_INTERVAL_SECONDS,
                    stored.intervalSeconds,
                ),
            )
        }
    }
}
