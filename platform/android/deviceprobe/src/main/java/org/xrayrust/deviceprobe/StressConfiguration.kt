package org.xrayrust.deviceprobe

import android.content.Intent

internal data class StressConfiguration(
    val cycle: Int,
    val httpAttempts: Int,
    val udpAttempts: Int,
    val concurrency: Int,
) {
    init {
        require(cycle in 1..MAX_CYCLE) { "stress cycle is outside the supported range" }
        require(httpAttempts in 1..MAX_ATTEMPTS) {
            "HTTP stress attempts are outside the supported range"
        }
        require(udpAttempts in 1..MAX_ATTEMPTS) {
            "UDP stress attempts are outside the supported range"
        }
        require(concurrency in 1..MAX_CONCURRENCY) {
            "stress concurrency is outside the supported range"
        }
    }

    companion object {
        const val EXTRA_CYCLE = "stress-cycle"
        const val EXTRA_HTTP_ATTEMPTS = "stress-http-attempts"
        const val EXTRA_UDP_ATTEMPTS = "stress-udp-attempts"
        const val EXTRA_CONCURRENCY = "stress-concurrency"

        const val DEFAULT_HTTP_ATTEMPTS = 240
        const val DEFAULT_UDP_ATTEMPTS = 480
        const val DEFAULT_CONCURRENCY = 32

        private const val MAX_CYCLE = 1_000
        private const val MAX_ATTEMPTS = 2_000
        private const val MAX_CONCURRENCY = 64

        fun fromIntent(intent: Intent): StressConfiguration = StressConfiguration(
            cycle = intent.getIntExtra(EXTRA_CYCLE, 1),
            httpAttempts = intent.getIntExtra(
                EXTRA_HTTP_ATTEMPTS,
                DEFAULT_HTTP_ATTEMPTS,
            ),
            udpAttempts = intent.getIntExtra(
                EXTRA_UDP_ATTEMPTS,
                DEFAULT_UDP_ATTEMPTS,
            ),
            concurrency = intent.getIntExtra(EXTRA_CONCURRENCY, DEFAULT_CONCURRENCY),
        )
    }
}
