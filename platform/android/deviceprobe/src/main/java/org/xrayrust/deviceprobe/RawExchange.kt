package org.xrayrust.deviceprobe

import android.content.Context
import android.content.Intent
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * One TCP exchange of given first bytes with an address, for the v0.11 TUN
 * sniffing scenario: the bytes name a host (HTTP Host or a ClientHello's
 * server name), and the fixture echoes them or the tunnel refuses the flow.
 */
internal data class ExchangeRequest(
    val id: Long,
    val host: String,
    val port: Int,
    val payload: ByteArray,
    val timeoutMillis: Int,
) {
    companion object {
        const val EXTRA_ID = "exchange-id"
        const val EXTRA_HOST = "exchange-host"
        const val EXTRA_PORT = "exchange-port"
        /** Hex, since java.util.Base64 needs API 26 and this app runs on 24. */
        const val EXTRA_PAYLOAD = "exchange-payload-hex"
        const val EXTRA_TIMEOUT_MILLIS = "exchange-timeout-millis"
        private const val MAX_PAYLOAD_BYTES = 8192
        private val IPV4 = Regex("""(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}""")
        private val IPV6 = Regex("""[0-9A-Fa-f:]{2,39}""")

        fun fromIntent(intent: Intent): ExchangeRequest =
            parse(
                id = intent.getLongExtra(EXTRA_ID, 0),
                host = intent.getStringExtra(EXTRA_HOST),
                port = intent.getIntExtra(EXTRA_PORT, 0),
                payload = intent.getStringExtra(EXTRA_PAYLOAD),
                timeoutMillis = intent.getIntExtra(EXTRA_TIMEOUT_MILLIS, 0),
            )

        /** Only an address literal: the probe never resolves a name here. */
        fun parse(id: Long, host: String?, port: Int, payload: String?, timeoutMillis: Int): ExchangeRequest {
            require(id > 0) { "exchange id" }
            require(host != null && (IPV4.matches(host) || (host.contains(':') && IPV6.matches(host)))) {
                "exchange host"
            }
            require(port in 1..65535) { "exchange port" }
            require(timeoutMillis in 1_000..30_000) { "exchange timeout" }
            val hex = requireNotNull(payload) { "exchange payload" }
            require(hex.length % 2 == 0 && hex.length / 2 in 1..MAX_PAYLOAD_BYTES) { "exchange payload size" }
            val bytes = ByteArray(hex.length / 2) { index ->
                val high = Character.digit(hex[index * 2], 16)
                val low = Character.digit(hex[index * 2 + 1], 16)
                require(high >= 0 && low >= 0) { "exchange payload hex" }
                ((high shl 4) or low).toByte()
            }
            return ExchangeRequest(id, host, port, bytes, timeoutMillis)
        }
    }
}

internal object RawExchange {
    const val ECHO = "echo"
    const val REFUSED = "refused"
    const val PARTIAL = "partial"
    const val MISMATCH = "mismatch"

    /**
     * Sends the payload and reads as many bytes back. All of them is an echo,
     * none before the peer closes, resets or times out is a refusal, and some
     * is neither.
     */
    fun run(request: ExchangeRequest): Pair<String, String?> {
        val received = java.io.ByteArrayOutputStream()
        var failure: String? = null
        try {
            Socket().use { socket ->
                socket.soTimeout = request.timeoutMillis
                socket.connect(
                    InetSocketAddress(InetAddress.getByName(request.host), request.port),
                    request.timeoutMillis,
                )
                socket.getOutputStream().apply {
                    write(request.payload)
                    flush()
                }
                val input = socket.getInputStream()
                val buffer = ByteArray(4096)
                while (received.size() < request.payload.size) {
                    val count = input.read(buffer, 0, minOf(buffer.size, request.payload.size - received.size()))
                    if (count < 0) break
                    received.write(buffer, 0, count)
                }
            }
        } catch (error: SocketTimeoutException) {
            failure = error.javaClass.simpleName
        } catch (error: IOException) {
            failure = error.javaClass.simpleName
        }
        return classify(received.toByteArray(), request.payload) to failure
    }

    fun classify(received: ByteArray, expected: ByteArray): String = when {
        received.contentEquals(expected) -> ECHO
        received.isEmpty() -> REFUSED
        received.size < expected.size -> PARTIAL
        else -> MISMATCH
    }
}

/** The last exchange's result, read by the matrix driver over run-as. */
internal object ExchangeStatus {
    private const val PREFERENCES = "device-probe-exchange"

    fun write(context: Context, id: Long, result: String, failure: String?) {
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .putLong("id", id)
            .putString("result", result)
            .putString("failure", failure ?: "none")
            .apply()
    }
}
