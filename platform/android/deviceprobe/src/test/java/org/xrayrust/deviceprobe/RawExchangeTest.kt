package org.xrayrust.deviceprobe

import java.net.InetAddress
import java.net.ServerSocket
import kotlin.concurrent.thread
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class RawExchangeTest {
    private val payload = "GET / HTTP/1.1\r\nHost: routed.v07-probe-abc.test\r\n\r\n".toByteArray()
    private val hex = payload.joinToString("") { "%02x".format(it) }

    @Test
    fun parsesAddressLiteralsAndHexPayloads() {
        val request = ExchangeRequest.parse(7, "198.51.100.8", 41001, hex, 5_000)
        assertArrayEquals(payload, request.payload)
        ExchangeRequest.parse(7, "2001:db8::8", 41001, hex.uppercase(), 5_000)
        ExchangeRequest.parse(7, "203.0.113.7", 1, "00", 30_000)
    }

    @Test
    fun rejectsNamesAndUnboundedInput() {
        val invalid = listOf<() -> Unit>(
            { ExchangeRequest.parse(0, "198.51.100.8", 41001, hex, 5_000) },
            { ExchangeRequest.parse(7, "routed.v07-probe-abc.test", 41001, hex, 5_000) },
            { ExchangeRequest.parse(7, "256.1.1.1", 41001, hex, 5_000) },
            { ExchangeRequest.parse(7, null, 41001, hex, 5_000) },
            { ExchangeRequest.parse(7, "198.51.100.8", 0, hex, 5_000) },
            { ExchangeRequest.parse(7, "198.51.100.8", 41001, hex, 999) },
            { ExchangeRequest.parse(7, "198.51.100.8", 41001, hex, 30_001) },
            { ExchangeRequest.parse(7, "198.51.100.8", 41001, "", 5_000) },
            { ExchangeRequest.parse(7, "198.51.100.8", 41001, "abc", 5_000) },
            { ExchangeRequest.parse(7, "198.51.100.8", 41001, "zz", 5_000) },
            { ExchangeRequest.parse(7, "198.51.100.8", 41001, "00".repeat(8193), 5_000) },
        )
        invalid.forEach { assertThrows(IllegalArgumentException::class.java) { it() } }
    }

    @Test
    fun classifiesEchoRefusalPartialAndMismatch() {
        assertEquals(RawExchange.ECHO, RawExchange.classify(payload, payload))
        assertEquals(RawExchange.REFUSED, RawExchange.classify(ByteArray(0), payload))
        assertEquals(RawExchange.PARTIAL, RawExchange.classify(payload.copyOf(5), payload))
        assertEquals(RawExchange.MISMATCH, RawExchange.classify(payload.reversedArray(), payload))
    }

    @Test
    fun exchangesWithARealPeer() {
        assertEquals(RawExchange.ECHO, against { input, output ->
            output.write(input.readNBytesCompat(payload.size)); output.flush()
        }.first)
        assertEquals(RawExchange.REFUSED, against { input, _ -> input.readNBytesCompat(payload.size) }.first)
        assertEquals(RawExchange.PARTIAL, against { input, output ->
            output.write(input.readNBytesCompat(payload.size).copyOf(3)); output.flush()
        }.first)
    }

    private fun against(peer: (java.io.InputStream, java.io.OutputStream) -> Unit): Pair<String, String?> =
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val worker = thread {
                server.accept().use { socket -> peer(socket.getInputStream(), socket.getOutputStream()) }
            }
            val result = RawExchange.run(ExchangeRequest.parse(1, "127.0.0.1", server.localPort, hex, 2_000))
            worker.join()
            result
        }

    private fun java.io.InputStream.readNBytesCompat(count: Int): ByteArray {
        val buffer = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val read = read(buffer, offset, count - offset)
            if (read < 0) break
            offset += read
        }
        return buffer.copyOf(offset)
    }
}
