package org.xrayrust.mobile

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

class XrayTunAdmissionNativeTest {
    private val config = """{"inbounds":[{"protocol":"tun","tag":"tun-in"}],"outbounds":[{"protocol":"freedom","tag":"direct"}]}"""

    private fun nativeAvailable() = assumeTrue(java.lang.Boolean.getBoolean("xray.test.nativeImport"))

    @Test fun validatesTimeoutBeforeCallingNative() {
        for (timeout in listOf(0, 5001)) {
            assertThrows(IllegalArgumentException::class.java) {
                XrayTunAdmissionOptions(XrayTunFlowAdmission { true }, timeout)
            }
        }
    }

    @Test fun allowedUdpReportsOriginalTupleAndCallsOnce() {
        nativeAvailable()
        val calls = AtomicInteger()
        val seen = AtomicReference<XrayTunFlow>()
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout = 1000
            XrayCore.create(config, tunAdmission = XrayTunAdmissionOptions(XrayTunFlowAdmission {
                calls.incrementAndGet(); seen.set(it); true
            })).use { core ->
                core.start()
                repeat(3) {
                    core.pushPacket(packet(server.localPort))
                    val datagram = DatagramPacket(ByteArray(64), 64)
                    server.receive(datagram)
                    assertEquals("admission", String(datagram.data, 0, datagram.length))
                }
                assertEquals(1, calls.get())
                assertEquals(17, seen.get().protocol)
                assertEquals("10.10.0.2", seen.get().source.address.hostAddress)
                assertEquals(41000, seen.get().source.port)
                assertEquals(server.localPort, seen.get().destination.port)
            }
        }
    }

    @Test fun explicitDenialAndJavaExceptionCannotFailOpen() {
        nativeAvailable()
        for (throws in listOf(false, true)) {
            DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { server ->
                server.soTimeout = 200
                val entered = CountDownLatch(1)
                XrayCore.create(config, tunAdmission = XrayTunAdmissionOptions(XrayTunFlowAdmission {
                    entered.countDown()
                    if (throws) error("host callback failure") else false
                }, failOpen = true)).use { core ->
                    core.start()
                    core.pushPacket(packet(server.localPort))
                    assertTrue(entered.await(1, TimeUnit.SECONDS))
                    assertThrows(SocketTimeoutException::class.java) {
                        server.receive(DatagramPacket(ByteArray(64), 64))
                    }
                }
            }
        }
    }

    @Test fun closeDoesNotWaitForBlockedHostCallback() {
        nativeAvailable()
        val entered = CountDownLatch(1)
        val unblock = CountDownLatch(1)
        val retired = CountDownLatch(1)
        val core = XrayCore.create(config, tunAdmission = XrayTunAdmissionOptions(XrayTunFlowAdmission {
            entered.countDown()
            try { unblock.await(3, TimeUnit.SECONDS); true } finally { retired.countDown() }
        }, timeoutMs = 5))
        try {
            core.start()
            core.pushPacket(packet(9))
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            val start = System.nanoTime()
            core.close()
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1000)
        } finally {
            unblock.countDown()
            core.close()
        }
        assertTrue(retired.await(1, TimeUnit.SECONDS))
    }

    private fun packet(port: Int): ByteArray {
        val body = "admission".toByteArray()
        val packet = ByteArray(28 + body.size)
        fun put16(offset: Int, value: Int) { packet[offset] = (value ushr 8).toByte(); packet[offset + 1] = value.toByte() }
        packet[0] = 0x45
        put16(2, packet.size)
        packet[8] = 64; packet[9] = 17
        byteArrayOf(10, 10, 0, 2).copyInto(packet, 12)
        byteArrayOf(127, 0, 0, 1).copyInto(packet, 16)
        var sum = 0
        for (i in 0 until 20 step 2) sum += ((packet[i].toInt() and 255) shl 8) or (packet[i + 1].toInt() and 255)
        while (sum > 65535) sum = (sum and 65535) + (sum ushr 16)
        put16(10, sum.inv() and 65535)
        put16(20, 41000); put16(22, port); put16(24, 8 + body.size)
        body.copyInto(packet, 28)
        return packet
    }
}
