package org.xrayrust.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.TimeUnit
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference

/**
 * Optional host JNI integration for the ABI 1.9 outbound probe; run with the current native
 * libraries (see scripts/test-profile-import-jni.sh), not Android stubs.
 */
class XrayOutboundProbeNativeTest {
    private fun enabled() {
        assumeTrue(java.lang.Boolean.getBoolean("xray.test.nativeImport"))
    }

    @Test
    fun probesThroughActualJniAndRust() {
        enabled()
        assertTrue(XrayCore.ffiInfo().supports(XrayFfiCapability.OutboundProbe))
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val serverError = AtomicReference<Throwable?>()
            val worker = Thread {
                try {
                    server.accept().use { socket ->
                        val reader = socket.getInputStream().bufferedReader(Charsets.US_ASCII)
                        check(reader.readLine() == "GET /health HTTP/1.1") { "unexpected request" }
                        while (reader.readLine()?.isNotEmpty() == true) {
                            // Drain the remaining request headers.
                        }
                        socket.getOutputStream().write(
                            "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n"
                                .toByteArray(Charsets.US_ASCII),
                        )
                    }
                } catch (error: Throwable) {
                    serverError.set(error)
                }
            }
            worker.start()

            XrayCore.create(SOCKS_FREEDOM_CONFIG).use { core ->
                core.start()
                val url = "http://127.0.0.1:${server.localPort}/health"
                val result = core.probeOutboundUrl(url, timeoutMs = 5_000, outboundTag = "direct")
                assertEquals(XrayOutboundHealthFailureKind.HttpStatus, result.failureKind)
                assertEquals(503, result.httpStatus)
                assertNull(result.delayMs)

                val unknownTag = assertThrows(XrayCoreException::class.java) {
                    core.probeOutboundUrl(url, timeoutMs = 1_000, outboundTag = "missing")
                }
                assertEquals(XRAY_STATUS_INVALID_ARGUMENT, unknownTag.code)
                for (invalid in listOf<() -> Unit>(
                    { core.probeOutboundUrl("", timeoutMs = 1_000) },
                    { core.probeOutboundUrl(url, timeoutMs = 0) },
                    { core.probeOutboundUrl(url, timeoutMs = 60_001) },
                    { core.probeOutboundUrl("$url\u0000", timeoutMs = 1_000) },
                )) {
                    assertThrows(IllegalArgumentException::class.java) { invalid() }
                }
                core.stop()

                val stopped = assertThrows(XrayCoreException::class.java) {
                    core.probeOutboundUrl(url, timeoutMs = 1_000)
                }
                assertEquals(XRAY_STATUS_RUNTIME_ERROR, stopped.code)
            }
            worker.join(TimeUnit.SECONDS.toMillis(5))
            serverError.get()?.let { throw it }
        }
    }

    @Test
    fun stopAndCloseCancelStalledSixtySecondProbes() {
        enabled()
        for (close in listOf(false, true)) {
            ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
                server.soTimeout = 5_000
                val accepted = CountDownLatch(1)
                val releaseServer = CountDownLatch(1)
                val serverError = AtomicReference<Throwable?>()
                val serverWorker = Thread {
                    try {
                        server.accept().use {
                            accepted.countDown()
                            releaseServer.await(10, TimeUnit.SECONDS)
                        }
                    } catch (error: Throwable) {
                        serverError.set(error)
                    }
                }
                val core = XrayCore.create(SOCKS_FREEDOM_CONFIG)
                core.start()
                serverWorker.start()
                val probeError = AtomicReference<Throwable?>()
                val finished = CountDownLatch(1)
                val probeWorker = Thread {
                    try {
                        core.probeOutboundUrl("http://127.0.0.1:${server.localPort}/", 60_000)
                    } catch (error: Throwable) {
                        probeError.set(error)
                    } finally {
                        finished.countDown()
                    }
                }
                probeWorker.start()
                try {
                    assertTrue("probe must connect", accepted.await(5, TimeUnit.SECONDS))
                    val started = System.nanoTime()
                    if (close) core.close() else core.stop()
                    assertTrue("teardown must cancel without waiting for timeout",
                        System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2))
                    assertTrue(finished.await(2, TimeUnit.SECONDS))
                    val error = probeError.get()
                    assertTrue("expected cancellation, got $error", error is XrayCoreException)
                    assertEquals(XRAY_STATUS_RUNTIME_ERROR, (error as XrayCoreException).code)
                } finally {
                    releaseServer.countDown()
                    serverWorker.join(5_000)
                    probeWorker.join(5_000)
                    core.close()
                }
                serverError.get()?.let { throw it }
            }
        }
    }

    private companion object {
        const val XRAY_STATUS_RUNTIME_ERROR = 5
        const val XRAY_STATUS_INVALID_ARGUMENT = 9
        const val SOCKS_FREEDOM_CONFIG = """{
            "inbounds": [{
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": 0,
                "settings": {"udp": false}
            }],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        }"""
    }
}
