package org.xrayrust.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.Closeable
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Optional host JNI integration for the ABI 1.12 startup-probe preflight; run with the current
 * native libraries (see scripts/test-profile-import-jni.sh), not Android stubs. Each start runs
 * the [XrayVpnService] coordinator with a real core; `establish` stands in for the VPN interface.
 */
class XrayStartupProbePreflightNativeTest {
    private fun enabled() {
        assumeTrue(java.lang.Boolean.getBoolean("xray.test.nativeImport"))
    }

    @Test
    fun networkSetupWaitsForTheProbeAndTheDataPathDoesNotRepeatIt() {
        enabled()
        val info = XrayCore.ffiInfo()
        assertTrue(info.version.minor >= 12)
        assertTrue(info.supports(XrayFfiCapability.StartupProbePreflight))
        ProbeServer().use { server ->
            val start = PreflightStart(server.probe(timeoutMs = 2_000))
            start.begin()
            assertTrue(server.requestReceived.await(5, TimeUnit.SECONDS))
            assertFalse("routes must wait for the probe response", start.established.get())

            server.respond(204)
            start.awaitFinished()
            assertNull(start.error.get())
            assertTrue(start.established.get())

            // As in XrayVpnService, the data-path core has no probe. A repeated probe would be a
            // second request, which the server would also answer.
            createCore(startupProbe = null).use { dataPath ->
                dataPath.start()
                dataPath.stop()
            }
            assertEquals(1, server.requests.get())
        }
    }

    @Test
    fun failedProbeNeverEstablishes() {
        enabled()
        ProbeServer().use { server ->
            val start = PreflightStart(server.probe(timeoutMs = 2_000))
            server.respond(503)
            start.begin()
            start.awaitFinished()

            val error = start.error.get()
            assertTrue("expected native probe failure, got $error", error is XrayCoreException)
            assertEquals(XRAY_STATUS_RUNTIME_ERROR, (error as XrayCoreException).code)
            assertTrue(error.message.orEmpty().contains("HTTP status 503"))
            assertFalse(start.established.get())
            assertTrue(start.lifecycle.isStartFailureReportable(start.token))
        }
    }

    @Test
    fun timedOutProbeNeverEstablishes() {
        enabled()
        ProbeServer().use { server ->
            val start = PreflightStart(server.probe(timeoutMs = 200))
            val started = System.nanoTime()
            start.begin()
            start.awaitFinished()

            val error = start.error.get()
            assertTrue("expected native probe timeout, got $error", error is XrayCoreException)
            assertTrue(error?.message.orEmpty().contains("timed out"))
            assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(3))
            assertFalse(start.established.get())
        }
    }

    @Test
    fun stopDuringASixtySecondProbeCancelsItWithoutEstablishing() {
        enabled()
        ProbeServer().use { server ->
            val start = PreflightStart(server.probe(timeoutMs = 60_000))
            start.begin()
            assertTrue(server.requestReceived.await(5, TimeUnit.SECONDS))

            // The XrayVpnService stop path for a pending start.
            val stopped = System.nanoTime()
            assertEquals(XrayTunnelStopAction.CancelStart, start.lifecycle.requestStop())
            start.preflight.cancel()
            assertTrue(System.nanoTime() - stopped < TimeUnit.SECONDS.toNanos(1))
            start.awaitFinished(timeoutSeconds = 2)

            val error = start.error.get()
            assertTrue("expected native cancellation, got $error", error is XrayCoreException)
            assertTrue(error?.message.orEmpty().contains("cancelled"))
            assertFalse(start.established.get())
            assertFalse(start.lifecycle.isStartFailureReportable(start.token))
        }
    }

    @Test
    fun stopAndCloseCancelAStalledPreflight() {
        enabled()
        for (close in listOf(false, true)) {
            ProbeServer().use { server ->
                val core = createCore(server.probe(timeoutMs = 60_000))
                val probeError = AtomicReference<Throwable?>()
                val finished = CountDownLatch(1)
                val worker = Thread {
                    try {
                        core.preflightStartupProbe()
                    } catch (error: Throwable) {
                        probeError.set(error)
                    } finally {
                        finished.countDown()
                    }
                }
                worker.start()
                try {
                    assertTrue(server.requestReceived.await(5, TimeUnit.SECONDS))
                    val started = System.nanoTime()
                    if (close) core.close() else core.stop()
                    assertTrue("teardown must cancel without waiting for timeout",
                        System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2))
                    assertTrue(finished.await(2, TimeUnit.SECONDS))
                    val error = probeError.get()
                    assertTrue("expected cancellation, got $error", error is XrayCoreException)
                    assertEquals(XRAY_STATUS_RUNTIME_ERROR, (error as XrayCoreException).code)
                } finally {
                    worker.join(5_000)
                    core.close()
                }
            }
        }
    }

    @Test
    fun preflightWithoutAProbeReturnsWithoutNetworkActivity() {
        enabled()
        ProbeServer().use { server ->
            createCore(startupProbe = null).use { core ->
                core.preflightStartupProbe()
            }
            assertFalse(server.requestReceived.await(200, TimeUnit.MILLISECONDS))
        }
    }

    /** One start attempt through the coordinator, run on its own worker like XrayVpnService. */
    private class PreflightStart(private val startupProbe: XrayStartupProbeOptions) {
        val lifecycle = XrayTunnelStateMachine<String>()
        val token = lifecycle.beginStart()!!
        val preflight = XrayStartupProbePreflight<XrayCore>(
            lifecycle = lifecycle,
            preflight = XrayCore::preflightStartupProbe,
            cancelPreflight = XrayCore::cancelStartupProbePreflight,
        )
        val established = AtomicBoolean(false)
        val error = AtomicReference<Throwable?>()
        private val worker = Thread {
            try {
                preflight.run(token, startupProbe) { createCore(it) }
                established.set(true)
            } catch (failure: Throwable) {
                error.set(failure)
            }
        }

        fun begin() = worker.start()

        fun awaitFinished(timeoutSeconds: Long = 5) {
            worker.join(TimeUnit.SECONDS.toMillis(timeoutSeconds))
            assertFalse("preflight worker did not finish", worker.isAlive)
        }
    }

    /** Loopback HTTP server that holds every probe request until [respond] is called. */
    private class ProbeServer : Closeable {
        val requestReceived = CountDownLatch(1)
        val requests = AtomicInteger()
        private val server = ServerSocket(0, 8, InetAddress.getLoopbackAddress())
        private val sockets: MutableList<Socket> = Collections.synchronizedList(mutableListOf())
        private val status = AtomicInteger()
        private val released = CountDownLatch(1)

        init {
            Thread {
                while (true) {
                    val socket = try {
                        server.accept()
                    } catch (_: IOException) {
                        return@Thread
                    }
                    sockets += socket
                    Thread { serve(socket) }.apply { isDaemon = true }.start()
                }
            }.apply { isDaemon = true }.start()
        }

        fun probe(timeoutMs: Long) = XrayStartupProbeOptions(
            url = "http://127.0.0.1:${server.localPort}/health",
            timeoutMs = timeoutMs,
        )

        fun respond(code: Int) {
            status.set(code)
            released.countDown()
        }

        private fun serve(socket: Socket) {
            try {
                val reader = socket.getInputStream().bufferedReader(Charsets.US_ASCII)
                check(reader.readLine() == "GET /health HTTP/1.1") { "unexpected request" }
                while (reader.readLine()?.isNotEmpty() == true) {
                    // Drain the remaining request headers.
                }
                requests.incrementAndGet()
                requestReceived.countDown()
                released.await()
                socket.getOutputStream().write(
                    "HTTP/1.1 ${status.get()} Test\r\nContent-Length: 0\r\n\r\n"
                        .toByteArray(Charsets.US_ASCII),
                )
            } catch (_: IOException) {
                // close() ended a stalled request.
            }
        }

        override fun close() {
            server.close()
            synchronized(sockets) { sockets.forEach { runCatching { it.close() } } }
            // Wake stalled handlers only after their sockets are closed.
            released.countDown()
        }
    }

    private companion object {
        const val XRAY_STATUS_RUNTIME_ERROR = 5
        const val TUN_FREEDOM_CONFIG =
            """{"inbounds":[{"protocol":"tun","tag":"tun-in"}],"outbounds":[{"protocol":"freedom","tag":"direct"}]}"""

        /** Matches the preflight and data-path cores of XrayVpnService, without a VpnService. */
        fun createCore(startupProbe: XrayStartupProbeOptions?): XrayCore = XrayCore.create(
            configJson = TUN_FREEDOM_CONFIG,
            startupProbe = startupProbe,
            dnsBootstrapMode = XrayDnsBootstrapMode.StaticOnly,
        )
    }
}
