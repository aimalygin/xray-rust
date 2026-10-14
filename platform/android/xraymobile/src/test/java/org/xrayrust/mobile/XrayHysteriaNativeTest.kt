package org.xrayrust.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference

class XrayHysteriaNativeTest {
    /** Optional pinned-server proof; JSON contains only a synthetic local test profile. */
    @Test
    fun liveRebindRetainsTcpThroughActualJni() {
        assumeTrue(java.lang.Boolean.getBoolean("xray.test.nativeImport"))
        val fixture = System.getenv("XRAY_TEST_HYSTERIA_CONFIG")
        assumeTrue("requires pinned Hysteria fixture", fixture != null)
        val socksPort = ServerSocket(0).use { it.localPort }
        val config = JSONObject(File(fixture!!).readText())
        config.put("inbounds", JSONArray().put(JSONObject()
            .put("protocol", "socks").put("listen", "127.0.0.1").put("port", socksPort)))
        ServerSocket(0).use { server ->
            server.soTimeout = 5_000
            val failure = AtomicReference<Throwable?>()
            val echo = Thread {
                try {
                    server.accept().use { socket ->
                        socket.soTimeout = 5_000
                        val input = socket.getInputStream()
                        val output = socket.getOutputStream()
                        while (true) {
                            val value = input.read()
                            if (value < 0) break
                            output.write(value)
                        }
                    }
                } catch (error: Throwable) { failure.set(error) }
            }
            echo.start()
            XrayCore.create(config.toString(), hysteriaStreamLimits = XrayHysteriaStreamLimits(128, 64)).use { core ->
                core.start()
                assertEquals(0L, core.rebindHysteria())
                Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort))).use { socket ->
                    socket.soTimeout = 5_000
                    socket.connect(InetSocketAddress("127.0.0.1", server.localPort), 5_000)
                    for (value in 0..15) {
                        socket.getOutputStream().write(value)
                        assertEquals(value, socket.getInputStream().read())
                        assertEquals(1L, core.rebindHysteria())
                        assertEquals(0L, core.rebindWireGuard())
                    }
                }
                core.stop()
                assertEquals(0L, core.rebindHysteria())
            }
            echo.join(6_000)
            failure.get()?.let { throw it }
            assertTrue("echo worker must terminate", !echo.isAlive)
        }
    }

    @Test
    fun limitsRejectInvalidValues() {
        assertEquals(64, XrayHysteriaStreamLimits().maxTcpStreams)
        assertEquals(32, XrayHysteriaStreamLimits().maxUdpSessions)
        for ((tcp, udp) in listOf(0 to 32, 257 to 32, 64 to 0, 64 to 129, -1 to 32)) {
            assertThrows(IllegalArgumentException::class.java) { XrayHysteriaStreamLimits(tcp, udp) }
        }
    }

    @Test
    fun rebindAndLimitsUseActualJniWithoutOpeningIdleCarriers() {
        assumeTrue(java.lang.Boolean.getBoolean("xray.test.nativeImport"))
        assertTrue(XrayCore.ffiInfo().supports(XrayFfiCapability.HysteriaStreamLimits))
        val config = """{"inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":0}],
            "outbounds":[{"protocol":"hysteria","settings":{
            "version":2,"address":"127.0.0.1","port":443},"streamSettings":{
            "network":"hysteria","security":"tls","tlsSettings":{"serverName":"localhost"},
            "hysteriaSettings":{"version":2,"auth":"synthetic-test-password"}}}]}"""
        val core = XrayCore.create(config, hysteriaStreamLimits = XrayHysteriaStreamLimits(256, 128))
        core.use {
            assertEquals(0L, it.rebindHysteria())
            assertEquals(0L, it.rebindWireGuard())
            it.start()
            repeat(8) { _ ->
                assertEquals(0L, it.rebindHysteria())
                assertEquals(0L, it.rebindWireGuard())
            }
            it.stop()
            assertEquals(0L, it.rebindHysteria())
            assertEquals(0L, it.rebindWireGuard())
        }
        assertThrows(IllegalStateException::class.java) { core.rebindHysteria() }
        assertThrows(IllegalStateException::class.java) { core.rebindWireGuard() }
    }
}
