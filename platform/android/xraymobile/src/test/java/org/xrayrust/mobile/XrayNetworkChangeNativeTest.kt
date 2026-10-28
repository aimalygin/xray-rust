package org.xrayrust.mobile

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.Closeable
import java.util.concurrent.Executor

/** Real JNI and core; synthetic network events do not establish Android path migration. */
class XrayNetworkChangeNativeTest {
    private fun core(): XrayCore {
        assumeTrue(java.lang.Boolean.getBoolean("xray.test.nativeImport"))
        // Documentation-only keys and loopback endpoints. No peers need to be running.
        val imported = XrayProfileImporter.profile("""
            [Interface]
            PrivateKey = QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=
            Address = 10.44.0.2/32
            DNS = 192.0.2.53
            [Peer]
            PublicKey = U1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1M=
            Endpoint = 127.0.0.1:51820
            AllowedIPs = 0.0.0.0/0
        """.trimIndent(), XrayProfileFormat.Wireguard)
        val wireGuard = JSONObject(imported.configJson).getJSONArray("outbounds")
        val outbound = (0 until wireGuard.length()).map { wireGuard.getJSONObject(it) }
            .single { it.getString("protocol") == "wireguard" }.put("tag", "wg")
        val hysteria = JSONObject("""{"tag":"hy","protocol":"hysteria","settings":{
            "version":2,"address":"127.0.0.1","port":443},"streamSettings":{
            "network":"hysteria","security":"tls","tlsSettings":{"serverName":"localhost"},
            "hysteriaSettings":{"version":2,"auth":"synthetic-test-password"},
            "finalmask":{"quicParams":{"disableChromeParrot":true}}}}""")
        val config = JSONObject().put("inbounds", JSONArray().put(JSONObject()
            .put("protocol", "socks").put("listen", "127.0.0.1").put("port", 0)))
            .put("outbounds", JSONArray().put(hysteria).put(outbound))
        return XrayCore.create(config.toString())
    }

    private class Session(core: XrayCore) : Closeable {
        val tasks = ArrayDeque<Runnable>()
        lateinit var events: XrayNetworkEvents<String, Boolean, Int>
        val results = mutableListOf<XrayNetworkRebindResult>()
        var unregistered = false
        private val state = XrayNetworkChangeState<String, Boolean, Int>(
            executor = Executor { tasks.addLast(it) },
            register = { events = it; Closeable { unregistered = true } },
            usable = { it },
            selectAndApply = { candidates, _ -> candidates.lastOrNull()?.network },
            onResult = { results += it },
            onError = { throw AssertionError("unexpected coordinator error", it) },
        )
        init {
            state.start(object : XrayNetworkRebindTarget {
                override fun rebindHysteria() = core.rebindHysteria()
                override fun rebindWireGuard() = core.rebindWireGuard()
            })
        }
        fun available(network: String) {
            events.available(network); events.capabilities(network, true); events.properties(network, 1)
        }
        fun drain() { while (tasks.isNotEmpty()) tasks.removeFirst().run() }
        override fun close() = state.close()
    }

    @Test fun configuredIdleProtocolsAcceptZeroThroughActualJni() {
        core().use { core ->
            core.start()
            Session(core).use { session ->
                session.available("wifi"); session.drain(); assertTrue(session.results.isEmpty())
                repeat(8) { index -> session.available("carrier-$index"); session.drain() }
                assertEquals(8, session.results.size)
                session.results.forEach {
                    assertEquals(XrayRebindRequestResult.Accepted(0), it.hysteria)
                    assertEquals(XrayRebindRequestResult.Accepted(0), it.wireGuard)
                }
            }
            core.stop()
        }
    }

    @Test fun closingObserverFencesQueuedJniCallsBeforeCoreClose() {
        val core = core()
        core.use {
            core.start()
            Session(core).use { session ->
                session.available("wifi"); session.drain()
                session.available("cellular")
                session.close(); assertTrue(session.unregistered)
                core.stop(); core.close()
                session.drain()
                session.available("stale"); session.drain()
                assertTrue(session.results.isEmpty())
            }
        }
    }

    @Test fun accidentalCoreCloseReportsBothExistingJniGuards() {
        val core = core()
        core.use {
            core.start()
            Session(core).use { session ->
                session.available("wifi"); session.drain()
                core.close()
                session.available("cellular"); session.drain()
                val result = session.results.single()
                assertTrue((result.hysteria as XrayRebindRequestResult.Failed).error is IllegalStateException)
                assertTrue((result.wireGuard as XrayRebindRequestResult.Failed).error is IllegalStateException)
            }
        }
    }
}
