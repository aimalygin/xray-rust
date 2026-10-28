package org.xrayrust.mobile

import java.util.concurrent.TimeUnit
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class XrayHttpDnsBootstrapTest {
    @Test
    fun pinsBothFormsWithoutResolvingDestinationsOrChangingCredentialsAndTls() {
        for (legacy in listOf(false, true)) {
            val json = config(" Proxy.Example. ", legacy)
            val queries = mutableListOf<String>()
            val prepared = prepare(json) { domain ->
                queries.add(domain)
                listOf("2001:db8::9", "192.0.2.9")
            }
            assertEquals(listOf("proxy.example"), queries)
            val original = JSONObject(json)
            val root = JSONObject(prepared.json)
            for (key in listOf("outbounds", "routing")) {
                assertEquals(original.get(key).toString(), root.get(key).toString())
            }
            val addresses = root.getJSONObject("dns").getJSONObject("hosts")
                .getJSONArray("full:proxy.example")
            assertEquals(canonicalBootstrapAddresses(listOf("2001:db8::9", "192.0.2.9")),
                (0 until addresses.length()).map(addresses::getString))
        }
    }

    @Test
    fun literalsIncludingBracketedIpv6SkipSystemLookup() {
        for (legacy in listOf(false, true)) {
            for (address in listOf("192.0.2.9", " 192.0.2.9 ", "[192.0.2.9]",
                "2001:db8::9", "[2001:db8::9]", "::ffff:192.0.2.9")) {
                prepare(config(address, legacy))
            }
        }
    }

    @Test
    fun rejectsTunnelOwnedLiteralAndResolvedCarriers() {
        for (legacy in listOf(false, true)) {
            for (address in listOf("198.18.0.1", "fd00:7872::1", "[fd00:7872::1]", "::ffff:198.18.0.1")) {
                assertThrows(IllegalArgumentException::class.java) { prepare(config(address, legacy)) }
                assertThrows(IllegalArgumentException::class.java) {
                    prepare(config("proxy.example", legacy)) { listOf(address) }
                }
            }
        }
    }

    @Test
    fun lookupFailureFailsPreparation() {
        for (legacy in listOf(false, true)) {
            assertThrows(IllegalArgumentException::class.java) {
                prepare(config("proxy.example", legacy)) { emptyList() }
            }
        }
    }

    private fun config(address: String, legacy: Boolean): String {
        val settings = if (legacy) {
            """{"servers":[{"address":"$address","port":3128,"users":[{"user":"synthetic-user","pass":"synthetic-secret"}]}]}"""
        } else {
            """{"address":"$address","port":3128,"user":"synthetic-user","pass":"synthetic-secret"}"""
        }
        return """{"outbounds":[{"tag":"proxy","protocol":"http","settings":$settings,
            "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"tls.example"}}}],
            "routing":{"rules":[{"type":"field","domain":["full:destination.example"],"outboundTag":"proxy"}]}}"""
    }

    private fun prepare(
        json: String,
        lookup: (String) -> List<String> = { error("unexpected system DNS lookup: $it") },
    ): PreparedAndroidVpnConfig = BoundedAndroidDnsBootstrapResolver(
        maxConcurrentLookups = 2,
        lookup = lookup,
    ).use { resolver ->
        prepareAndroidVpnConfigWithinDeadline(
            configJson = json,
            resolver = resolver,
            deadline = AndroidDnsBootstrapDeadline(TimeUnit.SECONDS.toNanos(5)),
        )
    }
}
