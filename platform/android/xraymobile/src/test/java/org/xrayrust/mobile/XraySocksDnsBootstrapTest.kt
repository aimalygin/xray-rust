package org.xrayrust.mobile

import java.util.concurrent.TimeUnit
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class XraySocksDnsBootstrapTest {
    @Test
    fun pinsBothFormsWithoutResolvingDestinationsOrChangingCredentialsAndTls() {
        for (legacy in listOf(false, true)) {
            val json = config(" Socks.Example. ", legacy)
            val queries = mutableListOf<String>()
            val prepared = prepare(json) { domain ->
                queries.add(domain)
                listOf("2001:db8::8", "192.0.2.8")
            }
            assertEquals(listOf("socks.example"), queries)
            val original = JSONObject(json)
            val root = JSONObject(prepared.json)
            for (key in listOf("outbounds", "routing")) {
                assertEquals(original.get(key).toString(), root.get(key).toString())
            }
            val addresses = root.getJSONObject("dns").getJSONObject("hosts")
                .getJSONArray("full:socks.example")
            assertEquals(canonicalBootstrapAddresses(listOf("2001:db8::8", "192.0.2.8")),
                (0 until addresses.length()).map(addresses::getString))
        }
    }

    @Test
    fun existingStaticHostsAndAliasesSkipSystemLookup() {
        for (legacy in listOf(false, true)) {
            for (target in listOf("""["2001:db8::8","192.0.2.8"]""", """"Alias.Example."""")) {
                val json = JSONObject(config("Socks.Example.", legacy)).put("dns", JSONObject("""
                    {"hosts":{"Socks.Example.":$target,"alias.example":["2001:db8::8","192.0.2.8"]}}
                """))
                val prepared = prepare(json.toString())
                val hosts = JSONObject(prepared.json).getJSONObject("dns").getJSONObject("hosts")
                assertEquals(2, hosts.getJSONArray("full:alias.example").length())
                assertTrue(hosts.has("full:socks.example"))
            }
        }
    }

    @Test
    fun literalsIncludingBracketedIpv6SkipSystemLookup() {
        for (legacy in listOf(false, true)) {
            for (address in listOf("192.0.2.8", " 192.0.2.8 ", "[192.0.2.8]",
                "2001:db8::8", "[2001:db8::8]", "::ffff:192.0.2.8")) {
                prepare(config(address, legacy))
            }
        }
    }

    @Test
    fun rejectsTunnelOwnedLiteralResolvedAndAliasedCarriers() {
        for (legacy in listOf(false, true)) {
            for (address in listOf("198.18.0.1", "10.7.0.1", "fd00:7872::1", "[fd00:7872::1]", "::ffff:198.18.0.1")) {
                assertThrows(IllegalArgumentException::class.java) { prepare(config(address, legacy)) }
                assertThrows(IllegalArgumentException::class.java) {
                    prepare(config("socks.example", legacy)) { listOf(address) }
                }
                val json = JSONObject(config("socks.example", legacy)).put("dns", JSONObject("""
                    {"hosts":{"socks.example":"alias.example","alias.example":"$address"}}
                """))
                assertThrows(IllegalArgumentException::class.java) { prepare(json.toString()) }
            }
        }
    }

    @Test
    fun lookupFailureFailsPreparation() {
        for (legacy in listOf(false, true)) {
            assertThrows(IllegalArgumentException::class.java) {
                prepare(config("socks.example", legacy)) { emptyList() }
            }
        }
    }

    private fun config(address: String, legacy: Boolean): String {
        val settings = if (legacy) {
            """{"servers":[{"address":"$address","port":1080,"users":[{"user":"synthetic-user","pass":"synthetic-secret"}]}]}"""
        } else {
            """{"address":"$address","port":1080,"user":"synthetic-user","pass":"synthetic-secret"}"""
        }
        return """{"outbounds":[{"tag":"proxy","protocol":"socks","settings":$settings,
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
