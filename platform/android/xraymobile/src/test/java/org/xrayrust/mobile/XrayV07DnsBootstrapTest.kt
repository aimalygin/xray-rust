package org.xrayrust.mobile

import java.util.concurrent.TimeUnit
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class XrayV07DnsBootstrapTest {
    private fun prepare(
        json: String,
        lookup: (String) -> List<String> = { error("unexpected system DNS lookup") },
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

    @Test
    fun pinsEveryCarrierAndPreservesAuthenticationAndPeerSettings() {
        val json = """
            {"dns":{"servers":["192.0.2.53"]},"outbounds":[
              {"protocol":"hysteria","settings":{"address":"Hy.Example.","port":443},
               "streamSettings":{"hysteriaSettings":{"auth":"synthetic-auth"},"tlsSettings":{"serverName":"tls.example"}}},
              {"protocol":"wireguard","settings":{"secretKey":"synthetic-key","address":["10.0.0.1/32"],"peers":[
                {"endpoint":"WG.Example.:51820","preSharedKey":"synthetic-psk","allowedIPs":["0.0.0.0/0"]},
                {"endpoint":"hy.example:51821"},{"endpoint":"[2001:db8::7]:51820"},{"endpoint":"192.0.2.7:51820"}
              ]}}
            ]}
        """.trimIndent()
        val queries = mutableListOf<String>()
        val prepared = prepare(json) { domain ->
            queries.add(domain)
            if (domain == "hy.example") listOf("2001:db8::8", "192.0.2.8") else listOf("192.0.2.9")
        }
        val root = JSONObject(prepared.json)
        assertEquals(JSONObject(json).getJSONArray("outbounds").toString(),
            root.getJSONArray("outbounds").toString())
        assertEquals(listOf("hy.example", "wg.example"), queries)
        val hosts = root.getJSONObject("dns").getJSONObject("hosts")
        assertEquals(canonicalBootstrapAddresses(listOf("2001:db8::8", "192.0.2.8")),
            hosts.getJSONArray("full:hy.example").let { array ->
                (0 until array.length()).map(array::getString)
            })
        assertEquals("192.0.2.9", hosts.getJSONArray("full:wg.example").getString(0))
        assertTrue(prepared.usesLocalDnsAnchor)
    }

    @Test
    fun usesExistingAliasesForAllPeersWithoutSystemLookup() {
        val prepared = prepare("""
            {"dns":{"hosts":{"WG.Example.":"Alias.Example.","alias.example":["2001:db8::8","192.0.2.8"]}},
             "outbounds":[{"protocol":"wireguard","settings":{"peers":[
               {"endpoint":"WG.Example.:51820"},{"endpoint":"alias.example:51821"}
             ]}}]}
        """.trimIndent())
        val hosts = JSONObject(prepared.json).getJSONObject("dns").getJSONObject("hosts")
        assertEquals("alias.example", hosts.getString("full:wg.example"))
        assertEquals(2, hosts.getJSONArray("full:alias.example").length())
    }

    @Test
    fun lastPeerLookupFailureAndExpiredDeadlineFailWholePreparation() {
        val json = """{"outbounds":[{"protocol":"wireguard","settings":{"peers":[
            {"endpoint":"first.example:51820"},{"endpoint":"last.example:51821"}
        ]}}]}"""
        val queries = mutableListOf<String>()
        assertThrows(IllegalArgumentException::class.java) {
            prepare(json) { domain ->
                queries.add(domain)
                if (domain == "first.example") listOf("192.0.2.8") else emptyList()
            }
        }
        assertEquals(listOf("first.example", "last.example"), queries)
        var now = 0L
        val deadline = AndroidDnsBootstrapDeadline(1) { now }
        now = 2
        BoundedAndroidDnsBootstrapResolver { error("expired lookup must not run") }.use { resolver ->
            assertThrows(AndroidDnsBootstrapTimeoutException::class.java) {
                prepareAndroidVpnConfigWithinDeadline(json, resolver, deadline)
            }
        }
    }

    @Test
    fun tunnelOwnedLiteralResolvedAndAliasedCarriersAreRejected() {
        for (address in listOf("198.18.0.1", "10.7.0.1", "fd00:7872::1")) {
            val endpoint = if (':' in address) "[$address]:51820" else "$address:51820"
            for (outbound in listOf(
                """{"protocol":"hysteria","settings":{"address":"$address"}}""",
                """{"protocol":"wireguard","settings":{"peers":[{"endpoint":"$endpoint"}]}}""",
                """{"protocol":"wireguard","settings":{"peers":[{"endpoint":"wg.example:51820"}]}}""",
                """{"protocol":"hysteria","settings":{"address":"wg.example"}}""",
            )) {
                for (pin in listOf(false, true)) {
                    val hosts = if (pin) {
                        """, "dns":{"hosts":{"wg.example":"alias.example","alias.example":"$address"}}"""
                    } else ""
                    assertThrows(IllegalArgumentException::class.java) {
                        prepare("""{"outbounds":[$outbound]$hosts}""") { listOf(address) }
                    }
                }
            }
        }
    }

    @Test
    fun malformedEndpointsNeverReachDnsAndErrorsOmitInput() {
        for (endpoint in listOf("secret@host:51820", "secret:0", "secret:65536", "secret:+1",
            "secret:١", "secret:", "[secret]:51820", "2001:db8::7:51820",
            "https://secret:51820", "secret:51820/path", "[fe80::1%1]:51820")) {
            val error = assertThrows(IllegalArgumentException::class.java) {
                prepare("""{"outbounds":[{"protocol":"wireguard","settings":{"peers":[{"endpoint":"$endpoint"}]}}]}""")
            }
            assertFalse(error.toString().contains(endpoint))
        }
    }

    private fun fakeIpConfig(protocol: String, rules: String = "[]", servers: String = "[]", balancers: String = "[]") = """
        {"dns":{"fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16"},"servers":$servers},
         "inbounds":[{"protocol":"tun","tag":"tun-in"}],
         "outbounds":[{"protocol":"$protocol","tag":"proxy","settings":{"address":"192.0.2.8","peers":[{"endpoint":"192.0.2.8:51820"}]}},
                      {"protocol":"wireguard","tag":"wg","settings":{"peers":[{"endpoint":"192.0.2.9:51820"}]}}],
         "routing":{"rules":$rules,"balancers":$balancers}}
    """.trimIndent()

    @Test
    fun fakeIpChecksBalancerCandidatesAndFallbacks() {
        for (balancer in listOf(
            """[{"tag":"pool","selector":["w"]}]""",
            """[{"tag":"pool","selector":["proxy"],"fallbackTag":"wg"}]""",
        )) {
            assertThrows(IllegalArgumentException::class.java) {
                prepare(fakeIpConfig("hysteria", """[{"balancerTag":"pool"}]""", balancers = balancer))
            }
            prepare(fakeIpConfig("hysteria", """[{"balancerTag":"pool","ip":["192.0.2.0/24"]}]""", balancers = balancer))
            prepare(fakeIpConfig("hysteria", """[{"balancerTag":"pool","inboundTag":["socks-in"]}]""", balancers = balancer))
        }
        prepare(fakeIpConfig("hysteria", """[{"balancerTag":"pool"}]""",
            balancers = """[{"tag":"pool","selector":["proxy"]}]"""))
    }

    @Test
    fun wireguardDefaultNeedsRealDestinationDnsButHysteriaCanResolveRemotely() {
        assertThrows(IllegalArgumentException::class.java) { prepare(fakeIpConfig("wireguard")) }
        prepare(fakeIpConfig("wireguard", servers = """["192.0.2.53"]"""))
        prepare(fakeIpConfig("hysteria"))
    }

    @Test
    fun wireguardDomainRoutesNeedDnsWhileIpOnlyAndNonTunRoutesAreAllowed() {
        for (matchers in listOf("", """, "domain":["domain:example"]""",
            """, "domains":["domain:example"], "ip":["192.0.2.0/24"]""")) {
            assertThrows(IllegalArgumentException::class.java) {
                prepare(fakeIpConfig("hysteria", """[{"outboundTag":"wg", "inboundTag":["tun-in"]$matchers}]"""))
            }
        }
        prepare(fakeIpConfig("hysteria", """[{"outboundTag":"wg", "ip":["192.0.2.0/24"]}]"""))
        prepare(fakeIpConfig("hysteria", """[{"outboundTag":"wg", "domain":["domain:example"], "inboundTag":["socks-in"]}]"""))
    }
}
