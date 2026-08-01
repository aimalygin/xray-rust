package org.xrayrust.mobile

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

class XrayTunBackendTest {
    @Test
    fun directFileDescriptorBackendIsTheDefault() {
        assertEquals(XrayTunBackend.FileDescriptor, DEFAULT_XRAY_TUN_BACKEND)
    }

    @Test
    fun packetPumpRemainsAnExplicitFallback() {
        assertTrue(XrayTunBackend.entries.contains(XrayTunBackend.PacketPump))
        assertTrue(XrayTunBackend.PacketPump != DEFAULT_XRAY_TUN_BACKEND)
    }

    @Test
    fun dnsBootstrapModesMatchTheCAbiDiscriminants() {
        assertEquals(0, XrayDnsBootstrapMode.System.ffiValue)
        assertEquals(1, XrayDnsBootstrapMode.StaticOnly.ffiValue)
    }

    @Test
    fun bootstrapDomainsUseCanonicalDnsIdentity() {
        assertEquals("server.example", normalizeBootstrapDomain("Server.Example."))
    }

    @Test
    fun domainDnsServerDropsPortBeforeBootstrap() {
        assertEquals(
            "dns.example",
            dnsServerBootstrapDomain("DNS.Example.:5353"),
        )
        assertEquals(
            AndroidDnsBootstrapDomain("dns.example", 5353),
            dnsServerBootstrapUpstreamDomain("DNS.Example.:5353"),
        )
    }

    @Test
    fun numericDnsServerDoesNotNeedBootstrap() {
        assertNull(dnsServerBootstrapDomain("[2001:db8::53]:5353"))
    }

    @Test
    fun scopedIpv6DnsServerDoesNotNeedBootstrap() {
        assertNull(dnsServerBootstrapDomain("[fe80::53%2]:5353"))
    }

    @Test
    fun objectDnsServerUsesAddressAndAcceptsXrayDefaultPort() {
        assertEquals(
            "dns.example",
            dnsServerBootstrapDomain(
                mapOf(
                    "address" to "DNS.Example.",
                    "port" to 0,
                    "domains" to listOf("domain:internal.example"),
                    "expectedIPs" to listOf("geoip:private", "!192.0.2.0/24"),
                    "expectIPs" to "geoip:private,geoip:cn",
                    "unexpectedIPs" to null,
                    "tag" to "dns-route",
                    "timeoutMs" to 1_750L,
                    "skipFallback" to true,
                    "queryStrategy" to "UseIPv4",
                    "finalQuery" to true,
                ),
            ),
        )
        assertNull(
            dnsServerBootstrapDomain(mapOf("address" to "2001:db8::53", "port" to 0)),
        )
        assertEquals(
            AndroidDnsBootstrapDomain("dns.example", 53),
            dnsServerBootstrapUpstreamDomain(
                mapOf("address" to "DNS.Example.", "port" to 0),
            ),
        )
    }

    @Test
    fun tcpDnsServerUrlsUseStrictAuthorityAndEmbeddedPortSemantics() {
        assertNull(dnsServerBootstrapUpstreamDomain("tcp://192.0.2.53"))
        assertNull(dnsServerBootstrapUpstreamDomain("TCP+LOCAL://[2001:db8::53]:5353"))
        assertEquals(
            AndroidDnsBootstrapDomain("resolver.example", 53, rejectsTunnelOwnedAddress = true),
            dnsServerBootstrapUpstreamDomain("Tcp://Resolver.Example."),
        )
        assertEquals(
            AndroidDnsBootstrapDomain("resolver.example", 5353, rejectsTunnelOwnedAddress = true),
            dnsServerBootstrapUpstreamDomain(
                mapOf(
                    "address" to "tcp+local://Resolver.Example.:5353",
                    "port" to 0,
                    "tag" to "dns-local",
                ),
            ),
        )
    }

    @Test
    fun malformedTcpDnsServerUrlsFailDuringBootstrapPreflight() {
        for (server in listOf<Any>(
            "tcp:/resolver.example",
            "tcp://",
            "tcp://user@resolver.example",
            "tcp://resolver.example/path",
            "tcp://resolver.example?query",
            "tcp://resolver.example#fragment",
            "tcp://resolver.example:0",
            "tcp://resolver.example:65536",
            "tcp://resolver.example:not-a-port",
            "tcp://resolver.example:+53",
            "tcp://resolver.example:٥٣",
            "tcp://2001:db8::53",
            "tcp://[192.0.2.53]",
            "tcp://[2001:db8::53",
            "tcp://resolver example",
            "tcp://resolver\u0001.example",
            "tcp://$XRAY_TUN_DNS_ANCHOR",
            "tcp://$XRAY_TUN_DNS_ANCHOR:5353",
            "tcp://10.7.0.1:5353",
            "tcp+local://[fd00:7872::1]:5353",
            mapOf("address" to "tcp+local://resolver.example/path"),
            mapOf("address" to "tcp://resolver.example", "port" to "53"),
            mapOf("address" to "tcp://resolver.example", "port" to 65_536),
        )) {
            assertThrows(IllegalArgumentException::class.java) {
                dnsServerBootstrapUpstreamDomain(server)
            }
        }
    }

    @Test
    fun mixedStringAndObjectDnsServersExposeBootstrapDomainsInStableOrder() {
        val servers = listOf<Any>(
            mapOf("address" to "Object-DNS.Example.", "port" to 0),
            "String-DNS.Example.:5353",
            mapOf("address" to "2001:db8::53", "port" to 5353),
        )

        assertEquals(
            listOf("object-dns.example", "string-dns.example", null),
            servers.map(::dnsServerBootstrapDomain),
        )
    }

    @Test
    fun malformedObjectDnsServerFailsDuringBootstrapPreflight() {
        for (server in listOf<Any>(
            mapOf("port" to 53),
            mapOf("address" to 42),
            mapOf("address" to "resolver.example", "port" to true),
            mapOf("address" to "resolver.example", "port" to 53.0),
            mapOf("address" to "resolver.example", "port" to null),
            mapOf("address" to "resolver.example", "port" to -1),
            mapOf("address" to "resolver.example", "port" to 65_536),
            mapOf("address" to "resolver.example", "domains" to 42),
            mapOf("address" to "resolver.example", "domains" to listOf("domain:ok", 42)),
            mapOf("address" to "resolver.example", "expectedIPs" to 42),
            mapOf("address" to "resolver.example", "expectedIPs" to listOf("geoip:private", 42)),
            mapOf("address" to "resolver.example", "expectIPs" to true),
            mapOf("address" to "resolver.example", "expectIPs" to listOf(null)),
            mapOf("address" to "resolver.example", "unexpectedIPs" to mapOf("ip" to "192.0.2.1")),
            mapOf("address" to "resolver.example", "unexpectedIPs" to listOf("192.0.2.0/24", false)),
            mapOf("address" to "resolver.example", "tag" to 42),
            mapOf("address" to "resolver.example", "tag" to true),
            mapOf("address" to "resolver.example", "tag" to listOf("dns-route")),
            mapOf("address" to "resolver.example", "timeoutMs" to -1),
            mapOf("address" to "resolver.example", "timeoutMs" to 1.5),
            mapOf("address" to "resolver.example", "timeoutMs" to "1000"),
            mapOf("address" to "resolver.example", "timeoutMs" to true),
            mapOf("address" to "resolver.example", "timeoutMs" to 4_611_686_018_428L),
            mapOf("address" to "resolver.example", "skipFallback" to "true"),
            mapOf("address" to "resolver.example", "finalQuery" to 1),
            mapOf("address" to "resolver.example", "queryStrategy" to 42),
            mapOf("address" to "resolver.example", "queryStrategy" to "UseSystem"),
            mapOf("address" to "resolver.example", "unexpected" to true),
            mapOf("address" to "localhost"),
            mapOf("address" to XRAY_TUN_DNS_ANCHOR, "port" to 0),
        )) {
            assertThrows(IllegalArgumentException::class.java) {
                dnsServerBootstrapDomain(server)
            }
        }
    }

    @Test
    fun malformedDnsIpPolicyStringListReportsTheFieldAndItemIndex() {
        val scalarError = assertThrows(IllegalArgumentException::class.java) {
            dnsServerBootstrapDomain(
                mapOf("address" to "resolver.example", "expectedIPs" to 42),
            )
        }
        assertTrue(scalarError.message?.contains("expectedIPs") == true)
        assertTrue(scalarError.message?.contains("string or an array") == true)

        val itemError = assertThrows(IllegalArgumentException::class.java) {
            dnsServerBootstrapDomain(
                mapOf(
                    "address" to "resolver.example",
                    "unexpectedIPs" to listOf("192.0.2.0/24", false),
                ),
            )
        }
        assertTrue(itemError.message?.contains("unexpectedIPs") == true)
        assertTrue(itemError.message?.contains("index 1") == true)
    }

    @Test
    fun dnsServerTimeoutAcceptsXrayZeroAndNullButRejectsUnsafeValues() {
        for (timeoutMs in listOf<Any?>(0, null, JSONObject.NULL, 1_750L, 4_611_686_018_427L)) {
            assertEquals(
                "resolver.example",
                dnsServerBootstrapDomain(
                    mapOf("address" to "resolver.example", "timeoutMs" to timeoutMs),
                ),
            )
        }

        for (timeoutMs in listOf<Any>(-1, 1.5, "1000", true, 4_611_686_018_428L)) {
            val error = assertThrows(IllegalArgumentException::class.java) {
                dnsServerBootstrapDomain(
                    mapOf("address" to "resolver.example", "timeoutMs" to timeoutMs),
                )
            }
            assertTrue(error.message?.contains("timeoutMs") == true)
        }
    }

    @Test
    fun dnsServerTagAcceptsXrayStringEmptyAndNullValues() {
        for (tag in listOf<Any?>(null, JSONObject.NULL, "", "dns-route", " dns route ")) {
            assertEquals(
                "resolver.example",
                dnsServerBootstrapDomain(mapOf("address" to "resolver.example", "tag" to tag)),
            )
        }

        for (tag in listOf<Any>(42, true, listOf("dns-route"))) {
            val error = assertThrows(IllegalArgumentException::class.java) {
                dnsServerBootstrapDomain(mapOf("address" to "resolver.example", "tag" to tag))
            }
            assertTrue(error.message?.contains("tag") == true)
        }
    }

    @Test
    fun dnsServerEndpointsRejectSurroundingWhitespace() {
        for (server in listOf<Any>(
            " resolver.example",
            "resolver.example ",
            mapOf("address" to " resolver.example"),
            mapOf("address" to "resolver.example "),
            mapOf("address" to " 192.0.2.53 "),
        )) {
            assertThrows(IllegalArgumentException::class.java) {
                dnsServerBootstrapDomain(server)
            }
        }
    }

    @Test
    fun directDnsServersRejectTunnelOwnedPort53ButAllowOtherPorts() {
        for (server in listOf<Any>(
            XRAY_TUN_DNS_ANCHOR,
            "$XRAY_TUN_DNS_ANCHOR:53",
            mapOf("address" to XRAY_TUN_DNS_ANCHOR),
            mapOf("address" to "198.18.0.2", "port" to 0),
        )) {
            assertThrows(IllegalArgumentException::class.java) {
                dnsServerBootstrapDomain(server)
            }
        }

        assertNull(dnsServerBootstrapDomain("$XRAY_TUN_DNS_ANCHOR:5353"))
        assertNull(
            dnsServerBootstrapDomain(mapOf("address" to "198.18.0.2", "port" to 5353)),
        )
    }

    @Test
    fun exactDnsHostMappingsCanonicalizeKeysAndPreserveTargets() {
        val canonical = canonicalizeExactDnsHostMappings(
            listOf("full:Proxy.Example." to "Alias.Example."),
        )

        assertTrue(canonical.modified)
        assertEquals(
            mapOf(
                "full:proxy.example" to AndroidDnsHostTarget.Alias("alias.example"),
            ),
            canonical.mappings,
        )
    }

    @Test
    fun bareDnsHostMappingsAreExactAndCanonicalizedLikeXray() {
        val canonical = canonicalizeExactDnsHostMappings(
            listOf<Pair<String, Any>>(
                "Proxy.Example." to "Alias.Example.",
                "alias.example" to listOf("192.0.2.7"),
            ),
        )

        assertTrue(canonical.modified)
        assertEquals(
            AndroidDnsHostTarget.Alias("alias.example"),
            canonical.mappings["full:proxy.example"],
        )
        assertEquals(
            AndroidDnsHostTarget.Addresses(listOf("192.0.2.7")),
            canonical.mappings["full:alias.example"],
        )
    }

    @Test
    fun bareAliasAndAddressArrayAvoidSystemBootstrapLookup() {
        val lookups = AtomicInteger()
        val canonical = canonicalizeExactDnsHostMappings(
            listOf<Pair<String, Any>>(
                "proxy.example" to "alias.example",
                "alias.example" to listOf("2001:db8::7", "192.0.2.7"),
            ),
        )
        val mappings = canonical.mappings.toMutableMap()

        val modified = ensureBootstrapHostMapping(
            domain = "proxy.example",
            exactMappings = mappings,
            resolvedAddresses = mutableMapOf(),
            activeAliases = mutableSetOf(),
            depth = 0,
        ) {
            lookups.incrementAndGet()
            error("unexpected system lookup for $it")
        }

        assertFalse(modified)
        assertEquals(
            AndroidDnsHostTarget.Addresses(listOf("2001:db8:0:0:0:0:0:7", "192.0.2.7")),
            mappings["full:alias.example"],
        )
        assertEquals(0, lookups.get())
    }

    @Test
    fun port53DnsBootstrapRejectsTunnelOwnedAddressAfterAliasResolution() {
        val mappings = canonicalizeExactDnsHostMappings(
            listOf<Pair<String, Any>>(
                "resolver.example" to "alias.example",
                "alias.example" to listOf(XRAY_TUN_DNS_ANCHOR),
            ),
        ).mappings.toMutableMap()

        assertThrows(IllegalArgumentException::class.java) {
            ensureBootstrapHostMapping(
                domain = "resolver.example",
                exactMappings = mappings,
                resolvedAddresses = mutableMapOf(),
                activeAliases = mutableSetOf(),
                depth = 0,
                dnsUpstreamPort = 53,
            ) {
                error("unexpected system lookup for $it")
            }
        }
    }

    @Test
    fun port53DnsBootstrapRejectsTunnelOwnedSystemResolutionBeforePublishingMapping() {
        val mappings = mutableMapOf<String, AndroidDnsHostTarget>()

        assertThrows(IllegalArgumentException::class.java) {
            ensureBootstrapHostMapping(
                domain = "resolver.example",
                exactMappings = mappings,
                resolvedAddresses = mutableMapOf(),
                activeAliases = mutableSetOf(),
                depth = 0,
                dnsUpstreamPort = 53,
            ) {
                listOf(XRAY_TUN_DNS_ANCHOR)
            }
        }
        assertFalse(mappings.containsKey("full:resolver.example"))
    }

    @Test
    fun nonstandardDnsPortMayResolveToTunnelOwnedAddress() {
        val mappings = mutableMapOf<String, AndroidDnsHostTarget>()

        assertTrue(
            ensureBootstrapHostMapping(
                domain = "resolver.example",
                exactMappings = mappings,
                resolvedAddresses = mutableMapOf(),
                activeAliases = mutableSetOf(),
                depth = 0,
                dnsUpstreamPort = 5353,
            ) {
                listOf(XRAY_TUN_DNS_ANCHOR)
            },
        )
        assertEquals(
            AndroidDnsHostTarget.Addresses(listOf(XRAY_TUN_DNS_ANCHOR)),
            mappings["full:resolver.example"],
        )
    }

    @Test
    fun equivalentExactDnsHostMappingsAreCoalesced() {
        val canonical = canonicalizeExactDnsHostMappings(
            listOf(
                "full:Proxy.Example." to "198.51.100.7",
                "full:proxy.example" to "198.51.100.7",
            ),
        )

        assertTrue(canonical.modified)
        assertEquals(
            mapOf(
                "full:proxy.example" to AndroidDnsHostTarget.Addresses(
                    listOf("198.51.100.7"),
                ),
            ),
            canonical.mappings,
        )
    }

    @Test
    fun conflictingExactDnsHostMappingsAreRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            canonicalizeExactDnsHostMappings(
                listOf(
                    "full:Proxy.Example." to "198.51.100.7",
                    "full:proxy.example" to "198.51.100.8",
                ),
            )
        }
    }

    @Test
    fun fakeIpWithoutDnsServersRejectsDefaultFreedom() {
        assertThrows(IllegalArgumentException::class.java) {
            validateAndroidDnsPreflightTopology(
                AndroidDnsPreflightTopology(
                    fakeIpEnabled = true,
                    hasDnsServers = false,
                    defaultOutboundIsFreedom = true,
                    routingRules = emptyList(),
                ),
            )
        }
    }

    @Test
    fun fakeIpWithoutDnsServersRejectsTunDomainRuleToFreedom() {
        assertThrows(IllegalArgumentException::class.java) {
            validateAndroidDnsPreflightTopology(
                AndroidDnsPreflightTopology(
                    fakeIpEnabled = true,
                    hasDnsServers = false,
                    defaultOutboundIsFreedom = false,
                    routingRules = listOf(
                        AndroidDnsPreflightRoutingRule(
                            selectsFreedom = true,
                            appliesToTun = true,
                            hasDomainMatchers = true,
                            hasIpMatchers = false,
                        ),
                    ),
                ),
            )
        }
    }

    @Test
    fun fakeIpWithoutDnsServersAcceptsDefaultVlessAndIpOnlyFreedomRule() {
        validateAndroidDnsPreflightTopology(
            AndroidDnsPreflightTopology(
                fakeIpEnabled = true,
                hasDnsServers = false,
                defaultOutboundIsFreedom = false,
                routingRules = listOf(
                    AndroidDnsPreflightRoutingRule(
                        selectsFreedom = true,
                        appliesToTun = true,
                        hasDomainMatchers = false,
                        hasIpMatchers = true,
                    ),
                ),
            ),
        )
    }

    @Test
    fun fakeIpWithDnsServersAcceptsFreedomTopology() {
        validateAndroidDnsPreflightTopology(
            AndroidDnsPreflightTopology(
                fakeIpEnabled = true,
                hasDnsServers = true,
                defaultOutboundIsFreedom = true,
                routingRules = listOf(
                    AndroidDnsPreflightRoutingRule(
                        selectsFreedom = true,
                        appliesToTun = true,
                        hasDomainMatchers = true,
                        hasIpMatchers = false,
                    ),
                ),
            ),
        )
    }

    @Test
    fun ipv4FakeIpRejectsIpv6OnlyQueryStrategyBeforeTunnelSetup() {
        for (strategy in listOf(
            "UseIP6",
            "UseIPv6",
            "use_ip6",
            "use_ipv6",
            "use_ip_v6",
            "use-ip6",
            "use-ipv6",
            "use-ip-v6",
        )) {
            assertFalse(
                isIpv4FakeIpDnsQueryStrategyCompatible(
                    fakeIpEnabled = true,
                    rawStrategy = strategy,
                ),
            )
        }
        assertTrue(isIpv4FakeIpDnsQueryStrategyCompatible(true, "UseIPv4"))
        assertTrue(isIpv4FakeIpDnsQueryStrategyCompatible(false, "UseIPv6"))
    }

    @Test
    fun fakeIpEnabledRequiresAnActualJsonBooleanBeforeTunnelSetup() {
        assertFalse(
            optionalStrictJsonBoolean(
                rawValue = null,
                isPresent = false,
                field = "dns.fakeIp.enabled",
            ),
        )
        assertTrue(
            optionalStrictJsonBoolean(
                rawValue = true,
                isPresent = true,
                field = "dns.fakeIp.enabled",
            ),
        )
        assertFalse(
            optionalStrictJsonBoolean(
                rawValue = false,
                isPresent = true,
                field = "dns.fakeIp.enabled",
            ),
        )
        for (rawValue in listOf<Any>("true", "false", 1, 0, 1.0)) {
            assertThrows(IllegalArgumentException::class.java) {
                optionalStrictJsonBoolean(
                    rawValue = rawValue,
                    isPresent = true,
                    field = "dns.fakeIp.enabled",
                )
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            optionalStrictJsonBoolean(
                rawValue = null,
                isPresent = true,
                field = "dns.fakeIp.enabled",
            )
        }
    }

    @Test
    fun dnsServerStrategyMustIntersectGlobalStrategyBeforeTunnelSetup() {
        validateDnsServerQueryStrategyCompatibility("UseIP", "UseIPv6")
        validateDnsServerQueryStrategyCompatibility("UseIPv4", "UseIP")
        validateDnsServerQueryStrategyCompatibility(null, "UseIPv6")

        assertThrows(IllegalArgumentException::class.java) {
            validateDnsServerQueryStrategyCompatibility("UseIPv4", "UseIPv6")
        }
        assertThrows(IllegalArgumentException::class.java) {
            validateDnsServerQueryStrategyCompatibility("UseIPv6", "UseIPv4")
        }
    }

    @Test
    fun dnsServerCountIsBoundedBeforeTunnelSetup() {
        validateAndroidDnsServerCount(8)
        assertThrows(IllegalArgumentException::class.java) {
            validateAndroidDnsServerCount(9)
        }
    }

    @Test
    fun dnsBootstrapDeadlineIsSharedAcrossSequentialLookups() {
        val now = AtomicLong(1_000)
        val deadline = AndroidDnsBootstrapDeadline(
            timeoutNanos = 100,
            nanoTime = now::get,
        )

        assertEquals(100L, deadline.remainingNanos())
        now.set(1_060)
        assertEquals(40L, deadline.remainingNanos())
        now.set(1_100)
        assertThrows(AndroidDnsBootstrapTimeoutException::class.java) {
            deadline.remainingNanos()
        }
    }

    @Test
    fun blockedSystemLookupTimesOutAndWorkerCapacityStaysBounded() {
        val lookupStarted = CountDownLatch(1)
        val releaseLookup = CountDownLatch(1)
        val resolver = BoundedAndroidDnsBootstrapResolver(maxConcurrentLookups = 1) {
            lookupStarted.countDown()
            var released = false
            while (!released) {
                try {
                    if (releaseLookup.await(10, TimeUnit.MILLISECONDS)) {
                        released = true
                    }
                } catch (_: InterruptedException) {
                    // Model InetAddress implementations that ignore interruption.
                }
            }
            listOf("192.0.2.1")
        }
        try {
            assertThrows(AndroidDnsBootstrapTimeoutException::class.java) {
                resolver.resolve("blocked.example", TimeUnit.MILLISECONDS.toNanos(50))
            }
            assertTrue(lookupStarted.await(1, TimeUnit.SECONDS))
            assertThrows(IllegalStateException::class.java) {
                resolver.resolve("queued.example", TimeUnit.MILLISECONDS.toNanos(50))
            }
        } finally {
            releaseLookup.countDown()
            resolver.close()
        }
    }

    @Test
    fun lookupResultThatArrivesAfterCommonDeadlineIsNotPublished() {
        val now = AtomicLong(1_000)
        val resolver = BoundedAndroidDnsBootstrapResolver(maxConcurrentLookups = 1) {
            now.set(1_000 + TimeUnit.SECONDS.toNanos(1))
            listOf("192.0.2.1")
        }
        try {
            val deadline = AndroidDnsBootstrapDeadline(
                timeoutNanos = TimeUnit.SECONDS.toNanos(1),
                nanoTime = now::get,
            )

            assertThrows(AndroidDnsBootstrapTimeoutException::class.java) {
                resolveAndroidDnsBootstrapAddressesWithinDeadline(
                    domain = "proxy.example",
                    resolver = resolver,
                    deadline = deadline,
                )
            }
        } finally {
            resolver.close()
        }
    }

    @Test
    fun configPinningPreservesTcpDnsServerUrlsAndObjectPolicyFields() {
        val stringUrl = "TCP://String-DNS.Example.:5353"
        val objectUrl = "tcp+local://Object-DNS.Example.:5443"
        val config = """
            {"dns":{"servers":[
              "$stringUrl",
              {"address":"$objectUrl","port":53,"domains":["domain:internal.example"],"expectedIPs":["geoip:private"],"unexpectedIPs":["192.0.2.0/24"],"tag":"dns-local","timeoutMs":1750,"skipFallback":true,"queryStrategy":"UseIPv4","finalQuery":true},
              "tcp://192.0.2.53"
            ]},"outbounds":[{"protocol":"freedom"}]}
        """.trimIndent()
        val resolvedDomains = mutableListOf<String>()
        val resolver = BoundedAndroidDnsBootstrapResolver(maxConcurrentLookups = 2) { domain ->
            resolvedDomains.add(domain)
            if (domain == "string-dns.example") {
                listOf("198.51.100.53")
            } else {
                listOf("198.51.100.54")
            }
        }
        try {
            val prepared = prepareAndroidVpnConfigWithinDeadline(
                configJson = config,
                resolver = resolver,
                deadline = AndroidDnsBootstrapDeadline(TimeUnit.SECONDS.toNanos(1)),
            )
            val root = JSONObject(prepared.json)
            val dns = root.getJSONObject("dns")
            val servers = dns.getJSONArray("servers")
            val objectServer = servers.getJSONObject(1)
            val hosts = dns.getJSONObject("hosts")

            assertEquals(
                listOf("string-dns.example", "object-dns.example"),
                resolvedDomains,
            )
            assertEquals("198.51.100.53", hosts.getJSONArray("full:string-dns.example").getString(0))
            assertEquals("198.51.100.54", hosts.getJSONArray("full:object-dns.example").getString(0))
            assertEquals(stringUrl, servers.getString(0))
            assertEquals("tcp://192.0.2.53", servers.getString(2))
            assertEquals(objectUrl, objectServer.getString("address"))
            assertEquals(53, objectServer.getInt("port"))
            assertEquals("domain:internal.example", objectServer.getJSONArray("domains").getString(0))
            assertEquals("geoip:private", objectServer.getJSONArray("expectedIPs").getString(0))
            assertEquals("192.0.2.0/24", objectServer.getJSONArray("unexpectedIPs").getString(0))
            assertEquals("dns-local", objectServer.getString("tag"))
            assertEquals(1_750, objectServer.getInt("timeoutMs"))
            assertTrue(objectServer.getBoolean("skipFallback"))
            assertEquals("UseIPv4", objectServer.getString("queryStrategy"))
            assertTrue(objectServer.getBoolean("finalQuery"))
        } finally {
            resolver.close()
        }
    }

    @Test
    fun tcpDnsServerUrlRejectsTunnelOwnedResolutionAtNonstandardPort() {
        for (address in listOf(XRAY_TUN_DNS_ANCHOR, "10.7.0.1", "fd00:7872::1")) {
            val resolver = BoundedAndroidDnsBootstrapResolver(maxConcurrentLookups = 1) {
                listOf(address)
            }
            try {
                assertThrows(IllegalArgumentException::class.java) {
                    prepareAndroidVpnConfigWithinDeadline(
                        configJson =
                            "{\"dns\":{\"servers\":[\"tcp://resolver.example:5353\"]}}",
                        resolver = resolver,
                        deadline = AndroidDnsBootstrapDeadline(TimeUnit.SECONDS.toNanos(1)),
                    )
                }
            } finally {
                resolver.close()
            }
        }
    }

    @Test
    fun bootstrapRetainsEveryResolvedAddressInStableOrder() {
        assertEquals(
            listOf("2001:db8:0:0:0:0:0:7", "192.0.2.7"),
            canonicalBootstrapAddresses(
                listOf("2001:db8::7", "192.0.2.7", "2001:db8::7"),
            ),
        )
    }

    @Test
    fun lifecyclePublishesAndStopsOneSessionAtomically() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val token = lifecycle.beginStart()
        assertNotNull(token)
        assertNull(lifecycle.beginStart())
        assertTrue(lifecycle.isStartActive(token!!))
        assertTrue(lifecycle.publish(token, "session"))

        val action = lifecycle.requestStop()
        assertTrue(action is XrayTunnelStopAction.StopSession)
        assertEquals("session", (action as XrayTunnelStopAction.StopSession).session)
        lifecycle.completeStop()
        assertNotNull(lifecycle.beginStart())
    }

    @Test
    fun stopDuringStartCancelsPublicationWithoutWaiting() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val token = lifecycle.beginStart()!!
        assertEquals(XrayTunnelStopAction.CancelStart, lifecycle.requestStop())
        assertFalse(lifecycle.isStartActive(token))
        assertFalse(lifecycle.publish(token, "must-not-publish"))

        lifecycle.failStart(token)
        assertNotNull(lifecycle.beginStart())
    }

    @Test
    fun cancellingQueuedStartBeforeFirstRunDoesNotStrandLifecycle() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val token = lifecycle.beginStart()!!
        val queuedTask = AtomicReference<Runnable?>()
        val blockRan = AtomicBoolean(false)
        val coordinator = XrayAsyncStartCoordinator(
            lifecycle = lifecycle,
            executor = Executor { queuedTask.set(it) },
        )
        coordinator.execute(token) { blockRan.set(true) }

        assertEquals(XrayTunnelStopAction.CancelStart, lifecycle.requestStop())
        coordinator.cancelActiveStart()

        assertFalse(coordinator.hasActiveStart())
        assertNotNull(lifecycle.beginStart())
        queuedTask.get()?.run()
        assertFalse(blockRan.get())
    }

    @Test
    fun completionCallbackCanReentrantlyScheduleANewStart() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val coordinator = XrayAsyncStartCoordinator(
            lifecycle = lifecycle,
            executor = Executor(Runnable::run),
        )
        val firstToken = lifecycle.beginStart()!!
        val retryRan = AtomicBoolean(false)

        coordinator.execute(
            token = firstToken,
            block = { "failed" },
            afterRelease = {
                assertFalse(coordinator.hasActiveStart())
                val retryToken = lifecycle.beginStart()!!
                coordinator.execute(retryToken) { retryRan.set(true) }
            },
        )

        assertTrue(retryRan.get())
    }

    @Test
    fun stopAfterPublicationCancelsStartTailAndReturnsRunningSession() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val token = lifecycle.beginStart()!!
        val published = CountDownLatch(1)
        val releaseWorker = CountDownLatch(1)
        val workerFinished = CountDownLatch(1)
        val coordinator = XrayAsyncStartCoordinator(
            lifecycle = lifecycle,
            executor = Executor { runnable -> Thread(runnable).start() },
        )
        coordinator.execute(token) {
            try {
                assertTrue(lifecycle.publish(token, "session"))
                published.countDown()
                var released = false
                while (!released) {
                    try {
                        releaseWorker.await()
                        released = true
                    } catch (_: InterruptedException) {
                        // A host callback may not return immediately on cancellation.
                    }
                }
            } finally {
                workerFinished.countDown()
            }
        }
        assertTrue(published.await(1, TimeUnit.SECONDS))

        val action = lifecycle.requestStop()
        assertTrue(action is XrayTunnelStopAction.StopSession)
        assertEquals("session", (action as XrayTunnelStopAction.StopSession).session)
        coordinator.cancelActiveStart()
        lifecycle.completeStop()

        assertFalse(coordinator.hasActiveStart())
        val restarted = lifecycle.beginStart()!!
        val restartedWorker = CountDownLatch(1)
        coordinator.execute(restarted) { restartedWorker.countDown() }
        assertTrue(restartedWorker.await(1, TimeUnit.SECONDS))

        releaseWorker.countDown()
        assertTrue(workerFinished.await(1, TimeUnit.SECONDS))
    }

    @Test
    fun oldStartTailCannotCompleteAnInProgressSessionStop() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val token = lifecycle.beginStart()!!
        assertTrue(lifecycle.publish(token, "session"))
        assertTrue(lifecycle.requestStop() is XrayTunnelStopAction.StopSession)

        lifecycle.failStart(token)

        assertNull(lifecycle.beginStart())
        lifecycle.completeStop()
        assertNotNull(lifecycle.beginStart())
    }

    @Test
    fun publicationFailureCanOnlyBeCompletedByItsOwnStartToken() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val token = lifecycle.beginStart()!!
        val unrelatedToken = XrayTunnelStateMachine.StartToken()
        assertThrows(IllegalStateException::class.java) {
            lifecycle.publish(token, "session") { error("pump start failed") }
        }
        assertTrue(lifecycle.isStartFailureReportable(token))

        lifecycle.failStart(unrelatedToken)
        assertNull(lifecycle.beginStart())

        lifecycle.failStart(token)
        assertNotNull(lifecycle.beginStart())
    }

    @Test
    fun rapidRestartIsRejectedUntilCancelledWorkerFinishesCleanup() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val token = lifecycle.beginStart()!!
        val workerStarted = CountDownLatch(1)
        val releaseCleanup = CountDownLatch(1)
        val workerFinished = CountDownLatch(1)
        val coordinator = XrayAsyncStartCoordinator(
            lifecycle = lifecycle,
            executor = Executor { runnable -> Thread(runnable).start() },
        )
        coordinator.execute(token) {
            try {
                workerStarted.countDown()
                while (true) {
                    try {
                        releaseCleanup.await()
                        break
                    } catch (_: InterruptedException) {
                        // Model bounded cleanup that observes cancellation later.
                    }
                }
            } finally {
                workerFinished.countDown()
            }
        }
        assertTrue(workerStarted.await(1, TimeUnit.SECONDS))

        assertEquals(XrayTunnelStopAction.CancelStart, lifecycle.requestStop())
        coordinator.cancelActiveStart()
        assertNull(lifecycle.beginStart())

        releaseCleanup.countDown()
        assertTrue(workerFinished.await(1, TimeUnit.SECONDS))
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
        var restarted: XrayTunnelStateMachine.StartToken? = null
        while (restarted == null && System.nanoTime() < deadline) {
            restarted = lifecycle.beginStart()
            if (restarted == null) {
                Thread.yield()
            }
        }
        assertNotNull(restarted)
    }

    @Test
    fun onePumpFailureTearsDownTheWholeSessionExactlyOnce() {
        data class FakeSession(
            val active: AtomicBoolean = AtomicBoolean(true),
            val peerStopped: AtomicBoolean = AtomicBoolean(false),
            val coreClosed: AtomicBoolean = AtomicBoolean(false),
            val tunnelClosed: AtomicBoolean = AtomicBoolean(false),
            val shutdownCalls: AtomicInteger = AtomicInteger(),
        ) {
            fun shutdown() {
                shutdownCalls.incrementAndGet()
                active.set(false)
                peerStopped.set(true)
                coreClosed.set(true)
                tunnelClosed.set(true)
            }
        }

        val lifecycle = XrayTunnelStateMachine<FakeSession>()
        val token = lifecycle.beginStart()
        assertNotNull(token)
        val session = FakeSession()
        assertTrue(lifecycle.publish(token!!, session))

        assertTrue(teardownFailedXraySession(lifecycle, session) { it.shutdown() })
        assertFalse(teardownFailedXraySession(lifecycle, session) { it.shutdown() })
        assertFalse(session.active.get())
        assertTrue(session.peerStopped.get())
        assertTrue(session.coreClosed.get())
        assertTrue(session.tunnelClosed.get())
        assertEquals(1, session.shutdownCalls.get())
        assertNotNull(lifecycle.beginStart())
    }

    @Test
    fun repeatedPushBackpressureNeverTearsDownThePacketPump() {
        val lifecycle = XrayTunnelStateMachine<Any>()
        val token = lifecycle.beginStart()
        assertNotNull(token)
        val session = Any()
        assertTrue(lifecycle.publish(token!!, session))
        val backpressure = XrayCoreException(code = 8, message = "TUN queue is full")

        repeat(10_000) {
            assertTrue(isRecoverablePacketPushFailure(backpressure))
        }

        assertTrue(lifecycle.isRunningSession(session))
        assertFalse(isRecoverablePacketPushFailure(IllegalStateException("I/O failed")))
    }

    @Test
    fun packetPumpShutdownDoesNotWaitForItsOwnThread() {
        val returned = CountDownLatch(1)
        val worker = Thread {
            joinXrayPumpThreadUninterruptibly(Thread.currentThread())
            returned.countDown()
        }
        worker.isDaemon = true
        worker.start()

        assertTrue(returned.await(1, TimeUnit.SECONDS))
    }
}
