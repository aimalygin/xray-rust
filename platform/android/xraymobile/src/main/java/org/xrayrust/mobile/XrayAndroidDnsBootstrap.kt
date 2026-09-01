package org.xrayrust.mobile

import java.net.Inet6Address
import java.net.InetAddress
import java.util.Locale
import java.util.concurrent.ExecutionException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONArray
import org.json.JSONObject

internal data class PreparedAndroidVpnConfig(
    val json: String,
    val usesLocalDnsAnchor: Boolean,
)

internal data class AndroidDnsBootstrapDomain(
    val domain: String,
    val port: Int,
    val rejectsTunnelOwnedAddress: Boolean = false,
)

internal class AndroidDnsBootstrapTimeoutException(message: String) :
    IllegalArgumentException(message)

internal class AndroidDnsBootstrapCancelledException : RuntimeException()

internal class AndroidDnsBootstrapDeadline(
    timeoutNanos: Long,
    private val nanoTime: () -> Long = System::nanoTime,
) {
    private val deadlineNanos: Long

    init {
        require(timeoutNanos > 0) { "DNS bootstrap timeout must be positive" }
        deadlineNanos = nanoTime() + timeoutNanos
    }

    fun remainingNanos(): Long {
        val remaining = deadlineNanos - nanoTime()
        if (remaining <= 0) {
            throw AndroidDnsBootstrapTimeoutException(
                "DNS bootstrap deadline elapsed before all hostnames were resolved",
            )
        }
        return remaining
    }
}

internal class BoundedAndroidDnsBootstrapResolver(
    maxConcurrentLookups: Int = MAX_BLOCKED_DNS_LOOKUP_THREADS,
    private val lookup: (String) -> List<String> = ::lookupSystemBootstrapAddresses,
) : AutoCloseable {
    private val threadSequence = AtomicInteger()
    private val executor = ThreadPoolExecutor(
        0,
        maxConcurrentLookups,
        DNS_LOOKUP_THREAD_KEEP_ALIVE_SECONDS,
        TimeUnit.SECONDS,
        SynchronousQueue(),
        ThreadFactory { runnable ->
            Thread(
                runnable,
                "xray-dns-bootstrap-${threadSequence.incrementAndGet()}",
            ).apply {
                isDaemon = true
            }
        },
        ThreadPoolExecutor.AbortPolicy(),
    )

    init {
        require(maxConcurrentLookups > 0) { "DNS lookup worker limit must be positive" }
    }

    fun resolve(domain: String, timeoutNanos: Long): List<String> {
        if (timeoutNanos <= 0) {
            throw AndroidDnsBootstrapTimeoutException(
                "DNS bootstrap deadline elapsed before resolving `$domain`",
            )
        }
        val future = try {
            executor.submit<List<String>> { lookup(domain) }
        } catch (error: RejectedExecutionException) {
            throw IllegalStateException(
                "DNS bootstrap worker capacity is exhausted by blocked system lookups",
                error,
            )
        }
        try {
            return future.get(timeoutNanos, TimeUnit.NANOSECONDS)
        } catch (error: TimeoutException) {
            future.cancel(true)
            throw AndroidDnsBootstrapTimeoutException(
                "DNS bootstrap deadline elapsed while resolving `$domain`",
            )
        } catch (error: InterruptedException) {
            future.cancel(true)
            Thread.currentThread().interrupt()
            throw AndroidDnsBootstrapCancelledException()
        } catch (error: ExecutionException) {
            val cause = error.cause ?: error
            if (cause is RuntimeException) {
                throw cause
            }
            throw IllegalArgumentException(
                "failed to resolve bootstrap domain `$domain` before establishing the VPN tunnel",
                cause,
            )
        }
    }

    override fun close() {
        executor.shutdownNow()
    }
}

internal fun prepareAndroidVpnConfigWithinDeadline(
    configJson: String,
    resolver: BoundedAndroidDnsBootstrapResolver,
    deadline: AndroidDnsBootstrapDeadline,
): PreparedAndroidVpnConfig {
    val root = JSONObject(configJson)
    val dns = if (root.has("dns")) root.getJSONObject("dns") else null
    val dnsServers = if (dns?.has("servers") == true) {
        dns.getJSONArray("servers")
    } else {
        null
    }
    validateAndroidDnsServerCount(dnsServers?.length() ?: 0)
    val globalQueryStrategy = dns?.opt("queryStrategy")
    dnsQueryStrategyFamilies(globalQueryStrategy, "global DNS")
    validateAndroidDnsCachePolicy(dns)
    val usesFakeIp = if (dns?.has("fakeIp") == true) {
        val fakeIp = dns.getJSONObject("fakeIp")
        optionalStrictJsonBoolean(
            rawValue = fakeIp.opt("enabled"),
            isPresent = fakeIp.has("enabled"),
            field = "dns.fakeIp.enabled",
        )
    } else {
        false
    }
    require(
        isIpv4FakeIpDnsQueryStrategyCompatible(
            fakeIpEnabled = usesFakeIp,
            rawStrategy = dns?.opt("queryStrategy"),
        ),
    ) {
        "IPv4 fake-IP DNS cannot be used with an IPv6-only queryStrategy"
    }
    val usesLocalDnsAnchor = usesFakeIp || (dnsServers?.length() ?: 0) > 0
    if (usesFakeIp && (dnsServers?.length() ?: 0) == 0) {
        validateAndroidDnsPreflightTopology(
            androidDnsPreflightTopology(
                root = root,
                fakeIpEnabled = true,
                hasDnsServers = false,
            ),
        )
    }

    val carrierBootstrapDomains = linkedSetOf<String>()
    val dnsBootstrapDomains = linkedSetOf<AndroidDnsBootstrapDomain>()
    collectVlessBootstrapDomains(root, carrierBootstrapDomains)
    if (dnsServers != null) {
        for (index in 0 until dnsServers.length()) {
            val rawServer = dnsServers.get(index)
            dnsServerBootstrapUpstreamDomain(rawServer)?.let(dnsBootstrapDomains::add)
            validateDnsServerQueryStrategyCompatibility(
                globalStrategy = globalQueryStrategy,
                serverStrategy = when (rawServer) {
                    is JSONObject -> rawServer.opt("queryStrategy")
                    else -> null
                },
            )
        }
    }
    val preparedDns = dns ?: JSONObject()
    val hosts = if (preparedDns.has("hosts")) {
        preparedDns.getJSONObject("hosts")
    } else {
        JSONObject()
    }
    val canonicalMappings = canonicalizeExactDnsHostMappingsFromJson(hosts)
    val exactMappings = canonicalMappings.mappings.toMutableMap()
    val resolvedAddresses = mutableMapOf<String, List<String>>()
    var modified = canonicalMappings.modified
    val resolveSystemBootstrapAddresses: (String) -> List<String> = { domain ->
        resolveAndroidDnsBootstrapAddressesWithinDeadline(domain, resolver, deadline)
    }
    for (domain in carrierBootstrapDomains) {
        modified = ensureBootstrapHostMapping(
            domain = domain,
            exactMappings = exactMappings,
            resolvedAddresses = resolvedAddresses,
            activeAliases = mutableSetOf(),
            depth = 0,
            resolveSystemBootstrapAddresses = resolveSystemBootstrapAddresses,
        ) || modified
    }
    for (upstream in dnsBootstrapDomains) {
        modified = ensureBootstrapHostMapping(
            domain = upstream.domain,
            exactMappings = exactMappings,
            resolvedAddresses = resolvedAddresses,
            activeAliases = mutableSetOf(),
            depth = 0,
            dnsUpstreamPort = upstream.port,
            rejectsTunnelOwnedAddress = upstream.rejectsTunnelOwnedAddress,
            resolveSystemBootstrapAddresses = resolveSystemBootstrapAddresses,
        ) || modified
    }

    if (!modified) {
        return PreparedAndroidVpnConfig(configJson, usesLocalDnsAnchor)
    }
    val existingKeys = hosts.keys().asSequence().toList()
    for (key in existingKeys) {
        if (exactDnsHostIdentity(key) != null) {
            hosts.remove(key)
        }
    }
    for ((key, target) in exactMappings) {
        hosts.put(key, target.toJsonValue())
    }
    if (!preparedDns.has("hosts")) {
        preparedDns.put("hosts", hosts)
    }
    if (!root.has("dns")) {
        root.put("dns", preparedDns)
    }
    return PreparedAndroidVpnConfig(root.toString(), usesLocalDnsAnchor)
}

internal fun resolveAndroidDnsBootstrapAddressesWithinDeadline(
    domain: String,
    resolver: BoundedAndroidDnsBootstrapResolver,
    deadline: AndroidDnsBootstrapDeadline,
): List<String> {
    val addresses = resolver.resolve(domain, deadline.remainingNanos())
    deadline.remainingNanos()
    return addresses
}

internal data class AndroidDnsPreflightRoutingRule(
    val selectsFreedom: Boolean,
    val appliesToTun: Boolean,
    val hasDomainMatchers: Boolean,
    val hasIpMatchers: Boolean,
) {
    val canSelectDomainTraffic: Boolean
        get() = hasDomainMatchers || !hasIpMatchers
}

internal data class AndroidDnsPreflightTopology(
    val fakeIpEnabled: Boolean,
    val hasDnsServers: Boolean,
    val defaultOutboundIsFreedom: Boolean,
    val routingRules: List<AndroidDnsPreflightRoutingRule>,
)

internal fun validateAndroidDnsPreflightTopology(topology: AndroidDnsPreflightTopology) {
    if (!topology.fakeIpEnabled || topology.hasDnsServers) {
        return
    }
    require(!topology.defaultOutboundIsFreedom) {
        "fake-IP with a default Freedom outbound requires at least one dns.servers upstream"
    }
    require(
        topology.routingRules.none { rule ->
            rule.selectsFreedom && rule.appliesToTun && rule.canSelectDomainTraffic
        },
    ) {
        "fake-IP with a TUN domain route to Freedom requires at least one dns.servers upstream"
    }
}

private fun androidDnsPreflightTopology(
    root: JSONObject,
    fakeIpEnabled: Boolean,
    hasDnsServers: Boolean,
): AndroidDnsPreflightTopology {
    val outbounds = root.optJSONArray("outbounds")
    val outboundProtocolsByTag = linkedMapOf<String, String>()
    if (outbounds != null) {
        for (index in 0 until outbounds.length()) {
            val outbound = outbounds.optJSONObject(index) ?: continue
            val tag = outbound.optString("tag").takeIf(String::isNotEmpty) ?: continue
            outboundProtocolsByTag.putIfAbsent(tag, outbound.optString("protocol"))
        }
    }
    val defaultOutboundIsFreedom = outbounds
        ?.optJSONObject(0)
        ?.optString("protocol")
        ?.equals("freedom", ignoreCase = true) == true
    val tunInboundTags = tunInboundTags(root)
    val routingRules = mutableListOf<AndroidDnsPreflightRoutingRule>()
    val rawRules = root.optJSONObject("routing")?.optJSONArray("rules")
    if (rawRules != null) {
        for (index in 0 until rawRules.length()) {
            val rule = rawRules.getJSONObject(index)
            val outboundProtocol = outboundProtocolsByTag[rule.optString("outboundTag")]
            routingRules.add(
                AndroidDnsPreflightRoutingRule(
                    selectsFreedom = outboundProtocol.equals("freedom", ignoreCase = true),
                    appliesToTun = routingRuleAppliesToTun(rule, tunInboundTags),
                    hasDomainMatchers = hasArrayEntries(rule, "domain") ||
                        hasArrayEntries(rule, "domains"),
                    hasIpMatchers = hasArrayEntries(rule, "ip"),
                ),
            )
        }
    }
    return AndroidDnsPreflightTopology(
        fakeIpEnabled = fakeIpEnabled,
        hasDnsServers = hasDnsServers,
        defaultOutboundIsFreedom = defaultOutboundIsFreedom,
        routingRules = routingRules,
    )
}

private fun tunInboundTags(root: JSONObject): Set<String?> {
    val tags = linkedSetOf<String?>()
    val inbounds = root.optJSONArray("inbounds") ?: return tags
    for (index in 0 until inbounds.length()) {
        val inbound = inbounds.optJSONObject(index) ?: continue
        if (!inbound.optString("protocol").equals("tun", ignoreCase = true)) {
            continue
        }
        tags.add(inbound.optString("tag").takeIf(String::isNotEmpty))
    }
    return tags
}

private fun routingRuleAppliesToTun(rule: JSONObject, tunInboundTags: Set<String?>): Boolean {
    if (tunInboundTags.isEmpty()) {
        return false
    }
    if (!rule.has("inboundTag")) {
        return true
    }
    val inboundTags = rule.getJSONArray("inboundTag")
    if (inboundTags.length() == 0) {
        return true
    }
    for (index in 0 until inboundTags.length()) {
        if (tunInboundTags.contains(inboundTags.getString(index))) {
            return true
        }
    }
    return false
}

private fun hasArrayEntries(value: JSONObject, key: String): Boolean =
    value.has(key) && value.getJSONArray(key).length() > 0

internal data class CanonicalExactDnsHostMappings(
    val mappings: Map<String, AndroidDnsHostTarget>,
    val modified: Boolean,
)

internal sealed class AndroidDnsHostTarget {
    data class Alias(val domain: String) : AndroidDnsHostTarget()

    data class Addresses(val values: List<String>) : AndroidDnsHostTarget()
}

internal fun canonicalizeExactDnsHostMappings(
    entries: List<Pair<String, Any>>,
): CanonicalExactDnsHostMappings {
    val mappings = linkedMapOf<String, AndroidDnsHostTarget>()
    var modified = false
    for ((key, rawTarget) in entries) {
        val identity = requireNotNull(exactDnsHostIdentity(key)) {
            "DNS host mapping must be exact"
        }
        val canonicalKey = "$EXACT_DNS_HOST_PREFIX$identity"
        val target = canonicalAndroidDnsHostTarget(rawTarget)
        modified = modified || key != canonicalKey || !dnsHostTargetMatchesRaw(target, rawTarget)

        val existingTarget = mappings[canonicalKey]
        if (existingTarget != null) {
            require(existingTarget == target) {
                "conflicting exact DNS host mappings for `$identity`"
            }
            modified = true
        } else {
            mappings[canonicalKey] = target
        }
    }
    return CanonicalExactDnsHostMappings(mappings, modified)
}

private fun canonicalizeExactDnsHostMappingsFromJson(
    hosts: JSONObject,
): CanonicalExactDnsHostMappings {
    val entries = mutableListOf<Pair<String, Any>>()
    val keys = hosts.keys()
    while (keys.hasNext()) {
        val key = keys.next()
        if (exactDnsHostIdentity(key) != null) {
            entries.add(key to hosts.get(key))
        }
    }

    return canonicalizeExactDnsHostMappings(entries)
}

private fun canonicalAndroidDnsHostTarget(rawTarget: Any): AndroidDnsHostTarget =
    when (rawTarget) {
        is String -> canonicalIpAddress(rawTarget)?.let {
            AndroidDnsHostTarget.Addresses(listOf(it))
        } ?: AndroidDnsHostTarget.Alias(normalizeBootstrapDomain(rawTarget))
        is JSONArray -> {
            require(rawTarget.length() > 0) { "DNS host address array must not be empty" }
            val addresses = linkedSetOf<String>()
            for (index in 0 until rawTarget.length()) {
                val rawAddress = rawTarget.getString(index)
                val address = requireNotNull(canonicalIpAddress(rawAddress)) {
                    "DNS host address array must contain only IP literals"
                }
                addresses.add(address)
            }
            AndroidDnsHostTarget.Addresses(addresses.toList())
        }
        is List<*> -> {
            require(rawTarget.isNotEmpty()) { "DNS host address array must not be empty" }
            val addresses = linkedSetOf<String>()
            for (rawAddress in rawTarget) {
                require(rawAddress is String) {
                    "DNS host address array must contain only strings"
                }
                val address = requireNotNull(canonicalIpAddress(rawAddress)) {
                    "DNS host address array must contain only IP literals"
                }
                addresses.add(address)
            }
            AndroidDnsHostTarget.Addresses(addresses.toList())
        }
        else -> throw IllegalArgumentException("DNS host target must be a string or address array")
    }

private fun dnsHostTargetMatchesRaw(target: AndroidDnsHostTarget, rawTarget: Any): Boolean =
    when (target) {
        is AndroidDnsHostTarget.Alias -> rawTarget == target.domain
        is AndroidDnsHostTarget.Addresses -> {
            when (rawTarget) {
                is JSONArray ->
                    rawTarget.length() == target.values.size &&
                        target.values.indices.all { rawTarget.optString(it) == target.values[it] }
                is List<*> -> rawTarget == target.values
                else -> false
            }
        }
    }

private fun AndroidDnsHostTarget.toJsonValue(): Any = when (this) {
    is AndroidDnsHostTarget.Alias -> domain
    is AndroidDnsHostTarget.Addresses -> JSONArray(values)
}

private fun collectVlessBootstrapDomains(
    root: JSONObject,
    bootstrapDomains: MutableSet<String>,
) {
    val outbounds = root.optJSONArray("outbounds") ?: return
    for (outboundIndex in 0 until outbounds.length()) {
        val outbound = outbounds.optJSONObject(outboundIndex) ?: continue
        if (!outbound.optString("protocol").trim().equals("vless", ignoreCase = true)) {
            continue
        }
        val vnext = outbound.getJSONObject("settings").getJSONArray("vnext")
        for (serverIndex in 0 until vnext.length()) {
            val serverAddress = vnext.getJSONObject(serverIndex).getString("address")
            require(serverAddress.isNotEmpty()) { "VLESS bootstrap domain must not be empty" }
            if (!isIpLiteral(serverAddress)) {
                bootstrapDomains.add(serverAddress)
            }
        }
    }
}

internal fun dnsServerBootstrapDomain(server: Any): String? =
    dnsServerBootstrapUpstreamDomain(server)?.domain

internal fun dnsServerBootstrapUpstreamDomain(server: Any): AndroidDnsBootstrapDomain? =
    when (server) {
        is String -> dnsServerBootstrapDomainFromString(server)
        is JSONObject -> dnsServerBootstrapDomainFromObject(server)
        is Map<*, *> -> dnsServerBootstrapDomainFromObjectFields(
            server.entries.associate { (key, value) ->
                require(key is String) { "DNS server object fields must have string names" }
                key to value
            },
        )
        else -> throw IllegalArgumentException("DNS server must be a string or an object")
    }

private fun dnsServerBootstrapDomainFromString(server: String): AndroidDnsBootstrapDomain? {
    if (hasDnsTcpUrlScheme(server)) {
        return dnsServerBootstrapDomainFromTcpUrl(server)
    }
    require(server == server.trim()) {
        "DNS server must not contain surrounding whitespace"
    }
    require(server.isNotEmpty()) { "DNS server must not be empty" }
    if (isIpLiteral(server)) {
        validateDirectDnsUpstreamAddress(server, 53)
        return null
    }
    parseNumericDnsSocketAddress(server)?.let { socketAddress ->
        validateDirectDnsUpstreamAddress(socketAddress.address, socketAddress.port)
        return null
    }

    val separator = server.lastIndexOf(':')
    val (domain, port) = if (separator > 0 && server.indexOf(':') == separator) {
        val port = server.substring(separator + 1).toIntOrNull()
        require(port != null && port in 1..65_535) { "invalid DNS server port" }
        server.substring(0, separator) to port
    } else {
        server to 53
    }
    return AndroidDnsBootstrapDomain(normalizeBootstrapDomain(domain), port)
}

private fun dnsServerBootstrapDomainFromObject(server: JSONObject): AndroidDnsBootstrapDomain? {
    val fields = linkedMapOf<String, Any?>()
    val keys = server.keys()
    while (keys.hasNext()) {
        val key = keys.next()
        fields[key] = server.opt(key)
    }
    return dnsServerBootstrapDomainFromObjectFields(fields)
}

private fun dnsServerBootstrapDomainFromObjectFields(
    server: Map<String, Any?>,
): AndroidDnsBootstrapDomain? {
    // Android has no standalone FFI config-validation entry point before Builder.establish().
    // Keep this preflight limited to the object shape needed for safe bootstrap; Rust remains
    // authoritative for matcher syntax, geodata expansion, and matcher budgets.
    for (key in server.keys) {
        require(key in DNS_SERVER_OBJECT_FIELDS) { "unsupported DNS server field `$key`" }
    }

    val address = server["address"]
    require(address is String && address.isNotEmpty()) {
        "object DNS server address must be a non-empty string"
    }
    require(address == address.trim()) {
        "object DNS server address must not contain surrounding whitespace"
    }
    validateDnsServerObjectDomains(server)
    validateDnsServerStringList(server, "expectedIPs")
    validateDnsServerStringList(server, "expectIPs")
    validateDnsServerStringList(server, "unexpectedIPs")
    validateDnsServerTag(server)
    validateDnsServerTimeout(server)
    validateOptionalDnsServerBoolean(server, "skipFallback")
    validateOptionalDnsServerBoolean(server, "finalQuery")
    validateDnsServerObjectQueryStrategy(server)
    val port = if ("port" in server) {
        val rawPort = server["port"]
        val parsedPort = when (rawPort) {
            is Byte -> rawPort.toLong()
            is Short -> rawPort.toLong()
            is Int -> rawPort.toLong()
            is Long -> rawPort
            else -> null
        }
        require(parsedPort != null && parsedPort in 0..65_535) {
            "object DNS server port must be an integer from 0 through 65535"
        }
        // Match Xray: an explicit zero is valid and selects classic DNS port 53.
        if (parsedPort == 0L) 53 else parsedPort.toInt()
    } else {
        53
    }
    if (hasDnsTcpUrlScheme(address)) {
        // Xray validates the sibling object `port` as uint16, but takes the
        // TCP endpoint entirely from the URL and preserves both.
        return dnsServerBootstrapDomainFromTcpUrl(address)
    }

    if (isIpLiteral(address)) {
        validateDirectDnsUpstreamAddress(address, port)
        return null
    }
    require(
        !address.equals("localhost", ignoreCase = true) &&
            !address.equals("fakedns", ignoreCase = true),
    ) {
        "special DNS server `$address` is not supported yet"
    }
    require(':' !in address) {
        "object DNS server address must not include a port or unsupported URL scheme"
    }
    return AndroidDnsBootstrapDomain(normalizeBootstrapDomain(address), port)
}

private fun hasDnsTcpUrlScheme(server: String): Boolean {
    val separator = server.indexOf(':')
    if (separator <= 0) {
        return false
    }
    val scheme = server.substring(0, separator)
    return scheme.equals("tcp", ignoreCase = true) ||
        scheme.equals("tcp+local", ignoreCase = true) ||
        scheme.equals("tls", ignoreCase = true) ||
        scheme.equals("https", ignoreCase = true) ||
        scheme.equals("https+local", ignoreCase = true) ||
        scheme.equals("quic+local", ignoreCase = true)
}

private fun dnsServerBootstrapDomainFromTcpUrl(server: String): AndroidDnsBootstrapDomain? {
    require(server.none(::isForbiddenDnsTcpUrlCharacter)) {
        "DNS TCP server URL must not contain whitespace or control characters"
    }
    val schemeSeparator = server.indexOf(':')
    require(schemeSeparator > 0 && hasDnsTcpUrlScheme(server)) {
        "unsupported DNS TCP server URL scheme"
    }
    val scheme = server.substring(0, schemeSeparator)
    val isHttps = scheme.equals("https", ignoreCase = true) ||
        scheme.equals("https+local", ignoreCase = true)
    val defaultPort = when {
        isHttps -> 443
        scheme.equals("tls", ignoreCase = true) ||
            scheme.equals("quic+local", ignoreCase = true) -> 853
        else -> 53
    }
    require(server.regionMatches(schemeSeparator + 1, "//", 0, 2)) {
        "DNS TCP server URL must use an authority"
    }
    val remainder = server.substring(schemeSeparator + 3)
    val authorityEnd = if (isHttps) {
        listOf(remainder.indexOf('/'), remainder.indexOf('?'))
            .filter { it >= 0 }
            .minOrNull() ?: remainder.length
    } else {
        remainder.length
    }
    val authority = remainder.substring(0, authorityEnd)
    val pathAndQuery = remainder.substring(authorityEnd)
    require(authority.isNotEmpty() && authority.none { it in "@\\%" }) {
        "DNS stream server URL must contain an authority host and optional port"
    }
    if (isHttps) {
        require('#' !in remainder) { "DNS HTTPS server URL must not contain a fragment" }
        require(
            pathAndQuery.isEmpty() ||
                pathAndQuery.startsWith('/') ||
                pathAndQuery.startsWith('?'),
        ) { "DNS HTTPS server URL contains an invalid path or query" }
        require(pathAndQuery.all { it.code <= 0x7f } && '\\' !in pathAndQuery) {
            "DNS HTTPS server URL contains an invalid path or query"
        }
    } else {
        require(pathAndQuery.isEmpty() && authority.none { it in "/?#" }) {
            "DNS TCP server URL must contain only an authority host and optional port"
        }
    }

    val host: String
    val port: Int
    if (authority.startsWith('[')) {
        val closingBracket = authority.indexOf(']')
        require(
            closingBracket > 1 &&
                authority.indexOf(']', closingBracket + 1) == -1,
        ) {
            "DNS TCP server URL contains malformed IPv6 brackets"
        }
        host = authority.substring(1, closingBracket)
        require(':' in host && isIpLiteral(host)) {
            "DNS TCP server URL brackets require an IPv6 literal"
        }
        val remainder = authority.substring(closingBracket + 1)
        port = if (remainder.isEmpty()) {
            defaultPort
        } else {
            require(remainder.startsWith(':')) {
                "DNS TCP server URL contains data after its host"
            }
            parseDnsTcpUrlPort(remainder.substring(1))
        }
    } else {
        require('[' !in authority && ']' !in authority) {
            "DNS TCP server URL contains malformed host brackets"
        }
        require(authority.count { it == ':' } <= 1) {
            "DNS TCP server URL requires brackets around IPv6 literals"
        }
        val portSeparator = authority.indexOf(':')
        if (portSeparator >= 0) {
            host = authority.substring(0, portSeparator)
            port = parseDnsTcpUrlPort(authority.substring(portSeparator + 1))
        } else {
            host = authority
            port = defaultPort
        }
        require(host.isNotEmpty()) { "DNS TCP server URL host must not be empty" }
    }

    if (isIpLiteral(host)) {
        validateDnsTcpUrlUpstreamAddress(host)
        return null
    }
    require(':' !in host) { "DNS TCP server URL contains an invalid host" }
    return AndroidDnsBootstrapDomain(
        domain = normalizeBootstrapDomain(host),
        port = port,
        rejectsTunnelOwnedAddress = true,
    )
}

private fun isForbiddenDnsTcpUrlCharacter(character: Char): Boolean =
    character.isISOControl() ||
        character.isWhitespace() ||
        Character.isSpaceChar(character)

private fun parseDnsTcpUrlPort(rawPort: String): Int {
    require(rawPort.isNotEmpty() && rawPort.all { it in '0'..'9' }) {
        "DNS TCP server URL port must be an integer from 1 through 65535"
    }
    val port = rawPort.toIntOrNull()
    require(port != null && port in 1..65_535) {
        "DNS TCP server URL port must be an integer from 1 through 65535"
    }
    return port
}

private fun validateDnsTcpUrlUpstreamAddress(address: String) {
    val canonicalAddress = requireNotNull(canonicalIpAddress(address)) {
        "DNS TCP server URL contains an invalid IP address"
    }
    require(canonicalAddress !in XRAY_TUN_OWNED_ADDRESSES) {
        "DNS TCP server URL cannot point at a tunnel-local DNS address"
    }
}

private fun validateDnsServerObjectDomains(server: Map<String, Any?>) {
    if ("domains" !in server) {
        return
    }
    val domains = server["domains"]
    when (domains) {
        is String -> require(domains.split(',').all(String::isNotEmpty)) {
            "DNS server domain matcher cannot be empty"
        }
        is JSONArray -> {
            for (index in 0 until domains.length()) {
                val domain = domains.get(index)
                require(domain is String && domain.isNotEmpty()) {
                    "DNS server domain matcher must be a non-empty string"
                }
            }
        }
        is List<*> -> require(domains.all { it is String && it.isNotEmpty() }) {
            "DNS server domain matcher must be a non-empty string"
        }
        else -> throw IllegalArgumentException("DNS server domains must be a string or an array")
    }
}

private fun validateDnsServerStringList(server: Map<String, Any?>, key: String) {
    if (key !in server) {
        return
    }
    when (val value = server[key]) {
        null, JSONObject.NULL -> Unit
        is String -> Unit
        is JSONArray -> {
            for (index in 0 until value.length()) {
                require(value.get(index) is String) {
                    "DNS server `$key` item at index $index must be a string"
                }
            }
        }
        is List<*> -> value.forEachIndexed { index, item ->
            require(item is String) {
                "DNS server `$key` item at index $index must be a string"
            }
        }
        else -> throw IllegalArgumentException(
            "DNS server `$key` must be a string or an array",
        )
    }
}

private fun validateDnsServerTimeout(server: Map<String, Any?>) {
    if ("timeoutMs" !in server) {
        return
    }
    val timeoutMs = when (val value = server["timeoutMs"]) {
        null, JSONObject.NULL -> 0L
        is Byte -> value.toLong()
        is Short -> value.toLong()
        is Int -> value.toLong()
        is Long -> value
        else -> null
    }
    require(timeoutMs != null && timeoutMs in 0..MAX_DNS_SERVER_TIMEOUT_MS) {
        "DNS server `timeoutMs` must be an integer from 0 through $MAX_DNS_SERVER_TIMEOUT_MS"
    }
}

private fun validateDnsServerTag(server: Map<String, Any?>) {
    if ("tag" !in server) {
        return
    }
    val value = server["tag"]
    require(value == null || value === JSONObject.NULL || value is String) {
        "DNS server `tag` must be a string or null"
    }
}

private fun validateOptionalDnsServerBoolean(server: Map<String, Any?>, key: String) {
    if (key in server) {
        require(server[key] is Boolean) { "DNS server `$key` must be a boolean" }
    }
}

private fun validateDnsServerObjectQueryStrategy(server: Map<String, Any?>) {
    if ("queryStrategy" !in server) {
        return
    }
    val strategy = server["queryStrategy"]
    require(strategy is String && strategy.lowercase(Locale.ROOT) in DNS_QUERY_STRATEGIES) {
        "unsupported DNS server queryStrategy"
    }
}

internal fun isIpv4FakeIpDnsQueryStrategyCompatible(
    fakeIpEnabled: Boolean,
    rawStrategy: Any?,
): Boolean = !fakeIpEnabled ||
    (rawStrategy as? String)?.lowercase(Locale.ROOT) !in DNS_IPV6_ONLY_QUERY_STRATEGIES

internal fun optionalStrictJsonBoolean(
    rawValue: Any?,
    isPresent: Boolean,
    field: String,
): Boolean {
    if (!isPresent) {
        return false
    }
    require(rawValue is Boolean) { "$field must be a JSON boolean" }
    return rawValue
}

private fun validateAndroidDnsCachePolicy(dns: JSONObject?) {
    if (dns == null) {
        return
    }
    val disableCache = optionalStrictJsonBoolean(
        rawValue = dns.opt("disableCache"),
        isPresent = dns.has("disableCache"),
        field = "dns.disableCache",
    )
    val serveStale = optionalStrictJsonBoolean(
        rawValue = dns.opt("serveStale"),
        isPresent = dns.has("serveStale"),
        field = "dns.serveStale",
    )
    val serveExpiredTtl = if (dns.has("serveExpiredTTL")) {
        when (val value = dns.opt("serveExpiredTTL")) {
            is Byte -> value.toLong()
            is Short -> value.toLong()
            is Int -> value.toLong()
            is Long -> value
            else -> null
        }
    } else {
        0L
    }
    require(
        serveExpiredTtl != null && serveExpiredTtl in 0..MAX_DNS_SERVE_EXPIRED_TTL_SECONDS,
    ) {
        "dns.serveExpiredTTL must be an integer from 0 through $MAX_DNS_SERVE_EXPIRED_TTL_SECONDS"
    }
    require(!serveStale || !disableCache) {
        "dns.serveStale requires dns.disableCache to be false"
    }
    require(!serveStale || serveExpiredTtl > 0) {
        "dns.serveStale requires an explicit nonzero bounded dns.serveExpiredTTL"
    }
}

internal fun validateAndroidDnsServerCount(serverCount: Int) {
    require(serverCount in 0..MAX_DNS_SERVERS) {
        "DNS config contains $serverCount servers; maximum supported is $MAX_DNS_SERVERS"
    }
}

internal fun validateDnsServerQueryStrategyCompatibility(
    globalStrategy: Any?,
    serverStrategy: Any?,
) {
    val globalFamilies = dnsQueryStrategyFamilies(globalStrategy, "global DNS")
    val serverFamilies = dnsQueryStrategyFamilies(serverStrategy, "DNS server")
    require(globalFamilies and serverFamilies != 0) {
        "DNS server queryStrategy has no address family in common with global dns.queryStrategy"
    }
}

private fun dnsQueryStrategyFamilies(rawStrategy: Any?, owner: String): Int {
    if (rawStrategy == null) {
        return DNS_FAMILY_IPV4 or DNS_FAMILY_IPV6
    }
    require(rawStrategy is String) { "$owner queryStrategy must be a string" }
    return when (rawStrategy.lowercase(Locale.ROOT)) {
        in DNS_USE_IP_QUERY_STRATEGIES -> DNS_FAMILY_IPV4 or DNS_FAMILY_IPV6
        in DNS_IPV4_ONLY_QUERY_STRATEGIES -> DNS_FAMILY_IPV4
        in DNS_IPV6_ONLY_QUERY_STRATEGIES -> DNS_FAMILY_IPV6
        else -> throw IllegalArgumentException("unsupported $owner queryStrategy")
    }
}

private data class NumericDnsSocketAddress(
    val address: String,
    val port: Int,
)

private fun parseNumericDnsSocketAddress(server: String): NumericDnsSocketAddress? {
    if (server.startsWith('[')) {
        val closingBracket = server.lastIndexOf("]:")
        if (closingBracket <= 1) {
            return null
        }
        val port = server.substring(closingBracket + 2).toIntOrNull()
        val address = server.substring(1, closingBracket)
        return if (port != null &&
            port in 1..65_535 &&
            isIpLiteral(value = address, allowNumericIpv6Scope = true)
        ) {
            NumericDnsSocketAddress(address, port)
        } else {
            null
        }
    }

    val separator = server.indexOf(':')
    if (separator <= 0 || separator != server.lastIndexOf(':')) {
        return null
    }
    val port = server.substring(separator + 1).toIntOrNull()
    val address = server.substring(0, separator)
    return if (port != null && port in 1..65_535 && isIpv4Literal(address)) {
        NumericDnsSocketAddress(address, port)
    } else {
        null
    }
}

private fun validateDirectDnsUpstreamAddress(address: String, port: Int) {
    if (port != 53) {
        return
    }
    val canonicalAddress = canonicalIpAddress(address)
    require(canonicalAddress !in XRAY_TUN_OWNED_ADDRESSES) {
        "DNS server cannot point at a tunnel-local DNS address"
    }
}

internal fun ensureBootstrapHostMapping(
    domain: String,
    exactMappings: MutableMap<String, AndroidDnsHostTarget>,
    resolvedAddresses: MutableMap<String, List<String>>,
    activeAliases: MutableSet<String>,
    depth: Int,
    dnsUpstreamPort: Int? = null,
    rejectsTunnelOwnedAddress: Boolean = false,
    resolveSystemBootstrapAddresses: (String) -> List<String>,
): Boolean {
    require(depth < MAX_BOOTSTRAP_ALIAS_DEPTH) {
        "DNS bootstrap alias chain exceeds $MAX_BOOTSTRAP_ALIAS_DEPTH entries"
    }
    val identity = normalizeBootstrapDomain(domain)
    require(activeAliases.add(identity)) { "DNS bootstrap alias cycle at `$domain`" }
    try {
        val existingKey = "$EXACT_DNS_HOST_PREFIX$identity"
        exactMappings[existingKey]?.let { target ->
            return when (target) {
                is AndroidDnsHostTarget.Addresses -> {
                    validateDnsUpstreamBootstrapAddresses(
                        target.values,
                        dnsUpstreamPort,
                        rejectsTunnelOwnedAddress,
                    )
                    false
                }
                is AndroidDnsHostTarget.Alias -> ensureBootstrapHostMapping(
                    domain = target.domain,
                    exactMappings = exactMappings,
                    resolvedAddresses = resolvedAddresses,
                    activeAliases = activeAliases,
                    depth = depth + 1,
                    dnsUpstreamPort = dnsUpstreamPort,
                    rejectsTunnelOwnedAddress = rejectsTunnelOwnedAddress,
                    resolveSystemBootstrapAddresses = resolveSystemBootstrapAddresses,
                )
            }
        }

        val addresses = resolvedAddresses.getOrPut(identity) {
            canonicalBootstrapAddresses(resolveSystemBootstrapAddresses(identity))
        }
        require(addresses.isNotEmpty()) {
            "bootstrap domain `$domain` resolved without a usable address"
        }
        validateDnsUpstreamBootstrapAddresses(
            addresses,
            dnsUpstreamPort,
            rejectsTunnelOwnedAddress,
        )
        exactMappings[existingKey] = AndroidDnsHostTarget.Addresses(addresses)
        return true
    } finally {
        activeAliases.remove(identity)
    }
}

private fun validateDnsUpstreamBootstrapAddresses(
    addresses: List<String>,
    port: Int?,
    rejectsTunnelOwnedAddress: Boolean,
) {
    if (!rejectsTunnelOwnedAddress && port != 53) {
        return
    }
    require(addresses.none { it in XRAY_TUN_OWNED_ADDRESSES }) {
        "DNS server resolves to a tunnel-local DNS address"
    }
}

private fun exactDnsHostIdentity(key: String): String? {
    val domain = when {
        key.startsWith(EXACT_DNS_HOST_PREFIX) -> key.substring(EXACT_DNS_HOST_PREFIX.length)
        ':' !in key -> key
        else -> return null
    }
    return normalizeBootstrapDomain(domain)
}

private fun lookupSystemBootstrapAddresses(domain: String): List<String> {
    val resolved = try {
        InetAddress.getAllByName(domain)
    } catch (error: Exception) {
        throw IllegalArgumentException(
            "failed to resolve bootstrap domain `$domain` before establishing the VPN tunnel",
            error,
        )
    }
    val addresses = linkedSetOf<String>()
    for (address in resolved) {
        if (address is Inet6Address && address.scopeId != 0) {
            continue
        }
        val hostAddress = address.hostAddress ?: continue
        canonicalIpAddress(hostAddress)?.let(addresses::add)
    }
    require(addresses.isNotEmpty()) {
        "bootstrap domain `$domain` resolved without a usable address"
    }
    return addresses.toList()
}

private fun canonicalIpAddress(value: String): String? {
    if (!isIpLiteral(value)) {
        return null
    }
    return runCatching { InetAddress.getByName(value).hostAddress }.getOrNull()
}

internal fun canonicalBootstrapAddresses(rawAddresses: List<String>): List<String> {
    require(rawAddresses.isNotEmpty()) { "DNS bootstrap address list must not be empty" }
    val addresses = linkedSetOf<String>()
    for (rawAddress in rawAddresses) {
        val address = requireNotNull(canonicalIpAddress(rawAddress)) {
            "DNS bootstrap address list must contain only IP literals"
        }
        addresses.add(address)
    }
    return addresses.toList()
}

internal fun normalizeBootstrapDomain(domain: String): String {
    val normalized = domain.trimEnd('.').lowercase(Locale.ROOT)
    require(normalized.isNotEmpty()) { "DNS bootstrap domain must not be empty" }
    return normalized
}

private fun isIpLiteral(
    value: String,
    allowNumericIpv6Scope: Boolean = false,
): Boolean {
    if (isIpv4Literal(value)) {
        return true
    }
    val scopeSeparator = value.lastIndexOf('%')
    val address = if (scopeSeparator >= 0) {
        val scope = value.substring(scopeSeparator + 1)
        if (!allowNumericIpv6Scope ||
            scope.isEmpty() ||
            !scope.all { it.isDigit() } ||
            scope.toUIntOrNull() == null
        ) {
            return false
        }
        value.substring(0, scopeSeparator)
    } else {
        value
    }
    if (address.count { it == ':' } < 2) {
        return false
    }
    return runCatching { InetAddress.getByName(address) }.isSuccess
}

private fun isIpv4Literal(value: String): Boolean {
    val components = value.split('.')
    if (components.size != 4) {
        return false
    }
    return components.all { component ->
        component.isNotEmpty() &&
            (component == "0" || !component.startsWith('0')) &&
            component.all { it.isDigit() } &&
            component.toIntOrNull()?.let { it in 0..255 } == true
    }
}

private const val MAX_BOOTSTRAP_ALIAS_DEPTH = 8
private const val MAX_BLOCKED_DNS_LOOKUP_THREADS = 2
private const val DNS_LOOKUP_THREAD_KEEP_ALIVE_SECONDS = 30L
private const val EXACT_DNS_HOST_PREFIX = "full:"
internal const val XRAY_TUN_DNS_ANCHOR = "198.18.0.1"
private const val MAX_DNS_SERVERS = 8
private const val DNS_FAMILY_IPV4 = 1
private const val DNS_FAMILY_IPV6 = 2

private val XRAY_TUN_OWNED_ADDRESSES = listOf(
    XRAY_TUN_DNS_ANCHOR,
    "198.18.0.2",
    "10.7.0.1",
    "fd00:7872::1",
).mapTo(linkedSetOf()) { address ->
    requireNotNull(canonicalIpAddress(address))
}

private val DNS_SERVER_OBJECT_FIELDS = setOf(
    "address",
    "port",
    "domains",
    "expectedIPs",
    "expectIPs",
    "unexpectedIPs",
    "tag",
    "timeoutMs",
    "skipFallback",
    "queryStrategy",
    "finalQuery",
)

private const val MAX_DNS_SERVER_TIMEOUT_MS = 4_611_686_018_427L
private const val MAX_DNS_SERVE_EXPIRED_TTL_SECONDS = 86_400L

private val DNS_QUERY_STRATEGIES = setOf(
    "useip",
    "use_ip",
    "use-ip",
    "useip4",
    "useipv4",
    "use_ip4",
    "use_ipv4",
    "use_ip_v4",
    "use-ip4",
    "use-ipv4",
    "use-ip-v4",
    "useip6",
    "useipv6",
    "use_ip6",
    "use_ipv6",
    "use_ip_v6",
    "use-ip6",
    "use-ipv6",
    "use-ip-v6",
)

private val DNS_USE_IP_QUERY_STRATEGIES = setOf(
    "useip",
    "use_ip",
    "use-ip",
)

private val DNS_IPV4_ONLY_QUERY_STRATEGIES = setOf(
    "useip4",
    "useipv4",
    "use_ip4",
    "use_ipv4",
    "use_ip_v4",
    "use-ip4",
    "use-ipv4",
    "use-ip-v4",
)

private val DNS_IPV6_ONLY_QUERY_STRATEGIES = setOf(
    "useip6",
    "useipv6",
    "use_ip6",
    "use_ipv6",
    "use_ip_v6",
    "use-ip6",
    "use-ipv6",
    "use-ip-v6",
)
