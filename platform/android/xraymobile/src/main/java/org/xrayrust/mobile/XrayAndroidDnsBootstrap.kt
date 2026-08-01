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
import org.json.JSONObject

internal data class PreparedAndroidVpnConfig(
    val json: String,
    val usesLocalDnsAnchor: Boolean,
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
    private val lookup: (String) -> String = ::lookupSystemBootstrapAddress,
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

    fun resolve(domain: String, timeoutNanos: Long): String {
        if (timeoutNanos <= 0) {
            throw AndroidDnsBootstrapTimeoutException(
                "DNS bootstrap deadline elapsed before resolving `$domain`",
            )
        }
        val future = try {
            executor.submit<String> { lookup(domain) }
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
    val usesFakeIp = if (dns?.has("fakeIp") == true) {
        dns.getJSONObject("fakeIp").optBoolean("enabled", false)
    } else {
        false
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

    val bootstrapDomains = linkedSetOf<String>()
    collectVlessBootstrapDomains(root, bootstrapDomains)
    if (dnsServers != null) {
        for (index in 0 until dnsServers.length()) {
            dnsServerBootstrapDomain(dnsServers.getString(index))?.let(bootstrapDomains::add)
        }
    }
    val preparedDns = dns ?: JSONObject()
    val hosts = if (preparedDns.has("hosts")) {
        preparedDns.getJSONObject("hosts")
    } else {
        JSONObject()
    }
    val resolvedAddresses = mutableMapOf<String, String>()
    var modified = canonicalizeExactDnsHostMappingKeys(hosts)
    val resolveSystemBootstrapAddress: (String) -> String = { domain ->
        resolveAndroidDnsBootstrapAddressWithinDeadline(domain, resolver, deadline)
    }
    for (domain in bootstrapDomains) {
        modified = ensureBootstrapHostMapping(
            domain = domain,
            hosts = hosts,
            resolvedAddresses = resolvedAddresses,
            activeAliases = mutableSetOf(),
            depth = 0,
            resolveSystemBootstrapAddress = resolveSystemBootstrapAddress,
        ) || modified
    }

    if (!modified) {
        return PreparedAndroidVpnConfig(configJson, usesLocalDnsAnchor)
    }
    if (!preparedDns.has("hosts")) {
        preparedDns.put("hosts", hosts)
    }
    if (!root.has("dns")) {
        root.put("dns", preparedDns)
    }
    return PreparedAndroidVpnConfig(root.toString(), usesLocalDnsAnchor)
}

internal fun resolveAndroidDnsBootstrapAddressWithinDeadline(
    domain: String,
    resolver: BoundedAndroidDnsBootstrapResolver,
    deadline: AndroidDnsBootstrapDeadline,
): String {
    val address = resolver.resolve(domain, deadline.remainingNanos())
    deadline.remainingNanos()
    return address
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
    val mappings: Map<String, String>,
    val modified: Boolean,
)

internal fun canonicalizeExactDnsHostMappings(
    entries: List<Pair<String, String>>,
): CanonicalExactDnsHostMappings {
    val mappings = linkedMapOf<String, String>()
    var modified = false
    for ((key, target) in entries) {
        require(key.startsWith(EXACT_DNS_HOST_PREFIX)) { "DNS host mapping must be exact" }
        val identity = normalizeBootstrapDomain(key.substring(EXACT_DNS_HOST_PREFIX.length))
        val canonicalKey = "$EXACT_DNS_HOST_PREFIX$identity"
        modified = modified || key != canonicalKey

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

private fun canonicalizeExactDnsHostMappingKeys(hosts: JSONObject): Boolean {
    val entries = mutableListOf<Pair<String, String>>()
    val keys = hosts.keys()
    while (keys.hasNext()) {
        val key = keys.next()
        if (key.startsWith(EXACT_DNS_HOST_PREFIX)) {
            entries.add(key to hosts.getString(key))
        }
    }

    val canonical = canonicalizeExactDnsHostMappings(entries)
    if (!canonical.modified) {
        return false
    }
    for ((key, _) in entries) {
        hosts.remove(key)
    }
    for ((key, target) in canonical.mappings) {
        hosts.put(key, target)
    }
    return true
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

internal fun dnsServerBootstrapDomain(server: String): String? {
    require(server.isNotEmpty()) { "DNS server must not be empty" }
    if (isIpLiteral(server) || isNumericDnsSocketAddress(server)) {
        return null
    }

    val separator = server.lastIndexOf(':')
    val domain = if (separator > 0 && server.indexOf(':') == separator) {
        val port = server.substring(separator + 1).toIntOrNull()
        require(port != null && port in 1..65_535) { "invalid DNS server port" }
        server.substring(0, separator)
    } else {
        server
    }
    return normalizeBootstrapDomain(domain)
}

private fun isNumericDnsSocketAddress(server: String): Boolean {
    if (server.startsWith('[')) {
        val closingBracket = server.lastIndexOf("]:")
        if (closingBracket <= 1) {
            return false
        }
        val port = server.substring(closingBracket + 2).toIntOrNull()
        return port != null &&
            port in 1..65_535 &&
            isIpLiteral(
                value = server.substring(1, closingBracket),
                allowNumericIpv6Scope = true,
            )
    }

    val separator = server.indexOf(':')
    if (separator <= 0 || separator != server.lastIndexOf(':')) {
        return false
    }
    val port = server.substring(separator + 1).toIntOrNull()
    return port != null &&
        port in 1..65_535 &&
        isIpv4Literal(server.substring(0, separator))
}

private fun ensureBootstrapHostMapping(
    domain: String,
    hosts: JSONObject,
    resolvedAddresses: MutableMap<String, String>,
    activeAliases: MutableSet<String>,
    depth: Int,
    resolveSystemBootstrapAddress: (String) -> String,
): Boolean {
    require(depth < MAX_BOOTSTRAP_ALIAS_DEPTH) {
        "DNS bootstrap alias chain exceeds $MAX_BOOTSTRAP_ALIAS_DEPTH entries"
    }
    val identity = normalizeBootstrapDomain(domain)
    require(activeAliases.add(identity)) { "DNS bootstrap alias cycle at `$domain`" }
    try {
        val existingKey = findExactDnsHostMappingKey(hosts, identity)
        if (existingKey != null) {
            val target = hosts.getString(existingKey)
            if (isIpLiteral(target)) {
                return false
            }
            return ensureBootstrapHostMapping(
                domain = normalizeBootstrapDomain(target),
                hosts = hosts,
                resolvedAddresses = resolvedAddresses,
                activeAliases = activeAliases,
                depth = depth + 1,
                resolveSystemBootstrapAddress = resolveSystemBootstrapAddress,
            )
        }

        val address = resolvedAddresses.getOrPut(identity) {
            resolveSystemBootstrapAddress(identity)
        }
        hosts.put("full:$identity", address)
        return true
    } finally {
        activeAliases.remove(identity)
    }
}

private fun findExactDnsHostMappingKey(hosts: JSONObject, domain: String): String? {
    val keys = hosts.keys()
    while (keys.hasNext()) {
        val key = keys.next()
        if (key.startsWith(EXACT_DNS_HOST_PREFIX) &&
            normalizeBootstrapDomain(key.substring(EXACT_DNS_HOST_PREFIX.length)) == domain
        ) {
            return key
        }
    }
    return null
}

private fun lookupSystemBootstrapAddress(domain: String): String {
    val address = try {
        InetAddress.getAllByName(domain).firstOrNull {
            it !is Inet6Address || it.scopeId == 0
        }
    } catch (error: Exception) {
        throw IllegalArgumentException(
            "failed to resolve bootstrap domain `$domain` before establishing the VPN tunnel",
            error,
        )
    }
    return requireNotNull(address?.hostAddress) {
        "bootstrap domain `$domain` resolved without a usable address"
    }
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
