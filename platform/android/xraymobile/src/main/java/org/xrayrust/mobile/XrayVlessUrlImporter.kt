package org.xrayrust.mobile

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.net.URI
import java.net.URISyntaxException
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.UUID

enum class XrayVlessUrlImportErrorCode {
    InvalidUrl,
    UnsupportedScheme,
    MissingUserId,
    InvalidUserId,
    MissingHost,
    MissingPort,
    MissingQueryValue,
    DuplicateQueryValue,
    UnsupportedQueryParameter,
    UnsupportedQueryValue,
    InvalidXhttpExtra,
    XhttpExtraTooLarge,
}

class XrayVlessUrlImportException internal constructor(
    val code: XrayVlessUrlImportErrorCode,
    val parameter: String? = null,
    val rejectedValue: String? = null,
    val expected: String? = null,
    message: String,
) : IllegalArgumentException(message)

data class XrayImportedProfile(
    val name: String,
    val serverAddress: String,
    val configJson: String,
)

/**
 * Imports the same fail-closed VLESS share-link subset as the Apple adapter.
 *
 * Supported transports are raw/TCP with REALITY and XHTTP/SplitHTTP with
 * none, TLS, or REALITY security. The result is a self-contained TUN profile;
 * persistence, UI, and Android VPN consent remain host responsibilities.
 */
object XrayVlessUrlImporter {
    private const val VISION_FLOW = "xtls-rprx-vision"
    private const val VISION_UDP_443_FLOW = "xtls-rprx-vision-udp443"
    private const val MAX_XHTTP_EXTRA_BYTES = 64 * 1024
    private val networkAliases = setOf("tcp", "raw")
    private val xhttpNetworkAliases = setOf("xhttp", "splithttp")
    private val criticalQueryNames = listOf(
        "type",
        "encryption",
        "security",
        "flow",
        "host",
        "path",
        "mode",
        "sni",
        "fp",
        "alpn",
        "allowInsecure",
        "pbk",
        "sid",
        "spx",
        "pqv",
        "extra",
        "pcs",
        "vcn",
        "ech",
        "echQuery",
    )
    private val schemePattern = Regex("vless://", RegexOption.IGNORE_CASE)
    private val authorityPattern = Regex(
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" +
            "[0-9a-fA-F]{4}-[0-9a-fA-F]{12}@",
    )

    fun profile(rawUrl: String): XrayImportedProfile {
        val endpoint = parseEndpoint(rawUrl)
        return XrayImportedProfile(
            name = endpoint.profileName,
            serverAddress = endpoint.host,
            configJson = endpoint.mobileConfigJson(),
        )
    }

    private fun parseEndpoint(rawUrl: String): Endpoint {
        val normalized = normalizeVlessUrl(rawUrl)
        val uri = try {
            URI(normalized)
        } catch (_: URISyntaxException) {
            throw importError(XrayVlessUrlImportErrorCode.InvalidUrl, "Invalid VLESS URL.")
        }
        val scheme = uri.scheme
        if (!scheme.equals("vless", ignoreCase = true)) {
            throw importError(
                XrayVlessUrlImportErrorCode.UnsupportedScheme,
                "Unsupported URL scheme `${scheme ?: "none"}`. Expected `vless`.",
                rejectedValue = scheme,
                expected = "vless",
            )
        }

        val rawUserId = uri.rawUserInfo?.substringBefore(':')
        if (rawUserId.isNullOrEmpty()) {
            throw importError(
                XrayVlessUrlImportErrorCode.MissingUserId,
                "VLESS URL is missing a user id.",
            )
        }
        val userId = decodeComponent(rawUserId)
        val parsedUserId = runCatching { UUID.fromString(userId) }.getOrNull()
        if (parsedUserId == null || !parsedUserId.toString().equals(userId, ignoreCase = true)) {
            throw importError(
                XrayVlessUrlImportErrorCode.InvalidUserId,
                "Invalid VLESS user id `$userId`.",
                rejectedValue = userId,
            )
        }

        val host = uri.host?.removeSurrounding("[", "]")
        if (host.isNullOrEmpty()) {
            throw importError(
                XrayVlessUrlImportErrorCode.MissingHost,
                "VLESS URL is missing a host.",
            )
        }
        val port = uri.port
        if (port !in 1..65535) {
            throw importError(
                XrayVlessUrlImportErrorCode.MissingPort,
                "VLESS URL is missing a port.",
            )
        }

        val query = QueryValues.parse(uri.rawQuery)
        query.rejectDuplicates(criticalQueryNames)
        val network = query.optional("type", "tcp")
        val encryption = query.optional("encryption", "none")
        requireValue(encryption, "encryption", listOf("none"))
        val security = query.optional("security", "none")
        val flow = query.optional("flow", "")

        val transport = when {
            network in networkAliases -> {
                requireValue(security, "security", listOf("reality"))
                if (flow.isNotEmpty()) {
                    requireValue(flow, "flow", listOf(VISION_FLOW, VISION_UDP_443_FLOW))
                }
                Transport.RawReality(rawRealityParameters(query, flow.ifEmpty { null }))
            }

            network in xhttpNetworkAliases -> {
                if (flow.isNotEmpty()) {
                    throw unsupportedValue("flow", flow, "empty")
                }
                val mode = query.optional("mode", "auto").ifEmpty { "auto" }
                requireValue(mode, "mode", listOf("auto", "packet-up", "stream-up", "stream-one"))
                val extra = query.value("extra")?.let(::decodeXhttpExtra)
                rejectUnsupportedSecurityValues(query)
                val xhttpSecurity = when (security) {
                    "none" -> XhttpSecurity.None
                    "tls" -> {
                        rejectRealityOnlyValues(query)
                        XhttpSecurity.Tls(tlsParameters(query, host))
                    }

                    "reality" -> {
                        validateRealityCompatibilityValues(query)
                        XhttpSecurity.Reality(xhttpRealityParameters(query, host))
                    }

                    else -> throw unsupportedValue("security", security, "none or tls or reality")
                }
                Transport.Xhttp(
                    XhttpParameters(
                        host = query.optional("host", ""),
                        path = query.optional("path", ""),
                        mode = mode,
                        extra = extra,
                        security = xhttpSecurity,
                    ),
                )
            }

            else -> throw unsupportedValue(
                "type",
                network,
                (networkAliases + xhttpNetworkAliases).joinToString(" or "),
            )
        }

        val profileName = uri.rawFragment
            ?.takeIf(String::isNotEmpty)
            ?.let(::decodeComponent)
            ?: "$host:$port"
        return Endpoint(userId, host, port, encryption, transport, profileName)
    }

    private fun tlsParameters(query: QueryValues, defaultServerName: String): TlsParameters {
        val serverName = query.value("sni")?.also { requireNonEmpty(it, "sni") }
            ?: defaultServerName
        val fingerprint = query.value("fp")?.also { requireNonEmpty(it, "fp") }
            ?: "chrome"
        val alpn = query.value("alpn")?.let { raw ->
            val values = raw.split(',', ignoreCase = false, limit = 0)
            if (raw.isEmpty() || raw.any(Char::isWhitespace) || values.any(String::isEmpty)) {
                throw unsupportedValue(
                    "alpn",
                    raw,
                    "comma-separated values without spaces or empty entries",
                )
            }
            values
        }
        val allowInsecure = query.value("allowInsecure")?.let { raw ->
            when (raw.lowercase(Locale.ROOT)) {
                "0", "false" -> false
                "1", "true" -> true
                else -> throw unsupportedValue(
                    "allowInsecure",
                    raw,
                    "0 or 1 or false or true",
                )
            }
        }
        return TlsParameters(serverName, fingerprint, alpn, allowInsecure)
    }

    private fun rawRealityParameters(query: QueryValues, flow: String?): RealityParameters {
        val pqv = query.optional("pqv", "").ifEmpty { null }
        return RealityParameters(
            publicKey = query.required("pbk"),
            fingerprint = query.required("fp"),
            serverName = query.required("sni"),
            shortId = query.required("sid"),
            spiderX = query.optional("spx", ""),
            mldsa65Verify = pqv,
            flow = flow,
        )
    }

    private fun xhttpRealityParameters(
        query: QueryValues,
        defaultServerName: String,
    ): RealityParameters {
        val serverName = query.value("sni")?.also { requireNonEmpty(it, "sni") }
            ?: defaultServerName
        val fingerprint = query.value("fp") ?: throw missingQueryValue("fp")
        requireNonEmpty(fingerprint, "fp")
        return RealityParameters(
            publicKey = query.required("pbk"),
            fingerprint = fingerprint,
            serverName = serverName,
            shortId = query.requiredPresent("sid"),
            spiderX = query.optional("spx", ""),
            mldsa65Verify = query.optional("pqv", "").ifEmpty { null },
            flow = null,
        )
    }

    private fun rejectUnsupportedSecurityValues(query: QueryValues) {
        for (name in listOf("pcs", "vcn", "ech", "echQuery")) {
            if (!query.value(name).isNullOrEmpty()) {
                throw importError(
                    XrayVlessUrlImportErrorCode.UnsupportedQueryParameter,
                    "VLESS URL contains unsupported `$name`.",
                    parameter = name,
                )
            }
        }
    }

    private fun rejectRealityOnlyValues(query: QueryValues) {
        for (name in listOf("pbk", "sid", "spx", "pqv")) {
            if (query.value(name) != null) {
                throw importError(
                    XrayVlessUrlImportErrorCode.UnsupportedQueryParameter,
                    "VLESS URL contains unsupported `$name`.",
                    parameter = name,
                )
            }
        }
    }

    private fun validateRealityCompatibilityValues(query: QueryValues) {
        query.value("alpn")?.let { alpn ->
            if (alpn != "h2") {
                throw unsupportedValue("alpn", alpn, "h2 or absent for Reality")
            }
        }
        if (query.value("allowInsecure") != null) {
            throw importError(
                XrayVlessUrlImportErrorCode.UnsupportedQueryParameter,
                "VLESS URL contains unsupported `allowInsecure`.",
                parameter = "allowInsecure",
            )
        }
    }

    private fun decodeXhttpExtra(raw: String): JSONObject {
        if (raw.isEmpty()) {
            throw invalidXhttpExtra()
        }
        requireBoundedExtra(raw)
        parseJsonObject(raw)?.let { return it }
        val decoded = runCatching { decodeComponent(raw) }.getOrElse { throw invalidXhttpExtra() }
        requireBoundedExtra(decoded)
        if (decoded == raw) {
            throw invalidXhttpExtra()
        }
        return parseJsonObject(decoded) ?: throw invalidXhttpExtra()
    }

    private fun requireBoundedExtra(value: String) {
        if (value.toByteArray(StandardCharsets.UTF_8).size > MAX_XHTTP_EXTRA_BYTES) {
            throw importError(
                XrayVlessUrlImportErrorCode.XhttpExtraTooLarge,
                "VLESS XHTTP `extra` is too large.",
                parameter = "extra",
            )
        }
    }

    private fun parseJsonObject(value: String): JSONObject? = try {
        JSONObject(value)
    } catch (_: JSONException) {
        null
    }

    private fun invalidXhttpExtra() = importError(
        XrayVlessUrlImportErrorCode.InvalidXhttpExtra,
        "Invalid VLESS XHTTP `extra`. Expected a JSON object.",
        parameter = "extra",
    )

    private fun requireNonEmpty(value: String, name: String) {
        if (value.isEmpty()) {
            throw unsupportedValue(name, value, "non-empty")
        }
    }

    private fun requireValue(value: String, name: String, expected: List<String>) {
        if (value !in expected) {
            throw unsupportedValue(name, value, expected.joinToString(" or "))
        }
    }

    private fun unsupportedValue(
        name: String,
        value: String,
        expected: String,
    ) = importError(
        XrayVlessUrlImportErrorCode.UnsupportedQueryValue,
        "Unsupported VLESS $name `$value`. Expected `$expected`.",
        parameter = name,
        rejectedValue = value,
        expected = expected,
    )

    private fun missingQueryValue(name: String) = importError(
        XrayVlessUrlImportErrorCode.MissingQueryValue,
        "VLESS URL is missing `$name`.",
        parameter = name,
    )

    private fun normalizeVlessUrl(rawUrl: String): String {
        val trimmed = rawUrl.trim()
        if (trimmed.isEmpty()) {
            return trimmed
        }
        schemePattern.find(trimmed)?.let { match ->
            return firstToken(trimmed.substring(match.range.first))
        }
        authorityPattern.find(trimmed)?.let { match ->
            return "vless://${firstToken(trimmed.substring(match.range.first))}"
        }
        return trimmed
    }

    private fun firstToken(value: String): String = value
        .split(Regex("\\s+"), limit = 2)
        .firstOrNull()
        .orEmpty()
        .trim('"', '\'', ',', ';')

    private fun decodeComponent(value: String): String = try {
        URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8.name())
    } catch (_: IllegalArgumentException) {
        throw importError(XrayVlessUrlImportErrorCode.InvalidUrl, "Invalid VLESS URL.")
    }

    private fun importError(
        code: XrayVlessUrlImportErrorCode,
        message: String,
        parameter: String? = null,
        rejectedValue: String? = null,
        expected: String? = null,
    ) = XrayVlessUrlImportException(
        code = code,
        parameter = parameter,
        rejectedValue = rejectedValue,
        expected = expected,
        message = message,
    )

    private data class Endpoint(
        val userId: String,
        val host: String,
        val port: Int,
        val encryption: String,
        val transport: Transport,
        val profileName: String,
    ) {
        fun mobileConfigJson(): String {
            val user = JSONObject()
                .put("id", userId)
                .put("encryption", encryption)
            val streamSettings = when (val selected = transport) {
                is Transport.RawReality -> {
                    selected.reality.flow?.let { user.put("flow", it) }
                    JSONObject()
                        .put("network", "tcp")
                        .put("security", "reality")
                        .put("realitySettings", selected.reality.toJson())
                }

                is Transport.Xhttp -> selected.parameters.toStreamSettingsJson()
            }
            val inbound = JSONObject()
                .put("tag", "tun-in")
                .put("protocol", "tun")
                .put("listen", "127.0.0.1")
                .put("port", 0)
                .put("settings", JSONObject())
                .put(
                    "sniffing",
                    JSONObject()
                        .put("enabled", true)
                        .put("destOverride", JSONArray(listOf("http", "tls", "quic")))
                        .put("metadataOnly", false),
                )
            val proxy = JSONObject()
                .put("tag", "proxy")
                .put("protocol", "vless")
                .put(
                    "settings",
                    JSONObject().put(
                        "vnext",
                        JSONArray().put(
                            JSONObject()
                                .put("address", host)
                                .put("port", port)
                                .put("users", JSONArray().put(user)),
                        ),
                    ),
                )
                .put("streamSettings", streamSettings)
            val direct = JSONObject()
                .put("tag", "direct")
                .put("protocol", "freedom")
                .put("settings", JSONObject())
            val routing = JSONObject()
                .put("domainStrategy", "AsIs")
                .put(
                    "rules",
                    JSONArray().put(
                        JSONObject()
                            .put("type", "field")
                            .put(
                                "ip",
                                JSONArray(listOf("geoip:private", "127.0.0.0/8", "fd00::/8")),
                            )
                            .put("outboundTag", "direct"),
                    ),
                )
            val dns = JSONObject()
                .put("queryStrategy", "UseIPv4")
                .put(
                    "fakeIp",
                    JSONObject()
                        .put("enabled", true)
                        .put("ipv4Pool", "198.19.0.0/16")
                        .put("poolSize", 32768)
                        .put("ttl", 60),
                )
            return JSONObject()
                .put("inbounds", JSONArray().put(inbound))
                .put("outbounds", JSONArray().put(proxy).put(direct))
                .put("routing", routing)
                .put("dns", dns)
                .toString(2)
        }
    }

    private sealed class Transport {
        data class RawReality(val reality: RealityParameters) : Transport()

        data class Xhttp(val parameters: XhttpParameters) : Transport()
    }

    private data class RealityParameters(
        val publicKey: String,
        val fingerprint: String,
        val serverName: String,
        val shortId: String,
        val spiderX: String,
        val mldsa65Verify: String?,
        val flow: String?,
    ) {
        fun toJson(): JSONObject = JSONObject()
            .put("serverName", serverName)
            .put("fingerprint", fingerprint)
            .put("publicKey", publicKey)
            .put("shortId", shortId)
            .put("spiderX", spiderX)
            .also { json -> mldsa65Verify?.let { json.put("mldsa65Verify", it) } }
    }

    private data class TlsParameters(
        val serverName: String,
        val fingerprint: String,
        val alpn: List<String>?,
        val allowInsecure: Boolean?,
    ) {
        fun toJson(): JSONObject = JSONObject()
            .put("serverName", serverName)
            .put("fingerprint", fingerprint)
            .also { json ->
                alpn?.let { json.put("alpn", JSONArray(it)) }
                allowInsecure?.let { json.put("allowInsecure", it) }
            }
    }

    private sealed class XhttpSecurity {
        object None : XhttpSecurity()

        data class Tls(val parameters: TlsParameters) : XhttpSecurity()

        data class Reality(val parameters: RealityParameters) : XhttpSecurity()
    }

    private data class XhttpParameters(
        val host: String,
        val path: String,
        val mode: String,
        val extra: JSONObject?,
        val security: XhttpSecurity,
    ) {
        fun toStreamSettingsJson(): JSONObject {
            val xhttpSettings = JSONObject()
                .put("host", host)
                .put("path", path)
                .put("mode", mode)
                .also { json -> extra?.let { json.put("extra", it) } }
            return JSONObject()
                .put("network", "xhttp")
                .put("xhttpSettings", xhttpSettings)
                .also { json ->
                    when (val selected = security) {
                        XhttpSecurity.None -> json.put("security", "none")
                        is XhttpSecurity.Tls -> json
                            .put("security", "tls")
                            .put("tlsSettings", selected.parameters.toJson())

                        is XhttpSecurity.Reality -> json
                            .put("security", "reality")
                            .put("realitySettings", selected.parameters.toJson())
                    }
                }
        }
    }

    private class QueryValues private constructor(
        private val values: Map<String, String>,
        private val duplicateNames: Set<String>,
    ) {
        fun required(name: String): String = value(name)?.takeIf(String::isNotEmpty)
            ?: throw missingQueryValue(name)

        fun requiredPresent(name: String): String = value(name) ?: throw missingQueryValue(name)

        fun optional(name: String, default: String): String = value(name) ?: default

        fun value(name: String): String? = values[name.lowercase(Locale.ROOT)]

        fun rejectDuplicates(names: List<String>) {
            names.firstOrNull { it.lowercase(Locale.ROOT) in duplicateNames }?.let { name ->
                throw importError(
                    XrayVlessUrlImportErrorCode.DuplicateQueryValue,
                    "VLESS URL contains duplicate `$name` values.",
                    parameter = name,
                )
            }
        }

        companion object {
            fun parse(rawQuery: String?): QueryValues {
                val values = linkedMapOf<String, String>()
                val duplicates = mutableSetOf<String>()
                rawQuery?.split('&')?.forEach { item ->
                    val separator = item.indexOf('=')
                    val rawName = if (separator >= 0) item.substring(0, separator) else item
                    val rawValue = if (separator >= 0) item.substring(separator + 1) else ""
                    val name = decodeComponent(rawName).lowercase(Locale.ROOT)
                    if (values.containsKey(name)) {
                        duplicates += name
                    }
                    values[name] = decodeComponent(rawValue)
                }
                return QueryValues(values, duplicates)
            }
        }
    }
}
