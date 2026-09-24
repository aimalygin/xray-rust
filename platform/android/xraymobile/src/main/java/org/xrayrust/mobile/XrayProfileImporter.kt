package org.xrayrust.mobile

import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

/** Supported source formats, independent of the resulting JSON outbound name. */
enum class XrayProfileFormat(val wireValue: String, internal val capability: XrayFfiCapability) {
    Hysteria2("hysteria2", XrayFfiCapability.Hysteria2Outbound),
    Wireguard("wireguard", XrayFfiCapability.WireguardOutbound),
}

fun XrayFfiInfo.supportsProfileImport(format: XrayProfileFormat): Boolean =
    version.major == 1 && version.minor >= 5 &&
        supports(XrayFfiCapability.ProfileImport) && supports(format.capability)

/** Imports text already read by the host. No file access, network or VPN startup. */
object XrayProfileImporter {
    @JvmStatic
    @JvmOverloads
    fun profile(
        text: String,
        format: XrayProfileFormat,
        name: String? = null,
        dnsServers: List<String> = emptyList(),
    ): XrayImportedProfile = importProfile(text, format, name, dnsServers,
        XrayCore.ffiInfo(), XrayCore::importProfileJson)

    internal fun importProfile(
        text: String, format: XrayProfileFormat, name: String?, dnsServers: List<String>,
        info: XrayFfiInfo, nativeImport: (ByteArray) -> ByteArray,
    ): XrayImportedProfile {
        check(info.supportsProfileImport(format)) { "native library does not support the requested profile import" }
        require(validUtf8Size(text, 64 * 1024) &&
            (name == null || validUtf8Size(name, 128)) && dnsServers.size <= 8 &&
            dnsServers.all { validUtf8Size(it, 253) }
        ) { "invalid or oversized profile import input" }
        val request = JSONObject().put("format", format.wireValue).put("text", text)
            .put("dnsServers", JSONArray(dnsServers))
        if (name != null) request.put("name", name)
        val input = request.toString().toByteArray(Charsets.UTF_8)
        try {
            require(input.size <= 256 * 1024) { "profile import request exceeds its size limit" }
            val output = nativeImport(input)
            try {
                check(output.size <= 256 * 1024) { "invalid imported profile response size" }
                // Never attach a JSON parse exception that might quote credential data.
                val profile = runCatching {
                    val textResult = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(output))
                    val result = JSONObject(textResult.toString())
                    check(result.get("schemaVersion") == 1)
                    XrayImportedProfile(result.get("name") as String, result.get("serverAddress") as String,
                        result.get("configJSON") as String)
                }.getOrNull()
                return checkNotNull(profile) { "native library returned an invalid imported profile" }
            } finally { output.fill(0) }
        } finally { input.fill(0) }
    }

    // Validate Unicode without creating another credential byte array. The
    // default JVM encoder replaces unpaired surrogates, changing passwords.
    private fun validUtf8Size(value: String, maxBytes: Int): Boolean {
        if (value.length > maxBytes) return false
        var bytes = 0
        var index = 0
        while (index < value.length) {
            val c = value[index++]
            bytes += when {
                c.code < 0x80 -> 1
                c.code < 0x800 -> 2
                Character.isHighSurrogate(c) -> {
                    if (index == value.length || !Character.isLowSurrogate(value[index++])) return false
                    4
                }
                Character.isLowSurrogate(c) -> return false
                else -> 3
            }
            if (bytes > maxBytes) return false
        }
        return true
    }
}
