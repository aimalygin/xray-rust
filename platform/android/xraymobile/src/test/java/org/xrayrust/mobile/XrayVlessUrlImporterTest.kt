package org.xrayrust.mobile

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

class XrayVlessUrlImporterTest {
    @Test
    fun buildsMobileRawRealityProfile() {
        val profile = XrayVlessUrlImporter.profile(sampleRealityUrl)

        assertEquals("example-reality", profile.name)
        assertEquals("203.0.113.10", profile.serverAddress)
        val root = JSONObject(profile.configJson)
        val inbound = root.getJSONArray("inbounds").getJSONObject(0)
        assertEquals("tun-in", inbound.getString("tag"))
        assertEquals("tun", inbound.getString("protocol"))
        assertEquals(
            listOf("http", "tls", "quic"),
            inbound.getJSONObject("sniffing").getJSONArray("destOverride").strings(),
        )

        val outbounds = root.getJSONArray("outbounds")
        assertEquals(2, outbounds.length())
        val proxy = outbounds.getJSONObject(0)
        val server = proxy.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
        assertEquals("203.0.113.10", server.getString("address"))
        assertEquals(32134, server.getInt("port"))
        val user = server.getJSONArray("users").getJSONObject(0)
        assertEquals(TEST_USER_ID, user.getString("id"))
        assertEquals("none", user.getString("encryption"))
        assertEquals("xtls-rprx-vision", user.getString("flow"))

        val stream = proxy.getJSONObject("streamSettings")
        assertEquals("tcp", stream.getString("network"))
        assertEquals("reality", stream.getString("security"))
        val reality = stream.getJSONObject("realitySettings")
        assertEquals("example.com", reality.getString("serverName"))
        assertEquals("chrome", reality.getString("fingerprint"))
        assertEquals("0123456789ab", reality.getString("shortId"))
        assertEquals("/", reality.getString("spiderX"))
        assertEquals("ignored-for-now", reality.getString("mldsa65Verify"))

        val dns = root.getJSONObject("dns")
        assertEquals("UseIPv4", dns.getString("queryStrategy"))
        val fakeIp = dns.getJSONObject("fakeIp")
        assertTrue(fakeIp.getBoolean("enabled"))
        assertEquals("198.19.0.0/16", fakeIp.getString("ipv4Pool"))
        assertEquals(32768, fakeIp.getInt("poolSize"))
        assertEquals(60, fakeIp.getInt("ttl"))
    }

    @Test
    fun buildsPlainXhttpProfileFromDoubleEncodedExtra() {
        val extra = """{"noGRPCHeader":false,"xmux":{"maxConnections":16}}"""
        val encodedTwice = encode(encode(extra))
        val profile = XrayVlessUrlImporter.profile(
            "vless://$TEST_USER_ID@203.0.113.20:80" +
                "?type=xhttp&host=edge.example&path=%2F&mode=packet-up" +
                "&extra=$encodedTwice&security=none#Legacy%20XHTTP%20sample",
        )

        assertEquals("Legacy XHTTP sample", profile.name)
        val stream = proxy(profile).getJSONObject("streamSettings")
        assertEquals("xhttp", stream.getString("network"))
        assertEquals("none", stream.getString("security"))
        assertFalse(stream.has("realitySettings"))
        val xhttp = stream.getJSONObject("xhttpSettings")
        assertEquals("edge.example", xhttp.getString("host"))
        assertEquals("/", xhttp.getString("path"))
        assertEquals("packet-up", xhttp.getString("mode"))
        assertFalse(xhttp.getJSONObject("extra").getBoolean("noGRPCHeader"))
        assertEquals(16, xhttp.getJSONObject("extra").getJSONObject("xmux").getInt("maxConnections"))
        assertFalse(firstUser(profile).has("flow"))
    }

    @Test
    fun canonicalizesSplitHttpAndMaterializesDefaults() {
        val profile = XrayVlessUrlImporter.profile(
            "vless://$TEST_USER_ID@203.0.113.20:80?type=splithttp&security=none",
        )
        val stream = proxy(profile).getJSONObject("streamSettings")
        val xhttp = stream.getJSONObject("xhttpSettings")

        assertEquals("xhttp", stream.getString("network"))
        assertEquals("none", stream.getString("security"))
        assertEquals("", xhttp.getString("host"))
        assertEquals("", xhttp.getString("path"))
        assertEquals("auto", xhttp.getString("mode"))
        assertFalse(xhttp.has("extra"))
    }

    @Test
    fun buildsXhttpTlsWithoutLosingFields() {
        val profile = XrayVlessUrlImporter.profile(
            "vless://$TEST_USER_ID@203.0.113.21:443" +
                "?type=xhttp&security=tls&host=cdn.example&path=%2Fupload&mode=stream-up" +
                "&sni=origin.example&fp=hellochrome_120&alpn=h2%2Chttp%2F1.1" +
                "&allowInsecure=1",
        )
        val stream = proxy(profile).getJSONObject("streamSettings")
        val tls = stream.getJSONObject("tlsSettings")

        assertEquals("tls", stream.getString("security"))
        assertEquals("origin.example", tls.getString("serverName"))
        assertEquals("hellochrome_120", tls.getString("fingerprint"))
        assertEquals(listOf("h2", "http/1.1"), tls.getJSONArray("alpn").strings())
        assertTrue(tls.getBoolean("allowInsecure"))
        assertNull(firstUser(profile).opt("flow"))
    }

    @Test
    fun buildsXhttpRealityAndAcceptsEmptyShortId() {
        val profile = XrayVlessUrlImporter.profile(
            "vless://$TEST_USER_ID@reality-endpoint.example:443" +
                "?type=xhttp&security=reality&host=edge.example&path=%2Freality" +
                "&mode=stream-one&pbk=$PUBLIC_KEY&fp=hellochrome_131&sid=" +
                "&spx=%2Fcrawl&pqv=post-quantum-key&alpn=h2",
        )
        val stream = proxy(profile).getJSONObject("streamSettings")
        val reality = stream.getJSONObject("realitySettings")

        assertEquals("reality", stream.getString("security"))
        assertEquals("reality-endpoint.example", reality.getString("serverName"))
        assertEquals("hellochrome_131", reality.getString("fingerprint"))
        assertEquals("", reality.getString("shortId"))
        assertEquals("/crawl", reality.getString("spiderX"))
        assertEquals("post-quantum-key", reality.getString("mldsa65Verify"))
        assertFalse(stream.has("tlsSettings"))
        assertFalse(firstUser(profile).has("flow"))
    }

    @Test
    fun acceptsPastedSchemeLessRawAliasAndUdp443Flow() {
        val schemeLess = sampleRealityUrl
            .removePrefix("vless://")
            .replace("type=tcp", "type=raw")
            .replace("flow=xtls-rprx-vision", "flow=xtls-rprx-vision-udp443")
        val profile = XrayVlessUrlImporter.profile("configuration url:\n$schemeLess\n")

        assertEquals("example-reality", profile.name)
        assertEquals("tcp", proxy(profile).getJSONObject("streamSettings").getString("network"))
        assertEquals("xtls-rprx-vision-udp443", firstUser(profile).getString("flow"))
    }

    @Test
    fun removesIpv6UriBracketsFromTheXrayAddress() {
        val profile = XrayVlessUrlImporter.profile(
            "vless://$TEST_USER_ID@[2001:db8::10]:443" +
                "?type=xhttp&security=tls&sni=origin.example",
        )

        assertEquals("2001:db8::10", profile.serverAddress)
        assertEquals(
            "2001:db8::10",
            proxy(profile)
                .getJSONObject("settings")
                .getJSONArray("vnext")
                .getJSONObject(0)
                .getString("address"),
        )
    }

    @Test
    fun parsesAllSupportedAllowInsecureSpellings() {
        for ((raw, expected) in listOf(
            "0" to false,
            "false" to false,
            "FALSE" to false,
            "1" to true,
            "true" to true,
            "TRUE" to true,
        )) {
            val profile = XrayVlessUrlImporter.profile(
                "vless://$TEST_USER_ID@example.com:443" +
                    "?type=xhttp&security=tls&allowInsecure=$raw",
            )
            val tls = proxy(profile).getJSONObject("streamSettings").getJSONObject("tlsSettings")
            assertEquals(raw, expected, tls.getBoolean("allowInsecure"))
        }
    }

    @Test
    fun rejectsUnsupportedTransportSecurityModeAndFlow() {
        for ((query, parameter) in listOf(
            "type=ws&security=none" to "type",
            "type=xhttp&security=xtls" to "security",
            "type=xhttp&security=none&mode=burst" to "mode",
            "type=xhttp&security=none&flow=xtls-rprx-vision" to "flow",
        )) {
            val error = assertImportError(
                "vless://$TEST_USER_ID@203.0.113.20:80?$query",
                XrayVlessUrlImportErrorCode.UnsupportedQueryValue,
            )
            assertEquals(parameter, error.parameter)
        }
    }

    @Test
    fun rejectsDuplicateSecurityCriticalFields() {
        val error = assertImportError(
            "vless://$TEST_USER_ID@example.com:443" +
                "?type=xhttp&security=tls&sni=one.example&sni=two.example",
            XrayVlessUrlImportErrorCode.DuplicateQueryValue,
        )
        assertEquals("sni", error.parameter)
    }

    @Test
    fun rejectsRealityOnlyTlsFieldsAndDoesNotLeakUnsupportedSecrets() {
        val realityOnly = assertImportError(
            "vless://$TEST_USER_ID@example.com:443?type=xhttp&security=tls&sid=",
            XrayVlessUrlImportErrorCode.UnsupportedQueryParameter,
        )
        assertEquals("sid", realityOnly.parameter)

        val secret = "sensitive-security-material"
        val unsupported = assertImportError(
            "vless://$TEST_USER_ID@example.com:443" +
                "?type=xhttp&security=none&ech=$secret",
            XrayVlessUrlImportErrorCode.UnsupportedQueryParameter,
        )
        assertEquals("ech", unsupported.parameter)
        assertFalse(unsupported.message.orEmpty().contains(secret))
    }

    @Test
    fun rejectsInvalidOrRecursivelyEncodedXhttpExtra() {
        val recursivelyEncoded = encode(encode(encode("{}")))
        for (value in listOf("", "%5B%5D", "null", "7", "%7Bbroken", recursivelyEncoded)) {
            val error = assertImportError(
                "vless://$TEST_USER_ID@203.0.113.20:80" +
                    "?type=xhttp&security=none&extra=$value",
                XrayVlessUrlImportErrorCode.InvalidXhttpExtra,
            )
            if (value.isNotEmpty()) {
                assertFalse(error.message.orEmpty().contains(value))
            }
        }
    }

    @Test
    fun boundsXhttpExtraBeforeParsing() {
        val oversized = "a".repeat(64 * 1024 + 1)
        assertImportError(
            "vless://$TEST_USER_ID@203.0.113.20:80" +
                "?type=xhttp&security=none&extra=$oversized",
            XrayVlessUrlImportErrorCode.XhttpExtraTooLarge,
        )
    }

    @Test
    fun rejectsInvalidUuidMissingPortAndMissingRealityFields() {
        assertImportError(
            "vless://not-a-uuid@example.com:443?type=tcp&security=reality",
            XrayVlessUrlImportErrorCode.InvalidUserId,
        )
        assertImportError(
            "vless://$TEST_USER_ID@example.com?type=tcp&security=reality",
            XrayVlessUrlImportErrorCode.MissingPort,
        )
        val missing = assertImportError(
            "vless://$TEST_USER_ID@example.com:443" +
                "?type=xhttp&security=reality&pbk=$PUBLIC_KEY&sid=",
            XrayVlessUrlImportErrorCode.MissingQueryValue,
        )
        assertEquals("fp", missing.parameter)
    }

    @Test
    fun invalidUrlErrorDoesNotRetainTheShareLinkOrParserCause() {
        val secret = "credential-material"
        val error = assertImportError(
            "vless://$TEST_USER_ID@example.com:443?type=xhttp&security=none&host=%$secret",
            XrayVlessUrlImportErrorCode.InvalidUrl,
        )

        assertFalse(error.message.orEmpty().contains(secret))
        assertNull(error.cause)
    }

    private fun assertImportError(
        url: String,
        code: XrayVlessUrlImportErrorCode,
    ): XrayVlessUrlImportException {
        val error = assertThrows(XrayVlessUrlImportException::class.java) {
            XrayVlessUrlImporter.profile(url)
        }
        assertEquals(code, error.code)
        return error
    }

    private fun proxy(profile: XrayImportedProfile): JSONObject = JSONObject(profile.configJson)
        .getJSONArray("outbounds")
        .getJSONObject(0)

    private fun firstUser(profile: XrayImportedProfile): JSONObject = proxy(profile)
        .getJSONObject("settings")
        .getJSONArray("vnext")
        .getJSONObject(0)
        .getJSONArray("users")
        .getJSONObject(0)

    private fun org.json.JSONArray.strings(): List<String> =
        List(length()) { index -> getString(index) }

    private fun encode(value: String): String = URLEncoder.encode(
        value,
        StandardCharsets.UTF_8.name(),
    )

    companion object {
        private const val TEST_USER_ID = "11111111-1111-4111-8111-111111111111"
        private const val PUBLIC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        private const val sampleRealityUrl =
            "vless://$TEST_USER_ID@203.0.113.10:32134" +
                "?type=tcp&encryption=none&security=reality&pbk=$PUBLIC_KEY" +
                "&fp=chrome&sni=example.com&sid=0123456789ab&spx=%2F" +
                "&pqv=ignored-for-now&flow=xtls-rprx-vision#example-reality"
    }
}
