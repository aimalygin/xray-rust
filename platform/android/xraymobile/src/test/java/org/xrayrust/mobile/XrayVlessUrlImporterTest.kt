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
    fun rejectedEncryptionDoesNotExposeKeyMaterial() {
        val key = "synthetic-key-material-for-redaction"
        val url = "vless://11111111-1111-4111-8111-111111111111@example.test:443" +
            "?encryption=mlkem768x25519plus.native.1rtt.$key"
        val error = assertThrows(XrayVlessUrlImportException::class.java) {
            XrayVlessUrlImporter.profile(url)
        }
        assertEquals("encryption", error.parameter)
        assertEquals("<redacted>", error.rejectedValue)
        assertFalse(error.toString().contains(key))
    }

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
            "type=kcp&security=tls" to "type",
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
    fun buildsRawTlsProfileWithAndWithoutVision() {
        val vision = XrayVlessUrlImporter.profile(
            "vless://$TEST_USER_ID@203.0.113.30:443" +
                "?type=tcp&security=tls&flow=xtls-rprx-vision&sni=origin.example" +
                "&fp=firefox&alpn=h2%2Chttp%2F1.1&allowInsecure=0&headerType=none#vision-tls",
        )
        val stream = proxy(vision).getJSONObject("streamSettings")
        val tls = stream.getJSONObject("tlsSettings")

        assertEquals("vision-tls", vision.name)
        assertEquals("tcp", stream.getString("network"))
        assertEquals("tls", stream.getString("security"))
        assertEquals("origin.example", tls.getString("serverName"))
        assertEquals("firefox", tls.getString("fingerprint"))
        assertEquals(listOf("h2", "http/1.1"), tls.getJSONArray("alpn").strings())
        assertFalse(tls.getBoolean("allowInsecure"))
        assertFalse(stream.has("realitySettings"))
        assertEquals("xtls-rprx-vision", firstUser(vision).getString("flow"))

        val plain = XrayVlessUrlImporter.profile(
            "vless://$TEST_USER_ID@origin.example:443?type=raw&security=tls",
        )
        val plainStream = proxy(plain).getJSONObject("streamSettings")
        assertEquals("tcp", plainStream.getString("network"))
        assertEquals("origin.example", plainStream.getJSONObject("tlsSettings").getString("serverName"))
        assertEquals("chrome", plainStream.getJSONObject("tlsSettings").getString("fingerprint"))
        assertFalse(firstUser(plain).has("flow"))
    }

    @Test
    fun buildsWebSocketAndHttpUpgradeTlsProfiles() {
        for ((type, network) in listOf(
            "ws" to "ws",
            "websocket" to "ws",
            "httpupgrade" to "httpupgrade",
        )) {
            val profile = XrayVlessUrlImporter.profile(
                "vless://$TEST_USER_ID@203.0.113.31:443" +
                    "?type=$type&security=tls&host=cdn.example&path=%2Fws%3Fed%3D2048" +
                    "&sni=cdn.example&fp=chrome&alpn=http%2F1.1",
            )
            val stream = proxy(profile).getJSONObject("streamSettings")
            val settings = stream.getJSONObject("${network}Settings")

            assertEquals(type, network, stream.getString("network"))
            assertEquals(type, "tls", stream.getString("security"))
            assertEquals(type, "cdn.example", stream.getJSONObject("tlsSettings").getString("serverName"))
            assertEquals(type, listOf("http/1.1"), stream.getJSONObject("tlsSettings").getJSONArray("alpn").strings())
            assertEquals(type, "cdn.example", settings.getString("host"))
            assertEquals(type, "/ws?ed=2048", settings.getString("path"))
            assertFalse(type, firstUser(profile).has("flow"))
        }

        val bare = proxy(
            XrayVlessUrlImporter.profile("vless://$TEST_USER_ID@cdn.example:443?type=ws&security=tls"),
        ).getJSONObject("streamSettings")
        assertFalse(bare.has("wsSettings"))
    }

    @Test
    fun buildsGrpcTlsAndRealityProfiles() {
        val tls = proxy(
            XrayVlessUrlImporter.profile(
                "vless://$TEST_USER_ID@203.0.113.32:443" +
                    "?type=grpc&security=tls&serviceName=tunnel&authority=cdn.example&mode=gun",
            ),
        ).getJSONObject("streamSettings")
        val tlsGrpc = tls.getJSONObject("grpcSettings")

        assertEquals("grpc", tls.getString("network"))
        assertEquals("tls", tls.getString("security"))
        assertEquals("tunnel", tlsGrpc.getString("serviceName"))
        assertEquals("cdn.example", tlsGrpc.getString("authority"))
        assertFalse(tlsGrpc.has("multiMode"))

        val reality = proxy(
            XrayVlessUrlImporter.profile(
                "vless://$TEST_USER_ID@203.0.113.32:443" +
                    "?type=grpc&security=reality&serviceName=tunnel&mode=multi" +
                    "&pbk=$PUBLIC_KEY&fp=chrome&sni=example.com&sid=0123456789ab",
            ),
        ).getJSONObject("streamSettings")

        assertEquals("reality", reality.getString("security"))
        assertEquals("example.com", reality.getJSONObject("realitySettings").getString("serverName"))
        assertTrue(reality.getJSONObject("grpcSettings").getBoolean("multiMode"))
        assertFalse(reality.has("tlsSettings"))
    }

    @Test
    fun rejectsUnsupportedFramedAndRawTlsCombinations() {
        for ((query, parameter) in listOf(
            "type=tcp&security=none" to "security",
            "type=ws&security=none" to "security",
            "type=httpupgrade&security=reality&pbk=$PUBLIC_KEY&fp=chrome&sid=" to "security",
            "type=ws&security=reality&pbk=$PUBLIC_KEY&fp=chrome&sid=" to "security",
            "type=ws&security=tls&flow=xtls-rprx-vision" to "flow",
            "type=grpc&security=tls&flow=xtls-rprx-vision" to "flow",
            "type=grpc&security=tls&mode=guna" to "mode",
            "type=tcp&security=tls&allowInsecure=1" to "allowInsecure",
            "type=ws&security=tls&allowInsecure=true" to "allowInsecure",
        )) {
            val error = assertImportError(
                "vless://$TEST_USER_ID@203.0.113.33:443?$query",
                XrayVlessUrlImportErrorCode.UnsupportedQueryValue,
            )
            assertEquals(query, parameter, error.parameter)
        }
    }

    @Test
    fun rejectsFieldsThatBelongToAnotherCarrierOrSecurity() {
        for ((query, parameter) in listOf(
            "type=tcp&security=tls&path=%2Fignored" to "path",
            "type=tcp&security=tls&pbk=$PUBLIC_KEY" to "pbk",
            "type=tcp&security=tls&ech=sensitive" to "ech",
            "type=ws&security=tls&extra=%7B%7D" to "extra",
            "type=ws&security=tls&serviceName=tunnel" to "serviceName",
            "type=httpupgrade&security=tls&mode=multi" to "mode",
            "type=grpc&security=tls&host=cdn.example" to "host",
            "type=grpc&security=tls&sid=" to "sid",
        )) {
            val error = assertImportError(
                "vless://$TEST_USER_ID@203.0.113.33:443?$query",
                XrayVlessUrlImportErrorCode.UnsupportedQueryParameter,
            )
            assertEquals(query, parameter, error.parameter)
        }
    }

    @Test
    fun rejectsRealitySpiderXWithoutLeadingSlashLikeXrayCore() {
        val xhttpReality = "vless://$TEST_USER_ID@203.0.113.30:443" +
            "?type=xhttp&security=reality&pbk=$PUBLIC_KEY&fp=chrome&sid=0123456789ab"
        for (url in listOf(sampleRealityUrl, xhttpReality)) {
            val base = url.substringBefore('#').replace("&spx=%2F", "")
            val error = assertImportError(
                "$base&spx=crawl",
                XrayVlessUrlImportErrorCode.UnsupportedQueryValue,
            )
            assertEquals("spx", error.parameter)
            val reality = proxy(XrayVlessUrlImporter.profile("$base&spx="))
                .getJSONObject("streamSettings")
                .getJSONObject("realitySettings")
            assertEquals("", reality.getString("spiderX"))
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
    fun emptyUnsupportedSecurityValuesRemainAllowedButRealityFieldsRemainRejected() {
        val base = "vless://$TEST_USER_ID@example.com:443?type=xhttp&security=tls"
        val profile = XrayVlessUrlImporter.profile("$base&pcs=&vcn=&ech=&echQuery=")
        val stream = proxy(profile).getJSONObject("streamSettings")
        assertEquals("tls", stream.getString("security"))
        assertEquals("example.com", stream.getJSONObject("tlsSettings").getString("serverName"))

        for (name in listOf("pbk", "sid", "spx", "pqv")) {
            val error = assertImportError("$base&$name=", XrayVlessUrlImportErrorCode.UnsupportedQueryParameter)
            assertEquals(name, error.parameter)
        }
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
    fun copiesFinalMaskVerbatimIntoEveryTransport() {
        val finalMask = """{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200"}}]}"""
        val links = listOf(
            "vless://$TEST_USER_ID@203.0.113.10:443?type=tcp&security=tls",
            "vless://$TEST_USER_ID@203.0.113.10:443?type=tcp&security=reality&pbk=$PUBLIC_KEY&fp=chrome&sni=example.com&sid=0123",
            "vless://$TEST_USER_ID@203.0.113.10:443?type=xhttp&security=tls&path=%2F",
            "vless://$TEST_USER_ID@203.0.113.10:443?type=ws&security=tls&path=%2Fws",
            "vless://$TEST_USER_ID@203.0.113.10:443?type=grpc&security=tls&serviceName=svc",
        )
        for (link in links) {
            val stream = proxy(XrayVlessUrlImporter.profile("$link&FM=${encode(finalMask)}"))
                .getJSONObject("streamSettings")
            assertEquals(link, JSONObject(finalMask).toString(), stream.getJSONObject("finalmask").toString())
        }
    }

    @Test
    fun emptyFinalMaskIsAbsent() {
        val stream = proxy(XrayVlessUrlImporter.profile("vless://$TEST_USER_ID@203.0.113.10:443?type=tcp&security=tls&fm="))
            .getJSONObject("streamSettings")
        assertFalse(stream.has("finalmask"))
    }

    @Test
    fun rejectsNonObjectOrDuplicateFinalMask() {
        val base = "vless://$TEST_USER_ID@203.0.113.10:443?type=tcp&security=tls"
        for (value in listOf("%5B%5D", "null", "7", "%22mask%22", "%7Bbroken", "%7B%7Dtrailing", encode(encode("{}")))) {
            val error = assertImportError("$base&fm=$value", XrayVlessUrlImportErrorCode.UnsupportedQueryValue)
            assertEquals(value, "fm", error.parameter)
            assertEquals(value, "<redacted>", error.rejectedValue)
        }
        val duplicate = assertImportError("$base&fm=%7B%7D&fm=%7B%7D", XrayVlessUrlImportErrorCode.DuplicateQueryValue)
        assertEquals("fm", duplicate.parameter)
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
