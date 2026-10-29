package org.xrayrust.mobile

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

class XrayProfileImporterTest {
    private val all = XrayFfiCapability.ProfileImport.mask or XrayFfiCapability.Hysteria2Outbound.mask or
        XrayFfiCapability.WireguardOutbound.mask
    private val current = XrayFfiInfo(XrayFfiVersion(1, 5), all)

    @Test fun httpImportRequiresItsOwnCapabilityAndMinorBeforeNative() {
        val caps = XrayFfiCapability.ProfileImport.mask or XrayFfiCapability.HttpProfileImport.mask
        assertTrue(XrayFfiInfo(XrayFfiVersion(1, 14), caps).supportsProfileImport(XrayProfileFormat.Http))
        for (info in listOf(
            XrayFfiInfo(XrayFfiVersion(1, 13), caps),
            XrayFfiInfo(XrayFfiVersion(2, 14), caps),
            XrayFfiInfo(XrayFfiVersion(1, 14), XrayFfiCapability.ProfileImport.mask),
            XrayFfiInfo(XrayFfiVersion(1, 14), XrayFfiCapability.HttpProfileImport.mask),
        )) {
            assertThrows(IllegalStateException::class.java) {
                XrayProfileImporter.importProfile("secret", XrayProfileFormat.Http, null, emptyList(), info) {
                    fail("unavailable HTTP import invoked native code"); byteArrayOf()
                }
            }
        }
    }

    @Test fun socksImportRequiresItsOwnCapabilityAndMinorBeforeNative() {
        val caps = XrayFfiCapability.ProfileImport.mask or XrayFfiCapability.SocksProfileImport.mask
        assertTrue(XrayFfiInfo(XrayFfiVersion(1, 13), caps).supportsProfileImport(XrayProfileFormat.Socks))
        for (info in listOf(
            XrayFfiInfo(XrayFfiVersion(1, 12), caps),
            XrayFfiInfo(XrayFfiVersion(2, 13), caps),
            XrayFfiInfo(XrayFfiVersion(1, 13), XrayFfiCapability.ProfileImport.mask),
            XrayFfiInfo(XrayFfiVersion(1, 13), XrayFfiCapability.SocksProfileImport.mask),
        )) {
            assertThrows(IllegalStateException::class.java) {
                XrayProfileImporter.importProfile("secret", XrayProfileFormat.Socks, null, emptyList(), info) {
                    fail("unavailable SOCKS import invoked native code"); byteArrayOf()
                }
            }
        }
    }

    @Test fun checksVersionAndBothCapabilitiesBeforeCallingNative() {
        for (info in listOf(XrayFfiInfo(XrayFfiVersion(1, 4), all), XrayFfiInfo(XrayFfiVersion(2, 5), all),
            XrayFfiInfo(XrayFfiVersion(1, 5), XrayFfiCapability.ProfileImport.mask),
            XrayFfiInfo(XrayFfiVersion(1, 5), XrayFfiCapability.Hysteria2Outbound.mask))) {
            assertThrows(IllegalStateException::class.java) {
                XrayProfileImporter.importProfile("secret", XrayProfileFormat.Hysteria2, null, emptyList(), info) {
                    fail("unavailable import invoked native code"); byteArrayOf()
                }
            }
        }
        val hysteria = XrayFfiInfo(XrayFfiVersion(1, 6), XrayFfiCapability.ProfileImport.mask or XrayFfiCapability.Hysteria2Outbound.mask)
        assertTrue(hysteria.supportsProfileImport(XrayProfileFormat.Hysteria2))
        assertFalse(hysteria.supportsProfileImport(XrayProfileFormat.Wireguard))
    }

    @Test fun preservesUnicodeOptionsAndWipesBoundaryArrays() {
        val source = "hy2://user:p%40ss@server.example#🔑"
        val output = JSONObject().put("schemaVersion", 1).put("name", "Name 🔑")
            .put("serverAddress", "server.example").put("configJSON", "secret✓").toString().toByteArray()
        var retainedInput = byteArrayOf()
        val profile = XrayProfileImporter.importProfile(source, XrayProfileFormat.Hysteria2, "Name 🔑",
            listOf("192.0.2.53"), current) { input ->
            retainedInput = input
            val request = JSONObject(input.toString(Charsets.UTF_8))
            assertEquals(source, request.getString("text"))
            assertEquals("hysteria2", request.getString("format"))
            assertEquals("Name 🔑", request.getString("name"))
            assertEquals("192.0.2.53", request.getJSONArray("dnsServers").getString(0))
            output
        }
        assertEquals("secret✓", profile.configJson)
        assertEquals("Name 🔑", profile.name)
        assertFalse(profile.toString().contains("secret"))
        assertTrue(retainedInput.isNotEmpty() && retainedInput.all { it == 0.toByte() })
        assertTrue(output.all { it == 0.toByte() })
    }

    @Test fun rejectsOversizeAndUnpairedSurrogatesBeforeNative() {
        for (source in listOf("🔑".repeat(17000), "x".repeat(65537), "secret\uD800", "secret\uDC00")) {
            val error = assertThrows(IllegalArgumentException::class.java) {
                XrayProfileImporter.importProfile(source, XrayProfileFormat.Hysteria2, null, emptyList(), current) {
                    fail("invalid Unicode or oversized input invoked native code"); byteArrayOf()
                }
            }
            assertFalse(error.toString().contains("secret"))
        }
    }

    @Test fun malformedNativeResultsAreRedactedAndWiped() {
        for (output in listOf("{secret".toByteArray(), byteArrayOf(0xff.toByte()),
            """{"schemaVersion":2,"name":"secret","serverAddress":"secret","configJSON":"secret"}""".toByteArray(),
            """{"schemaVersion":1,"name":false,"serverAddress":"secret","configJSON":"secret"}""".toByteArray(),
            ByteArray(256 * 1024 + 1))) {
            val error = assertThrows(IllegalStateException::class.java) {
                XrayProfileImporter.importProfile("secret", XrayProfileFormat.Wireguard, null, emptyList(), current) { output }
            }
            assertFalse(error.toString().contains("secret"))
            assertNull(error.cause)
            assertTrue(output.all { it == 0.toByte() })
        }
    }

    @Test fun nativeFailureStillWipesRequest() {
        var retained = byteArrayOf()
        assertThrows(IllegalArgumentException::class.java) {
            XrayProfileImporter.importProfile("secret", XrayProfileFormat.Wireguard, null, emptyList(), current) {
                retained = it
                throw IllegalArgumentException("profile contains an unsupported setting")
            }
        }
        assertTrue(retained.isNotEmpty() && retained.all { it == 0.toByte() })
    }
}

/** Optional host JNI integration; run with the current native libraries, not Android stubs. */
class XrayProfileImporterNativeTest {
    private fun enabled() { assumeTrue(java.lang.Boolean.getBoolean("xray.test.nativeImport")) }

    @Test fun importsHttpAndHttpsThroughActualJniWithSafeTLSAndTCPDNS() {
        enabled()
        assertTrue(XrayCore.ffiInfo().supportsProfileImport(XrayProfileFormat.Http))
        for ((file, tls) in listOf("http.txt" to false, "https.txt" to true)) {
            val profile = XrayProfileImporter.profile(fixture(file), XrayProfileFormat.Http,
                dnsServers = listOf("192.0.2.53", "2001:db8::53"))
            assertEquals("Test ✓", profile.name)
            assertEquals("Proxy.Example.", profile.serverAddress)
            val root = JSONObject(profile.configJson)
            val proxy = root.getJSONArray("outbounds").getJSONObject(0)
            assertEquals("synthetic-user", proxy.getJSONObject("settings").getString("user"))
            assertEquals("p@ss:+✓", proxy.getJSONObject("settings").getString("pass"))
            val stream = proxy.getJSONObject("streamSettings")
            assertEquals(if (tls) "tls" else "none", stream.getString("security"))
            if (tls) {
                val security = stream.getJSONObject("tlsSettings")
                assertEquals("Proxy.Example.", security.getString("serverName"))
                assertEquals("http/1.1", security.getJSONArray("alpn").getString(0))
                assertFalse(security.has("allowInsecure"))
            }
            val dns = root.getJSONObject("dns").getJSONArray("servers")
            assertEquals("tcp://192.0.2.53:53", dns.getString(0))
            assertEquals("tcp://[2001:db8::53]:53", dns.getString(1))
            BoundedAndroidDnsBootstrapResolver(maxConcurrentLookups = 2, lookup = { domain ->
                assertEquals("proxy.example", domain)
                listOf("192.0.2.9")
            }).use { resolver ->
                val prepared = prepareAndroidVpnConfigWithinDeadline(profile.configJson, resolver,
                    AndroidDnsBootstrapDeadline(java.util.concurrent.TimeUnit.SECONDS.toNanos(5)))
                assertEquals(root.getJSONArray("outbounds").toString(), JSONObject(prepared.json).getJSONArray("outbounds").toString())
            }
            assertFalse(profile.toString().contains("synthetic"))
        }
        for (text in listOf("http://proxy.example", "https://[2001:db8::7]", "https://synthetic@proxy.example")) {
            val root = JSONObject(XrayProfileImporter.profile(text, XrayProfileFormat.Http).configJson)
            assertTrue(root.getJSONObject("dns").getJSONObject("fakeIp").getBoolean("enabled"))
        }
        for (text in listOf("http://:synthetic-secret@proxy.example", "https://synthetic-secret:p@proxy.example?allowInsecure=1")) {
            val error = assertThrows(XrayCoreException::class.java) {
                XrayProfileImporter.profile(text, XrayProfileFormat.Http)
            }
            assertFalse(error.toString().contains("synthetic-secret"))
        }
    }

    @Test fun importsSocksThroughActualJniAndRust() {
        enabled()
        assertTrue(XrayCore.ffiInfo().supportsProfileImport(XrayProfileFormat.Socks))
        val profile = XrayProfileImporter.profile(fixture("socks.txt"), XrayProfileFormat.Socks)
        assertEquals("Test ✓", profile.name)
        assertEquals("Socks.Example.", profile.serverAddress)
        val root = JSONObject(profile.configJson)
        val settings = root.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings")
        assertEquals("synthetic:user", settings.getString("user"))
        assertEquals("p@ss:+✓", settings.getString("pass"))
        assertTrue(root.getJSONObject("dns").getJSONObject("fakeIp").getBoolean("enabled"))
        assertFalse(profile.toString().contains("synthetic"))
        val base64 = XrayProfileImporter.profile("socks://c3ludGhldGljOnBhc3M=@[2001:db8::7]:1080", XrayProfileFormat.Socks)
        assertEquals("2001:db8::7", base64.serverAddress)
        assertEquals("pass", JSONObject(base64.configJson).getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getString("pass"))
        val noauth = XrayProfileImporter.profile("socks5://Og==@socks.example:1080", XrayProfileFormat.Socks)
        assertFalse(JSONObject(noauth.configJson).getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").has("user"))
        for (text in listOf("socks://synthetic-secret:@socks.example:1080", "socks5://synthetic-secret:p@socks.example:1080?security=tls")) {
            val error = assertThrows(XrayCoreException::class.java) {
                XrayProfileImporter.profile(text, XrayProfileFormat.Socks)
            }
            assertFalse(error.toString().contains("synthetic-secret"))
        }
    }
    private fun fixture(name: String): String {
        val root = generateSequence(File(requireNotNull(System.getProperty("user.dir")))) { it.parentFile }
            .first { File(it, "crates/xray-ffi/Cargo.toml").isFile }
        return File(root, "tests/fixtures/profile-import/$name").readText()
    }

    @Test fun importsBothFixturesThroughActualJniAndRust() {
        enabled()
        assertTrue(XrayCore.ffiInfo().supportsProfileImport(XrayProfileFormat.Hysteria2))
        assertTrue(XrayCore.ffiInfo().supportsProfileImport(XrayProfileFormat.Wireguard))
        val hysteria = XrayProfileImporter.profile(fixture("hysteria2.txt"), XrayProfileFormat.Hysteria2)
        assertEquals("Test ✓", hysteria.name)
        assertEquals("user:p@ss:+✓", JSONObject(hysteria.configJson).getJSONArray("outbounds").getJSONObject(0)
            .getJSONObject("streamSettings").getJSONObject("hysteriaSettings").getString("auth"))
        val wireguard = XrayProfileImporter.profile(fixture("wireguard.conf"), XrayProfileFormat.Wireguard, "Tunnel 🔑")
        assertEquals("Tunnel 🔑", wireguard.name)
        val config = JSONObject(wireguard.configJson)
        assertEquals(2, config.getJSONArray("outbounds").getJSONObject(1).getJSONObject("settings").getJSONArray("peers").length())
        val remoteDns = config.getJSONArray("outbounds").getJSONObject(1).getJSONObject("settings").getJSONArray("remoteDNS")
        assertEquals(2, remoteDns.length())
        assertEquals("192.0.2.53", remoteDns.getString(0))
        assertEquals("2001:db8::53", remoteDns.getString(1))
        assertFalse(config.getJSONObject("dns").has("fakeIp"))
    }

    @Test fun importsTrojanThroughActualJniAndRust() {
        enabled()
        assertTrue(XrayCore.ffiInfo().supportsProfileImport(XrayProfileFormat.Trojan))
        val profile = XrayProfileImporter.profile("trojan://synthetic%3Apass+word@trojan.example?type=ws&path=%2Ftrojan#Test%20%E2%9C%93", XrayProfileFormat.Trojan)
        assertEquals("Test ✓", profile.name)
        assertEquals("trojan.example", profile.serverAddress)
        val root = JSONObject(profile.configJson)
        assertEquals("synthetic:pass+word", root.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getString("password"))
        assertFalse(profile.toString().contains("synthetic"))
    }

    @Test fun importsVmessThroughActualJniAndRust() {
        enabled()
        assertTrue(XrayCore.ffiInfo().supportsProfileImport(XrayProfileFormat.Vmess))
        val profile = XrayProfileImporter.profile("vmess://00112233-4455-6677-8899-aabbccddeeff@vmess.example?type=ws&path=%2Fvmess#Test%20%E2%9C%93", XrayProfileFormat.Vmess)
        assertEquals("Test ✓", profile.name)
        assertEquals("vmess.example", profile.serverAddress)
        val root = JSONObject(profile.configJson)
        assertEquals("00112233-4455-6677-8899-aabbccddeeff", root.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getString("id"))
        assertFalse(profile.toString().contains("00112233"))
    }

    @Test fun importsShadowsocks2022ThroughActualJniAndRust() {
        enabled()
        assertTrue(XrayCore.ffiInfo().supportsProfileImport(XrayProfileFormat.Shadowsocks2022))
        val profile = XrayProfileImporter.profile("ss://2022-blake3-aes-128-gcm:AQEBAQEBAQEBAQEBAQEBAQ==@ss2022.example:8388#Test%20%E2%9C%93", XrayProfileFormat.Shadowsocks2022)
        assertEquals("Test ✓", profile.name)
        assertEquals("ss2022.example", profile.serverAddress)
        val root = JSONObject(profile.configJson)
        assertEquals("AQEBAQEBAQEBAQEBAQEBAQ==", root.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getString("password"))
        assertFalse(profile.toString().contains("AQEB"))
    }

    @Test fun actualJniErrorsAreRedactedAndDoNotPoisonSubsequentImports() {
        enabled()
        for (text in listOf("hy2://secret@server.example?insecure=1", "hy2://secret%00@server.example")) {
            val error = assertThrows(XrayCoreException::class.java) {
                XrayProfileImporter.profile(text, XrayProfileFormat.Hysteria2)
            }
            assertFalse(error.toString().contains("secret"))
        }
        assertEquals("Test ✓", XrayProfileImporter.profile(fixture("hysteria2.txt"), XrayProfileFormat.Hysteria2).name)
    }
}
