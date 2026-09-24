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
        assertFalse(config.getJSONObject("dns").has("fakeIp"))
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
