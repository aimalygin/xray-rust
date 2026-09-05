package org.xrayrust.mobile

import org.json.JSONObject
import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class XrayVlessEncryptionTest {
    private fun normalized(value: Any): Any = when (value) {
        is JSONObject -> value.keys().asSequence().associateWith { normalized(value.get(it)) }
        is JSONArray -> (0 until value.length()).map { normalized(value.get(it)) }
        else -> value
    }

    @Test
    fun sessionChainAndPaddingBounds() {
        val key = "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        listOf(
            "mlkem768x25519plus.native.0rtt.$key",
            "mlkem768x25519plus.random.1rtt.100-35-64.100-0-1000.50-128-512.$key.$key",
        ).forEach { assertTrue(it, XrayVlessEncryption.isSupported(it)) }
        listOf(
            "mlkem768x25519plus.native.1rtt.99-35-35.$key",
            "mlkem768x25519plus.native.1rtt.100-34-35.$key",
            "mlkem768x25519plus.native.1rtt.100-35-35.100-0-1001.$key",
            "mlkem768x25519plus.native.1rtt.100-35-65554.$key",
            "mlkem768x25519plus.native.1rtt.${List(9) { key }.joinToString(".")}",
            "mlkem768x25519plus.native.1rtt.${List(33) { "100-35-35" }.joinToString(".")}.$key",
        ).forEach { assertFalse(it, XrayVlessEncryption.isSupported(it)) }
    }

    @Test
    fun sharedKeyAndProfileFixtures() {
        val root = generateSequence(File(requireNotNull(System.getProperty("user.dir")))) { it.parentFile }
            .first { File(it, "tests/fixtures/vless-encryption/imports.json").isFile }
        val fixture = JSONObject(File(root, "tests/fixtures/vless-encryption/imports.json").readText())
        val keys = fixture.getJSONArray("keys")
        for (i in 0 until keys.length()) {
            val test = keys.getJSONObject(i)
            assertEquals(test.getString("name"), test.getBoolean("accepted"), XrayVlessEncryption.isSupported(test.getString("encryption")))
        }
        val profiles = fixture.getJSONArray("profiles")
        for (i in 0 until profiles.length()) {
            val test = profiles.getJSONObject(i)
            if (test.has("errorParameter")) {
                val error = assertThrows(test.getString("name"), XrayVlessUrlImportException::class.java) {
                    XrayVlessUrlImporter.profile(test.getString("url"))
                }
                assertEquals(test.getString("name"), test.getString("errorParameter"), error.parameter)
                if (error.parameter == "encryption") assertEquals("<redacted>", error.rejectedValue)
            } else {
                val profile = XrayVlessUrlImporter.profile(test.getString("url"))
                val actual = JSONObject(profile.configJson).getJSONArray("outbounds").getJSONObject(0)
                assertEquals(test.getString("name"), normalized(test.getJSONObject("outbound")), normalized(actual))
                assertEquals("encrypted-profile", profile.name)
            }
        }
    }
}
