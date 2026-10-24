package org.xrayrust.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files

class XrayGeodataNativeTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    private fun nativeAvailable() = assumeTrue(java.lang.Boolean.getBoolean("xray.test.nativeImport"))

    @Test
    fun directoryPathRequiresAnExistingDirectory() {
        val directory = temporaryFolder.newFolder("geodata")
        assertEquals(directory.absolutePath, geodataSearchDirectoryPath(directory))
        val missing = File(directory, "missing")
        val regularFile = File(directory, "geosite.dat").apply { writeBytes(geositeData()) }
        for (invalid in listOf(missing, regularFile)) {
            assertThrows(IllegalArgumentException::class.java) { geodataSearchDirectoryPath(invalid) }
        }
    }

    @Test
    fun policyMapsToTheExclusiveNativeFlag() {
        assertTrue(XrayGeodataSearchPolicy.Exclusive.exclusive)
        assertFalse(XrayGeodataSearchPolicy.FallbackToDefaults.exclusive)
    }

    @Test
    fun directoryCompilesGeositeAndGeoipRulesUnderEitherPolicy() {
        nativeAvailable()
        assertTrue(XrayCore.ffiInfo().supports(XrayFfiCapability.GeodataSearch))
        val directory = geodataDirectory()
        for (policy in XrayGeodataSearchPolicy.entries) {
            XrayCore.create(
                GEODATA_CONFIG,
                geodataSearchDirectory = directory,
                geodataSearchPolicy = policy,
            ).use { core ->
                assertEquals(2, core.routingPolicySnapshot().ruleCount)
            }
        }
    }

    @Test
    fun missingGeodataFileFailsConfigLoad() {
        nativeAvailable()
        val directory = geodataDirectory()
        assertTrue(File(directory, "geoip.dat").delete())
        val error = assertThrows(XrayCoreException::class.java) {
            XrayCore.create(GEODATA_CONFIG, geodataSearchDirectory = directory)
        }
        assertEquals(CONFIG_ERROR, error.code)
        assertTrue(error.message.orEmpty(), error.message.orEmpty().contains("geoip.dat"))
    }

    @Test
    fun missingDirectoryIsRejectedBeforeConfigLoad() {
        nativeAvailable()
        val missing = File(temporaryFolder.root, "missing")
        assertThrows(IllegalArgumentException::class.java) {
            XrayCore.create(GEODATA_CONFIG, geodataSearchDirectory = missing)
        }
    }

    @Test
    fun symlinkedDirectoryIsRejectedByTheCore() {
        nativeAvailable()
        val link = File(temporaryFolder.root, "linked-geodata")
        Files.createSymbolicLink(link.toPath(), geodataDirectory().toPath())
        val error = assertThrows(XrayCoreException::class.java) {
            XrayCore.create(GEODATA_CONFIG, geodataSearchDirectory = link)
        }
        assertEquals(CONFIG_ERROR, error.code)
    }

    @Test
    fun routingReplacementReadsTheSameDirectory() {
        nativeAvailable()
        val directory = geodataDirectory()
        XrayCore.create(DIRECT_CONFIG, geodataSearchDirectory = directory).use { core ->
            core.replaceRoutingPolicy(GEODATA_ROUTING)
            val snapshot = core.routingPolicySnapshot()
            assertEquals(1L, snapshot.revision)
            assertEquals(2, snapshot.ruleCount)

            assertTrue(File(directory, "geoip.dat").delete())
            val error = assertThrows(XrayCoreException::class.java) {
                core.replaceRoutingPolicy(GEODATA_ROUTING)
            }
            assertEquals(CONFIG_ERROR, error.code)
            assertTrue(error.message.orEmpty(), error.message.orEmpty().contains("geoip.dat"))
            assertEquals(1L, core.routingPolicySnapshot().revision)
        }
    }

    private fun geodataDirectory(): File {
        val directory = temporaryFolder.newFolder()
        File(directory, "geosite.dat").writeBytes(geositeData())
        File(directory, "geoip.dat").writeBytes(geoipData())
        return directory
    }

    private companion object {
        const val CONFIG_ERROR = 3
        const val ROOT_DOMAIN = 2

        const val GEODATA_RULES = """[
            {"type":"field","domain":["geosite:test"],"outboundTag":"direct"},
            {"type":"field","ip":["geoip:test"],"outboundTag":"direct"}]"""

        const val OUTBOUNDS = """"outbounds":[{"tag":"direct","protocol":"freedom"}]"""

        val DIRECT_CONFIG = """{$OUTBOUNDS,"routing":{"rules":[]}}"""

        val GEODATA_CONFIG = """{$OUTBOUNDS,"routing":{"rules":$GEODATA_RULES}}"""

        val GEODATA_ROUTING = """{"routing":{"rules":$GEODATA_RULES}}"""

        /** v2fly `GeoSiteList` with one synthetic `TEST` entry for `example.test`. */
        fun geositeData(): ByteArray {
            val domain = message {
                varintField(1, ROOT_DOMAIN)
                bytesField(2, "example.test".toByteArray())
            }
            val site = message {
                bytesField(1, "TEST".toByteArray())
                bytesField(2, domain)
            }
            return message { bytesField(1, site) }
        }

        /** v2fly `GeoIPList` with one synthetic `TEST` entry for RFC 5737 `192.0.2.0/24`. */
        fun geoipData(): ByteArray {
            val cidr = message {
                bytesField(1, byteArrayOf(192.toByte(), 0, 2, 0))
                varintField(2, 24)
            }
            val ip = message {
                bytesField(1, "TEST".toByteArray())
                bytesField(2, cidr)
            }
            return message { bytesField(1, ip) }
        }

        fun message(build: ByteArrayOutputStream.() -> Unit): ByteArray =
            ByteArrayOutputStream().apply(build).toByteArray()

        fun ByteArrayOutputStream.varint(value: Int) {
            var remaining = value
            while (remaining >= 0x80) {
                write(remaining and 0x7f or 0x80)
                remaining = remaining ushr 7
            }
            write(remaining)
        }

        fun ByteArrayOutputStream.varintField(number: Int, value: Int) {
            varint(number shl 3)
            varint(value)
        }

        fun ByteArrayOutputStream.bytesField(number: Int, payload: ByteArray) {
            varint(number shl 3 or 2)
            varint(payload.size)
            write(payload)
        }
    }
}
