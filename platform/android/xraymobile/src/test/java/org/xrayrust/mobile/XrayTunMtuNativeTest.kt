package org.xrayrust.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Optional host JNI check of the ABI 1.16 TUN MTU option against the current native library. */
class XrayTunMtuNativeTest {
    @Test
    fun hostMtuReachesTheCoreAndSizesPacketPolls() {
        assumeTrue(java.lang.Boolean.getBoolean("xray.test.nativeImport"))
        assertTrue(XrayCore.ffiInfo().supports(XrayFfiCapability.TunMtu))
        assertEquals(9_000, XrayCore.supportedTunMtu(9_000))

        XrayCore.create(FREEDOM_CONFIG).use { assertEquals(XrayTunInterface.MTU, it.tunMtu) }
        XrayCore.create(FREEDOM_CONFIG, tunMtu = 9_000).use { core ->
            assertEquals(9_000, core.tunMtu)
            core.start()
            val packet = ipv4Header(totalLength = 9_000)
            core.pushPacket(packet)
            core.stop()
        }
    }

    @Test
    fun mtuOutsideTheRangeIsRejectedBeforeTheCoreExists() {
        assumeTrue(java.lang.Boolean.getBoolean("xray.test.nativeImport"))
        for (mtu in listOf(0, 576, XrayTunInterface.MIN_MTU - 1, XrayTunInterface.MAX_MTU + 1)) {
            assertThrows(IllegalArgumentException::class.java) { XrayCore.supportedTunMtu(mtu) }
        }
        assertThrows(IllegalArgumentException::class.java) {
            XrayCore.create(FREEDOM_CONFIG, tunMtu = XrayTunInterface.MAX_MTU + 1)
        }
    }

    private fun ipv4Header(totalLength: Int) = ByteArray(totalLength).apply {
        this[0] = 0x45
        this[2] = (totalLength shr 8).toByte()
        this[3] = totalLength.toByte()
        this[8] = 64
        this[9] = 17
    }

    private companion object {
        const val FREEDOM_CONFIG = """{
            "inbounds": [{"tag": "tun-in", "protocol": "tun"}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        }"""
    }
}
