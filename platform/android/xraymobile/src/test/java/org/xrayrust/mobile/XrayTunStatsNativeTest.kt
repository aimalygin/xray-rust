package org.xrayrust.mobile

import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Optional host JNI check that the native stats carrier matches the Kotlin decoder. */
class XrayTunStatsNativeTest {
    @Test
    fun freshCoreReportsZeroLiveTrafficThroughActualJni() {
        assumeTrue(java.lang.Boolean.getBoolean("xray.test.nativeImport"))
        XrayCore.create(FREEDOM_CONFIG).use { core ->
            val stats = core.stats()
            assertEquals(0L, stats.tcpRemoteWrittenBytes)
            assertEquals(0L, stats.tcpRemoteReadBytes)
            assertEquals(0L, stats.uplinkBytes)
            assertEquals(0L, stats.downlinkBytes)
        }
    }

    private companion object {
        const val FREEDOM_CONFIG = """{"outbounds": [{"tag": "direct", "protocol": "freedom"}]}"""
    }
}
