package org.xrayrust.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class XrayTunStatsTest {
    @Test
    fun decodesNativeStatsInAbiFieldOrder() {
        val stats = tunStatsFromNative(LongArray(NATIVE_TUN_STATS_VALUE_COUNT) { it + 1L })

        assertEquals(1L, stats.inboundPackets)
        assertEquals(3L, stats.droppedPackets)
        assertEquals(8L, stats.tcpOpenEvents)
        assertEquals(14L, stats.tcp443OpenEvents)
        assertEquals(19L, stats.tcp443FirstByteDurationMsMax)
    }

    @Test
    fun rejectsUnexpectedNativeStatsSize() {
        for (size in listOf(0, NATIVE_TUN_STATS_VALUE_COUNT - 1, NATIVE_TUN_STATS_VALUE_COUNT + 1)) {
            assertThrows(IllegalStateException::class.java) {
                tunStatsFromNative(LongArray(size))
            }
        }
    }
}
