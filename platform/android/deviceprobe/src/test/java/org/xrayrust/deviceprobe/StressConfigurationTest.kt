package org.xrayrust.deviceprobe

import org.junit.Assert.assertThrows
import org.junit.Test

class StressConfigurationTest {
    @Test
    fun acceptsDefaultAndExplicitBoundedConfiguration() {
        StressConfiguration(1, 240, 480, 32)
        StressConfiguration(1, 240, 0, 32)
        StressConfiguration(1, 0, 480, 32)
        StressConfiguration(1_000, 2_000, 2_000, 64)
    }

    @Test
    fun rejectsUnboundedConfiguration() {
        assertThrows(IllegalArgumentException::class.java) {
            StressConfiguration(0, 1, 1, 1)
        }
        assertThrows(IllegalArgumentException::class.java) {
            StressConfiguration(1, -1, 1, 1)
        }
        assertThrows(IllegalArgumentException::class.java) {
            StressConfiguration(1, 1, 2_001, 1)
        }
        assertThrows(IllegalArgumentException::class.java) {
            StressConfiguration(1, 1, 1, 65)
        }
        assertThrows(IllegalArgumentException::class.java) {
            StressConfiguration(1, 0, 0, 1)
        }
    }
}
