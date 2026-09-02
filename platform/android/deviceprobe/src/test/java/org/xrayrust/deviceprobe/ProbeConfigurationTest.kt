package org.xrayrust.deviceprobe

import org.junit.Assert.assertThrows
import org.junit.Test

class ProbeConfigurationTest {
    @Test
    fun acceptsBoundedHttpAndUdpConfiguration() {
        ProbeConfiguration("https://example.test/probe", "echo.test", 53, 5)
        ProbeConfiguration("http://192.0.2.1/", "192.0.2.2", 65535, 60)
    }

    @Test
    fun rejectsUnsafeOrUnboundedConfiguration() {
        assertThrows(IllegalArgumentException::class.java) {
            ProbeConfiguration("file:///tmp/probe", "echo.test", 53, 5)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProbeConfiguration("https://example.test", "", 53, 5)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProbeConfiguration("https://example.test", "echo.test", 0, 5)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProbeConfiguration("https://example.test", "echo.test", 53, 61)
        }
    }
}
