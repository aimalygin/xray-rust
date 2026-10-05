package org.xrayrust.devicehost

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.xrayrust.mobile.XrayProfileFormat
import org.xrayrust.mobile.XrayTunBackend

class DeviceGateOptionsTest {
    @Test fun defaultsToExistingBackendAndExplicitlySelectsBothPaths() {
        assertEquals(XrayTunBackend.FileDescriptor, DeviceGateOptions.backend(null))
        for ((name, backend) in listOf(
            "file-descriptor" to XrayTunBackend.FileDescriptor,
            "packet-pump" to XrayTunBackend.PacketPump,
        )) {
            assertEquals(backend, DeviceGateOptions.backend(name))
            assertEquals(name, DeviceGateOptions.backendName(backend))
        }
    }

    @Test fun unknownBackendCannotSilentlyBecomeFileDescriptor() {
        for (value in listOf("", "PacketPump", "packet-pump-typo")) {
            assertThrows(IllegalArgumentException::class.java) { DeviceGateOptions.backend(value) }
        }
    }

    @Test fun routesProtocolLinksToTheExistingImporters() {
        assertNull(DeviceGateOptions.profileFormat("vless://example"))
        for ((scheme, format) in listOf(
            "trojan" to XrayProfileFormat.Trojan,
            "ss" to XrayProfileFormat.Shadowsocks2022,
            "vmess" to XrayProfileFormat.Vmess,
            "hysteria2" to XrayProfileFormat.Hysteria2,
            "hy2" to XrayProfileFormat.Hysteria2,
        )) {
            assertEquals(format, DeviceGateOptions.profileFormat("$scheme://example"))
        }
    }

    @Test fun invalidInputIsRejectedWithoutEchoingCredentials() {
        val input = "unsupported://private-input@example.invalid"
        val error = assertThrows(IllegalArgumentException::class.java) {
            DeviceGateOptions.profileFormat(input)
        }
        assertFalse(error.message.orEmpty().contains("private-input"))
        assertThrows(IllegalArgumentException::class.java) { DeviceGateOptions.profileFormat("vmess") }
    }
}
