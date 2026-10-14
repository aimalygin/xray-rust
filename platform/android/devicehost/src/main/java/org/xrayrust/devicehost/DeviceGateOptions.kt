package org.xrayrust.devicehost

import org.xrayrust.mobile.XrayProfileFormat
import org.xrayrust.mobile.XrayTunBackend
import java.util.Locale

/** Explicit test selections; diagnostics must never include raw input. */
internal object DeviceGateOptions {
    const val EXTRA_TUN_BACKEND = "tun-backend"

    fun backend(value: String?): XrayTunBackend = when (value) {
        null, "file-descriptor" -> XrayTunBackend.FileDescriptor
        "packet-pump" -> XrayTunBackend.PacketPump
        else -> throw IllegalArgumentException("unsupported test TUN backend")
    }

    fun backendName(value: XrayTunBackend): String = when (value) {
        XrayTunBackend.FileDescriptor -> "file-descriptor"
        XrayTunBackend.PacketPump -> "packet-pump"
    }

    // VLESS keeps its existing importer; other links use the shared Rust importer.
    fun profileFormat(text: String): XrayProfileFormat? {
        val schemeEnd = text.indexOf("://")
        require(schemeEnd > 0) { "unsupported test profile format" }
        return when (text.substring(0, schemeEnd).lowercase(Locale.ROOT)) {
            "vless" -> null
            "trojan" -> XrayProfileFormat.Trojan
            "ss" -> XrayProfileFormat.Shadowsocks2022
            "vmess" -> XrayProfileFormat.Vmess
            "hysteria2", "hy2" -> XrayProfileFormat.Hysteria2
            else -> throw IllegalArgumentException("unsupported test profile format")
        }
    }
}
