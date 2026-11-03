package org.xrayrust.mobile

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

class XrayTunInterfaceTest {
    @Test
    fun mtuBoundsMatchTheCoreTunMtu() {
        val lib = "crates/xray-core-rs/src/lib.rs"
        assertEquals(rustConstant(lib, """pub const DEFAULT: Self = Self\((\d+)\);""").toInt(), XrayTunInterface.MTU)
        assertEquals(rustConstant(lib, """pub const MIN: u32 = (\d+);""").toInt(), XrayTunInterface.MIN_MTU)
        assertEquals(rustConstant(lib, """pub const MAX: u32 = (\d+);""").toInt(), XrayTunInterface.MAX_MTU)
    }

    @Test
    fun dnsAnchorMatchesTheCoreTunDnsAnchor() {
        val octets = rustConstant(
            "crates/xray-core-rs/src/tun.rs",
            """const TUN_DNS_ANCHOR: Ipv4Addr = Ipv4Addr::new\((\d+), (\d+), (\d+), (\d+)\);""",
        )
        assertEquals(octets, XrayTunInterface.DNS_ANCHOR)
    }

    private fun rustConstant(path: String, pattern: String): String {
        val root = generateSequence(File(requireNotNull(System.getProperty("user.dir")))) { it.parentFile }
            .first { File(it, "crates/xray-ffi/Cargo.toml").isFile }
        val match = requireNotNull(Regex(pattern).find(File(root, path).readText())) {
            "$path no longer declares the constant matched by $pattern"
        }
        return match.groupValues.drop(1).joinToString(".")
    }
}
