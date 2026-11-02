package org.xrayrust.mobile

import android.net.VpnService

/**
 * Android VPN interface values shared by the Rust core and the reference [XrayVpnService], for
 * hosts that establish the interface themselves.
 *
 * [MTU] is the default TUN MTU of the core. A host may pick another in [MIN_MTU]..[MAX_MTU]
 * with [XrayCore.supportedTunMtu] and must give the interface and [XrayCore.create] that same
 * value: the core drops TUN packets longer than its MTU. The core answers DNS at [DNS_ANCHOR] only
 * when the config enables `dns.fakeIp` or a non-empty `dns.servers` list. The interface addresses
 * are the reference service's choice; the core does not depend on them.
 */
object XrayTunInterface {
    const val IPV4_ADDRESS = "10.7.0.1"
    const val IPV4_PREFIX_LENGTH = 32
    const val IPV6_ADDRESS = "fd00:7872::1"
    const val IPV6_PREFIX_LENGTH = 128
    const val DNS_ANCHOR = "198.18.0.1"
    const val MTU = 1_500
    const val MIN_MTU = 1_280
    const val MAX_MTU = 9_000
}

/**
 * Sets [mtu] and both interface addresses as [XrayVpnService] does, and adds
 * [XrayTunInterface.DNS_ANCHOR] as the DNS server when [dnsAnchor] is true. Pass true only when the
 * config enables the core's local DNS endpoint; otherwise lookups sent to the anchor fail. Routes,
 * session name, metering and application rules stay with the caller.
 */
fun VpnService.Builder.applyXrayTunInterface(
    dnsAnchor: Boolean,
    mtu: Int = XrayTunInterface.MTU,
): VpnService.Builder = apply {
    setMtu(mtu)
    addAddress(XrayTunInterface.IPV4_ADDRESS, XrayTunInterface.IPV4_PREFIX_LENGTH)
    addAddress(XrayTunInterface.IPV6_ADDRESS, XrayTunInterface.IPV6_PREFIX_LENGTH)
    if (dnsAnchor) addDnsServer(XrayTunInterface.DNS_ANCHOR)
}
