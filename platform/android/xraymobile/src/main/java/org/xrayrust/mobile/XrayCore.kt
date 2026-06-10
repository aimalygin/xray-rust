package org.xrayrust.mobile

import android.net.VpnService
import java.io.Closeable

class XrayCore private constructor(private var nativeHandle: Long) : Closeable {
    companion object {
        init {
            System.loadLibrary("xray_ffi")
            System.loadLibrary("xray_mobile_jni")
        }

        fun create(
            configJson: String,
            vpnService: VpnService? = null,
            tunFileDescriptor: XrayTunFileDescriptor? = null,
            collectTcpTimings: Boolean = false,
            tunRuntimeProfile: XrayTunRuntimeProfile = XrayTunRuntimeProfile.Default,
        ): XrayCore {
            val core = XrayCore(nativeNew())
            try {
                if (vpnService != null) {
                    core.setSocketProtector(SocketProtector(vpnService))
                }
                if (tunFileDescriptor != null) {
                    core.setTunFd(tunFileDescriptor)
                }
                core.setTunCollectTcpTimings(collectTcpTimings)
                core.setTunRuntimeProfile(tunRuntimeProfile)
                core.loadConfig(configJson)
                return core
            } catch (error: Throwable) {
                core.close()
                throw error
            }
        }

        @JvmStatic
        private external fun nativeNew(): Long
    }

    fun start() = nativeStart(requireHandle())

    fun stop() = nativeStop(requireHandle())

    fun pushPacket(packet: ByteArray) = nativePushPacket(requireHandle(), packet)

    fun pollPacket(maxBytes: Int = 65_535): ByteArray? = nativePollPacket(requireHandle(), maxBytes)

    fun stats(): XrayTunStats {
        val raw = nativeStats(requireHandle())
        return XrayTunStats(
            inboundPackets = raw[0],
            outboundPackets = raw[1],
            droppedPackets = raw[2],
            udpRemoteOpenEvents = raw[3],
            udpRemoteUdp443OpenEvents = raw[4],
            udpRemoteWrittenBytes = raw[5],
            udpRemoteReadBytes = raw[6],
            tcpOpenEvents = raw[7],
            tcpOpenDurationMsTotal = raw[8],
            tcpOpenDurationMsMax = raw[9],
            tcpFirstByteEvents = raw[10],
            tcpFirstByteDurationMsTotal = raw[11],
            tcpFirstByteDurationMsMax = raw[12],
            tcp443OpenEvents = raw[13],
            tcp443OpenDurationMsTotal = raw[14],
            tcp443OpenDurationMsMax = raw[15],
            tcp443FirstByteEvents = raw[16],
            tcp443FirstByteDurationMsTotal = raw[17],
            tcp443FirstByteDurationMsMax = raw[18],
        )
    }

    override fun close() {
        val handle = nativeHandle
        if (handle == 0L) {
            return
        }

        nativeHandle = 0L
        nativeFree(handle)
    }

    private fun loadConfig(configJson: String) = nativeLoadConfig(requireHandle(), configJson)

    private fun setSocketProtector(protector: SocketProtector) {
        nativeSetSocketProtector(requireHandle(), protector)
    }

    private fun setTunFd(tunFileDescriptor: XrayTunFileDescriptor) {
        nativeSetTunFd(
            requireHandle(),
            tunFileDescriptor.fd,
            tunFileDescriptor.packetFormat.ffiValue,
            tunFileDescriptor.closePolicy.ffiValue,
        )
    }

    private fun setTunRuntimeProfile(profile: XrayTunRuntimeProfile) {
        nativeSetTunRuntimeProfile(requireHandle(), profile.ffiValue)
    }

    private fun setTunCollectTcpTimings(collect: Boolean) {
        nativeSetTunCollectTcpTimings(requireHandle(), collect)
    }

    private fun requireHandle(): Long {
        check(nativeHandle != 0L) { "xray core is closed" }
        return nativeHandle
    }

    private external fun nativeLoadConfig(handle: Long, configJson: String)
    private external fun nativeStart(handle: Long)
    private external fun nativeStop(handle: Long)
    private external fun nativeFree(handle: Long)
    private external fun nativeSetSocketProtector(handle: Long, protector: SocketProtector)
    private external fun nativeSetTunFd(
        handle: Long,
        fd: Int,
        packetFormat: Int,
        closePolicy: Int,
    )
    private external fun nativeSetTunRuntimeProfile(handle: Long, profile: Int)
    private external fun nativeSetTunCollectTcpTimings(handle: Long, collect: Boolean)
    private external fun nativePushPacket(handle: Long, packet: ByteArray)
    private external fun nativePollPacket(handle: Long, maxBytes: Int): ByteArray?
    private external fun nativeStats(handle: Long): LongArray
}

data class XrayTunFileDescriptor(
    val fd: Int,
    val packetFormat: XrayTunFdPacketFormat = XrayTunFdPacketFormat.RawIp,
    val closePolicy: XrayTunFdClosePolicy = XrayTunFdClosePolicy.Borrowed,
)

enum class XrayTunFdPacketFormat(val ffiValue: Int) {
    RawIp(0),
    DarwinUtun(1),
}

enum class XrayTunFdClosePolicy(val ffiValue: Int) {
    Borrowed(0),
    Owned(1),
}

enum class XrayTunRuntimeProfile(val ffiValue: Int) {
    Default(0),
    Mobile(1),
    Desktop(2),
    LowMemory(3),
    Throughput(4),
}

data class XrayTunStats(
    val inboundPackets: Long,
    val outboundPackets: Long,
    val droppedPackets: Long,
    val udpRemoteOpenEvents: Long,
    val udpRemoteUdp443OpenEvents: Long,
    val udpRemoteWrittenBytes: Long,
    val udpRemoteReadBytes: Long,
    val tcpOpenEvents: Long,
    val tcpOpenDurationMsTotal: Long,
    val tcpOpenDurationMsMax: Long,
    val tcpFirstByteEvents: Long,
    val tcpFirstByteDurationMsTotal: Long,
    val tcpFirstByteDurationMsMax: Long,
    val tcp443OpenEvents: Long,
    val tcp443OpenDurationMsTotal: Long,
    val tcp443OpenDurationMsMax: Long,
    val tcp443FirstByteEvents: Long,
    val tcp443FirstByteDurationMsTotal: Long,
    val tcp443FirstByteDurationMsMax: Long,
)

class XrayCoreException(
    val code: Int,
    message: String,
) : RuntimeException(message)

class SocketProtector(private val vpnService: VpnService) {
    fun protect(fd: Int): Boolean = vpnService.protect(fd)
}
