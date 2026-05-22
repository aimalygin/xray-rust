package org.xrayrust.mobile

import android.net.VpnService
import java.io.Closeable

class XrayCore private constructor(private var nativeHandle: Long) : Closeable {
    companion object {
        init {
            System.loadLibrary("xray_ffi")
            System.loadLibrary("xray_mobile_jni")
        }

        fun create(configJson: String, vpnService: VpnService? = null): XrayCore {
            val core = XrayCore(nativeNew())
            try {
                if (vpnService != null) {
                    core.setSocketProtector(SocketProtector(vpnService))
                }
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

    private fun requireHandle(): Long {
        check(nativeHandle != 0L) { "xray core is closed" }
        return nativeHandle
    }

    private external fun nativeLoadConfig(handle: Long, configJson: String)
    private external fun nativeStart(handle: Long)
    private external fun nativeStop(handle: Long)
    private external fun nativeFree(handle: Long)
    private external fun nativeSetSocketProtector(handle: Long, protector: SocketProtector)
    private external fun nativePushPacket(handle: Long, packet: ByteArray)
    private external fun nativePollPacket(handle: Long, maxBytes: Int): ByteArray?
    private external fun nativeStats(handle: Long): LongArray
}

data class XrayTunStats(
    val inboundPackets: Long,
    val outboundPackets: Long,
    val droppedPackets: Long,
)

class XrayCoreException(
    val code: Int,
    message: String,
) : RuntimeException(message)

class SocketProtector(private val vpnService: VpnService) {
    fun protect(fd: Int): Boolean = vpnService.protect(fd)
}
