package org.xrayrust.mobile

import android.net.VpnService
import android.util.Log
import java.io.Closeable
import java.nio.ByteBuffer
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

class XrayCore private constructor(handle: Long) : Closeable {
    private val lifecycleLock = ReentrantReadWriteLock(true)
    private var nativeHandle: Long = handle

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
            startupProbe: XrayStartupProbeOptions? = null,
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
                if (startupProbe != null) {
                    core.setStartupProbe(startupProbe)
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

    fun start() = withLifecycleHandle { nativeStart(it) }

    fun stop() = withLifecycleHandle { nativeStop(it) }

    fun pushPacket(packet: ByteArray, length: Int = packet.size) {
        require(length in 0..packet.size) { "packet length is outside the source buffer" }
        withDataPathHandle { nativePushPacket(it, packet, length) }
    }

    fun pollPacket(maxBytes: Int = 1_500): ByteArray? {
        require(maxBytes > 0) { "maxBytes must be positive" }
        val storage = ByteBuffer.allocateDirect(maxBytes)
        val lengths = IntArray(1)
        val count = pollPacketsInto(
            storage = storage,
            lengths = lengths,
            maxPacketBytes = maxBytes,
            waitMilliseconds = 0,
        )
        if (count == 0) {
            return null
        }
        return ByteArray(lengths[0]).also {
            storage.position(0)
            storage.get(it)
        }
    }

    fun pollPacketsInto(
        storage: ByteBuffer,
        lengths: IntArray,
        maxPacketBytes: Int = 1_500,
        waitMilliseconds: Int = 250,
    ): Int {
        require(storage.isDirect) { "packet storage must be a direct ByteBuffer" }
        require(lengths.isNotEmpty()) { "lengths must not be empty" }
        require(maxPacketBytes > 0) { "maxPacketBytes must be positive" }
        require(waitMilliseconds >= 0) { "waitMilliseconds must not be negative" }
        require(
            storage.capacity().toLong() >= lengths.size.toLong() * maxPacketBytes.toLong(),
        ) {
            "packet storage is smaller than lengths.size * maxPacketBytes"
        }
        storage.clear()
        return withDataPathHandle {
            nativePollPackets(
                handle = it,
                storage = storage,
                lengths = lengths,
                maxPacketBytes = maxPacketBytes,
                waitMilliseconds = waitMilliseconds,
            )
        }
    }

    fun stats(): XrayTunStats {
        val raw = withDataPathHandle { nativeStats(it) }
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
        // Zero the handle under the write lock so no concurrent data-path caller can observe
        // (and pass to native code) a handle that is about to be freed.
        val handle = lifecycleLock.write {
            val current = nativeHandle
            nativeHandle = 0L
            current
        }
        if (handle != 0L) {
            nativeFree(handle)
        }
    }

    private fun loadConfig(configJson: String) = withLifecycleHandle {
        nativeLoadConfig(it, configJson)
        nativeConfigWarnings(it)?.lineSequence()
            ?.filter { warning -> warning.isNotBlank() }
            ?.forEach { warning -> Log.w("XrayCore", "Config warning: $warning") }
    }

    private fun setSocketProtector(protector: SocketProtector) {
        withLifecycleHandle { nativeSetSocketProtector(it, protector) }
    }

    private fun setTunFd(tunFileDescriptor: XrayTunFileDescriptor) {
        withLifecycleHandle {
            nativeSetTunFd(
                it,
                tunFileDescriptor.fd,
                tunFileDescriptor.packetFormat.ffiValue,
                tunFileDescriptor.closePolicy.ffiValue,
            )
        }
    }

    private fun setTunRuntimeProfile(profile: XrayTunRuntimeProfile) {
        withLifecycleHandle { nativeSetTunRuntimeProfile(it, profile.ffiValue) }
    }

    private fun setTunCollectTcpTimings(collect: Boolean) {
        withLifecycleHandle { nativeSetTunCollectTcpTimings(it, collect) }
    }

    private fun setStartupProbe(startupProbe: XrayStartupProbeOptions) {
        withLifecycleHandle {
            nativeSetStartupProbe(
                it,
                startupProbe.url,
                startupProbe.timeoutMs,
                startupProbe.outboundTag,
            )
        }
    }

    private inline fun <T> withLifecycleHandle(block: (Long) -> T): T =
        lifecycleLock.write {
            check(nativeHandle != 0L) { "xray core is closed" }
            block(nativeHandle)
        }

    private inline fun <T> withDataPathHandle(block: (Long) -> T): T =
        lifecycleLock.read {
            check(nativeHandle != 0L) { "xray core is closed" }
            block(nativeHandle)
        }

    private external fun nativeLoadConfig(handle: Long, configJson: String)
    private external fun nativeConfigWarnings(handle: Long): String?
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
    private external fun nativeSetStartupProbe(
        handle: Long,
        url: String,
        timeoutMs: Long,
        outboundTag: String?,
    )
    private external fun nativePushPacket(handle: Long, packet: ByteArray, length: Int)
    private external fun nativePollPackets(
        handle: Long,
        storage: ByteBuffer,
        lengths: IntArray,
        maxPacketBytes: Int,
        waitMilliseconds: Int,
    ): Int
    private external fun nativeStats(handle: Long): LongArray
}

data class XrayStartupProbeOptions(
    val url: String,
    val timeoutMs: Long = 5_000,
    val outboundTag: String? = null,
) {
    init {
        require(url.isNotEmpty()) { "startup probe URL must not be empty" }
        require(timeoutMs > 0) { "startup probe timeout must be positive" }
    }
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
    MobilePlus(5),
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
