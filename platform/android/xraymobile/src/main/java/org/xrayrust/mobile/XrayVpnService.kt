package org.xrayrust.mobile

import android.content.pm.PackageManager.NameNotFoundException
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean

enum class XrayTunBackend {
    PacketPump,
    FileDescriptor,
}

open class XrayVpnService : VpnService() {
    private val running = AtomicBoolean(false)
    private var core: XrayCore? = null
    private var tun: ParcelFileDescriptor? = null
    private var inboundThread: Thread? = null
    private var outboundThread: Thread? = null

    open fun startXrayTunnel(
        configJson: String,
        tunBackend: XrayTunBackend = XrayTunBackend.PacketPump,
        tunRuntimeProfile: XrayTunRuntimeProfile = XrayTunRuntimeProfile.Default,
    ) {
        if (!running.compareAndSet(false, true)) {
            return
        }

        val tunnel = buildTunnel().establish()
            ?: error("failed to establish Android VPN tunnel")
        val xrayCore = XrayCore.create(
            configJson = configJson,
            vpnService = this,
            tunRuntimeProfile = tunRuntimeProfile,
            tunFileDescriptor = when (tunBackend) {
                XrayTunBackend.PacketPump -> null
                XrayTunBackend.FileDescriptor -> XrayTunFileDescriptor(
                    fd = tunnel.fd,
                    packetFormat = XrayTunFdPacketFormat.RawIp,
                    closePolicy = XrayTunFdClosePolicy.Borrowed,
                )
            },
        )
        xrayCore.start()

        tun = tunnel
        core = xrayCore
        if (tunBackend == XrayTunBackend.PacketPump) {
            inboundThread = Thread({ readTunPackets(tunnel, xrayCore) }, "xray-tun-in").also {
                it.start()
            }
            outboundThread = Thread({ writeTunPackets(tunnel, xrayCore) }, "xray-tun-out").also {
                it.start()
            }
        }
    }

    open fun stopXrayTunnel() {
        if (!running.compareAndSet(true, false)) {
            return
        }

        inboundThread?.interrupt()
        outboundThread?.interrupt()
        inboundThread = null
        outboundThread = null
        tun?.close()
        tun = null
        core?.close()
        core = null
    }

    fun protectSocket(fd: Int): Boolean = protect(fd)

    override fun onDestroy() {
        stopXrayTunnel()
        super.onDestroy()
    }

    protected open fun buildTunnel(): Builder {
        val builder = Builder()
            .setSession("xray-rust")
            .setMtu(1500)
            .addAddress("10.7.0.1", 32)
            .addRoute("0.0.0.0", 0)
            .addAddress("fd00:7872::1", 128)
            .addRoute("::", 0)
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: NameNotFoundException) {
            // Some host/test contexts may not expose the package to PackageManager.
        }
        return builder
    }

    private fun readTunPackets(tunnel: ParcelFileDescriptor, xrayCore: XrayCore) {
        val input = FileInputStream(tunnel.fileDescriptor)
        val packetBuffer = ByteArray(65_535)

        while (running.get() && !Thread.currentThread().isInterrupted) {
            val read = try {
                input.read(packetBuffer)
            } catch (_: Throwable) {
                break
            }
            if (read > 0) {
                xrayCore.pushPacket(packetBuffer.copyOf(read))
            }
        }
    }

    private fun writeTunPackets(tunnel: ParcelFileDescriptor, xrayCore: XrayCore) {
        val output = FileOutputStream(tunnel.fileDescriptor)

        while (running.get() && !Thread.currentThread().isInterrupted) {
            var wrotePacket = false
            while (running.get()) {
                val packet = xrayCore.pollPacket() ?: break
                output.write(packet)
                wrotePacket = true
            }

            if (!wrotePacket) {
                Thread.sleep(5)
            }
        }
    }
}
