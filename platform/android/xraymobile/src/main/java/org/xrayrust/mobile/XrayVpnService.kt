package org.xrayrust.mobile

import android.content.pm.PackageManager.NameNotFoundException
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.EOFException
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

enum class XrayTunBackend {
    FileDescriptor,
    PacketPump,
}

internal val DEFAULT_XRAY_TUN_BACKEND = XrayTunBackend.FileDescriptor

internal class XrayTunnelStateMachine<Session> {
    class StartToken internal constructor() {
        internal var stopRequested = false
    }

    private val lock = Object()
    private var state: State<Session> = State.Stopped

    fun beginStart(): StartToken? = synchronized(lock) {
        if (state !== State.Stopped) {
            return@synchronized null
        }
        StartToken().also {
            state = State.Starting(it)
        }
    }

    fun isStartActive(token: StartToken): Boolean = synchronized(lock) {
        val current = state
        current is State.Starting &&
            current.token === token &&
            !token.stopRequested
    }

    fun publish(
        token: StartToken,
        session: Session,
        beforePublication: () -> Unit = {},
    ): Boolean = synchronized(lock) {
        val current = state
        if (current !is State.Starting ||
            current.token !== token ||
            token.stopRequested
        ) {
            return@synchronized false
        }
        try {
            beforePublication()
            state = State.Running(session)
            lock.notifyAll()
            true
        } catch (error: Throwable) {
            state = State.Stopping
            lock.notifyAll()
            throw error
        }
    }

    fun failStart(token: StartToken) {
        synchronized(lock) {
            val current = state
            if ((current is State.Starting && current.token === token) ||
                current === State.Stopping
            ) {
                state = State.Stopped
            }
            lock.notifyAll()
        }
    }

    fun takeSessionForStop(): Session? = synchronized(lock) {
        var restoreInterrupt = false
        try {
            while (true) {
                when (val current = state) {
                    State.Stopped -> return@synchronized null
                    is State.Starting -> {
                        current.token.stopRequested = true
                        try {
                            lock.wait()
                        } catch (_: InterruptedException) {
                            restoreInterrupt = true
                        }
                    }
                    is State.Running -> {
                        state = State.Stopping
                        return@synchronized current.session
                    }
                    State.Stopping -> {
                        try {
                            lock.wait()
                        } catch (_: InterruptedException) {
                            restoreInterrupt = true
                        }
                    }
                }
            }
            @Suppress("UNREACHABLE_CODE")
            null
        } finally {
            if (restoreInterrupt) {
                Thread.currentThread().interrupt()
            }
        }
    }

    fun takeSessionForFailure(failedSession: Session): Session? = synchronized(lock) {
        val current = state
        if (current !is State.Running || current.session !== failedSession) {
            return@synchronized null
        }
        state = State.Stopping
        current.session
    }

    fun isRunningSession(session: Session): Boolean = synchronized(lock) {
        val current = state
        current is State.Running && current.session === session
    }

    fun completeStop() {
        synchronized(lock) {
            state = State.Stopped
            lock.notifyAll()
        }
    }

    private sealed interface State<out Session> {
        data object Stopped : State<Nothing>
        class Starting(val token: StartToken) : State<Nothing>
        class Running<Session>(val session: Session) : State<Session>
        data object Stopping : State<Nothing>
    }
}

internal fun <Session> teardownFailedXraySession(
    lifecycle: XrayTunnelStateMachine<Session>,
    failedSession: Session,
    shutdown: (Session) -> Unit,
): Boolean {
    val session = lifecycle.takeSessionForFailure(failedSession) ?: return false
    try {
        shutdown(session)
    } finally {
        lifecycle.completeStop()
    }
    return true
}

internal fun joinXrayPumpThreadUninterruptibly(thread: Thread?) {
    if (thread == null || thread === Thread.currentThread()) {
        return
    }
    var restoreInterrupt = false
    while (thread.isAlive) {
        try {
            thread.join()
        } catch (_: InterruptedException) {
            restoreInterrupt = true
        }
    }
    if (restoreInterrupt) {
        Thread.currentThread().interrupt()
    }
}

internal fun isRecoverablePacketPushFailure(error: Throwable): Boolean =
    error is XrayCoreException

open class XrayVpnService : VpnService() {
    private val lifecycle = XrayTunnelStateMachine<TunnelSession>()

    open fun startXrayTunnel(
        configJson: String,
        tunBackend: XrayTunBackend = DEFAULT_XRAY_TUN_BACKEND,
        tunRuntimeProfile: XrayTunRuntimeProfile = XrayTunRuntimeProfile.Default,
        startupProbe: XrayStartupProbeOptions? = null,
    ) {
        val attempt = lifecycle.beginStart() ?: return

        var tunnel: ParcelFileDescriptor? = null
        var xrayCore: XrayCore? = null
        var coreStarted = false
        try {
            ensureStartIsActive(attempt)
            tunnel = buildTunnel().establish()
                ?: error("failed to establish Android VPN tunnel")
            ensureStartIsActive(attempt)

            xrayCore = XrayCore.create(
                configJson = configJson,
                vpnService = this,
                tunRuntimeProfile = tunRuntimeProfile,
                startupProbe = startupProbe,
                tunFileDescriptor = when (tunBackend) {
                    XrayTunBackend.PacketPump -> null
                    XrayTunBackend.FileDescriptor -> XrayTunFileDescriptor(
                        fd = tunnel.fd,
                        packetFormat = XrayTunFdPacketFormat.RawIp,
                        closePolicy = XrayTunFdClosePolicy.Borrowed,
                    )
                },
            )
            ensureStartIsActive(attempt)
            xrayCore.start()
            coreStarted = true
            ensureStartIsActive(attempt)

            val session = TunnelSession(
                backend = tunBackend,
                tunnel = tunnel,
                core = xrayCore,
            )
            if (tunBackend == XrayTunBackend.PacketPump) {
                session.inboundThread = Thread(
                    { readTunPackets(session) },
                    "xray-tun-in",
                )
                session.outboundThread = Thread(
                    { writeTunPackets(session) },
                    "xray-tun-out",
                )
            }

            val published = try {
                lifecycle.publish(attempt, session) {
                    session.inboundThread?.start()
                    session.outboundThread?.start()
                }
            } catch (error: Throwable) {
                runCatching { session.shutdown() }
                lifecycle.failStart(attempt)
                throw error
            }

            if (!published) {
                session.shutdown()
                lifecycle.failStart(attempt)
            }
        } catch (_: StartCancelledException) {
            cleanupUnpublishedSession(
                tunnel = tunnel,
                core = xrayCore,
                coreStarted = coreStarted,
            )
            lifecycle.failStart(attempt)
        } catch (error: Throwable) {
            cleanupUnpublishedSession(
                tunnel = tunnel,
                core = xrayCore,
                coreStarted = coreStarted,
            )
            lifecycle.failStart(attempt)
            throw error
        }
    }

    open fun stopXrayTunnel() {
        val session = lifecycle.takeSessionForStop() ?: return
        try {
            session.shutdown()
        } finally {
            lifecycle.completeStop()
        }
    }

    fun protectSocket(fd: Int): Boolean = protect(fd)

    override fun onDestroy() {
        stopXrayTunnel()
        super.onDestroy()
    }

    protected open fun buildTunnel(): Builder {
        val builder = Builder()
            .setSession("xray-rust")
            .setMtu(PACKET_BYTES)
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

    private fun ensureStartIsActive(attempt: XrayTunnelStateMachine.StartToken) {
        if (!lifecycle.isStartActive(attempt)) {
            throw StartCancelledException()
        }
    }

    private fun cleanupUnpublishedSession(
        tunnel: ParcelFileDescriptor?,
        core: XrayCore?,
        coreStarted: Boolean,
    ) {
        // For the borrowed-fd backend, Rust must finish all fd tasks before the
        // ParcelFileDescriptor can be closed or reused by the process.
        if (coreStarted) {
            runCatching { core?.stop() }
        }
        runCatching { core?.close() }
        runCatching { tunnel?.close() }
    }

    private fun readTunPackets(session: TunnelSession) {
        try {
            val input = FileInputStream(session.tunnel.fileDescriptor)
            val packetBuffer = ByteArray(PACKET_BYTES)

            while (session.active.get() && !Thread.currentThread().isInterrupted) {
                val read = input.read(packetBuffer)
                if (read < 0) {
                    throw EOFException("Android VPN tunnel reached EOF")
                }
                if (read > 0) {
                    try {
                        session.core.pushPacket(packetBuffer, read)
                    } catch (error: Throwable) {
                        // Queue saturation is currently surfaced through the same
                        // public exception as other TUN push errors. PacketTooLarge
                        // is excluded by the MTU-sized buffer, and QueueClosed also
                        // wakes the outbound poll worker with a terminal error.
                        // Therefore push-side core errors are packet drops; I/O and
                        // outbound poll/write failures own terminal teardown.
                        if (!isRecoverablePacketPushFailure(error)) {
                            throw error
                        }
                        Thread.yield()
                    }
                }
            }
        } catch (_: Throwable) {
            if (session.active.get()) {
                handlePacketPumpFailure(session)
            }
        }
    }

    private fun writeTunPackets(session: TunnelSession) {
        try {
            val output = FileOutputStream(session.tunnel.fileDescriptor)
            val storage = ByteBuffer.allocateDirect(MAX_PACKETS_PER_POLL * PACKET_BYTES)
            val lengths = IntArray(MAX_PACKETS_PER_POLL)
            val packetBuffer = ByteArray(PACKET_BYTES)

            while (session.active.get() && !Thread.currentThread().isInterrupted) {
                val packetCount = session.core.pollPacketsInto(
                    storage = storage,
                    lengths = lengths,
                    maxPacketBytes = PACKET_BYTES,
                    waitMilliseconds = POLL_WAIT_MILLISECONDS,
                )
                check(packetCount in 0..lengths.size) {
                    "native packet count exceeds the destination lengths buffer"
                }

                var offset = 0
                for (index in 0 until packetCount) {
                    if (!session.active.get()) {
                        return
                    }
                    val length = lengths[index]
                    check(length in 1..PACKET_BYTES) {
                        "native packet length is outside the packet buffer"
                    }
                    storage.position(offset)
                    storage.get(packetBuffer, 0, length)
                    output.write(packetBuffer, 0, length)
                    offset += length
                }
            }
        } catch (_: Throwable) {
            if (session.active.get()) {
                handlePacketPumpFailure(session)
            }
        }
    }

    private fun handlePacketPumpFailure(session: TunnelSession) {
        runCatching {
            teardownFailedXraySession(lifecycle, session) { it.shutdown() }
        }
    }

    private class TunnelSession(
        val backend: XrayTunBackend,
        val tunnel: ParcelFileDescriptor,
        val core: XrayCore,
    ) {
        val active = AtomicBoolean(true)
        var inboundThread: Thread? = null
        var outboundThread: Thread? = null

        fun shutdown() {
            if (!active.compareAndSet(true, false)) {
                return
            }

            var firstFailure: Throwable? = null
            fun capture(block: () -> Unit) {
                try {
                    block()
                } catch (error: Throwable) {
                    if (firstFailure == null) {
                        firstFailure = error
                    }
                }
            }

            inboundThread?.interrupt()
            outboundThread?.interrupt()

            if (backend == XrayTunBackend.PacketPump) {
                // Closing first unblocks FileInputStream.read. The Rust core does
                // not own this fd in packet-pump mode.
                capture { tunnel.close() }
                joinXrayPumpThreadUninterruptibly(inboundThread)
                joinXrayPumpThreadUninterruptibly(outboundThread)
                capture { core.stop() }
                capture { core.close() }
            } else {
                // Rust owns active tasks over a borrowed descriptor. Stop and free
                // them before closing the ParcelFileDescriptor.
                capture { core.stop() }
                capture { core.close() }
                capture { tunnel.close() }
            }

            firstFailure?.let { throw it }
        }
    }

    private class StartCancelledException : RuntimeException()

    private companion object {
        const val PACKET_BYTES = 1_500
        const val MAX_PACKETS_PER_POLL = 64
        const val POLL_WAIT_MILLISECONDS = 250
    }
}
