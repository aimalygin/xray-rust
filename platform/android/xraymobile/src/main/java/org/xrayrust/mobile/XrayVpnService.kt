package org.xrayrust.mobile

import android.content.pm.PackageManager.NameNotFoundException
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.EOFException
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.Callable
import java.util.concurrent.Executor
import java.util.concurrent.FutureTask
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

enum class XrayTunBackend {
    FileDescriptor,
    PacketPump,
}

internal val DEFAULT_XRAY_TUN_BACKEND = XrayTunBackend.FileDescriptor

internal sealed interface XrayTunnelStopAction<out Session> {
    data object None : XrayTunnelStopAction<Nothing>
    data object CancelStart : XrayTunnelStopAction<Nothing>
    data class StopSession<Session>(val session: Session) : XrayTunnelStopAction<Session>
}

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

    fun isStartFailureReportable(token: StartToken): Boolean = synchronized(lock) {
        val current = state
        val belongsToToken = (current is State.Starting && current.token === token) ||
            (current is State.Stopping && current.failedStartToken === token)
        belongsToToken && !token.stopRequested
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
            state = State.Stopping(token)
            lock.notifyAll()
            throw error
        }
    }

    fun failStart(token: StartToken) {
        synchronized(lock) {
            val current = state
            if ((current is State.Starting && current.token === token) ||
                (current is State.Stopping && current.failedStartToken === token)
            ) {
                state = State.Stopped
            }
            lock.notifyAll()
        }
    }

    fun requestStop(): XrayTunnelStopAction<Session> = synchronized(lock) {
        when (val current = state) {
            State.Stopped -> XrayTunnelStopAction.None
            is State.Starting -> {
                current.token.stopRequested = true
                XrayTunnelStopAction.CancelStart
            }
            is State.Running -> {
                state = State.Stopping(failedStartToken = null)
                XrayTunnelStopAction.StopSession(current.session)
            }
            is State.Stopping -> {
                val failedStartToken = current.failedStartToken
                if (failedStartToken == null) {
                    XrayTunnelStopAction.None
                } else {
                    failedStartToken.stopRequested = true
                    XrayTunnelStopAction.CancelStart
                }
            }
        }
    }

    fun takeSessionForFailure(failedSession: Session): Session? = synchronized(lock) {
        val current = state
        if (current !is State.Running || current.session !== failedSession) {
            return@synchronized null
        }
        state = State.Stopping(failedStartToken = null)
        current.session
    }

    fun isRunningSession(session: Session): Boolean = synchronized(lock) {
        val current = state
        current is State.Running && current.session === session
    }

    fun runningSession(): Session? = synchronized(lock) {
        when (val current = state) {
            is State.Running -> current.session
            else -> null
        }
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
        class Stopping(val failedStartToken: StartToken?) : State<Nothing>
    }
}

internal class XrayAsyncStartCoordinator<Session>(
    private val lifecycle: XrayTunnelStateMachine<Session>,
    private val executor: Executor,
) {
    private val lock = Any()
    private var activeTask: FutureTask<Unit>? = null
    private var activeToken: XrayTunnelStateMachine.StartToken? = null

    fun execute(
        token: XrayTunnelStateMachine.StartToken,
        block: () -> Unit,
    ) = execute(token, block) {}

    fun <Result> execute(
        token: XrayTunnelStateMachine.StartToken,
        block: () -> Result,
        afterRelease: (Result) -> Unit,
    ) {
        val workerStarted = AtomicBoolean(false)
        val task = object : FutureTask<Unit>(
            Callable {
                workerStarted.set(true)
                val result = try {
                    block()
                } finally {
                    clearActiveStart(token)
                    lifecycle.failStart(token)
                }
                afterRelease(result)
            },
        ) {
            override fun done() {
                clearActiveStart(token)
                if (!workerStarted.get()) {
                    lifecycle.failStart(token)
                }
            }
        }
        synchronized(lock) {
            check(activeTask == null) { "an Xray start worker is already active" }
            activeTask = task
            activeToken = token
        }
        try {
            executor.execute(task)
        } catch (error: Throwable) {
            task.cancel(false)
            throw error
        }
    }

    fun cancelActiveStart() {
        val task = synchronized(lock) { activeTask }
        task?.cancel(true)
    }

    fun hasActiveStart(): Boolean = synchronized(lock) { activeTask != null }

    private fun clearActiveStart(token: XrayTunnelStateMachine.StartToken) {
        synchronized(lock) {
            if (activeToken === token) {
                activeTask = null
                activeToken = null
            }
        }
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

/** A point-in-time, credential-free view of the reference VPN service runtime. */
data class XrayVpnRuntimeSnapshot(
    val running: Boolean,
    val runtimeGeneration: Long,
    val tunStats: XrayTunStats?,
    val activeConnections: Int,
    val fatalTunErrors: Long,
)

open class XrayVpnService : VpnService() {
    private val lifecycle = XrayTunnelStateMachine<TunnelSession>()
    private val startThreadSequence = AtomicInteger()
    private val startExecutor = ThreadPoolExecutor(
        0,
        MAX_CONCURRENT_START_WORKERS,
        START_THREAD_KEEP_ALIVE_SECONDS,
        TimeUnit.SECONDS,
        SynchronousQueue(),
        ThreadFactory { runnable ->
            Thread(
                runnable,
                "xray-vpn-start-${startThreadSequence.incrementAndGet()}",
            ).apply {
                isDaemon = true
            }
        },
        ThreadPoolExecutor.AbortPolicy(),
    )
    private val startCoordinator = XrayAsyncStartCoordinator(
        lifecycle = lifecycle,
        executor = startExecutor,
    )
    private val dnsBootstrapResolver = BoundedAndroidDnsBootstrapResolver()
    private val runtimeGeneration = AtomicLong()
    private val fatalTunErrors = AtomicLong()

    open fun startXrayTunnel(
        configJson: String,
        tunBackend: XrayTunBackend = DEFAULT_XRAY_TUN_BACKEND,
        tunRuntimeProfile: XrayTunRuntimeProfile = XrayTunRuntimeProfile.Default,
        startupProbe: XrayStartupProbeOptions? = null,
    ) {
        val attempt = lifecycle.beginStart() ?: return
        val dnsBootstrapDeadline = AndroidDnsBootstrapDeadline(
            TimeUnit.MILLISECONDS.toNanos(DNS_BOOTSTRAP_TIMEOUT_MILLISECONDS),
        )
        try {
            startCoordinator.execute(
                token = attempt,
                block = {
                    runXrayTunnelStart(
                        attempt = attempt,
                        configJson = configJson,
                        tunBackend = tunBackend,
                        tunRuntimeProfile = tunRuntimeProfile,
                        startupProbe = startupProbe,
                        dnsBootstrapDeadline = dnsBootstrapDeadline,
                    )
                },
                afterRelease = { outcome ->
                    when (outcome) {
                        is XrayTunnelStartOutcome.Started -> {
                            if (lifecycle.isRunningSession(outcome.session)) {
                                runCatching { onXrayTunnelStarted() }
                            }
                        }
                        is XrayTunnelStartOutcome.Failed -> {
                            if (!Thread.currentThread().isInterrupted) {
                                notifyXrayTunnelStartFailed(outcome.error)
                            }
                        }
                        XrayTunnelStartOutcome.Cancelled -> Unit
                    }
                },
            )
        } catch (error: Throwable) {
            lifecycle.failStart(attempt)
            throw error
        }
    }

    private fun runXrayTunnelStart(
        attempt: XrayTunnelStateMachine.StartToken,
        configJson: String,
        tunBackend: XrayTunBackend,
        tunRuntimeProfile: XrayTunRuntimeProfile,
        startupProbe: XrayStartupProbeOptions?,
        dnsBootstrapDeadline: AndroidDnsBootstrapDeadline,
    ): XrayTunnelStartOutcome {
        val prepareAndroidVpnConfig: (String) -> PreparedAndroidVpnConfig = { rawConfig ->
            prepareAndroidVpnConfigWithinDeadline(
                configJson = rawConfig,
                resolver = dnsBootstrapResolver,
                deadline = dnsBootstrapDeadline,
            )
        }
        var tunnel: ParcelFileDescriptor? = null
        var xrayCore: XrayCore? = null
        var coreStarted = false
        try {
            ensureStartIsActive(attempt)
            val preparedConfig = prepareAndroidVpnConfig(configJson)
            ensureStartIsActive(attempt)
            val tunnelBuilder = buildTunnel()
            if (preparedConfig.usesLocalDnsAnchor) {
                tunnelBuilder.addDnsServer(XRAY_TUN_DNS_ANCHOR)
            }
            tunnel = tunnelBuilder.establish()
                ?: error("failed to establish Android VPN tunnel")
            ensureStartIsActive(attempt)

            xrayCore = XrayCore.create(
                configJson = preparedConfig.json,
                vpnService = this,
                tunRuntimeProfile = tunRuntimeProfile,
                startupProbe = startupProbe,
                dnsBootstrapMode = XrayDnsBootstrapMode.StaticOnly,
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
                runtimeGeneration = runtimeGeneration.incrementAndGet(),
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
                throw error
            }

            if (!published) {
                session.shutdown()
                return XrayTunnelStartOutcome.Cancelled
            } else {
                return XrayTunnelStartOutcome.Started(session)
            }
        } catch (_: StartCancelledException) {
            cleanupUnpublishedSession(
                tunnel = tunnel,
                core = xrayCore,
                coreStarted = coreStarted,
            )
            return XrayTunnelStartOutcome.Cancelled
        } catch (_: AndroidDnsBootstrapCancelledException) {
            cleanupUnpublishedSession(
                tunnel = tunnel,
                core = xrayCore,
                coreStarted = coreStarted,
            )
            return XrayTunnelStartOutcome.Cancelled
        } catch (error: Throwable) {
            cleanupUnpublishedSession(
                tunnel = tunnel,
                core = xrayCore,
                coreStarted = coreStarted,
            )
            return if (lifecycle.isStartFailureReportable(attempt) &&
                !Thread.currentThread().isInterrupted
            ) {
                XrayTunnelStartOutcome.Failed(error)
            } else {
                XrayTunnelStartOutcome.Cancelled
            }
        }
    }

    open fun stopXrayTunnel() {
        when (val action = lifecycle.requestStop()) {
            XrayTunnelStopAction.None -> Unit
            XrayTunnelStopAction.CancelStart -> startCoordinator.cancelActiveStart()
            is XrayTunnelStopAction.StopSession -> {
                startCoordinator.cancelActiveStart()
                try {
                    action.session.shutdown()
                } finally {
                    lifecycle.completeStop()
                }
            }
        }
    }

    /** Called on the asynchronous start worker after the running session is published. */
    protected open fun onXrayTunnelStarted() = Unit

    /** Called on the asynchronous start worker when startup fails without cancellation. */
    protected open fun onXrayTunnelStartFailed(error: Throwable) = Unit

    /** Called after an already-published tunnel stops because its packet pump failed. */
    protected open fun onXrayTunnelFatalError(error: Throwable) = Unit

    /**
     * Returns a read-only snapshot suitable for host telemetry and physical-device reports.
     * A concurrent stop may make the native counters temporarily unavailable; callers should
     * sample again rather than treating a null [XrayVpnRuntimeSnapshot.tunStats] as a reset.
     */
    protected fun xrayVpnRuntimeSnapshot(): XrayVpnRuntimeSnapshot {
        val session = lifecycle.runningSession()
        val stats = session?.let { runCatching { it.core.stats() }.getOrNull() }
        val activeConnections = session?.let {
            runCatching { it.core.connectionSnapshot().connections.size }.getOrDefault(0)
        } ?: 0
        return XrayVpnRuntimeSnapshot(
            running = session != null && stats != null,
            runtimeGeneration = session?.runtimeGeneration ?: runtimeGeneration.get(),
            tunStats = stats,
            activeConnections = activeConnections,
            fatalTunErrors = fatalTunErrors.get(),
        )
    }

    /**
     * Requests cancellation of every connection visible in one atomic inventory snapshot.
     * Connections that finish concurrently are ignored; the return value counts close requests
     * accepted by the running core. New traffic may create connections immediately afterwards.
     */
    protected fun closeAllXrayVpnConnections(): Int {
        val session = lifecycle.runningSession() ?: return 0
        val connections = runCatching { session.core.connectionSnapshot().connections }
            .getOrDefault(emptyList())
        return connections.count { connection ->
            runCatching { session.core.closeConnection(connection.id) }.isSuccess
        }
    }

    fun protectSocket(fd: Int): Boolean = protect(fd)

    override fun onDestroy() {
        stopXrayTunnel()
        startExecutor.shutdownNow()
        dnsBootstrapResolver.close()
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

    private fun notifyXrayTunnelStartFailed(error: Throwable) {
        runCatching { onXrayTunnelStartFailed(error) }
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
        } catch (error: Throwable) {
            if (session.active.get()) {
                handlePacketPumpFailure(session, error)
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
        } catch (error: Throwable) {
            if (session.active.get()) {
                handlePacketPumpFailure(session, error)
            }
        }
    }

    private fun handlePacketPumpFailure(session: TunnelSession, error: Throwable) {
        val stopped = runCatching {
            teardownFailedXraySession(lifecycle, session) { it.shutdown() }
        }.getOrDefault(false)
        if (stopped) {
            fatalTunErrors.incrementAndGet()
            runCatching { onXrayTunnelFatalError(error) }
        }
    }

    private class TunnelSession(
        val backend: XrayTunBackend,
        val tunnel: ParcelFileDescriptor,
        val core: XrayCore,
        val runtimeGeneration: Long,
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

    private sealed interface XrayTunnelStartOutcome {
        data class Started(val session: TunnelSession) : XrayTunnelStartOutcome
        data class Failed(val error: Throwable) : XrayTunnelStartOutcome
        data object Cancelled : XrayTunnelStartOutcome
    }

    private companion object {
        const val PACKET_BYTES = 1_500
        const val MAX_PACKETS_PER_POLL = 64
        const val POLL_WAIT_MILLISECONDS = 250
        const val DNS_BOOTSTRAP_TIMEOUT_MILLISECONDS = 5_000L
        const val MAX_CONCURRENT_START_WORKERS = 2
        const val START_THREAD_KEEP_ALIVE_SECONDS = 30L
    }
}
