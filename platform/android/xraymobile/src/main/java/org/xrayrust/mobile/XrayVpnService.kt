package org.xrayrust.mobile

import android.Manifest
import android.content.pm.PackageManager
import android.content.pm.PackageManager.NameNotFoundException
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.Closeable
import java.io.EOFException
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.util.concurrent.Callable
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
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

    /** [discardedQueuedStart]: a replacement start that never reached a worker was dropped as well. */
    data class CancelStart(val discardedQueuedStart: Boolean = false) : XrayTunnelStopAction<Nothing>
    data class StopSession<Session>(val session: Session) : XrayTunnelStopAction<Session>
}

internal sealed interface XrayTunnelStartAdmission {
    /** The lifecycle was stopped; the caller schedules [token] now. */
    data class Started(val token: XrayTunnelStateMachine.StartToken) : XrayTunnelStartAdmission

    /**
     * An in-flight attempt was cancelled. Its release schedules the queued launch; [displacedQueuedStart]
     * reports an older queued replacement that will never run.
     */
    data class Queued(
        val cancelled: XrayTunnelStateMachine.StartToken,
        val displacedQueuedStart: Boolean,
    ) : XrayTunnelStartAdmission

    /**
     * A session is stopping; the stop that completes it schedules the queued launch.
     * [displacedQueuedStart] reports an older queued start that will never run.
     */
    data class AwaitingStop(val displacedQueuedStart: Boolean) : XrayTunnelStartAdmission

    /** A session is running, or the same request is already starting or queued. */
    data object Rejected : XrayTunnelStartAdmission
}

internal class XrayTunnelStateMachine<Session> {
    class StartToken internal constructor(internal val request: Any? = null) {
        internal var stopRequested = false
    }

    private class QueuedStart(val token: StartToken, val launch: (StartToken) -> Unit)

    private val lock = Object()
    private var state: State<Session> = State.Stopped

    // Only while an attempt that has been asked to stop is still releasing, or a session is stopping.
    private var queuedStart: QueuedStart? = null

    fun beginStart(): StartToken? = synchronized(lock) {
        if (state !== State.Stopped) {
            return@synchronized null
        }
        StartToken().also {
            state = State.Starting(it)
        }
    }

    /**
     * Like [beginStart], but an in-flight attempt is cancelled and replaced: [launch] runs with a new
     * token once that attempt has released the lifecycle, from the thread releasing it. A non-null
     * [request] equal to the one still starting, or already queued, is rejected instead.
     */
    fun beginOrReplaceStart(
        request: Any? = null,
        launch: (StartToken) -> Unit,
    ): XrayTunnelStartAdmission = synchronized(lock) { admitStartLocked(request, launch) }

    private fun admitStartLocked(request: Any?, launch: (StartToken) -> Unit): XrayTunnelStartAdmission {
        val current = state
        val starting = when (current) {
            State.Stopped -> return XrayTunnelStartAdmission.Started(
                StartToken(request).also { state = State.Starting(it) },
            )
            is State.Starting -> current.token
            is State.Stopping -> current.failedStartToken ?: return queueAfterStopLocked(request, launch)
            is State.Running -> null
        } ?: return XrayTunnelStartAdmission.Rejected
        if (current is State.Starting && request != null && request == pendingRequest(starting)) {
            return XrayTunnelStartAdmission.Rejected
        }
        starting.stopRequested = true
        val displaced = queuedStart != null
        queuedStart = QueuedStart(StartToken(request), launch)
        return XrayTunnelStartAdmission.Queued(cancelled = starting, displacedQueuedStart = displaced)
    }

    private fun queueAfterStopLocked(request: Any?, launch: (StartToken) -> Unit): XrayTunnelStartAdmission {
        if (request != null && request == queuedStart?.token?.request) return XrayTunnelStartAdmission.Rejected
        val displaced = queuedStart != null
        queuedStart = QueuedStart(StartToken(request), launch)
        return XrayTunnelStartAdmission.AwaitingStop(displacedQueuedStart = displaced)
    }

    // The request that will run unless stopped: the queued replacement, else the live attempt.
    private fun pendingRequest(starting: StartToken): Any? =
        queuedStart?.token?.request ?: starting.request.takeUnless { starting.stopRequested }

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

    /**
     * Releases [token]'s attempt. Returns the queued replacement, now Starting, which the caller must
     * run after its own completion callback.
     */
    fun failStart(token: StartToken): (() -> Unit)? = synchronized(lock) {
        val current = state
        val owned = (current is State.Starting && current.token === token) ||
            (current is State.Stopping && current.failedStartToken === token)
        val next = queuedStart?.takeIf { owned }
        if (owned) {
            queuedStart = null
            state = next?.let { State.Starting(it.token) } ?: State.Stopped
        }
        lock.notifyAll()
        next?.let { queued -> { queued.launch(queued.token) } }
    }

    fun requestStop(): XrayTunnelStopAction<Session> = synchronized(lock) {
        when (val current = state) {
            State.Stopped -> XrayTunnelStopAction.None
            is State.Starting -> {
                current.token.stopRequested = true
                cancelStart()
            }
            is State.Running -> {
                state = State.Stopping(failedStartToken = null)
                XrayTunnelStopAction.StopSession(current.session)
            }
            is State.Stopping -> {
                val failedStartToken = current.failedStartToken
                if (failedStartToken == null) {
                    if (queuedStart == null) XrayTunnelStopAction.None else cancelStart()
                } else {
                    failedStartToken.stopRequested = true
                    cancelStart()
                }
            }
        }
    }

    private fun cancelStart(): XrayTunnelStopAction<Nothing> {
        val discarded = queuedStart != null
        queuedStart = null
        return XrayTunnelStopAction.CancelStart(discardedQueuedStart = discarded)
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

    /**
     * Ends a session stop. Returns the start queued while it stopped, now Starting, which the caller
     * must run last.
     */
    fun completeStop(): (() -> Unit)? = synchronized(lock) {
        val next = queuedStart
        queuedStart = null
        state = next?.let { State.Starting(it.token) } ?: State.Stopped
        lock.notifyAll()
        next?.let { queued -> { queued.launch(queued.token) } }
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
    ) = execute(token, block, afterRelease = {})

    /**
     * Runs [block], releases [token], then calls [afterRelease] on the worker. A task cancelled before
     * its worker began calls [onCancelledBeforeRun] on the cancelling thread instead. Either way a
     * replacement queued on the lifecycle is launched last, after that callback. A scheduling failure
     * is thrown with [token] still held: the caller releases it, reports, then launches the replacement.
     */
    fun <Result> execute(
        token: XrayTunnelStateMachine.StartToken,
        block: () -> Result,
        afterRelease: (Result) -> Unit,
        onCancelledBeforeRun: () -> Unit = {},
    ) {
        // The worker and the cancellation path race for one claim; only the winner releases and reports.
        val claimed = AtomicBoolean(false)
        val task = object : FutureTask<Unit>(
            Callable {
                if (!claimed.compareAndSet(false, true)) return@Callable
                var replacement: (() -> Unit)? = null
                try {
                    val result = try {
                        block()
                    } finally {
                        clearActiveStart(token)
                        replacement = lifecycle.failStart(token)
                    }
                    afterRelease(result)
                } finally {
                    replacement?.invoke()
                }
            },
        ) {
            override fun done() {
                clearActiveStart(token)
                if (!claimed.compareAndSet(false, true)) return
                val replacement = lifecycle.failStart(token)
                try {
                    onCancelledBeforeRun()
                } finally {
                    replacement?.invoke()
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
            claimed.set(true)
            clearActiveStart(token)
            task.cancel(false)
            throw error
        }
    }

    fun cancelActiveStart() {
        val task = synchronized(lock) { activeTask }
        task?.cancel(true)
    }

    /** Cancels only [token]'s worker, never a replacement that has already been launched. */
    fun cancelActiveStart(token: XrayTunnelStateMachine.StartToken) {
        val task = synchronized(lock) { activeTask?.takeIf { activeToken === token } }
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

/** Thrown on the start worker once the lifecycle has cancelled its attempt. */
internal class XrayStartCancelledException : RuntimeException()

/**
 * Runs the startup probe on a separate unstarted core before the VPN interface is established,
 * so a slow or failing probe never leaves apps without a network (#69). [cancel] lets the stop
 * path end a pending native probe without waiting for the start worker.
 */
internal class XrayStartupProbePreflight<Core : Closeable>(
    private val lifecycle: XrayTunnelStateMachine<*>,
    private val preflight: (Core) -> Unit,
    private val cancelPreflight: (Core) -> Unit,
) {
    private val lock = Any()
    private var pendingToken: XrayTunnelStateMachine.StartToken? = null
    private var pendingCore: Core? = null

    /**
     * Returns only after [startupProbe] passed while [token] is still active, or at once without a
     * probe. The core from [createCore] is closed before this returns or throws, so the data-path
     * core must be created without a probe. A cancelled start throws [XrayStartCancelledException];
     * probe failures propagate unchanged.
     */
    fun run(
        token: XrayTunnelStateMachine.StartToken,
        startupProbe: XrayStartupProbeOptions?,
        createCore: (XrayStartupProbeOptions) -> Core,
    ) {
        if (startupProbe == null) {
            return
        }
        createCore(startupProbe).use { core ->
            // Serialized with cancel(): a stop either prevents the native call or finds the core.
            val registered = synchronized(lock) {
                lifecycle.isStartActive(token).also { active ->
                    if (active) {
                        pendingToken = token
                        pendingCore = core
                    }
                }
            }
            if (!registered) {
                throw XrayStartCancelledException()
            }
            try {
                preflight(core)
            } finally {
                synchronized(lock) {
                    pendingToken = null
                    pendingCore = null
                }
            }
        }
        if (!lifecycle.isStartActive(token)) {
            throw XrayStartCancelledException()
        }
    }

    /** Cancels the pending native probe of a start that the lifecycle has already cancelled. */
    fun cancel() {
        val core = synchronized(lock) {
            val token = pendingToken ?: return
            if (lifecycle.isStartActive(token)) {
                return
            }
            pendingCore
        } ?: return
        cancelPreflight(core)
    }
}

/**
 * Stops [failedSession] if it is still the running one, then calls [onStopped] with what [shutdown]
 * threw, if anything. A start queued while it stopped is launched after [onStopped].
 */
internal fun <Session> teardownFailedXraySession(
    lifecycle: XrayTunnelStateMachine<Session>,
    failedSession: Session,
    onStopped: (shutdownFailure: Throwable?) -> Unit = {},
    shutdown: (Session) -> Unit,
): Boolean {
    val session = lifecycle.takeSessionForFailure(failedSession) ?: return false
    val shutdownFailure = runCatching { shutdown(session) }.exceptionOrNull()
    val next = lifecycle.completeStop()
    try {
        onStopped(shutdownFailure)
    } finally {
        next?.invoke()
    }
    return true
}

/**
 * Fences the started callback against a stop. Once [awaitDelivery] returns after the lifecycle left
 * Running, no started callback of that session is running or still to come. A callback that calls
 * [awaitDelivery] on its own thread does not wait for itself.
 */
internal class XrayStartedNotice<Session>(private val lifecycle: XrayTunnelStateMachine<Session>) {
    private val lock = Any()

    fun deliver(session: Session, onStarted: () -> Unit, onCancelled: () -> Unit) = synchronized(lock) {
        if (lifecycle.isRunningSession(session)) onStarted() else onCancelled()
    }

    fun awaitDelivery() = synchronized(lock) { Unit }
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

/** Keep attempting shutdown steps, retaining the first error and later diagnostics. */
internal class XrayShutdownFailures {
    private var firstFailure: Throwable? = null

    fun capture(block: () -> Unit) {
        try {
            block()
        } catch (error: Throwable) {
            val first = firstFailure
            if (first == null) {
                firstFailure = error
            } else if (first !== error) {
                first.addSuppressed(error)
            }
        }
    }

    fun throwIfAny() {
        firstFailure?.let { throw it }
    }
}

internal fun isRecoverablePacketPushFailure(error: Throwable): Boolean =
    error is XrayCoreException

/** The default carrier choice of [XrayVpnService.selectUnderlyingNetwork]. */
internal fun <Candidate, N> List<Candidate>.preferredUnderlyingNetwork(
    network: (Candidate) -> N,
    validated: (Candidate) -> Boolean,
    systemDefault: N?,
    previous: N?,
): N? {
    val networks = map(network)
    return systemDefault?.takeIf { it in networks }
        ?: previous?.takeIf { it in networks }
        ?: firstOrNull(validated)?.let(network)
        ?: networks.firstOrNull()
}

/**
 * Releases [attempt] whose worker could not be scheduled, reports it, then launches the replacement
 * queued meanwhile. An attempt already stopped or replaced reports cancellation, not failure.
 */
internal fun reportUnscheduledStart(
    lifecycle: XrayTunnelStateMachine<*>,
    attempt: XrayTunnelStateMachine.StartToken,
    error: Throwable,
    onFailed: (Throwable) -> Unit,
    onCancelled: () -> Unit,
) {
    val reportable = lifecycle.isStartFailureReportable(attempt)
    val next = lifecycle.failStart(attempt)
    try {
        if (reportable) onFailed(error) else onCancelled()
    } finally {
        next?.invoke()
    }
}

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
    private val startedNotice = XrayStartedNotice(lifecycle)
    private val startupProbePreflight = XrayStartupProbePreflight<XrayCore>(
        lifecycle = lifecycle,
        preflight = XrayCore::preflightStartupProbe,
        cancelPreflight = XrayCore::cancelStartupProbePreflight,
    )
    private val dnsBootstrapResolver = BoundedAndroidDnsBootstrapResolver()
    private val networkControlLock = Any()
    private var networkControlWorker: ExecutorService? = null

    // Set by onDestroy before the workers shut down; a late start worker must not recreate them.
    @Volatile
    private var destroyed = false
    private val runtimeGeneration = AtomicLong()
    private val fatalTunErrors = AtomicLong()

    /** Optional host policy, created after the VPN interface is established. */
    protected open fun tunAdmissionOptions(): XrayTunAdmissionOptions? = null

    /**
     * Optional existing directory with `geosite.dat`, `geoip.dat` and `ext:` files, searched
     * exclusively. The startup-probe preflight core and the data-path core both load it, so a
     * missing file or code reaches [onXrayTunnelStartFailed].
     */
    protected open fun geodataSearchDirectory(): File? = null

    /**
     * Opt-in Hysteria2/WireGuard carrier rebind on underlying-network changes. When true, each session
     * runs an [XrayNetworkChangeCoordinator] on a private serial control worker, started after the
     * core and closed before the core stops and before the TUN descriptor closes. The host manifest
     * must declare `ACCESS_NETWORK_STATE`; without it the start fails with a [SecurityException]
     * before the VPN interface is established. Read once per start, on the start worker.
     */
    protected open fun networkChangeRebindEnabled(): Boolean = false

    /**
     * The carrier policy of [networkChangeRebindEnabled], called on the control worker with copied
     * snapshots of usable non-VPN Internet networks. Apply the host's carrier settings, such as
     * `setUnderlyingNetworks`, before returning the selected [Network], or null while offline.
     * It must be quick, idempotent and must not wait for another call on the same worker.
     *
     * The default keeps `setUnderlyingNetworks(null)` and returns the network protected sockets
     * follow: the system default network when it is a candidate, otherwise [previous] while it
     * remains a candidate, otherwise the first validated candidate, otherwise the first candidate.
     * It is correct only while this package is excluded from its own VPN, as the default
     * [buildTunnel] does: otherwise the system default is the VPN itself, the choice sticks to
     * [previous], so override this method. Selection runs on candidate events only, not on
     * default-network switches that leave every candidate unchanged.
     */
    protected open fun selectUnderlyingNetwork(
        candidates: List<XrayUnderlyingNetwork>,
        previous: Network?,
    ): Network? = candidates.preferredUnderlyingNetwork(
        network = { it.network },
        validated = { it.capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) },
        systemDefault = systemDefaultNetwork(),
        previous = previous,
    )

    /**
     * Rebind requests made for a carrier change of the running session, on the control worker.
     * Acceptance is not evidence of a completed handshake.
     */
    protected open fun onXrayNetworkRebind(result: XrayNetworkRebindResult) = Unit

    /** Carrier policy or scheduling failures of [networkChangeRebindEnabled]; no rebind was requested. */
    protected open fun onXrayNetworkChangeError(error: Exception) = Unit

    /**
     * Starts asynchronously. A [startupProbe] runs before `Builder.establish()`, so its failure,
     * timeout or cancellation leaves routes and DNS untouched; requires ABI 1.12. [tunMtu] is
     * given to both the interface and the core; a library without ABI 1.16 `TunMtu` runs both
     * at [XrayTunInterface.MTU].
     *
     * Every accepted call ends in exactly one of [onXrayTunnelStarted], [onXrayTunnelStartFailed]
     * or [onXrayTunnelStartCancelled]. A call while an earlier start with different arguments is
     * still in flight replaces it: the earlier attempt is cancelled and reports
     * [onXrayTunnelStartCancelled], and this one begins once its cleanup has finished. A call while
     * a session is stopping, after [stopXrayTunnel] or a packet-pump failure, begins once that stop
     * has finished; a later such call replaces it, and the replaced one reports
     * [onXrayTunnelStartCancelled]. A call with the same arguments as the start in flight or
     * queued, or while a session is running, is ignored. Failure to schedule the worker of a start that did not replace another one is thrown
     * here. The callbacks carry no attempt identity, and those of different attempts can arrive
     * on different threads and interleave.
     */
    open fun startXrayTunnel(
        configJson: String,
        tunBackend: XrayTunBackend = DEFAULT_XRAY_TUN_BACKEND,
        tunRuntimeProfile: XrayTunRuntimeProfile = XrayTunRuntimeProfile.Default,
        startupProbe: XrayStartupProbeOptions? = null,
        tunMtu: Int = XrayTunInterface.MTU,
    ) {
        val request = StartRequest(configJson, tunBackend, tunRuntimeProfile, startupProbe, tunMtu)
        val admission = lifecycle.beginOrReplaceStart(request) { attempt -> launchReplacementStart(attempt, request) }
        when (admission) {
            is XrayTunnelStartAdmission.Started -> {
                val attempt = admission.token
                try {
                    launchXrayTunnelStart(attempt, request)
                } catch (error: Throwable) {
                    lifecycle.failStart(attempt)?.invoke()
                    throw error
                }
            }
            is XrayTunnelStartAdmission.AwaitingStop ->
                if (admission.displacedQueuedStart) notifyXrayTunnelStartCancelled()
            is XrayTunnelStartAdmission.Queued -> {
                // Before the cancel below, which can launch this start on the calling thread.
                if (admission.displacedQueuedStart) notifyXrayTunnelStartCancelled()
                startupProbePreflight.cancel()
                startCoordinator.cancelActiveStart(admission.cancelled)
            }
            XrayTunnelStartAdmission.Rejected -> Unit
        }
    }

    private fun launchXrayTunnelStart(attempt: XrayTunnelStateMachine.StartToken, request: StartRequest) {
        // The bootstrap deadline begins once the lifecycle accepts this attempt.
        val dnsBootstrapDeadline = AndroidDnsBootstrapDeadline(
            TimeUnit.MILLISECONDS.toNanos(DNS_BOOTSTRAP_TIMEOUT_MILLISECONDS),
        )
        startCoordinator.execute(
            token = attempt,
            block = { runXrayTunnelStart(attempt, request, dnsBootstrapDeadline) },
            afterRelease = ::deliverStartOutcome,
            onCancelledBeforeRun = ::notifyXrayTunnelStartCancelled,
        )
    }

    // Runs on the thread releasing the replaced attempt, so a scheduling failure becomes a callback.
    private fun launchReplacementStart(attempt: XrayTunnelStateMachine.StartToken, request: StartRequest) {
        try {
            launchXrayTunnelStart(attempt, request)
        } catch (error: Throwable) {
            reportUnscheduledStart(
                lifecycle = lifecycle,
                attempt = attempt,
                error = error,
                onFailed = ::notifyXrayTunnelStartFailed,
                onCancelled = ::notifyXrayTunnelStartCancelled,
            )
        }
    }

    private fun deliverStartOutcome(outcome: XrayTunnelStartOutcome) {
        when (outcome) {
            is XrayTunnelStartOutcome.Started -> startedNotice.deliver(
                session = outcome.session,
                onStarted = ::notifyXrayTunnelStarted,
                onCancelled = ::notifyXrayTunnelStartCancelled,
            )
            is XrayTunnelStartOutcome.Failed ->
                if (Thread.currentThread().isInterrupted) notifyXrayTunnelStartCancelled()
                else notifyXrayTunnelStartFailed(outcome.error)
            XrayTunnelStartOutcome.Cancelled -> notifyXrayTunnelStartCancelled()
        }
    }

    private fun runXrayTunnelStart(
        attempt: XrayTunnelStateMachine.StartToken,
        request: StartRequest,
        dnsBootstrapDeadline: AndroidDnsBootstrapDeadline,
    ): XrayTunnelStartOutcome {
        val configJson = request.configJson
        val tunBackend = request.tunBackend
        val startupProbe = request.startupProbe
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
        var networkChange: XrayNetworkChangeCoordinator? = null
        try {
            ensureStartIsActive(attempt)
            val rebindEnabled = networkChangeRebindEnabled()
            // Checked before establish(), so a missing permission never brings the interface up.
            if (rebindEnabled) requireNetworkStatePermission()
            val preparedConfig = prepareAndroidVpnConfig(configJson)
            val geodataSearchDirectory = geodataSearchDirectory()
            ensureStartIsActive(attempt)
            // No TUN fd, listeners or admission policy: this core only runs the probe. Routing
            // still compiles geodata rules, so it needs the same search directory.
            startupProbePreflight.run(attempt, startupProbe) { probe ->
                XrayCore.create(
                    configJson = preparedConfig.json,
                    vpnService = this,
                    startupProbe = probe,
                    dnsBootstrapMode = XrayDnsBootstrapMode.StaticOnly,
                    geodataSearchDirectory = geodataSearchDirectory,
                )
            }
            // One value for the interface and the core, whatever buildTunnel() set.
            val mtu = XrayCore.supportedTunMtu(request.tunMtu)
            val tunnelBuilder = buildTunnel().setMtu(mtu)
            if (preparedConfig.usesLocalDnsAnchor) {
                tunnelBuilder.addDnsServer(XrayTunInterface.DNS_ANCHOR)
            }
            tunnel = tunnelBuilder.establish()
                ?: error("failed to establish Android VPN tunnel")
            ensureStartIsActive(attempt)

            // The preflight above already ran the startup probe; the data path must not repeat it.
            xrayCore = XrayCore.create(
                configJson = preparedConfig.json,
                vpnService = this,
                tunRuntimeProfile = request.tunRuntimeProfile,
                dnsBootstrapMode = XrayDnsBootstrapMode.StaticOnly,
                tunAdmission = tunAdmissionOptions(),
                geodataSearchDirectory = geodataSearchDirectory,
                tunMtu = mtu,
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
            if (rebindEnabled) networkChange = startNetworkChangeRebind(xrayCore)

            val session = TunnelSession(
                backend = tunBackend,
                tunnel = tunnel,
                core = xrayCore,
                networkChange = networkChange,
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
            } else {
                // The core pumps the descriptor itself and has no way to call back when it
                // gives up on it, so this session watches for that as a pump thread would fail.
                session.fdWatchThread = XrayTunFdLoopWatch(
                    loopExits = {
                        runCatching { session.core.stats() }.getOrNull()
                            ?.let { it.tunFdReadLoopExits + it.tunFdWriteLoopExits }
                    },
                    onStopped = {
                        if (session.active.get()) {
                            handlePacketPumpFailure(
                                session,
                                IOException("the core stopped pumping the Android VPN tunnel"),
                            )
                        }
                    },
                ).thread
            }

            val published = try {
                lifecycle.publish(attempt, session) {
                    session.inboundThread?.start()
                    session.outboundThread?.start()
                    session.fdWatchThread?.start()
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
        } catch (error: Throwable) {
            cleanupUnpublishedSession(
                tunnel = tunnel,
                core = xrayCore,
                coreStarted = coreStarted,
                networkChange = networkChange,
            )
            if (error is XrayStartCancelledException ||
                error is AndroidDnsBootstrapCancelledException
            ) {
                return XrayTunnelStartOutcome.Cancelled
            }
            return if (lifecycle.isStartFailureReportable(attempt) &&
                !Thread.currentThread().isInterrupted
            ) {
                XrayTunnelStartOutcome.Failed(error)
            } else {
                XrayTunnelStartOutcome.Cancelled
            }
        }
    }

    /**
     * Stops the running session or cancels the start in flight, along with a start queued behind
     * either. Stopping a session blocks until the core has stopped, since its tasks over the
     * borrowed descriptor must end before the descriptor closes. Once this returns, that session
     * calls no [onXrayTunnelStarted]: this waits for one already running.
     */
    open fun stopXrayTunnel() {
        when (val action = lifecycle.requestStop()) {
            XrayTunnelStopAction.None -> Unit
            is XrayTunnelStopAction.CancelStart -> {
                if (action.discardedQueuedStart) notifyXrayTunnelStartCancelled()
                startupProbePreflight.cancel()
                startCoordinator.cancelActiveStart()
            }
            is XrayTunnelStopAction.StopSession -> {
                startCoordinator.cancelActiveStart()
                startedNotice.awaitDelivery()
                try {
                    action.session.shutdown()
                } finally {
                    lifecycle.completeStop()?.invoke()
                }
            }
        }
    }

    /**
     * Called on the asynchronous start worker after the running session is published.
     * [stopXrayTunnel] waits for it, so it must not wait for a thread that is stopping the tunnel.
     */
    protected open fun onXrayTunnelStarted() = Unit

    /** Called on the asynchronous start worker when startup fails without cancellation. */
    protected open fun onXrayTunnelStartFailed(error: Throwable) = Unit

    /**
     * Called once a start ends without a running tunnel because [stopXrayTunnel] or a replacing
     * [startXrayTunnel] cancelled it. Runs on the start worker, or on the thread of that stop/start
     * call when the attempt never reached a worker. A packet-pump failure racing publication may
     * report [onXrayTunnelFatalError] as well.
     */
    protected open fun onXrayTunnelStartCancelled() = Unit

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
        destroyed = true
        stopXrayTunnel()
        startExecutor.shutdownNow()
        synchronized(networkControlLock) { networkControlWorker?.shutdownNow() }
        dnsBootstrapResolver.close()
        super.onDestroy()
    }

    /**
     * Interface settings before the tunnel is established. The MTU set here is replaced: the
     * service gives the interface the `tunMtu` of [startXrayTunnel], the value the core runs at,
     * so pass a non-default MTU there rather than calling `setMtu` in an override.
     */
    protected open fun buildTunnel(): Builder {
        val builder = Builder()
            .setSession("xray-rust")
            .applyXrayTunInterface(dnsAnchor = false)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
        if (Build.VERSION.SDK_INT >= 29) {
            // A VPN of an app targeting API 29+ is metered by default, even on Wi-Fi.
            builder.setMetered(false)
        }
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: NameNotFoundException) {
            // Some host/test contexts may not expose the package to PackageManager.
        }
        return builder
    }

    private fun ensureStartIsActive(attempt: XrayTunnelStateMachine.StartToken) {
        if (!lifecycle.isStartActive(attempt)) {
            throw XrayStartCancelledException()
        }
    }

    private fun notifyXrayTunnelStartFailed(error: Throwable) {
        runCatching { onXrayTunnelStartFailed(error) }
    }

    private fun notifyXrayTunnelStarted() {
        runCatching { onXrayTunnelStarted() }
    }

    private fun notifyXrayTunnelStartCancelled() {
        runCatching { onXrayTunnelStartCancelled() }
    }

    @Suppress("MissingPermission") // Opt-in callers declare ACCESS_NETWORK_STATE in the host manifest.
    private fun systemDefaultNetwork(): Network? =
        runCatching { getSystemService(ConnectivityManager::class.java)?.activeNetwork }.getOrNull()

    private fun requireNetworkStatePermission() {
        if (checkSelfPermission(Manifest.permission.ACCESS_NETWORK_STATE) != PackageManager.PERMISSION_GRANTED) {
            throw SecurityException("networkChangeRebindEnabled() requires ${Manifest.permission.ACCESS_NETWORK_STATE}")
        }
    }

    // Created on first use; after onDestroy the start is cancelled instead of leaking a new worker.
    private fun networkControlExecutor(): ExecutorService = synchronized(networkControlLock) {
        if (destroyed) throw XrayStartCancelledException()
        networkControlWorker ?: Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "xray-vpn-network").apply { isDaemon = true }
        }.also { networkControlWorker = it }
    }

    private fun startNetworkChangeRebind(core: XrayCore): XrayNetworkChangeCoordinator {
        val connectivity = checkNotNull(getSystemService(ConnectivityManager::class.java)) {
            "ConnectivityManager is unavailable"
        }
        val coordinator = XrayNetworkChangeCoordinator(
            connectivityManager = connectivity,
            controlExecutor = networkControlExecutor(),
            selectAndApply = { candidates, previous -> selectUnderlyingNetwork(candidates, previous) },
            // A start racing onDestroy sees its worker rejected; that is not a host-visible error.
            onError = { error -> if (!destroyed) runCatching { onXrayNetworkChangeError(error) } },
            onResult = { result -> runCatching { onXrayNetworkRebind(result) } },
        )
        try {
            coordinator.start(core)
        } catch (error: Throwable) {
            runCatching { coordinator.close() }
            throw error
        }
        return coordinator
    }

    private fun cleanupUnpublishedSession(
        tunnel: ParcelFileDescriptor?,
        core: XrayCore?,
        coreStarted: Boolean,
        networkChange: XrayNetworkChangeCoordinator?,
    ) {
        // The coordinator must stop requesting rebinds before the core it targets stops.
        runCatching { networkChange?.close() }
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
            val packetBuffer = ByteArray(session.core.tunMtu)
            val readable = StructPollfd().apply {
                fd = session.tunnel.fileDescriptor
                events = OsConstants.POLLIN.toShort()
            }
            val pollDescriptors = arrayOf(readable)

            while (session.active.get() && !Thread.currentThread().isInterrupted) {
                val read = input.read(packetBuffer)
                if (read == 0) {
                    // Android maps EAGAIN on a nonblocking TUN to a zero-byte
                    // FileInputStream read. Wait for readiness instead of spinning.
                    // A bounded poll also lets shutdown join this worker even if
                    // closing the descriptor does not immediately wake poll().
                    try {
                        Os.poll(pollDescriptors, POLL_WAIT_MILLISECONDS)
                    } catch (error: ErrnoException) {
                        if (error.errno != OsConstants.EINTR) throw error
                        continue
                    }
                    if (readable.revents.toInt() and
                        (OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL) != 0
                    ) {
                        throw IOException("Android VPN tunnel poll failed")
                    }
                    continue
                }
                if (read < 0) {
                    throw EOFException("Android VPN tunnel reached EOF")
                }
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
        } catch (error: Throwable) {
            if (session.active.get()) {
                handlePacketPumpFailure(session, error)
            }
        }
    }

    private fun writeTunPackets(session: TunnelSession) {
        try {
            val output = FileOutputStream(session.tunnel.fileDescriptor)
            val packetBytes = session.core.tunMtu
            val storage = ByteBuffer.allocateDirect(MAX_PACKETS_PER_POLL * packetBytes)
            val lengths = IntArray(MAX_PACKETS_PER_POLL)
            val packetBuffer = ByteArray(packetBytes)

            while (session.active.get() && !Thread.currentThread().isInterrupted) {
                val packetCount = session.core.pollPacketsInto(
                    storage = storage,
                    lengths = lengths,
                    maxPacketBytes = packetBytes,
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
                    check(length in 1..packetBytes) {
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
        // A shutdown step that throws has still taken the session and left it stopped, so the
        // host hears of the failure all the same, with what the shutdown threw attached.
        teardownFailedXraySession(
            lifecycle = lifecycle,
            failedSession = session,
            onStopped = { shutdownFailure ->
                shutdownFailure?.let(error::addSuppressed)
                fatalTunErrors.incrementAndGet()
                runCatching { onXrayTunnelFatalError(error) }
            },
            shutdown = { it.shutdown() },
        )
    }

    private class TunnelSession(
        val backend: XrayTunBackend,
        val tunnel: ParcelFileDescriptor,
        val core: XrayCore,
        val networkChange: XrayNetworkChangeCoordinator?,
        val runtimeGeneration: Long,
    ) {
        val active = AtomicBoolean(true)
        var inboundThread: Thread? = null
        var outboundThread: Thread? = null
        var fdWatchThread: Thread? = null

        fun shutdown() {
            if (!active.compareAndSet(true, false)) {
                return
            }

            val failures = XrayShutdownFailures()

            // Unregister and wait for in-flight rebind work before the core or its fd go away.
            networkChange?.let { failures.capture { it.close() } }
            inboundThread?.interrupt()
            outboundThread?.interrupt()
            fdWatchThread?.interrupt()

            if (backend == XrayTunBackend.PacketPump) {
                // Closing first unblocks FileInputStream.read. The Rust core does
                // not own this fd in packet-pump mode.
                failures.capture { tunnel.close() }
                joinXrayPumpThreadUninterruptibly(inboundThread)
                joinXrayPumpThreadUninterruptibly(outboundThread)
                failures.capture { core.stop() }
                failures.capture { core.close() }
            } else {
                // Rust owns active tasks over a borrowed descriptor. Stop and free
                // them before closing the ParcelFileDescriptor.
                joinXrayPumpThreadUninterruptibly(fdWatchThread)
                failures.capture { core.stop() }
                failures.capture { core.close() }
                failures.capture { tunnel.close() }
            }

            failures.throwIfAny()
        }
    }

    // Not a data class: the config carries credentials and must never reach a toString().
    // Equality lets a duplicate start of the same request be ignored rather than replace itself.
    private class StartRequest(
        val configJson: String,
        val tunBackend: XrayTunBackend,
        val tunRuntimeProfile: XrayTunRuntimeProfile,
        val startupProbe: XrayStartupProbeOptions?,
        val tunMtu: Int,
    ) {
        override fun equals(other: Any?): Boolean = other is StartRequest &&
            configJson == other.configJson &&
            tunBackend == other.tunBackend &&
            tunRuntimeProfile == other.tunRuntimeProfile &&
            startupProbe == other.startupProbe &&
            tunMtu == other.tunMtu

        override fun hashCode(): Int = configJson.hashCode()
    }

    private sealed interface XrayTunnelStartOutcome {
        data class Started(val session: TunnelSession) : XrayTunnelStartOutcome
        data class Failed(val error: Throwable) : XrayTunnelStartOutcome
        data object Cancelled : XrayTunnelStartOutcome
    }

    private companion object {
        const val MAX_PACKETS_PER_POLL = 64
        const val POLL_WAIT_MILLISECONDS = 250
        const val DNS_BOOTSTRAP_TIMEOUT_MILLISECONDS = 5_000L
        // A worker launching its replacement still holds its thread, an earlier worker may still run
        // onXrayTunnelStarted, and a finishing worker still counts while the next handoff happens.
        const val MAX_CONCURRENT_START_WORKERS = 4
        const val START_THREAD_KEEP_ALIVE_SECONDS = 30L
    }
}
