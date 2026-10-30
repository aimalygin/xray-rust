package org.xrayrust.mobile

import java.io.Closeable
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** An accepted request is not evidence that a handshake or traffic recovery completed. */
sealed class XrayRebindRequestResult {
    data class Accepted(val requests: Long) : XrayRebindRequestResult() {
        init { require(requests >= 0) }
    }
    data class Failed(val error: Exception) : XrayRebindRequestResult()
}

data class XrayNetworkRebindResult(
    val sessionGeneration: Long,
    val hysteria: XrayRebindRequestResult,
    val wireGuard: XrayRebindRequestResult,
)

internal interface XrayNetworkRebindTarget {
    fun rebindHysteria(): Long
    fun rebindWireGuard(): Long
}

internal data class XrayNetworkObservation<N, C, P>(
    val network: N,
    val capabilities: C,
    val properties: P,
)

internal interface XrayNetworkEvents<N, C, P> {
    fun available(network: N)
    fun capabilities(network: N, capabilities: C)
    fun properties(network: N, properties: P)
    fun blocked(network: N, blocked: Boolean)
    fun lost(network: N)
}

/** The Android adapter supplies copied callback values; this state has no platform dependencies. */
internal class XrayNetworkChangeState<N : Any, C : Any, P : Any>(
    private val executor: Executor,
    private val register: (XrayNetworkEvents<N, C, P>) -> Closeable,
    private val usable: (C) -> Boolean,
    private val selectAndApply: (List<XrayNetworkObservation<N, C, P>>, N?) -> N?,
    private val onResult: (XrayNetworkRebindResult) -> Unit,
    private val onError: (Exception) -> Unit,
    private val waitForBlockedCallback: Boolean = false,
    // Queried on the control worker, never from a callback; null when the network is gone.
    private val currentObservation: (N) -> XrayNetworkObservation<N, C, P>? = { null },
) : Closeable {
    // Also fences in-flight work: close returns only after a running policy/rebind call ends.
    // Reentrant so a host callback can stop its own session without deadlocking.
    private val lock = ReentrantLock()
    private var generation = 0L
    private var active: Session? = null
    private var pendingUnregister: Closeable? = null

    private inner class Entry {
        var capabilities: C? = null
        var properties: P? = null
        var blocked: Boolean? = if (waitForBlockedCallback) null else false

        val settled get() = capabilities != null && properties != null && blocked != null

        fun observation(network: N): XrayNetworkObservation<N, C, P>? {
            val caps = capabilities ?: return null
            val props = properties ?: return null
            return if (blocked == false && usable(caps)) XrayNetworkObservation(network, caps, props) else null
        }
    }

    private inner class Session(val generation: Long, val target: XrayNetworkRebindTarget, initialNetwork: N?) {
        val networks = linkedMapOf<N, Entry>()
        var selected: N? = initialNetwork
        var everSelected = initialNetwork != null
        // The host's actual carrier until its own callbacks or onLost arrive.
        var unreportedInitial: N? = initialNetwork
        var registered = false
        var registration: Closeable? = null
        var dirty = false
        var queued = false
    }

    private inner class Work(val session: Session) : Runnable {
        override fun run() = drain(session)
    }

    fun start(target: XrayNetworkRebindTarget, initialNetwork: N? = null) {
        val task = lock.withLock {
            check(active == null) { "network-change coordinator is already started" }
            // A failed unregister must not accumulate observers over repeated starts.
            unregisterPending()
            val session = Session(++generation, target, initialNetwork)
            active = session
            try {
                session.registration = register(events(session))
                session.registered = true
                queue(session)
            } catch (error: Exception) {
                active = null
                ++generation
                throw error
            }
        }
        submit(task)
    }

    override fun close() {
        lock.withLock {
            val previous = active
            active = null
            ++generation
            if (previous != null) pendingUnregister = previous.registration
            unregisterPending()
        }
    }

    private fun unregisterPending() {
        pendingUnregister?.close()
        pendingUnregister = null
    }

    private fun events(session: Session) = object : XrayNetworkEvents<N, C, P> {
        override fun available(network: N) = change(session) {
            session.networks.getOrPut(network) { Entry() }
        }

        override fun capabilities(network: N, capabilities: C) = update(session, network) {
            it.capabilities = capabilities
        }

        override fun properties(network: N, properties: P) = update(session, network) {
            it.properties = properties
        }

        override fun blocked(network: N, blocked: Boolean) = update(session, network) {
            it.blocked = blocked
        }

        override fun lost(network: N) = change(session) {
            session.networks.remove(network)
            if (session.unreportedInitial == network) session.unreportedInitial = null
            if (session.selected == network) session.dirty = true
        }
    }

    private fun update(session: Session, network: N, update: (Entry) -> Unit) = change(session) {
        // Late capability/property callbacks cannot resurrect a network after onLost.
        val entry = session.networks[network] ?: return@change
        val before = entry.observation(network)
        update(entry)
        if (session.unreportedInitial == network && entry.settled) session.unreportedInitial = null
        val after = entry.observation(network)
        if (before != after && (after != null || session.selected == network)) session.dirty = true
        // A caller-supplied initial carrier may become unusable before all metadata arrives.
        if (session.selected == network &&
            (entry.blocked == true || entry.capabilities?.let { !usable(it) } == true)
        ) session.dirty = true
    }

    private fun change(session: Session, update: () -> Unit) {
        val task = lock.withLock {
            if (active !== session) return
            update()
            queue(session)
        }
        submit(task)
    }

    private fun queue(session: Session): Work? {
        if (active !== session || !session.registered || !session.dirty || session.queued) return null
        session.queued = true
        return Work(session)
    }

    private fun submit(task: Work?) {
        if (task == null) return
        try {
            executor.execute(task)
        } catch (error: RejectedExecutionException) {
            // No control worker means the observer must stop rather than silently lose migrations.
            lock.withLock {
                if (active !== task.session) return
                try {
                    close()
                } catch (cleanup: Exception) {
                    if (cleanup !== error) error.addSuppressed(cleanup)
                }
            }
            onError(error)
        }
    }

    private fun drain(session: Session) {
        var next: Work? = null
        try {
            lock.withLock {
                if (active !== session) return
                session.dirty = false
                try {
                    val observed = session.networks.mapNotNull { (network, entry) -> entry.observation(network) }
                    val candidates = observed + listOfNotNull(unreportedInitial(session))
                    val selected = selectAndApply(candidates, session.selected)
                    if (active !== session || session.dirty) return@withLock
                    require(selected == null || candidates.any { it.network == selected }) {
                        "network policy selected an unavailable underlying network"
                    }
                    val previous = session.selected
                    session.selected = selected
                    if (selected == null) return@withLock
                    val initial = !session.everSelected
                    session.everSelected = true
                    if (initial || selected == previous) return@withLock

                    val hysteria = request { session.target.rebindHysteria() }
                    if (active !== session) return@withLock
                    val wireGuard = request { session.target.rebindWireGuard() }
                    if (active !== session) return@withLock
                    onResult(XrayNetworkRebindResult(session.generation, hysteria, wireGuard))
                } catch (error: Exception) {
                    onError(error)
                } finally {
                    session.queued = false
                    next = queue(session)
                }
            }
        } finally {
            submit(next)
        }
    }

    /**
     * Android reports existing networks one at a time, so the first drain can run before the
     * host's actual carrier has reported. Its current state keeps that partial burst from looking
     * like a migration away from it; a carrier that is already gone is handled as lost.
     */
    private fun unreportedInitial(session: Session): XrayNetworkObservation<N, C, P>? {
        val network = session.unreportedInitial ?: return null
        val current = currentObservation(network)?.takeIf { usable(it.capabilities) }
        if (current == null) session.unreportedInitial = null
        return current
    }

    private fun request(call: () -> Long): XrayRebindRequestResult = try {
        XrayRebindRequestResult.Accepted(call())
    } catch (error: Exception) {
        XrayRebindRequestResult.Failed(error)
    }
}
