package org.xrayrust.mobile

import org.junit.Assert.*
import org.junit.Test
import java.io.Closeable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class XrayNetworkChangeStateTest {
    private data class Caps(val usable: Boolean = true, val revision: Int = 0)
    private class Worker : Executor {
        val tasks = ArrayDeque<Runnable>()
        var reject = false
        override fun execute(command: Runnable) {
            if (reject) throw RejectedExecutionException("synthetic stopped worker")
            tasks.addLast(command)
        }
        fun drain() { while (tasks.isNotEmpty()) tasks.removeFirst().run() }
    }
    private class Target : XrayNetworkRebindTarget {
        val calls = mutableListOf<String>()
        var closed = false
        var hysteria: () -> Long = { 1 }
        var wireGuard: () -> Long = { 2 }
        override fun rebindHysteria(): Long {
            check(!closed) { "closed core" }; calls += "hysteria"; return hysteria()
        }
        override fun rebindWireGuard(): Long {
            check(!closed) { "closed core" }; calls += "wireguard"; return wireGuard()
        }
    }
    private class Fixture(waitForBlocked: Boolean = false, executor: Executor? = null) {
        val worker = Worker()
        val target = Target()
        val callbacks = mutableListOf<XrayNetworkEvents<String, Caps, Int>>()
        val results = mutableListOf<XrayNetworkRebindResult>()
        val errors = mutableListOf<Exception>()
        val applied = mutableListOf<String?>()
        var preference: String? = null
        var registrationError: Exception? = null
        var unregisterError: Exception? = null
        var unregisterCalls = 0
        var duringRegister: ((XrayNetworkEvents<String, Caps, Int>) -> Unit)? = null
        var policy: ((List<XrayNetworkObservation<String, Caps, Int>>, String?) -> String?)? = null
        var resultObserver: ((XrayNetworkRebindResult) -> Unit)? = null
        val state = XrayNetworkChangeState<String, Caps, Int>(
            executor ?: worker,
            register = { events ->
                callbacks += events
                duringRegister?.invoke(events)
                registrationError?.let { throw it }
                Closeable { unregisterCalls++; unregisterError?.let { throw it } }
            },
            usable = { it.usable },
            selectAndApply = { candidates, previous ->
                val currentPolicy = policy
                val selected = if (currentPolicy != null) currentPolicy(candidates, previous) else run {
                    val names = candidates.map { it.network }
                    preference?.takeIf { it in names } ?: previous?.takeIf { it in names } ?: names.firstOrNull()
                }
                applied += selected
                selected
            },
            onResult = { results += it; resultObserver?.invoke(it) },
            onError = { errors += it },
            waitForBlockedCallback = waitForBlocked,
        )
        val events get() = callbacks.last()
        fun start(target: Target = this.target) = state.start(target)
        fun available(name: String, usable: Boolean = true) {
            events.available(name); events.capabilities(name, Caps(usable)); events.properties(name, 1)
        }
        fun baseline() { start(); available("wifi"); worker.drain() }
        fun migrate(name: String = "cellular") {
            preference = name; available(name); worker.drain()
        }
    }

    @Test fun initialObservationWaitsForCallbackMetadataAndDoesNotRebind() {
        val f = Fixture(); f.start()
        f.events.available("wifi"); f.worker.drain(); assertTrue(f.applied.isEmpty())
        f.events.capabilities("wifi", Caps()); f.worker.drain(); assertTrue(f.applied.isEmpty())
        f.events.properties("wifi", 1); f.worker.drain()
        assertEquals(listOf("wifi"), f.applied); assertTrue(f.target.calls.isEmpty())
    }

    @Test fun knownInitialCarrierDoesNotRebindWhenObservedButDoesOnChange() {
        val f = Fixture(); f.state.start(f.target, "wifi")
        f.available("wifi"); f.worker.drain(); assertTrue(f.target.calls.isEmpty())
        f.migrate(); assertEquals(2, f.target.calls.size)
    }

    @Test fun knownInitialCarrierLossIsHandledBeforeItsMetadataArrives() {
        val f = Fixture(); f.state.start(f.target, "wifi")
        f.events.lost("wifi"); f.worker.drain(); assertNull(f.applied.last())
        f.migrate(); assertEquals(2, f.target.calls.size)
    }

    @Test fun firstDifferentCarrierIsMigrationWhenHostSuppliedActualInitialNetwork() {
        val f = Fixture(); f.state.start(f.target, "wifi"); f.migrate()
        assertEquals(2, f.target.calls.size)
    }

    @Test fun knownInitialCarrierBlockedBeforeMetadataRecordsOfflineThenRecovery() {
        val f = Fixture(waitForBlocked = true); f.state.start(f.target, "wifi")
        f.events.available("wifi"); f.events.blocked("wifi", true); f.worker.drain()
        assertNull(f.applied.last()); assertTrue(f.target.calls.isEmpty())
        f.available("wifi"); f.events.blocked("wifi", false); f.worker.drain()
        assertEquals(2, f.target.calls.size)
    }

    @Test fun metadataMayArriveInEitherOrder() {
        val f = Fixture(); f.start(); f.events.available("wifi")
        f.events.properties("wifi", 1); f.worker.drain(); assertTrue(f.applied.isEmpty())
        f.events.capabilities("wifi", Caps()); f.worker.drain()
        assertEquals(listOf("wifi"), f.applied)
    }

    @Test fun android29WaitsForUnblockedCallback() {
        val f = Fixture(waitForBlocked = true); f.start(); f.available("wifi"); f.worker.drain()
        assertTrue(f.applied.isEmpty())
        f.events.blocked("wifi", true); f.worker.drain(); assertTrue(f.applied.isEmpty())
        f.events.blocked("wifi", false); f.worker.drain()
        assertEquals(listOf("wifi"), f.applied); assertTrue(f.target.calls.isEmpty())
    }

    @Test fun unusableNetworksNeverReachPolicy() {
        val f = Fixture(); f.start(); f.available("vpn", usable = false); f.worker.drain()
        assertTrue(f.applied.isEmpty()); assertTrue(f.target.calls.isEmpty())
    }

    @Test fun duplicateCallbacksAndSameNetworkMetadataDoNotRebind() {
        val f = Fixture(); f.baseline()
        repeat(20) { f.available("wifi") }
        assertTrue(f.worker.tasks.isEmpty())
        f.events.capabilities("wifi", Caps(revision = 1)); f.events.properties("wifi", 2)
        assertEquals(1, f.worker.tasks.size); f.worker.drain()
        assertEquals(listOf("wifi", "wifi"), f.applied); assertTrue(f.target.calls.isEmpty())
    }

    @Test fun burstCoalescesToLatestAppliedCarrier() {
        val f = Fixture(); f.baseline()
        f.available("cellular"); f.available("ethernet"); f.preference = "ethernet"
        repeat(20) { f.available("cellular") }
        assertEquals(1, f.worker.tasks.size); f.worker.drain()
        assertEquals("ethernet", f.applied.last())
        assertEquals(listOf("hysteria", "wireguard"), f.target.calls)
        assertEquals(1, f.results.size)
    }

    @Test fun policyIsAppliedBeforeBothRebindRequests() {
        val f = Fixture(); f.baseline()
        f.target.hysteria = { assertEquals("cellular", f.applied.last()); 0 }
        f.target.wireGuard = { assertEquals("cellular", f.applied.last()); 0 }
        f.migrate()
        assertEquals(XrayRebindRequestResult.Accepted(0), f.results.single().hysteria)
        assertEquals(XrayRebindRequestResult.Accepted(0), f.results.single().wireGuard)
    }

    @Test fun losingUnrelatedNetworkDoesNotChangeSelectedCarrier() {
        val f = Fixture(); f.baseline(); f.available("cellular"); f.available("ethernet"); f.worker.drain()
        val count = f.applied.size
        f.preference = "cellular"; f.events.lost("ethernet"); f.worker.drain()
        assertEquals(count, f.applied.size); assertTrue(f.target.calls.isEmpty())
    }

    @Test fun lossWithoutReplacementDoesNotRebindAndOnlineRecoveryDoes() {
        val f = Fixture(); f.baseline(); f.events.lost("wifi"); f.worker.drain()
        assertNull(f.applied.last()); assertTrue(f.target.calls.isEmpty())
        f.migrate(); assertEquals(listOf("hysteria", "wireguard"), f.target.calls)
    }

    @Test fun lossOfSelectedNetworkCanUseAlreadyAvailableReplacement() {
        val f = Fixture(); f.baseline(); f.available("cellular"); f.worker.drain()
        assertTrue(f.target.calls.isEmpty())
        f.events.lost("wifi"); f.worker.drain()
        assertEquals("cellular", f.applied.last()); assertEquals(2, f.target.calls.size)
    }

    @Test fun blockedSelectedNetworkBehavesLikeLoss() {
        val f = Fixture(); f.baseline(); f.events.blocked("wifi", true); f.worker.drain()
        assertNull(f.applied.last()); assertTrue(f.target.calls.isEmpty())
        f.events.blocked("wifi", false); f.worker.drain(); assertEquals(2, f.target.calls.size)
    }

    @Test fun lateMetadataCannotResurrectLostNetwork() {
        val f = Fixture(); f.baseline(); f.events.lost("wifi"); f.worker.drain()
        val count = f.applied.size
        f.events.capabilities("wifi", Caps()); f.events.properties("wifi", 2); f.events.blocked("wifi", false)
        f.worker.drain(); assertEquals(count, f.applied.size); assertTrue(f.target.calls.isEmpty())
    }

    @Test fun firstNetworkLostBeforeObservationDoesNotCreateMigration() {
        val f = Fixture(); f.start(); f.available("wifi"); f.events.lost("wifi"); f.worker.drain()
        f.migrate(); assertTrue(f.target.calls.isEmpty())
    }

    @Test fun stopFencesQueuedWorkBeforeCoreClose() {
        val f = Fixture(); f.baseline(); f.preference = "cellular"; f.available("cellular")
        f.state.close(); assertEquals(1, f.unregisterCalls); f.target.closed = true
        f.worker.drain(); assertTrue(f.target.calls.isEmpty()); assertTrue(f.errors.isEmpty())
    }

    @Test fun callbacksAndQueuedTasksFromOldGenerationCannotTouchNewCore() {
        val f = Fixture(); f.baseline(); val old = f.events; f.available("cellular")
        f.state.close(); f.target.closed = true
        val next = Target(); f.start(next)
        old.available("stale"); old.capabilities("stale", Caps()); old.properties("stale", 1)
        f.available("wifi"); f.worker.drain(); assertTrue(next.calls.isEmpty())
        f.migrate(); assertEquals(2, next.calls.size); assertTrue(f.target.calls.isEmpty())
    }

    @Test fun activeStartIsRejectedWithoutReplacingSession() {
        val f = Fixture(); f.baseline()
        assertThrows(IllegalStateException::class.java) { f.start(Target()) }
        f.migrate(); assertEquals(2, f.target.calls.size); assertEquals(1, f.callbacks.size)
    }

    @Test fun registrationFailureDiscardsEvenSynchronousEvents() {
        val f = Fixture(); val failure = SecurityException("synthetic missing permission")
        f.duringRegister = { it.available("wifi"); it.capabilities("wifi", Caps()); it.properties("wifi", 1) }
        f.registrationError = failure
        assertSame(failure, assertThrows(SecurityException::class.java) { f.start() })
        f.worker.drain(); assertTrue(f.applied.isEmpty())
        val old = f.events; f.registrationError = null; f.duringRegister = null; f.start()
        old.available("old"); old.capabilities("old", Caps()); old.properties("old", 1)
        f.available("wifi"); f.worker.drain(); assertEquals(listOf("wifi"), f.applied)
    }

    @Test fun policyCannotRunBeforeSuccessfulRegistrationReturns() {
        val f = Fixture(executor = Executor { it.run() }); var registered = false
        f.duringRegister = { it.available("wifi"); it.capabilities("wifi", Caps()); it.properties("wifi", 1); registered = true }
        f.policy = { candidates, _ -> assertTrue(registered); candidates.first().network }
        f.start(); assertEquals(listOf("wifi"), f.applied)
    }

    @Test fun unregisterFailureStillFencesCallbacksAndCanBeRetried() {
        val f = Fixture(); f.baseline(); val failure = IllegalStateException("synthetic unregister failure")
        f.unregisterError = failure
        assertSame(failure, assertThrows(IllegalStateException::class.java) { f.state.close() })
        f.migrate(); assertTrue(f.target.calls.isEmpty())
        assertThrows(IllegalStateException::class.java) { f.start() }
        assertEquals(1, f.callbacks.size)
        f.unregisterError = null; f.state.close(); f.start(); f.available("wifi"); f.worker.drain()
    }

    @Test fun rejectedWorkerUnregistersAndReportsFailure() {
        val f = Fixture(); f.start(); f.worker.reject = true; f.available("wifi")
        assertEquals(1, f.unregisterCalls); assertTrue(f.errors.single() is RejectedExecutionException)
        f.worker.reject = false; f.start(); f.available("wifi"); f.worker.drain()
        assertTrue(f.target.calls.isEmpty())
    }

    @Test fun oldSubmissionRejectionCannotStopNewGeneration() {
        lateinit var f: Fixture
        var restart = true
        val executor = Executor { task ->
            if (restart) {
                restart = false
                f.state.close(); f.start()
                throw RejectedExecutionException("old generation submission")
            }
            task.run()
        }
        f = Fixture(executor = executor)
        f.start(); f.available("wifi")
        assertEquals(1, f.unregisterCalls); assertTrue(f.errors.isEmpty())
        f.available("wifi"); f.migrate()
        assertEquals(2, f.target.calls.size)
        assertEquals(1, f.unregisterCalls)
    }

    @Test fun oneProtocolFailureDoesNotPreventOtherRequestOrHideItsResult() {
        val f = Fixture(); f.baseline(); val unsupported = IllegalStateException("synthetic missing capability")
        f.target.hysteria = { throw unsupported }; f.migrate()
        assertSame(unsupported, (f.results.single().hysteria as XrayRebindRequestResult.Failed).error)
        assertEquals(XrayRebindRequestResult.Accepted(2), f.results.single().wireGuard)
        assertEquals(listOf("hysteria", "wireguard"), f.target.calls)
    }

    @Test fun alreadyClosedCoreProducesTwoIndependentErrors() {
        val f = Fixture(); f.baseline(); f.target.closed = true; f.migrate()
        assertTrue(f.results.single().hysteria is XrayRebindRequestResult.Failed)
        assertTrue(f.results.single().wireGuard is XrayRebindRequestResult.Failed)
    }

    @Test fun invalidHostSelectionNeverRebinds() {
        val f = Fixture(); f.baseline(); f.policy = { _, _ -> "absent" }; f.migrate()
        assertTrue(f.errors.single() is IllegalArgumentException); assertTrue(f.target.calls.isEmpty())
    }

    @Test fun hostCanDeclineAllAvailableNetworks() {
        val f = Fixture(); f.baseline(); f.policy = { _, _ -> null }; f.migrate()
        assertNull(f.applied.last()); assertTrue(f.target.calls.isEmpty())
        f.policy = null; f.events.properties("cellular", 2); f.worker.drain()
        assertEquals(2, f.target.calls.size)
    }

    @Test fun policyFailureLeavesNextEventProcessable() {
        val f = Fixture(); f.baseline(); val failure = IllegalStateException("synthetic policy failure")
        f.policy = { _, _ -> throw failure }; f.migrate()
        assertSame(failure, f.errors.single()); assertTrue(f.target.calls.isEmpty())
        f.policy = null; f.migrate("ethernet"); assertEquals(2, f.target.calls.size)
    }

    @Test fun policyCanStopSessionWithoutRebindingOrDeadlocking() {
        val f = Fixture(); f.baseline()
        f.policy = { candidates, _ -> f.state.close(); candidates.last().network }
        f.migrate(); assertTrue(f.target.calls.isEmpty()); assertEquals(1, f.unregisterCalls)
    }

    @Test fun callbackBurstDuringPolicyIsReevaluatedBeforeRebind() {
        val f = Fixture(); f.baseline(); var inject = true
        f.policy = { candidates, _ ->
            if (inject) { inject = false; f.available("ethernet") }
            candidates.last().network
        }
        f.migrate(); assertEquals("ethernet", f.applied.last()); assertEquals(2, f.target.calls.size)
    }

    @Test fun resultObserverFailureDoesNotWedgeNextEvent() {
        val f = Fixture(); f.baseline(); f.resultObserver = { throw IllegalStateException("synthetic observer failure") }
        f.migrate(); assertEquals(1, f.errors.size)
        f.resultObserver = null; f.migrate("ethernet"); assertEquals(2, f.results.size)
    }

    @Test fun closeWaitsForInFlightRequestsBeforeReturning() {
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val finished = CountDownLatch(1); val closed = CountDownLatch(1)
        val async = AtomicBoolean(false)
        val f = Fixture(executor = Executor { task ->
            if (async.get()) Thread { try { task.run() } finally { finished.countDown() } }.start() else task.run()
        })
        f.start(); f.available("wifi")
        f.target.hysteria = { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); 1 }
        async.set(true); f.preference = "cellular"; f.available("cellular")
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        val stop = Thread { f.state.close(); f.target.closed = true; closed.countDown() }
        stop.start()
        try { assertFalse(closed.await(100, TimeUnit.MILLISECONDS)) } finally { release.countDown() }
        assertTrue(closed.await(5, TimeUnit.SECONDS)); assertTrue(finished.await(5, TimeUnit.SECONDS)); stop.join()
        assertEquals(listOf("hysteria", "wireguard"), f.target.calls); assertEquals(1, f.unregisterCalls)
    }
}
