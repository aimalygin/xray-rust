package org.xrayrust.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class XrayTunnelStartReplacementTest {
    private val launched = AtomicReference<XrayTunnelStateMachine.StartToken?>()

    private fun XrayTunnelStateMachine<String>.replace(): XrayTunnelStartAdmission =
        beginOrReplaceStart { launched.set(it) }

    @Test(timeout = TIMEOUT_MILLIS)
    fun stoppedLifecycleStartsImmediately() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val admission = lifecycle.replace()

        assertTrue(admission is XrayTunnelStartAdmission.Started)
        assertTrue(lifecycle.isStartActive((admission as XrayTunnelStartAdmission.Started).token))
        assertNull(launched.get())
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun replacementWaitsForTheCancelledAttemptToRelease() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val first = checkNotNull(lifecycle.beginStart())

        val admission = lifecycle.replace()

        assertEquals(XrayTunnelStartAdmission.Queued(cancelled = first, displacedQueuedStart = false), admission)
        assertFalse(lifecycle.isStartActive(first))
        assertFalse(lifecycle.publish(first, "stale"))
        assertNull(lifecycle.beginStart())
        assertNull(launched.get())

        val launch = checkNotNull(lifecycle.failStart(first))
        assertNull(launched.get())
        assertNull(lifecycle.beginStart())
        launch()

        val second = checkNotNull(launched.get())
        assertTrue(lifecycle.isStartActive(second))
        assertTrue(lifecycle.publish(second, "session"))
        assertEquals("session", lifecycle.runningSession())
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun laterReplacementDisplacesTheQueuedOne() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val first = checkNotNull(lifecycle.beginStart())
        val launches = CopyOnWriteArrayList<String>()

        lifecycle.beginOrReplaceStart { launches += "second" }
        val admission = lifecycle.beginOrReplaceStart { launches += "third" }

        assertEquals(XrayTunnelStartAdmission.Queued(cancelled = first, displacedQueuedStart = true), admission)
        checkNotNull(lifecycle.failStart(first)).invoke()
        assertEquals(listOf("third"), launches)
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun stopDiscardsTheQueuedReplacement() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val first = checkNotNull(lifecycle.beginStart())
        lifecycle.replace()

        assertEquals(XrayTunnelStopAction.CancelStart(discardedQueuedStart = true), lifecycle.requestStop())
        assertNull(lifecycle.failStart(first))
        assertNull(launched.get())
        assertNotNull(lifecycle.beginStart())
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun startIsRejectedWhileASessionRuns() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val token = checkNotNull(lifecycle.beginStart())
        assertTrue(lifecycle.publish(token, "session"))

        assertEquals(XrayTunnelStartAdmission.Rejected, lifecycle.replace())
        assertTrue(lifecycle.requestStop() is XrayTunnelStopAction.StopSession)
        assertNull(lifecycle.completeStop())
        assertTrue(lifecycle.replace() is XrayTunnelStartAdmission.Started)
        assertNull(launched.get())
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun startWhileASessionStopsRunsOnceTheStopCompletes() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val token = checkNotNull(lifecycle.beginStart())
        assertTrue(lifecycle.publish(token, "session"))
        assertTrue(lifecycle.requestStop() is XrayTunnelStopAction.StopSession)

        assertEquals(XrayTunnelStartAdmission.AwaitingStop(displacedQueuedStart = false), lifecycle.replace())
        assertNull(launched.get())

        checkNotNull(lifecycle.completeStop()).invoke()
        assertTrue(lifecycle.isStartActive(checkNotNull(launched.get())))
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun startDuringAPumpFailureTeardownRunsAfterTheFatalReport() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val token = checkNotNull(lifecycle.beginStart())
        assertTrue(lifecycle.publish(token, "session"))
        val events = CopyOnWriteArrayList<String>()
        val shutdownFailure = IllegalStateException("tunnel close failed")

        val stopped = teardownFailedXraySession(
            lifecycle = lifecycle,
            failedSession = "session",
            shutdown = {
                events += "shutdown"
                val admission = lifecycle.beginOrReplaceStart("next") { events += "launch" }
                assertEquals(XrayTunnelStartAdmission.AwaitingStop(displacedQueuedStart = false), admission)
                throw shutdownFailure
            },
            onStopped = { failure ->
                assertSame(shutdownFailure, failure)
                events += "fatal"
            },
        )

        assertTrue(stopped)
        assertEquals(listOf("shutdown", "fatal", "launch"), events)
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun startsQueuedBehindAStopDisplaceOrRepeatAndStopDiscardsThem() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val token = checkNotNull(lifecycle.beginStart())
        assertTrue(lifecycle.publish(token, "session"))
        assertTrue(lifecycle.requestStop() is XrayTunnelStopAction.StopSession)
        val launches = CopyOnWriteArrayList<String>()

        lifecycle.beginOrReplaceStart("first") { launches += "first" }
        assertEquals(XrayTunnelStartAdmission.Rejected, lifecycle.beginOrReplaceStart("first") { launches += "again" })
        assertEquals(
            XrayTunnelStartAdmission.AwaitingStop(displacedQueuedStart = true),
            lifecycle.beginOrReplaceStart("second") { launches += "second" },
        )
        assertEquals(XrayTunnelStopAction.CancelStart(discardedQueuedStart = true), lifecycle.requestStop())
        assertEquals(XrayTunnelStopAction.None, lifecycle.requestStop())

        assertNull(lifecycle.completeStop())
        assertTrue(launches.isEmpty())
        assertNotNull(lifecycle.beginStart())
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun startedCallbackNeverFollowsAStopThatReturned() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val notice = XrayStartedNotice(lifecycle)
        val token = checkNotNull(lifecycle.beginStart())
        assertTrue(lifecycle.publish(token, "session"))
        val events = CopyOnWriteArrayList<String>()
        val inCallback = CountDownLatch(1)
        val releaseCallback = CountDownLatch(1)

        val worker = Thread {
            notice.deliver(
                session = "session",
                onStarted = {
                    events += "started"
                    inCallback.countDown()
                    releaseCallback.await()
                },
                onCancelled = { events += "cancelled" },
            )
        }.apply { start() }
        assertTrue(inCallback.await(1, TimeUnit.SECONDS))

        assertTrue(lifecycle.requestStop() is XrayTunnelStopAction.StopSession)
        val stopper = Thread {
            notice.awaitDelivery()
            events += "stopped"
        }.apply { start() }
        stopper.join(100)
        assertTrue(stopper.isAlive)

        releaseCallback.countDown()
        stopper.join(1_000)
        worker.join(1_000)
        notice.deliver("session", onStarted = { events += "late started" }, onCancelled = { events += "cancelled" })
        assertEquals(listOf("started", "stopped", "cancelled"), events)
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun startedCallbackMayStopItsOwnSession() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val notice = XrayStartedNotice(lifecycle)
        val token = checkNotNull(lifecycle.beginStart())
        assertTrue(lifecycle.publish(token, "session"))

        notice.deliver(
            session = "session",
            onStarted = {
                assertTrue(lifecycle.requestStop() is XrayTunnelStopAction.StopSession)
                notice.awaitDelivery()
                lifecycle.completeStop()
            },
            onCancelled = { error("the session was running") },
        )

        assertNull(lifecycle.runningSession())
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun replacementAfterFailedPublicationRunsOnceThatAttemptReleases() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val first = checkNotNull(lifecycle.beginStart())
        assertThrows(IllegalStateException::class.java) {
            lifecycle.publish(first, "session") { error("pump start failed") }
        }

        assertEquals(XrayTunnelStartAdmission.Queued(cancelled = first, displacedQueuedStart = false), lifecycle.replace())
        assertFalse(lifecycle.isStartFailureReportable(first))
        checkNotNull(lifecycle.failStart(first)).invoke()
        assertTrue(lifecycle.isStartActive(checkNotNull(launched.get())))
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun staleReleaseCannotTouchThePromotedReplacement() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val first = checkNotNull(lifecycle.beginStart())
        lifecycle.replace()
        checkNotNull(lifecycle.failStart(first)).invoke()
        val second = checkNotNull(launched.get())

        assertNull(lifecycle.failStart(first))
        assertTrue(lifecycle.isStartActive(second))
        assertEquals(XrayTunnelStopAction.CancelStart(), lifecycle.requestStop())
        assertFalse(lifecycle.isStartActive(second))
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun attemptCancelledBeforeItsWorkerRanReportsThenLaunchesTheReplacement() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val queuedTask = AtomicReference<Runnable?>()
        val coordinator = XrayAsyncStartCoordinator(lifecycle, Executor { queuedTask.set(it) })
        val events = CopyOnWriteArrayList<String>()
        val first = checkNotNull(lifecycle.beginStart())
        coordinator.execute(
            token = first,
            block = { events += "block" },
            afterRelease = { events += "afterRelease" },
            onCancelledBeforeRun = { events += "cancelled" },
        )

        val admission = lifecycle.beginOrReplaceStart { events += "launch" }
        coordinator.cancelActiveStart((admission as XrayTunnelStartAdmission.Queued).cancelled)

        assertEquals(listOf("cancelled", "launch"), events)
        assertFalse(coordinator.hasActiveStart())
        queuedTask.get()?.run()
        assertEquals(listOf("cancelled", "launch"), events)
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun workerDeliversItsOutcomeBeforeLaunchingTheReplacement() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val coordinator = XrayAsyncStartCoordinator(lifecycle, Executor { Thread(it).start() })
        val events = CopyOnWriteArrayList<String>()
        val blockStarted = CountDownLatch(1)
        val launchedReplacement = CountDownLatch(1)
        val first = checkNotNull(lifecycle.beginStart())
        coordinator.execute(
            token = first,
            block = {
                blockStarted.countDown()
                while (lifecycle.isStartActive(first)) Thread.yield()
                "cancelled"
            },
            afterRelease = { outcome -> events += outcome },
            onCancelledBeforeRun = { events += "never ran" },
        )
        assertTrue(blockStarted.await(1, TimeUnit.SECONDS))

        lifecycle.beginOrReplaceStart {
            events += "launch"
            launchedReplacement.countDown()
        }

        assertTrue(launchedReplacement.await(1, TimeUnit.SECONDS))
        assertEquals(listOf("cancelled", "launch"), events)
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun rejectedSchedulingIsThrownWithoutACancellationCallback() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val coordinator = XrayAsyncStartCoordinator(
            lifecycle,
            Executor { throw RejectedExecutionException("saturated") },
        )
        val cancelled = AtomicReference(false)
        val token = checkNotNull(lifecycle.beginStart())

        assertThrows(RejectedExecutionException::class.java) {
            coordinator.execute(token, block = {}, afterRelease = {}, onCancelledBeforeRun = { cancelled.set(true) })
        }
        assertFalse(cancelled.get())
        assertFalse(coordinator.hasActiveStart())
        assertNull(lifecycle.beginStart())
        assertNull(lifecycle.failStart(token))
        assertNotNull(lifecycle.beginStart())
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun rejectedSchedulingLeavesTheQueuedReplacementToTheCaller() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val coordinator = XrayAsyncStartCoordinator(
            lifecycle,
            Executor { throw RejectedExecutionException("saturated") },
        )
        val events = CopyOnWriteArrayList<String>()
        val token = checkNotNull(lifecycle.beginStart())
        lifecycle.beginOrReplaceStart { events += "launch" }

        val error = assertThrows(RejectedExecutionException::class.java) {
            coordinator.execute(token, block = {}, afterRelease = {}, onCancelledBeforeRun = { events += "cancelled" })
        }
        assertEquals(emptyList<String>(), events)

        reportUnscheduledStart(
            lifecycle = lifecycle,
            attempt = token,
            error = error,
            onFailed = { events += "failed" },
            onCancelled = { events += "cancelled" },
        )
        assertEquals(listOf("cancelled", "launch"), events)
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun unscheduledActiveStartReportsFailure() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val events = CopyOnWriteArrayList<String>()
        val token = checkNotNull(lifecycle.beginStart())

        reportUnscheduledStart(
            lifecycle = lifecycle,
            attempt = token,
            error = RejectedExecutionException("saturated"),
            onFailed = { events += "failed" },
            onCancelled = { events += "cancelled" },
        )

        assertEquals(listOf("failed"), events)
        assertNotNull(lifecycle.beginStart())
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun unscheduledStartStoppedMeanwhileReportsCancellation() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val events = CopyOnWriteArrayList<String>()
        val token = checkNotNull(lifecycle.beginStart())
        lifecycle.requestStop()

        reportUnscheduledStart(
            lifecycle = lifecycle,
            attempt = token,
            error = RejectedExecutionException("shut down"),
            onFailed = { events += "failed" },
            onCancelled = { events += "cancelled" },
        )

        assertEquals(listOf("cancelled"), events)
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun identicalRequestWhileStartingIsIgnored() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val first = (lifecycle.beginOrReplaceStart("a") {} as XrayTunnelStartAdmission.Started).token

        assertEquals(XrayTunnelStartAdmission.Rejected, lifecycle.beginOrReplaceStart("a") {})
        assertTrue(lifecycle.isStartActive(first))

        val admission = lifecycle.beginOrReplaceStart("b") { launched.set(it) }
        assertEquals(XrayTunnelStartAdmission.Queued(cancelled = first, displacedQueuedStart = false), admission)
        assertEquals(XrayTunnelStartAdmission.Rejected, lifecycle.beginOrReplaceStart("b") {})

        checkNotNull(lifecycle.failStart(first)).invoke()
        val second = checkNotNull(launched.get())
        assertEquals(XrayTunnelStartAdmission.Rejected, lifecycle.beginOrReplaceStart("b") {})
        assertTrue(lifecycle.isStartActive(second))
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun identicalRequestAfterStopReplaces() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val stopped = (lifecycle.beginOrReplaceStart("a") {} as XrayTunnelStartAdmission.Started).token
        lifecycle.requestStop()

        assertEquals(
            XrayTunnelStartAdmission.Queued(cancelled = stopped, displacedQueuedStart = false),
            lifecycle.beginOrReplaceStart("a") { launched.set(it) },
        )
        checkNotNull(lifecycle.failStart(stopped)).invoke()
        assertTrue(lifecycle.isStartActive(checkNotNull(launched.get())))
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun identicalRequestAfterFailedPublicationReplaces() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val failed = (lifecycle.beginOrReplaceStart("a") {} as XrayTunnelStartAdmission.Started).token
        assertThrows(IllegalStateException::class.java) {
            lifecycle.publish(failed, "session") { error("pump start failed") }
        }

        assertEquals(
            XrayTunnelStartAdmission.Queued(cancelled = failed, displacedQueuedStart = false),
            lifecycle.beginOrReplaceStart("a") {},
        )
    }

    @Test(timeout = TIMEOUT_MILLIS)
    fun targetedCancelIgnoresAnotherAttemptsWorker() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val queuedTask = AtomicReference<Runnable?>()
        val coordinator = XrayAsyncStartCoordinator(lifecycle, Executor { queuedTask.set(it) })
        val ran = AtomicReference(false)
        val token = checkNotNull(lifecycle.beginStart())
        coordinator.execute(token) { ran.set(true) }

        coordinator.cancelActiveStart(XrayTunnelStateMachine.StartToken())

        assertTrue(coordinator.hasActiveStart())
        checkNotNull(queuedTask.get()).run()
        assertTrue(ran.get())
    }

    @Test
    fun defaultCarrierPrefersSystemDefaultThenPreviousThenValidated() {
        data class Candidate(val network: String, val validated: Boolean)

        val candidates = listOf(Candidate("cell", validated = false), Candidate("wifi", validated = true))
        fun pick(systemDefault: String?, previous: String?) = candidates.preferredUnderlyingNetwork(
            network = { it.network },
            validated = { it.validated },
            systemDefault = systemDefault,
            previous = previous,
        )

        assertSame("cell", pick(systemDefault = "cell", previous = "wifi"))
        assertSame("cell", pick(systemDefault = "vpn", previous = "cell"))
        assertSame("wifi", pick(systemDefault = null, previous = "gone"))
        val unvalidated = listOf(Candidate("cell", validated = false), Candidate("wifi", validated = false))
        assertSame("cell", unvalidated.preferredUnderlyingNetwork({ it.network }, { it.validated }, "vpn", null))
        assertNull(emptyList<Candidate>().preferredUnderlyingNetwork({ it.network }, { it.validated }, "cell", "wifi"))
    }

    private companion object {
        const val TIMEOUT_MILLIS = 5_000L
    }
}
