package org.xrayrust.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.Closeable
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/** Exercises the preflight coordinator used by [XrayVpnService] with a scripted core. */
class XrayStartupProbePreflightTest {
    private val probe = XrayStartupProbeOptions(url = "http://127.0.0.1:9/health")
    private val events: MutableList<String> = Collections.synchronizedList(mutableListOf())
    private val lifecycle = XrayTunnelStateMachine<String>()
    private val preflight = XrayStartupProbePreflight<ScriptedCore>(
        lifecycle = lifecycle,
        preflight = { it.preflight() },
        cancelPreflight = { it.cancel() },
    )

    @Test
    fun startupProbePreflightKeepsItsAbiBit() {
        assertEquals(1L shl 25, XrayFfiCapability.StartupProbePreflight.mask)
    }

    @Test
    fun disabledProbeCreatesNoPreflightCore() {
        val token = lifecycle.beginStart()!!

        preflight.run(token, startupProbe = null) { error("a disabled probe must not create a core") }
        events += "establish"

        assertEquals(listOf("establish"), events)
    }

    @Test
    fun probeAndCoreCloseFinishBeforeTheCallerEstablishes() {
        val token = lifecycle.beginStart()!!
        val requested = AtomicReference<XrayStartupProbeOptions>()

        preflight.run(token, probe) { options ->
            requested.set(options)
            ScriptedCore(events)
        }
        events += "establish"

        assertSame(probe, requested.get())
        assertEquals(listOf("create", "preflight", "close", "establish"), events)
    }

    @Test
    fun failedProbeOrCoreCreationPropagatesWithoutReturning() {
        val token = lifecycle.beginStart()!!
        val probeFailure = XrayCoreException(5, "startup probe received HTTP status 503")
        val invalidProbe = XrayCoreException(9, "unsupported startup probe URL")

        val error = assertThrows(XrayCoreException::class.java) {
            preflight.run(token, probe) { ScriptedCore(events) { throw probeFailure } }
        }
        assertSame(probeFailure, error)
        assertSame(invalidProbe, assertThrows(XrayCoreException::class.java) {
            preflight.run(token, probe) { throw invalidProbe }
        })

        assertEquals(listOf("create", "preflight", "close"), events)
        assertTrue(lifecycle.isStartFailureReportable(token))
    }

    @Test
    fun stopDuringProbeCancelsItWithoutWaitingForTheWorker() {
        val token = lifecycle.beginStart()!!
        val entered = CountDownLatch(1)
        val releaseClose = CountDownLatch(1)
        val pending = AtomicReference<ScriptedCore>()
        val outcome = AtomicReference<Throwable?>()
        val worker = Thread {
            try {
                preflight.run(token, probe) {
                    ScriptedCore(events, onClose = { releaseClose.await(5, TimeUnit.SECONDS) }) { core ->
                        pending.set(core)
                        entered.countDown()
                        // Like the native latch, only a cancellation releases the probe.
                        check(core.cancelled.await(5, TimeUnit.SECONDS)) { "probe was not cancelled" }
                        throw XrayCoreException(5, "startup probe was cancelled")
                    }
                }
                events += "establish"
            } catch (error: Throwable) {
                outcome.set(error)
            }
        }
        worker.start()
        assertTrue(entered.await(5, TimeUnit.SECONDS))

        val started = System.nanoTime()
        assertEquals(XrayTunnelStopAction.CancelStart, lifecycle.requestStop())
        preflight.cancel()
        // The worker is still blocked in close(), so the stop path did not join it.
        assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(1))
        assertTrue(worker.isAlive)
        releaseClose.countDown()
        worker.join(5_000)

        assertFalse(worker.isAlive)
        assertEquals(1, pending.get().cancelCalls.get())
        assertTrue(outcome.get() is XrayCoreException)
        assertEquals(listOf("create", "preflight", "close"), events)
        // XrayVpnService reports this native cancellation as Cancelled, not Failed.
        assertFalse(lifecycle.isStartFailureReportable(token))
    }

    @Test
    fun stopWhileTheCoreIsCreatedSkipsTheNativeProbe() {
        val token = lifecycle.beginStart()!!

        assertThrows(XrayStartCancelledException::class.java) {
            preflight.run(token, probe) {
                assertEquals(XrayTunnelStopAction.CancelStart, lifecycle.requestStop())
                preflight.cancel()
                ScriptedCore(events) { error("a cancelled start must not probe") }
            }
        }

        assertEquals(listOf("create", "close"), events)
    }

    @Test
    fun stopAfterTheProbePassedStillPreventsEstablish() {
        val token = lifecycle.beginStart()!!

        assertThrows(XrayStartCancelledException::class.java) {
            preflight.run(token, probe) {
                ScriptedCore(events) { lifecycle.requestStop() }
            }
        }

        assertEquals(listOf("create", "preflight", "close"), events)
    }

    @Test
    fun cancelOnlyEndsTheProbeOfACancelledStart() {
        val token = lifecycle.beginStart()!!
        val cancelCallsWhileActive = AtomicInteger(-1)
        val pending = AtomicReference<ScriptedCore>()

        assertThrows(XrayStartCancelledException::class.java) {
            preflight.run(token, probe) {
                ScriptedCore(events) { core ->
                    pending.set(core)
                    // A late stop for an earlier attempt must not cancel this active start.
                    preflight.cancel()
                    cancelCallsWhileActive.set(core.cancelCalls.get())
                    assertEquals(XrayTunnelStopAction.CancelStart, lifecycle.requestStop())
                    preflight.cancel()
                }
            }
        }

        assertEquals(0, cancelCallsWhileActive.get())
        assertEquals(1, pending.get().cancelCalls.get())
        preflight.cancel()
        assertEquals(1, pending.get().cancelCalls.get())
    }

    private class ScriptedCore(
        private val events: MutableList<String>,
        private val onClose: () -> Unit = {},
        private val onPreflight: (ScriptedCore) -> Unit = {},
    ) : Closeable {
        val cancelled = CountDownLatch(1)
        val cancelCalls = AtomicInteger()

        init {
            events += "create"
        }

        fun preflight() {
            events += "preflight"
            onPreflight(this)
        }

        fun cancel() {
            cancelCalls.incrementAndGet()
            cancelled.countDown()
        }

        override fun close() {
            onClose()
            events += "close"
        }
    }
}
