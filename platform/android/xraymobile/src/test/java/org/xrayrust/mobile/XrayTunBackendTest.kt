package org.xrayrust.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

class XrayTunBackendTest {
    @Test
    fun directFileDescriptorBackendIsTheDefault() {
        assertEquals(XrayTunBackend.FileDescriptor, DEFAULT_XRAY_TUN_BACKEND)
    }

    @Test
    fun packetPumpRemainsAnExplicitFallback() {
        assertTrue(XrayTunBackend.entries.contains(XrayTunBackend.PacketPump))
        assertTrue(XrayTunBackend.PacketPump != DEFAULT_XRAY_TUN_BACKEND)
    }

    @Test
    fun lifecyclePublishesAndStopsOneSessionAtomically() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val token = lifecycle.beginStart()
        assertNotNull(token)
        assertNull(lifecycle.beginStart())
        assertTrue(lifecycle.isStartActive(token!!))
        assertTrue(lifecycle.publish(token, "session"))

        assertEquals("session", lifecycle.takeSessionForStop())
        lifecycle.completeStop()
        assertNotNull(lifecycle.beginStart())
    }

    @Test
    fun stopDuringStartCancelsPublicationAndWaitsForRollback() {
        val lifecycle = XrayTunnelStateMachine<String>()
        val token = lifecycle.beginStart()
        assertNotNull(token)
        val stoppedSession = AtomicReference<String?>("not-finished")
        val stopReturned = CountDownLatch(1)
        val stopThread = Thread {
            stoppedSession.set(lifecycle.takeSessionForStop())
            stopReturned.countDown()
        }
        stopThread.start()

        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
        while (lifecycle.isStartActive(token!!) && System.nanoTime() < deadline) {
            Thread.yield()
        }
        assertFalse(lifecycle.isStartActive(token))
        assertFalse(lifecycle.publish(token, "must-not-publish"))
        assertFalse(stopReturned.await(50, TimeUnit.MILLISECONDS))

        lifecycle.failStart(token)
        assertTrue(stopReturned.await(1, TimeUnit.SECONDS))
        assertNull(stoppedSession.get())
    }

    @Test
    fun onePumpFailureTearsDownTheWholeSessionExactlyOnce() {
        data class FakeSession(
            val active: AtomicBoolean = AtomicBoolean(true),
            val peerStopped: AtomicBoolean = AtomicBoolean(false),
            val coreClosed: AtomicBoolean = AtomicBoolean(false),
            val tunnelClosed: AtomicBoolean = AtomicBoolean(false),
            val shutdownCalls: AtomicInteger = AtomicInteger(),
        ) {
            fun shutdown() {
                shutdownCalls.incrementAndGet()
                active.set(false)
                peerStopped.set(true)
                coreClosed.set(true)
                tunnelClosed.set(true)
            }
        }

        val lifecycle = XrayTunnelStateMachine<FakeSession>()
        val token = lifecycle.beginStart()
        assertNotNull(token)
        val session = FakeSession()
        assertTrue(lifecycle.publish(token!!, session))

        assertTrue(teardownFailedXraySession(lifecycle, session) { it.shutdown() })
        assertFalse(teardownFailedXraySession(lifecycle, session) { it.shutdown() })
        assertFalse(session.active.get())
        assertTrue(session.peerStopped.get())
        assertTrue(session.coreClosed.get())
        assertTrue(session.tunnelClosed.get())
        assertEquals(1, session.shutdownCalls.get())
        assertNotNull(lifecycle.beginStart())
    }

    @Test
    fun repeatedPushBackpressureNeverTearsDownThePacketPump() {
        val lifecycle = XrayTunnelStateMachine<Any>()
        val token = lifecycle.beginStart()
        assertNotNull(token)
        val session = Any()
        assertTrue(lifecycle.publish(token!!, session))
        val backpressure = XrayCoreException(code = 8, message = "TUN queue is full")

        repeat(10_000) {
            assertTrue(isRecoverablePacketPushFailure(backpressure))
        }

        assertTrue(lifecycle.isRunningSession(session))
        assertFalse(isRecoverablePacketPushFailure(IllegalStateException("I/O failed")))
    }

    @Test
    fun packetPumpShutdownDoesNotWaitForItsOwnThread() {
        val returned = CountDownLatch(1)
        val worker = Thread {
            joinXrayPumpThreadUninterruptibly(Thread.currentThread())
            returned.countDown()
        }
        worker.isDaemon = true
        worker.start()

        assertTrue(returned.await(1, TimeUnit.SECONDS))
    }
}
