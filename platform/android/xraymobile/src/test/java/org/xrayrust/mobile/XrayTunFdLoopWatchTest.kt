package org.xrayrust.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class XrayTunFdLoopWatchTest {
    @Test
    fun reportsTheFirstLoopExitOnceAndEnds() {
        val reads = AtomicInteger()
        val stopped = AtomicInteger()
        val reported = CountDownLatch(1)
        val watch = XrayTunFdLoopWatch(
            intervalMillis = 5,
            // Unreadable at first, then running, then one loop gone.
            loopExits = { listOf(null, 0L, 0L, 1L)[reads.getAndIncrement().coerceAtMost(3)] },
            onStopped = {
                stopped.incrementAndGet()
                reported.countDown()
            },
        )
        watch.thread.start()

        assertTrue(reported.await(5, TimeUnit.SECONDS))
        watch.thread.join(5_000)
        assertFalse(watch.thread.isAlive)
        assertEquals(1, stopped.get())
        assertEquals(4, reads.get())
    }

    @Test
    fun aRunningSessionIsLeftAloneUntilItIsInterrupted() {
        val reads = CountDownLatch(3)
        val stopped = AtomicInteger()
        val watch = XrayTunFdLoopWatch(
            intervalMillis = 5,
            loopExits = {
                reads.countDown()
                0L
            },
            onStopped = { stopped.incrementAndGet() },
        )
        watch.thread.start()

        assertTrue(reads.await(5, TimeUnit.SECONDS))
        watch.thread.interrupt()
        watch.thread.join(5_000)
        assertFalse(watch.thread.isAlive)
        assertEquals(0, stopped.get())
        assertTrue(watch.thread.isDaemon)
    }
}
