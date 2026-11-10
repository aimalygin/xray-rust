package org.xrayrust.mobile

internal const val TUN_FD_LOOP_WATCH_INTERVAL_MILLISECONDS = 2_000L

/**
 * Notices that the core gave up on a file-descriptor TUN session. Its read and write loops over the
 * borrowed descriptor stop on an error that means the descriptor is gone, and only count that they
 * did: nothing calls the host, which would go on showing a tunnel that moves no packets. This reads
 * the count every [intervalMillis] and reports the first stop once; a count that cannot be read, as
 * while the core closes, is not a stop.
 */
internal class XrayTunFdLoopWatch(
    private val intervalMillis: Long = TUN_FD_LOOP_WATCH_INTERVAL_MILLISECONDS,
    private val loopExits: () -> Long?,
    private val onStopped: () -> Unit,
) {
    val thread = Thread({ watch() }, "xray-tun-fd-watch").apply { isDaemon = true }

    private fun watch() {
        try {
            while (!Thread.currentThread().isInterrupted) {
                Thread.sleep(intervalMillis)
                if ((loopExits() ?: 0) > 0) {
                    onStopped()
                    return
                }
            }
        } catch (_: InterruptedException) {
            // The session is shutting down.
        }
    }
}
