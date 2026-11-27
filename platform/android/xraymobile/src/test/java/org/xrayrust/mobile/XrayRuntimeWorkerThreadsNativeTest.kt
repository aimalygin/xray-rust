package org.xrayrust.mobile

import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Optional host JNI check of the ABI 1.18 runtime worker threads against the current native library. */
class XrayRuntimeWorkerThreadsNativeTest {
    @Test
    fun hostWorkerCountReachesTheCore() {
        assumeTrue(java.lang.Boolean.getBoolean("xray.test.nativeImport"))
        assertTrue(XrayCore.ffiInfo().supports(XrayFfiCapability.RuntimeWorkerThreads))
        for (workers in listOf(1, 2, 6)) {
            XrayCore.create(FREEDOM_CONFIG, runtimeWorkerThreads = workers).use { core ->
                core.start()
                core.stop()
            }
        }
    }

    @Test
    fun workerCountOutsideTheRangeIsRejectedBeforeTheCoreExists() {
        assumeTrue(java.lang.Boolean.getBoolean("xray.test.nativeImport"))
        for (workers in listOf(-1, 0, MAX_RUNTIME_WORKER_THREADS + 1)) {
            assertThrows(IllegalArgumentException::class.java) {
                XrayCore.create(FREEDOM_CONFIG, runtimeWorkerThreads = workers)
            }
        }
    }

    @Test
    fun vpnServiceChecksItsHookWithTheSameRange() {
        assumeTrue(java.lang.Boolean.getBoolean("xray.test.nativeImport"))
        // XrayVpnService.runtimeWorkerThreads() goes through this before establish().
        for (workers in listOf(null, 1, MAX_RUNTIME_WORKER_THREADS)) {
            XrayCore.requireRuntimeWorkerThreadsInRange(workers)
        }
        for (workers in listOf(-1, 0, MAX_RUNTIME_WORKER_THREADS + 1)) {
            assertThrows(IllegalArgumentException::class.java) {
                XrayCore.requireRuntimeWorkerThreadsInRange(workers)
            }
        }
    }

    private companion object {
        const val FREEDOM_CONFIG = """{
            "inbounds": [{"tag": "tun-in", "protocol": "tun"}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        }"""
    }
}
