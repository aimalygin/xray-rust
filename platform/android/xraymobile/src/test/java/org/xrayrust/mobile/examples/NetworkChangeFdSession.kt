package org.xrayrust.mobile.examples

import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor
import org.xrayrust.mobile.*
import java.io.Closeable
import java.util.concurrent.Executor

/**
 * Compiled integration example for an app that owns its VPN lifecycle and TUN fd.
 * Call start/close on the same serial VPN worker used by the coordinator.
 * This example takes ownership of tun, including on startup failure; the core only borrows it.
 */
class NetworkChangeFdSession private constructor(
    private val tun: ParcelFileDescriptor,
    private val core: XrayCore,
    private val coordinator: XrayNetworkChangeCoordinator,
) : Closeable {
    private var closed = false

    companion object {
        fun start(
            preparedConfig: String,
            tun: ParcelFileDescriptor,
            service: VpnService,
            connectivity: ConnectivityManager,
            worker: Executor,
            actualInitialNetwork: Network?,
            selectAndApply: (List<XrayUnderlyingNetwork>, Network?) -> Network?,
            onError: (Exception) -> Unit,
            onResult: (XrayNetworkRebindResult) -> Unit,
        ): NetworkChangeFdSession {
            // The app prepared DNS/endpoints before establishing tun. The service's protect(fd)
            // must protect each carrier and apply any explicit Network.bindSocket policy.
            var core: XrayCore? = null
            var coordinator: XrayNetworkChangeCoordinator? = null
            try {
                core = XrayCore.create(
                    preparedConfig,
                    vpnService = service,
                    tunFileDescriptor = XrayTunFileDescriptor(tun.fd), // Borrowed, raw IP.
                    dnsBootstrapMode = XrayDnsBootstrapMode.StaticOnly,
                )
                core.start()
                coordinator = XrayNetworkChangeCoordinator(
                    connectivity, worker, selectAndApply, onError, onResult,
                )
                coordinator.start(core, actualInitialNetwork)
                return NetworkChangeFdSession(tun, core, coordinator)
            } catch (error: Throwable) {
                // Preserve the original error while releasing resources in dependency order.
                listOfNotNull(coordinator, core, tun).forEach { resource ->
                    try { resource.close() } catch (cleanup: Throwable) {
                        if (cleanup !== error) error.addSuppressed(cleanup)
                    }
                }
                throw error
            }
        }
    }

    override fun close() {
        if (closed) {
            coordinator.close() // Retry a previous unregister failure without touching core/tun.
            return
        }
        closed = true
        tun.use {
            core.use {
                coordinator.close() // Unregister, invalidate queued work, wait for in-flight work.
                core.stop()
            } // Core close still runs if unregister/stop throws.
        } // Borrowed fd outlives the core, including on errors.
    }
}
