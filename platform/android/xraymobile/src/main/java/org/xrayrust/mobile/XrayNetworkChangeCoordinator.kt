package org.xrayrust.mobile

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Parcel
import java.io.Closeable
import java.util.concurrent.Executor

/** Callback snapshots copied for this policy invocation; mutating them does not change the observer. */
data class XrayUnderlyingNetwork(
    val network: Network,
    val capabilities: NetworkCapabilities,
    val linkProperties: LinkProperties,
)

/**
 * Opt-in observation of non-VPN Internet networks. Requires ACCESS_NETWORK_STATE in the host manifest.
 *
 * [controlExecutor] must be the application's serial VPN control worker. [selectAndApply] runs there:
 * select a usable candidate, finish updating the application's carrier/socket-binding policy, then
 * return its Network (or null while offline). It must be quick and idempotent. Selection is always
 * application-owned; this helper neither binds sockets nor calls bindProcessToNetwork.
 *
 * Without an initial network, the first usable selection establishes a baseline. Subsequent identity
 * changes or recovery after loss request Hysteria2 and WireGuard rebind independently. Metadata updates do not
 * request rebind. Counts describe accepted/coalesced requests, never successful migration. Existing
 * endpoints are retained: DNS/NAT64 refresh and protocols without rebind need a host restart policy.
 *
 * Call [close] before core.stop()/close() and before closing its borrowed TUN descriptor. It unregisters
 * observation, invalidates queued work and waits for in-flight policy/rebind work. Start a new session
 * only after closing the old one; callbacks from its generation cannot touch the new core.
 *
 * [onError] reports policy and worker-scheduling failures (scheduling failures can be reported on a
 * callback thread). Registration/unregistration failures are thrown to the lifecycle caller. Both
 * protocol outcomes, including capability/closed-core errors, are delivered through [onResult].
 * Diagnostics callbacks should not throw. No core, descriptor, executor or Network is owned here.
 */
class XrayNetworkChangeCoordinator(
    connectivityManager: ConnectivityManager,
    controlExecutor: Executor,
    selectAndApply: (List<XrayUnderlyingNetwork>, Network?) -> Network?,
    onError: (Exception) -> Unit,
    onResult: (XrayNetworkRebindResult) -> Unit = {},
) : Closeable {
    private val state = XrayNetworkChangeState<Network, NetworkCapabilities, LinkProperties>(
        executor = controlExecutor,
        register = { events ->
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = events.available(network)
                override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) =
                    events.capabilities(network, NetworkCapabilities(capabilities))
                override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) =
                    events.properties(network, copyLinkProperties(properties))
                override fun onBlockedStatusChanged(network: Network, blocked: Boolean) =
                    events.blocked(network, blocked)
                override fun onLost(network: Network) = events.lost(network)
            }
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            try {
                // ACCESS_NETWORK_STATE belongs to the host manifest (class KDoc), which library lint cannot
                // see. Without it this throws SecurityException, which the catch below rethrows to start().
                @Suppress("MissingPermission")
                connectivityManager.registerNetworkCallback(request, callback)
            } catch (error: RuntimeException) {
                // Also covers a platform implementation that registers before throwing.
                try {
                    connectivityManager.unregisterNetworkCallback(callback)
                } catch (_: IllegalArgumentException) {
                    // No registration was installed.
                } catch (cleanup: RuntimeException) {
                    if (cleanup !== error) error.addSuppressed(cleanup)
                }
                throw error
            }
            Closeable { connectivityManager.unregisterNetworkCallback(callback) }
        },
        usable = { capabilities ->
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        },
        selectAndApply = { observations, previous ->
            selectAndApply(observations.map {
                XrayUnderlyingNetwork(it.network, NetworkCapabilities(it.capabilities), copyLinkProperties(it.properties))
            }, previous)
        },
        onResult = onResult,
        onError = onError,
        waitForBlockedCallback = Build.VERSION.SDK_INT >= 29,
        seedOnAvailable = Build.VERSION.SDK_INT < 26,
        currentObservation = { network -> connectivityManager.currentObservation(network) },
    )

    /**
     * Call after starting this core. Pass [initialNetwork] when the host already knows its actual
     * applied carrier, so changing it in the first observation is treated as a real migration.
     * Otherwise the first usable observation only establishes a baseline.
     */
    @JvmOverloads
    fun start(core: XrayCore, initialNetwork: Network? = null) = state.start(object : XrayNetworkRebindTarget {
        override fun rebindHysteria(): Long = core.rebindHysteria()
        override fun rebindWireGuard(): Long = core.rebindWireGuard()
    }, initialNetwork)

    override fun close() = state.close()
}

// LinkProperties' copy constructor is hidden from the public Android SDK. Parcelable preserves
// all fields supported by the running OS without relying on hidden APIs or a partial field list.
private fun copyLinkProperties(source: LinkProperties): LinkProperties {
    val parcel = Parcel.obtain()
    return try {
        source.writeToParcel(parcel, 0)
        parcel.setDataPosition(0)
        LinkProperties.CREATOR.createFromParcel(parcel)
    } finally {
        parcel.recycle()
    }
}

/**
 * Queried on the control worker, and from onAvailable only before API 26, where no metadata
 * callbacks follow it; a stale answer there is replaced by the next change callback. The host
 * manifest grants ACCESS_NETWORK_STATE.
 */
@Suppress("MissingPermission")
private fun ConnectivityManager.currentObservation(
    network: Network,
): XrayNetworkObservation<Network, NetworkCapabilities, LinkProperties>? {
    val capabilities = getNetworkCapabilities(network) ?: return null
    val properties = getLinkProperties(network) ?: return null
    return XrayNetworkObservation(network, capabilities, properties)
}
