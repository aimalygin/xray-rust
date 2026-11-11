package org.xrayrust.devicehost

import android.content.Context

internal data class DeviceGateStatus(
    val state: String,
    val detail: String,
    val hasProfile: Boolean,
    val runtimeGeneration: Long,
    val fatalTunErrors: Long,
) {
    companion object {
        private const val PREFERENCES = "device-gate-status"
        private const val STATE = "state"
        private const val DETAIL = "detail"
        private const val HAS_PROFILE = "has-profile"
        private const val RUNTIME_GENERATION = "runtime-generation"
        private const val FATAL_TUN_ERRORS = "fatal-tun-errors"
        private const val NETWORK_REBINDS = "network-rebinds"
        private const val NETWORK_CHANGE_ERRORS = "network-change-errors"

        fun read(context: Context): DeviceGateStatus {
            val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            return DeviceGateStatus(
                state = preferences.getString(STATE, "stopped") ?: "stopped",
                detail = preferences.getString(DETAIL, "") ?: "",
                hasProfile = EncryptedProfileStore(context).exists(),
                runtimeGeneration = preferences.getLong(RUNTIME_GENERATION, 0),
                fatalTunErrors = preferences.getLong(FATAL_TUN_ERRORS, 0),
            )
        }

        fun write(
            context: Context,
            state: String,
            detail: String = "",
            runtimeGeneration: Long? = null,
            fatalTunErrors: Long? = null,
        ) {
            val editor = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                .edit()
                .putString(STATE, state)
                .putString(DETAIL, detail)
            runtimeGeneration?.let { editor.putLong(RUNTIME_GENERATION, it) }
            fatalTunErrors?.let { editor.putLong(FATAL_TUN_ERRORS, it) }
            editor.apply()
        }

        fun incrementGeneration(context: Context): Long {
            val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            val next = preferences.getLong(RUNTIME_GENERATION, 0) + 1
            preferences.edit().putLong(RUNTIME_GENERATION, next).apply()
            return next
        }

        fun incrementFatalTunErrors(context: Context): Long {
            val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            val next = preferences.getLong(FATAL_TUN_ERRORS, 0) + 1
            preferences.edit().putLong(FATAL_TUN_ERRORS, next).apply()
            return next
        }

        /** Rebind requests the SDK made after an underlying-network change. */
        fun incrementNetworkRebinds(context: Context): Long = increment(context, NETWORK_REBINDS)

        /** Network changes the SDK could not turn into a rebind request. */
        fun incrementNetworkChangeErrors(context: Context): Long =
            increment(context, NETWORK_CHANGE_ERRORS)

        private fun increment(context: Context, key: String): Long {
            val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            val next = preferences.getLong(key, 0) + 1
            preferences.edit().putLong(key, next).apply()
            return next
        }

        fun resetCounters(context: Context) {
            context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                .edit()
                .putLong(RUNTIME_GENERATION, 0)
                .putLong(FATAL_TUN_ERRORS, 0)
                .putLong(NETWORK_REBINDS, 0)
                .putLong(NETWORK_CHANGE_ERRORS, 0)
                .apply()
        }
    }
}
