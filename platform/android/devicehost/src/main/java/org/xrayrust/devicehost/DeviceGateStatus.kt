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

        fun resetCounters(context: Context) {
            context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                .edit()
                .putLong(RUNTIME_GENERATION, 0)
                .putLong(FATAL_TUN_ERRORS, 0)
                .apply()
        }
    }
}
