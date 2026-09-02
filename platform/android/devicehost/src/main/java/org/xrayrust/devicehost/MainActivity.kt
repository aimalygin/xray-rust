package org.xrayrust.devicehost

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import org.xrayrust.mobile.XrayVlessUrlImportException
import org.xrayrust.mobile.XrayVlessUrlImporter
import java.io.File
import java.io.RandomAccessFile

class MainActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var profileInput: EditText
    private lateinit var statusText: TextView
    private lateinit var connectButton: Button
    private lateinit var disconnectButton: Button
    private val refreshStatus = object : Runnable {
        override fun run() {
            renderStatus()
            handler.postDelayed(this, STATUS_REFRESH_MILLISECONDS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildContentView())
        requestNotificationPermission()
        handleAutomationCommand(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleAutomationCommand(intent)
    }

    override fun onResume() {
        super.onResume()
        handler.post(refreshStatus)
    }

    override fun onPause() {
        handler.removeCallbacks(refreshStatus)
        super.onPause()
    }

    @Deprecated("VpnService consent uses the platform activity result API on API 24+")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_CONSENT_REQUEST) {
            if (resultCode == RESULT_OK) {
                startVpnService()
            } else {
                showToast("VPN permission was not granted")
            }
        }
    }

    private fun buildContentView(): View {
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(20), dp(24), dp(20), dp(24))
        }
        content.addView(TextView(this).apply {
            text = "Xray Android Device Gate"
            textSize = 24f
            setTextColor(0xff172033.toInt())
        }, matchWrap())
        content.addView(TextView(this).apply {
            text = "The profile is encrypted with Android Keystore and is never logged. " +
                "Use the separate Device Probe app to generate traffic through the VPN."
            textSize = 15f
            setTextColor(0xff4b5568.toInt())
            setPadding(0, dp(8), 0, dp(18))
        }, matchWrap())

        statusText = TextView(this).apply {
            textSize = 16f
            setTextColor(0xff172033.toInt())
            setPadding(dp(14), dp(12), dp(14), dp(12))
            setBackgroundColor(0xffe8eef8.toInt())
        }
        content.addView(statusText, matchWrap())

        profileInput = EditText(this).apply {
            hint = "Paste a VLESS share link"
            minLines = 3
            maxLines = 7
            inputType = InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            }
            contentDescription = "VLESS profile input"
        }
        content.addView(profileInput, matchWrap(top = 18))

        content.addView(button("Import and encrypt profile") { importProfile() })
        connectButton = button("Connect VPN") { requestVpnConsentAndConnect() }
        content.addView(connectButton)
        disconnectButton = button("Disconnect VPN") { sendServiceAction(DeviceGateVpnService.ACTION_STOP) }
        content.addView(disconnectButton)
        content.addView(button("Rapid connect then stop") { rapidConnectThenStop() })
        content.addView(button("Close active connections") {
            sendServiceAction(DeviceGateVpnService.ACTION_CLOSE_CONNECTIONS, foreground = false)
        })
        content.addView(button("Reset campaign counters") {
            sendServiceAction(DeviceGateVpnService.ACTION_RESET_COUNTERS, foreground = false)
        })
        content.addView(button("Delete encrypted profile") {
            val status = DeviceGateStatus.read(this)
            if (status.state == "running" || status.state == "starting") {
                showToast("Disconnect before deleting the profile")
            } else {
                EncryptedProfileStore(this).clear()
                renderStatus()
            }
        })

        return ScrollView(this).apply { addView(content) }
    }

    private fun importProfile() {
        val rawUrl = profileInput.text.toString()
        if (rawUrl.isBlank()) {
            showToast("Paste a VLESS share link first")
            return
        }
        try {
            importRawProfile(rawUrl)
            profileInput.text.clear()
            clearClipboard()
            showToast("Profile imported and encrypted")
            renderStatus()
        } catch (error: XrayVlessUrlImportException) {
            val parameter = error.parameter?.let { " ($it)" } ?: ""
            showToast("Profile rejected: ${error.code}$parameter")
        } catch (error: Throwable) {
            showToast("Profile storage failed: ${error.javaClass.simpleName}")
        }
    }

    private fun importPendingPrivateProfile() {
        val pending = File(noBackupFilesDir, PENDING_PROFILE_FILE)
        if (!pending.isFile || pending.length() !in 1..MAX_PENDING_PROFILE_BYTES) {
            DeviceGateStatus.write(this, state = "failed", detail = "pending-profile-invalid")
            eraseAndDelete(pending)
            return
        }
        val rawBytes = pending.readBytes()
        try {
            importRawProfile(rawBytes.toString(Charsets.UTF_8))
        } catch (error: XrayVlessUrlImportException) {
            DeviceGateStatus.write(
                this,
                state = "failed",
                detail = "pending-profile-rejected-${error.code}",
            )
        } catch (error: Throwable) {
            DeviceGateStatus.write(
                this,
                state = "failed",
                detail = "pending-profile-${error.javaClass.simpleName}",
            )
        } finally {
            rawBytes.fill(0)
            eraseAndDelete(pending)
            renderStatus()
        }
    }

    private fun importPendingPrivateConfig() {
        val pending = File(noBackupFilesDir, PENDING_CONFIG_FILE)
        if (!pending.isFile || pending.length() !in 1..MAX_PENDING_PROFILE_BYTES) {
            DeviceGateStatus.write(this, state = "failed", detail = "pending-config-invalid")
            eraseAndDelete(pending)
            return
        }
        val rawBytes = pending.readBytes()
        try {
            val configJson = rawBytes.toString(Charsets.UTF_8)
            val config = JSONObject(configJson)
            require(config.getJSONArray("inbounds").length() > 0) {
                "profile config has no inbounds"
            }
            require(config.getJSONArray("outbounds").length() > 0) {
                "profile config has no outbounds"
            }
            EncryptedProfileStore(this).write(configJson)
            DeviceGateStatus.write(this, state = "stopped", detail = "config-profile-ready")
        } catch (error: Throwable) {
            DeviceGateStatus.write(
                this,
                state = "failed",
                detail = "pending-config-${error.javaClass.simpleName}",
            )
        } finally {
            rawBytes.fill(0)
            eraseAndDelete(pending)
            renderStatus()
        }
    }

    private fun importRawProfile(rawUrl: String) {
        val profile = XrayVlessUrlImporter.profile(rawUrl)
        EncryptedProfileStore(this).write(profile.configJson)
        DeviceGateStatus.write(this, state = "stopped", detail = "profile-ready")
    }

    private fun eraseAndDelete(file: File) {
        runCatching {
            if (file.isFile) {
                RandomAccessFile(file, "rw").use { output ->
                    val zeros = ByteArray(4096)
                    var remaining = output.length()
                    output.seek(0)
                    while (remaining > 0) {
                        val count = minOf(remaining, zeros.size.toLong()).toInt()
                        output.write(zeros, 0, count)
                        remaining -= count
                    }
                    output.fd.sync()
                }
            }
        }
        runCatching { file.delete() }
    }

    private fun requestVpnConsentAndConnect() {
        if (!EncryptedProfileStore(this).exists()) {
            showToast("Import a profile first")
            return
        }
        val consent = VpnService.prepare(this)
        if (consent == null) {
            startVpnService()
        } else {
            @Suppress("DEPRECATION")
            startActivityForResult(consent, VPN_CONSENT_REQUEST)
        }
    }

    private fun startVpnService() {
        sendServiceAction(DeviceGateVpnService.ACTION_START)
    }

    private fun rapidConnectThenStop() {
        if (!EncryptedProfileStore(this).exists()) {
            showToast("Import a profile first")
            return
        }
        if (DeviceGateStatus.read(this).state in setOf("running", "starting")) {
            showToast("Disconnect before the rapid-stop test")
            return
        }
        if (VpnService.prepare(this) != null) {
            showToast("Grant VPN permission before the rapid-stop test")
            return
        }
        sendServiceAction(DeviceGateVpnService.ACTION_RAPID_STOP)
    }

    private fun sendServiceAction(action: String, foreground: Boolean = true) {
        val serviceIntent = Intent(this, DeviceGateVpnService::class.java).setAction(action)
        if (foreground && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent)
        } else {
            startService(serviceIntent)
        }
    }

    private fun handleAutomationCommand(intent: Intent?) {
        when (intent?.getStringExtra(EXTRA_COMMAND)) {
            COMMAND_CONNECT -> requestVpnConsentAndConnect()
            COMMAND_DISCONNECT -> sendServiceAction(
                DeviceGateVpnService.ACTION_STOP,
                foreground = false,
            )
            COMMAND_RESET -> sendServiceAction(
                DeviceGateVpnService.ACTION_RESET_COUNTERS,
                foreground = false,
            )
            COMMAND_CLOSE_CONNECTIONS -> sendServiceAction(
                DeviceGateVpnService.ACTION_CLOSE_CONNECTIONS,
                foreground = false,
            )
            COMMAND_RAPID_STOP -> rapidConnectThenStop()
            COMMAND_IMPORT_PENDING -> importPendingPrivateProfile()
            COMMAND_IMPORT_PENDING_CONFIG -> importPendingPrivateConfig()
        }
        intent?.removeExtra(EXTRA_COMMAND)
    }

    private fun renderStatus() {
        val status = DeviceGateStatus.read(this)
        val detail = status.detail.takeIf { it.isNotBlank() }
            ?.let { getString(R.string.device_gate_detail, it) }
            ?: ""
        statusText.text = getString(
            R.string.device_gate_status,
            status.state,
            if (status.hasProfile) "ready" else "missing",
            status.runtimeGeneration,
            status.fatalTunErrors,
            detail,
        )
        connectButton.isEnabled = status.hasProfile && status.state !in setOf("running", "starting")
        disconnectButton.isEnabled = status.state in setOf("running", "starting", "fatal")
    }

    private fun clearClipboard() {
        val clipboard = getSystemService(ClipboardManager::class.java)
        clipboard.setPrimaryClip(ClipData.newPlainText("cleared", ""))
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
    }

    private fun button(label: String, onClick: () -> Unit): Button = Button(this).apply {
        text = label
        isAllCaps = false
        setOnClickListener { onClick() }
        layoutParams = matchWrap(top = 10)
    }

    private fun matchWrap(top: Int = 0): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(top) }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun showToast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    companion object {
        const val EXTRA_COMMAND = "command"
        const val COMMAND_CONNECT = "connect"
        const val COMMAND_DISCONNECT = "disconnect"
        const val COMMAND_RESET = "reset"
        const val COMMAND_CLOSE_CONNECTIONS = "close-connections"
        const val COMMAND_RAPID_STOP = "rapid-stop"
        const val COMMAND_IMPORT_PENDING = "import-pending"
        const val COMMAND_IMPORT_PENDING_CONFIG = "import-pending-config"
        const val PENDING_PROFILE_FILE = "profile-import.pending"
        const val PENDING_CONFIG_FILE = "profile-config-import.pending"
        private const val MAX_PENDING_PROFILE_BYTES = 256 * 1024L
        private const val VPN_CONSENT_REQUEST = 5041
        private const val STATUS_REFRESH_MILLISECONDS = 1_000L
    }
}
