package org.xrayrust.deviceprobe

import android.Manifest
import android.app.Activity
import android.content.Intent
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

class ProbeActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var httpUrlInput: EditText
    private lateinit var udpHostInput: EditText
    private lateinit var udpPortInput: EditText
    private lateinit var intervalInput: EditText
    private lateinit var statusText: TextView
    private lateinit var startButton: Button
    private lateinit var stopButton: Button
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
        loadConfiguration()
        handler.post(refreshStatus)
    }

    override fun onPause() {
        handler.removeCallbacks(refreshStatus)
        super.onPause()
    }

    private fun buildContentView(): View {
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(20), dp(24), dp(20), dp(24))
        }
        content.addView(TextView(this).apply {
            text = "Xray Android Device Probe"
            textSize = 24f
            setTextColor(0xff172033.toInt())
        }, matchWrap())
        content.addView(TextView(this).apply {
            text = "This app has a separate UID from the VPN host, so its HTTP and UDP " +
                "traffic traverses the Android TUN interface. Probe logs contain no endpoints."
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

        httpUrlInput = input("HTTP probe URL", InputType.TYPE_CLASS_TEXT)
        udpHostInput = input("UDP oracle host", InputType.TYPE_CLASS_TEXT)
        udpPortInput = input("UDP oracle port", InputType.TYPE_CLASS_NUMBER)
        intervalInput = input("Probe interval in seconds", InputType.TYPE_CLASS_NUMBER)
        content.addView(httpUrlInput, matchWrap(top = 18))
        content.addView(udpHostInput, matchWrap(top = 8))
        content.addView(udpPortInput, matchWrap(top = 8))
        content.addView(intervalInput, matchWrap(top = 8))

        startButton = button("Start HTTP + UDP probes") { startProbes() }
        content.addView(startButton)
        stopButton = button("Stop probes") { sendServiceAction(ProbeService.ACTION_STOP) }
        content.addView(stopButton)
        content.addView(button("Run bounded memory stress") { startStress() })
        content.addView(button("Reset probe counters") {
            sendServiceAction(ProbeService.ACTION_RESET, foreground = false)
        })
        return ScrollView(this).apply { addView(content) }
    }

    private fun loadConfiguration() {
        if (httpUrlInput.hasFocus() || udpHostInput.hasFocus() ||
            udpPortInput.hasFocus() || intervalInput.hasFocus()
        ) {
            return
        }
        val configuration = ProbeConfiguration.read(this)
        httpUrlInput.setText(configuration.httpUrl)
        udpHostInput.setText(configuration.udpHost)
        udpPortInput.setText(getString(R.string.integer_value, configuration.udpPort))
        intervalInput.setText(getString(R.string.integer_value, configuration.intervalSeconds))
    }

    private fun startProbes(overrides: Intent? = null) {
        val configuration = try {
            if (overrides == null) {
                ProbeConfiguration(
                    httpUrl = httpUrlInput.text.toString(),
                    udpHost = udpHostInput.text.toString(),
                    udpPort = udpPortInput.text.toString().toInt(),
                    intervalSeconds = intervalInput.text.toString().toLong(),
                )
            } else {
                ProbeConfiguration.fromIntent(this, overrides)
            }
        } catch (error: Throwable) {
            showToast("Invalid probe configuration: ${error.javaClass.simpleName}")
            return
        }
        configuration.store(this)
        val serviceIntent = Intent(this, ProbeService::class.java)
            .setAction(ProbeService.ACTION_START)
            .putExtra(ProbeConfiguration.EXTRA_HTTP_URL, configuration.httpUrl)
            .putExtra(ProbeConfiguration.EXTRA_UDP_HOST, configuration.udpHost)
            .putExtra(ProbeConfiguration.EXTRA_UDP_PORT, configuration.udpPort)
            .putExtra(
                ProbeConfiguration.EXTRA_INTERVAL_SECONDS,
                configuration.intervalSeconds,
            )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent)
        } else {
            startService(serviceIntent)
        }
    }

    private fun sendServiceAction(action: String, foreground: Boolean = true) {
        val serviceIntent = Intent(this, ProbeService::class.java).setAction(action)
        if (foreground && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent)
        } else {
            startService(serviceIntent)
        }
    }

    private fun handleAutomationCommand(intent: Intent?) {
        when (intent?.getStringExtra(EXTRA_COMMAND)) {
            COMMAND_START -> startProbes(intent)
            COMMAND_STOP -> sendServiceAction(ProbeService.ACTION_STOP, foreground = false)
            COMMAND_RESET -> sendServiceAction(ProbeService.ACTION_RESET, foreground = false)
            COMMAND_STRESS -> startStress(intent)
        }
        intent?.removeExtra(EXTRA_COMMAND)
    }

    private fun startStress(overrides: Intent? = null) {
        val source = overrides ?: Intent()
        val stress = try {
            StressConfiguration.fromIntent(source)
        } catch (error: Throwable) {
            showToast("Invalid stress configuration: ${error.javaClass.simpleName}")
            return
        }
        val serviceIntent = Intent(this, ProbeService::class.java)
            .setAction(ProbeService.ACTION_STRESS)
            .putExtra(StressConfiguration.EXTRA_CYCLE, stress.cycle)
            .putExtra(StressConfiguration.EXTRA_HTTP_ATTEMPTS, stress.httpAttempts)
            .putExtra(StressConfiguration.EXTRA_UDP_ATTEMPTS, stress.udpAttempts)
            .putExtra(StressConfiguration.EXTRA_CONCURRENCY, stress.concurrency)
        startService(serviceIntent)
    }

    private fun renderStatus() {
        val status = ProbeStatus.read(this)
        statusText.text = getString(
            R.string.device_probe_status,
            if (status.running) "running" else "stopped",
            status.httpPassed,
            status.httpFailed,
            status.udpPassed,
            status.udpFailed,
        )
        startButton.isEnabled = !status.running
        stopButton.isEnabled = status.running
    }

    private fun input(hint: String, type: Int): EditText = EditText(this).apply {
        this.hint = hint
        inputType = type or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
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

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun showToast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    companion object {
        const val EXTRA_COMMAND = "command"
        const val COMMAND_START = "start"
        const val COMMAND_STOP = "stop"
        const val COMMAND_RESET = "reset"
        const val COMMAND_STRESS = "stress"
        private const val STATUS_REFRESH_MILLISECONDS = 1_000L
    }
}
