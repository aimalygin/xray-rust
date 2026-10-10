package org.xrayrust.deviceprobe

import android.app.Activity
import android.content.Intent
import java.util.concurrent.atomic.AtomicBoolean
import android.os.Bundle
import android.widget.TextView
import org.json.JSONObject
import java.io.File

/** Device-test entry point. Run from an included or excluded, unprivileged UID. */
class AdmissionProbeActivity : Activity() {
    private lateinit var label: TextView
    private val running = AtomicBoolean(false)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        label = TextView(this).apply { text = "Checking TUN flow admission…" }
        setContentView(label)
        runProbe(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        runProbe(intent)
    }

    private fun runProbe(intent: Intent) {
        if (!running.compareAndSet(false, true)) return
        val address = intent.getStringExtra("address") ?: ""
        val port = intent.getIntExtra("port", 0)
        val udp = intent.getBooleanExtra("udp", false)
        val device = intent.getStringExtra("bind-device")
        val nonce = intent.getStringExtra("nonce") ?: ""
        Thread({
            val result = runCatching { nativeProbe(address, port, udp, device) }
            val json = JSONObject().put("nonce", nonce).put("uid", android.os.Process.myUid())
                .put("protocol", if (udp) "udp" else "tcp").put("bound", device != null)
            result.onSuccess { values ->
                json.put("bindErrno", values[0]).put("ioErrno", values[1]).put("echoBytes", values[2])
            }.onFailure { json.put("error", it.javaClass.simpleName) }
            File(filesDir, "admission-result.json").writeText(json.toString())
            running.set(false)
            runOnUiThread { label.text = json.toString(2) }
        }, "tun-admission-device-probe").start()
    }

    private external fun nativeProbe(address: String, port: Int, udp: Boolean, device: String?): IntArray

    companion object { init { System.loadLibrary("xray_tun_admission_probe") } }
}
