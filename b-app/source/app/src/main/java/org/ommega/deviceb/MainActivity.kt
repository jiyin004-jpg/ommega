package org.ommega.deviceb

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import java.security.SecureRandom
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicReference

class MainActivity : AppCompatActivity() {

    private lateinit var urlInput: EditText
    private lateinit var deviceIdInput: EditText
    private lateinit var tokenInput: EditText
    private lateinit var statusText: TextView
    private lateinit var connectionStatusText: TextView
    private lateinit var testOutput: TextView
    private lateinit var tlsInsecureCb: CheckBox

    private val prefs by lazy { getSharedPreferences(RelayService.PREFS_NAME, MODE_PRIVATE) }
    private val PREF_URL = "server_url"
    private val PREF_DEVICE_ID = "device_id"
    private val PREF_TOKEN = "relay_token"
    private val PREF_TLS_INSECURE = "tls_insecure"

    private val ioExecutor = Executors.newCachedThreadPool()
    private val runningTasks = ConcurrentLinkedQueue<Future<*>>()

    private fun runBackground(task: () -> Unit) {
        val holder = AtomicReference<Future<*>?>()
        val future = ioExecutor.submit {
            try {
                task()
            } finally {
                holder.get()?.let { runningTasks.remove(it) }
            }
        }
        holder.set(future)
        runningTasks.add(future)
    }

    private fun postToUi(action: () -> Unit) {
        if (isFinishing || isDestroyed) return
        runOnUiThread { if (!isFinishing && !isDestroyed) action() }
    }

    private val notifPermLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) doStartService() else statusText.text = "⚠️ 需要通知权限"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val savedUrl = prefs.getString(PREF_URL, "http://110.40.170.96:10886")!!
        val savedToken = prefs.getString(PREF_TOKEN, "Mytju8b0_lhLlqTKcEUhuwSbAsAtjom0")!!
        // First launch (or cleared prefs): mint a fresh random device id so each
        // install registers uniquely on the relay_server.
        var savedDeviceId = prefs.getString(PREF_DEVICE_ID, null)
        if (savedDeviceId.isNullOrEmpty()) {
            savedDeviceId = randomDeviceId()
            prefs.edit().putString(PREF_DEVICE_ID, savedDeviceId).apply()
        }
        val savedTlsInsecure = prefs.getBoolean(PREF_TLS_INSECURE, true)

        ServerClient.serverUrl = savedUrl
        ServerClient.deviceId = savedDeviceId
        ServerClient.relayToken = savedToken
        ServerClient.tlsInsecure = savedTlsInsecure
        ServerClient.machineId = { getMachineId() }

        val root = ScrollView(this)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 64, 48, 48)
        }
        root.addView(layout)

        layout.addView(TextView(this).apply { text = "服务器地址" })
        urlInput = EditText(this).apply {
            hint = "http://IP:10886 或 https://域名:8443"
            setText(savedUrl)
            setSingleLine()
        }
        layout.addView(urlInput)

        tlsInsecureCb = CheckBox(this).apply {
            text = "HTTPS：信任所有证书（仅自签/内网调试）"
            isChecked = savedTlsInsecure
        }
        layout.addView(tlsInsecureCb)

        layout.addView(TextView(this).apply { text = "设备ID（用于任务绑定）" })
        deviceIdInput = EditText(this).apply {
            hint = "device-b-1"
            setText(savedDeviceId)
            setSingleLine()
        }
        layout.addView(deviceIdInput)

        layout.addView(TextView(this).apply { text = "Relay Token（与 relay 的 B 端 token 一致）" })
        tokenInput = EditText(this).apply {
            hint = "与 server 的 B 端 token 一致"
            setText(savedToken)
            setSingleLine()
        }
        layout.addView(tokenInput)

        statusText = TextView(this).apply {
            setPadding(0, 16, 0, 8)
            text = "就绪"
        }
        layout.addView(statusText)

        connectionStatusText = TextView(this).apply {
            setPadding(0, 0, 0, 16)
            text = "● 未连接"
            setTextColor(0xFF888888.toInt())
        }
        layout.addView(connectionStatusText)

        RelayService.uiListener = object : RelayService.ConnectionListener {
            override fun onStateChanged(state: RelayService.ConnectionState) {
                postToUi {
                    when (state) {
                        RelayService.ConnectionState.CONNECTED -> {
                            connectionStatusText.text = "● 通讯中"
                            connectionStatusText.setTextColor(0xFF4CAF50.toInt())
                        }
                        RelayService.ConnectionState.DISCONNECTED -> {
                            connectionStatusText.text = "● 通讯中断"
                            connectionStatusText.setTextColor(0xFFF44336.toInt())
                        }
                        RelayService.ConnectionState.CONFLICT -> {
                            connectionStatusText.text = "⛔ device_id 冲突"
                            connectionStatusText.setTextColor(0xFFFF9800.toInt())
                        }
                        RelayService.ConnectionState.IDLE -> {
                            connectionStatusText.text = "● 未连接"
                            connectionStatusText.setTextColor(0xFF888888.toInt())
                        }
                    }
                }
            }
        }

        val btnRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        btnRow.addView(Button(this).apply {
            text = "启动服务"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { onStartClicked() }
        })
        btnRow.addView(Button(this).apply {
            text = "停止服务"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener {
                stopService(Intent(this@MainActivity, RelayService::class.java))
                statusText.text = "⏹ 服务已停止"
            }
        })
        btnRow.addView(Button(this).apply {
            text = "检测连接"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { checkConnection() }
        })
        layout.addView(btnRow)

        layout.addView(View(this).apply {
            setBackgroundColor(0x33FFFFFF)
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 1).apply { setMargins(0, 32, 0, 32) }
        })

        layout.addView(TextView(this).apply { text = "本地 TEE 测试"; textSize = 16f })
        layout.addView(Button(this).apply {
            text = "随机 Challenge 签名测试"
            setOnClickListener { testAttest() }
        })
        layout.addView(Button(this).apply {
            text = "获取本地证书链"
            setOnClickListener { testGetCertChain() }
        })

        testOutput = TextView(this).apply {
            setPadding(0, 16, 0, 0)
            setTextIsSelectable(true)
            textSize = 11f
        }
        layout.addView(testOutput)

        setContentView(root)
    }

    /** Machine id reported to the relay_server: the current device model. */
    private fun getMachineId(): String = Build.MODEL

    /** Fresh random device id (device-b-<8 hex>) for the first launch of an install. */
    private fun randomDeviceId(): String {
        val hex = "0123456789abcdef"
        val rand = SecureRandom()
        val sb = StringBuilder("device-b-")
        repeat(8) { sb.append(hex[rand.nextInt(hex.length)]) }
        return sb.toString()
    }

    override fun onDestroy() {
        RelayService.uiListener = null
        runningTasks.forEach { it.cancel(true) }
        runningTasks.clear()
        ioExecutor.shutdownNow()
        super.onDestroy()
    }

    private fun saveAndApplyUrl(): Boolean {
        val url = urlInput.text.toString().trim().trimEnd('/')
        val deviceId = deviceIdInput.text.toString().trim()
        val token = tokenInput.text.toString().trim()
        if (url.isEmpty()) { statusText.text = "⚠️ 请输入地址"; return false }
        if (deviceId.isEmpty()) { statusText.text = "⚠️ 请输入设备ID"; return false }
        prefs.edit()
            .putString(PREF_URL, url)
            .putString(PREF_DEVICE_ID, deviceId)
            .putString(PREF_TOKEN, token)
            .putBoolean(PREF_TLS_INSECURE, tlsInsecureCb.isChecked)
            .apply()
        ServerClient.serverUrl = url
        ServerClient.deviceId = deviceId
        ServerClient.relayToken = token
        ServerClient.tlsInsecure = tlsInsecureCb.isChecked
        return true
    }

    private fun onStartClicked() {
        if (!saveAndApplyUrl()) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            return
        }
        doStartService()
    }

    private fun doStartService() {
        val intent = Intent(this, RelayService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent) else startService(intent)
        statusText.text = "⏳ 服务已启动"
    }

    private fun checkConnection() {
        val url = urlInput.text.toString().trim().trimEnd('/')
        val deviceId = deviceIdInput.text.toString().trim()
        val token = tokenInput.text.toString().trim()
        if (url.isEmpty()) { statusText.text = "⚠️ 请输入地址"; return }
        if (deviceId.isEmpty()) { statusText.text = "⚠️ 请输入设备ID"; return }
        ServerClient.serverUrl = url
        ServerClient.deviceId = deviceId
        ServerClient.relayToken = token
        ServerClient.tlsInsecure = tlsInsecureCb.isChecked
        statusText.text = "⏳ 检测中..."
        runBackground {
            val ok = ServerClient.ping()
            postToUi {
                statusText.text = if (ok) "✅ connection success → $url" else "❌ 无法连接 → $url"
            }
        }
    }

    private fun testGetCertChain() {
        testOutput.text = "获取中..."
        runBackground {
            val result = try {
                val json = KeystoreHelper.getCertChain(this)
                val chain = json.getJSONArray("cert_chain")
                buildString {
                    appendLine("✅ 证书链获取成功，共 ${chain.length()} 张证书")
                    for (i in 0 until chain.length()) {
                        appendLine("\n[$i] ${chain.getString(i).take(60)}...")
                    }
                }
            } catch (e: Exception) { "❌ 失败: ${e.message}" }
            postToUi { testOutput.text = result }
        }
    }

    private fun testAttest() {
        testOutput.text = "签名中..."
        runBackground {
            val result = try {
                val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
                val b64 = Base64.encodeToString(challenge, Base64.NO_WRAP)
                val json = KeystoreHelper.attest(this, b64)
                val chain = json.getJSONArray("cert_chain")
                buildString {
                    appendLine("✅ Attestation 成功")
                    appendLine("Challenge: ${b64.take(32)}...")
                    appendLine("证书链共 ${chain.length()} 张")
                    for (i in 0 until chain.length()) {
                        appendLine("\n[$i] ${chain.getString(i).take(60)}...")
                    }
                }
            } catch (e: Exception) { "❌ 失败: ${e.message}" }
            postToUi { testOutput.text = result }
        }
    }
}
