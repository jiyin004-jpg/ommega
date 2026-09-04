package org.ommega.deviceb

import android.util.Log
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import kotlin.math.min
import org.json.JSONObject

object ServerClient {
    private const val TAG = "DeviceB.ServerClient"
    private const val POST_RESULT_MAX_RETRY = 3
    private const val POST_RESULT_MAX_BACKOFF_MS = 5_000L

    /** Default relay endpoint; can be overridden from UI. Official service default. */
    var serverUrl: String = "http://110.40.170.96:10886"
    var deviceId: String = "device-b-1"
    var relayToken: String = "Mytju8b0_lhLlqTKcEUhuwSbAsAtjom0"

    /** Debug only: skip TLS validation when true. */
    var tlsInsecure: Boolean = false

    /** Injected by MainActivity for poll conflict checks. */
    var machineId: () -> String = { "" }

    private val trustAllManager =
        object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}

            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}

            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }

    private val insecureSsl: SSLContext by lazy {
        SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustAllManager), SecureRandom()) }
    }

    private val trustAllHosts = HostnameVerifier { _, _ -> true }

    private fun applyTls(conn: HttpURLConnection) {
        if (!tlsInsecure || conn !is HttpsURLConnection) return
        conn.sslSocketFactory = insecureSsl.socketFactory
        conn.hostnameVerifier = trustAllHosts
    }

    /** Public accessor for applyTls, used by MainActivity for ad-hoc requests. */
    fun applyTlsPublic(conn: HttpURLConnection) = applyTls(conn)

    /** Opens a connection that bypasses the system proxy (VPN/Clash) so the
     * relay long-poll is not dropped by an intermediate proxy. */
    private fun openDirect(url: URL): HttpURLConnection =
        url.openConnection(Proxy.NO_PROXY) as HttpURLConnection

    /** Checks relay connectivity. relay_rs `/api/ping/` returns plain `"pong"`. */
    fun ping(): Boolean {
        return try {
            val conn = openDirect(URL("$serverUrl/api/ping/")).apply {
                    requestMethod = "GET"
                    connectTimeout = 5_000
                    readTimeout = 5_000
                    if (relayToken.isNotBlank()) {
                        setRequestProperty("X-Relay-Token", relayToken)
                    }
                }
            applyTls(conn)
            if (conn.responseCode != 200) return false
            val body = conn.inputStream.bufferedReader().readText()
            body.trim() == "pong"
        } catch (e: Exception) {
            Log.e(TAG, "ping failed: ${e.message}")
            false
        }
    }

    /** Long-polls one task; throws ConflictException on 409. */
    fun pollTask(timeoutSec: Int = 10): JSONObject? {
        return try {
            val url = URL("$serverUrl/api/b/poll/?timeout=$timeoutSec&device_id=$deviceId&machine_id=${machineId()}")
            val conn = openDirect(url).apply {
                    requestMethod = "GET"
                    connectTimeout = (timeoutSec + 5) * 1000
                    readTimeout = (timeoutSec + 5) * 1000
                    if (relayToken.isNotBlank()) {
                        setRequestProperty("X-Relay-Token", relayToken)
                    }
                }
            applyTls(conn)
            val code = conn.responseCode
            if (code == 204) return null
            if (code == 409) {
                val body = conn.errorStream?.bufferedReader()?.readText() ?: ""
                throw ConflictException(body)
            }
            if (code == 200) {
                val body = conn.inputStream.bufferedReader().readText()
                JSONObject(body)
            } else {
                val err = conn.errorStream?.bufferedReader()?.readText()?.take(300) ?: ""
                throw IllegalStateException("pollTask http=$code body=$err")
            }
        } catch (e: ConflictException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "pollTask error", e)
            throw e
        }
    }

    class ConflictException(message: String) : Exception(message)

    /** Uploads task result. */
    fun postResult(taskId: String, result: JSONObject): Boolean {
        val body =
            JSONObject().apply {
                put("task_id", taskId)
                put("device_id", deviceId)
                put("result", result)
            }
        var waitMs = 300L
        repeat(POST_RESULT_MAX_RETRY) { attempt ->
            try {
                val url = URL("$serverUrl/api/b/result/")
                val conn = openDirect(url).apply {
                        requestMethod = "POST"
                        setRequestProperty("Content-Type", "application/json")
                        if (relayToken.isNotBlank()) {
                            setRequestProperty("X-Relay-Token", relayToken)
                        }
                        doOutput = true
                        connectTimeout = 10_000
                        readTimeout = 10_000
                    }
                applyTls(conn)
                OutputStreamWriter(conn.outputStream).use { it.write(body.toString()) }
                when (conn.responseCode) {
                    200 -> return true
                    404 -> {
                        Log.w(TAG, "postResult task expired taskId=$taskId")
                        return false
                    }
                    else -> Log.w(TAG, "postResult http=${conn.responseCode} attempt=${attempt + 1}")
                }
            } catch (e: Exception) {
                Log.e(TAG, "postResult error attempt=${attempt + 1}", e)
            }
            if (attempt < POST_RESULT_MAX_RETRY - 1) {
                Thread.sleep(waitMs)
                waitMs = min(waitMs * 2, POST_RESULT_MAX_BACKOFF_MS)
            }
        }
        return false
    }
}
