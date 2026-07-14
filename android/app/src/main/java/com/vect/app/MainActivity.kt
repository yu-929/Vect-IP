package com.vect.app

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import java.io.BufferedReader
import java.io.File
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {
    private lateinit var webView: WebView
    private var serverProcess: Process? = null
    private val executor = Executors.newSingleThreadExecutor()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        createNotificationChannel()
        requestNotificationPermission()

        TracerouteService.start()

        startVectServer()
    }

    private fun startVectServer() {
        executor.execute {
            try {
                val binDir = File(cacheDir, "bin")
                binDir.mkdirs()
                val binary = File(binDir, "vect_server")

                // Extract binary from assets
                assets.open("bin/vect_server").use { input ->
                    FileOutputStream(binary).use { output ->
                        input.copyTo(output)
                    }
                }
                binary.setExecutable(true)

                android.util.Log.i("Vect", "binary size: ${binary.length()}, executable: ${binary.canExecute()}, path: ${binary.absolutePath}")

// Start server as subprocess
val pb = ProcessBuilder(binary.absolutePath)
    .directory(binDir)
    .redirectErrorStream(true)
serverProcess = pb.start()
                android.util.Log.i("Vect", "server process started")

                // Read startup output in background
                val reader = BufferedReader(InputStreamReader(serverProcess!!.inputStream))
                val output = StringBuffer()
                thread(isDaemon = true) {
                    try {
                        while (true) {
                            val line = reader.readLine() ?: break
                            output.append(line).append('\n')
                            android.util.Log.i("Vect", "server: $line")
                        }
                    } catch (_: Exception) {}
                }

                // Wait briefly, then check if process is still alive
                Thread.sleep(2000)
                if (!serverProcess!!.isAlive) {
                    val exitCode = serverProcess!!.exitValue()
                    android.util.Log.e("Vect", "server exited immediately with code: $exitCode, output: ${output}")
                    runOnUiThread { showError("Server crashed on startup (exit code: $exitCode)\n\nOutput:\n$output") }
                    return@execute
                }

                // Read whatever output we have so far
                val initialOutput = output.toString()
                android.util.Log.i("Vect", "server initial output: $initialOutput")

                // Wait for server to be ready
                val startTime = System.currentTimeMillis()
                val timeout = 20000L
                var ready = false
                var lastError = ""

                while (System.currentTimeMillis() - startTime < timeout && !ready) {
                    try {
                        val url = java.net.URL("http://127.0.0.1:8080/api/health")
                        val conn = url.openConnection() as java.net.HttpURLConnection
                        conn.connectTimeout = 1000
                        conn.readTimeout = 1000
                        conn.requestMethod = "GET"
                        val code = conn.responseCode
                        conn.disconnect()
                        if (code == 200) {
                            ready = true
                        }
                    } catch (e: Exception) {
                        lastError = e.message ?: "unknown error"
                        Thread.sleep(200)
                    }
                }

                if (ready) {
                    runOnUiThread { loadWebView() }
                } else {
                    val log = try { reader.readLine() ?: "" } catch (_: Exception) { "" }
                    val msg = "Server did not start in 20s\n\nLast error: $lastError\n\nInitial output: $initialOutput\n\nLatest: $log"
                    android.util.Log.e("Vect", msg)
                    runOnUiThread { showError(msg) }
                }
            } catch (e: Exception) {
                android.util.Log.e("Vect", "Failed to start server", e)
                runOnUiThread { showError("Failed: ${e.message}") }
            }
        }
    }

    private fun loadWebView() {
        webView = findViewById(R.id.webView)
        setupWebView()
    }

    private fun setupWebView() {
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowContentAccess = false
            allowFileAccess = false
            mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
            userAgentString = userAgentString.replace("; wv)", ")")
        }

        webView.addJavascriptInterface(object {
            @JavascriptInterface
            fun onScanComplete(data: String) {
                runOnUiThread {
                    showNotification(data)
                }
            }
        }, "Android")

        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                return false
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                super.onPageFinished(view, url)
                injectBridge()
            }
        }

        webView.loadUrl("http://127.0.0.1:8080")
    }

    private fun injectBridge() {
        webView.evaluateJavascript("""
            (function() {
                if (!window.vectNotify) {
                    window.vectNotify = function(data) {
                        try {
                            Android.onScanComplete(JSON.stringify(data || {}));
                        } catch(e) {}
                    };
                }
            })();
        """.trimIndent(), null)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "scan_complete", "扫描完成",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Vect 扫描完成通知"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 100
                )
            }
        }
    }

    private fun showNotification(data: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) return

        val notification = NotificationCompat.Builder(this, "scan_complete")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("Vect 扫描完成")
            .setContentText(data)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()

        NotificationManagerCompat.from(this).notify(1001, notification)
    }

    private fun showError(msg: String) {
        findViewById<android.widget.TextView>(R.id.errorText).apply {
            text = msg
            visibility = android.view.View.VISIBLE
        }
        findViewById<android.webkit.WebView>(R.id.webView).visibility = android.view.View.GONE
    }

    override fun onDestroy() {
        serverProcess?.destroy()
        TracerouteService.stop()
        executor.shutdownNow()
        super.onDestroy()
    }
}