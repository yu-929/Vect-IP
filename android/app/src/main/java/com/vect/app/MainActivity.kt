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
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

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
                val binDir = File(filesDir, "bin")
                binDir.mkdirs()
                val binary = File(binDir, "vect_server")

                // Extract binary from assets
                assets.open("bin/vect_server").use { input ->
                    FileOutputStream(binary).use { output ->
                        input.copyTo(output)
                    }
                }
                binary.setExecutable(true)

                // Start server as subprocess
                val pb = ProcessBuilder(binary.absolutePath)
                    .directory(binDir)
                    .redirectErrorStream(true)
                serverProcess = pb.start()

                // Wait for server to be ready
                val startTime = System.currentTimeMillis()
                val timeout = 10000L
                var ready = false

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
                    } catch (_: Exception) {
                        Thread.sleep(200)
                    }
                }

                if (ready) {
                    runOnUiThread { loadWebView() }
                } else {
                    android.util.Log.e("Vect", "Server did not start in time")
                }
            } catch (e: Exception) {
                android.util.Log.e("Vect", "Failed to start server", e)
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

    override fun onDestroy() {
        serverProcess?.destroy()
        TracerouteService.stop()
        executor.shutdownNow()
        super.onDestroy()
    }
}