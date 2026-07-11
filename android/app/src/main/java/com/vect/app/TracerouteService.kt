package com.vect.app

import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.StandardSocketOptions
import kotlin.concurrent.thread

data class TracerouteHop(
    val hop: Int,
    val ip: String?,
    val ms: String?,
    val lost: Boolean
)

object TracerouteService {
    private var running = false
    private var serverThread: Thread? = null

    fun start() {
        if (running) return
        running = true
        serverThread = thread(name = "traceroute-server", isDaemon = true) {
            try {
                val serverSocket = ServerSocket(8091, 50, InetAddress.getByName("127.0.0.1"))
                while (running) {
                    try {
                        val client = serverSocket.accept()
                        thread(name = "traceroute-client", isDaemon = true) {
                            try {
                                val reader = BufferedReader(InputStreamReader(client.getInputStream()))
                                val request = reader.readLine() ?: return@thread
                                val parts = request.split(" ")
                                if (parts.size < 2) return@thread
                                val path = parts[1]
                                if (path.startsWith("/traceroute/")) {
                                    val ip = path.removePrefix("/traceroute/").trim()
                                    val hops = runTraceroute(ip)
                                    val json = hopsToJson(hops)
                                    val response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${json.length}\r\nConnection: close\r\n\r\n$json"
                                    client.getOutputStream().write(response.toByteArray())
                                } else {
                                    val response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                    client.getOutputStream().write(response.toByteArray())
                                }
                            } catch (_: Exception) {
                            } finally {
                                try { client.close() } catch (_: Exception) {}
                            }
                        }
                    } catch (_: Exception) {
                        if (!running) break
                    }
                }
                serverSocket.close()
            } catch (_: Exception) {
            }
        }
    }

    fun stop() {
        running = false
        serverThread?.interrupt()
        serverThread = null
    }

    private fun hopsToJson(hops: List<TracerouteHop>): String {
        val arr = JSONArray()
        for (h in hops) {
            val obj = JSONObject()
            obj.put("hop", h.hop)
            obj.put("ip", h.ip ?: JSONObject.NULL)
            obj.put("ms", h.ms ?: JSONObject.NULL)
            obj.put("lost", h.lost)
            arr.put(obj)
        }
        return arr.toString()
    }

    private fun runTraceroute(target: String): List<TracerouteHop> {
        val hops = mutableListOf<TracerouteHop>()
        val destAddr = try { InetAddress.getByName(target) } catch (_: Exception) { return hops }

        for (ttl in 1..30) {
            val start = System.nanoTime()
            var hopIP: String? = null
            var ms: String? = null
            var lost = false

            try {
                val socket = Socket()
                try {
                    socket.setOption(StandardSocketOptions.IP_TTL, Integer.valueOf(ttl))
                } catch (_: IllegalArgumentException) {
                }
                socket.connect(InetSocketAddress(destAddr, 443), 3000)
                val elapsed = (System.nanoTime() - start) / 1_000_000.0
                ms = String.format("%.2f", elapsed)
                hopIP = destAddr.hostAddress
                socket.close()
                hops.add(TracerouteHop(hop = ttl, ip = hopIP, ms = ms, lost = false))
                break
            } catch (e: SocketTimeoutException) {
                lost = true
            } catch (e: Exception) {
                val elapsed = (System.nanoTime() - start) / 1_000_000.0
                ms = String.format("%.2f", elapsed)
                hops.add(TracerouteHop(hop = ttl, ip = destAddr.hostAddress, ms = ms, lost = false))
                break
            }

            hops.add(TracerouteHop(hop = ttl, ip = hopIP, ms = ms, lost = lost))
        }

        return hops
    }
}