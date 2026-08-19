package com.covertcomm.app.transport

import android.content.Context
import android.net.wifi.WifiManager
import android.util.Log
import com.covertcomm.app.crypto.IdentityManager
import com.covertcomm.app.security.SecurityGuard
import java.io.*
import java.net.*

class HotspotTransport(
    private val context: Context,
    private val identityManager: IdentityManager
) {
    private val TAG = "HotspotTransport"

    private var serverSocket: ServerSocket? = null
    private var clientSocket: Socket? = null
    private var isRunning = false
    private var isHost = false
    private var hotspotReservation: WifiManager.LocalOnlyHotspotReservation? = null

    var listener: HotspotListener? = null

    interface HotspotListener {
        fun onPeerConnected(address: String)
        fun onPeerDisconnected()
        fun onMessageReceived(data: ByteArray)
        fun onTransportError(error: String)
        fun onHandshakeSent()
        fun onHotspotStarted(ssid: String, password: String, ip: String)
        fun onHotspotFailed(ssid: String, password: String)
    }

    private var currentSSID: String = "CovertComm"
    private var currentPassword: String = "covert123"

    fun startAsHost(port: Int = 8888) {
        isHost = true
        isRunning = true
        currentSSID = SecurityGuard.secureRandomSSID()
        currentPassword = SecurityGuard.secureRandomPassword()

        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager

        try {
            wifiManager.startLocalOnlyHotspot(object : WifiManager.LocalOnlyHotspotCallback() {
                override fun onStarted(reservation: WifiManager.LocalOnlyHotspotReservation) {
                    hotspotReservation = reservation
                    val ip = getServerIpAddress()
                    Log.d(TAG, "LocalOnlyHotspot started, ip=$ip")
                    listener?.onHotspotStarted(currentSSID, currentPassword, ip)
                    startServer(port)
                }

                override fun onStopped() {
                    Log.d(TAG, "LocalOnlyHotspot stopped")
                    listener?.onPeerDisconnected()
                }

                override fun onFailed(reason: Int) {
                    Log.e(TAG, "LocalOnlyHotspot failed: $reason")
                    val reasonText = when (reason) {
                        1 -> "TETHERING_UNSUPPORTED"
                        2 -> "NO_CHANNEL"
                        3 -> "UNSUPPORTED_AUTHORIZATION"
                        else -> "reason=$reason"
                    }
                    listener?.onTransportError("Hotspot failed: $reasonText. Please enable Wi-Fi hotspot manually in Settings, then use Connect with the hotspot IP.")
                    listener?.onHotspotFailed(currentSSID, currentPassword)
                    startServer(port)
                }
            }, null)
        } catch (e: SecurityException) {
            Log.e(TAG, "startLocalOnlyHotspot SecurityException", e)
            listener?.onTransportError("Hotspot permission denied. Please grant Nearby Wi-Fi Devices permission.")
            listener?.onHotspotFailed(currentSSID, currentPassword)
            startServer(port)
        } catch (e: Exception) {
            Log.e(TAG, "startLocalOnlyHotspot failed", e)
            listener?.onTransportError("Hotspot error: ${e.message}. Try enabling hotspot manually in Settings.")
            listener?.onHotspotFailed(currentSSID, currentPassword)
            startServer(port)
        }
    }

    fun startAsClient(hostAddress: String, port: Int = 8888) {
        isHost = false
        isRunning = true
        connectToHost(hostAddress, port)
    }

    private fun startServer(port: Int) {
        Thread {
            try {
                serverSocket = ServerSocket(port)
                serverSocket?.soTimeout = 0
                while (isRunning) {
                    try {
                        val client = serverSocket?.accept() ?: break
                        clientSocket = client
                        listener?.onPeerConnected(client.inetAddress.hostAddress ?: "unknown")
                        handleClient(client)
                        sendHandshake()
                    } catch (e: SocketTimeoutException) {
                        continue
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Server error", e)
                listener?.onTransportError(e.message ?: "Server error")
            }
        }.start()
    }

    private fun connectToHost(hostAddress: String, port: Int) {
        Thread {
            try {
                clientSocket = Socket()
                clientSocket?.connect(InetSocketAddress(hostAddress, port), 15000)
                clientSocket?.soTimeout = 0
                clientSocket?.let {
                    sendHandshake()
                    listener?.onPeerConnected(hostAddress)
                    handleClient(it)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Client connect error", e)
                listener?.onTransportError(e.message ?: "Connection failed")
            }
        }.start()
    }

    private fun handleClient(socket: Socket) {
        Thread {
            try {
                val input = DataInputStream(BufferedInputStream(socket.getInputStream()))
                while (isRunning && !socket.isClosed) {
                    val length = input.readInt()
                    if (length <= 0 || length > MAX_MESSAGE_SIZE) break
                    val data = ByteArray(length)
                    input.readFully(data)
                    listener?.onMessageReceived(data)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Receive error", e)
                listener?.onPeerDisconnected()
            }
        }.start()
    }

    fun sendData(data: ByteArray) {
        Thread {
            try {
                val socket = clientSocket
                socket?.let {
                    val output = DataOutputStream(BufferedOutputStream(it.getOutputStream()))
                    output.writeInt(data.size)
                    output.write(data)
                    output.flush()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Send error", e)
                listener?.onTransportError(e.message ?: "Send failed")
            }
        }.start()
    }

    private fun sendHandshake() {
        val keys = identityManager.exportEncodedPublicKeys()
        val sb = StringBuilder("{\"type\":\"handshake\",\"keys\":{")
        var first = true
        for ((k, v) in keys) {
            if (!first) sb.append(",")
            sb.append("\"").append(k).append("\":\"").append(v).append("\"")
            first = false
        }
        sb.append("}}")
        val data = sb.toString().toByteArray()
        sendData(data)
        listener?.onHandshakeSent()
        SecurityGuard.wipeStringBuilder(sb)
    }

    private fun getServerIpAddress(): String {
        return if (isHost) {
            "192.168.49.1"
        } else {
            "0.0.0.0"
        }
    }

    fun close() {
        isRunning = false
        try { serverSocket?.close() } catch (_: Exception) {}
        try { clientSocket?.close() } catch (_: Exception) {}
        try { hotspotReservation?.close() } catch (_: Exception) {}
        serverSocket = null
        clientSocket = null
        hotspotReservation = null
    }

    companion object {
        private const val MAX_MESSAGE_SIZE = 1024 * 1024
    }
}