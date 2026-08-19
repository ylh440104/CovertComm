package com.covertcomm.app.transport

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pDeviceList
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.covertcomm.app.crypto.IdentityManager
import com.covertcomm.app.security.SecurityGuard
import java.io.*
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

class WifiDirectTransport(
    private val context: Context,
    private val identityManager: IdentityManager
) {
    private val TAG = "WifiDirectTransport"
    private val handler = Handler(Looper.getMainLooper())

    private var p2pManager: WifiP2pManager? = null
    private var channel: WifiP2pManager.Channel? = null
    private var serverSocket: ServerSocket? = null
    private var clientSocket: Socket? = null
    private var isRunning = false
    private var isHost = false
    private var peerDeviceName = ""

    var listener: WifiDirectListener? = null

    interface WifiDirectListener {
        fun onPeerConnected(address: String)
        fun onPeerDisconnected()
        fun onMessageReceived(data: ByteArray)
        fun onTransportError(error: String)
        fun onHandshakeSent()
        fun onDiscoveryStarted()
        fun onDiscoveryFailed(reason: String)
        fun onPeerFound(deviceName: String)
    }

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, intent: Intent) {
            when (intent.action) {
                WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION -> {}
                WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> {
                    p2pManager?.requestPeers(channel) { peers -> handlePeers(peers) }
                }
                WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> {
                    p2pManager?.requestConnectionInfo(channel) { info -> handleConnectionInfo(info) }
                }
                WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION -> {}
            }
        }
    }

    private fun handlePeers(peers: WifiP2pDeviceList) {
        for (device in peers.deviceList) {
            listener?.onPeerFound(device.deviceName)
            if (!isHost) {
                connectToPeer(device)
                break
            }
        }
    }

    private fun handleConnectionInfo(info: WifiP2pInfo) {
        if (info.groupFormed && info.isGroupOwner) {
            isHost = true
            startServer(8888)
            listener?.onPeerConnected("p2p:group-owner")
        } else if (info.groupFormed) {
            isHost = false
            if (info.groupOwnerAddress != null) {
                connectToHost(info.groupOwnerAddress.hostAddress ?: "")
            }
        } else {
            listener?.onPeerDisconnected()
        }
    }

    fun init(): Boolean {
        p2pManager = context.getSystemService(Context.WIFI_P2P_SERVICE) as? WifiP2pManager
        if (p2pManager == null) {
            listener?.onTransportError("Wi-Fi Direct not supported")
            return false
        }
        channel = p2pManager?.initialize(context, Looper.getMainLooper(), null)
        if (channel == null) {
            listener?.onTransportError("Wi-Fi Direct channel init failed")
            return false
        }
        registerReceiver()
        isRunning = true
        return true
    }

    fun startDiscovery() {
        p2pManager?.discoverPeers(channel, object : WifiP2pManager.ActionListener {
            override fun onSuccess() { listener?.onDiscoveryStarted() }
            override fun onFailure(reason: Int) { listener?.onDiscoveryFailed("code $reason") }
        })
    }

    fun startGroupOwner() {
        p2pManager?.createGroup(channel, object : WifiP2pManager.ActionListener {
            override fun onSuccess() { listener?.onDiscoveryStarted() }
            override fun onFailure(reason: Int) { listener?.onDiscoveryFailed("group create $reason") }
        })
    }

    private fun connectToPeer(device: WifiP2pDevice) {
        val config = WifiP2pConfig().apply { deviceAddress = device.deviceAddress }
        p2pManager?.connect(channel, config, object : WifiP2pManager.ActionListener {
            override fun onSuccess() { Log.d(TAG, "Connect initiated to ${device.deviceName}") }
            override fun onFailure(reason: Int) { listener?.onTransportError("P2P connect failed: $reason") }
        })
    }

    private fun startServer(port: Int) {
        Thread {
            try {
                serverSocket = ServerSocket(port)
                serverSocket?.soTimeout = 0
                while (isRunning) {
                    val client = serverSocket?.accept() ?: break
                    clientSocket = client
                    listener?.onPeerConnected(client.inetAddress.hostAddress ?: "p2p-peer")
                    handleClient(client)
                    sendHandshake()
                }
            } catch (e: Exception) {
                Log.e(TAG, "P2P server error", e)
                listener?.onTransportError(e.message ?: "P2P server error")
            }
        }.start()
    }

    private fun connectToHost(hostAddress: String, port: Int = 8888) {
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
                Log.e(TAG, "P2P client error", e)
                listener?.onTransportError(e.message ?: "P2P connect failed")
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
                Log.e(TAG, "P2P receive error", e)
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
                Log.e(TAG, "P2P send error", e)
                listener?.onTransportError(e.message ?: "P2P send failed")
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

    private fun registerReceiver() {
        val filter = IntentFilter().apply {
            addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION)
        }
        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }
    }

    fun close() {
        isRunning = false
        try { context.unregisterReceiver(receiver) } catch (_: Exception) {}
        try { serverSocket?.close() } catch (_: Exception) {}
        try { clientSocket?.close() } catch (_: Exception) {}
        p2pManager?.removeGroup(channel, null)
        serverSocket = null
        clientSocket = null
    }

    companion object {
        private const val MAX_MESSAGE_SIZE = 1024 * 1024
    }
}