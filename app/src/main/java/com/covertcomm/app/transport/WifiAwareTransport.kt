package com.covertcomm.app.transport

import android.content.Context
import android.net.wifi.aware.AttachCallback
import android.net.wifi.aware.DiscoverySessionCallback
import android.net.wifi.aware.PeerHandle
import android.net.wifi.aware.PublishConfig
import android.net.wifi.aware.PublishDiscoverySession
import android.net.wifi.aware.SubscribeConfig
import android.net.wifi.aware.SubscribeDiscoverySession
import android.net.wifi.aware.WifiAwareManager
import android.net.wifi.aware.WifiAwareSession
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.annotation.RequiresApi
import com.covertcomm.app.crypto.CryptoUtils
import com.covertcomm.app.crypto.IdentityManager
import com.covertcomm.app.mesh.MeshFrame
import com.covertcomm.app.mesh.MeshRouter
import com.covertcomm.app.security.SecurityGuard

@RequiresApi(Build.VERSION_CODES.O)
class WifiAwareTransport(
    private val context: Context,
    private val identityManager: IdentityManager
) {
    private val TAG = "WifiAwareTransport"

    companion object {
        const val SERVICE_PREFIX = "covertcomm.aware.v1."
        const val HANDSHAKE_TIMEOUT_MS = 15000
    }

    private var awareManager: WifiAwareManager? = null
    private var awareSession: WifiAwareSession? = null
    private var publishSession: PublishDiscoverySession? = null
    private var subscribeSession: SubscribeDiscoverySession? = null
    private var router: MeshRouter? = null
    private var passphrase: String? = null
    private var serviceName: String = ""
    private var isRunning = false
    private var isHost = false
    private var statusConnected = false

    private var peerHandle: PeerHandle? = null
    private val handler = Handler(Looper.getMainLooper())

    var listener: WifiAwareListener? = null

    interface WifiAwareListener {
        fun onPeerConnected(address: String)
        fun onPeerDisconnected()
        fun onMessageReceived(data: ByteArray, senderFP: ByteArray)
        fun onTransportError(error: String)
        fun onHandshakeSent()
        fun onDiscoveryStarted()
        fun onDiscoveryFailed(reason: String)
        fun onPeerDiscovered(peerId: String)
    }

    fun init(router: MeshRouter): Boolean {
        this.router = router

        awareManager = context.getSystemService(Context.WIFI_AWARE_SERVICE) as? WifiAwareManager

        if (awareManager == null) {
            listener?.onTransportError("Wi-Fi Aware service not available on this device")
            return false
        }

        if (!awareManager!!.isAvailable) {
            listener?.onTransportError("Wi-Fi Aware unavailable. Enable Wi-Fi (no connection needed), disable power saving, then retry.")
            return false
        }

        attachToAware()
        return true
    }

    fun setPassphrase(passphrase: String) {
        this.passphrase = passphrase
        val hash = CryptoUtils.sha256(passphrase.toByteArray())
        this.serviceName = SERVICE_PREFIX + hash.copyOfRange(0, 8).joinToString("") { "%02x".format(it) }
    }

    fun startPublish() {
        isHost = true
        isRunning = true

        if (awareSession == null) {
            handler.postDelayed({ startPublish() }, 500)
            return
        }

        val config = PublishConfig.Builder()
            .setServiceName(serviceName)
            .setServiceSpecificInfo(passphrase?.toByteArray())
            .setPublishType(PublishConfig.PUBLISH_TYPE_UNSOLICITED)
            .build()

        awareSession?.publish(config, object : DiscoverySessionCallback() {
            override fun onPublishStarted(session: PublishDiscoverySession) {
                publishSession = session
                listener?.onDiscoveryStarted()
                Log.d(TAG, "Publish started: $serviceName")
            }

            override fun onSessionConfigFailed() {
                listener?.onDiscoveryFailed("Publish config failed")
                Log.e(TAG, "Publish config failed")
            }

            override fun onMessageReceived(peer: PeerHandle, message: ByteArray) {
                Log.d(TAG, "Message from peer: ${message.size} bytes")
                peerHandle = peer
                if (!statusConnected) {
                    listener?.onPeerConnected("nan:peer")
                    statusConnected = true
                    sendHandshake()
                }
                handleIncomingMessage(message)
            }
        }, handler)
    }

    fun startSubscribe() {
        isHost = false
        isRunning = true

        if (awareSession == null) {
            handler.postDelayed({ startSubscribe() }, 500)
            return
        }

        val config = SubscribeConfig.Builder()
            .setServiceName(serviceName)
            .setSubscribeType(SubscribeConfig.SUBSCRIBE_TYPE_PASSIVE)
            .build()

        awareSession?.subscribe(config, object : DiscoverySessionCallback() {
            override fun onSubscribeStarted(session: SubscribeDiscoverySession) {
                subscribeSession = session
                listener?.onDiscoveryStarted()
                Log.d(TAG, "Subscribe started: $serviceName")
            }

            override fun onSessionConfigFailed() {
                listener?.onDiscoveryFailed("Subscribe config failed")
                Log.e(TAG, "Subscribe config failed")
            }

            override fun onMessageReceived(peer: PeerHandle, message: ByteArray) {
                Log.d(TAG, "Message from peer: ${message.size} bytes")
                peerHandle = peer
                if (!statusConnected) {
                    listener?.onPeerConnected("nan:peer")
                    statusConnected = true
                }
                handleIncomingMessage(message)
            }
        }, handler)
    }

    private val sendMutex = Any()
    private var messageId = 0
    private val MESSAGE_MAX_NAN = 255
    private val FRAG_MAGIC: Byte = 0x7A
    private val fragBuffer = java.util.concurrent.ConcurrentHashMap<Int, ByteArray>()
    private val fragTotal = java.util.concurrent.ConcurrentHashMap<Int, Int>()
    private val fragCount = java.util.concurrent.ConcurrentHashMap<Int, Int>()

    fun sendData(data: ByteArray) {
        val session = if (isHost) publishSession else subscribeSession
        val peer = peerHandle
        if (session == null || peer == null) {
            listener?.onTransportError("No NAN session or peer")
            return
        }

        if (data.size <= MESSAGE_MAX_NAN - 6) {
            val frag = ByteArray(data.size + 6)
            frag[0] = FRAG_MAGIC
            frag[1] = (messageId shr 8).toByte(); frag[2] = messageId.toByte()
            frag[3] = 0; frag[4] = 1
            frag[5] = (data.size and 0xFF).toByte()
            System.arraycopy(data, 0, frag, 6, data.size)
            messageId++
            sendNan(session, peer, frag)
        } else {
            val mid = messageId++
            val chunks = data.toList().chunked(MESSAGE_MAX_NAN - 6).map { it.toByteArray() }
            val total = chunks.size
            for ((idx, chunk) in chunks.withIndex()) {
                val frag = ByteArray(chunk.size + 6)
                frag[0] = FRAG_MAGIC
                frag[1] = (mid shr 8).toByte(); frag[2] = mid.toByte()
                frag[3] = idx.toByte(); frag[4] = total.toByte()
                frag[5] = (chunk.size and 0xFF).toByte()
                System.arraycopy(chunk, 0, frag, 6, chunk.size)
                sendNan(session, peer, frag)
            }
        }
    }

    private fun sendNan(session: android.net.wifi.aware.DiscoverySession, peer: PeerHandle, data: ByteArray) {
        synchronized(sendMutex) {
            try { session.sendMessage(peer, 0, data) }
            catch (e: Exception) { Log.e(TAG, "sendMessage failed", e); listener?.onTransportError("NAN send failed: ${e.message}") }
        }
    }

    private fun getMyFP(): ByteArray {
        val fp = identityManager.getShortFingerprint()
        return if (fp.length >= 2) byteArrayOf((fp[0].code and 0xFF).toByte(), (fp[1].code and 0xFF).toByte()) else ByteArray(2)
    }

    fun sendData(targetFP: ByteArray, data: ByteArray) {
        val seqNum = router?.nextSeqNum() ?: 0
        val frame = MeshFrame.create(
            MeshFrame.TYPE_DATA,
            getMyFP(),
            targetFP,
            data,
            seqNum
        )
        val frameBytes = frame.toBytes()
        if (frameBytes.size <= MESSAGE_MAX_NAN) {
            sendData(frameBytes)
        } else {
            val chunks = frameBytes.toList().chunked(MESSAGE_MAX_NAN).map { it.toByteArray() }
            for (chunk in chunks) sendData(chunk)
        }
    }

    private fun sendHandshake() {
        if (isHost) {
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
    }

    private fun handleIncomingMessage(data: ByteArray) {
        if (data.size < 6 || data[0] != FRAG_MAGIC) {
            listener?.onMessageReceived(data, ByteArray(2))
            return
        }

        val mid = ((data[1].toInt() and 0xFF) shl 8) or (data[2].toInt() and 0xFF)
        val fragIdx = data[3].toInt() and 0xFF
        val total = data[4].toInt() and 0xFF
        val payloadLen = data[5].toInt() and 0xFF
        val payload = data.copyOfRange(6, 6 + payloadLen)

        if (total <= 1) {
            listener?.onMessageReceived(payload, ByteArray(2))
            return
        }

        val expected = total
        fragTotal[mid] = expected
        val current = (fragCount[mid] ?: 0) + 1
        fragCount[mid] = current

        val buf = fragBuffer.getOrPut(mid) { ByteArray(0) }
        fragBuffer[mid] = buf + payload

        if (current >= expected) {
            val full = fragBuffer[mid] ?: ByteArray(0)
            fragBuffer.remove(mid)
            fragCount.remove(mid)
            fragTotal.remove(mid)
            val frame = MeshFrame.parse(full)
            if (frame != null && router != null) {
                router!!.processIncomingFrame(frame, ByteArray(2))
            } else {
                listener?.onMessageReceived(full, ByteArray(2))
            }
        }
    }

    private fun attachToAware() {
        awareManager?.attach(object : AttachCallback() {
            override fun onAttached(session: WifiAwareSession) {
                awareSession = session
                Log.d(TAG, "Wi-Fi Aware attached")
            }

            override fun onAttachFailed() {
                listener?.onTransportError("Wi-Fi Aware attach failed")
                Log.e(TAG, "Attach failed")
            }
        }, handler)
    }

    fun close() {
        isRunning = false
        statusConnected = false
        try { publishSession?.close() } catch (_: Exception) {}
        try { subscribeSession?.close() } catch (_: Exception) {}
        publishSession = null
        subscribeSession = null
        peerHandle = null
        awareSession = null
        passphrase = null
        fragBuffer.clear()
        fragCount.clear()
        fragTotal.clear()
        router?.wipe()
    }
}