package com.covertcomm.app.transport

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.covertcomm.app.crypto.CryptoUtils
import com.covertcomm.app.crypto.IdentityManager
import com.covertcomm.app.security.SecurityGuard
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.ConcurrentHashMap

class CellularTransport(
    private val context: Context,
    private val identityManager: IdentityManager
) {
    private val TAG = "CellularTransport"
    private val handler = Handler(Looper.getMainLooper())

    private fun trace(msg: String) {
        try {
            val pid = android.os.Process.myPid()
            val pkg = context.packageName
            val f = java.io.File("/sdcard/Download/cc_trace_${pkg.replace('.','_')}.log")
            java.io.FileOutputStream(f, true).bufferedWriter().use { it.appendLine("${System.currentTimeMillis()} $pid $msg") }
        } catch (e: Exception) {}
    }

    companion object {
        private const val BROKER_HOST = "broker.hivemq.com"
        private const val BROKER_PORT = 1883
        private const val KEEPALIVE_S = 45
        private const val TOPIC_PREFIX = "cc/"
    }

    private var socket: Socket? = null
    private var input: DataInputStream? = null
    private var output: DataOutputStream? = null
    private val writeLock = Any()
    @Volatile private var running = false
    @Volatile private var connected = false
    private var packetId: Int = 1

    private var clientId: String = ""
    private var topic: String = ""
    private var sessionKey: ByteArray? = null
    private var passphrase: String = ""
    private var customHost: String = BROKER_HOST
    private var customPort: Int = BROKER_PORT

    var listener: CellularListener? = null

    fun setCustomBroker(host: String, port: Int = 1883) {
        customHost = host
        customPort = port
    }

    interface CellularListener {
        fun onConnected(address: String)
        fun onDisconnected()
        fun onMessageReceived(data: ByteArray, senderFP: ByteArray)
        fun onTransportError(error: String)
        fun onHandshakeSent()
        fun onJoined(sessionId: String)
        fun onJoinFailed(reason: String)
        fun onPeerJoined(peerId: String)
    }

    fun setPassphrase(passphrase: String) {
        this.passphrase = passphrase
        val sid = CryptoUtils.sha256(("cc-session:" + passphrase).toByteArray())
        val sessionId = sid.copyOfRange(0, 6).joinToString("") { "%02x".format(it) }
        this.topic = TOPIC_PREFIX + sessionId
        val salt = CryptoUtils.sha256(("cc-salt:" + passphrase).toByteArray())
        this.sessionKey = CryptoUtils.hkdf(passphrase.toByteArray(), salt, "CovertComm-Cell-v2".toByteArray(), 32)
    }

    fun init(): Boolean {
        if (passphrase.isEmpty()) return false
        clientId = "cc_" + identityManager.getShortFingerprint().take(10)
        running = true
        return true
    }

    fun start() {
        trace("start() running=$running topicEmpty=${topic.isEmpty()}")
        if (!running || topic.isEmpty()) { listener?.onJoinFailed("Set passphrase first"); return }
        Thread {
            try {
                trace("connecting to $customHost:$customPort topic=$topic")
                connectToBroker()
                connected = true
                listener?.onConnected(customHost)
                listener?.onJoined(topic.removePrefix(TOPIC_PREFIX))
                Thread.sleep(500)
                sendAnnounce()
                readLoop()
            } catch (e: Exception) {
                trace("start error: ${e.message}")
                listener?.onTransportError("Cellular link lost: ${e.message}")
                connected = false
                listener?.onDisconnected()
            }
        }.start()
    }

    fun sendData(data: ByteArray) {
        trace("sendData size=${data.size} connected=$connected")
        if (sessionKey == null) { listener?.onTransportError("Set passphrase first"); return }
        if (!connected) { listener?.onTransportError("Not connected"); return }
        val key = sessionKey ?: return
        val aad = CryptoUtils.sha256(("cc-aad:" + passphrase).toByteArray())
        val ep = CryptoUtils.encryptAESGCM(key, data, aad)
        val ct = ep.toCombined()
        trace("sending ${data.size} -> ${ct.size} bytes")
        publish(ct)
        SecurityGuard.wipeMemory(ep.nonce); SecurityGuard.wipeMemory(ep.ciphertext); SecurityGuard.wipeMemory(ct)
    }

    fun sendData(targetFP: ByteArray, data: ByteArray) { sendData(data) }

    private fun sendAnnounce() {
        val msg = "ANN::${clientId}"
        val key = sessionKey ?: return
        val aad = CryptoUtils.sha256(("cc-aad:" + passphrase).toByteArray())
        val ep = CryptoUtils.encryptAESGCM(key, msg.toByteArray(), aad)
        publish(ep.toCombined())
        SecurityGuard.wipeMemory(ep.nonce); SecurityGuard.wipeMemory(ep.ciphertext)
    }

    private fun publish(payload: ByteArray) {
        try {
            trace("publish ${payload.size}b to $topic")
            packetId++
            if (packetId > 65535) packetId = 1
            synchronized(writeLock) {
                val tb = topic.toByteArray()
                val body = byteArrayOf((tb.size shr 8).toByte(), (tb.size and 0xFF).toByte()) + tb + byteArrayOf((packetId shr 8).toByte(), packetId.toByte()) + payload
                writeAll(byteArrayOf(0x32.toByte()) + encodeRemainingLength(body.size))
                writeAll(body)
                output?.flush()
            }
        } catch (e: Exception) { trace("publish error: ${e.message}") }
    }

    private fun readLoop() {
        trace("readLoop begin")
        try {
            while (running && connected) {
                val header = input?.read() ?: break
                val type = (header shr 4) and 0xFF
                val remaining = readRemainingLength()
                if (remaining < 0 || remaining > 65536) break
                when (type) {
                    3 -> {
                        val len = readShort()
                        if (len <= 0 || len + 2 > remaining) { input?.skipBytes(remaining); continue }
                        input?.skipBytes(len)
                        val payloadLen = remaining - 2 - len
                        if (payloadLen > 0) {
                            val payload = ByteArray(payloadLen)
                            readFully(payload)
                            handleIncoming(payload)
                        }
                    }
                    4 -> { input?.skipBytes(remaining) }
                    13 -> {}
                    9 -> { input?.skipBytes(remaining) }
                    else -> { input?.skipBytes(remaining) }
                }
            }
        } catch (e: Exception) { trace("readLoop error: ${e.message}") }
        if (running) { connected = false; listener?.onDisconnected() }
        trace("readLoop end")
    }

    private val seenAnns = ConcurrentHashMap<String, Boolean>()

    private fun handleIncoming(payload: ByteArray) {
        val key = sessionKey ?: return
        val aad = CryptoUtils.sha256(("cc-aad:" + passphrase).toByteArray())
        trace("incoming ${payload.size}b")
        val plain = try { CryptoUtils.decryptAESGCM(key, payload, aad) } catch (e: Exception) { trace("decrypt fail: ${e.message}"); null }
        if (plain != null) {
            val text = String(plain, Charsets.UTF_8)
            if (text.startsWith("ANN::")) {
                val peerId = text.removePrefix("ANN::")
                if (peerId != clientId && seenAnns.putIfAbsent(peerId, true) == null) {
                    listener?.onPeerJoined(peerId)
                    Thread { Thread.sleep(500); sendAnnounce() }.start()
                }
            } else {
                listener?.onMessageReceived(plain.copyOf(), ByteArray(2))
            }
            SecurityGuard.wipeMemory(plain)
        }
    }

    private fun readShort(): Int {
        val h = input?.read() ?: return 0; val l = input?.read() ?: return 0
        return (h shl 8) or l
    }

    private fun readRemainingLength(): Int {
        var m = 1; var v = 0; var c = 0
        while (true) {
            val b = input?.read() ?: return -1
            v += (b and 0x7F) * m
            if ((b and 0x80) == 0) break
            m *= 128; c++
            if (c > 4) return -1
        }
        return v
    }

    private fun encodeRemainingLength(l: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        var x = l
        while (true) { var d = x % 128; x /= 128; if (x > 0) d = d or 0x80; out.write(d); if (x <= 0) break }
        return out.toByteArray()
    }

    private fun readFully(b: ByteArray) {
        var off = 0
        while (off < b.size) { val n = input?.read(b, off, b.size - off) ?: break; if (n <= 0) break; off += n }
    }

    private fun writeAll(b: ByteArray) { output?.write(b) }

    private fun connectToBroker() {
        trace("TCP connect $customHost:$customPort")
        socket = Socket(customHost, customPort)
        socket?.tcpNoDelay = true
        socket?.soTimeout = 0
        input = DataInputStream(socket?.getInputStream())
        output = DataOutputStream(socket?.getOutputStream())

        val id = clientId.toByteArray()
        val pkt = byteArrayOf(0, 4, 'M'.code.toByte(), 'Q'.code.toByte(), 'T'.code.toByte(), 'T'.code.toByte()) +
                byteArrayOf(0x04, 0x02) + byteArrayOf((KEEPALIVE_S shr 8).toByte(), KEEPALIVE_S.toByte()) +
                byteArrayOf((id.size shr 8).toByte(), (id.size and 0xFF).toByte()) + id
        synchronized(writeLock) { writeAll(byteArrayOf(0x10) + encodeRemainingLength(pkt.size)); writeAll(pkt); output?.flush() }

        input?.read()
        readRemainingLength()
        input?.skipBytes(2)
        trace("CONNACK OK")

        val tb = topic.toByteArray()
        val sub = byteArrayOf(0x00, 0x01) + byteArrayOf((tb.size shr 8).toByte(), (tb.size and 0xFF).toByte()) + tb + byteArrayOf(0x01)
        synchronized(writeLock) { writeAll(byteArrayOf(0x82.toByte()) + encodeRemainingLength(sub.size)); writeAll(sub); output?.flush() }
        trace("SUBSCRIBED to $topic")
    }

    fun close() {
        running = false; connected = false
        try { socket?.close() } catch (_: Exception) {}
        socket = null; sessionKey?.let { CryptoUtils.wipe(it) }; sessionKey = null
    }
}