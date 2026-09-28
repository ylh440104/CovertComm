package com.covertcomm.app.transport

import android.content.Context
import android.util.Log
import com.covertcomm.app.crypto.CryptoUtils
import com.covertcomm.app.crypto.IdentityManager
import com.covertcomm.app.crypto.NestedCipher
import com.covertcomm.app.security.SecurityGuard
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Global messaging transport over MQTT 3.1.1 to a public or custom broker.
 *
 * Fixes in this revision:
 *  - PUBLISH parsing consumes the packet identifier for QoS > 0, so inbound
 *    payloads are no longer shifted by two bytes (which broke every decrypt).
 *  - PUBACK is returned for inbound QoS1 messages.
 *  - CONNACK / SUBACK are validated instead of being blindly skipped.
 *  - A PINGREQ keepalive thread stops the broker from dropping an idle link.
 *  - Automatic reconnect with exponential backoff.
 *  - Passphrase -> key derivation hardened with PBKDF2-HMAC-SHA256.
 */
class CellularTransport(
    private val context: Context,
    private val identityManager: IdentityManager
) {
    private companion object {
        const val BROKER_HOST = "broker.hivemq.com"
        const val BROKER_PORT = 1883
        const val KEEPALIVE_S = 30
        const val TOPIC_PREFIX = "cc/"
        const val CONNECT_TIMEOUT_MS = 15000
        const val MAX_REMAINING = 1 shl 20
        const val PBKDF2_ITERATIONS = 100_000
        const val TRACE = false

        const val PKT_PUBLISH = 3
    }

    private val TAG = "CellularTransport"

    @Volatile private var socket: Socket? = null
    private var input: DataInputStream? = null
    private var output: DataOutputStream? = null
    private val writeLock = Any()

    @Volatile private var running = false
    @Volatile private var connected = false
    private var packetId = 1
    private var supervisor: Thread? = null
    private var pinger: Thread? = null

    private var clientId = ""
    private var topic = ""
    @Volatile private var sessionKey: ByteArray? = null
    @Volatile private var nestedSession: NestedCipher.Session? = null
    private var passphrase = ""
    @Volatile private var customHost = BROKER_HOST
    @Volatile private var customPort = BROKER_PORT

    private val seenAnns = ConcurrentHashMap<String, Long>()

    // MQTT 3.1.1 has no "no local" option, so the broker echoes a client's own
    // PUBLISH back to it. Without this, our own messages are re-processed as if
    // they came from the peer (overwriting the pending handshake bundle and
    // colliding on ratchet counters, which surfaced as "Decrypt failed").
    private val ownEchoes = ConcurrentHashMap<String, Long>()

    var listener: CellularListener? = null

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

    private fun trace(msg: String) {
        if (TRACE) Log.d(TAG, msg)
    }

    fun setCustomBroker(host: String, port: Int = 1883) {
        customHost = host.ifBlank { BROKER_HOST }
        customPort = if (port in 1..65535) port else BROKER_PORT
    }

    fun setPassphrase(passphrase: String) {
        this.passphrase = passphrase
        val sessionId = CryptoUtils.sha256(("cc-session:" + passphrase).toByteArray())
            .copyOfRange(0, 6).joinToString("") { "%02x".format(it) }
        this.topic = TOPIC_PREFIX + sessionId
        this.sessionKey = deriveSessionKey(passphrase)
        this.nestedSession = NestedCipher.derive(passphrase)
    }

    private fun deriveSessionKey(passphrase: String): ByteArray {
        val salt = CryptoUtils.sha256(("cc-salt:" + passphrase).toByteArray())
        return try {
            val spec = PBEKeySpec(passphrase.toCharArray(), salt, PBKDF2_ITERATIONS, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val key = factory.generateSecret(spec).encoded
            spec.clearPassword()
            key
        } catch (e: Exception) {
            CryptoUtils.hkdf(passphrase.toByteArray(), salt, "CovertComm-Cell-v2".toByteArray(), 32)
        }
    }

    fun init(): Boolean {
        if (passphrase.isEmpty() || sessionKey == null || topic.isEmpty()) return false
        clientId = "cc_" + identityManager.getShortFingerprint().take(10)
        return true
    }

    fun start() {
        if (sessionKey == null || topic.isEmpty()) {
            listener?.onJoinFailed("Set passphrase first")
            return
        }
        if (running) return
        running = true
        supervisor = Thread({ supervise() }, "cellular-supervisor").also {
            it.isDaemon = true
            it.start()
        }
    }

    private fun supervise() {
        var attempt = 0
        while (running) {
            try {
                connectAndSubscribe()
                connected = true
                attempt = 0
                listener?.onConnected(customHost)
                listener?.onJoined(topic.removePrefix(TOPIC_PREFIX))
                startPinger()
                try { Thread.sleep(300) } catch (_: InterruptedException) {}
                sendAnnounce()
                readLoop()
            } catch (e: Exception) {
                trace("connection failed: ${e.message}")
                if (running && !connected) {
                    listener?.onTransportError("Cellular link error: ${e.message}")
                }
            }
            stopPinger()
            val wasConnected = connected
            connected = false
            closeSocket()
            if (wasConnected) listener?.onDisconnected()
            if (!running) break
            attempt = (attempt + 1).coerceAtMost(6)
            val backoff = (1L shl attempt) * 500L
            trace("reconnect in ${backoff}ms")
            try { Thread.sleep(backoff) } catch (_: InterruptedException) { break }
        }
    }

    private fun connectAndSubscribe() {
        val s = Socket()
        s.tcpNoDelay = true
        s.connect(InetSocketAddress(customHost, customPort), CONNECT_TIMEOUT_MS)
        s.soTimeout = 0
        socket = s
        input = DataInputStream(s.getInputStream().buffered())
        output = DataOutputStream(s.getOutputStream().buffered())

        sendConnect()
        readConnack()
        sendSubscribe()
        readSuback()
    }

    private fun sendConnect() {
        val id = clientId.toByteArray(Charsets.UTF_8)
        val body = ByteArray(12 + id.size)
        var i = 0
        body[i++] = 0x00
        body[i++] = 0x04
        body[i++] = 'M'.code.toByte()
        body[i++] = 'Q'.code.toByte()
        body[i++] = 'T'.code.toByte()
        body[i++] = 'T'.code.toByte()
        body[i++] = 0x04                                    // protocol level 3.1.1
        body[i++] = 0x02                                    // clean session
        body[i++] = ((KEEPALIVE_S shr 8) and 0xFF).toByte()
        body[i++] = (KEEPALIVE_S and 0xFF).toByte()
        body[i++] = ((id.size shr 8) and 0xFF).toByte()
        body[i++] = (id.size and 0xFF).toByte()
        System.arraycopy(id, 0, body, i, id.size)

        synchronized(writeLock) {
            writeAll(byteArrayOf(0x10) + encodeRemainingLength(body.size))
            writeAll(body)
            output?.flush()
        }
    }

    private fun readConnack() {
        val b0 = input!!.readUnsignedByte()
        if (b0 != 0x20) throw IOException("Expected CONNACK, got 0x%02x".format(b0))
        val len = readRemainingLength()
        if (len != 2) throw IOException("Bad CONNACK length $len")
        input!!.readUnsignedByte()                          // session present flag
        val rc = input!!.readUnsignedByte()
        if (rc != 0) throw IOException("Broker refused connection (code $rc)")
    }

    private fun sendSubscribe() {
        val tb = topic.toByteArray(Charsets.UTF_8)
        val body = ByteArray(2 + 2 + tb.size + 1)
        var i = 0
        body[i++] = 0x00
        body[i++] = 0x01                                    // packet id 1
        body[i++] = ((tb.size shr 8) and 0xFF).toByte()
        body[i++] = (tb.size and 0xFF).toByte()
        System.arraycopy(tb, 0, body, i, tb.size)
        i += tb.size
        body[i] = 0x01                                      // requested QoS 1

        synchronized(writeLock) {
            writeAll(byteArrayOf(0x82.toByte()) + encodeRemainingLength(body.size))
            writeAll(body)
            output?.flush()
        }
    }

    private fun readSuback() {
        val b0 = input!!.readUnsignedByte()
        if ((b0 and 0xF0) != 0x90) throw IOException("Expected SUBACK, got 0x%02x".format(b0))
        val len = readRemainingLength()
        if (len < 3) throw IOException("Bad SUBACK length $len")
        input!!.readUnsignedShort()                         // packet id
        val granted = input!!.readUnsignedByte()            // first return code
        if (len > 3) skipFully(len - 3)
        if (granted == 0x80) throw IOException("Subscription rejected by broker")
    }

    private fun readLoop() {
        val ins = input ?: return
        while (running && connected) {
            val header = ins.read()
            if (header < 0) break
            val type = (header shr 4) and 0x0F
            val flags = header and 0x0F
            val remaining = readRemainingLength()
            if (remaining < 0) break
            when (type) {
                PKT_PUBLISH -> handlePublish(flags, remaining)
                else -> skipFully(remaining)                // PUBACK / SUBACK / PINGRESP / CONNACK
            }
        }
    }

    private fun handlePublish(flags: Int, remaining: Int) {
        val ins = input ?: return
        if (remaining < 2) { skipFully(remaining); return }

        val topicLen = ins.readUnsignedShort()
        if (topicLen + 2 > remaining) { skipFully(remaining - 2); return }
        skipFully(topicLen)

        val qos = (flags shr 1) and 0x03
        var pid = 0
        if (qos > 0) {
            if (remaining < topicLen + 4) { skipFully(remaining - 2 - topicLen); return }
            pid = ins.readUnsignedShort()
        }

        val consumed = 2 + topicLen + (if (qos > 0) 2 else 0)
        val payloadLen = remaining - consumed
        if (payloadLen < 0) return

        val payload = ByteArray(payloadLen)
        ins.readFully(payload)

        if (qos == 1 && pid > 0) sendPuback(pid)
        handleIncoming(payload)
    }

    private fun handleIncoming(payload: ByteArray) {
        val key = sessionKey ?: return
        // Drop the broker's echo of our own PUBLISH. The entry is NOT removed on
        // match: a QoS1 retransmission can deliver the same echo more than once,
        // and removing it would let the duplicate through on the second copy.
        val echo = echoKey(payload)
        if (ownEchoes.containsKey(echo)) {
            trace("ignored own echo")
            return
        }
        val aad = CryptoUtils.sha256(("cc-aad:" + passphrase).toByteArray())
        val unwrapped = nestedSession?.let { NestedCipher.decrypt(it, payload) } ?: payload
        val plain = try {
            CryptoUtils.decryptAESGCM(key, unwrapped, aad)
        } catch (e: Exception) {
            trace("decrypt fail: ${e.message}")
            null
        } ?: return

        try {
            val text = String(plain, Charsets.UTF_8)
            if (text.startsWith("ANN::")) {
                val peerId = text.removePrefix("ANN::")
                if (peerId != clientId) {
                    val now = System.currentTimeMillis()
                    val prev = seenAnns[peerId]
                    if (prev == null || now - prev > 60_000) {
                        seenAnns[peerId] = now
                        listener?.onPeerJoined(peerId)
                        // Answer once so the peer learns about us, then stay quiet.
                        Thread {
                            try { Thread.sleep(300) } catch (_: InterruptedException) {}
                            sendAnnounce()
                        }.start()
                    }
                }
            } else {
                listener?.onMessageReceived(plain.copyOf(), ByteArray(2))
            }
        } finally {
            SecurityGuard.wipeMemory(plain)
        }
    }

    fun sendData(data: ByteArray) {
        val key = sessionKey
        if (key == null) { listener?.onTransportError("Set passphrase first"); return }
        if (!connected) { listener?.onTransportError("Not connected"); return }
        val aad = CryptoUtils.sha256(("cc-aad:" + passphrase).toByteArray())
        val ep = CryptoUtils.encryptAESGCM(key, data, aad)
        var ct = ep.toCombined()
        // Extra layered pass (Feistel + XOR + AES-GCM) as documented for the
        // cellular path.
        nestedSession?.let { ct = NestedCipher.encrypt(it, ct) }
        publish(ct)
        SecurityGuard.wipeMemory(ep.nonce)
        SecurityGuard.wipeMemory(ep.ciphertext)
        SecurityGuard.wipeMemory(ct)
    }

    fun sendData(targetFP: ByteArray, data: ByteArray) = sendData(data)

    private fun sendAnnounce() {
        val key = sessionKey ?: return
        val aad = CryptoUtils.sha256(("cc-aad:" + passphrase).toByteArray())
        val ep = CryptoUtils.encryptAESGCM(key, "ANN::$clientId".toByteArray(Charsets.UTF_8), aad)
        var ct = ep.toCombined()
        nestedSession?.let { ct = NestedCipher.encrypt(it, ct) }
        publish(ct)
        SecurityGuard.wipeMemory(ep.nonce)
        SecurityGuard.wipeMemory(ep.ciphertext)
        SecurityGuard.wipeMemory(ct)
    }

    private fun publish(payload: ByteArray) {
        if (!connected) { trace("publish skipped, not connected"); return }
        try {
            // Remember this payload so the broker's echo of our own PUBLISH can be
            // dropped instead of being treated as an inbound peer message.
            val fingerprint = echoKey(payload)
            val now = System.currentTimeMillis()
            ownEchoes[fingerprint] = now
            if (ownEchoes.size > 512) {
                val iter = ownEchoes.entries.iterator()
                while (iter.hasNext()) {
                    if (now - iter.next().value > 120_000) iter.remove()
                }
            }

            val tb = topic.toByteArray(Charsets.UTF_8)
            synchronized(writeLock) {
                val pid = nextPacketIdLocked()
                val body = ByteArray(2 + tb.size + 2 + payload.size)
                var i = 0
                body[i++] = ((tb.size shr 8) and 0xFF).toByte()
                body[i++] = (tb.size and 0xFF).toByte()
                System.arraycopy(tb, 0, body, i, tb.size)
                i += tb.size
                body[i++] = ((pid shr 8) and 0xFF).toByte()
                body[i++] = (pid and 0xFF).toByte()
                System.arraycopy(payload, 0, body, i, payload.size)

                writeAll(byteArrayOf(0x32.toByte()) + encodeRemainingLength(body.size))
                writeAll(body)
                output?.flush()
            }
        } catch (e: Exception) {
            trace("publish error: ${e.message}")
        }
    }

    private fun nextPacketIdLocked(): Int {
        packetId++
        if (packetId > 65535) packetId = 1
        return packetId
    }

    private fun echoKey(payload: ByteArray): String {
        return CryptoUtils.sha256(payload).copyOfRange(0, 16).joinToString("") { "%02x".format(it) }
    }

    private fun sendPuback(pid: Int) {
        try {
            synchronized(writeLock) {
                writeAll(
                    byteArrayOf(
                        0x40,
                        0x02,
                        ((pid shr 8) and 0xFF).toByte(),
                        (pid and 0xFF).toByte()
                    )
                )
                output?.flush()
            }
        } catch (_: Exception) {}
    }

    private fun sendPingReq() {
        synchronized(writeLock) {
            writeAll(byteArrayOf(0xC0.toByte(), 0x00))
            output?.flush()
        }
    }

    private fun startPinger() {
        stopPinger()
        pinger = Thread({
            while (running && connected) {
                try { Thread.sleep(KEEPALIVE_S * 1000L / 2) } catch (_: InterruptedException) { return@Thread }
                if (!running || !connected) return@Thread
                try { sendPingReq() } catch (_: Exception) { return@Thread }
            }
        }, "cellular-pinger").also {
            it.isDaemon = true
            it.start()
        }
    }

    private fun stopPinger() {
        pinger?.interrupt()
        pinger = null
    }

    private fun readRemainingLength(): Int {
        val ins = input ?: return -1
        var multiplier = 1
        var value = 0
        var bytes = 0
        while (true) {
            val b = ins.read()
            if (b < 0) return -1
            value += (b and 0x7F) * multiplier
            if ((b and 0x80) == 0) break
            multiplier *= 128
            bytes++
            if (bytes > 3 || value > MAX_REMAINING) return -1
        }
        return value
    }

    private fun encodeRemainingLength(l: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        var x = l
        while (true) {
            var d = x % 128
            x /= 128
            if (x > 0) d = d or 0x80
            out.write(d)
            if (x <= 0) break
        }
        return out.toByteArray()
    }

    private fun skipFully(n: Int) {
        if (n <= 0) return
        val ins = input ?: return
        val buf = ByteArray(256)
        var left = n
        while (left > 0) {
            val chunk = minOf(left, buf.size)
            val read = ins.read(buf, 0, chunk)
            if (read < 0) throw EOFException()
            left -= read
        }
    }

    private fun writeAll(b: ByteArray) {
        output?.write(b)
    }

    private fun closeSocket() {
        try { socket?.close() } catch (_: Exception) {}
        socket = null
        input = null
        output = null
    }

    fun close() {
        running = false
        connected = false
        stopPinger()
        closeSocket()
        supervisor?.interrupt()
        supervisor = null
        sessionKey?.let { CryptoUtils.wipe(it) }
        sessionKey = null
        nestedSession?.wipe()
        nestedSession = null
        seenAnns.clear()
        ownEchoes.clear()
    }
}