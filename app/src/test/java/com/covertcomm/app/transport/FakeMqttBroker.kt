package com.covertcomm.app.transport

import com.covertcomm.app.crypto.CryptoUtils
import com.covertcomm.app.crypto.NestedCipher
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * A minimal MQTT 3.1.1 broker that speaks exactly the subset of the protocol that
 * CellularTransport implements: CONNECT/CONNACK, SUBSCRIBE/SUBACK, PUBLISH (QoS1) with PUBACK,
 * PINGREQ/PINGRESP. It can push encrypted frames to every subscribed client, which lets tests
 * exercise the real client without any real network hardware.
 */
class FakeMqttBroker {

    data class Publication(val topic: String, val payload: ByteArray)

    private val server = ServerSocket(0)
    val port: Int get() = server.localPort

    private val clients = CopyOnWriteArrayList<Client>()
    private val publications = CopyOnWriteArrayList<Publication>()

    @Volatile private var running = true
    private val acceptThread = Thread({ acceptLoop() }, "fake-broker-accept").apply {
        isDaemon = true
        start()
    }

    private inner class Client(val socket: Socket) {
        val out = DataOutputStream(socket.getOutputStream().buffered())
        val writeLock = Any()
        @Volatile var clientId: String = ""
        @Volatile var topic: String = ""
        @Volatile var closed = false
    }

    private fun acceptLoop() {
        while (running) {
            val socket = try { server.accept() } catch (e: Exception) { return }
            val client = Client(socket)
            clients.add(client)
            Thread({ serve(client) }, "fake-broker-client").apply { isDaemon = true; start() }
        }
    }

    private fun serve(client: Client) {
        try {
            val input = DataInputStream(client.socket.getInputStream().buffered())
            while (running && !client.closed) {
                val header = input.read()
                if (header < 0) break
                val type = (header shr 4) and 0x0F
                val remaining = readRemainingLength(input)
                if (remaining < 0) break
                val body = ByteArray(remaining)
                input.readFully(body)
                when (type) {
                    1 -> handleConnect(client, body)
                    8 -> handleSubscribe(client, body)
                    3 -> handlePublish(client, (header and 0x0F), body)
                    12 -> handlePingReq(client)
                    14 -> break
                    else -> {}
                }
            }
        } catch (_: Exception) {
        } finally {
            client.closed = true
            clients.remove(client)
            try { client.socket.close() } catch (_: Exception) {}
        }
    }

    private fun handleConnect(client: Client, body: ByteArray) {
        var i = 0
        val protoLen = ((body[i].toInt() and 0xFF) shl 8) or (body[i + 1].toInt() and 0xFF)
        i += 2 + protoLen
        i += 1
        val flags = body[i].toInt() and 0xFF
        i += 1
        i += 2
        val idLen = ((body[i].toInt() and 0xFF) shl 8) or (body[i + 1].toInt() and 0xFF)
        i += 2
        client.clientId = String(body, i, idLen, Charsets.UTF_8)
        val sessionPresent = if ((flags and 0x02) != 0) 0x01 else 0x00
        synchronized(client.writeLock) {
            client.out.write(byteArrayOf(0x20, 0x02, sessionPresent.toByte(), 0x00))
            client.out.flush()
        }
    }

    private fun handleSubscribe(client: Client, body: ByteArray) {
        val packetId = ((body[0].toInt() and 0xFF) shl 8) or (body[1].toInt() and 0xFF)
        val topicLen = ((body[2].toInt() and 0xFF) shl 8) or (body[3].toInt() and 0xFF)
        client.topic = String(body, 4, topicLen, Charsets.UTF_8)
        synchronized(client.writeLock) {
            client.out.write(byteArrayOf(0x90.toByte(), 0x03, ((packetId shr 8) and 0xFF).toByte(), (packetId and 0xFF).toByte(), 0x01))
            client.out.flush()
        }
    }

    private fun handlePublish(client: Client, flags: Int, body: ByteArray) {
        val qos = (flags shr 1) and 0x03
        val topicLen = ((body[0].toInt() and 0xFF) shl 8) or (body[1].toInt() and 0xFF)
        val topic = String(body, 2, topicLen, Charsets.UTF_8)
        var offset = 2 + topicLen
        var packetId = 0
        if (qos > 0) {
            packetId = ((body[offset].toInt() and 0xFF) shl 8) or (body[offset + 1].toInt() and 0xFF)
            offset += 2
        }
        val payload = body.copyOfRange(offset, body.size)
        publications.add(Publication(topic, payload))
        if (qos == 1) {
            synchronized(client.writeLock) {
                client.out.write(byteArrayOf(0x40, 0x02, ((packetId shr 8) and 0xFF).toByte(), (packetId and 0xFF).toByte()))
                client.out.flush()
            }
        }
    }

    private fun handlePingReq(client: Client) {
        synchronized(client.writeLock) {
            client.out.write(byteArrayOf(0xC0.toByte(), 0x00))
            client.out.flush()
        }
    }

    /** Pushes a QoS1 PUBLISH to every client subscribed to [topic], mimicking a real broker. */
    fun push(topic: String, payload: ByteArray) {
        var packetId = 1
        for (client in clients) {
            if (client.closed || client.topic != topic) continue
            val topicBytes = topic.toByteArray(Charsets.UTF_8)
            val body = ByteArray(2 + topicBytes.size + 2 + payload.size)
            var i = 0
            body[i++] = ((topicBytes.size shr 8) and 0xFF).toByte()
            body[i++] = (topicBytes.size and 0xFF).toByte()
            System.arraycopy(topicBytes, 0, body, i, topicBytes.size)
            i += topicBytes.size
            val pid = packetId++
            body[i++] = ((pid shr 8) and 0xFF).toByte()
            body[i++] = (pid and 0xFF).toByte()
            System.arraycopy(payload, 0, body, i, payload.size)
            synchronized(client.writeLock) {
                client.out.write(byteArrayOf(0x32, encodeRemainingLength(body.size)[0]))
                if (body.size >= 128) client.out.write(encodeRemainingLength(body.size), 1, encodeRemainingLength(body.size).size - 1)
                client.out.write(body)
                client.out.flush()
            }
        }
    }

    fun connectedClientIds(): List<String> = clients.filter { !it.closed }.map { it.clientId }

    fun publishedPayloads(): List<ByteArray> = publications.map { it.payload }

    fun awaitClientCount(count: Int, timeoutMs: Long = 5000): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (clients.count { !it.closed } >= count) return true
            Thread.sleep(20)
        }
        return clients.count { !it.closed } >= count
    }

    fun awaitPublicationCount(count: Int, timeoutMs: Long = 5000): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (publications.size >= count) return true
            Thread.sleep(20)
        }
        return publications.size >= count
    }

    fun close() {
        running = false
        for (c in clients) { try { c.socket.close() } catch (_: Exception) {} }
        try { server.close() } catch (_: Exception) {}
    }

    private fun readRemainingLength(input: InputStream): Int {
        var multiplier = 1
        var value = 0
        var count = 0
        while (true) {
            val b = input.read()
            if (b < 0) return -1
            value += (b and 0x7F) * multiplier
            if ((b and 0x80) == 0) break
            multiplier *= 128
            count++
            if (count > 3) return -1
        }
        return value
    }

    private fun encodeRemainingLength(l: Int): ByteArray {
        val out = ByteArrayOutputStream()
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
}
