package com.covertcomm.app.transport

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.covertcomm.app.crypto.IdentityManager
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class HotspotTransportTest {

    private lateinit var context: Context
    private lateinit var identity: IdentityManager
    private lateinit var server: ServerSocket
    private var peer: Socket? = null
    private var transport: HotspotTransport? = null
    private val received = CopyOnWriteArrayList<ByteArray>()
    private val incoming = CountDownLatch(1)
    private val peerConnected = CountDownLatch(1)
    private val peerDisconnected = CountDownLatch(1)

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        identity = IdentityManager(context)
        server = ServerSocket(0)
    }

    @After
    fun tearDown() {
        transport?.close()
        try { peer?.close() } catch (_: Exception) {}
        try { server.close() } catch (_: Exception) {}
    }

    private fun acceptPeer(): Socket {
        val socket = server.accept()
        peer = socket
        return socket
    }

    private fun startClient(): HotspotTransport {
        val t = HotspotTransport(context, identity)
        t.listener = object : HotspotTransport.HotspotListener {
            override fun onPeerConnected(address: String) { peerConnected.countDown() }
            override fun onPeerDisconnected() { peerDisconnected.countDown() }
            override fun onMessageReceived(data: ByteArray) {
                received.add(data)
                incoming.countDown()
            }
            override fun onTransportError(error: String) {}
            override fun onHandshakeSent() {}
            override fun onHotspotStarted(ssid: String, password: String, ip: String) {}
            override fun onHotspotFailed(ssid: String, password: String) {}
        }
        transport = t
        t.startAsClient("127.0.0.1", server.localPort)
        return t
    }

    @Test
    fun clientSendsLengthPrefixedFrames() {
        startClient()
        val socket = acceptPeer()
        val input = DataInputStream(socket.getInputStream().buffered())

        assertTrue("client must report the link as connected", peerConnected.await(6, TimeUnit.SECONDS))

        val t = transport!!
        t.sendData("hello-hotspot".toByteArray())
        t.sendData(ByteArray(0))

        val first = ByteArray(input.readInt())
        input.readFully(first)
        assertArrayEquals("hello-hotspot".toByteArray(), first)

        assertEquals("empty frame must still be framed", 0, input.readInt())
    }

    @Test
    fun clientReceivesFramesFromHost() {
        startClient()
        val socket = acceptPeer()
        assertTrue(peerConnected.await(6, TimeUnit.SECONDS))

        val out = DataOutputStream(socket.getOutputStream().buffered())
        val payload = "reply-from-host".toByteArray()
        out.writeInt(payload.size)
        out.write(payload)
        out.flush()

        assertTrue("host frame must reach the listener", incoming.await(6, TimeUnit.SECONDS))
        assertArrayEquals(payload, received.first())
    }

    @Test
    fun largeFrameIsReassembledByReader() {
        startClient()
        val socket = acceptPeer()
        assertTrue(peerConnected.await(6, TimeUnit.SECONDS))

        val out = DataOutputStream(socket.getOutputStream().buffered())
        val payload = ByteArray(200_000) { (it % 251).toByte() }
        out.writeInt(payload.size)
        out.write(payload)
        out.flush()

        assertTrue("large frame must arrive intact", incoming.await(10, TimeUnit.SECONDS))
        assertEquals(payload.size, received.first().size)
        assertArrayEquals(payload, received.first())
    }

    @Test
    fun oversizedLengthIsRejected() {
        startClient()
        val socket = acceptPeer()
        assertTrue(peerConnected.await(6, TimeUnit.SECONDS))

        val out = DataOutputStream(socket.getOutputStream().buffered())
        out.writeInt(8 * 1024 * 1024)
        out.flush()

        assertTrue("reader must stop on an oversized frame", peerDisconnected.await(8, TimeUnit.SECONDS) || received.isEmpty())
        Thread.sleep(500)
        assertTrue("no message may be delivered for an oversized frame", received.isEmpty())
    }
}