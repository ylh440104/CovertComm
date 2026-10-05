package com.covertcomm.app.transport

import android.content.Context
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import androidx.test.core.app.ApplicationProvider
import com.covertcomm.app.crypto.IdentityManager
import com.covertcomm.app.testutil.Reflect
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadow.api.Shadow
import org.robolectric.shadows.ShadowWifiP2pManager
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class WifiDirectTransportTest {

    private lateinit var context: Context
    private lateinit var identity: IdentityManager
    private lateinit var p2pManager: WifiP2pManager
    private lateinit var shadowP2p: ShadowWifiP2pManager
    private var transport: WifiDirectTransport? = null
    private var peer: Socket? = null
    private var server: ServerSocket? = null

    private val received = CopyOnWriteArrayList<ByteArray>()
    private val incoming = CountDownLatch(1)
    private val connected = CountDownLatch(1)

    private class Recorder : WifiDirectTransport.WifiDirectListener {
        val errors = CopyOnWriteArrayList<String>()
        val peers = CopyOnWriteArrayList<String>()
        override fun onPeerConnected(address: String) {}
        override fun onPeerDisconnected() {}
        override fun onMessageReceived(data: ByteArray) {}
        override fun onTransportError(error: String) { errors.add(error) }
        override fun onHandshakeSent() {}
        override fun onDiscoveryStarted() {}
        override fun onDiscoveryFailed(reason: String) { errors.add(reason) }
        override fun onPeerFound(deviceName: String) { peers.add(deviceName) }
    }

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        identity = IdentityManager(context)
        p2pManager = context.getSystemService(Context.WIFI_P2P_SERVICE) as WifiP2pManager
        shadowP2p = Shadow.extract(p2pManager)
    }

    @After
    fun tearDown() {
        transport?.close()
        transport = null
        try { peer?.close() } catch (_: Exception) {}
        try { server?.close() } catch (_: Exception) {}
    }

    @Test
    fun initSucceedsAndRegistersReceiver() {
        val t = WifiDirectTransport(context, identity)
        transport = t
        assertTrue("init must succeed when the P2P service exists", t.init())
    }

    @Test
    fun createGroupSuccessIsReported() {
        val recorder = Recorder()
        val t = WifiDirectTransport(context, identity)
        transport = t
        t.listener = recorder
        t.init()
        t.startGroupOwner()
        shadowOf(android.os.Looper.getMainLooper()).idle()
        assertTrue("createGroup success must be reported", recorder.errors.isEmpty())
    }

    @Test
    fun createGroupFailureIsReported() {
        val recorder = Recorder()
        val t = WifiDirectTransport(context, identity)
        transport = t
        t.listener = recorder
        t.init()
        shadowP2p.setNextActionFailure(WifiP2pManager.BUSY)
        t.startGroupOwner()
        shadowOf(android.os.Looper.getMainLooper()).idle()
        assertTrue(recorder.errors.any { it.contains("group create") })
    }

    @Test
    fun peerListIsBroadcastToListener() {
        val recorder = Recorder()
        val t = WifiDirectTransport(context, identity)
        transport = t
        t.listener = recorder
        t.init()

        val peers = android.net.wifi.p2p.WifiP2pDeviceList()
        val field = android.net.wifi.p2p.WifiP2pDeviceList::class.java.getDeclaredField("mDevices")
        field.isAccessible = true
        val map = field.get(peers) as MutableMap<String, WifiP2pDevice>
        val device = WifiP2pDevice()
        device.deviceName = "PeerDevice"
        device.deviceAddress = "02:00:00:00:00:01"
        map[device.deviceAddress] = device

        Reflect.call(t, "handlePeers", peers)
        assertTrue("discovered peer must be reported", recorder.peers.contains("PeerDevice"))
    }

    @Test
    fun groupOwnerStartsServerAndAcceptsConnection() {
        val t = WifiDirectTransport(context, identity)
        transport = t
        t.listener = object : WifiDirectTransport.WifiDirectListener {
            override fun onPeerConnected(address: String) { connected.countDown() }
            override fun onPeerDisconnected() {}
            override fun onMessageReceived(data: ByteArray) { received.add(data); incoming.countDown() }
            override fun onTransportError(error: String) {}
            override fun onHandshakeSent() {}
            override fun onDiscoveryStarted() {}
            override fun onDiscoveryFailed(reason: String) {}
            override fun onPeerFound(deviceName: String) {}
        }
        t.init()

        val info = WifiP2pInfo()
        info.groupFormed = true
        info.isGroupOwner = true
        Reflect.call(t, "handleConnectionInfo", info)

        val socket = Socket("127.0.0.1", 8888)
        peer = socket
        assertTrue("group owner must report the peer", connected.await(6, TimeUnit.SECONDS))

        val out = DataOutputStream(socket.getOutputStream().buffered())
        val payload = "p2p-payload".toByteArray()
        out.writeInt(payload.size)
        out.write(payload)
        out.flush()

        assertTrue("group owner must deliver the frame", incoming.await(6, TimeUnit.SECONDS))
        assertArrayEquals(payload, received.first())
    }

    @Test
    fun clientSendsLengthPrefixedFrame() {
        server = ServerSocket(0)
        val t = WifiDirectTransport(context, identity)
        transport = t
        t.init()
        t.startAsClientForTest("127.0.0.1", server!!.localPort)

        val accepted = server!!.accept()
        peer = accepted
        val input = DataInputStream(accepted.getInputStream().buffered())

        assertTrue(waitFor { Reflect.field(t, "clientSocket") != null })

        t.sendData("p2p-out".toByteArray())
        val len = input.readInt()
        val body = ByteArray(len)
        input.readFully(body)
        assertArrayEquals("p2p-out".toByteArray(), body)
    }

    private fun WifiDirectTransport.startAsClientForTest(host: String, port: Int) {
        Reflect.set(this, "isRunning", true)
        Reflect.call(this, "connectToHost", host, port)
    }

    private fun waitFor(timeoutMs: Long = 6000, condition: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            Thread.sleep(25)
        }
        return condition()
    }
}