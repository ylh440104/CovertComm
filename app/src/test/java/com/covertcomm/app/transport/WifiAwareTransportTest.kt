package com.covertcomm.app.transport

import android.content.Context
import android.net.wifi.aware.WifiAwareManager
import android.os.Binder
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import com.covertcomm.app.crypto.CryptoUtils
import com.covertcomm.app.crypto.IdentityManager
import com.covertcomm.app.mesh.FragmentCodec
import com.covertcomm.app.mesh.MeshFrame
import com.covertcomm.app.mesh.MeshRouter
import com.covertcomm.app.testutil.Reflect
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadow.api.Shadow
import org.robolectric.shadows.ShadowWifiAwareManager
import java.util.concurrent.CopyOnWriteArrayList

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class WifiAwareTransportTest {

    private lateinit var context: Context
    private lateinit var identity: IdentityManager
    private lateinit var awareManager: WifiAwareManager
    private lateinit var shadowAware: ShadowWifiAwareManager
    private var transport: WifiAwareTransport? = null

    private val fragMagic: Byte = 0x7A

    private class Recorder : WifiAwareTransport.WifiAwareListener {
        val errors = CopyOnWriteArrayList<String>()
        val messages = CopyOnWriteArrayList<ByteArray>()
        val discovered = CopyOnWriteArrayList<String>()
        @Volatile var discoveryStarted = false
        @Volatile var peerConnected = false
        override fun onPeerConnected(address: String) { peerConnected = true }
        override fun onPeerDisconnected() {}
        override fun onMessageReceived(data: ByteArray, senderFP: ByteArray) { messages.add(data) }
        override fun onTransportError(error: String) { errors.add(error) }
        override fun onHandshakeSent() {}
        override fun onDiscoveryStarted() { discoveryStarted = true }
        override fun onDiscoveryFailed(reason: String) { errors.add(reason) }
        override fun onPeerDiscovered(peerId: String) { discovered.add(peerId) }
    }

    private class RouterRecorder : MeshRouter.RouterListener {
        val data = CopyOnWriteArrayList<Pair<ByteArray, ByteArray>>()
        override fun onFrameReady(frame: ByteArray, nextHop: ByteArray?) {}
        override fun onDataReceived(payload: ByteArray, senderFP: ByteArray) { data.add(payload to senderFP) }
        override fun onRouteEstablished(targetFP: ByteArray) {}
        override fun onRouteRequest(targetFP: ByteArray) {}
    }

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        identity = IdentityManager(context)
        awareManager = context.getSystemService(Context.WIFI_AWARE_SERVICE) as WifiAwareManager
        shadowAware = Shadow.extract(awareManager)
    }

    @After
    fun tearDown() {
        transport?.close()
        transport = null
    }

    private fun myFingerprint(): ByteArray {
        val fp = identity.getShortFingerprint()
        return byteArrayOf((fp[0].code and 0xFF).toByte(), (fp[1].code and 0xFF).toByte())
    }

    private fun newTransport(): WifiAwareTransport {
        val t = WifiAwareTransport(context, identity)
        transport = t
        return t
    }

    @Test
    fun initFailsWhenServiceUnavailable() {
        shadowAware.setAvailable(false)
        val recorder = Recorder()
        val t = newTransport()
        t.listener = recorder
        assertFalse(t.init(MeshRouter(myFingerprint())))
        assertTrue(recorder.errors.any { it.contains("unavailable") })
    }

    @Test
    fun initAttachesToAwareService() {
        shadowAware.setAvailable(true)
        shadowAware.setWifiAwareSession(
            ShadowWifiAwareManager.newWifiAwareSession(awareManager, Binder(), 1)
        )
        val t = newTransport()
        assertTrue(t.init(MeshRouter(myFingerprint())))
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue("aware session must be attached", Reflect.field(t, "awareSession") != null)
    }

    @Test
    fun passphraseDerivesDeterministicServiceName() {
        val t = newTransport()
        t.setPassphrase("aware-secret")
        val name = Reflect.field(t, "serviceName") as String
        val expectedHash = CryptoUtils.sha256("aware-secret".toByteArray())
        val expected = WifiAwareTransport.SERVICE_PREFIX +
            expectedHash.copyOfRange(0, 8).joinToString("") { "%02x".format(it) }
        assertEquals("service name must be derived from the passphrase", expected, name)

        val other = newTransport()
        other.setPassphrase("aware-secret")
        assertEquals(name, Reflect.field(other, "serviceName") as String)
    }

    @Test
    fun publishStartsDiscovery() {
        shadowAware.setAvailable(true)
        shadowAware.setWifiAwareSession(
            ShadowWifiAwareManager.newWifiAwareSession(awareManager, Binder(), 1)
        )
        shadowAware.setDiscoverySessionToPublish(
            ShadowWifiAwareManager.newPublishDiscoverySession(awareManager, 1, 1)
        )
        val recorder = Recorder()
        val t = newTransport()
        t.listener = recorder
        t.init(MeshRouter(myFingerprint()))
        t.setPassphrase("aware-secret")
        t.startPublish()

        shadowOf(Looper.getMainLooper()).idle()
        assertTrue("publish must start a discovery session", recorder.discoveryStarted)
        assertTrue(Reflect.field(t, "publishSession") != null)
    }

    @Test
    fun sendWithoutPeerReportsError() {
        shadowAware.setAvailable(true)
        shadowAware.setWifiAwareSession(
            ShadowWifiAwareManager.newWifiAwareSession(awareManager, Binder(), 1)
        )
        val recorder = Recorder()
        val t = newTransport()
        t.listener = recorder
        t.init(MeshRouter(myFingerprint()))
        t.setPassphrase("aware-secret")

        t.sendData("no-peer".toByteArray())
        assertTrue(recorder.errors.any { it.contains("No NAN session or peer") })
    }

    @Test
    fun reassemblesFragmentedMeshFrameFromPeer() {
        val router = MeshRouter(myFingerprint())
        val routerRecorder = RouterRecorder()
        router.setListener(routerRecorder)

        val t = newTransport()
        Reflect.set(t, "router", router)

        val payload = "nan-fragmented-payload".toByteArray()
        val frame = MeshFrame.create(
            MeshFrame.TYPE_DATA,
            byteArrayOf(0x55, 0x66),
            myFingerprint(),
            payload,
            3
        ).toBytes()

        val chunk = 255 - FragmentCodec.HEADER
        val fragments = FragmentCodec.fragment(fragMagic, 9, frame, chunk)
        for (fragment in fragments) {
            Reflect.call(t, "handleIncomingMessage", fragment)
        }

        assertEquals(1, routerRecorder.data.size)
        assertArrayEquals(payload, routerRecorder.data.first().first)
        assertArrayEquals(byteArrayOf(0x55, 0x66), routerRecorder.data.first().second)
    }
}