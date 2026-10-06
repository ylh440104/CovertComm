package com.covertcomm.app.mesh

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.covertcomm.app.crypto.IdentityManager
import com.covertcomm.app.testutil.Reflect
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadow.api.Shadow
import org.robolectric.shadows.ShadowBluetoothAdapter
import org.robolectric.shadows.ShadowBluetoothDevice
import org.robolectric.shadows.ShadowBluetoothGatt
import org.robolectric.shadows.ShadowBluetoothGattServer
import org.robolectric.util.ReflectionHelpers
import java.util.concurrent.CopyOnWriteArrayList

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class BleMeshTransportTest {

    private lateinit var context: Context
    private lateinit var identity: IdentityManager
    private lateinit var adapter: android.bluetooth.BluetoothAdapter
    private var transport: BLEMeshTransport? = null
    private val fragMagic: Byte = 0x7B

    private class RouterRecorder : MeshRouter.RouterListener {
        val data = CopyOnWriteArrayList<Pair<ByteArray, ByteArray>>()
        val frames = CopyOnWriteArrayList<ByteArray>()
        override fun onFrameReady(frame: ByteArray, nextHop: ByteArray?) { frames.add(frame) }
        override fun onDataReceived(payload: ByteArray, senderFP: ByteArray) { data.add(payload to senderFP) }
        override fun onRouteEstablished(targetFP: ByteArray) {}
        override fun onRouteRequest(targetFP: ByteArray) {}
    }

    private class LinkRecorder : BLEMeshTransport.BLEMeshListener {
        val messages = CopyOnWriteArrayList<ByteArray>()
        val errors = CopyOnWriteArrayList<String>()
        val connected = CopyOnWriteArrayList<String>()
        override fun onPeerConnected(address: String) { connected.add(address) }
        override fun onPeerDisconnected() {}
        override fun onMessageReceived(data: ByteArray, senderFP: ByteArray) { messages.add(data) }
        override fun onTransportError(error: String) { errors.add(error) }
        override fun onHandshakeSent() {}
        override fun onRendezvousMatched(peerAddress: String) {}
        override fun onRendezvousFailed(reason: String) { errors.add(reason) }
        override fun onAdvertiseStarted() {}
    }

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        identity = IdentityManager(context)
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        adapter = manager.adapter
        adapter.enable()
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

    private fun newTransport(): BLEMeshTransport {
        val t = BLEMeshTransport(context, identity)
        transport = t
        return t
    }

    private fun startGattServerWithoutInit(t: BLEMeshTransport, router: MeshRouter) {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        Reflect.set(t, "bluetoothManager", manager)
        Reflect.call(t, "startGattServer")
        Reflect.set(t, "router", router)
        Reflect.set(t, "isRunning", true)
    }

    @Test
    fun initFailsWhenBluetoothDisabled() {
        adapter.disable()
        val recorder = LinkRecorder()
        val t = newTransport()
        t.listener = recorder
        assertFalse("init must fail when Bluetooth is off", t.init(MeshRouter(myFingerprint())))
        assertTrue(recorder.errors.any { it.contains("Bluetooth is OFF") })
    }

    @Test
    fun initFailsWhenBluetoothUnsupported() {
        ShadowBluetoothAdapter.setIsBluetoothSupported(false)
        val recorder = LinkRecorder()
        val t = newTransport()
        t.listener = recorder
        assertFalse("init must fail when Bluetooth is unavailable", t.init(MeshRouter(myFingerprint())))
        assertTrue(recorder.errors.any { it.contains("Bluetooth not supported") })
    }

    @Test
    fun initSucceedsAndRegistersGattService() {
        adapter.enable()
        val advertiser = ReflectionHelpers.newInstance(BluetoothLeAdvertiser::class.java)
        shadowOf(adapter).setBluetoothLeAdvertiser(advertiser)
        val recorder = LinkRecorder()
        val t = newTransport()
        t.listener = recorder
        assertTrue("init must succeed with advertiser available", t.init(MeshRouter(myFingerprint())))

        val server = Reflect.field(t, "gattServer") as? BluetoothGattServer
        assertNotNull("GATT server must be opened", server)
        val service = server!!.getService(BLEMeshTransport.SERVICE_UUID)
        assertNotNull("GATT service must be registered", service)
        assertNotNull("TX characteristic must exist", service!!.getCharacteristic(BLEMeshTransport.CHAR_TX_UUID))
        assertNotNull("RX characteristic must exist", service.getCharacteristic(BLEMeshTransport.CHAR_RX_UUID))
        assertNotNull(
            "CCCD descriptor must be attached to TX",
            service.getCharacteristic(BLEMeshTransport.CHAR_TX_UUID)!!.getDescriptor(BLEMeshTransport.CCCD_UUID)
        )
    }

    @Test
    fun reassemblesFragmentedFrameFromPeer() {
        val router = MeshRouter(myFingerprint())
        val routerRecorder = RouterRecorder()
        router.setListener(routerRecorder)

        val t = newTransport()
        startGattServerWithoutInit(t, router)

        val server = Reflect.field(t, "gattServer") as BluetoothGattServer
        val shadowServer = Shadow.extract<ShadowBluetoothGattServer>(server)
        val rx = server.getService(BLEMeshTransport.SERVICE_UUID)!!
            .getCharacteristic(BLEMeshTransport.CHAR_RX_UUID)!!

        val payload = "fragmented-ble-payload".toByteArray()
        val frame = MeshFrame.create(
            MeshFrame.TYPE_DATA,
            byteArrayOf(0x11, 0x22),
            myFingerprint(),
            payload,
            7
        ).toBytes()

        val fragments = FragmentCodec.fragment(fragMagic, 42, frame, 20)
        assertTrue("payload must be split into multiple fragments", fragments.size > 1)

        val device = ShadowBluetoothDevice.newInstance("AA:BB:CC:DD:EE:FF")
        for ((index, fragment) in fragments.withIndex()) {
            val accepted = shadowServer.notifyOnCharacteristicWriteRequest(
                device, index + 1, rx, false, false, 0, fragment
            )
            assertTrue("write request must be accepted", accepted)
        }

        assertEquals("assembled frame must reach the router once", 1, routerRecorder.data.size)
        assertArrayEquals(payload, routerRecorder.data.first().first)
        assertArrayEquals(byteArrayOf(0x11, 0x22), routerRecorder.data.first().second)
        assertTrue("router must emit an ACK frame", routerRecorder.frames.isNotEmpty())
    }

    @Test
    fun sendDataFragmentsReassembleToOriginalFrame() {
        val t = newTransport()
        Reflect.set(t, "isRunning", true)

        val device = ShadowBluetoothDevice.newInstance("11:22:33:44:55:66")
        val gatt = ShadowBluetoothGatt.newInstance(device)
        val shadowGatt = Shadow.extract<ShadowBluetoothGatt>(gatt)

        val service = BluetoothGattService(BLEMeshTransport.SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        service.addCharacteristic(
            BluetoothGattCharacteristic(
                BLEMeshTransport.CHAR_RX_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_WRITE
            )
        )
        shadowGatt.addDiscoverableService(service)

        val captured = CopyOnWriteArrayList<ByteArray>()
        shadowGatt.setGattCallback(object : BluetoothGattCallback() {
            override fun onCharacteristicWrite(
                g: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int
            ) {
                captured.add(characteristic.value.copyOf())
            }
        })
        gatt.discoverServices()

        Reflect.set(t, "connectedGatt", gatt)

        val payload = "outgoing-ble-payload".toByteArray()
        t.sendData(byteArrayOf(0x33, 0x44), payload)

        assertTrue("fragments must be written to the peer", captured.isNotEmpty())

        val assembler = FragmentAssembler()
        var assembled: ByteArray? = null
        for (bytes in captured) {
            val packet = FragmentCodec.decode(fragMagic, bytes)
            assertNotNull("each written packet must be a valid fragment", packet)
            val full = assembler.offer(packet!!)
            if (full != null) assembled = full
        }
        assertNotNull("all fragments must reassemble", assembled)

        val frame = MeshFrame.parse(assembled!!)
        assertNotNull("reassembled bytes must be a valid MeshFrame", frame)
        assertArrayEquals(payload, frame!!.payload)
        assertArrayEquals(byteArrayOf(0x33, 0x44), frame.targetFP)
    }

    @Test
    fun mtuNegotiationChangesFragmentSize() {
        val t = newTransport()
        Reflect.set(t, "isRunning", true)

        val device = ShadowBluetoothDevice.newInstance("77:88:99:AA:BB:CC")
        val gatt = ShadowBluetoothGatt.newInstance(device)
        val shadowGatt = Shadow.extract<ShadowBluetoothGatt>(gatt)

        val service = BluetoothGattService(BLEMeshTransport.SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        service.addCharacteristic(
            BluetoothGattCharacteristic(
                BLEMeshTransport.CHAR_RX_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_WRITE
            )
        )
        shadowGatt.addDiscoverableService(service)

        val captured = CopyOnWriteArrayList<ByteArray>()
        shadowGatt.setGattCallback(object : BluetoothGattCallback() {
            override fun onCharacteristicWrite(
                g: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int
            ) {
                captured.add(characteristic.value.copyOf())
            }
        })
        gatt.discoverServices()
        Reflect.set(t, "connectedGatt", gatt)

        val serverCallback = Reflect.field(t, "gattServerCallback")!!
        Reflect.call(serverCallback, "onMtuChanged", device, 247)

        val payload = ByteArray(600) { (it % 251).toByte() }
        t.sendData(byteArrayOf(0x01, 0x02), payload)

        assertTrue(captured.isNotEmpty())
        val packet = FragmentCodec.decode(fragMagic, captured.first())!!
        assertEquals("fragment step must follow the negotiated MTU", 244, packet.chunk)
        assertTrue("600 bytes must require at least 3 fragments", captured.size >= 3)
    }
}