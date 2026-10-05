package com.covertcomm.app.transport

import android.content.Context
import android.hardware.usb.UsbConfiguration
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import androidx.test.core.app.ApplicationProvider
import com.covertcomm.app.crypto.IdentityManager
import com.covertcomm.app.mesh.FragmentCodec
import com.covertcomm.app.mesh.MeshFrame
import com.covertcomm.app.mesh.MeshRouter
import com.covertcomm.app.testutil.Reflect
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadow.api.Shadow
import org.robolectric.shadows.ShadowUsbDeviceConnection
import org.robolectric.shadows.ShadowUsbManager
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.concurrent.CopyOnWriteArrayList

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class LoRaTransportTest {

    private lateinit var context: Context
    private lateinit var identity: IdentityManager
    private lateinit var usbManager: UsbManager
    private lateinit var shadowUsb: ShadowUsbManager
    private var transport: LoRaTransport? = null
    private var device: UsbDevice? = null

    private val loraMagic: Byte = 0x7C

    private class Recorder : LoRaTransport.LoRaListener {
        val errors = CopyOnWriteArrayList<String>()
        val messages = CopyOnWriteArrayList<Pair<ByteArray, ByteArray>>()
        val devices = CopyOnWriteArrayList<String>()
        @Volatile var ready = false
        override fun onPeerConnected(address: String) {}
        override fun onPeerDisconnected() {}
        override fun onMessageReceived(data: ByteArray, senderFP: ByteArray) { messages.add(data to senderFP) }
        override fun onTransportError(error: String) { errors.add(error) }
        override fun onHandshakeSent() {}
        override fun onDeviceAttached(deviceName: String) { devices.add(deviceName) }
        override fun onDeviceDetached() {}
        override fun onReady() { ready = true }
    }

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        identity = IdentityManager(context)
        usbManager = context.getSystemService(Context.USB_SERVICE) as UsbManager
        shadowUsb = Shadow.extract(usbManager)
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

    private fun buildEndpoint(direction: Int): UsbEndpoint {
        val ep = ReflectionHelpersNewInstance(UsbEndpoint::class.java)
        Reflect.set(ep, "mAddress", if (direction == UsbConstants.USB_DIR_IN) 0x81 else 0x01)
        Reflect.set(ep, "mAttributes", UsbConstants.USB_ENDPOINT_XFER_BULK)
        Reflect.set(ep, "mMaxPacketSize", 64)
        Reflect.set(ep, "mInterval", 0)
        return ep
    }

    private fun ReflectionHelpersNewInstance(cls: Class<*>): Any {
        val ctor = cls.getDeclaredConstructor()
        ctor.isAccessible = true
        return ctor.newInstance()
    }

    private fun buildLoraDevice(): UsbDevice {
        val epOut = buildEndpoint(UsbConstants.USB_DIR_OUT)
        val epIn = buildEndpoint(UsbConstants.USB_DIR_IN)

        val iface = ReflectionHelpersNewInstance(UsbInterface::class.java)
        Reflect.set(iface, "mId", 0)
        Reflect.set(iface, "mAlternateSetting", 0)
        Reflect.set(iface, "mName", "LoRa")
        Reflect.set(iface, "mClass", UsbConstants.USB_CLASS_CDC_DATA)
        Reflect.set(iface, "mSubclass", 0)
        Reflect.set(iface, "mProtocol", 0)
        Reflect.set(iface, "mEndpoints", arrayOf(epOut, epIn))

        val config = ReflectionHelpersNewInstance(UsbConfiguration::class.java)
        Reflect.set(config, "mId", 1)
        Reflect.set(config, "mName", "config")
        Reflect.set(config, "mAttributes", 0x80)
        Reflect.set(config, "mMaxPower", 100)
        Reflect.set(config, "mInterfaces", arrayOf(iface))

        val dev = ReflectionHelpersNewInstance(UsbDevice::class.java)
        Reflect.set(dev, "mName", "/dev/bus/usb/001/002")
        Reflect.set(dev, "mVendorId", 0x1A86)
        Reflect.set(dev, "mProductId", 0x7523)
        Reflect.set(dev, "mClass", 0)
        Reflect.set(dev, "mSubclass", 0)
        Reflect.set(dev, "mProtocol", 0)
        Reflect.set(dev, "mManufacturerName", "QinHeng")
        Reflect.set(dev, "mProductName", "USB Serial")
        Reflect.set(dev, "mVersion", "1.0")
        Reflect.set(dev, "mConfigurations", arrayOf(config))
        return dev
    }

    @Test
    fun initWithoutDeviceReportsError() {
        val recorder = Recorder()
        val t = LoRaTransport(context, identity)
        transport = t
        t.listener = recorder
        assertTrue("init must succeed even with no module attached", t.init(MeshRouter(myFingerprint())))
        assertTrue(recorder.errors.any { it.contains("No LoRa USB device found") })
    }

    @Test
    fun attachedModuleIsOpenedAndConfigured() {
        val dev = buildLoraDevice()
        device = dev
        shadowUsb.addOrUpdateUsbDevice(dev, true)

        val recorder = Recorder()
        val t = LoRaTransport(context, identity)
        transport = t
        t.listener = recorder
        t.init(MeshRouter(myFingerprint()))

        assertTrue("device must be reported as attached", recorder.devices.any { it.contains("bus/usb") })
        assertTrue("transport must become ready", recorder.ready)

        val connection = Reflect.field(t, "connection") as? UsbDeviceConnection
        assertTrue(connection != null)
        val shadowConn = Shadow.extract<ShadowUsbDeviceConnection>(connection)
        val written = readAll(shadowConn.outgoingDataStream)
        val text = String(written, Charsets.UTF_8)
        assertTrue("AT configuration must be sent to the module", text.contains("AT+FREQ=868100000"))
        assertTrue(text.contains("AT+SF=12"))
        assertTrue(text.contains("AT+CR=8"))
    }

    @Test
    fun incomingFragmentIsReassembledIntoMeshFrame() {
        val dev = buildLoraDevice()
        shadowUsb.addOrUpdateUsbDevice(dev, true)

        val router = MeshRouter(myFingerprint())
        val received = CopyOnWriteArrayList<Pair<ByteArray, ByteArray>>()
        router.setListener(object : MeshRouter.RouterListener {
            override fun onFrameReady(frame: ByteArray, nextHop: ByteArray?) {}
            override fun onDataReceived(payload: ByteArray, senderFP: ByteArray) { received.add(payload to senderFP) }
            override fun onRouteEstablished(targetFP: ByteArray) {}
            override fun onRouteRequest(targetFP: ByteArray) {}
        })

        val t = LoRaTransport(context, identity)
        transport = t
        t.listener = Recorder()
        t.init(router)

        val payload = "lora-fragmented".toByteArray()
        val frame = MeshFrame.create(
            MeshFrame.TYPE_DATA,
            byteArrayOf(0x77, 0x88),
            myFingerprint(),
            payload,
            5
        ).toBytes()
        val fragments = FragmentCodec.fragment(loraMagic, 11, frame, LoRaTransport.LORA_MAX_PAYLOAD)
        assertTrue("frame must be fragmented for the 247-byte payload limit", fragments.size > 1)

        for (fragment in fragments) {
            Reflect.call(t, "handleIncomingBytes", fragment)
        }

        assertEquals(1, received.size)
        assertArrayEquals(payload, received.first().first)
        assertArrayEquals(byteArrayOf(0x77, 0x88), received.first().second)
    }

    @Test
    fun oversizedPacketIsSplitIntoMaxPackets() {
        val dev = buildLoraDevice()
        shadowUsb.addOrUpdateUsbDevice(dev, true)

        val router = MeshRouter(myFingerprint())
        val received = CopyOnWriteArrayList<ByteArray>()
        router.setListener(object : MeshRouter.RouterListener {
            override fun onFrameReady(frame: ByteArray, nextHop: ByteArray?) {}
            override fun onDataReceived(payload: ByteArray, senderFP: ByteArray) { received.add(payload) }
            override fun onRouteEstablished(targetFP: ByteArray) {}
            override fun onRouteRequest(targetFP: ByteArray) {}
        })

        val t = LoRaTransport(context, identity)
        transport = t
        t.listener = Recorder()
        t.init(router)

        val payload = ByteArray(200) { (it % 251).toByte() }
        val frame = MeshFrame.create(MeshFrame.TYPE_DATA, byteArrayOf(0x01, 0x02), myFingerprint(), payload, 1).toBytes()
        val fragment = FragmentCodec.fragment(loraMagic, 12, frame, LoRaTransport.LORA_MAX_PAYLOAD).first()

        val concatenated = ByteArray(fragment.size * 2)
        System.arraycopy(fragment, 0, concatenated, 0, fragment.size)
        System.arraycopy(fragment, 0, concatenated, fragment.size, fragment.size)

        Reflect.call(t, "handleIncomingBytes", concatenated)
        assertEquals("duplicated fragment must still assemble exactly one frame", 1, received.size)
    }

    private fun readAll(stream: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (true) {
            val read = stream.read(buffer)
            if (read <= 0) break
            out.write(buffer, 0, read)
            if (read < buffer.size) break
        }
        return out.toByteArray()
    }
}