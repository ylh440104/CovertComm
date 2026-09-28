package com.covertcomm.app.transport

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbManager
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.covertcomm.app.crypto.IdentityManager
import com.covertcomm.app.mesh.MeshFrame
import com.covertcomm.app.mesh.MeshRouter
import com.covertcomm.app.security.SecurityGuard

class LoRaTransport(
    private val context: Context,
    private val identityManager: IdentityManager
) {
    private val TAG = "LoRaTransport"

    companion object {
        const val LORA_MAX_PACKET = 255
        // Payload available to the fragment codec inside one LoRa packet.
        const val LORA_MAX_PAYLOAD = LORA_MAX_PACKET - FragmentCodec.HEADER
        const val LORA_MAGIC: Byte = 0x7C
        const val LORA_BAUD = 9600
        const val FRAGMENT_TIMEOUT_MS = 30000L
        const val USB_PERMISSION = "com.covertcomm.app.USB_PERMISSION"

        val VENDOR_IDS = intArrayOf(0x1A86, 0x0403, 0x10C4, 0x067B, 0x2341)
    }

    private var usbManager: UsbManager? = null
    private var connection: UsbDeviceConnection? = null
    private var serialReader: SerialReader? = null
    private var connectedDevice: UsbDevice? = null
    private var isRunning = false
    private var router: MeshRouter? = null
    private val handler = Handler(Looper.getMainLooper())

    private val assembler = FragmentAssembler(maxFrame = 64 * 1024, timeoutMs = FRAGMENT_TIMEOUT_MS)

    var listener: LoRaListener? = null

    interface LoRaListener {
        fun onPeerConnected(address: String)
        fun onPeerDisconnected()
        fun onMessageReceived(data: ByteArray, senderFP: ByteArray)
        fun onTransportError(error: String)
        fun onHandshakeSent()
        fun onDeviceAttached(deviceName: String)
        fun onDeviceDetached()
        fun onReady()
    }

    fun init(router: MeshRouter): Boolean {
        this.router = router
        usbManager = context.getSystemService(Context.USB_SERVICE) as? UsbManager

        if (usbManager == null) {
            listener?.onTransportError("USB service unavailable")
            return false
        }

        registerUsbReceiver()
        tryConnect()
        return true
    }

    private fun registerUsbReceiver() {
        val filter = IntentFilter().apply {
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
            addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
            addAction(USB_PERMISSION)
        }
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(usbReceiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            context.registerReceiver(usbReceiver, filter)
        }
    }

    private fun tryConnect() {
        val manager = usbManager ?: return
        val deviceList = manager.deviceList
        var found: UsbDevice? = null

        for ((_, dev) in deviceList) {
            if (VENDOR_IDS.contains(dev.vendorId)) {
                found = dev
                break
            }
        }

        if (found == null) {
            listener?.onTransportError("No LoRa USB device found. Connect a USB-Serial LoRa module (e.g. SX1278 via CH340).")
            return
        }

        if (!manager.hasPermission(found)) {
            val pi = PendingIntent.getBroadcast(
                context, 0,
                Intent(USB_PERMISSION).setPackage(context.packageName),
                PendingIntent.FLAG_IMMUTABLE
            )
            manager.requestPermission(found, pi)
            listener?.onTransportError("Requesting USB permission for LoRa device...")
            return
        }

        connectDevice(found)
    }

    private fun connectDevice(device: UsbDevice) {
        val manager = usbManager ?: return
        connection = manager.openDevice(device)

        if (connection == null) {
            listener?.onTransportError("Cannot open USB device: ${device.deviceName}")
            return
        }

        val ok = setupSerial(connection!!, device)
        if (!ok) {
            listener?.onTransportError("Serial setup failed for: ${device.deviceName}")
            connection?.close()
            connection = null
            return
        }

        connectedDevice = device
        serialReader = SerialReader(connection!!, device) { data ->
            handleIncomingBytes(data)
        }
        serialReader?.start()

        isRunning = true
        listener?.onDeviceAttached(device.deviceName)
        sendConfigCommand()
        listener?.onReady()
    }

    private fun setupSerial(conn: UsbDeviceConnection, device: UsbDevice): Boolean {
        if (device.interfaceCount == 0) return false
        val iface = device.getInterface(0)
        if (!conn.claimInterface(iface, true)) return false

        if (iface.endpointCount < 2) return false

        var epOut: UsbEndpoint? = null
        var epIn: UsbEndpoint? = null
        for (i in 0 until iface.endpointCount) {
            val ep = iface.getEndpoint(i)
            if (ep.direction == UsbConstants.USB_DIR_OUT) {
                epOut = ep
            } else if (ep.direction == UsbConstants.USB_DIR_IN) {
                epIn = ep
            }
        }
        if (epOut == null) epOut = iface.getEndpoint(0)
        if (epIn == null && iface.endpointCount >= 2) epIn = iface.getEndpoint(1)
        if (epOut == null || epIn == null) return false

        val vendorId = device.vendorId

        when (vendorId) {
            VENDOR_IDS[0] -> {
                conn.controlTransfer(UsbConstants.USB_TYPE_VENDOR or 0x40, 0xA1, 0x00C2, 0, null, 0, 0)
                conn.controlTransfer(UsbConstants.USB_TYPE_VENDOR or 0x40, 0x9604, 0, 0, null, 0, 0)
                conn.controlTransfer(UsbConstants.USB_TYPE_VENDOR or 0x40, 0x0306, 0, 0, null, 0, 0)
            }
            VENDOR_IDS[1] -> {
                val baudRate = LORA_BAUD
                val divisor = (48000000 / (16 * baudRate)).toShort()
                conn.controlTransfer(UsbConstants.USB_TYPE_VENDOR or 0x40, 0, 0x0403, 0, null, 0, 0)
                conn.controlTransfer(UsbConstants.USB_TYPE_VENDOR or 0x40, 0x03, divisor.toInt(), 0, null, 0, 0)
                conn.controlTransfer(UsbConstants.USB_TYPE_VENDOR or 0x40, 0x04, 0x03, 0, null, 0, 0)
            }
        }

        return true
    }

    private fun sendConfigCommand() {
        val cmd = buildATConfig(868100000, 125, 12, 15, 8, 4)
        serialWrite(cmd)
    }

    private fun buildATConfig(freq: Long, sf: Int, bw: Int, txPower: Int, cr: Int, preamble: Int): ByteArray {
        val sb = StringBuilder()
        sb.append("AT+FREQ=$freq\r\n")
        sb.append("AT+SF=$sf\r\n")
        sb.append("AT+BW=$bw\r\n")
        sb.append("AT+TP=$txPower\r\n")
        sb.append("AT+CR=$cr\r\n")
        sb.append("AT+PRE=$preamble\r\n")
        sb.append("AT+MODE=0\r\n")
        return sb.toString().toByteArray()
    }

    private fun serialWrite(data: ByteArray) {
        val conn = connection ?: return
        val dev = connectedDevice ?: return
        if (dev.interfaceCount == 0) return
        val iface = dev.getInterface(0)
        val epOut = iface.getEndpoint(0)
        conn.bulkTransfer(epOut, data, data.size, 1000)
    }

    private fun handleIncomingBytes(data: ByteArray) {
        if (data.size > LORA_MAX_PACKET) {
            processMultipleFragments(data)
        } else {
            processSinglePacket(data)
        }
    }

    private fun processMultipleFragments(data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            if (offset + LORA_MAX_PACKET > data.size) {
                processSinglePacket(data.copyOfRange(offset, data.size))
                break
            }
            processSinglePacket(data.copyOfRange(offset, offset + LORA_MAX_PACKET))
            offset += LORA_MAX_PACKET
        }
    }

    private fun processSinglePacket(packet: ByteArray) {
        val decoded = FragmentCodec.decode(LORA_MAGIC, packet) ?: return
        val full = assembler.offer(decoded) ?: return
        handleAssembledFrameComplete(full)
    }

    private fun handleAssembledFrameComplete(frameBytes: ByteArray) {
        val frame = MeshFrame.parse(frameBytes)
        if (frame != null && router != null) {
            router!!.processIncomingFrame(frame, ByteArray(2))
        } else {
            listener?.onMessageReceived(frameBytes, ByteArray(2))
        }
    }

    fun sendData(targetFP: ByteArray, data: ByteArray) {
        val seqNum = router?.nextSeqNum() ?: 0
        val frame = MeshFrame.create(
            MeshFrame.TYPE_DATA,
            identityManager.getShortFingerprint().substring(0, 2).toByteArray(),
            targetFP,
            data,
            seqNum
        )
        sendFrame(frame.toBytes())
    }

    fun sendHandshake(targetFP: ByteArray, data: ByteArray) {
        val seqNum = router?.nextSeqNum() ?: 0
        val frame = MeshFrame.create(
            MeshFrame.TYPE_HANDSHAKE,
            identityManager.getShortFingerprint().substring(0, 2).toByteArray(),
            targetFP,
            data,
            seqNum
        )
        sendFrame(frame.toBytes())
        listener?.onHandshakeSent()
    }

    private fun sendFrame(frameBytes: ByteArray) {
        // The 8-byte fragment header must fit inside a single LoRa packet.
        val chunk = LORA_MAX_PAYLOAD
        val msgId = (SecurityGuard.secureRandomBytes(1)[0].toInt() and 0xFF)
        val fragments = try {
            FragmentCodec.fragment(LORA_MAGIC, msgId, frameBytes, chunk)
        } catch (e: Exception) {
            listener?.onTransportError("Frame too large for LoRa: ${frameBytes.size} bytes")
            return
        }
        for ((i, f) in fragments.withIndex()) {
            sendLoRaPacket(f)
            // Give the radio time to drain before the next fragment.
            try {
                Thread.sleep(if (fragments.size > 10) 2000L else 500L)
            } catch (_: InterruptedException) {}
        }
    }

    private fun sendLoRaPacket(packet: ByteArray) {
        val atCmd = "AT+SEND=${packet.size}\r\n"
        serialWrite(atCmd.toByteArray())
        try { Thread.sleep(50) } catch (_: InterruptedException) {}
        serialWrite(packet)
    }

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context?, intent: Intent?) {
            when (intent?.action) {
                UsbManager.ACTION_USB_DEVICE_ATTACHED -> {
                    val dev = intent.getParcelableExtra<UsbDevice>(UsbManager.EXTRA_DEVICE)
                    if (dev != null && VENDOR_IDS.contains(dev.vendorId)) {
                        tryConnect()
                    }
                }
                UsbManager.ACTION_USB_DEVICE_DETACHED -> {
                    val dev = intent.getParcelableExtra<UsbDevice>(UsbManager.EXTRA_DEVICE)
                    if (dev != null && dev == connectedDevice) {
                        disconnect()
                        listener?.onDeviceDetached()
                    }
                }
                USB_PERMISSION -> {
                    val granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)
                    if (granted) {
                        tryConnect()
                    } else {
                        listener?.onTransportError("USB permission denied for LoRa device")
                    }
                }
            }
        }
    }

    private fun disconnect() {
        isRunning = false
        serialReader?.stop()
        serialReader = null
        connection?.close()
        connection = null
        connectedDevice = null
        assembler.clear()
    }

    fun close() {
        disconnect()
        try { context.unregisterReceiver(usbReceiver) } catch (_: Exception) {}
        router?.wipe()
    }

    private class SerialReader(
        private val connection: UsbDeviceConnection,
        private val device: UsbDevice,
        private val onData: (ByteArray) -> Unit
    ) {
        @Volatile private var running = false
        private var thread: Thread? = null
        private var epIn: android.hardware.usb.UsbEndpoint? = null

        fun start() {
            if (device.interfaceCount == 0) return
            val iface = device.getInterface(0)
            for (i in 0 until iface.endpointCount) {
                val ep = iface.getEndpoint(i)
                if (ep.direction == android.hardware.usb.UsbConstants.USB_DIR_IN) {
                    epIn = ep
                    break
                }
            }
            if (epIn == null && iface.endpointCount >= 2) {
                epIn = iface.getEndpoint(1)
            }

            running = true
            thread = Thread {
                val buffer = ByteArray(512)
                val ep = epIn ?: return@Thread
                while (running) {
                    try {
                        val len = connection.bulkTransfer(ep, buffer, buffer.size, 500)
                        if (len > 0) {
                            onData(buffer.copyOfRange(0, len))
                        }
                    } catch (_: Exception) {
                        break
                    }
                }
            }.apply {
                isDaemon = true
                name = "LoRaSerialReader"
                start()
            }
        }

        fun stop() {
            running = false
            thread?.interrupt()
            thread = null
        }
    }
}
