package com.covertcomm.app.mesh

import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.util.Log
import com.covertcomm.app.crypto.IdentityManager
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

class BLEMeshTransport(
    private val context: Context,
    private val identityManager: IdentityManager
) {
    private val TAG = "BLEMeshTransport"
    private val handler = Handler(Looper.getMainLooper())

    private var bluetoothManager: BluetoothManager? = null
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var scanner: BluetoothLeScanner? = null
    private var gattServer: BluetoothGattServer? = null
    private var connectedGatt: BluetoothGatt? = null
    private var isRunning = false
    private var isAdvertising = false
    private var isScanning = false

    private var router: MeshRouter? = null
    private var rendezvousSession: RendezvousProtocol.RendezvousSession? = null
    private var pendingPassphrase: String? = null

    private val clientGatts = ConcurrentHashMap<String, BluetoothGatt>()

    private val serverDevices = ConcurrentHashMap<String, BluetoothDevice>()

    @Volatile private var negotiatedMtu = 23

    private val msgIdGen = AtomicInteger(0)
    private val assembler = FragmentAssembler(MAX_FRAME)

    var listener: BLEMeshListener? = null

    interface BLEMeshListener {
        fun onPeerConnected(address: String)
        fun onPeerDisconnected()
        fun onMessageReceived(data: ByteArray, senderFP: ByteArray)
        fun onTransportError(error: String)
        fun onHandshakeSent()
        fun onRendezvousMatched(peerAddress: String)
        fun onRendezvousFailed(reason: String)
        fun onAdvertiseStarted()
    }

    companion object {
        val SERVICE_UUID: UUID = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef0123456789")
        val CHAR_TX_UUID: UUID = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef0123456790")
        val CHAR_RX_UUID: UUID = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef0123456791")
        val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        private const val FRAG_MAGIC: Byte = 0x7B
        private const val REQUESTED_MTU = 517
        private const val MAX_FRAME = 64 * 1024
    }

    fun init(router: MeshRouter): Boolean {
        this.router = router
        bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        bluetoothAdapter = bluetoothManager?.adapter

        if (bluetoothAdapter == null) {
            listener?.onTransportError("Bluetooth not supported on this device")
            return false
        }

        if (!bluetoothAdapter!!.isEnabled) {
            listener?.onTransportError("Bluetooth is OFF. Please enable Bluetooth first.")
            return false
        }

        advertiser = bluetoothAdapter?.bluetoothLeAdvertiser
        scanner = bluetoothAdapter?.bluetoothLeScanner

        if (advertiser == null) {
            listener?.onTransportError("BLE advertising not supported")
            return false
        }

        startGattServer()
        isRunning = true
        return true
    }

    fun isBleReady(): Boolean = isRunning && bluetoothAdapter?.isEnabled == true

    fun setRendezvousPassphrase(passphrase: String) {
        pendingPassphrase = passphrase
        rendezvousSession = RendezvousProtocol.createSession(passphrase)
    }

    fun startRendezvous() {
        val session = rendezvousSession
        if (session == null || !RendezvousProtocol.isWindowValid(session)) {
            listener?.onRendezvousFailed("No valid session")
            return
        }

        if (!isRunning || bluetoothAdapter == null || !bluetoothAdapter!!.isEnabled) {
            listener?.onRendezvousFailed("Bluetooth is OFF. Enable Bluetooth and retry.")
            return
        }

        startAdvertising(session)
        startScanning(session)

        handler.postDelayed({
            stopAdvertising()
            stopScanning()
            if (clientGatts.isEmpty() && serverDevices.isEmpty()) {
                listener?.onRendezvousFailed("Window expired")
            }
        }, 45000)
    }

    private fun startAdvertising(session: RendezvousProtocol.RendezvousSession) {
        if (advertiser == null) {
            listener?.onRendezvousFailed("BLE advertising not supported")
            return
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(true)
            .setTimeout(45000)
            .build()

        val data = AdvertiseData.Builder()
            .addServiceData(ParcelUuid(SERVICE_UUID), RendezvousProtocol.generateAdvertiseData(session))
            .setIncludeTxPowerLevel(false)
            .setIncludeDeviceName(false)
            .build()

        try {
            advertiser?.startAdvertising(settings, data, advertiseCallback)
            isAdvertising = true
            listener?.onAdvertiseStarted()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start advertising", e)
            listener?.onRendezvousFailed("Cannot start advertising")
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            Log.d(TAG, "Advertising started")
        }

        override fun onStartFailure(errorCode: Int) {
            Log.e(TAG, "Advertising failed: $errorCode")
            isAdvertising = false
            listener?.onRendezvousFailed("Advertise failed: $errorCode")
        }
    }

    private fun stopAdvertising() {
        if (isAdvertising) {
            try { advertiser?.stopAdvertising(advertiseCallback) } catch (_: Exception) {}
            isAdvertising = false
        }
    }

    private fun startScanning(session: RendezvousProtocol.RendezvousSession) {
        if (scanner == null) {
            listener?.onRendezvousFailed("BLE scanning not supported")
            return
        }

        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        val filter = ScanFilter.Builder()
            .setServiceData(ParcelUuid(SERVICE_UUID), ByteArray(0))
            .build()

        try {
            scanner?.startScan(listOf(filter), settings, scanCallback)
            isScanning = true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start scanning", e)
            listener?.onRendezvousFailed("Cannot start scanning")
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val device = result.device ?: return
            val mac = device.address

            if (clientGatts.containsKey(mac) || serverDevices.containsKey(mac)) return

            val serviceData = result.scanRecord?.getServiceData(ParcelUuid(SERVICE_UUID)) ?: return
            val parsed = RendezvousProtocol.parseAdvertiseData(serviceData) ?: return
            val session = rendezvousSession ?: return

            val remoteChallenge = RendezvousProtocol.computeRemoteChallenge(session.passphrase, parsed.first)

            if (remoteChallenge.contentEquals(parsed.second)) {
                listener?.onRendezvousMatched(mac)
                stopAdvertising()
                stopScanning()
                connectToDevice(device)
            }
        }

        override fun onScanFailed(errorCode: Int) {
            Log.e(TAG, "Scan failed: $errorCode")
            listener?.onTransportError("Scan failed: $errorCode")
        }
    }

    private fun stopScanning() {
        if (isScanning) {
            try { scanner?.stopScan(scanCallback) } catch (_: Exception) {}
            isScanning = false
        }
    }

    @Suppress("DEPRECATION")
    private fun connectToDevice(device: BluetoothDevice) {
        val mac = device.address
        val session = rendezvousSession ?: return

        if (!RendezvousProtocol.shouldAllowConnection(session, mac)) {
            listener?.onRendezvousFailed("Rate limited")
            return
        }

        try {
            val gatt = device.connectGatt(context, false, object : BluetoothGattCallback() {
                override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
                    when (newState) {
                        BluetoothProfile.STATE_CONNECTED -> {
                            clientGatts[mac] = g
                            listener?.onPeerConnected(mac)
                            try { g.requestMtu(REQUESTED_MTU) } catch (_: Exception) {}
                            try { g.discoverServices() } catch (_: Exception) {}
                        }
                        BluetoothProfile.STATE_DISCONNECTED -> {
                            clientGatts.remove(mac)
                            try { g.close() } catch (_: Exception) {}
                            if (clientGatts.isEmpty() && serverDevices.isEmpty()) listener?.onPeerDisconnected()
                        }
                    }
                }

                override fun onMtuChanged(g: BluetoothGatt, mtu: Int, status: Int) {
                    if (status == BluetoothGatt.GATT_SUCCESS) negotiatedMtu = mtu
                }

                override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
                    val service = g.getService(SERVICE_UUID) ?: return

                    val charTx = service.getCharacteristic(CHAR_TX_UUID) ?: return
                    try {
                        g.setCharacteristicNotification(charTx, true)
                        val cccd = charTx.getDescriptor(CCCD_UUID)
                        if (cccd != null) {
                            cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                            g.writeDescriptor(cccd)
                        }
                    } catch (_: Exception) {}
                }

                override fun onDescriptorWrite(g: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
                    if (descriptor.uuid == CCCD_UUID) {

                        listener?.onPeerConnected(g.device.address)
                    }
                }

                override fun onCharacteristicChanged(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
                    val data = characteristic.value ?: return
                    handleIncomingBytes(data)
                }
            }, BluetoothDevice.TRANSPORT_LE)
            connectedGatt = gatt
        } catch (e: Exception) {
            Log.e(TAG, "Connect failed", e)
            listener?.onTransportError("Connection failed: ${e.message}")
        }
    }

    private fun startGattServer() {
        try {
            val server = bluetoothManager?.openGattServer(context, gattServerCallback)
            gattServer = server

            val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
            val charTx = BluetoothGattCharacteristic(
                CHAR_TX_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                BluetoothGattCharacteristic.PERMISSION_READ
            )
            val charRx = BluetoothGattCharacteristic(
                CHAR_RX_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_WRITE
            )
            charTx.addDescriptor(
                BluetoothGattDescriptor(CCCD_UUID, BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE)
            )
            service.addCharacteristic(charTx)
            service.addCharacteristic(charRx)
            server?.addService(service)
        } catch (e: SecurityException) {
            Log.e(TAG, "GATT server start failed", e)
            listener?.onTransportError("BLE permission denied")
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    val mac = device.address
                    val session = rendezvousSession
                    if (session != null && !RendezvousProtocol.shouldAllowConnection(session, mac)) {
                        try { gattServer?.cancelConnection(device) } catch (_: Exception) {}
                        return
                    }
                    serverDevices[mac] = device
                    listener?.onPeerConnected(mac)
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    serverDevices.remove(device.address)
                    if (clientGatts.isEmpty() && serverDevices.isEmpty()) listener?.onPeerDisconnected()
                }
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            negotiatedMtu = mtu
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray
        ) {
            if (responseNeeded) {
                try {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, ByteArray(0))
                } catch (_: Exception) {}
            }
            handleIncomingBytes(value)
        }
    }

    @Suppress("DEPRECATION")
    private fun sendRawFrame(frameBytes: ByteArray) {
        val chunk = (negotiatedMtu - 3).coerceAtLeast(20)
        val msgId = msgIdGen.incrementAndGet() and 0xFFFF
        val fragments = try {
            FragmentCodec.fragment(FRAG_MAGIC, msgId, frameBytes, chunk)
        } catch (e: Exception) {
            listener?.onTransportError("Frame too large for BLE: ${frameBytes.size} bytes")
            return
        }
        for (f in fragments) writePacket(f)
    }

    @Suppress("DEPRECATION")
    private fun writePacket(packet: ByteArray) {

        val server = gattServer
        if (serverDevices.isNotEmpty() && server != null) {
            val service = server.getService(SERVICE_UUID)
            val char = service?.getCharacteristic(CHAR_TX_UUID)
            if (char != null) {
                for ((_, device) in serverDevices) {
                    try {
                        char.value = packet
                        server.notifyCharacteristicChanged(device, char, false)
                    } catch (e: Exception) {
                        Log.e(TAG, "notify failed", e)
                    }
                }
            }
            return
        }

        val gatt = connectedGatt
        if (gatt != null) {
            val service = gatt.getService(SERVICE_UUID)
            val char = service?.getCharacteristic(CHAR_RX_UUID)
            if (char != null) {
                try {
                    char.value = packet
                    char.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                    gatt.writeCharacteristic(char)
                } catch (e: Exception) {
                    Log.e(TAG, "write failed", e)
                }
            }
        }
    }

    private fun handleIncomingBytes(data: ByteArray) {
        val packet = FragmentCodec.decode(FRAG_MAGIC, data)
        if (packet == null) {

            handleAssembled(data)
            return
        }
        val full = assembler.offer(packet) ?: return
        handleAssembled(trimToFrame(full))
    }

    private fun trimToFrame(buffer: ByteArray): ByteArray {

        if (buffer.size < MeshFrame.HEADER_SIZE) return buffer
        val payloadLen = ((buffer[12].toInt() and 0xFF) shl 8) or (buffer[13].toInt() and 0xFF)
        val frameLen = MeshFrame.HEADER_SIZE + payloadLen + MeshFrame.HMAC_SIZE
        return if (frameLen in MeshFrame.HEADER_SIZE..buffer.size) buffer.copyOfRange(0, frameLen) else buffer
    }

    private fun handleAssembled(frameBytes: ByteArray) {
        val frame = MeshFrame.parse(frameBytes)
        if (frame != null && router != null) {
            router!!.processIncomingFrame(frame, ByteArray(2))
        } else {
            listener?.onMessageReceived(frameBytes, ByteArray(2))
        }
    }

    fun sendData(targetFP: ByteArray, payload: ByteArray) {
        val seqNum = router?.nextSeqNum() ?: 0
        val frame = MeshFrame.create(
            MeshFrame.TYPE_DATA,
            identityManager.getShortFingerprint().substring(0, 2).toByteArray(),
            targetFP,
            payload,
            seqNum
        )
        sendRawFrame(frame.toBytes())
    }

    fun sendHandshake(targetFP: ByteArray, payload: ByteArray) {
        val seqNum = router?.nextSeqNum() ?: 0
        val frame = MeshFrame.create(
            MeshFrame.TYPE_HANDSHAKE,
            identityManager.getShortFingerprint().substring(0, 2).toByteArray(),
            targetFP,
            payload,
            seqNum
        )
        sendRawFrame(frame.toBytes())
        listener?.onHandshakeSent()
    }

    fun close() {
        isRunning = false
        stopAdvertising()
        stopScanning()

        for ((_, gatt) in clientGatts) {
            try { gatt.disconnect(); gatt.close() } catch (_: Exception) {}
        }
        clientGatts.clear()
        serverDevices.clear()
        assembler.clear()

        try { connectedGatt?.disconnect(); connectedGatt?.close() } catch (_: Exception) {}
        try { gattServer?.close() } catch (_: Exception) {}

        rendezvousSession?.let { RendezvousProtocol.wipeSession(it) }
        rendezvousSession = null
        pendingPassphrase = null
    }
}