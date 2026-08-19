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
import com.covertcomm.app.security.SecurityGuard
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

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

    private val connectedDevices = ConcurrentHashMap<String, BluetoothGatt>()
    private val deviceFingerprints = ConcurrentHashMap<String, ByteArray>()

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
        private const val ADVERTISE_INTERVAL_MS = 300
        private const val SCAN_INTERVAL_MS = 10000
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
        val session = RendezvousProtocol.createSession(passphrase)
        rendezvousSession = session
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
            if (connectedDevices.isEmpty()) {
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
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_ULTRA_LOW)
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

            if (connectedDevices.containsKey(mac)) return

            val serviceData = result.scanRecord?.getServiceData(ParcelUuid(SERVICE_UUID))
            if (serviceData == null) return

            val parsed = RendezvousProtocol.parseAdvertiseData(serviceData) ?: return
            val session = rendezvousSession ?: return

            val remoteChallenge = RendezvousProtocol.computeRemoteChallenge(
                session.passphrase, parsed.first
            )

            if (remoteChallenge.contentEquals(parsed.second)) {
                listener?.onRendezvousMatched(mac)
                stopAdvertising()
                stopScanning()
                connectToDevice(device, parsed.first)
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

    private fun connectToDevice(device: BluetoothDevice, peerSalt: ByteArray) {
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
                            connectedDevices[mac] = g
                            listener?.onPeerConnected(mac)
                            try { g.discoverServices() } catch (_: Exception) {}
                            setPhyCoded(g)
                        }
                        BluetoothProfile.STATE_DISCONNECTED -> {
                            connectedDevices.remove(mac)
                            try { g.close() } catch (_: Exception) {}
                            listener?.onPeerDisconnected()
                        }
                    }
                }

                override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
                    val service = g.getService(SERVICE_UUID) ?: return
                    val charRx = service.getCharacteristic(CHAR_RX_UUID) ?: return
                    try { g.setCharacteristicNotification(charRx, true) } catch (_: Exception) {}
                    sendHandshakeOverGATT(g)
                }

                override fun onCharacteristicChanged(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
                    val data = characteristic.value ?: return
                    handleIncomingData(data, g.device.address)
                }
            }, BluetoothDevice.TRANSPORT_LE)
            connectedGatt = gatt
        } catch (e: Exception) {
            Log.e(TAG, "Connect failed", e)
            listener?.onTransportError("Connection failed: ${e.message}")
        }
    }

    private fun sendHandshakeOverGATT(gatt: BluetoothGatt) {
        val session = rendezvousSession ?: return
        val payload = RendezvousProtocol.generateAdvertiseData(session)
        val senderFP = identityManager.getShortFingerprint().substring(0, 2).toByteArray()
        val seqNum = router?.nextSeqNum() ?: 0
        val frame = MeshFrame.create(
            MeshFrame.TYPE_HANDSHAKE,
            senderFP,
            ByteArray(2),
            payload,
            seqNum
        )
        sendRawFrame(frame.toBytes())
        listener?.onHandshakeSent()
    }

    private fun setPhyCoded(gatt: BluetoothGatt) {
        if (Build.VERSION.SDK_INT >= 26) {
            try {
                gatt.setPreferredPhy(
                    BluetoothDevice.PHY_LE_CODED,
                    BluetoothDevice.PHY_LE_CODED,
                    BluetoothDevice.PHY_OPTION_S8
                )
            } catch (_: Exception) {}
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
            charTx.addDescriptor(BluetoothGattDescriptor(
                UUID.fromString("00002902-0000-1000-8000-00805f9b34fb"),
                BluetoothGattDescriptor.PERMISSION_WRITE
            ))
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
                    listener?.onPeerConnected(mac)
                    setServerPhyCoded(device)
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    listener?.onPeerDisconnected()
                }
            }
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
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, ByteArray(0))
            }
            handleIncomingData(value, device.address)
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            Log.d(TAG, "MTU changed: $mtu")
        }
    }

    private fun setServerPhyCoded(device: BluetoothDevice) {
        if (Build.VERSION.SDK_INT >= 26) {
            try {
                gattServer?.setPreferredPhy(
                    device,
                    BluetoothDevice.PHY_LE_CODED,
                    BluetoothDevice.PHY_LE_CODED,
                    BluetoothDevice.PHY_OPTION_S8
                )
            } catch (_: Exception) {}
        }
    }

    private fun handleIncomingData(data: ByteArray, fromAddress: String) {
        val frame = MeshFrame.parse(data)
        if (frame != null && router != null) {
            val peerAddrBytes = fromAddress.toByteArray()
            router!!.processIncomingFrame(frame, peerAddrBytes)
        } else {
            listener?.onMessageReceived(data, ByteArray(2))
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

    private fun sendRawFrame(frameBytes: ByteArray) {
        if (connectedGatt != null) {
            val service = connectedGatt!!.getService(SERVICE_UUID)
            val char = service?.getCharacteristic(CHAR_RX_UUID)
            if (char != null) {
                char.value = frameBytes
                connectedGatt!!.writeCharacteristic(char)
                return
            }
        }

        gattServer?.let { server ->
            for ((_, _) in connectedDevices) {
                val service = server.getService(SERVICE_UUID)
                val char = service?.getCharacteristic(CHAR_TX_UUID)
                if (char != null) {
                    char.value = frameBytes
                    server.notifyCharacteristicChanged(null, char, false)
                }
            }
        }
    }

    fun close() {
        isRunning = false
        stopAdvertising()
        stopScanning()

        for ((_, gatt) in connectedDevices) {
            try { gatt.disconnect(); gatt.close() } catch (_: Exception) {}
        }
        connectedDevices.clear()
        deviceFingerprints.clear()

        try { connectedGatt?.disconnect(); connectedGatt?.close() } catch (_: Exception) {}
        try { gattServer?.close() } catch (_: Exception) {}

        rendezvousSession?.let { RendezvousProtocol.wipeSession(it) }
        rendezvousSession = null
        pendingPassphrase = null
        router?.wipe()
    }
}