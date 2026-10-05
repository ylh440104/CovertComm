package com.covertcomm.app

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Context
import android.net.wifi.WifiManager
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowBluetoothAdapter

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SmokeTest {
    @Test
    fun frameworkShadowsAreAvailable() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        assertNotNull(ctx)
        val bm = ctx.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val adapter = bm.adapter
        assertNotNull(adapter)
        ShadowBluetoothAdapter.setEnabled(true)
        org.junit.Assert.assertEquals(true, adapter.isEnabled)
        val wifi = ctx.getSystemService(Context.WIFI_SERVICE) as WifiManager
        assertNotNull(wifi)
        val p2p = ctx.getSystemService(Context.WIFI_P2P_SERVICE) as WifiP2pManager
        assertNotNull(p2p)
        org.junit.Assert.assertTrue(Build.VERSION.SDK_INT >= 26)
    }
}
