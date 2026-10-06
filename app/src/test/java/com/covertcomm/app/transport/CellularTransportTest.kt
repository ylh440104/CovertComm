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
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class CellularTransportTest {

    private lateinit var broker: FakeMqttBroker
    private lateinit var context: Context
    private lateinit var identity: IdentityManager
    private val transports = mutableListOf<CellularTransport>()

    private class Recorder : CellularTransport.CellularListener {
        val messages = CopyOnWriteArrayList<ByteArray>()
        val errors = CopyOnWriteArrayList<String>()
        val latch = CountDownLatch(1)
        @Volatile var connected = false
        @Volatile var joined = false

        override fun onConnected(address: String) { connected = true }
        override fun onDisconnected() {}
        override fun onMessageReceived(data: ByteArray, senderFP: ByteArray) {
            messages.add(data)
            latch.countDown()
        }
        override fun onTransportError(error: String) { errors.add(error) }
        override fun onHandshakeSent() {}
        override fun onJoined(sessionId: String) { joined = true }
        override fun onJoinFailed(reason: String) { errors.add(reason) }
        override fun onPeerJoined(peerId: String) {}
    }

    private fun newTransport(passphrase: String, recorder: Recorder): CellularTransport {
        val t = CellularTransport(context, identity)
        t.listener = recorder
        t.setCustomBroker("127.0.0.1", broker.port)
        t.setPassphrase(passphrase)
        transports.add(t)
        return t
    }

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        identity = IdentityManager(context)
        broker = FakeMqttBroker()
    }

    @After
    fun tearDown() {
        for (t in transports) t.close()
        transports.clear()
        broker.close()
    }

    @Test
    fun connectsAndSubscribesToDerivedTopic() {
        val recorder = Recorder()
        val t = newTransport("shared-secret", recorder)
        assertTrue("init must succeed with passphrase set", t.init())
        t.start()

        assertTrue("broker must see the client connect", broker.awaitClientCount(1, 5000))
        assertTrue("client must report connected", waitFor { recorder.connected })
        assertTrue("client must report channel joined", waitFor { recorder.joined })
    }

    @Test
    fun sendsEncryptedFrameAndReceivesPeerFrame() {
        val recorder = Recorder()
        val t = newTransport("shared-secret", recorder)
        t.init()
        t.start()
        assertTrue(broker.awaitClientCount(1, 5000))
        assertTrue(waitFor { recorder.connected })

        val outgoing = "hello-cellular".toByteArray()
        t.sendData(outgoing)
        assertTrue("broker must receive the published frame", broker.awaitPublicationCount(1, 5000))

        val ciphertext = broker.publishedPayloads().first()
        assertTrue("published payload must not be plaintext", !String(ciphertext).contains("hello-cellular"))

        val second = Recorder()
        val peer = newTransport("shared-secret", second)
        peer.init()
        peer.start()
        assertTrue(broker.awaitClientCount(2, 5000))
        assertTrue(waitFor { second.connected })

        broker.push(brokerTopic(), ciphertext)

        assertTrue("peer must decrypt the frame", second.latch.await(8, TimeUnit.SECONDS))
        assertArrayEquals(outgoing, second.messages.first())
    }

    @Test
    fun differentPassphraseCannotDecrypt() {
        val recorder = Recorder()
        val t = newTransport("shared-secret", recorder)
        t.init()
        t.start()
        assertTrue(broker.awaitClientCount(1, 5000))
        assertTrue(waitFor { recorder.connected })

        t.sendData("top-secret".toByteArray())
        assertTrue(broker.awaitPublicationCount(1, 5000))
        val ciphertext = broker.publishedPayloads().first()

        val wrongRecorder = Recorder()
        val wrong = newTransport("other-secret", wrongRecorder)
        wrong.init()
        wrong.start()
        assertTrue(broker.awaitClientCount(2, 5000))

        broker.push(brokerTopic("other-secret"), ciphertext)
        Thread.sleep(1500)
        assertTrue("wrong passphrase must not decrypt", wrongRecorder.messages.isEmpty())
    }

    private fun brokerTopic(passphrase: String = "shared-secret"): String {
        val h = com.covertcomm.app.crypto.CryptoUtils.sha256(("cc-session:" + passphrase).toByteArray())
        return "cc/" + h.copyOfRange(0, 6).joinToString("") { "%02x".format(it) }
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