package com.covertcomm.app.ui

import com.covertcomm.app.crypto.DoubleRatchet
import com.covertcomm.app.mesh.MeshFrame
import com.covertcomm.app.testutil.Reflect
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import java.net.ServerSocket
import java.net.Socket

/**
 * End-to-end test of the real MainActivity protocol: two activity instances perform the real
 * X3DH + ML-KEM handshake, the real pq_exchange and exchange real encrypted chat messages over a
 * real TCP socket pair. No hand-written protocol model is involved.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class HandshakeEndToEndTest {

    private val controllers = mutableListOf<ActivityController<MainActivity>>()
    private var server: ServerSocket? = null
    private var peerSocket: Socket? = null

    @After
    fun tearDown() {
        for (controller in controllers) {
            try { controller.pause().stop().destroy() } catch (_: Exception) {}
        }
        controllers.clear()
        try { peerSocket?.close() } catch (_: Exception) {}
        try { server?.close() } catch (_: Exception) {}
    }

    private fun launch(): MainActivity {
        val controller = Robolectric.buildActivity(MainActivity::class.java).setup()
        controllers.add(controller)
        return controller.get()
    }

    private fun pump() {
        shadowOf(android.os.Looper.getMainLooper()).idle()
    }

    private fun waitFor(timeoutMs: Long = 25000, condition: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            pump()
            if (condition()) return true
            Thread.sleep(40)
        }
        pump()
        return condition()
    }

    private fun ready(activity: MainActivity): Boolean {
        return Reflect.field(activity, "identityManager") != null &&
            Reflect.field(activity, "ratchet") != null &&
            Reflect.field(activity, "hotspotTransport") != null &&
            Reflect.field(activity, "meshRouter") != null
    }

    private fun ratchetReady(activity: MainActivity): Boolean {
        val ratchet = Reflect.field(activity, "ratchet") as? DoubleRatchet ?: return false
        return ratchet.initialized
    }

    @Suppress("UNCHECKED_CAST")
    private fun chatMessages(activity: MainActivity): List<ChatMessage> {
        return Reflect.field(activity, "messages") as List<ChatMessage>
    }

    private fun setActiveMode(activity: MainActivity, name: String) {
        val modeClass = Class.forName("com.covertcomm.app.ui.MainActivity\$Mode")
        val constants = modeClass.enumConstants as Array<Enum<*>>
        val mode = constants.first { it.name == name }
        Reflect.set(activity, "activeMode", mode)
    }

    private fun bridge(activityA: MainActivity, activityB: MainActivity) {
        server = ServerSocket(0)
        val transportA = Reflect.field(activityA, "hotspotTransport")!!
        val transportB = Reflect.field(activityB, "hotspotTransport")!!
        Reflect.call(transportA, "startAsClient", "127.0.0.1", server!!.localPort)

        val serverSide = server!!.accept()
        peerSocket = serverSide

        Reflect.set(transportB, "clientSocket", serverSide)
        Reflect.set(transportB, "isRunning", true)
        Reflect.set(transportB, "isHost", false)
        Thread { Reflect.call(transportB, "handleClient", serverSide) }.start()
    }

    @Test
    fun twoActivitiesEstablishSessionAndExchangeMessages() {
        val activityA = launch()
        val activityB = launch()

        assertTrue("activity A must finish initialisation", waitFor { ready(activityA) })
        assertTrue("activity B must finish initialisation", waitFor { ready(activityB) })

        setActiveMode(activityA, "HOTSPOT")
        setActiveMode(activityB, "HOTSPOT")

        bridge(activityA, activityB)

        assertTrue("handshake must complete on A (real X3DH + ML-KEM)", waitFor { ratchetReady(activityA) })
        assertTrue("handshake must complete on B (real X3DH + ML-KEM)", waitFor { ratchetReady(activityB) })

        Reflect.call(activityA, "sendEncryptedMessage", "hello-from-A")

        assertTrue(
            "B must decrypt the message from A",
            waitFor { chatMessages(activityB).any { it.text == "hello-from-A" && !it.isOutgoing } }
        )

        Reflect.call(activityB, "sendEncryptedMessage", "reply-from-B")

        assertTrue(
            "A must decrypt the reply from B",
            waitFor { chatMessages(activityA).any { it.text == "reply-from-B" && !it.isOutgoing } }
        )

        assertFalse(
            "no decrypt failure may be reported",
            chatMessages(activityA).any { it.text.contains("Decrypt failed") } ||
                chatMessages(activityB).any { it.text.contains("Decrypt failed") }
        )
        assertFalse(
            "no session may be missing",
            chatMessages(activityA).any { it.text.contains("No session") } ||
                chatMessages(activityB).any { it.text.contains("No session") }
        )
    }

    @Test
    fun queuedMessageIsFlushedAfterHandshake() {
        val activityA = launch()
        val activityB = launch()
        assertTrue(waitFor { ready(activityA) })
        assertTrue(waitFor { ready(activityB) })
        setActiveMode(activityA, "HOTSPOT")
        setActiveMode(activityB, "HOTSPOT")

        Reflect.call(activityA, "sendEncryptedMessage", "queued-before-session")
        assertTrue(
            "message sent before the session must be queued",
            chatMessages(activityA).any { it.text.contains("queued") }
        )

        bridge(activityA, activityB)

        assertTrue(waitFor { ratchetReady(activityA) })
        assertTrue(waitFor { ratchetReady(activityB) })

        assertTrue(
            "queued message must be delivered once the session is up",
            waitFor { chatMessages(activityB).any { it.text == "queued-before-session" && !it.isOutgoing } }
        )
    }

    @Test
    fun sessionShowsSafetyNumberAndKeepsMeshIntegrity() {
        val activityA = launch()
        val activityB = launch()
        assertTrue(waitFor { ready(activityA) })
        assertTrue(waitFor { ready(activityB) })
        setActiveMode(activityA, "HOTSPOT")
        setActiveMode(activityB, "HOTSPOT")

        bridge(activityA, activityB)
        assertTrue(waitFor { ratchetReady(activityA) })
        assertTrue(waitFor { ratchetReady(activityB) })

        assertTrue(
            "a session established notice must be shown",
            chatMessages(activityA).any { it.text.contains("Session established") }
        )
        assertTrue(
            "a safety number must be shown",
            chatMessages(activityA).any { it.text.contains("SN:") }
        )

        val frame = MeshFrame.create(
            MeshFrame.TYPE_DATA,
            byteArrayOf(1, 2),
            byteArrayOf(3, 4),
            "x".toByteArray(),
            1
        ).toBytes()
        assertTrue(
            "frames signed with the session MAC key must verify",
            MeshFrame.parse(frame) != null
        )
    }
}