package com.covertcomm.app.mesh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.CopyOnWriteArrayList

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class MeshRouterTest {

    private val me = byteArrayOf(0x01, 0x02)
    private val peer = byteArrayOf(0x03, 0x04)

    private class Recorder : MeshRouter.RouterListener {
        val frames = CopyOnWriteArrayList<Pair<ByteArray, ByteArray?>>()
        val data = CopyOnWriteArrayList<Pair<ByteArray, ByteArray>>()
        val routes = CopyOnWriteArrayList<ByteArray>()
        val routeRequests = CopyOnWriteArrayList<ByteArray>()
        override fun onFrameReady(frame: ByteArray, nextHop: ByteArray?) { frames.add(frame to nextHop) }
        override fun onDataReceived(payload: ByteArray, senderFP: ByteArray) { data.add(payload to senderFP) }
        override fun onRouteEstablished(targetFP: ByteArray) { routes.add(targetFP) }
        override fun onRouteRequest(targetFP: ByteArray) { routeRequests.add(targetFP) }
    }

    private lateinit var router: MeshRouter
    private lateinit var recorder: Recorder

    @Before
    fun setUp() {
        router = MeshRouter(me)
        recorder = Recorder()
        router.setListener(recorder)
    }

    @Test
    fun dataFrameForMeIsDeliveredAndAcked() {
        val frame = MeshFrame.create(MeshFrame.TYPE_DATA, peer, me, "payload".toByteArray(), 1)
        router.processIncomingFrame(frame, peer)

        assertEquals(1, recorder.data.size)
        assertArrayEquals("payload".toByteArray(), recorder.data.first().first)
        assertArrayEquals(peer, recorder.data.first().second)
        assertTrue("an ACK must be emitted", recorder.frames.isNotEmpty())

        val ack = MeshFrame.parse(recorder.frames.first().first)
        assertNotNull(ack)
        assertEquals(MeshFrame.TYPE_ACK, ack!!.type)
        assertArrayEquals(peer, ack.targetFP)
    }

    @Test
    fun broadcastTargetIsDelivered() {
        val frame = MeshFrame.create(MeshFrame.TYPE_DATA, peer, ByteArray(2), "broadcast".toByteArray(), 1)
        router.processIncomingFrame(frame, peer)
        assertEquals(1, recorder.data.size)
    }

    @Test
    fun duplicateSequenceIsDropped() {
        val frame = MeshFrame.create(MeshFrame.TYPE_DATA, peer, me, "once".toByteArray(), 9)
        router.processIncomingFrame(frame, peer)
        router.processIncomingFrame(frame, peer)
        assertEquals("replayed sequence number must be ignored", 1, recorder.data.size)
    }

    @Test
    fun handshakeFrameIsDeliveredAsData() {
        val frame = MeshFrame.create(MeshFrame.TYPE_HANDSHAKE, peer, me, "handshake-bytes".toByteArray(), 2)
        router.processIncomingFrame(frame, peer)
        assertEquals(1, recorder.data.size)
        assertArrayEquals("handshake-bytes".toByteArray(), recorder.data.first().first)
    }

    @Test
    fun routeProbeProducesReply() {
        val frame = MeshFrame.create(MeshFrame.TYPE_ROUTE_PROBE, peer, me, ByteArray(0), 4)
        router.processIncomingFrame(frame, peer)
        assertTrue("a route probe must produce a reply frame", recorder.frames.isNotEmpty())
        val reply = MeshFrame.parse(recorder.frames.first().first)
        assertEquals(MeshFrame.TYPE_ROUTE_REPLY, reply!!.type)
        assertArrayEquals(peer, reply.targetFP)
    }

    @Test
    fun routeReplyEstablishesRoute() {
        val frame = MeshFrame.create(MeshFrame.TYPE_ROUTE_REPLY, peer, me, ByteArray(4), 5)
        router.processIncomingFrame(frame, peer)
        assertEquals(1, recorder.routes.size)
        assertArrayEquals(peer, recorder.routes.first())
    }

    @Test
    fun unknownRouteRequestsDiscoveryAndQueues() {
        router.sendData(peer, "queued".toByteArray())
        assertTrue("an unknown target must trigger route discovery", recorder.routeRequests.isNotEmpty())
        assertTrue("no frame may be sent before a route exists", recorder.frames.isEmpty())
    }

    @Test
    fun knownRouteForwardsWithoutDiscovery() {
        val reply = MeshFrame.create(MeshFrame.TYPE_ROUTE_REPLY, peer, me, ByteArray(4), 1)
        router.processIncomingFrame(reply, peer)
        recorder.frames.clear()

        router.sendData(peer, "direct".toByteArray())
        assertTrue(recorder.routeRequests.isEmpty())
        assertEquals(1, recorder.frames.size)
        val frame = MeshFrame.parse(recorder.frames.first().first)
        assertArrayEquals(peer, frame!!.targetFP)
        assertArrayEquals("direct".toByteArray(), frame.payload)
    }

    @Test
    fun forwardingDecrementsTtlAndKeepsPayload() {
        val middle = byteArrayOf(0x0A, 0x0B)
        val destination = byteArrayOf(0x0C, 0x0D)
        val frame = MeshFrame.create(MeshFrame.TYPE_DATA, peer, destination, "transit".toByteArray(), 6, ttl = 5)
        router.processIncomingFrame(frame, middle)

        val forwarded = recorder.frames.mapNotNull { MeshFrame.parse(it.first) }
            .firstOrNull { it.type == MeshFrame.TYPE_DATA }
        assertNotNull("frame must be forwarded toward its destination", forwarded)
        assertEquals((5 - 1).toByte(), forwarded!!.ttl)
        assertEquals((0 + 1).toByte(), forwarded.hops)
        assertArrayEquals("transit".toByteArray(), forwarded.payload)
        assertArrayEquals(destination, forwarded.targetFP)
    }

    @Test
    fun zeroTtlFrameIsNotForwarded() {
        val destination = byteArrayOf(0x0C, 0x0D)
        val frame = MeshFrame.create(MeshFrame.TYPE_DATA, peer, destination, "dead".toByteArray(), 7, ttl = 0)
        router.processIncomingFrame(frame, byteArrayOf(0x0A, 0x0B))
        val forwarded = recorder.frames.mapNotNull { MeshFrame.parse(it.first) }
            .firstOrNull { it.type == MeshFrame.TYPE_DATA }
        assertNull("expired frame must be dropped", forwarded)
    }

    @Test
    fun flushRoutesForgetsEstablishedRoute() {
        router.processIncomingFrame(MeshFrame.create(MeshFrame.TYPE_ROUTE_REPLY, peer, me, ByteArray(4), 1), peer)
        recorder.frames.clear()
        router.flushRoutes()
        router.sendData(peer, "again".toByteArray())
        assertTrue("route must be re-discovered after a flush", recorder.routeRequests.isNotEmpty())
    }

    @Test
    fun wipeResetsSequenceCounter() {
        router.nextSeqNum()
        router.nextSeqNum()
        router.wipe()
        assertEquals(1, router.nextSeqNum())
    }
}