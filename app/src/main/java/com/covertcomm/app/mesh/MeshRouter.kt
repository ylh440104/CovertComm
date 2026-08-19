package com.covertcomm.app.mesh

import com.covertcomm.app.crypto.CryptoUtils
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

class MeshRouter(
    private val myFingerprint: ByteArray
) {
    private val routingTable = ConcurrentHashMap<String, ByteArray>()
    private val reverseRoute = ConcurrentHashMap<String, ByteArray>()
    private val seenSeqNums = ConcurrentHashMap<Int, Long>()
    private val pendingMessages = ConcurrentHashMap<String, MutableList<ByteArray>>()
    private var seqCounter = 0
    private var listener: RouterListener? = null

    interface RouterListener {
        fun onFrameReady(frame: ByteArray, nextHop: ByteArray?)
        fun onDataReceived(payload: ByteArray, senderFP: ByteArray)
        fun onRouteEstablished(targetFP: ByteArray)
        fun onRouteRequest(targetFP: ByteArray)
    }

    fun setListener(l: RouterListener) { listener = l }

    fun nextSeqNum(): Int { seqCounter++; if (seqCounter < 0) seqCounter = 0; return seqCounter }

    private fun fpKey(fp: ByteArray): String =
        String.format("%02X%02X", fp[0], fp[1])

    fun processIncomingFrame(frame: MeshFrame.Frame, fromPeer: ByteArray) {
        if (!isSeqNumValid(frame.senderFP, frame.seqNum)) return

        val senderKey = fpKey(frame.senderFP)
        reverseRoute[senderKey] = fromPeer.copyOf()

        if (frame.targetFP.contentEquals(myFingerprint) || frame.targetFP.contentEquals(ByteArray(2))) {
            handleFrameForMe(frame)
            return
        }

        if (frame.canForward()) {
            forwardFrame(frame, fromPeer)
        }
    }

    private fun isSeqNumValid(senderFP: ByteArray, seqNum: Int): Boolean {
        val key = (String.format("%02X%02X", senderFP[0], senderFP[1]) + "_$seqNum").hashCode()
        val now = System.currentTimeMillis()
        val prev = seenSeqNums[key]
        if (prev != null && (now - prev) < 300000) return false
        seenSeqNums[key] = now
        cleanOldSeqNums(now)
        return true
    }

    private fun cleanOldSeqNums(now: Long) {
        val iter = seenSeqNums.entries.iterator()
        while (iter.hasNext()) {
            if (now - iter.next().value > 300000) iter.remove()
        }
        if (seenSeqNums.size > 10000) seenSeqNums.clear()
    }

    private fun handleFrameForMe(frame: MeshFrame.Frame) {
        when (frame.type) {
            MeshFrame.TYPE_DATA -> {
                listener?.onDataReceived(frame.payload, frame.senderFP)
                sendAck(frame.senderFP, frame.seqNum)
            }
            MeshFrame.TYPE_ROUTE_PROBE -> {
                val replyPayload = ByteArray(4)
                System.arraycopy(frame.senderFP, 0, replyPayload, 0, 2)
                replyPayload[2] = (frame.seqNum shr 8).toByte()
                replyPayload[3] = frame.seqNum.toByte()
                val reply = MeshFrame.create(
                    MeshFrame.TYPE_ROUTE_REPLY,
                    myFingerprint,
                    frame.senderFP,
                    replyPayload,
                    nextSeqNum()
                )
                val nextHop = reverseRoute[fpKey(frame.senderFP)]
                listener?.onFrameReady(reply.toBytes(), nextHop)
            }
            MeshFrame.TYPE_ROUTE_REPLY -> {
                listener?.onRouteEstablished(frame.senderFP)
            }
            MeshFrame.TYPE_HANDSHAKE -> {
                listener?.onDataReceived(frame.payload, frame.senderFP)
            }
            MeshFrame.TYPE_ACK -> {
                val targetKey = fpKey(frame.senderFP)
                pendingMessages.remove(targetKey)
            }
        }
    }

    private fun forwardFrame(frame: MeshFrame.Frame, fromPeer: ByteArray) {
        val forwarded = frame.forwarded()
        val targetKey = fpKey(frame.targetFP)
        val nextHop = routingTable[targetKey]
        if (nextHop != null && !nextHop.contentEquals(fromPeer)) {
            listener?.onFrameReady(forwarded.toBytes(), nextHop)
        } else {
            listener?.onFrameReady(forwarded.toBytes(), null)
        }
    }

    private fun sendAck(targetFP: ByteArray, originalSeq: Int) {
        val ackPayload = ByteArray(4)
        ackPayload[0] = (originalSeq shr 24).toByte()
        ackPayload[1] = (originalSeq shr 16).toByte()
        ackPayload[2] = (originalSeq shr 8).toByte()
        ackPayload[3] = originalSeq.toByte()
        val ack = MeshFrame.create(
            MeshFrame.TYPE_ACK,
            myFingerprint,
            targetFP,
            ackPayload,
            nextSeqNum()
        )
        val nextHop = reverseRoute[fpKey(targetFP)]
        listener?.onFrameReady(ack.toBytes(), nextHop)
    }

    fun sendData(targetFP: ByteArray, payload: ByteArray) {
        val frame = MeshFrame.create(
            MeshFrame.TYPE_DATA,
            myFingerprint,
            targetFP,
            payload,
            nextSeqNum()
        )
        val targetKey = fpKey(targetFP)
        val nextHop = routingTable[targetKey]
        if (nextHop != null) {
            listener?.onFrameReady(frame.toBytes(), nextHop)
        } else {
            listener?.onRouteRequest(targetFP)
            pendingMessages.getOrPut(targetKey) { mutableListOf() }.add(payload)
        }
    }

    fun sendHandshake(targetFP: ByteArray, payload: ByteArray) {
        val frame = MeshFrame.create(
            MeshFrame.TYPE_HANDSHAKE,
            myFingerprint,
            targetFP,
            payload,
            nextSeqNum()
        )
        val nextHop = routingTable[fpKey(targetFP)] ?: reverseRoute[fpKey(targetFP)]
        listener?.onFrameReady(frame.toBytes(), nextHop)
    }

    fun discoverRoute(targetFP: ByteArray) {
        val probe = MeshFrame.create(
            MeshFrame.TYPE_ROUTE_PROBE,
            myFingerprint,
            targetFP,
            ByteArray(0),
            nextSeqNum()
        )
        listener?.onFrameReady(probe.toBytes(), null)
    }

    fun addRoute(targetFP: ByteArray, nextHop: ByteArray) {
        routingTable[fpKey(targetFP)] = nextHop.copyOf()
        val targetKey = fpKey(targetFP)
        pendingMessages[targetKey]?.let { msgs ->
            for (msg in msgs) {
                sendData(targetFP, msg)
            }
            pendingMessages.remove(targetKey)
        }
    }

    fun flushRoutes() {
        routingTable.clear()
        reverseRoute.clear()
        seenSeqNums.clear()
        pendingMessages.clear()
    }

    fun wipe() {
        routingTable.clear()
        reverseRoute.clear()
        seenSeqNums.clear()
        pendingMessages.clear()
        seqCounter = 0
    }
}