package com.covertcomm.app.mesh

import com.covertcomm.app.crypto.CryptoUtils
import java.nio.ByteBuffer

object MeshFrame {

    const val VERSION: Byte = 1
    const val TYPE_ROUTE_PROBE: Byte = 0x01
    const val TYPE_ROUTE_REPLY: Byte = 0x02
    const val TYPE_DATA: Byte = 0x03
    const val TYPE_ACK: Byte = 0x04
    const val TYPE_BROADCAST: Byte = 0x05
    const val TYPE_HANDSHAKE: Byte = 0x06
    const val MAX_TTL: Byte = 15
    const val HEADER_SIZE = 1 + 1 + 2 + 2 + 1 + 1 + 4 + 2
    const val HMAC_SIZE = 32
    const val FRAME_OVERHEAD = HEADER_SIZE + HMAC_SIZE
    const val MAX_PAYLOAD = 4096
    const val MAX_FRAME_SIZE = FRAME_OVERHEAD + MAX_PAYLOAD

    data class Frame(
        val version: Byte,
        val type: Byte,
        val senderFP: ByteArray,
        val targetFP: ByteArray,
        val ttl: Byte,
        val hops: Byte,
        val seqNum: Int,
        val payload: ByteArray,
        val hmac: ByteArray
    ) {
        fun toBytes(): ByteArray {
            val buf = ByteBuffer.allocate(FRAME_OVERHEAD + payload.size)
            buf.put(version)
            buf.put(type)
            buf.put(senderFP)
            buf.put(targetFP)
            buf.put(ttl)
            buf.put(hops)
            buf.putInt(seqNum)
            buf.putShort(payload.size.toShort())
            buf.put(payload)
            val withoutHmac = buf.array().copyOfRange(0, HEADER_SIZE + payload.size)
            val hmacCalc = CryptoUtils.sha256(withoutHmac + "mesh_hmac".toByteArray())
            buf.put(hmacCalc)
            return buf.array()
        }

        fun canForward(): Boolean = ttl > 0

        fun forwarded(): Frame {
            return Frame(
                version, type, senderFP, targetFP,
                (ttl - 1).toByte(), (hops + 1).toByte(),
                seqNum, payload, hmac
            )
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Frame) return false
            return seqNum == other.seqNum &&
                    senderFP.contentEquals(other.senderFP) &&
                    targetFP.contentEquals(other.targetFP)
        }

        override fun hashCode(): Int = seqNum
    }

    fun parse(bytes: ByteArray): Frame? {
        if (bytes.size < FRAME_OVERHEAD) return null
        val buf = ByteBuffer.wrap(bytes)
        val version = buf.get()
        if (version != VERSION) return null
        val type = buf.get()
        val senderFP = ByteArray(2)
        buf.get(senderFP)
        val targetFP = ByteArray(2)
        buf.get(targetFP)
        val ttl = buf.get()
        val hops = buf.get()
        val seqNum = buf.getInt()
        val payloadLen = buf.getShort().toInt() and 0xFFFF
        if (payloadLen > MAX_PAYLOAD) return null
        val payload = ByteArray(payloadLen)
        buf.get(payload)
        val hmac = ByteArray(HMAC_SIZE)
        buf.get(hmac)
        val hmacCalc = CryptoUtils.sha256(
            bytes.copyOfRange(0, HEADER_SIZE + payloadLen) + "mesh_hmac".toByteArray()
        )
        if (!hmac.contentEquals(hmacCalc)) return null
        return Frame(version, type, senderFP, targetFP, ttl, hops, seqNum, payload, hmac)
    }

    fun create(
        type: Byte,
        senderFP: ByteArray,
        targetFP: ByteArray,
        payload: ByteArray,
        seqNum: Int,
        ttl: Byte = MAX_TTL
    ): Frame {
        val hmac = CryptoUtils.sha256(
            ByteBuffer.allocate(HEADER_SIZE + payload.size).apply {
                put(VERSION)
                put(type)
                put(senderFP)
                put(targetFP)
                put(ttl)
                put(0.toByte())
                putInt(seqNum)
                putShort(payload.size.toShort())
                put(payload)
            }.array() + "mesh_hmac".toByteArray()
        )
        return Frame(VERSION, type, senderFP, targetFP, ttl, 0, seqNum, payload, hmac)
    }
}