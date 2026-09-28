package com.covertcomm.app.mesh

import java.util.concurrent.ConcurrentHashMap

object FragmentCodec {

    const val HEADER = 8

    const val MAX_PAYLOAD = 250

    data class Packet(
        val msgId: Int,
        val index: Int,
        val total: Int,
        val chunk: Int,
        val payload: ByteArray
    )

    fun encode(magic: Byte, msgId: Int, index: Int, total: Int, chunk: Int, payload: ByteArray): ByteArray {
        val out = ByteArray(HEADER + payload.size)
        out[0] = magic
        out[1] = ((msgId shr 8) and 0xFF).toByte()
        out[2] = (msgId and 0xFF).toByte()
        out[3] = index.toByte()
        out[4] = total.toByte()
        out[5] = payload.size.toByte()
        out[6] = ((chunk shr 8) and 0xFF).toByte()
        out[7] = (chunk and 0xFF).toByte()
        System.arraycopy(payload, 0, out, HEADER, payload.size)
        return out
    }

    fun decode(magic: Byte, data: ByteArray): Packet? {
        if (data.size < HEADER || data[0] != magic) return null
        val msgId = ((data[1].toInt() and 0xFF) shl 8) or (data[2].toInt() and 0xFF)
        val index = data[3].toInt() and 0xFF
        val total = data[4].toInt() and 0xFF
        val len = data[5].toInt() and 0xFF
        val chunk = ((data[6].toInt() and 0xFF) shl 8) or (data[7].toInt() and 0xFF)
        if (total <= 0 || index >= total || chunk <= 0) return null
        if (len > data.size - HEADER) return null
        return Packet(msgId, index, total, chunk, data.copyOfRange(HEADER, HEADER + len))
    }

    fun fragment(magic: Byte, msgId: Int, frame: ByteArray, chunk: Int): List<ByteArray> {
        require(chunk > 0) { "chunk must be positive" }
        if (frame.size <= chunk) {
            return listOf(encode(magic, msgId, 0, 1, chunk, frame))
        }
        val total = (frame.size + chunk - 1) / chunk
        require(total <= 255) { "frame too large to fragment: ${frame.size} bytes" }
        val out = ArrayList<ByteArray>(total)
        var offset = 0
        for (i in 0 until total) {
            val end = minOf(offset + chunk, frame.size)
            out.add(encode(magic, msgId, i, total, chunk, frame.copyOfRange(offset, end)))
            offset = end
        }
        return out
    }
}

class FragmentAssembler(
    private val maxFrame: Int = 64 * 1024,
    private val timeoutMs: Long = 20000L
) {
    private class Entry(
        val total: Int,
        val chunk: Int,
        val buffer: ByteArray,
        val seen: BooleanArray,
        var received: Int,
        var lastLen: Int,
        val started: Long
    )

    private val entries = ConcurrentHashMap<Int, Entry>()

    fun offer(p: FragmentCodec.Packet): ByteArray? {
        if (p.total == 1) return p.payload

        val now = System.currentTimeMillis()
        val e = entries.getOrPut(p.msgId) {
            Entry(p.total, p.chunk, ByteArray(maxFrame), BooleanArray(p.total), 0, 0, now)
        }

        var complete: ByteArray? = null
        if (e.total != p.total || e.chunk != p.chunk) {

            entries.remove(p.msgId)
            return null
        }

        if (!e.seen[p.index]) {
            e.seen[p.index] = true
            e.received++
            val offset = p.index * e.chunk
            if (offset + p.payload.size <= e.buffer.size) {
                System.arraycopy(p.payload, 0, e.buffer, offset, p.payload.size)
            }
            if (p.index == e.total - 1) e.lastLen = p.payload.size
        }

        if (e.received >= e.total) {
            entries.remove(p.msgId)
            val length = (e.total - 1) * e.chunk + e.lastLen
            complete = if (length in 1..e.buffer.size) e.buffer.copyOfRange(0, length) else e.buffer
        }

        purge(now)
        return complete
    }

    fun purge(now: Long = System.currentTimeMillis()) {
        val iter = entries.entries.iterator()
        while (iter.hasNext()) {
            if (now - iter.next().value.started > timeoutMs) iter.remove()
        }
    }

    fun clear() = entries.clear()

    fun pending(): Int = entries.size
}
