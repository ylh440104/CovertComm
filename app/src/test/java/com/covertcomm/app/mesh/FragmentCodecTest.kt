package com.covertcomm.app.mesh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FragmentCodecTest {

    private val magic: Byte = 0x7B

    private fun roundTrip(frame: ByteArray, chunk: Int) {
        val fragments = FragmentCodec.fragment(magic, 42, frame, chunk)
        val assembler = FragmentAssembler()
        var result: ByteArray? = null
        for (f in fragments) {
            val p = FragmentCodec.decode(magic, f)
            assertNotNull("fragment must decode", p)
            result = assembler.offer(p!!) ?: result
        }
        assertNotNull("frame must reassemble", result)
        assertArrayEquals(frame, result)
    }

    @Test
    fun singleFragmentRoundTrip() = roundTrip("small".toByteArray(), 20)

    @Test
    fun multiFragmentRoundTrip() {
        val frame = ByteArray(500) { (it % 251).toByte() }
        roundTrip(frame, 20)
        roundTrip(frame, 128)
        roundTrip(frame, 250)
    }

    @Test
    fun exactMultipleOfChunk() {

        val frame = ByteArray(40) { it.toByte() }
        roundTrip(frame, 20)
    }

    @Test
    fun outOfOrderArrival() {
        val frame = ByteArray(300) { (it * 7 % 256).toByte() }
        val fragments = FragmentCodec.fragment(magic, 7, frame, 20)
        val assembler = FragmentAssembler()
        var result: ByteArray? = null
        for (f in fragments.reversed()) {
            result = assembler.offer(FragmentCodec.decode(magic, f)!!) ?: result
        }
        assertArrayEquals(frame, result)
    }

    @Test
    fun duplicateFragmentsAreIgnored() {
        val frame = ByteArray(200) { it.toByte() }
        val fragments = FragmentCodec.fragment(magic, 9, frame, 20)
        val assembler = FragmentAssembler()
        var result: ByteArray? = null

        for (f in fragments) {
            result = assembler.offer(FragmentCodec.decode(magic, f)!!) ?: result
            result = assembler.offer(FragmentCodec.decode(magic, f)!!) ?: result
        }
        assertArrayEquals(frame, result)
    }

    @Test
    fun differentStrideStillReassembles() {

        val frame = ByteArray(333) { (it % 97).toByte() }
        val fragments = FragmentCodec.fragment(magic, 11, frame, 40)
        val assembler = FragmentAssembler()
        var result: ByteArray? = null
        for (f in fragments) {
            result = assembler.offer(FragmentCodec.decode(magic, f)!!) ?: result
        }
        assertArrayEquals(frame, result)
    }

    @Test
    fun incompleteFrameYieldsNothing() {
        val frame = ByteArray(200) { it.toByte() }
        val fragments = FragmentCodec.fragment(magic, 5, frame, 20)
        val assembler = FragmentAssembler()
        var result: ByteArray? = null

        for (i in 0 until fragments.size - 1) {
            result = assembler.offer(FragmentCodec.decode(magic, fragments[i])!!) ?: result
        }
        assertNull("incomplete frame must not complete", result)
        assertEquals(1, assembler.pending())
    }

    @Test
    fun interleavedMessagesDoNotMix() {
        val a = ByteArray(150) { 1 }
        val b = ByteArray(150) { 2 }
        val fa = FragmentCodec.fragment(magic, 1, a, 20)
        val fb = FragmentCodec.fragment(magic, 2, b, 20)
        val assembler = FragmentAssembler()
        var ra: ByteArray? = null
        var rb: ByteArray? = null
        for (i in 0 until maxOf(fa.size, fb.size)) {
            if (i < fa.size) ra = assembler.offer(FragmentCodec.decode(magic, fa[i])!!) ?: ra
            if (i < fb.size) rb = assembler.offer(FragmentCodec.decode(magic, fb[i])!!) ?: rb
        }
        assertArrayEquals(a, ra)
        assertArrayEquals(b, rb)
    }

    @Test
    fun malformedInputIsRejected() {
        assertNull(FragmentCodec.decode(magic, ByteArray(3)))
        assertNull(FragmentCodec.decode(magic, byteArrayOf(0x00, 1, 0, 0, 1, 0, 0, 20)))
        assertNull(FragmentCodec.decode(magic, byteArrayOf(magic, 0, 1, 0, 2, 99, 0, 20)))
        assertNull(FragmentCodec.decode(magic, byteArrayOf(magic, 0, 1, 0, 2, 1, 0, 0, 5)))
    }

    @Test
    fun largeFrameAcrossManyFragments() {
        val frame = ByteArray(4000) { (it % 251).toByte() }
        roundTrip(frame, 200)
    }

    @Test
    fun frameLargerThanOneByteOfLength() {
        val frame = ByteArray(4096) { it.toByte() }
        val fragments = FragmentCodec.fragment(magic, 3, frame, 250)
        assertTrue("expected many fragments", fragments.size > 10)
        val assembler = FragmentAssembler()
        var result: ByteArray? = null
        for (f in fragments) result = assembler.offer(FragmentCodec.decode(magic, f)!!) ?: result
        assertArrayEquals(frame, result)
    }
}