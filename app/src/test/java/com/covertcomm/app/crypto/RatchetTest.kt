package com.covertcomm.app.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RatchetTest {

    private class Peer {
        val identity = CryptoUtils.generateIdentityKeyPair()
        val pre = CryptoUtils.generateECDHKeyPair()
        val dh = CryptoUtils.generateECDHKeyPair()
        val pq = PostQuantumKEM.generateKeyPair()
        val ratchet = DoubleRatchet { CryptoUtils.encodeKey(dh.publicKey) }

        fun bundle(): X3DH.PreKeyBundle = X3DH.PreKeyBundle(
            CryptoUtils.encodeKey(identity.publicKey),
            CryptoUtils.encodeKey(pre.publicKey),
            CryptoUtils.encodeKey(dh.publicKey),
            ""
        )
    }

    private fun handshake(a: Peer, b: Peer) {
        val encForB = PostQuantumKEM.encapsulate(b.pq.publicKey)
        val encForA = PostQuantumKEM.encapsulate(a.pq.publicKey)
        val decByB = PostQuantumKEM.decapsulate(b.pq.privateKey, encForB.ciphertext)
        val decByA = PostQuantumKEM.decapsulate(a.pq.privateKey, encForA.ciphertext)

        val aResult = X3DH.initiate(
            a.pre.privateKey, a.dh.privateKey, b.bundle(),
            encForB.sharedSecret.copyOf(), decByA.copyOf()
        )
        val bResult = X3DH.initiate(
            b.pre.privateKey, b.dh.privateKey, a.bundle(),
            encForA.sharedSecret.copyOf(), decByB.copyOf()
        )

        a.ratchet.initialize(aResult, a.identity.publicKey, b.identity.publicKey)
        b.ratchet.initialize(bResult, b.identity.publicKey, a.identity.publicKey)
    }

    @Test
    fun bothDirectionsDecrypt() {
        val a = Peer()
        val b = Peer()
        handshake(a, b)

        val fromA = a.ratchet.encrypt("hello-from-A".toByteArray())
        assertEquals("hello-from-A", String(b.ratchet.decrypt(fromA)))

        val fromB = b.ratchet.encrypt("hello-from-B".toByteArray())
        assertEquals("hello-from-B", String(a.ratchet.decrypt(fromB)))
    }

    @Test
    fun repeatedMessagesDecrypt() {
        val a = Peer()
        val b = Peer()
        handshake(a, b)

        for (i in 0 until 20) {
            val m = a.ratchet.encrypt("msg-$i".toByteArray())
            assertEquals("msg-$i", String(b.ratchet.decrypt(m)))
        }
        for (i in 0 until 20) {
            val m = b.ratchet.encrypt("reply-$i".toByteArray())
            assertEquals("reply-$i", String(a.ratchet.decrypt(m)))
        }
    }

    @Test
    fun outOfOrderMessagesDecrypt() {
        val a = Peer()
        val b = Peer()
        handshake(a, b)

        val m0 = a.ratchet.encrypt("zero".toByteArray())
        val m1 = a.ratchet.encrypt("one".toByteArray())
        val m2 = a.ratchet.encrypt("two".toByteArray())

        assertEquals("two", String(b.ratchet.decrypt(m2)))
        assertEquals("zero", String(b.ratchet.decrypt(m0)))
        assertEquals("one", String(b.ratchet.decrypt(m1)))
    }

    @Test(expected = DoubleRatchet.ReplayException::class)
    fun replayIsRejected() {
        val a = Peer()
        val b = Peer()
        handshake(a, b)

        val m = a.ratchet.encrypt("once".toByteArray())
        assertEquals("once", String(b.ratchet.decrypt(m)))
        b.ratchet.decrypt(m)
    }

    @Test
    fun crossSessionMessageFailsToDecrypt() {
        val a1 = Peer()
        val b1 = Peer()
        handshake(a1, b1)

        val a2 = Peer()
        val b2 = Peer()
        handshake(a2, b2)

        assertEquals("first", String(b1.ratchet.decrypt(a1.ratchet.encrypt("first".toByteArray()))))
        assertEquals("second", String(b2.ratchet.decrypt(a2.ratchet.encrypt("second".toByteArray()))))

        var threw = false
        try {
            b2.ratchet.decrypt(a1.ratchet.encrypt("cross".toByteArray()))
        } catch (e: Exception) {
            threw = true
        }
        assertTrue("a message from another session must not decrypt", threw)
    }

    @Test
    fun largeMessageDecrypts() {
        val a = Peer()
        val b = Peer()
        handshake(a, b)

        val payload = ByteArray(3000) { (it % 251).toByte() }
        val m = a.ratchet.encrypt(payload)
        val out = b.ratchet.decrypt(m)
        assertEquals(payload.size, out.size)
    }
}