package com.covertcomm.app.crypto

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Exercises the real X3DH + DoubleRatchet code that runs on device, so the
 * key-agreement path can be verified without two phones. If the two sides of a
 * handshake derive different keys, or a message cannot be decrypted, these tests
 * fail exactly where the device does.
 */
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

    /** Simulates the on-device handshake, including both PQ encapsulations. */
    private fun handshake(a: Peer, b: Peer) {
        // A encapsulates to B's key; B encapsulates to A's key.
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
    fun rolesAreComplementary() {
        val a = Peer()
        val b = Peer()
        handshake(a, b)

        // A's send chain must be B's receive chain, and vice versa. If both peers
        // pick the same role, these two assertions fail.
        assertEquals("A.send must equal B.recv", a.ratchet.debugSendKey(0), b.ratchet.debugRecvKey(0))
        assertEquals("B.send must equal A.recv", b.ratchet.debugSendKey(0), a.ratchet.debugRecvKey(0))
    }

    @Test
    fun repeatedMessagesDecrypt() {
        val a = Peer()
        val b = Peer()
        handshake(a, b)

        for (i in 0 until 5) {
            val m = a.ratchet.encrypt("msg-$i".toByteArray())
            assertEquals("msg-$i", String(b.ratchet.decrypt(m)))
        }
    }
}