package com.covertcomm.app.crypto

/**
 * Simplified symmetric ratchet with directional chains.
 *
 * The X3DH output is shared by both sides. To avoid the two peers colliding on
 * the same message numbers (which made the second speaker's messages look like
 * replays and fail to decrypt), the shared chain key is split into two
 * directional chains. The peer with the lexicographically smaller identity key
 * sends on chain A and receives on chain B, the other peer does the reverse, so
 * each direction has its own independent counter space.
 *
 * Replay protection: each inbound index is consumed exactly once per direction.
 */
class DoubleRatchet(
    private val dhPublicKeyProvider: () -> String
) {
    /** Convenience constructor used by the app. */
    constructor(identityManager: IdentityManager) : this({ identityManager.exportDHPublicKey() })

    private var rootKey: ByteArray = ByteArray(0)
    private var sendChainKey: ByteArray = ByteArray(0)
    private var recvChainKey: ByteArray = ByteArray(0)

    private var sendCounter = 0
    private val consumedRecv = HashSet<Int>()
    private val usedSendKeys = LinkedHashMap<Int, ByteArray>()

    var initialized = false
        private set

    data class RatchetMessage(
        val dhPublicKey: String,
        val previousMessageNumber: Int,
        val messageNumber: Int,
        val nonce: ByteArray,
        val ciphertext: ByteArray
    )

    class ReplayException(message: String) : Exception(message)

    fun initialize(x3dhResult: X3DH.X3DHResult, myIdentityPub: ByteArray, theirIdentityPub: ByteArray) {
        rootKey = x3dhResult.rootKey
        val chainA = CryptoUtils.hkdf(x3dhResult.chainKey, info = "chainA".toByteArray())
        val chainB = CryptoUtils.hkdf(x3dhResult.chainKey, info = "chainB".toByteArray())
        val iAmA = compareBytes(myIdentityPub, theirIdentityPub) <= 0
        sendChainKey = if (iAmA) chainA else chainB
        recvChainKey = if (iAmA) chainB else chainA
        // Do NOT wipe the "unused" chain here: sendChainKey/recvChainKey are
        // references, so wiping would zero the array the ratchet is using.
        sendCounter = 0
        consumedRecv.clear()
        usedSendKeys.clear()
        initialized = true
    }

    fun encrypt(plaintext: ByteArray): RatchetMessage {
        check(initialized) { "Ratchet not initialized" }
        val index = sendCounter
        val messageKey = deriveMessageKey(sendChainKey, index)
        sendCounter++

        val payload = CryptoUtils.encryptAESGCM(messageKey, plaintext)
        val msg = RatchetMessage(
            dhPublicKey = dhPublicKeyProvider(),
            previousMessageNumber = 0,
            messageNumber = index,
            nonce = payload.nonce,
            ciphertext = payload.ciphertext
        )

        usedSendKeys[index] = messageKey
        evict(usedSendKeys)
        return msg
    }

    fun decrypt(message: RatchetMessage): ByteArray {
        check(initialized) { "Ratchet not initialized" }
        val index = message.messageNumber
        if (!consumedRecv.add(index)) {
            throw ReplayException("Message $index already processed")
        }

        val messageKey = deriveMessageKey(recvChainKey, index)
        val payload = CryptoUtils.EncryptedPayload(message.nonce, message.ciphertext)
        return try {
            CryptoUtils.decryptAESGCM(messageKey, payload)
        } finally {
            CryptoUtils.wipe(messageKey)
        }
    }

    private fun deriveMessageKey(chainKey: ByteArray, index: Int): ByteArray {
        return CryptoUtils.hkdf(
            chainKey,
            info = "msgkey".toByteArray() + byteArrayOf(
                (index ushr 24).toByte(),
                (index ushr 16).toByte(),
                (index ushr 8).toByte(),
                index.toByte()
            )
        )
    }

    /** Diagnostic only: short fingerprints of the active chains. */
    fun debugChains(): String {
        fun fp(b: ByteArray) = CryptoUtils.sha256(b).copyOfRange(0, 6).joinToString("") { "%02x".format(it) }
        return "sendChain=" + fp(sendChainKey) + " recvChain=" + fp(recvChainKey) + " sendCnt=" + sendCounter
    }

    /** Diagnostic only: fingerprint of the key that would decrypt [index]. */
    fun debugRecvKey(index: Int): String {
        val k = deriveMessageKey(recvChainKey, index)
        val fp = CryptoUtils.sha256(k).copyOfRange(0, 6).joinToString("") { "%02x".format(it) }
        CryptoUtils.wipe(k)
        return fp
    }

    /** Diagnostic only: fingerprint of the key used to encrypt [index]. */
    fun debugSendKey(index: Int): String {
        val k = deriveMessageKey(sendChainKey, index)
        val fp = CryptoUtils.sha256(k).copyOfRange(0, 6).joinToString("") { "%02x".format(it) }
        CryptoUtils.wipe(k)
        return fp
    }

    private fun evict(map: LinkedHashMap<Int, ByteArray>) {
        while (map.size > 200) {
            val it = map.entries.iterator()
            if (it.hasNext()) {
                val e = it.next()
                CryptoUtils.wipe(e.value)
                it.remove()
            }
        }
    }

    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        val minLen = minOf(a.size, b.size)
        for (i in 0 until minLen) {
            val cmp = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (cmp != 0) return cmp
        }
        return a.size - b.size
    }

    fun wipe() {
        CryptoUtils.wipe(rootKey)
        CryptoUtils.wipe(sendChainKey)
        CryptoUtils.wipe(recvChainKey)
        for (v in usedSendKeys.values) CryptoUtils.wipe(v)
        usedSendKeys.clear()
        consumedRecv.clear()
        initialized = false
    }
}