package com.covertcomm.app.crypto

/**
 * Simplified symmetric ratchet.
 *
 * The X3DH output (root key + chain key) is shared by both sides, so a single
 * chain is used without the "who sends first" ambiguity that previously left the
 * responder unable to decrypt anything. Message keys are derived per index (HKDF
 * with the counter as info) so out-of-order delivery still decrypts.
 *
 * Replay protection: each inbound index is consumed exactly once. A duplicate
 * (same index again) is rejected instead of being decrypted with a re-derived
 * key, which previously made replays indistinguishable from retransmissions.
 */
class DoubleRatchet(
    private val identityManager: IdentityManager
) {
    private var rootKey: ByteArray = ByteArray(0)
    private var chainKey: ByteArray = ByteArray(0)
    private var sendCounter = 0
    private var recvCounter = 0

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

    fun initialize(x3dhResult: X3DH.X3DHResult) {
        rootKey = x3dhResult.rootKey
        chainKey = x3dhResult.chainKey
        sendCounter = 0
        recvCounter = 0
        consumedRecv.clear()
        usedSendKeys.clear()
        initialized = true
    }

    fun encrypt(plaintext: ByteArray): RatchetMessage {
        check(initialized) { "Ratchet not initialized" }
        val index = sendCounter
        val messageKey = deriveMessageKey(index)
        sendCounter++

        val payload = CryptoUtils.encryptAESGCM(messageKey, plaintext)
        val msg = RatchetMessage(
            dhPublicKey = identityManager.exportDHPublicKey(),
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
        if (index >= recvCounter) recvCounter = index + 1

        val messageKey = deriveMessageKey(index)
        val payload = CryptoUtils.EncryptedPayload(message.nonce, message.ciphertext)
        return try {
            CryptoUtils.decryptAESGCM(messageKey, payload)
        } finally {
            CryptoUtils.wipe(messageKey)
        }
    }

    private fun deriveMessageKey(index: Int): ByteArray {
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

    fun wipe() {
        CryptoUtils.wipe(rootKey)
        CryptoUtils.wipe(chainKey)
        for (v in usedSendKeys.values) CryptoUtils.wipe(v)
        usedSendKeys.clear()
        consumedRecv.clear()
        initialized = false
    }
}