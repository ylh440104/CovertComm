package com.covertcomm.app.crypto

class DoubleRatchet(
    private val dhPublicKeyProvider: () -> String
) {
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