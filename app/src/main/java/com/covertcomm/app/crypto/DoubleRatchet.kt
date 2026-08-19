package com.covertcomm.app.crypto

class DoubleRatchet(
    private val identityManager: IdentityManager
) {
    private var rootKey: ByteArray = ByteArray(0)
    private var sendingChainKey: ByteArray = ByteArray(0)
    private var receivingChainKey: ByteArray = ByteArray(0)
    private var dhSendingKey: CryptoUtils.DHKeyPair? = null
    private var theirDHPublic: ByteArray = ByteArray(0)

    private var sendMsgNum = 0
    private var recvMsgNum = 0
    private var previousSendMsgNum = 0

    var initialized = false
        private set

    data class RatchetMessage(
        val dhPublicKey: String,
        val previousMessageNumber: Int,
        val messageNumber: Int,
        val nonce: ByteArray,
        val ciphertext: ByteArray
    )

    fun initializeAsInitiator(x3dhResult: X3DH.X3DHResult) {
        rootKey = x3dhResult.rootKey
        sendingChainKey = x3dhResult.chainKey
        dhSendingKey = identityManager.currentDHKeyPair
        if (x3dhResult.theirDHPublic.isNotEmpty()) {
            theirDHPublic = CryptoUtils.decodeKey(x3dhResult.theirDHPublic)
        }
        initialized = true
    }

    fun initializeAsResponder(x3dhResult: X3DH.X3DHResult, theirInitialDHPub: String) {
        rootKey = x3dhResult.rootKey
        dhSendingKey = identityManager.regenerateDHKeyPair()
        theirDHPublic = CryptoUtils.decodeKey(theirInitialDHPub)
        performDHRatchet()
        initialized = true
    }

    fun encrypt(plaintext: ByteArray): RatchetMessage {
        check(initialized) { "Ratchet not initialized" }

        val (newChainKey, messageKey) = advanceChain(sendingChainKey)
        sendingChainKey = newChainKey

        val payload = CryptoUtils.encryptAESGCM(messageKey, plaintext)

        val msg = RatchetMessage(
            dhPublicKey = CryptoUtils.encodeKey(dhSendingKey!!.publicKey),
            previousMessageNumber = previousSendMsgNum,
            messageNumber = sendMsgNum,
            nonce = payload.nonce,
            ciphertext = payload.ciphertext
        )

        sendMsgNum++
        CryptoUtils.wipe(messageKey)
        return msg
    }

    fun decrypt(message: RatchetMessage): ByteArray {
        check(initialized) { "Ratchet not initialized" }

        val msgDHPub = CryptoUtils.decodeKey(message.dhPublicKey)

        if (theirDHPublic.isEmpty() || !msgDHPub.contentEquals(theirDHPublic)) {
            performDHRatchet(msgDHPub)
        }

        val (newChainKey, messageKey) = advanceChain(receivingChainKey)
        receivingChainKey = newChainKey

        val payload = CryptoUtils.EncryptedPayload(message.nonce, message.ciphertext)
        val result = CryptoUtils.decryptAESGCM(messageKey, payload)
        CryptoUtils.wipe(messageKey)
        return result
    }

    private fun performDHRatchet(newTheirDHPub: ByteArray? = null) {
        val theirPub = newTheirDHPub ?: if (theirDHPublic.isNotEmpty()) theirDHPublic else return

        val dhRecv = CryptoUtils.computeSharedSecret(dhSendingKey!!.privateKey, theirPub)
        val (newRoot, newRecvChain) = deriveRootAndChain(rootKey, dhRecv, "recv")
        rootKey = newRoot
        receivingChainKey = newRecvChain

        dhSendingKey = identityManager.regenerateDHKeyPair()
        val dhSend = CryptoUtils.computeSharedSecret(dhSendingKey!!.privateKey, theirPub)
        val (newRoot2, newSendChain) = deriveRootAndChain(rootKey, dhSend, "send")
        rootKey = newRoot2
        sendingChainKey = newSendChain

        previousSendMsgNum = sendMsgNum
        sendMsgNum = 0
        recvMsgNum = 0

        CryptoUtils.wipe(dhRecv)
        CryptoUtils.wipe(dhSend)

        if (newTheirDHPub != null) {
            theirDHPublic = newTheirDHPub
        }
    }

    private fun advanceChain(chainKey: ByteArray): Pair<ByteArray, ByteArray> {
        val newChain = CryptoUtils.hkdf(chainKey, info = "chain".toByteArray())
        val msgKey = CryptoUtils.hkdf(chainKey, info = "msgkey".toByteArray())
        return newChain to msgKey
    }

    private fun deriveRootAndChain(rk: ByteArray, dhOutput: ByteArray, label: String): Pair<ByteArray, ByteArray> {
        val combined = rk + dhOutput
        val newRoot = CryptoUtils.hkdf(combined, info = "ratchet_root".toByteArray())
        val chain = CryptoUtils.hkdf(newRoot, info = "ratchet_${label}_chain".toByteArray())
        CryptoUtils.wipe(combined)
        return newRoot to chain
    }

    fun wipe() {
        CryptoUtils.wipe(rootKey)
        CryptoUtils.wipe(sendingChainKey)
        CryptoUtils.wipe(receivingChainKey)
        initialized = false
    }
}