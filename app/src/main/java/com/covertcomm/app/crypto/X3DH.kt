package com.covertcomm.app.crypto

object X3DH {

    data class PreKeyBundle(
        val identityKey: String,
        val preKey: String,
        val dhKey: String,
        val fingerprint: String = ""
    )

    data class X3DHResult(
        val rootKey: ByteArray,
        val chainKey: ByteArray,
        val theirDHPublic: String,
        val pqSharedSecret: ByteArray? = null,
        val pqDecapsulatedSecret: ByteArray? = null
    )

    fun initiate(
        myIdPriv: ByteArray,
        myEphPriv: ByteArray,
        theirBundle: PreKeyBundle,
        pqSharedSecret: ByteArray? = null,
        pqDecapsulatedSecret: ByteArray? = null
    ): X3DHResult {
        val theirIdPub = CryptoUtils.decodeKey(theirBundle.identityKey)
        val theirPrePub = CryptoUtils.decodeKey(theirBundle.preKey)

        val dh1 = CryptoUtils.computeSharedSecret(myIdPriv, theirPrePub)
        val dh2 = CryptoUtils.computeSharedSecret(myEphPriv, theirIdPub)
        val dh3 = CryptoUtils.computeSharedSecret(myEphPriv, theirPrePub)

        var combined = dh1 + dh2 + dh3
        var pqSalt = ByteArray(0)
        if (pqSharedSecret != null && pqDecapsulatedSecret != null) {
            val ordered = if (byteArrayCompare(pqSharedSecret, pqDecapsulatedSecret) <= 0) {
                pqSharedSecret + pqDecapsulatedSecret
            } else {
                pqDecapsulatedSecret + pqSharedSecret
            }
            combined = combined + ordered
            pqSalt = CryptoUtils.sha256(ordered)
        } else if (pqSharedSecret != null) {
            combined = combined + pqSharedSecret
            pqSalt = CryptoUtils.sha256(pqSharedSecret)
        }
        val rootKey = CryptoUtils.hkdf(combined, salt = pqSalt, info = "X3DH_PQ_RootKey".toByteArray())
        val chainKey = CryptoUtils.hkdf(rootKey, info = "X3DH_PQ_ChainKey".toByteArray())

        CryptoUtils.wipe(dh1)
        CryptoUtils.wipe(dh2)
        CryptoUtils.wipe(dh3)
        CryptoUtils.wipe(combined)
        pqSharedSecret?.let { CryptoUtils.wipe(it) }
        pqDecapsulatedSecret?.let { CryptoUtils.wipe(it) }
        if (pqSalt.isNotEmpty()) CryptoUtils.wipe(pqSalt)

        return X3DHResult(rootKey, chainKey, theirBundle.dhKey)
    }

    fun respond(
        myIdPriv: ByteArray,
        myPrePriv: ByteArray,
        theirIdPub: ByteArray,
        theirEphPub: ByteArray
    ): X3DHResult {
        val dh1 = CryptoUtils.computeSharedSecret(myPrePriv, theirIdPub)
        val dh2 = CryptoUtils.computeSharedSecret(myIdPriv, theirEphPub)
        val dh3 = CryptoUtils.computeSharedSecret(myPrePriv, theirEphPub)

        val combined = dh1 + dh2 + dh3
        val rootKey = CryptoUtils.hkdf(combined, info = "X3DH_RootKey".toByteArray())
        val chainKey = CryptoUtils.hkdf(rootKey, info = "X3DH_ChainKey".toByteArray())

        CryptoUtils.wipe(dh1)
        CryptoUtils.wipe(dh2)
        CryptoUtils.wipe(dh3)
        CryptoUtils.wipe(combined)

        return X3DHResult(rootKey, chainKey, "")
    }

    private fun byteArrayCompare(a: ByteArray, b: ByteArray): Int {
        val minLen = minOf(a.size, b.size)
        for (i in 0 until minLen) {
            val cmp = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (cmp != 0) return cmp
        }
        return a.size - b.size
    }
}