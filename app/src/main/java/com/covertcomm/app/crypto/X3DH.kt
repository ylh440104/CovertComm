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
        myStaticPriv: ByteArray,
        myEphemeralPriv: ByteArray,
        theirBundle: PreKeyBundle,
        pqSharedSecret: ByteArray? = null,
        pqDecapsulatedSecret: ByteArray? = null
    ): X3DHResult {
        val theirStaticPub = CryptoUtils.decodeKey(theirBundle.preKey)
        val theirEphemeralPub = CryptoUtils.decodeKey(theirBundle.dhKey)
        return derive(myStaticPriv, myEphemeralPriv, theirStaticPub, theirEphemeralPub, theirBundle.dhKey, pqSharedSecret, pqDecapsulatedSecret)
    }

    fun respond(
        myStaticPriv: ByteArray,
        myEphemeralPriv: ByteArray,
        theirStaticPub: ByteArray,
        theirEphemeralPub: ByteArray,
        theirDHPublic: String = ""
    ): X3DHResult {
        return derive(myStaticPriv, myEphemeralPriv, theirStaticPub, theirEphemeralPub, theirDHPublic, null, null)
    }

    private fun derive(
        myStaticPriv: ByteArray,
        myEphemeralPriv: ByteArray,
        theirStaticPub: ByteArray,
        theirEphemeralPub: ByteArray,
        theirDHPublic: String,
        pqSharedSecret: ByteArray?,
        pqDecapsulatedSecret: ByteArray?
    ): X3DHResult {
        val dh1 = CryptoUtils.computeSharedSecret(myStaticPriv, theirEphemeralPub)
        val dh2 = CryptoUtils.computeSharedSecret(myEphemeralPriv, theirStaticPub)
        val dh3 = CryptoUtils.computeSharedSecret(myEphemeralPriv, theirEphemeralPub)

        val ordered = listOf(dh1, dh2, dh3).sortedWith(Comparator { a, b -> compareBytes(a, b) })
        var combined = ordered.fold(ByteArray(0)) { acc, b -> acc + b }

        var pqSalt = ByteArray(0)
        val pqParts = listOfNotNull(pqSharedSecret, pqDecapsulatedSecret).sortedWith(Comparator { a, b -> compareBytes(a, b) })
        if (pqParts.isNotEmpty()) {
            for (p in pqParts) combined += p
            pqSalt = CryptoUtils.sha256(pqParts.fold(ByteArray(0)) { acc, b -> acc + b })
        }

        val rootKey = CryptoUtils.hkdf(combined, salt = pqSalt, info = "X3DH_RootKey".toByteArray())
        val chainKey = CryptoUtils.hkdf(rootKey, info = "X3DH_ChainKey".toByteArray())

        CryptoUtils.wipe(dh1); CryptoUtils.wipe(dh2); CryptoUtils.wipe(dh3)
        CryptoUtils.wipe(combined)
        pqSharedSecret?.let { CryptoUtils.wipe(it) }
        pqDecapsulatedSecret?.let { CryptoUtils.wipe(it) }
        if (pqSalt.isNotEmpty()) CryptoUtils.wipe(pqSalt)

        return X3DHResult(rootKey, chainKey, theirDHPublic)
    }

    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        val minLen = minOf(a.size, b.size)
        for (i in 0 until minLen) {
            val cmp = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (cmp != 0) return cmp
        }
        return a.size - b.size
    }
}