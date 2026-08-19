package com.covertcomm.app.crypto

import android.content.Context
import android.util.Base64

class IdentityManager(context: Context) {

    private val appContext = context.applicationContext

    var identityKeyPair: CryptoUtils.DHKeyPair? = null
        private set

    var preKeyPair: CryptoUtils.DHKeyPair? = null
        private set

    var currentDHKeyPair: CryptoUtils.DHKeyPair? = null
        private set

    var pqKeyPair: PostQuantumKEM.PQKeyPair? = null
        private set

    init {
        generateKeys()
    }

    private fun generateKeys() {
        identityKeyPair = CryptoUtils.generateIdentityKeyPair()
        preKeyPair = CryptoUtils.generateECDHKeyPair()
        currentDHKeyPair = CryptoUtils.generateECDHKeyPair()
        try {
            pqKeyPair = PostQuantumKEM.generateKeyPair()
        } catch (e: Exception) {
            pqKeyPair = null
        }
    }

    fun regenerateIdentity() {
        wipeAll()
        generateKeys()
    }

    fun regenerateDHKeyPair(): CryptoUtils.DHKeyPair {
        val old = currentDHKeyPair
        currentDHKeyPair = CryptoUtils.generateECDHKeyPair()
        old?.let { CryptoUtils.wipe(it.privateKey); CryptoUtils.wipe(it.publicKey) }
        return currentDHKeyPair!!
    }

    fun getShortFingerprint(): String {
        val pubKey = identityKeyPair?.publicKey ?: return "----"
        val hash = CryptoUtils.sha256(pubKey)
        val sb = StringBuilder()
        for (i in 0 until 4) {
            sb.append(String.format("%02X", hash[i]))
        }
        return sb.toString()
    }

    fun getSafetyNumber(theirIdentityPubEncoded: String): String {
        val myPub = identityKeyPair!!.publicKey
        val theirPub = Base64.decode(theirIdentityPubEncoded, Base64.NO_WRAP)
        return CryptoUtils.computeSafetyNumber(myPub, theirPub)
    }

    fun exportPublicKey(): String = CryptoUtils.encodeKey(identityKeyPair!!.publicKey)
    fun exportPreKeyPublic(): String = CryptoUtils.encodeKey(preKeyPair!!.publicKey)
    fun exportDHPublicKey(): String = CryptoUtils.encodeKey(currentDHKeyPair!!.publicKey)

    fun exportEncodedPublicKeys(): Map<String, String> {
        return mapOf(
            "identityKey" to exportPublicKey(),
            "preKey" to exportPreKeyPublic(),
            "dhKey" to exportDHPublicKey(),
            "fingerprint" to getShortFingerprint(),
            "pqPublicKey" to exportPQPublicKey()
        )
    }

    fun exportPQPublicKey(): String {
        return PostQuantumKEM.encodePublicKey(pqKeyPair?.publicKey ?: ByteArray(0))
    }

    fun getPQSharedSecret(theirPQPublicKey: String): ByteArray? {
        if (theirPQPublicKey.isEmpty()) return null
        val theirPub = PostQuantumKEM.decodePublicKey(theirPQPublicKey)
        val encaps = PostQuantumKEM.encapsulate(theirPub)
        return encaps.sharedSecret
    }

    fun decapsulatePQ(ciphertext: ByteArray): ByteArray? {
        val priv = pqKeyPair?.privateKey ?: return null
        return PostQuantumKEM.decapsulate(priv, ciphertext)
    }

    fun wipeAll() {
        identityKeyPair?.let { CryptoUtils.wipe(it.privateKey); CryptoUtils.wipe(it.publicKey) }
        preKeyPair?.let { CryptoUtils.wipe(it.privateKey); CryptoUtils.wipe(it.publicKey) }
        currentDHKeyPair?.let { CryptoUtils.wipe(it.privateKey); CryptoUtils.wipe(it.publicKey) }
        pqKeyPair?.let { PostQuantumKEM.wipeKeyPair(it) }
        identityKeyPair = null
        preKeyPair = null
        currentDHKeyPair = null
        pqKeyPair = null
    }
}