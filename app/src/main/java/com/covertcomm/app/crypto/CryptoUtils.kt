package com.covertcomm.app.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

object CryptoUtils {

    private const val AES_ALGORITHM = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH = 128
    private const val GCM_NONCE_LENGTH = 12
    private val HKDF_INFO = "CovertComm-v1".toByteArray()

    data class DHKeyPair(
        val publicKey: ByteArray,
        val privateKey: ByteArray
    )

    fun generateECDHKeyPair(): DHKeyPair {
        val gen = X25519KeyPairGenerator()
        gen.init(X25519KeyGenerationParameters(SecureRandom()))
        val pair = gen.generateKeyPair()
        val pub = (pair.public as X25519PublicKeyParameters).getEncoded()
        val priv = (pair.private as X25519PrivateKeyParameters).getEncoded()
        return DHKeyPair(pub, priv)
    }

    fun computeSharedSecret(myPrivKey: ByteArray, theirPubKey: ByteArray): ByteArray {
        val priv = X25519PrivateKeyParameters(myPrivKey)
        val pub = X25519PublicKeyParameters(theirPubKey)
        val agreement = X25519Agreement()
        agreement.init(priv)
        val secret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(pub, secret, 0)
        return secret
    }

    fun generateIdentityKeyPair(): DHKeyPair {
        val priv = Ed25519PrivateKeyParameters(SecureRandom())
        val pub = priv.generatePublicKey()
        return DHKeyPair(pub.encoded, priv.encoded)
    }

    fun sign(privateKeyBytes: ByteArray, data: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(privateKeyBytes))
        signer.update(data, 0, data.size)
        return signer.generateSignature()
    }

    fun verify(publicKeyBytes: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
        return try {
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(publicKeyBytes))
            verifier.update(data, 0, data.size)
            verifier.verifySignature(signature)
        } catch (e: Exception) {
            false
        }
    }

    data class EncryptedPayload(val nonce: ByteArray, val ciphertext: ByteArray) {
        fun toCombined(): ByteArray = nonce + ciphertext
        companion object {
            fun fromCombined(combined: ByteArray): EncryptedPayload {
                val nonce = combined.copyOfRange(0, GCM_NONCE_LENGTH)
                val ciphertext = combined.copyOfRange(GCM_NONCE_LENGTH, combined.size)
                return EncryptedPayload(nonce, ciphertext)
            }
        }
    }

    fun encryptAESGCM(key: ByteArray, plaintext: ByteArray, aad: ByteArray = ByteArray(0)): EncryptedPayload {
        require(key.size == 32)
        val nonce = ByteArray(GCM_NONCE_LENGTH).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(AES_ALGORITHM)
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        val ciphertext = cipher.doFinal(plaintext)
        return EncryptedPayload(nonce, ciphertext)
    }

    fun decryptAESGCM(key: ByteArray, payload: EncryptedPayload, aad: ByteArray = ByteArray(0)): ByteArray {
        require(key.size == 32)
        val cipher = Cipher.getInstance(AES_ALGORITHM)
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, payload.nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(payload.ciphertext)
    }

    fun decryptAESGCM(key: ByteArray, combined: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        return decryptAESGCM(key, EncryptedPayload.fromCombined(combined), aad)
    }

    fun hkdf(inputKeyMaterial: ByteArray, salt: ByteArray = ByteArray(0), info: ByteArray = HKDF_INFO, outputLength: Int = 32): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val prk = if (salt.isNotEmpty()) {
            mac.init(SecretKeySpec(salt, "HmacSHA256"))
            mac.doFinal(inputKeyMaterial)
        } else {
            mac.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
            mac.doFinal(inputKeyMaterial)
        }

        val blocks = ArrayList<ByteArray>()
        var t = ByteArray(0)
        var index = 1
        var generated = 0
        while (generated < outputLength) {
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t)
            mac.update(info)
            mac.update(byteArrayOf(index.toByte()))
            t = mac.doFinal()
            blocks.add(t)
            generated += t.size
            index++
        }
        val result = ByteArray(outputLength)
        var offset = 0
        for (block in blocks) {
            val len = minOf(block.size, outputLength - offset)
            System.arraycopy(block, 0, result, offset, len)
            offset += len
        }
        return result
    }

    fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    fun wipe(data: ByteArray) {
        java.util.Arrays.fill(data, 0)
    }

    fun wipe(data: CharArray) {
        java.util.Arrays.fill(data, '\u0000')
    }

    fun encodeKey(key: ByteArray): String {
        return Base64.encodeToString(key, Base64.NO_WRAP)
    }

    fun decodeKey(encoded: String): ByteArray {
        return Base64.decode(encoded, Base64.NO_WRAP)
    }

    fun computeSafetyNumber(myIdentityPub: ByteArray, theirIdentityPub: ByteArray): String {
        val (first, second) = if (myIdentityPub.lexCompare(theirIdentityPub) <= 0) {
            myIdentityPub to theirIdentityPub
        } else {
            theirIdentityPub to myIdentityPub
        }
        val hash = sha256(first + second)
        val sb = StringBuilder()
        for (i in 0 until 12) {
            val byteIndex = i % hash.size
            sb.append((hash[byteIndex].toInt() and 0xFF) % 10)
            if (i == 3 || i == 7) sb.append(' ')
        }
        return sb.toString()
    }

    fun padWithLengthPrefix(data: ByteArray, targetSize: Int = 4096): ByteArray {
        val len = data.size
        val lenPrefix = byteArrayOf(
            (len shr 24).toByte(),
            (len shr 16).toByte(),
            (len shr 8).toByte(),
            len.toByte()
        )
        if (data.size + 4 >= targetSize) return lenPrefix + data
        val result = ByteArray(targetSize)
        System.arraycopy(lenPrefix, 0, result, 0, 4)
        System.arraycopy(data, 0, result, 4, data.size)
        SecureRandom().nextBytes(result.copyOfRange(4 + data.size, targetSize))
        return result
    }

    fun unpadWithLengthPrefix(data: ByteArray): ByteArray {
        if (data.size < 4) return data
        val originalLen = ((data[0].toInt() and 0xFF) shl 24) or
                ((data[1].toInt() and 0xFF) shl 16) or
                ((data[2].toInt() and 0xFF) shl 8) or
                (data[3].toInt() and 0xFF)
        if (originalLen <= 0 || originalLen > data.size - 4) return data
        return data.copyOfRange(4, 4 + originalLen)
    }

    fun randomBytes(length: Int): ByteArray {
        return ByteArray(length).also { SecureRandom().nextBytes(it) }
    }

    fun randomKey32(): ByteArray = randomBytes(32)

    private fun ByteArray.lexCompare(other: ByteArray): Int {
        val minLen = minOf(this.size, other.size)
        for (i in 0 until minLen) {
            val cmp = (this[i].toInt() and 0xFF) - (other[i].toInt() and 0xFF)
            if (cmp != 0) return cmp
        }
        return this.size - other.size
    }
}