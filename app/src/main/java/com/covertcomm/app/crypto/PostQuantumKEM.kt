package com.covertcomm.app.crypto

import android.util.Base64
import org.bouncycastle.crypto.SecretWithEncapsulation
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters
import java.security.SecureRandom

object PostQuantumKEM {

    private val rng = SecureRandom()

    data class PQKeyPair(
        val publicKey: ByteArray,
        val privateKey: ByteArray
    )

    data class PQEncapsulation(
        val ciphertext: ByteArray,
        val sharedSecret: ByteArray
    )

    fun generateKeyPair(): PQKeyPair {
        val gen = KyberKeyPairGenerator()
        gen.init(KyberKeyGenerationParameters(rng, KyberParameters.kyber768))
        val pair = gen.generateKeyPair()
        val pub = (pair.public as KyberPublicKeyParameters).getEncoded()
        val priv = (pair.private as KyberPrivateKeyParameters).getEncoded()
        return PQKeyPair(pub, priv)
    }

    fun encapsulate(theirPublicKey: ByteArray): PQEncapsulation {
        val pubKey = KyberPublicKeyParameters(KyberParameters.kyber768, theirPublicKey)
        val generator = KyberKEMGenerator(rng)
        val secret: SecretWithEncapsulation = generator.generateEncapsulated(pubKey)
        val ss = secret.secret
        val ct = secret.encapsulation
        return PQEncapsulation(ct, ss)
    }

    fun decapsulate(myPrivateKey: ByteArray, ciphertext: ByteArray): ByteArray {
        val privKey = KyberPrivateKeyParameters(KyberParameters.kyber768, myPrivateKey)
        val extractor = KyberKEMExtractor(privKey)
        val ss = extractor.extractSecret(ciphertext)
        val result = ss.copyOf()
        CryptoUtils.wipe(ss)
        return result
    }

    fun encodePublicKey(key: ByteArray): String {
        return Base64.encodeToString(key, Base64.NO_WRAP)
    }

    fun decodePublicKey(encoded: String): ByteArray {
        return Base64.decode(encoded, Base64.NO_WRAP)
    }

    fun wipeKeyPair(kp: PQKeyPair) {
        CryptoUtils.wipe(kp.publicKey)
        CryptoUtils.wipe(kp.privateKey)
    }
}