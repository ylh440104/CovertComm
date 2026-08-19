package com.covertcomm.app.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

object NestedCipher {

    private const val BLOCK = 16
    private const val ROUNDS = 24
    private const val GCM_TAG = 128
    private const val NONCE_LEN = 12
    private const val INFO = "CovertComm-Nested-v1"

    class Session(val keyK: ByteArray, val keyP: ByteArray, val keyX: ByteArray, val aad: ByteArray) {
        fun wipe() {
            CryptoUtils.wipe(keyK); CryptoUtils.wipe(keyP); CryptoUtils.wipe(keyX); CryptoUtils.wipe(aad)
        }
    }

    fun derive(password: String): Session {
        val pass = password.toByteArray()
        val salt = CryptoUtils.sha256(("cc-salt:" + password).toByteArray())
        val seed = CryptoUtils.hkdf(pass, salt, INFO.toByteArray(), 64)
        CryptoUtils.wipe(pass)
        val k = seed.copyOfRange(0, 32)
        val p = seed.copyOfRange(32, 48)
        val x = seed.copyOfRange(48, 64)
        CryptoUtils.wipe(seed); CryptoUtils.wipe(salt)
        val aad = CryptoUtils.sha256(("cc-aad:" + password).toByteArray())
        return Session(k, p, x, aad)
    }

    fun sessionId(password: String): String {
        val h = CryptoUtils.sha256(("cc-session:" + password).toByteArray())
        return h.copyOfRange(0, 6).joinToString("") { "%02x".format(it) }
    }

    fun encrypt(session: Session, data: ByteArray): ByteArray {
        val lenPrefixed = ByteArray(data.size + 2)
        lenPrefixed[0] = (data.size shr 8).toByte()
        lenPrefixed[1] = (data.size and 0xFF).toByte()
        System.arraycopy(data, 0, lenPrefixed, 2, data.size)
        val feisted = feistel(session.keyP, lenPrefixed)
        CryptoUtils.wipe(lenPrefixed)
        val xored = xorSpread(session.keyX, feisted)
        CryptoUtils.wipe(feisted)
        val nonce = CryptoUtils.randomBytes(NONCE_LEN)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(session.keyK, "AES"), GCMParameterSpec(GCM_TAG, nonce))
        cipher.updateAAD(session.aad)
        val ct = cipher.doFinal(xored)
        CryptoUtils.wipe(xored)
        return nonce + ct
    }

    fun decrypt(session: Session, data: ByteArray): ByteArray? {
        if (data.size < NONCE_LEN + BLOCK) return null
        val nonce = data.copyOfRange(0, NONCE_LEN)
        val ct = data.copyOfRange(NONCE_LEN, data.size)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(session.keyK, "AES"), GCMParameterSpec(GCM_TAG, nonce))
            cipher.updateAAD(session.aad)
            val xored = cipher.doFinal(ct)
            val feisted = unXorSpread(session.keyX, xored)
            CryptoUtils.wipe(xored)
            val out = unFeistel(session.keyP, feisted)
            CryptoUtils.wipe(feisted)
            if (out.size < 2) return null
            val origLen = ((out[0].toInt() and 0xFF) shl 8) or (out[1].toInt() and 0xFF)
            if (origLen < 0 || origLen > out.size - 2) return null
            out.copyOfRange(2, 2 + origLen)
        } catch (e: Exception) {
            null
        }
    }

    private fun subKey(key: ByteArray, round: Int): ByteArray {
        val k = ByteArray(BLOCK)
        for (i in 0 until BLOCK) {
            var v = (key[i % key.size].toInt() and 0xFF) xor (round * 31) xor (i * 7)
            v = (v xor (v shl 5) xor (v ushr 2)) and 0xFF
            k[i] = v.toByte()
        }
        return k
    }

    private fun feistelF(r: ByteArray, sub: ByteArray): ByteArray {
        val out = ByteArray(r.size)
        var acc = 0
        for (i in r.indices) {
            acc = (acc + (r[i].toInt() and 0xFF) + (sub[i % sub.size].toInt() and 0xFF)) and 0xFF
            var v = acc xor (r[i].toInt() and 0xFF)
            v = (v xor (v shl 3) xor (v ushr 4) xor (sub[(i + 5) % sub.size].toInt() and 0xFF)) and 0xFF
            out[i] = v.toByte()
        }
        return out
    }

    private fun feistel(key: ByteArray, data: ByteArray): ByteArray {
        val padded = if (data.size % BLOCK == 0) data.copyOf() else data.copyOf((data.size / BLOCK + 1) * BLOCK)
        val rounds = (ROUNDS * 2) + (padded.size / BLOCK)
        for (r in 0 until rounds) {
            val sub = subKey(key, r)
            for (b in 0 until padded.size step BLOCK) {
                val l = padded.copyOfRange(b, b + BLOCK / 2)
                val rr = padded.copyOfRange(b + BLOCK / 2, b + BLOCK)
                val f = feistelF(rr, sub)
                System.arraycopy(rr, 0, padded, b, l.size)
                for (i in l.indices) padded[b + l.size + i] = (l[i].toInt() xor f[i].toInt()).toByte()
                CryptoUtils.wipe(l); CryptoUtils.wipe(rr); CryptoUtils.wipe(f)
            }
            CryptoUtils.wipe(sub)
        }
        return padded
    }

    private fun unFeistel(key: ByteArray, data: ByteArray): ByteArray {
        val out = data.copyOf()
        val rounds = (ROUNDS * 2) + (out.size / BLOCK)
        for (r in rounds - 1 downTo 0) {
            val sub = subKey(key, r)
            for (b in 0 until out.size step BLOCK) {
                val l = out.copyOfRange(b, b + BLOCK / 2)
                val rr = out.copyOfRange(b + BLOCK / 2, b + BLOCK)
                val f = feistelF(l, sub)
                for (i in l.indices) out[b + i] = (rr[i].toInt() xor f[i].toInt()).toByte()
                System.arraycopy(l, 0, out, b + l.size, l.size)
                CryptoUtils.wipe(l); CryptoUtils.wipe(rr); CryptoUtils.wipe(f)
            }
            CryptoUtils.wipe(sub)
        }
        return out
    }

    private fun xorSpread(key: ByteArray, data: ByteArray): ByteArray {
        val out = data.copyOf()
        var carry = 0x5A
        for (i in out.indices) {
            val original = out[i].toInt() and 0xFF
            out[i] = (original xor (key[i % key.size].toInt() and 0xFF) xor carry).toByte()
            carry = (carry + original + (i * 17)) and 0xFF
        }
        return out
    }

    private fun unXorSpread(key: ByteArray, data: ByteArray): ByteArray {
        val out = data.copyOf()
        var carry = 0x5A
        for (i in out.indices) {
            val enc = out[i].toInt() and 0xFF
            val original = enc xor (key[i % key.size].toInt() and 0xFF) xor carry
            out[i] = original.toByte()
            carry = (carry + original + (i * 17)) and 0xFF
        }
        return out
    }
}