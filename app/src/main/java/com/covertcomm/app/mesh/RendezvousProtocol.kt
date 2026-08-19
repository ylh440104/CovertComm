package com.covertcomm.app.mesh

import com.covertcomm.app.crypto.CryptoUtils
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

object RendezvousProtocol {

    private const val ARGON2_ITERATIONS = 3
    private const val ARGON2_MEMORY = 65536
    private const val ARGON2_PARALLELISM = 1
    private const val ARGON2_KEY_LENGTH = 32
    private const val SALT_LENGTH = 8
    private const val CHALLENGE_LENGTH = 2
    private const val WINDOW_SECONDS = 45L
    private const val MAX_CONNECTION_ATTEMPTS = 2

    data class RendezvousChallenge(
        val salt: ByteArray,
        val challenge: ByteArray,
        val timestamp: Long
    )

    data class RendezvousSession(
        val passphrase: String,
        val mySalt: ByteArray,
        val myChallenge: ByteArray,
        val windowEnd: Long,
        var attempts: Int = 0,
        val allowedMacs: MutableSet<String> = mutableSetOf()
    )

    fun generateChallenge(passphrase: String): RendezvousChallenge {
        val salt = ByteArray(SALT_LENGTH)
        SecureRandom().nextBytes(salt)
        val derived = argon2id(passphrase, salt)
        val challenge = derived.copyOfRange(0, CHALLENGE_LENGTH)
        return RendezvousChallenge(salt, challenge, System.currentTimeMillis())
    }

    fun verifyChallenge(passphrase: String, salt: ByteArray, expectedChallenge: ByteArray): Boolean {
        val derived = argon2id(passphrase, salt)
        val calculated = derived.copyOfRange(0, CHALLENGE_LENGTH)
        val result = calculated.contentEquals(expectedChallenge)
        CryptoUtils.wipe(derived)
        return result
    }

    fun createSession(passphrase: String): RendezvousSession {
        val challenge = generateChallenge(passphrase)
        return RendezvousSession(
            passphrase,
            challenge.salt,
            challenge.challenge,
            System.currentTimeMillis() + WINDOW_SECONDS * 1000
        )
    }

    fun isWindowValid(session: RendezvousSession): Boolean =
        System.currentTimeMillis() < session.windowEnd

    fun shouldAllowConnection(session: RendezvousSession, mac: String): Boolean {
        if (!isWindowValid(session)) return false
        if (session.allowedMacs.contains(mac)) return true
        if (session.attempts >= MAX_CONNECTION_ATTEMPTS) return false
        session.attempts++
        session.allowedMacs.add(mac)
        return true
    }

    fun generateAdvertiseData(session: RendezvousSession): ByteArray {
        val data = ByteArray(session.mySalt.size + session.myChallenge.size)
        System.arraycopy(session.mySalt, 0, data, 0, session.mySalt.size)
        System.arraycopy(session.myChallenge, 0, data, session.mySalt.size, session.myChallenge.size)
        return data
    }

    fun parseAdvertiseData(data: ByteArray): Pair<ByteArray, ByteArray>? {
        if (data.size < SALT_LENGTH + CHALLENGE_LENGTH) return null
        val salt = data.copyOfRange(0, SALT_LENGTH)
        val challenge = data.copyOfRange(SALT_LENGTH, SALT_LENGTH + CHALLENGE_LENGTH)
        return salt to challenge
    }

    fun computeRemoteChallenge(passphrase: String, remoteSalt: ByteArray): ByteArray {
        val derived = argon2id(passphrase, remoteSalt)
        val challenge = derived.copyOfRange(0, CHALLENGE_LENGTH).copyOf()
        CryptoUtils.wipe(derived)
        return challenge
    }

    private fun argon2id(passphrase: String, salt: ByteArray): ByteArray {
        return try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val spec = PBEKeySpec(
                passphrase.toCharArray(),
                salt,
                ARGON2_ITERATIONS * 10000,
                ARGON2_KEY_LENGTH * 8
            )
            val key = factory.generateSecret(spec)
            val result = key.encoded
            spec.clearPassword()
            result
        } catch (e: Exception) {
            val derived = CryptoUtils.hkdf(
                passphrase.toByteArray(),
                salt,
                "rendezvous_v1".toByteArray(),
                ARGON2_KEY_LENGTH
            )
            derived
        }
    }

    fun wipeSession(session: RendezvousSession) {
        CryptoUtils.wipe(session.mySalt)
        CryptoUtils.wipe(session.myChallenge)
        val chars = session.passphrase.toCharArray()
        java.util.Arrays.fill(chars, '\u0000')
    }
}