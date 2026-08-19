package com.covertcomm.app.security

object NativeGuard {

    init {
        System.loadLibrary("covertcomm_native")
    }

    external fun secureWipe(data: ByteArray): ByteArray
    external fun secureRandomBytes(length: Int): ByteArray
    external fun getNativeVersion(): String
    external fun initAntiDebug()
    external fun initScramble()
    external fun purge()
    external fun xorEncrypt(data: ByteArray, key: ByteArray): ByteArray
    external fun splitKey(key: ByteArray): ByteArray
    external fun unscrambleKey(scrambled: ByteArray): ByteArray
    external fun aesEncrypt(plaintext: ByteArray, key: ByteArray): ByteArray
    external fun aesDecrypt(ciphertext: ByteArray, key: ByteArray): ByteArray
    external fun integrityCheck(): Int
}