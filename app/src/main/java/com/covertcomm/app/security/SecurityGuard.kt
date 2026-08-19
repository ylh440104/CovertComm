package com.covertcomm.app.security

import android.app.Activity
import android.os.Build
import android.view.WindowManager
import androidx.core.view.WindowInsetsControllerCompat
import java.security.SecureRandom

object SecurityGuard {

    private var lastAppliedFlags = 0

    fun apply(activity: Activity) {
        NativeGuard.initAntiDebug()
        NativeGuard.initScramble()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            activity.setRecentsScreenshotEnabled(false)
        }

        val window = activity.window
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val controller = WindowInsetsControllerCompat(window, window.decorView)
            controller.systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
        }

        lastAppliedFlags = window.attributes.flags
    }

    fun verify(activity: Activity): Boolean {
        val flags = activity.window.attributes.flags
        return (flags and WindowManager.LayoutParams.FLAG_SECURE) != 0
    }

    fun wipeMemory(buffer: ByteArray) {
        java.util.Arrays.fill(buffer, 0)
    }

    fun wipeMemory(buffer: CharArray) {
        java.util.Arrays.fill(buffer, '\u0000')
    }

    fun wipeMemory(vararg buffers: ByteArray) {
        for (b in buffers) {
            java.util.Arrays.fill(b, 0)
        }
    }

    fun secureRandomBytes(length: Int): ByteArray {
        val bytes = ByteArray(length)
        SecureRandom.getInstanceStrong().nextBytes(bytes)
        return bytes
    }

    fun secureRandomString(length: Int): String {
        val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        val sb = StringBuilder(length)
        val random = SecureRandom()
        for (i in 0 until length) {
            sb.append(chars[random.nextInt(chars.length)])
        }
        val result = sb.toString()
        val charArray = CharArray(length)
        sb.getChars(0, length, charArray, 0)
        java.util.Arrays.fill(charArray, '\u0000')
        return result
    }

    fun secureRandomSSID(): String {
        return secureRandomString(8)
    }

    fun secureRandomPassword(): String {
        return secureRandomString(16)
    }

    fun wipeStringBuilder(sb: StringBuilder) {
        for (i in 0 until sb.length) {
            sb.setCharAt(i, '\u0000')
        }
        sb.setLength(0)
    }

    fun onAppBackgrounded(activity: Activity) {
        val window = activity.window
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }

    fun onAppForegrounded(activity: Activity) {
        apply(activity)
    }
}