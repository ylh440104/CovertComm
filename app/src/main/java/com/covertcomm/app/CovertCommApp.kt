package com.covertcomm.app

import android.app.Application
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class CovertCommApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Security.addProvider(BouncyCastleProvider())
    }
}