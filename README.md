# CovertComm

Offline & online, end-to-end encrypted P2P messaging for Android.

**No registration, no phone number, no account, no server required.**

## Features

### Transport Modes
| Mode | Range | Description |
|------|-------|-------------|
| **Hotspot** | ~100m | Hidden SSID Wi-Fi hotspot, TCP socket (Host/Client) |
| **Rendezvous** | ~50m | BLE with passphrase-based pairing |
| **BLE Long Range** | ~500m | BLE Coded PHY for extended range |
| **LoRa (USB)** | 5-15km | USB LoRa module (RFM95/96) |
| **Wi-Fi Aware** | ~100m | NAN direct link (device support required) |
| **Wi-Fi Direct** | ~200m | P2P group direct connection |
| **Cellular** | Global | MQTT relay via SIM (custom broker support) |

### Encryption
- **X3DH** key agreement (3x X25519 DH) + **ML-KEM-768** post-quantum
- **Double Ratchet** (forward secrecy + post-compromise security)
- **AES-256-GCM** per-message encryption
- **Ed25519** identity signatures
- **HKDF-SHA256** key derivation
- **NestedCipher** custom Feistel + XOR + AES-GCM layered encryption (Cellular mode)

### Security
- Auto-handshake: first message automatically initiates X3DH
- Safety Number verification (face-to-face fingerprint comparison)
- Burn-after-read mode (auto-delete after read)
- Secure memory wipe on disconnect/exit/background
- Anti-debugging, anti-root, anti-Frida runtime detection
- Anti-tampering APK integrity check
- screenshots blocked (FLAG_SECURE) on main version
- Screenshot-allowed version available separately

## Building

### Requirements
- Android Studio Hedgehog 2024.1+ (or AGP 8.9+ compatible)
- JDK 17+
- Android SDK 34+ (compileSdk 34, minSdk 26)

### Build Steps
```bash
git clone https://github.com/ylh440104/CovertComm.git
cd CovertComm
./gradlew assembleDebug
```

The APK will be at `app/build/outputs/apk/debug/app-debug.apk`.

### Native Library
The native anti-tamper / anti-debug library is pre-built at `app/src/main/jniLibs/`. To rebuild:
```bash
bash build_native.sh
```
Requires: Android NDK 29+.

## Usage

### Cellular (Global)
1. Open app → tap 📡 icon → select **Cellular**
2. Choose broker: **No (default)** or enter custom MQTT broker
3. Enter a **passphrase** (shared secret) → tap **Create** or **Join**
4. Both devices with same passphrase are automatically connected
5. Send encrypted messages globally

### Hotspot (Local)
1. Device A: select **Hotspot** → app creates hidden hotspot
2. Device B: connect to A's hotspot via Wi-Fi settings
3. Device B: enter A's IP (default 192.168.43.1) → tap **Join**
4. X3DH handshake completes automatically on first message

### BLE Rendezvous
1. Select **Rendezvous** → enter passphrase
2. Both devices tap **Create** simultaneously
3. Apps auto-discover each other via BLE + passphrase
4. First message triggers automatic key exchange

### Burn After Read
Tap the 🔥 icon to toggle. Messages marked with 🔥 will display a countdown and auto-delete.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CovertComm App                        │
├──────────────┬──────────────┬────────────────────────────┤
│  Transport   │  Crypto      │  Security                  │
│  Layer       │  Layer       │  Layer                     │
├──────────────┼──────────────┼────────────────────────────┤
│ HotspotTransport     │ X3DH         │ SecurityGuard          │
│ BLEMeshTransport    │ DoubleRatchet│ NativeGuard (C++)      │
│ LoRaTransport       │ IdentityManager│ Anti-debug/root      │
│ WifiAwareTransport  │ PostQuantumKEM│ Anti-tamper           │
│ WifiDirectTransport │ NestedCipher │ Memory wipe            │
│ CellularTransport   │ CryptoUtils  │ FLAG_SECURE            │
└──────────────┴──────────────┴────────────────────────────┘
```

## Project Structure

```
CovertComm/
├── app/
│   └── src/main/
│       ├── java/com/covertcomm/app/
│       │   ├── CovertCommApp.kt
│       │   ├── crypto/          # Encryption algorithms
│       │   │   ├── CryptoUtils.kt
│       │   │   ├── DoubleRatchet.kt
│       │   │   ├── IdentityManager.kt
│       │   │   ├── NestedCipher.kt
│       │   │   ├── PostQuantumKEM.kt
│       │   │   └── X3DH.kt
│       │   ├── mesh/            # Mesh routing & BLE
│       │   │   ├── BLEMeshTransport.kt
│       │   │   ├── MeshFrame.kt
│       │   │   ├── MeshRouter.kt
│       │   │   └── RendezvousProtocol.kt
│       │   ├── security/        # Anti-tamper, anti-debug
│       │   │   ├── NativeGuard.kt
│       │   │   └── SecurityGuard.kt
│       │   ├── transport/       # Transport layers
│       │   │   ├── CellularTransport.kt
│       │   │   ├── HotspotTransport.kt
│       │   │   ├── LoRaTransport.kt
│       │   │   ├── WifiAwareTransport.kt
│       │   │   └── WifiDirectTransport.kt
│       │   └── ui/              # Compose UI
│       │       └── MainActivity.kt
│       ├── cpp/                 # Native C++ code
│       │   ├── CMakeLists.txt
│       │   └── native_guard.cpp
│       ├── jniLibs/             # Pre-built native libraries
│       │   ├── arm64-v8a/
│       │   └── armeabi-v7a/
│       ├── res/                 # Resources
│       └── AndroidManifest.xml
├── build.gradle.kts
├── settings.gradle.kts
├── gradle.properties
└── gradle/wrapper/
```

## Security Notes

- **No persistence**: all keys are in-memory only, wiped on exit
- **No auto-discovery**: hidden hotspot prevents third-party detection
- **Memory wipe**: all sensitive buffers zeroed after use (Arrays.fill)
- **Anti-forensics**: app excluded from recents list, no history saved
- **Root detection**: app exits on root detection (customizable behavior)
- **Session isolation**: each session has independent ratchet state

## License

MIT
