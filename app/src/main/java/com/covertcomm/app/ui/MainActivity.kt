package com.covertcomm.app.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.CountDownTimer
import android.util.Log
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.ui.draw.clip
import android.view.inputmethod.InputMethodManager
import android.content.Context
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.focus.onFocusChanged
import androidx.core.view.WindowCompat
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.covertcomm.app.crypto.CryptoUtils
import com.covertcomm.app.crypto.DoubleRatchet
import com.covertcomm.app.crypto.IdentityManager
import com.covertcomm.app.crypto.PostQuantumKEM
import com.covertcomm.app.crypto.X3DH
import com.covertcomm.app.mesh.BLEMeshTransport
import com.covertcomm.app.mesh.MeshRouter
import com.covertcomm.app.security.SecurityGuard
import com.covertcomm.app.transport.CellularTransport
import com.covertcomm.app.transport.HotspotTransport
import com.covertcomm.app.transport.LoRaTransport
import com.covertcomm.app.transport.WifiAwareTransport
import com.covertcomm.app.transport.WifiDirectTransport
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

data class ChatMessage(
    val text: String,
    val isOutgoing: Boolean,
    val timestamp: Long = System.currentTimeMillis(),
    val burnAfterRead: Boolean = false
)

private val WarmDark = darkColorScheme(
    primary = Color(0xFFD4A574),
    onPrimary = Color(0xFF1A1510),
    primaryContainer = Color(0xFF3D3024),
    onPrimaryContainer = Color(0xFFF0DCC6),
    secondary = Color(0xFFC97B6B),
    onSecondary = Color(0xFF1A0E0B),
    background = Color(0xFF1A1614),
    onBackground = Color(0xFFF5EDE0),
    surface = Color(0xFF2B2420),
    onSurface = Color(0xFFF5EDE0),
    surfaceVariant = Color(0xFF3A3028),
    onSurfaceVariant = Color(0xFFCBB8A6),
    surfaceContainer = Color(0xFF231D1A),
    outline = Color(0xFF5C4C3E),
    error = Color(0xFFD46A5A)
)

class MainActivity : ComponentActivity() {

    enum class Mode { NONE, HOTSPOT, BLE_MESH, LORA, AWARE, P2P, CELLULAR }

    private lateinit var identityManager: IdentityManager
    private lateinit var ratchet: DoubleRatchet
    private lateinit var hotspotTransport: HotspotTransport
    private lateinit var bleTransport: BLEMeshTransport
    private var loraTransport: LoRaTransport? = null
    private var wifiAwareTransport: WifiAwareTransport? = null
    private var wifiDirectTransport: WifiDirectTransport? = null
    private var cellularTransport: CellularTransport? = null
    private lateinit var meshRouter: MeshRouter

    private var burnAfterRead = false
    private var activeMode = Mode.NONE
    private var bleInitialized = false
    private var countdownTimer: CountDownTimer? = null
    private var burnCountdownTimer: CountDownTimer? = null
    private var pendingHandshakeBundle: X3DH.PreKeyBundle? = null
    private var pendingPQEncapsulated: ByteArray? = null
    private var pendingPQDecapsulated: ByteArray? = null

    private var pendingOutgoing: String? = null
    private val messages = mutableStateListOf<ChatMessage>()
    private val statusConnected = mutableStateOf(false)
    private val statusText = mutableStateOf("Ready")
    private val identityShortFP = mutableStateOf("----")
    private val burnEnabled = mutableStateOf(false)
    private val modeSheetVisible = mutableStateOf(false)
    private val connectPanelVisible = mutableStateOf(false)
    private val rendezvousPanelVisible = mutableStateOf(false)
    private val countdownText = mutableStateOf("")
    private val countdownVisible = mutableStateOf(false)
    private val hostIpInput = mutableStateOf("")
    private val passphraseInput = mutableStateOf("")
    private val passphraseFocused = mutableStateOf(false)
    private val showBrokerDialog = mutableStateOf(false)
    private val customBrokerInput = mutableStateOf("")
    private val messageInput = mutableStateOf("")

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { result ->
        if (result.values.all { it }) initBLE()
        else messages.add(ChatMessage("[Permissions required]", false))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.i("CovertComm", "onCreate v2.0.0-log pid=${android.os.Process.myPid()}")
        enableEdgeToEdge()
        window.statusBarColor = android.graphics.Color.TRANSPARENT
        window.navigationBarColor = android.graphics.Color.TRANSPARENT
        setContent {
            MaterialTheme(colorScheme = WarmDark) {
                Surface(modifier = Modifier.fillMaxSize(), color = Color.Transparent) {
                    Box(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Color(0xFF1E1A17), Color(0xFF14100E))))) {
                        MainScreen()
                    }
                }
            }
        }
        requestPermissions()
        thread {
            SecurityGuard.apply(this)
            identityManager = IdentityManager(this)
            ratchet = DoubleRatchet(identityManager)
            meshRouter = MeshRouter(getMyFP())
            hotspotTransport = HotspotTransport(this, identityManager)
            bleTransport = BLEMeshTransport(this, identityManager)
            loraTransport = LoRaTransport(this, identityManager)
            wifiAwareTransport = WifiAwareTransport(this, identityManager)
            wifiDirectTransport = WifiDirectTransport(this, identityManager)
            cellularTransport = CellularTransport(this, identityManager)
            runOnUiThread {
                identityShortFP.value = identityManager.getShortFingerprint()
                hotspotTransport.listener = hotspotListener
                bleTransport.listener = bleListener
                loraTransport?.listener = loraListener
                wifiAwareTransport?.listener = awareListener
                wifiDirectTransport?.listener = p2pListener
                cellularTransport?.listener = cellularListener
                meshRouter.setListener(meshRouterListener)
            }
        }
    }

    @Composable
    private fun MainScreen() {
        val listState = rememberLazyListState()
        LaunchedEffect(messages.size) {
            if (messages.isNotEmpty()) listState.scrollToItem(messages.size - 1)
        }
        Box(Modifier.fillMaxSize()) {
            GlowAccent()
            Column(Modifier.fillMaxSize().imePadding()) {
                StatusBar()
                if (connectPanelVisible.value) ConnectBar()
                if (rendezvousPanelVisible.value) RendezvousBar()
                MessageList(listState)
                if (!passphraseFocused.value) InputBar()
            }
            if (modeSheetVisible.value) ModeSheet()
            if (showBrokerDialog.value) BrokerDialog()
        }
    }

    @Composable
    private fun GlowAccent() {
        Box(Modifier.fillMaxSize()) {
            Box(Modifier.align(Alignment.TopEnd).size(220.dp).offset(x = 60.dp, y = (-80).dp)
                .background(Brush.radialGradient(listOf(Color(0x5567D9C4), Color.Transparent)), CircleShape))
            Box(Modifier.align(Alignment.BottomStart).size(260.dp).offset(x = (-70).dp, y = 60.dp)
                .background(Brush.radialGradient(listOf(Color(0x334A9EFF), Color.Transparent)), CircleShape))
        }
    }

    @Composable
    private fun StatusBar() {
        Surface(color = Color.Transparent) {
            Row(Modifier.fillMaxWidth().statusBarsPadding().padding(horizontal = 20.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(9.dp).background(if (statusConnected.value) Color(0xFFC9A87C) else Color(0xFF5C4C3E), CircleShape))
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(modeName(), fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF5EDE0))
                    Text(statusText.value, fontSize = 11.sp, color = Color(0xFFCBB8A6), fontWeight = FontWeight.Medium)
                }
                Surface(shape = RoundedCornerShape(50), color = Color(0x1AD4A574)) {
                    Text(identityShortFP.value, fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = Color(0xFFD4A574), modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp))
                }
                Spacer(Modifier.width(8.dp))
                IconButton(onClick = { burnAfterRead = !burnAfterRead; burnEnabled.value = burnAfterRead; messages.add(ChatMessage("[BURN ${if (burnAfterRead) "ON" else "OFF"}]", false)) }, modifier = Modifier.size(36.dp)) {
                    Icon(Icons.Default.LocalFireDepartment, null, Modifier.size(18.dp), tint = if (burnEnabled.value) Color(0xFFD46A5A) else Color(0xFF5C4C3E))
                }
                IconButton(onClick = { modeSheetVisible.value = true }, modifier = Modifier.size(36.dp).background(Color(0x1AD4A574), CircleShape)) {
                    Icon(Icons.Default.Cast, null, Modifier.size(18.dp), tint = Color(0xFFD4A574))
                }
            }
        }
    }

    private fun modeName(): String = when (activeMode) {
        Mode.NONE -> "CovertComm"
        Mode.HOTSPOT -> "Hotspot"
        Mode.BLE_MESH -> if (statusText.value == "LONG RANGE") "BLE Long Range" else "BLE Rendezvous"
        Mode.LORA -> "LoRa"
        Mode.AWARE -> "Wi-Fi Aware"
        Mode.P2P -> "Wi-Fi Direct"
        Mode.CELLULAR -> "Cellular"
    }

    @Composable
    private fun ModeSheet() {
        Box(Modifier.fillMaxSize().background(Color(0xAA020A12)).clickable { modeSheetVisible.value = false }) {
                Surface(
                    modifier = Modifier.align(Alignment.CenterEnd).fillMaxHeight().fillMaxWidth(0.86f),
                    color = Color(0xFF231D1A),
                    shape = RoundedCornerShape(topStart = 28.dp, bottomStart = 28.dp)
                ) {
                    Column(Modifier.fillMaxSize()) {
                        Row(Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 22.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text("LINK", fontSize = 13.sp, fontWeight = FontWeight.Bold, letterSpacing = 2.sp, color = Color(0xFFD4A574))
                                Text("choose a route", fontSize = 11.sp, color = Color(0xFFCBB8A6), modifier = Modifier.padding(top = 2.dp))
                            }
                            Box(Modifier.size(36.dp).clickable { modeSheetVisible.value = false }, contentAlignment = Alignment.Center) {
                                Text("\u2715", fontSize = 16.sp, color = Color(0xFFCBB8A6))
                            }
                        }
                        HorizontalDivider(color = Color(0x1AD4A574), thickness = 1.dp)
                        LazyColumn(Modifier.weight(1f).padding(horizontal = 14.dp, vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            item { SheetCard("Hotspot", "TCP over Wi-Fi hotspot", Icons.Default.Router, Mode.HOTSPOT) { activeMode = Mode.HOTSPOT; hotspotTransport?.startAsHost(); connectPanelVisible.value = true; rendezvousPanelVisible.value = false; statusText.value = "Hosting"; statusConnected.value = false; modeSheetVisible.value = false } }
                            item { SheetCard("Rendezvous", "BLE + passphrase", Icons.Default.Bluetooth, Mode.BLE_MESH) { activeMode = Mode.BLE_MESH; rendezvousPanelVisible.value = true; connectPanelVisible.value = false; statusText.value = "Rendezvous"; statusConnected.value = false; modeSheetVisible.value = false } }
                            item { SheetCard("BLE Long Range", "Coded PHY ~500m", Icons.Default.NearMe, Mode.BLE_MESH) { activeMode = Mode.BLE_MESH; rendezvousPanelVisible.value = true; connectPanelVisible.value = false; statusText.value = "LONG RANGE"; statusConnected.value = false; modeSheetVisible.value = false } }
                            item { SheetCard("LoRa (USB)", "RF module 5-15km", Icons.Default.Usb, Mode.LORA) { activeMode = Mode.LORA; val ok = loraTransport?.init(meshRouter) ?: false; if (ok) messages.add(ChatMessage("[LoRa ready]", false)) else messages.add(ChatMessage("[LoRa no module]", false)); connectPanelVisible.value = false; rendezvousPanelVisible.value = false; statusText.value = "LoRa"; statusConnected.value = false; modeSheetVisible.value = false } }
                            item { SheetCard("Wi-Fi Aware", "NAN direct link", Icons.Default.Wifi, Mode.AWARE) { activeMode = Mode.AWARE; val ok = wifiAwareTransport?.init(meshRouter) ?: false; if (ok) messages.add(ChatMessage("[NAN ready]", false)) else messages.add(ChatMessage("[NAN unavailable]", false)); rendezvousPanelVisible.value = true; connectPanelVisible.value = false; statusText.value = "NAN"; statusConnected.value = false; modeSheetVisible.value = false } }
                            item { SheetCard("Cellular", "Global via SIM (MQTT relay)", Icons.Default.Public, Mode.CELLULAR) { activeMode = Mode.CELLULAR; showBrokerDialog.value = true; modeSheetVisible.value = false; customBrokerInput.value = "" } }
                            item { SheetCard("Wi-Fi Direct", "P2P group direct", Icons.Default.SatelliteAlt, Mode.P2P) { activeMode = Mode.P2P; val ok = wifiDirectTransport?.init() ?: false; if (ok) messages.add(ChatMessage("[P2P ready]", false)) else messages.add(ChatMessage("[P2P unsupported]", false)); connectPanelVisible.value = true; rendezvousPanelVisible.value = false; statusText.value = "P2P"; statusConnected.value = false; modeSheetVisible.value = false } }
                        }
                    }
                }
            }
    }

    @Composable
    private fun SheetCard(name: String, desc: String, icon: ImageVector, mode: Mode, onClick: () -> Unit) {
        val selected = activeMode == mode && mode != Mode.NONE
        val accent: Long = if (selected) 0xFFD4A574 else 0xFFCBB8A6
        Surface(
            shape = RoundedCornerShape(18.dp),
            color = if (selected) Color(0x2AD4A574) else Color(0x14FFFFFF),
            modifier = Modifier.fillMaxWidth().clickable { onClick() }
        ) {
            Row(Modifier.padding(horizontal = 16.dp, vertical = 15.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(40.dp).background(if (selected) Color(0x33D4A574) else Color(0x1AFFFFFF), RoundedCornerShape(12.dp)), contentAlignment = Alignment.Center) {
                    Icon(icon, null, Modifier.size(20.dp), tint = Color(accent.toInt()))
                }
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text(name, fontSize = 15.sp, fontWeight = if (selected) FontWeight.Bold else FontWeight.SemiBold, color = Color(0xFFF5EDE0))
                    Text(desc, fontSize = 11.sp, color = Color(0xFFCBB8A6))
                }
                if (selected) {
                    Box(Modifier.size(8.dp).background(Color(0xFFD4A574), CircleShape))
                }
            }
        }
    }

    @Composable
    private fun ConnectBar() {
        Surface(color = Color.Transparent) {
            Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = hostIpInput.value, onValueChange = { hostIpInput.value = it },
                    modifier = Modifier.weight(1f), label = { Text("Host IP", fontSize = 12.sp) }, singleLine = true,
                    shape = RoundedCornerShape(14.dp), textStyle = TextStyle(fontSize = 13.sp),
                    colors = OutlinedTextFieldDefaults.colors()
                )
                Spacer(Modifier.width(8.dp))
                Button(onClick = {
                    if (activeMode == Mode.P2P) { wifiDirectTransport?.startDiscovery(); statusText.value = "Scanning"; messages.add(ChatMessage("[P2P discovering]", false)) }
                    else { val ip = hostIpInput.value.trim(); if (ip.isNotEmpty()) { connectPanelVisible.value = false; statusText.value = "Connecting"; hotspotTransport.startAsClient(ip) } }
                }, shape = RoundedCornerShape(14.dp), colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFD4A574), contentColor = Color(0xFF1A1510)), contentPadding = PaddingValues(horizontal = 18.dp, vertical = 10.dp)) { Text(if (activeMode == Mode.P2P) "Scan" else "Join", fontSize = 13.sp, fontWeight = FontWeight.Bold) }
            }
        }
    }

    @Composable
    private fun BrokerDialog() {
        val ctx = LocalContext.current
        AlertDialog(
            onDismissRequest = { showBrokerDialog.value = false; cellularTransport?.setCustomBroker("broker.emqx.io", 1883); rendezvousPanelVisible.value = true; connectPanelVisible.value = false; statusText.value = "Cellular"; statusConnected.value = false },
            title = { Text("Custom MQTT Broker", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF5EDE0)) },
            text = {
                Column {
                    Text("Use default broker (broker.emqx.io) or set your own?", fontSize = 13.sp, color = Color(0xFFCBB8A6))
                    Spacer(Modifier.height(12.dp))
                    OutlinedTextField(
                        value = customBrokerInput.value, onValueChange = { customBrokerInput.value = it },
                        modifier = Modifier.fillMaxWidth(), label = { Text("host:port (optional)", fontSize = 12.sp) }, singleLine = true,
                        shape = RoundedCornerShape(14.dp), textStyle = TextStyle(fontSize = 13.sp),
                        placeholder = { Text("e.g. mqtt.example.com:1883", fontSize = 12.sp, color = Color(0xFF5C4C3E)) },
                        colors = OutlinedTextFieldDefaults.colors()
                    )
                }
            },
            confirmButton = {
                Button(onClick = {
                    val raw = customBrokerInput.value.trim()
                    if (raw.isNotEmpty()) {
                        val parts = raw.split(":")
                        val host = parts[0].trim()
                        val port = if (parts.size > 1) parts[1].trim().toIntOrNull() ?: 1883 else 1883
                        cellularTransport?.setCustomBroker(host, port)
                    }
                    showBrokerDialog.value = false; rendezvousPanelVisible.value = true; connectPanelVisible.value = false; statusText.value = "Cellular"; statusConnected.value = false; hideKeyboard(ctx)
                }, shape = RoundedCornerShape(14.dp), colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFD4A574), contentColor = Color(0xFF1A1510))) { Text("Yes", fontWeight = FontWeight.Bold) }
            },
            dismissButton = {
                TextButton(onClick = {
                    cellularTransport?.setCustomBroker("broker.emqx.io", 1883)
                    showBrokerDialog.value = false; rendezvousPanelVisible.value = true; connectPanelVisible.value = false; statusText.value = "Cellular"; statusConnected.value = false
                }) { Text("No (default)", color = Color(0xFFCBB8A6)) }
            },
            containerColor = Color(0xFF2B2420),
            shape = RoundedCornerShape(20.dp)
        )
    }

    @Composable
    private fun RendezvousBar() {
        val ctx = LocalContext.current
        Surface(color = Color.Transparent) {
            Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
                OutlinedTextField(
                    value = passphraseInput.value, onValueChange = { passphraseInput.value = it },
                    modifier = Modifier.fillMaxWidth().onFocusChanged { passphraseFocused.value = it.isFocused }, label = { Text("Passphrase", fontSize = 12.sp) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), shape = RoundedCornerShape(14.dp), textStyle = TextStyle(fontSize = 13.sp),
                    colors = OutlinedTextFieldDefaults.colors()
                )
                Spacer(Modifier.height(6.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = {
                        val pass = passphraseInput.value.trim()
                        if (pass.isNotEmpty()) {
                            messages.clear()
                            when (activeMode) {
                                Mode.BLE_MESH -> { if (!bleInitialized) bleInitialized = bleTransport.init(meshRouter); if (bleInitialized) { bleTransport.setRendezvousPassphrase(pass); bleTransport.startRendezvous(); startCountdown(); passphraseInput.value = "" } else messages.add(ChatMessage("[Bluetooth off]", false)) }
                                Mode.AWARE -> { wifiAwareTransport?.let { it.setPassphrase(pass); it.startPublish() }; messages.add(ChatMessage("[NAN publishing]", false)); passphraseInput.value = ""; startCountdown() }
                                Mode.CELLULAR -> { cellularTransport?.let { it.setPassphrase(pass); val ok = it.init(); if (ok) { it.start(); messages.add(ChatMessage("[Waiting on channel, share same passphrase with peer]", false)) } else { messages.add(ChatMessage("[Cellular init failed]", false)) } }; passphraseInput.value = "" }
                                else -> {}
                            }
                            hideKeyboard(ctx); rendezvousPanelVisible.value = false; passphraseFocused.value = false
                        }
                    }, Modifier.weight(1f), shape = RoundedCornerShape(14.dp), colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFD4A574), contentColor = Color(0xFF1A1510)), contentPadding = PaddingValues(vertical = 10.dp)) { Text("Create", fontSize = 13.sp, fontWeight = FontWeight.Bold) }
                    Button(onClick = {
                        val pass = passphraseInput.value.trim()
                        if (pass.isNotEmpty()) {
                            when (activeMode) {
                                Mode.BLE_MESH -> { if (!bleInitialized) bleInitialized = bleTransport.init(meshRouter); if (bleInitialized) { bleTransport.setRendezvousPassphrase(pass); bleTransport.startRendezvous(); startCountdown(); passphraseInput.value = "" } else messages.add(ChatMessage("[Bluetooth off]", false)) }
                                Mode.AWARE -> { wifiAwareTransport?.let { it.setPassphrase(pass); it.startPublish() }; messages.add(ChatMessage("[NAN publishing]", false)); passphraseInput.value = ""; startCountdown() }
                                Mode.CELLULAR -> { cellularTransport?.let { it.setPassphrase(pass); val ok = it.init(); if (ok) { it.start(); messages.add(ChatMessage("[Waiting on channel, share same passphrase with peer]", false)) } else { messages.add(ChatMessage("[Cellular init failed]", false)) } }; passphraseInput.value = "" }
                                else -> {}
                            }
                            hideKeyboard(ctx); rendezvousPanelVisible.value = false; passphraseFocused.value = false
                        }
                    }, Modifier.weight(1f), shape = RoundedCornerShape(14.dp), colors = ButtonDefaults.buttonColors(containerColor = Color(0x1ACBB8A6), contentColor = Color(0xFFF5EDE0)), contentPadding = PaddingValues(vertical = 10.dp)) { Text("Join", fontSize = 13.sp, fontWeight = FontWeight.Bold) }
                    if (countdownVisible.value) Text(countdownText.value, fontSize = 12.sp, color = Color(0xFFD46A5A), modifier = Modifier.align(Alignment.CenterVertically))
                }
            }
        }
    }

    private fun hideKeyboard(context: Context) {
        val imm = context.getSystemService(Context.INPUT_METHOD_SERVICE) as? InputMethodManager
        imm?.let {
            val view = (context as? androidx.activity.ComponentActivity)?.currentFocus
            if (view != null) it.hideSoftInputFromWindow(view.windowToken, 0)
        }
    }

    @Composable
    private fun ColumnScope.MessageList(listState: androidx.compose.foundation.lazy.LazyListState) {
        val df = remember { SimpleDateFormat("HH:mm", Locale.getDefault()) }
        LazyColumn(Modifier.weight(1f).fillMaxWidth().padding(horizontal = 12.dp), state = listState) {
            items(messages) { msg ->
                Column(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalAlignment = if (msg.isOutgoing) Alignment.End else Alignment.Start) {
                    val shape = if (msg.isOutgoing)
                        RoundedCornerShape(topStart = 20.dp, topEnd = 6.dp, bottomStart = 20.dp, bottomEnd = 20.dp)
                    else
                        RoundedCornerShape(topStart = 6.dp, topEnd = 20.dp, bottomStart = 20.dp, bottomEnd = 20.dp)
                    Box(
                        modifier = Modifier
                            .widthIn(max = 290.dp)
                            .clip(shape)
                            .then(
                                if (msg.isOutgoing)
                                    Modifier.background(Brush.linearGradient(listOf(Color(0xFF4A3728), Color(0xFF3D2E1F))))
                                else
                                    Modifier.background(Color(0x1ACBB8A6))
                            )
                            .padding(horizontal = 14.dp, vertical = 10.dp)
                    ) {
                        Column {
                            Text(msg.text, fontSize = 14.sp, lineHeight = 19.sp, color = if (msg.isOutgoing) Color(0xFFF5EDE0) else Color(0xFFF5EDE0))
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.padding(top = 4.dp)) {
                                Text(df.format(Date(msg.timestamp)), fontSize = 9.sp, color = if (msg.isOutgoing) Color(0xAAF5EDE0) else Color(0xFFCBB8A6))
                                if (msg.burnAfterRead) Icon(Icons.Default.LocalFireDepartment, null, Modifier.size(10.dp), tint = if (msg.isOutgoing) Color(0xAAD46A5A) else Color(0xFFD46A5A))
                            }
                        }
                    }
                }
            }
        }
    }

    @Composable
    private fun InputBar() {
        Surface(color = Color.Transparent) {
            Row(Modifier.fillMaxWidth().height(56.dp).navigationBarsPadding().padding(horizontal = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(40.dp).clip(CircleShape).background(Color(0x1ACBB8A6)).clickable { messages.clear(); if (::ratchet.isInitialized) ratchet.wipe(); if (::meshRouter.isInitialized) meshRouter.flushRoutes() }, contentAlignment = Alignment.Center) {
                    Icon(Icons.Default.Clear, null, Modifier.size(18.dp), tint = Color(0xFFCBB8A6))
                }
                Spacer(Modifier.width(10.dp))
                OutlinedTextField(
                    value = messageInput.value, onValueChange = { messageInput.value = it },
                    modifier = Modifier.weight(1f), label = { Text("Message", fontSize = 12.sp) }, maxLines = 4,
                    shape = RoundedCornerShape(24.dp), textStyle = TextStyle(fontSize = 14.sp, color = Color(0xFFF5EDE0)),
                    colors = OutlinedTextFieldDefaults.colors(focusedTextColor = Color(0xFFF5EDE0), unfocusedTextColor = Color(0xFFF5EDE0))
                )
                Spacer(Modifier.width(10.dp))
                Box(Modifier.size(40.dp).clip(CircleShape).background(Color(0xFFD4A574)).clickable {
                    val text = messageInput.value.trim()
                    if (text.isNotEmpty()) { sendEncryptedMessage(text); messageInput.value = "" }
                }, contentAlignment = Alignment.Center) {
                    Icon(Icons.Default.Send, null, Modifier.size(18.dp), tint = Color(0xFF1A1510))
                }
            }
        }
    }

    private fun initBLE() {
        if (bleInitialized) return
        if (!::bleTransport.isInitialized) return
        bleInitialized = bleTransport.init(meshRouter)
    }

    private fun requestPermissions() {
        val perms = mutableListOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION, Manifest.permission.ACCESS_WIFI_STATE, Manifest.permission.CHANGE_WIFI_STATE, Manifest.permission.CHANGE_NETWORK_STATE, Manifest.permission.ACCESS_NETWORK_STATE)
        if (android.os.Build.VERSION.SDK_INT >= 31) { perms.add(Manifest.permission.BLUETOOTH_SCAN); perms.add(Manifest.permission.BLUETOOTH_ADVERTISE); perms.add(Manifest.permission.BLUETOOTH_CONNECT) }
        else { perms.add(Manifest.permission.BLUETOOTH); perms.add(Manifest.permission.BLUETOOTH_ADMIN) }
        if (android.os.Build.VERSION.SDK_INT >= 33) perms.add(Manifest.permission.NEARBY_WIFI_DEVICES)
        val needed = perms.filter { ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED }
        if (needed.isNotEmpty()) permissionLauncher.launch(needed.toTypedArray()) else initBLE()
    }

    private fun getMyFP(): ByteArray {
        val fp = identityManager.getShortFingerprint()
        return if (fp.length >= 2) byteArrayOf((fp[0].code and 0xFF).toByte(), (fp[1].code and 0xFF).toByte()) else ByteArray(2)
    }

    private fun startCountdown() {
        countdownTimer?.cancel(); countdownVisible.value = true
        countdownTimer = object : CountDownTimer(45000, 1000) {
            override fun onTick(m: Long) { countdownText.value = "${m / 1000}s" }
            override fun onFinish() { countdownVisible.value = false }
        }.start()
    }

    private fun sendEncryptedMessage(text: String) {
        if (activeMode == Mode.CELLULAR) {
            val data = text.toByteArray(Charsets.UTF_8)
            cellularTransport?.sendData(data)
            messages.add(ChatMessage(text, true, burnAfterRead = burnAfterRead))
            return
        }
        if (!::ratchet.isInitialized || !ratchet.initialized) {
            pendingOutgoing = text
            messages.add(ChatMessage(text, true, burnAfterRead = burnAfterRead))
            messages.add(ChatMessage("[Handshake initiated, message queued...]", false))
            sendHandshake()
            return
        }
        val plaintext = text.toByteArray(Charsets.UTF_8)
        val padded = CryptoUtils.padWithLengthPrefix(plaintext)
        val rm = ratchet.encrypt(padded)
        val json = JSONObject()
        json.put("type", "msg"); json.put("dhPublicKey", rm.dhPublicKey); json.put("pnum", rm.previousMessageNumber); json.put("num", rm.messageNumber)
        json.put("nonce", Base64.encodeToString(rm.nonce, Base64.NO_WRAP)); json.put("ciphertext", Base64.encodeToString(rm.ciphertext, Base64.NO_WRAP))
        val data = json.toString().toByteArray()
        when (activeMode) { Mode.HOTSPOT -> hotspotTransport.sendData(data); Mode.BLE_MESH -> bleTransport.sendData(ByteArray(2), data); Mode.LORA -> loraTransport?.sendData(ByteArray(2), data); Mode.AWARE -> wifiAwareTransport?.sendData(data); Mode.P2P -> wifiDirectTransport?.sendData(data); Mode.CELLULAR -> cellularTransport?.sendData(data); Mode.NONE -> {} }
        messages.add(ChatMessage(text, true, burnAfterRead = burnAfterRead))
        CryptoUtils.wipe(plaintext); CryptoUtils.wipe(padded); SecurityGuard.wipeMemory(rm.nonce); SecurityGuard.wipeMemory(rm.ciphertext)
    }

    private fun sendHandshake() {
        try {
            if (!::ratchet.isInitialized || !::identityManager.isInitialized) return
            val json = JSONObject()
            json.put("type", "handshake")
            val keys = JSONObject()
            keys.put("identityKey", encodeKey(identityManager.identityKeyPair!!.publicKey))
            keys.put("preKey", encodeKey(identityManager.currentDHKeyPair!!.publicKey))
            keys.put("dhKey", encodeKey(identityManager.currentDHKeyPair!!.publicKey))
            keys.put("fingerprint", identityManager.getShortFingerprint())
            json.put("keys", keys)
            val data = json.toString().toByteArray()
            when (activeMode) { Mode.HOTSPOT -> hotspotTransport.sendData(data); Mode.BLE_MESH -> bleTransport.sendData(ByteArray(2), data); Mode.LORA -> loraTransport?.sendData(ByteArray(2), data); Mode.AWARE -> wifiAwareTransport?.sendData(data); Mode.P2P -> wifiDirectTransport?.sendData(data); else -> {} }
        } catch (e: Exception) {
            messages.add(ChatMessage("[Handshake failed]", false))
        }
    }

    private fun encodeKey(key: ByteArray): String = Base64.encodeToString(key, Base64.NO_WRAP)

    private fun handleIncomingMessage(data: ByteArray) {
        try { val json = JSONObject(String(data, Charsets.UTF_8)); when (json.optString("type")) { "handshake" -> handleHandshake(json); "pq_exchange" -> handlePQExchange(json); "msg" -> handleEncryptedMessage(json) } } catch (_: Exception) {}
        SecurityGuard.wipeMemory(data)
    }

    private fun handleHandshake(json: JSONObject) {
        try {
            val k = json.getJSONObject("keys")
            val bundle = X3DH.PreKeyBundle(k.getString("identityKey"), k.getString("preKey"), k.getString("dhKey"), k.optString("fingerprint"))
            val pqKey = k.optString("pqPublicKey", "")
            if (pqKey.isNotEmpty()) {
                val enc = PostQuantumKEM.encapsulate(PostQuantumKEM.decodePublicKey(pqKey))
                pendingPQEncapsulated = enc.sharedSecret; pendingHandshakeBundle = bundle
                messages.add(ChatMessage("[PQ exchange]", false))
                val pj = JSONObject(); pj.put("type", "pq_exchange"); pj.put("ciphertext", Base64.encodeToString(enc.ciphertext, Base64.NO_WRAP))
                val pd = pj.toString().toByteArray()
                when (activeMode) { Mode.HOTSPOT -> hotspotTransport.sendData(pd); Mode.BLE_MESH -> bleTransport.sendData(ByteArray(2), pd); Mode.LORA -> loraTransport?.sendData(ByteArray(2), pd); Mode.AWARE -> wifiAwareTransport?.sendData(pd); Mode.P2P -> wifiDirectTransport?.sendData(pd); Mode.CELLULAR -> cellularTransport?.sendData(pd); Mode.NONE -> {} }
                tryInitRatchetWithPQ()
            } else {
                ratchet.initializeAsInitiator(X3DH.initiate(identityManager.identityKeyPair!!.privateKey, identityManager.currentDHKeyPair!!.privateKey, bundle))
                finishHandshakeUI(bundle)
            }
        } catch (e: Exception) { messages.add(ChatMessage("[Handshake failed]", false)) }
    }

    private fun handlePQExchange(json: JSONObject) {
        try { pendingPQDecapsulated = identityManager.decapsulatePQ(Base64.decode(json.getString("ciphertext"), Base64.NO_WRAP)); tryInitRatchetWithPQ() } catch (_: Exception) {}
    }

    private fun tryInitRatchetWithPQ() {
        val b = pendingHandshakeBundle ?: return; val enc = pendingPQEncapsulated ?: return; val dec = pendingPQDecapsulated ?: return
        ratchet.initializeAsInitiator(X3DH.initiate(identityManager.identityKeyPair!!.privateKey, identityManager.currentDHKeyPair!!.privateKey, b, enc.copyOf(), dec.copyOf()))
        finishHandshakeUI(b); CryptoUtils.wipe(enc); CryptoUtils.wipe(dec); pendingHandshakeBundle = null; pendingPQEncapsulated = null; pendingPQDecapsulated = null
    }

    private fun finishHandshakeUI(bundle: X3DH.PreKeyBundle) {
        val sn = identityManager.getSafetyNumber(bundle.identityKey)
        messages.add(ChatMessage("[PQ OK \u00b7 ML-KEM]", false))
        messages.add(ChatMessage("[Session established]", false))
        messages.add(ChatMessage("[SN: $sn]", false))
        flushPendingOutgoing()
    }

    private fun flushPendingOutgoing() {
        val text = pendingOutgoing ?: return
        pendingOutgoing = null
        messages.add(ChatMessage("[Sending queued message...]", false))
        sendEncryptedMessage(text)
    }

    private fun handleEncryptedMessage(json: JSONObject) {
        if (!::ratchet.isInitialized || !ratchet.initialized) { messages.add(ChatMessage("[No session]", false)); return }
        try {
            val rm = DoubleRatchet.RatchetMessage(json.getString("dhPublicKey"), json.getInt("pnum"), json.getInt("num"), Base64.decode(json.getString("nonce"), Base64.NO_WRAP), Base64.decode(json.getString("ciphertext"), Base64.NO_WRAP))
            val padded = ratchet.decrypt(rm); val pt = CryptoUtils.unpadWithLengthPrefix(padded); val text = String(pt, Charsets.UTF_8)
            messages.add(ChatMessage(text, false, burnAfterRead = burnAfterRead))
            if (burnAfterRead) { burnCountdownTimer?.cancel(); burnCountdownTimer = object : CountDownTimer(5000, 1000) { override fun onTick(m: Long) {} override fun onFinish() { if (messages.isNotEmpty()) messages.removeAt(messages.size - 1) } }.start() }
            CryptoUtils.wipe(padded); CryptoUtils.wipe(pt); SecurityGuard.wipeMemory(rm.nonce); SecurityGuard.wipeMemory(rm.ciphertext)
        } catch (_: Exception) { messages.add(ChatMessage("[Decrypt failed]", false)) }
    }

    private val hotspotListener = object : HotspotTransport.HotspotListener {
        override fun onPeerConnected(a: String) { runOnUiThread { statusText.value = "Connected"; statusConnected.value = true; messages.add(ChatMessage("[Link: $a]", false)) } }
        override fun onPeerDisconnected() { runOnUiThread { statusText.value = "Lost"; statusConnected.value = false; if (::ratchet.isInitialized) ratchet.wipe(); messages.add(ChatMessage("[Link lost]", false)) } }
        override fun onMessageReceived(d: ByteArray) { runOnUiThread { handleIncomingMessage(d) } }
        override fun onTransportError(e: String) { runOnUiThread { messages.add(ChatMessage("[$e]", false)) } }
        override fun onHandshakeSent() { runOnUiThread { messages.add(ChatMessage("[HS sent]", false)) } }
        override fun onHotspotStarted(s: String, p: String, i: String) { runOnUiThread { messages.add(ChatMessage("[AP $s]", false)); messages.add(ChatMessage("[PSK $p]", false)); messages.add(ChatMessage("[SRV $i:8888]", false)) } }
        override fun onHotspotFailed(s: String, p: String) { runOnUiThread { messages.add(ChatMessage("[AP manual $s]", false)); statusText.value = "AP failed"; statusConnected.value = false } }
    }

    private val bleListener = object : BLEMeshTransport.BLEMeshListener {
        override fun onPeerConnected(a: String) { runOnUiThread { statusText.value = "Connected"; statusConnected.value = true; messages.add(ChatMessage("[BLE link: $a]", false)) } }
        override fun onPeerDisconnected() { runOnUiThread { statusText.value = "Lost"; statusConnected.value = false; if (::ratchet.isInitialized) ratchet.wipe(); if (::meshRouter.isInitialized) meshRouter.flushRoutes(); messages.add(ChatMessage("[BLE lost]", false)) } }
        override fun onMessageReceived(d: ByteArray, s: ByteArray) { runOnUiThread { handleIncomingMessage(d) } }
        override fun onTransportError(e: String) { runOnUiThread { messages.add(ChatMessage("[$e]", false)) } }
        override fun onHandshakeSent() { runOnUiThread { messages.add(ChatMessage("[BLE HS sent]", false)) } }
        override fun onRendezvousMatched(a: String) { runOnUiThread { messages.add(ChatMessage("[Match]", false)) } }
        override fun onRendezvousFailed(r: String) { runOnUiThread { messages.add(ChatMessage("[Rendezvous failed]", false)); statusText.value = "Idle"; statusConnected.value = false; countdownVisible.value = false; countdownTimer?.cancel() } }
        override fun onAdvertiseStarted() { runOnUiThread { messages.add(ChatMessage("[Adv 45s]", false)) } }
    }

    private val loraListener = object : LoRaTransport.LoRaListener {
        override fun onPeerConnected(a: String) { runOnUiThread { statusText.value = "Connected"; statusConnected.value = true; messages.add(ChatMessage("[LoRa link]", false)) } }
        override fun onPeerDisconnected() { runOnUiThread { statusText.value = "Lost"; statusConnected.value = false; if (::ratchet.isInitialized) ratchet.wipe(); messages.add(ChatMessage("[LoRa lost]", false)) } }
        override fun onMessageReceived(d: ByteArray, s: ByteArray) { runOnUiThread { handleIncomingMessage(d) } }
        override fun onTransportError(e: String) { runOnUiThread { messages.add(ChatMessage("[$e]", false)) } }
        override fun onHandshakeSent() { runOnUiThread { messages.add(ChatMessage("[LoRa HS sent]", false)) } }
        override fun onDeviceAttached(d: String) { runOnUiThread { messages.add(ChatMessage("[Device $d]", false)) } }
        override fun onDeviceDetached() { runOnUiThread { messages.add(ChatMessage("[Device lost]", false)); statusText.value = "Idle"; statusConnected.value = false } }
        override fun onReady() { runOnUiThread { messages.add(ChatMessage("[LoRa 868.1MHz]", false)) } }
    }

    private val awareListener = object : WifiAwareTransport.WifiAwareListener {
        override fun onPeerConnected(address: String) { runOnUiThread { statusText.value = "Connected"; statusConnected.value = true; messages.add(ChatMessage("[NAN link]", false)) } }
        override fun onPeerDisconnected() { runOnUiThread { statusText.value = "Lost"; statusConnected.value = false; if (::ratchet.isInitialized) ratchet.wipe(); messages.add(ChatMessage("[NAN lost]", false)) } }
        override fun onMessageReceived(data: ByteArray, senderFP: ByteArray) { runOnUiThread { handleIncomingMessage(data) } }
        override fun onTransportError(error: String) { runOnUiThread { messages.add(ChatMessage("[$error]", false)) } }
        override fun onHandshakeSent() { runOnUiThread { messages.add(ChatMessage("[NAN HS sent]", false)) } }
        override fun onDiscoveryStarted() { runOnUiThread { messages.add(ChatMessage("[NAN discovery]", false)) } }
        override fun onDiscoveryFailed(reason: String) { runOnUiThread { messages.add(ChatMessage("[NAN failed]", false)); statusText.value = "Idle"; statusConnected.value = false; countdownVisible.value = false; countdownTimer?.cancel() } }
        override fun onPeerDiscovered(peerId: String) { runOnUiThread { messages.add(ChatMessage("[NAN peer found]", false)) } }
    }

    private val p2pListener = object : WifiDirectTransport.WifiDirectListener {
        override fun onPeerConnected(address: String) { runOnUiThread { statusText.value = "Connected"; statusConnected.value = true; messages.add(ChatMessage("[P2P link: $address]", false)) } }
        override fun onPeerDisconnected() { runOnUiThread { statusText.value = "Lost"; statusConnected.value = false; if (::ratchet.isInitialized) ratchet.wipe(); messages.add(ChatMessage("[P2P lost]", false)) } }
        override fun onMessageReceived(data: ByteArray) { runOnUiThread { handleIncomingMessage(data) } }
        override fun onTransportError(error: String) { runOnUiThread { messages.add(ChatMessage("[$error]", false)) } }
        override fun onHandshakeSent() { runOnUiThread { messages.add(ChatMessage("[P2P HS sent]", false)) } }
        override fun onDiscoveryStarted() { runOnUiThread { messages.add(ChatMessage("[P2P scanning]", false)) } }
        override fun onDiscoveryFailed(reason: String) { runOnUiThread { messages.add(ChatMessage("[P2P scan failed]", false)) } }
        override fun onPeerFound(deviceName: String) { runOnUiThread { messages.add(ChatMessage("[P2P peer: $deviceName]", false)) } }
    }


    private val cellularListener = object : CellularTransport.CellularListener {
        override fun onConnected(address: String) { runOnUiThread { statusText.value = "Connected"; statusConnected.value = true; messages.add(ChatMessage("[Cellular: $address]", false)) } }
        override fun onDisconnected() { runOnUiThread { statusText.value = "Lost"; statusConnected.value = false; if (::ratchet.isInitialized) ratchet.wipe(); messages.add(ChatMessage("[Cellular lost]", false)) } }
        override fun onMessageReceived(data: ByteArray, senderFP: ByteArray) { runOnUiThread {
                        Log.i("MainActivity", "onMessageReceived size=${data.size}")
                        val text = String(data, Charsets.UTF_8)
                        messages.add(ChatMessage(text, false, burnAfterRead = burnAfterRead))
                    } }
        override fun onTransportError(error: String) { runOnUiThread { messages.add(ChatMessage("[$error]", false)) } }
        override fun onHandshakeSent() { runOnUiThread { messages.add(ChatMessage("[Cellular HS sent]", false)) } }
        override fun onJoined(sessionId: String) { runOnUiThread { messages.add(ChatMessage("[Joined channel, waiting for peer...]", false)) } }
        override fun onJoinFailed(reason: String) { runOnUiThread { messages.add(ChatMessage("[Join failed: $reason]", false)) } }
        override fun onPeerJoined(peerId: String) { runOnUiThread { messages.add(ChatMessage("[有人加入了频道: $peerId]", false)) } }
    }
    private val meshRouterListener = object : MeshRouter.RouterListener {
        override fun onFrameReady(f: ByteArray, n: ByteArray?) { when (activeMode) { Mode.BLE_MESH -> bleTransport.sendData(ByteArray(2), f); Mode.LORA -> loraTransport?.sendData(ByteArray(2), f); Mode.AWARE -> wifiAwareTransport?.sendData(f); Mode.P2P -> wifiDirectTransport?.sendData(f); Mode.CELLULAR -> cellularTransport?.sendData(f); else -> {} } }
        override fun onDataReceived(p: ByteArray, s: ByteArray) { runOnUiThread { handleIncomingMessage(p) } }
        override fun onRouteEstablished(t: ByteArray) { runOnUiThread { messages.add(ChatMessage("[Route]", false)) } }
        override fun onRouteRequest(t: ByteArray) { if (::meshRouter.isInitialized) meshRouter.discoverRoute(t) }
    }

    override fun onResume() { super.onResume(); SecurityGuard.onAppForegrounded(this); if (!SecurityGuard.verify(this)) SecurityGuard.apply(this) }
    override fun onPause() { super.onPause(); SecurityGuard.onAppBackgrounded(this) }
    override fun onStop() { super.onStop(); messages.clear(); countdownTimer?.cancel(); burnCountdownTimer?.cancel(); pendingPQEncapsulated?.let { CryptoUtils.wipe(it) }; pendingPQDecapsulated?.let { CryptoUtils.wipe(it) }; pendingPQEncapsulated = null; pendingPQDecapsulated = null; pendingHandshakeBundle = null }
    override fun onDestroy() { super.onDestroy(); if (::ratchet.isInitialized) ratchet.wipe(); if (::hotspotTransport.isInitialized) hotspotTransport.close(); if (::bleTransport.isInitialized) bleTransport.close(); loraTransport?.close(); wifiAwareTransport?.close(); wifiDirectTransport?.close(); cellularTransport?.close(); if (::meshRouter.isInitialized) meshRouter.wipe(); if (::identityManager.isInitialized) identityManager.wipeAll() }
}
