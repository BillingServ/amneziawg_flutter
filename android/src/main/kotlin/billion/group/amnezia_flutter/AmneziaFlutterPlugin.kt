package billion.group.amnezia_flutter


import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.PluginRegistry

import android.app.Activity
import android.content.Intent
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.util.Log
import io.flutter.plugin.common.EventChannel
import kotlinx.coroutines.*
import org.amnezia.awg.config.Config
import org.amnezia.awg.backend.AbstractBackend
import org.amnezia.awg.backend.Backend
import org.amnezia.awg.backend.BackendException
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.NoopTunnelActionHandler
import org.amnezia.awg.backend.Tunnel
import java.util.*


import kotlinx.coroutines.launch
import java.io.ByteArrayInputStream

/** AmneziaFlutterPlugin */

const val PERMISSIONS_REQUEST_CODE = 10014
const val METHOD_CHANNEL_NAME = "billion.group.amnezia_flutter/wgcontrol"
const val METHOD_EVENT_NAME = "billion.group.amnezia_flutter/wgstage"

class AmneziaFlutterPlugin : FlutterPlugin, MethodCallHandler, ActivityAware,
    PluginRegistry.ActivityResultListener {
    private lateinit var channel: MethodChannel
    private lateinit var events: EventChannel
    private lateinit var tunnelName: String
    private var vpnStageSink: EventChannel.EventSink? = null
    private val scope = CoroutineScope(Job() + Dispatchers.Main.immediate)
    private var backend: Backend? = null
    private var havePermission = false
    private lateinit var context: Context
    private var activity: Activity? = null
    private var config: Config? = null
    private var tunnel: WireGuardTunnel? = null
    private val TAG = "NVPN"
    var isVpnChecked = false
    companion object {
        private var state: String = "no_connection"

        fun getStatus(): String {
            return state
        }
    }
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        this.havePermission =
            (requestCode == PERMISSIONS_REQUEST_CODE) && (resultCode == Activity.RESULT_OK)
        return havePermission
    }

    override fun onAttachedToActivity(activityPluginBinding: ActivityPluginBinding) {
        this.activity = activityPluginBinding.activity
        activityPluginBinding.addActivityResultListener(this)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        this.activity = null
    }

    override fun onReattachedToActivityForConfigChanges(activityPluginBinding: ActivityPluginBinding) {
        this.activity = activityPluginBinding.activity
        activityPluginBinding.addActivityResultListener(this)
    }

    override fun onDetachedFromActivity() {
        this.activity = null
    }

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, METHOD_CHANNEL_NAME)
        events = EventChannel(flutterPluginBinding.binaryMessenger, METHOD_EVENT_NAME)
        context = flutterPluginBinding.applicationContext

        channel.setMethodCallHandler(this)
        events.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                isVpnChecked = false
                vpnStageSink = events
            }

            override fun onCancel(arguments: Any?) {
                isVpnChecked = false
                vpnStageSink = null
            }
        })

    }

    @Synchronized
    private fun createBackend(): Backend {
        if (backend == null) {
            backend = GoBackend(context, NoopTunnelActionHandler())
        }
        return backend as Backend
    }

    private fun flutterSuccess(result: Result, o: Any) {
        scope.launch(Dispatchers.Main) {
            result.success(o)
        }
    }

    private fun flutterError(result: Result, error: String) {
        scope.launch(Dispatchers.Main) {
            result.error(error, null, null)
        }
    }

    private fun flutterNotImplemented(result: Result) {
        scope.launch(Dispatchers.Main) {
            result.notImplemented()
        }
    }

    override fun onMethodCall(call: MethodCall, result: Result) {

        when (call.method) {
            "initialize" -> setupTunnel(call.argument<String>("localizedDescription").toString(), result)
            "start" -> {
                connect(call.argument<String>("wgQuickConfig").toString(), result)

                if (!isVpnChecked) {
                    if (isVpnActive()) {
                        state = "connected"
                        isVpnChecked = true
                        println("VPN is active")
                    } else {
                        state = "disconnected"
                        isVpnChecked = true
                        println("VPN is not active")
                    }
                }
            }
            "stop" -> {
                disconnect(result)
            }
            "stage" -> {
                result.success(getStatus())
            }
            "checkPermission" -> {
                checkPermission()
                result.success(null)
            }
            else -> flutterNotImplemented(result)
        }
    }
    private fun isVpnActive(): Boolean {
        try {
            val connectivityManager =
                context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val activeNetwork = connectivityManager.activeNetwork
                val networkCapabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
                return networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            } else {
                return false
            }
        } catch (e: Exception) {
            Log.e(TAG, "isVpnActive - ERROR - ${e.message}")
            return false
        }
    }
    private fun updateStage(stage: String?) {
        scope.launch(Dispatchers.Main) {
            val updatedStage = stage ?: "no_connection"
            state = updatedStage
            vpnStageSink?.success(updatedStage.lowercase(Locale.ROOT))
        }
    }
    private fun updateStageFromState(state: Tunnel.State) {
        scope.launch(Dispatchers.Main) {
            when (state) {
                Tunnel.State.UP -> updateStage("connected")
                Tunnel.State.DOWN -> updateStage("disconnected")
                else -> updateStage("wait_connection")
            }
        }
    }
    private fun disconnect(result: Result) {
        scope.launch(Dispatchers.IO) {
            try {
                val backend = createBackend()
                if (backend.runningTunnelNames.isEmpty()) {
                    // Backend doesn't know about any tunnels - this happens after app restart
                    // Check if VPN is actually still running via system API
                    if (isVpnActive()) {
                        Log.i(TAG, "Disconnect - Backend has no tunnels but VPN is active, forcing stop")
                        updateStage("disconnecting")
                        
                        // Force stop the VPN service directly
                        val stopped = forceStopVpnService()
                        if (stopped) {
                            Log.i(TAG, "Disconnect - Force stop VPN service succeeded")
                            updateStage("disconnected")
                            flutterSuccess(result, "")
                            return@launch
                        } else {
                            Log.e(TAG, "Disconnect - Force stop VPN service failed")
                        }
                    }
                    
                    updateStage("disconnected")
                    throw Exception("Tunnel is not running")
                }
                updateStage("disconnecting")
                backend.setState(
                    tunnel(tunnelName) { state ->
                        scope.launch(Dispatchers.Main) {
                            Log.i(TAG, "onStateChange - $state")
                            updateStageFromState(state)
                        }
                    }, Tunnel.State.DOWN, config
                )
                Log.i(TAG, "Disconnect - success!")
                flutterSuccess(result, "")
            } catch (e: BackendException) {
                Log.e(TAG, "Disconnect - BackendException - ERROR - ${e.reason}", e)
                flutterError(result, e.reason.toString())
            } catch (e: Throwable) {
                Log.e(TAG, "Disconnect - Can't disconnect from tunnel: ${e.message}")
                flutterError(result, e.message.toString())
            }
        }
    }
    
    /**
     * Force stop the VPN service when the backend doesn't know about running tunnels.
     * This handles the case where the app was restarted while VPN was connected.
     */
    private fun forceStopVpnService(): Boolean {
        try {
            // Method 1: try to stop the userspace VPN service directly.
            val intent = Intent(context, AbstractBackend.VpnService::class.java)
            val stopped = context.stopService(intent)
            Log.i(TAG, "forceStopVpnService - stopService result: $stopped")

            // Method 2: access the static vpnService field and call stopSelf().
            try {
                val backendClass = Class.forName("org.amnezia.awg.backend.AbstractBackend")
                val vpnServiceField = backendClass.getDeclaredField("vpnService")
                vpnServiceField.isAccessible = true
                val vpnServiceFuture = vpnServiceField.get(null)
                
                if (vpnServiceFuture != null) {
                    val isDoneMethod = vpnServiceFuture.javaClass.getMethod("isDone")
                    val isDone = isDoneMethod.invoke(vpnServiceFuture) as Boolean
                    
                    if (isDone) {
                        val timeUnitClass = Class.forName("java.util.concurrent.TimeUnit")
                        val nanosecondsField = timeUnitClass.getField("NANOSECONDS")
                        val nanoseconds = nanosecondsField.get(null)
                        
                        val getMethod = vpnServiceFuture.javaClass.getMethod("get", Long::class.javaPrimitiveType, timeUnitClass)
                        val vpnServiceInstance = getMethod.invoke(vpnServiceFuture, 0L, nanoseconds)
                        
                        if (vpnServiceInstance != null) {
                            val stopSelfMethod = vpnServiceInstance.javaClass.getMethod("stopSelf")
                            stopSelfMethod.invoke(vpnServiceInstance)
                            Log.i(TAG, "forceStopVpnService - Called stopSelf() on VpnService")
                            return true
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "forceStopVpnService - Reflection failed: ${e.message}")
            }
            
            return stopped
        } catch (e: Exception) {
            Log.e(TAG, "forceStopVpnService - ERROR: ${e.message}")
            return false
        }
    }

    private fun connect(wgQuickConfig: String, result: Result) {
        scope.launch(Dispatchers.IO) {
            try {
                if (!havePermission) {
                    checkPermission()
                    throw Exception("Permissions are not given")
                }
                updateStage("prepare")
                val inputStream = ByteArrayInputStream(wgQuickConfig.toByteArray())
                config = Config.parse(inputStream)
                updateStage("connecting")
                createBackend().setState(
                    tunnel(tunnelName) { state ->
                        scope.launch(Dispatchers.Main) {
                            Log.i(TAG, "onStateChange - $state")
                            updateStageFromState(state)
                        }
                    }, Tunnel.State.UP, config
                )
                Log.i(TAG, "Connect - success!")
                flutterSuccess(result, "")
            } catch (e: BackendException) {
                Log.e(TAG, "Connect - BackendException - ERROR - ${e.reason}", e)
                flutterError(result, e.reason.toString())
            } catch (e: Throwable) {
                Log.e(TAG, "Connect - Can't connect to tunnel: $e", e)
                flutterError(result, e.message.toString())
            }
        }
    }

    private fun setupTunnel(localizedDescription: String, result: Result) {
        scope.launch(Dispatchers.IO) {
            if (Tunnel.isNameInvalid(localizedDescription)) {
                flutterError(result, "Invalid Name")
                return@launch
            }
            tunnelName = localizedDescription
            checkPermission()
            result.success(null)
        }
    }

    private fun checkPermission() {
        val intent = AbstractBackend.VpnService.prepare(this.activity)
        if (intent != null) {
            havePermission = false
            this.activity?.startActivityForResult(intent, PERMISSIONS_REQUEST_CODE)
        } else {
            havePermission = true
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        events.setStreamHandler(null)
        isVpnChecked = false
    }

    private fun tunnel(name: String, callback: StateChangeCallback? = null): WireGuardTunnel {
        if (tunnel == null) {
            tunnel = WireGuardTunnel(name, callback)
        }
        return tunnel as WireGuardTunnel
    }
}

typealias StateChangeCallback = (Tunnel.State) -> Unit

class WireGuardTunnel(
    private val name: String, private val onStateChanged: StateChangeCallback? = null
) : Tunnel {

    override fun getName() = name

    override fun isIpv4ResolutionPreferred() = false

    override fun isMetered() = false

    override fun onStateChange(newState: Tunnel.State) {
        onStateChanged?.invoke(newState)
    }

}

