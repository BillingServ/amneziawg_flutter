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
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.util.Log
import org.amnezia.awg.backend.BackendException
import io.flutter.plugin.common.EventChannel
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/** AmneziaFlutterPlugin */

const val PERMISSIONS_REQUEST_CODE = 10014
const val METHOD_CHANNEL_NAME = "billion.group.amnezia_flutter/wgcontrol"
const val METHOD_EVENT_NAME = "billion.group.amnezia_flutter/wgstage"

/**
 * Thin per-engine adapter. All tunnel state lives in [AmneziaRuntime] so it survives
 * Flutter engine recreation and Dart hot restart.
 */
class AmneziaFlutterPlugin : FlutterPlugin, MethodCallHandler, ActivityAware,
    PluginRegistry.ActivityResultListener {
    private lateinit var channel: MethodChannel
    private lateinit var events: EventChannel
    private lateinit var context: Context
    private var activityBinding: ActivityPluginBinding? = null
    private var stageListener: AmneziaRuntime.StageListener? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private var havePermission = false
    private val TAG = "NVPN"

    companion object {
        // Start and stop may run at the same time (stop cancels an in-flight start).
        private val worker: ExecutorService = Executors.newCachedThreadPool { runnable ->
            Thread(runnable, "amnezia-flutter").apply { isDaemon = true }
        }

        /** Kept for existing callers; reflects the process-wide runtime. */
        fun getStatus(): String {
            return AmneziaRuntime.currentStage
        }
    }

    private val activity: Activity?
        get() = activityBinding?.activity

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        if (requestCode != PERMISSIONS_REQUEST_CODE) return false
        havePermission = resultCode == Activity.RESULT_OK
        Log.i(TAG, "VPN permission result: granted=$havePermission")
        return true
    }

    override fun onAttachedToActivity(activityPluginBinding: ActivityPluginBinding) {
        attachActivity(activityPluginBinding)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        detachActivity()
    }

    override fun onReattachedToActivityForConfigChanges(activityPluginBinding: ActivityPluginBinding) {
        attachActivity(activityPluginBinding)
    }

    override fun onDetachedFromActivity() {
        detachActivity()
    }

    private fun attachActivity(binding: ActivityPluginBinding) {
        activityBinding?.removeActivityResultListener(this)
        activityBinding = binding
        binding.addActivityResultListener(this)
    }

    private fun detachActivity() {
        activityBinding?.removeActivityResultListener(this)
        activityBinding = null
    }

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        context = flutterPluginBinding.applicationContext
        AmneziaRuntime.init(context)
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, METHOD_CHANNEL_NAME)
        events = EventChannel(flutterPluginBinding.binaryMessenger, METHOD_EVENT_NAME)

        channel.setMethodCallHandler(this)
        events.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, sink: EventChannel.EventSink?) {
                clearStageListener()
                if (sink == null) return
                val listener = AmneziaRuntime.StageListener { stage -> sink.success(stage) }
                stageListener = listener
                AmneziaRuntime.addListener(listener)
                // Replay the current stage so a new listener never starts from a guess.
                sink.success(AmneziaRuntime.currentStage)
            }

            override fun onCancel(arguments: Any?) {
                clearStageListener()
            }
        })
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        events.setStreamHandler(null)
        clearStageListener()
    }

    private fun clearStageListener() {
        stageListener?.let { AmneziaRuntime.removeListener(it) }
        stageListener = null
    }

    private fun postSuccess(result: Result, value: Any?) {
        mainHandler.post { result.success(value) }
    }

    private fun postError(result: Result, code: String, message: String? = null) {
        mainHandler.post { result.error(code, message, null) }
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "initialize" -> setupTunnel(call.argument<String>("localizedDescription").toString(), result)
            "start" -> connect(call.argument<String>("wgQuickConfig").toString(), result)
            "stop" -> disconnect(result)
            "stage" -> result.success(AmneziaRuntime.currentStage)
            "refresh" -> {
                AmneziaRuntime.refresh()
                result.success(null)
            }
            "checkPermission" -> {
                checkPermission()
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    private fun disconnect(result: Result) {
        worker.execute {
            val stopped = AmneziaRuntime.stop()
            if (stopped) {
                Log.i(TAG, "Disconnect - verified down")
                postSuccess(result, "")
            } else {
                Log.e(TAG, "Disconnect - tunnel is still up")
                postError(result, "Tunnel did not stop", "AmneziaWG tunnel is still up after stop")
            }
        }
    }

    private fun connect(wgQuickConfig: String, result: Result) {
        if (!hasVpnPermission()) {
            checkPermission()
            result.error("Permissions are not given", null, null)
            return
        }
        val generation = AmneziaRuntime.startGeneration()
        worker.execute {
            try {
                AmneziaRuntime.start(wgQuickConfig, generation)
                Log.i(TAG, "Connect - success!")
                postSuccess(result, "")
            } catch (e: BackendException) {
                Log.e(TAG, "Connect - BackendException - ERROR - ${e.reason}", e)
                postError(result, e.reason.toString())
            } catch (e: Throwable) {
                Log.e(TAG, "Connect - Can't connect to tunnel: $e", e)
                postError(result, e.message ?: e.toString())
            }
        }
    }

    private fun setupTunnel(localizedDescription: String, result: Result) {
        if (!AmneziaRuntime.setTunnelName(localizedDescription)) {
            result.error("Invalid Name", null, null)
            return
        }
        checkPermission()
        result.success(null)
    }

    private fun hasVpnPermission(): Boolean {
        val granted = try {
            VpnService.prepare(context) == null
        } catch (e: Exception) {
            Log.w(TAG, "VpnService.prepare failed: ${e.message}")
            false
        }
        havePermission = granted
        return granted
    }

    /** Shows the system VPN consent dialog when needed. Main thread only. */
    private fun checkPermission() {
        val intent = try {
            VpnService.prepare(activity ?: context)
        } catch (e: Exception) {
            Log.w(TAG, "VpnService.prepare failed: ${e.message}")
            null
        }
        if (intent == null) {
            havePermission = true
            return
        }
        havePermission = false
        val current = activity
        if (current == null) {
            Log.w(TAG, "VPN permission needed but no activity is attached")
            return
        }
        try {
            current.startActivityForResult(intent, PERMISSIONS_REQUEST_CODE)
        } catch (e: Exception) {
            Log.e(TAG, "Could not show VPN permission dialog: ${e.message}")
        }
    }
}
