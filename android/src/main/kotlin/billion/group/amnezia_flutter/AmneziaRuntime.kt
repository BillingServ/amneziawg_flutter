package billion.group.amnezia_flutter

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import org.amnezia.awg.backend.AbstractBackend
import org.amnezia.awg.backend.BackendException
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.NoopTunnelActionHandler
import org.amnezia.awg.backend.Tunnel
import org.amnezia.awg.config.Config
import java.io.ByteArrayInputStream
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock

/**
 * Process-wide owner of the AmneziaWG backend, tunnel and stage.
 *
 * The Flutter engine (and with it the plugin instance) can be recreated while the process
 * and the system-bound VpnService stay alive, and a Dart hot restart re-subscribes to the
 * stage channel. Keeping the backend here means every plugin instance talks to the backend
 * that really owns the running tunnel, and the stage reported to Dart is the backend truth.
 *
 * Blocking calls ([start], [stop], [statistics]) must not run on the main thread.
 */
object AmneziaRuntime {
    private const val TAG = "AmneziaRuntime"

    const val STATE_UP = "up"
    const val STATE_CONNECTING = "connecting"
    const val STATE_DOWN = "down"

    const val STAGE_CONNECTED = "connected"
    const val STAGE_CONNECTING = "connecting"
    const val STAGE_DISCONNECTING = "disconnecting"
    const val STAGE_DISCONNECTED = "disconnected"
    const val STAGE_PREPARE = "prepare"
    const val STAGE_DENIED = "denied"

    const val DEFAULT_TUNNEL_NAME = "awg0"
    const val DEFAULT_STOP_TIMEOUT_MS = 8000L

    /** Receives stage strings on the main thread. */
    fun interface StageListener {
        fun onStageChanged(stage: String)
    }

    /** Cumulative counters for the running tunnel, as reported by the backend. */
    class TunnelStatistics(
        val rxBytes: Long,
        val txBytes: Long,
        val lastHandshakeEpochMs: Long?,
        val connectedSinceEpochMs: Long?
    )

    private val mainHandler = Handler(Looper.getMainLooper())
    private val opLock = ReentrantLock()
    // Each Go library needs its own JNI thread; sharing a caller thread across
    // WireGuard and AmneziaWG can reuse the other Go runtime's thread state.
    private val nativeWorker = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "AmneziaRuntime-native").apply { isDaemon = true }
    }

    private fun <T> nativeCall(call: Callable<T>): T {
        try {
            return nativeWorker.submit(call).get()
        } catch (e: ExecutionException) {
            throw (e.cause ?: e)
        }
    }

    private val listeners = CopyOnWriteArraySet<StageListener>()
    private val stopGeneration = AtomicLong(0)

    @Volatile private var appContext: Context? = null
    @Volatile private var backend: GoBackend? = null
    @Volatile private var tunnel: RuntimeTunnel? = null
    @Volatile private var activeTunnel: RuntimeTunnel? = null
    @Volatile private var stage: String = STAGE_DISCONNECTED
    private val inFlightStarts = AtomicInteger(0)
    private val starting: Boolean
        get() = inFlightStarts.get() > 0
    @Volatile private var connectedSinceEpochMs: Long? = null

    @Volatile
    var tunnelName: String = DEFAULT_TUNNEL_NAME
        private set

    /**
     * Runs on the starting thread before a tunnel is brought up. The app uses it to stop its
     * other protocols first, since all of them share the app's single VPN slot.
     */
    @Volatile
    var beforeStart: (() -> Unit)? = null

    fun init(context: Context) {
        if (appContext == null) {
            appContext = context.applicationContext
        }
    }

    /** Returns false when the name is not a valid tunnel name. */
    fun setTunnelName(name: String): Boolean {
        if (Tunnel.isNameInvalid(name)) return false
        tunnelName = name
        return true
    }

    fun addListener(listener: StageListener) {
        listeners.add(listener)
    }

    fun removeListener(listener: StageListener) {
        listeners.remove(listener)
    }

    /** The stage string Dart understands, corrected by the backend state. */
    val currentStage: String
        get() {
            val up = isUp()
            val recorded = stage
            return when {
                up && (recorded == STAGE_DISCONNECTED || recorded == STAGE_DENIED) -> STAGE_CONNECTED
                !up && !starting && recorded == STAGE_CONNECTED -> STAGE_DISCONNECTED
                else -> recorded
            }
        }

    /** "up", "connecting" or "down". */
    fun state(): String = when {
        isUp() -> STATE_UP
        starting -> STATE_CONNECTING
        else -> STATE_DOWN
    }

    /** True when an AmneziaWG tunnel of this process is up, whoever started it. */
    fun isUp(): Boolean {
        val running = try {
            backend?.runningTunnelNames?.isNotEmpty() == true
        } catch (e: Throwable) {
            false
        }
        return running || foreignOwnerRunning()
    }

    fun connectedSinceEpochMs(): Long? = if (isUp()) connectedSinceEpochMs else null

    /** Re-emits the current stage to every listener. */
    fun refresh() {
        notifyListeners(currentStage)
    }

    /**
     * Brings the tunnel up with the given wg-quick config. Blocks until the backend returns.
     * Throws on failure (BackendException carries the reason).
     */
    fun startGeneration(): Long = stopGeneration.get()

    @Throws(Exception::class)
    fun start(wgQuickConfig: String, generation: Long = startGeneration()) {
        check(generation == stopGeneration.get()) { "Start cancelled by a stop request" }
        // Counted before waiting for the lock so a queued start already reads as connecting
        // and a stop issued meanwhile cancels it.
        inFlightStarts.incrementAndGet()
        try {
            try {
                beforeStart?.invoke()
            } catch (e: Throwable) {
                Log.w(TAG, "start - beforeStart hook failed: ${e.message}")
            }
            opLock.lock()
            try {
                if (generation != stopGeneration.get()) {
                    throw IllegalStateException("Start cancelled by a stop request")
                }
                updateStage(STAGE_PREPARE)
                val parsed = Config.parse(ByteArrayInputStream(wgQuickConfig.toByteArray()))
                updateStage(STAGE_CONNECTING)
                val target = tunnelFor(tunnelName)
                nativeCall { backend().setState(target, Tunnel.State.UP, parsed) }

                if (generation != stopGeneration.get()) {
                    Log.i(TAG, "start - stop requested while connecting, bringing tunnel down")
                    bringDownLocked()
                    throw IllegalStateException("Start cancelled by a stop request")
                }
                if (!isUp()) {
                    throw IllegalStateException("Tunnel did not come up")
                }
                if (stage != STAGE_CONNECTED) {
                    updateStage(STAGE_CONNECTED)
                }
            } catch (e: Throwable) {
                if (!isUp()) {
                    val denied = e is BackendException &&
                        e.reason == BackendException.Reason.VPN_NOT_AUTHORIZED
                    updateStage(if (denied) STAGE_DENIED else STAGE_DISCONNECTED)
                }
                throw e
            } finally {
                opLock.unlock()
            }
        } finally {
            inFlightStarts.decrementAndGet()
        }
    }

    /**
     * Brings the tunnel down through the backend that owns it and verifies it is down.
     * Safe to call when nothing is running. Returns true only when verified down.
     */
    fun stop(timeoutMs: Long = DEFAULT_STOP_TIMEOUT_MS): Boolean {
        stopGeneration.incrementAndGet()
        val deadline = SystemClock.elapsedRealtime() + timeoutMs.coerceAtLeast(0L)
        val locked = try {
            opLock.tryLock(timeoutMs.coerceAtLeast(0L), TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        if (!locked) {
            Log.w(TAG, "stop - timed out waiting for an in-flight operation")
            return !isUp() && !starting
        }
        try {
            val wasUp = isUp()
            if (wasUp) {
                updateStage(STAGE_DISCONNECTING)
                bringDownLocked()
            }
            val down = !isUp()
            if (down) {
                connectedSinceEpochMs = null
                if (stage != STAGE_DISCONNECTED) updateStage(STAGE_DISCONNECTED)
                // Let the stopping VpnService finish onDestroy before a new start can reuse it;
                // its onDestroy would otherwise turn off the next tunnel.
                if (wasUp) {
                    val remaining = (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0L)
                    waitForServiceReset(minOf(2000L, remaining))
                }
            } else {
                Log.e(TAG, "stop - tunnel still up after stop attempt")
                updateStage(STAGE_CONNECTED)
            }
            return down
        } catch (e: Throwable) {
            Log.e(TAG, "stop - failed: ${e.message}", e)
            val down = !isUp()
            updateStage(if (down) STAGE_DISCONNECTED else STAGE_CONNECTED)
            return down
        } finally {
            opLock.unlock()
        }
    }

    /** Statistics of the running tunnel, or null when no tunnel is up. Blocking but quick. */
    fun statistics(): TunnelStatistics? {
        // The JNI statistics reader must not use a handle being freed by stop/start.
        // Skip this sample while the backend is busy rather than delaying teardown.
        if (!opLock.tryLock()) return null
        try {
            val owner = backend
            val current = activeTunnel ?: tunnel
            if (owner == null || current == null) return null
            return try {
                if (owner.getState(current) != Tunnel.State.UP) return null
                val stats = nativeCall { owner.getStatistics(current) }
                var handshake = 0L
                for (key in stats.peers()) {
                    val peer = stats.peer(key) ?: continue
                    if (peer.latestHandshakeEpochMillis() > handshake) {
                        handshake = peer.latestHandshakeEpochMillis()
                    }
                }
                TunnelStatistics(
                    rxBytes = stats.totalRx(),
                    txBytes = stats.totalTx(),
                    lastHandshakeEpochMs = if (handshake > 0) handshake else null,
                    connectedSinceEpochMs = connectedSinceEpochMs
                )
            } catch (e: Throwable) {
                Log.w(TAG, "statistics - failed: ${e.message}")
                null
            }
        } finally {
            opLock.unlock()
        }
    }

    // Caller holds opLock.
    private fun bringDownLocked() {
        val owner = backend
        if (owner != null) {
            val candidates = linkedSetOf<Tunnel>()
            activeTunnel?.let { candidates.add(it) }
            tunnel?.let { candidates.add(it) }
            currentTunnelOf(owner)?.let { candidates.add(it) }
            for (candidate in candidates) {
                if (owner.getState(candidate) == Tunnel.State.UP) {
                    nativeCall { owner.setState(candidate, Tunnel.State.DOWN, null) }
                }
            }
        }
        // A tunnel owned by a backend this runtime did not create (should not happen once
        // every caller goes through the runtime, kept as a safety net).
        val foreign = serviceOwner()
        if (foreign != null && foreign !== owner) {
            val foreignTunnel = currentTunnelOf(foreign)
            if (foreignTunnel != null) {
                Log.i(TAG, "stop - bringing down tunnel owned by another backend instance")
                nativeCall { foreign.setState(foreignTunnel, Tunnel.State.DOWN, null) }
            }
        }
        val deadline = SystemClock.elapsedRealtime() + 1000L
        while (isUp() && SystemClock.elapsedRealtime() < deadline) {
            Thread.sleep(50L)
        }
    }

    @Synchronized
    private fun backend(): GoBackend {
        backend?.let { return it }
        val context = appContext ?: throw IllegalStateException("AmneziaRuntime.init was not called")
        val created = GoBackend(context, NoopTunnelActionHandler())
        backend = created
        return created
    }

    private fun tunnelFor(name: String): RuntimeTunnel {
        val existing = tunnel
        if (existing != null && existing.getName() == name) return existing
        val created = RuntimeTunnel(name)
        tunnel = created
        return created
    }

    private fun onBackendStateChange(source: RuntimeTunnel, newState: Tunnel.State) {
        Log.i(TAG, "onStateChange - ${source.getName()} $newState")
        when (newState) {
            Tunnel.State.UP -> {
                activeTunnel = source
                if (connectedSinceEpochMs == null) connectedSinceEpochMs = System.currentTimeMillis()
                updateStage(STAGE_CONNECTED)
            }
            Tunnel.State.DOWN -> {
                if (activeTunnel === source) activeTunnel = null
                if (!isUp()) {
                    connectedSinceEpochMs = null
                    // During a config switch the old tunnel reports DOWN right before the new
                    // one comes up; the start path reports the outcome itself.
                    if (!starting) updateStage(STAGE_DISCONNECTED)
                }
            }
            else -> Unit
        }
    }

    private fun updateStage(newStage: String) {
        if (stage == newStage) return
        stage = newStage
        notifyListeners(newStage)
    }

    private fun notifyListeners(value: String) {
        mainHandler.post {
            for (listener in listeners) {
                try {
                    listener.onStageChanged(value)
                } catch (e: Throwable) {
                    Log.w(TAG, "listener failed: ${e.message}")
                }
            }
        }
    }

    private fun foreignOwnerRunning(): Boolean {
        val owner = serviceOwner() ?: return false
        if (owner === backend) return false
        return try {
            owner.runningTunnelNames.isNotEmpty()
        } catch (e: Throwable) {
            false
        }
    }

    // The library keeps the bound service in a static future and the owning backend in the
    // service. Both are private, so they are read by reflection (kept by consumer rules).
    private fun serviceOwner(): AbstractBackend? {
        val service = boundService() ?: return null
        return try {
            val ownerField = AbstractBackend.VpnService::class.java.getDeclaredField("owner")
            ownerField.isAccessible = true
            ownerField.get(service) as? AbstractBackend
        } catch (e: Throwable) {
            null
        }
    }

    private fun boundService(): Any? {
        return try {
            val futureField = AbstractBackend::class.java.getDeclaredField("vpnService")
            futureField.isAccessible = true
            val future = futureField.get(null) as? CompletableFuture<*> ?: return null
            if (!future.isDone || future.isCancelled || future.isCompletedExceptionally) return null
            future.getNow(null)
        } catch (e: Throwable) {
            null
        }
    }

    private fun waitForServiceReset(timeoutMs: Long) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (boundService() != null && SystemClock.elapsedRealtime() < deadline) {
            Thread.sleep(50L)
        }
        if (boundService() != null) {
            Log.w(TAG, "stop - VpnService still alive after tunnel went down")
        }
    }

    private fun currentTunnelOf(owner: AbstractBackend): Tunnel? {
        return try {
            val field = AbstractBackend::class.java.getDeclaredField("currentTunnel")
            field.isAccessible = true
            field.get(owner) as? Tunnel
        } catch (e: Throwable) {
            null
        }
    }

    private class RuntimeTunnel(private val name: String) : Tunnel {
        override fun getName() = name

        override fun isIpv4ResolutionPreferred() = false

        override fun isMetered() = false

        override fun onStateChange(newState: Tunnel.State) {
            onBackendStateChange(this, newState)
        }
    }
}
