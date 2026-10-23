package com.scourvex.app.shizuku

import android.content.ComponentName
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.IBinder
import android.os.ParcelFileDescriptor
import com.scourvex.app.BuildConfig
import com.scourvex.app.IShellService
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import rikka.shizuku.Shizuku

/** Connection to Shizuku and the shell-uid [ShellService]. */
object Shell {

    enum class State { NOT_RUNNING, NO_PERMISSION, READY }

    private val _state = MutableStateFlow(State.NOT_RUNNING)
    val state: StateFlow<State> = _state

    @Volatile private var service: IShellService? = null
    private var pending: CompletableDeferred<IShellService>? = null

    private val args = Shizuku.UserServiceArgs(ComponentName(BuildConfig.APPLICATION_ID, ShellService::class.java.name))
        .daemon(false)
        .processNameSuffix("shell")
        .debuggable(BuildConfig.DEBUG)
        .version(BuildConfig.VERSION_CODE)

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            if (binder != null && binder.pingBinder()) {
                val s = IShellService.Stub.asInterface(binder)
                service = s
                pending?.complete(s)
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            service = null
        }
    }

    fun init() {
        Shizuku.addBinderReceivedListenerSticky { refresh() }
        Shizuku.addBinderDeadListener {
            service = null
            refresh()
        }
        Shizuku.addRequestPermissionResultListener { _, _ -> refresh() }
        refresh()
    }

    fun refresh() {
        _state.value = when {
            !Shizuku.pingBinder() -> State.NOT_RUNNING
            Shizuku.isPreV11() -> State.NOT_RUNNING
            Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED -> State.NO_PERMISSION
            else -> State.READY
        }
    }

    fun requestPermission() {
        if (Shizuku.pingBinder() && !Shizuku.shouldShowRequestPermissionRationale()) {
            Shizuku.requestPermission(REQUEST_CODE)
        }
    }

    val ready: Boolean get() = state.value == State.READY

    private val bindLock = Mutex()

    /**
     * The bound shell service, binding it first if needed. Null when Shizuku is unavailable.
     * Once bound it is returned as is, with no Shizuku or binder ping per call: the dead-binder
     * listeners clear it, and callers that hit a [android.os.DeadObjectException] call [invalidate].
     */
    suspend fun get(): IShellService? {
        service?.let { return it }
        return bindLock.withLock {
            service?.let { return@withLock it }
            refresh()
            if (!ready) return@withLock null
            val d = CompletableDeferred<IShellService>()
            pending = d
            Shizuku.bindUserService(args, connection)
            withTimeoutOrNull(10_000) { d.await() }
        }
    }

    /** Forget the bound service (its process died); the next [get] rebinds. */
    fun invalidate() { service = null }

    /** Runs a shell command as uid 2000. Returns (exitCode, output) or null without Shizuku. */
    suspend fun exec(cmd: String): Pair<Int, String>? {
        val s = get() ?: return null
        val raw = try {
            s.exec(cmd)
        } catch (_: android.os.DeadObjectException) {
            invalidate()
            (get() ?: return null).exec(cmd)
        }
        val nl = raw.indexOf('\n')
        return raw.substring(0, nl).toInt() to raw.substring(nl + 1)
    }

    suspend fun walkPipe(root: String, skip: List<String>): ParcelFileDescriptor? {
        val s = get() ?: return null
        val (read, write) = ParcelFileDescriptor.createPipe()
        try {
            s.walk(root, skip.toTypedArray(), write)
        } catch (_: android.os.DeadObjectException) {
            invalidate()
            (get() ?: run { write.close(); read.close(); return null }).walk(root, skip.toTypedArray(), write)
        }
        write.close()
        return read
    }

    private const val REQUEST_CODE = 4711
}
