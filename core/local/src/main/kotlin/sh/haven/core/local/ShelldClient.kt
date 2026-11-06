package sh.haven.core.local

import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.IOException

/**
 * Client for the bundled `xnix-shelld` privileged daemon.
 *
 * Connects to the abstract AF_UNIX socket "@xnix-shelld" and runs
 * commands / allocates PTYs as the shell (UID 2000) user. This allows
 * PRoot and terminal sessions to run unrestricted by GrapheneOS's TSEC ptrace
 * denial on system apps.
 */
object ShelldClient {

    private const val TAG = "ShelldClient"
    private val nativeLoaded: Boolean = try {
        System.loadLibrary("pty_bridge")
        true
    } catch (_: UnsatisfiedLinkError) {
        false
    } catch (_: SecurityException) {
        false
    }

    /**
     * Connect to the daemon and request EXEC of [cmd] (`sh -c <cmd>`).
     * Returns a connected socket fd streaming the command's combined
     * stdout/stderr, or a negative errno on failure.
     */
    external fun connectExec(cmd: String): Int

    /**
     * Ask the daemon to allocate a real PTY and spawn `sh` (or `sh -c <cmd>`
     * when [cmd] is non-null). Returns the PTY master fd, or a negative errno.
     */
    external fun openPty(cmd: String?): Int

    /**
     * Check if the xnix-shelld daemon is alive and accessible.
     */
    fun isAvailable(): Boolean {
        if (!nativeLoaded) return false
        return try {
            val fd = openPty(null)
            if (fd >= 0) {
                try {
                    ParcelFileDescriptor.adoptFd(fd).close()
                } catch (_: Exception) {}
                true
            } else {
                false
            }
        } catch (t: Throwable) {
            Log.d(TAG, "xnix-shelld not available: ${t.message}")
            false
        }
    }

    /**
     * Convenience: run [command] via PTY in shell domain and accumulate output.
     */
    fun exec(command: String, timeoutMs: Long = 30_000): String {
        val fd = openPty(command)
        if (fd < 0) {
            Log.w(TAG, "openPty failed: errno=${-fd}")
            return "Error: xnix-shelld openPty failed (errno ${-fd})"
        }

        val sb = StringBuilder()
        val pfd = ParcelFileDescriptor.adoptFd(fd)
        val thread = Thread {
            try {
                FileInputStream(pfd.fileDescriptor).use { input ->
                    val buf = ByteArray(4096)
                    while (true) {
                        try {
                            val n = input.read(buf)
                            if (n < 0) break
                            sb.append(String(buf, 0, n))
                            if (sb.length > 65536) break
                        } catch (_: IOException) {
                            // EIO on PTY slave close is normal EOF on Linux
                            break
                        }
                    }
                }
            } catch (_: Exception) {}
        }
        thread.start()
        thread.join(timeoutMs)
        if (thread.isAlive) {
            thread.interrupt()
            sb.append("\n[timeout after ${timeoutMs / 1000}s]")
        }
        try { pfd.close() } catch (_: Exception) {}

        val raw = sb.toString()
        val nullIdx = raw.indexOf('\u0000')
        val out = (if (nullIdx >= 0) raw.substring(0, nullIdx) else raw).trim()
        Log.d(TAG, "exec ($command) -> ${out.take(200)}")
        return out
    }
}
