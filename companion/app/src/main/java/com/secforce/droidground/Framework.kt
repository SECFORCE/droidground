package com.secforce.droidground

import android.os.Handler
import android.os.HandlerThread

object Framework {
    private val thread: HandlerThread by lazy {
        HandlerThread("framework").apply { start() }
    }
    private val handler: Handler by lazy { Handler(thread.looper) }

    @Volatile private var _systemContext: android.content.Context? = null

    fun systemContext(): android.content.Context {
        _systemContext?.let { return it }

        val lock = Object()
        var error: Throwable? = null

        handler.post {
            try {
                _systemContext = createSystemContext()
            } catch (t: Throwable) {
                error = t
            } finally {
                synchronized(lock) { lock.notifyAll() }
            }
        }

        synchronized(lock) { lock.wait() }

        error?.let { throw RuntimeException("Failed to init system context", it) }
        return _systemContext!!
    }

    private fun createSystemContext(): android.content.Context {
        val atClass = Class.forName("android.app.ActivityThread")
        val current = atClass.getMethod("currentActivityThread").invoke(null)
        val thread = current ?: atClass.getMethod("systemMain").invoke(null)
        return atClass.getMethod("getSystemContext").invoke(thread) as android.content.Context
    }
}
