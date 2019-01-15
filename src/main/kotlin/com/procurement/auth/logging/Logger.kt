package com.procurement.auth.logging

inline fun Logger.error(message: () -> String) {
    if (this.isErrorEnabled)
        this.error(message())
}

inline fun Logger.error(exception: Throwable, message: () -> String) {
    if (this.isErrorEnabled)
        this.error(exception, message())
}

inline fun Logger.info(message: () -> String) {
    if (this.isInfoEnabled)
        this.info(message())
}

inline fun Logger.info(exception: Throwable, message: () -> String) {
    if (this.isInfoEnabled)
        this.info(exception, message())
}

inline fun Logger.warn(message: () -> String) {
    if (this.isWarnEnabled)
        this.warn(message())
}

inline fun Logger.warn(exception: Throwable, message: () -> String) {
    if (this.isWarnEnabled)
        this.warn(exception, message())
}

inline fun Logger.debug(message: () -> String) {
    if (this.isDebugEnabled)
        this.debug(message())
}

inline fun Logger.debug(exception: Throwable, message: () -> String) {
    if (this.isDebugEnabled)
        this.debug(exception, message())
}

interface Logger {
    enum class Level { ERROR, INFO, WARN, DEBUG }

    val isErrorEnabled: Boolean
    val isInfoEnabled: Boolean
    val isWarnEnabled: Boolean
    val isDebugEnabled: Boolean

    fun error(message: String)
    fun error(exception: Throwable, message: String)

    fun info(message: String)
    fun info(exception: Throwable, message: String)

    fun warn(message: String)
    fun warn(exception: Throwable, message: String)

    fun debug(message: String)
    fun debug(exception: Throwable, message: String)

    fun perform(level: Level, message: String)
    fun perform(level: Level, exception: Throwable, message: String)
}