package com.procurement.auth.infrastructure.logger

import com.procurement.auth.logging.Logger
import org.slf4j.LoggerFactory

class Slf4jLogger : Logger {
    companion object {
        private val log: org.slf4j.Logger = LoggerFactory.getLogger(Logger::class.java)
    }

    override val isErrorEnabled: Boolean
        get() = log.isErrorEnabled

    override val isWarnEnabled: Boolean
        get() = log.isWarnEnabled

    override val isInfoEnabled: Boolean
        get() = log.isInfoEnabled

    override val isDebugEnabled: Boolean
        get() = log.isDebugEnabled

    override fun error(message: String) {
        if (log.isErrorEnabled) log.error(message)
    }

    override fun error(exception: Throwable, message: String) {
        if (log.isErrorEnabled) log.error(message, exception)
    }

    override fun info(message: String) {
        if (log.isInfoEnabled) log.info(message)
    }

    override fun info(exception: Throwable, message: String) {
        if (log.isInfoEnabled) log.info(message, exception)
    }

    override fun warn(message: String) {
        if (log.isWarnEnabled) log.warn(message)
    }

    override fun warn(exception: Throwable, message: String) {
        if (log.isWarnEnabled) log.warn(message, exception)
    }

    override fun debug(message: String) {
        if (log.isDebugEnabled) log.debug(message)
    }

    override fun debug(exception: Throwable, message: String) {
        if (log.isDebugEnabled) log.debug(message, exception)
    }

    override fun perform(level: Logger.Level, message: String) {
        when (level) {
            Logger.Level.ERROR -> error(message)
            Logger.Level.INFO -> info(message)
            Logger.Level.WARN -> warn(message)
            Logger.Level.DEBUG -> debug(message)
        }
    }

    override fun perform(level: Logger.Level, exception: Throwable, message: String) {
        when (level) {
            Logger.Level.ERROR -> error(exception, message)
            Logger.Level.INFO -> info(exception, message)
            Logger.Level.WARN -> warn(exception, message)
            Logger.Level.DEBUG -> debug(exception, message)
        }
    }
}