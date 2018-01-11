package com.procurement.auth.controller

import com.procurement.auth.exception.security.*
import com.procurement.auth.model.BASIC_REALM
import com.procurement.auth.model.BEARER_REALM
import com.procurement.auth.model.HEADER_NAME_WWW_AUTHENTICATE
import com.procurement.auth.model.token.AuthTokenType
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler

@ControllerAdvice
class WebExceptionHandler : ResponseEntityExceptionHandler() {
    companion object {
        val log: Logger = LoggerFactory.getLogger(WebExceptionHandler::class.java)
    }

    @ExceptionHandler(value = [NoSuchAuthHeaderException::class])
    fun noSuchAuthHeaderException(e: NoSuchAuthHeaderException): ResponseEntity<*> {
        when (e.authTokenType) {
            AuthTokenType.BASIC -> log.debug("There is no 'Basic' authentication header.", e)
            AuthTokenType.BEARER -> log.debug("There is no 'Bearer' authentication header.", e)
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(HEADER_NAME_WWW_AUTHENTICATE, BASIC_REALM)
            .build<Any>()
    }

    @ExceptionHandler(value = [InvalidAuthHeaderTypeException::class])
    fun invalidAuthHeaderTypeException(e: InvalidAuthHeaderTypeException): ResponseEntity<*> {
        when (e.authTokenType) {
            AuthTokenType.BASIC ->
                log.debug("Invalid authentication type, requires a 'Basic' authentication type.", e)
            AuthTokenType.BEARER ->
                log.debug("Invalid authentication type, requires a 'Bearer' authentication type.", e)
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(HEADER_NAME_WWW_AUTHENTICATE, BASIC_REALM)
            .build<Any>()
    }

    @ExceptionHandler(value = [InvalidUserCredentialsTokenException::class])
    fun invalidUserCredentialsTokenException(e: InvalidUserCredentialsTokenException): ResponseEntity<*> {
        log.debug("Invalid format 'Basic' token.", e)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(HEADER_NAME_WWW_AUTHENTICATE, BASIC_REALM)
            .build<Any>()
    }

    @ExceptionHandler(value = [AccountNotFoundException::class])
    fun accountNotFoundException(e: AccountNotFoundException): ResponseEntity<*> {
        log.debug("Account not found.", e)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(HEADER_NAME_WWW_AUTHENTICATE, BASIC_REALM)
            .build<Any>()
    }

    @ExceptionHandler(value = [PlatformNotFoundException::class])
    fun platformNotFoundException(e: PlatformNotFoundException): ResponseEntity<*> {
        log.debug("Platform not found.", e)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(HEADER_NAME_WWW_AUTHENTICATE,
                    """$BEARER_REALM, error_code="invalid_token", error_message="Invalid platform id""""
            )
            .build<Any>()
    }

    @ExceptionHandler(value = [InvalidUserCredentialsException::class])
    fun invalidPasswordException(e: InvalidUserCredentialsException): ResponseEntity<*> {
        log.debug("Invalid user credentials.", e)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(HEADER_NAME_WWW_AUTHENTICATE, BASIC_REALM)
            .build<Any>()
    }

    @ExceptionHandler(value = [AccountRevokedException::class])
    fun accountRevokedException(e: AccountRevokedException): ResponseEntity<*> {
        log.debug("The account revoked.", e)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(HEADER_NAME_WWW_AUTHENTICATE,
                    when (e.authTokenType) {
                        AuthTokenType.BASIC -> """$BASIC_REALM, error_message="The account revoked""""
                        AuthTokenType.BEARER -> """$BEARER_REALM, error_code="invalid_token", error_message="The account revoked""""
                    }
            )
            .build<Any>()
    }

    @ExceptionHandler(value = [BearerTokenWrongTypeException::class])
    fun bearerTokenWrongTypeException(e: BearerTokenWrongTypeException): ResponseEntity<*> {
        log.debug("The bearer token of wrong type.", e)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(
                HEADER_NAME_WWW_AUTHENTICATE,
                """$BEARER_REALM, error_code="invalid_token", error_message="The token of wrong type""""
            )
            .build<Any>()
    }

    @ExceptionHandler(value = [RefreshTokenExpiredException::class])
    fun refreshTokenExpiredException(e: RefreshTokenExpiredException): ResponseEntity<*> {
        log.debug("The token expired.", e)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(
                HEADER_NAME_WWW_AUTHENTICATE,
                """$BEARER_REALM, error_code="invalid_token", error_message="The token expired""""
            )
            .build<Any>()
    }
}