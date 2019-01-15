package com.procurement.auth.controller

import com.procurement.auth.exception.security.AccountRevokedException
import com.procurement.auth.exception.security.EmptyAuthTokenException
import com.procurement.auth.exception.security.InvalidAuthHeaderTypeException
import com.procurement.auth.exception.security.InvalidAuthTokenFormatException
import com.procurement.auth.exception.security.InvalidCredentialsException
import com.procurement.auth.exception.security.NoSuchAuthHeaderException
import com.procurement.auth.helper.getUserCredentialsByAuthHeader
import com.procurement.auth.infrastructure.logger.Slf4jLogger
import com.procurement.auth.logging.Logger
import com.procurement.auth.model.AUTHORIZATION_HEADER_NAME
import com.procurement.auth.model.BASIC_REALM
import com.procurement.auth.model.CodesOfErrors
import com.procurement.auth.model.WWW_AUTHENTICATE_HEADER_NAME
import com.procurement.auth.model.response.Data
import com.procurement.auth.model.response.ErrorRS
import com.procurement.auth.model.response.TokenRS
import com.procurement.auth.model.response.Tokens
import com.procurement.auth.service.TokenService
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/auth")
class SignInController(
    private val tokenService: TokenService
) {

    companion object {
        val log: Logger = Slf4jLogger()
    }

    @GetMapping(value = ["/signin"])
    fun signIn(
        @RequestHeader(
            value = AUTHORIZATION_HEADER_NAME,
            required = false,
            defaultValue = "") authorizationHeader: String): ResponseEntity<TokenRS> {
        val userCredentials = getUserCredentialsByAuthHeader(authorizationHeader)
        val authTokens = tokenService.getTokensByUserCredentials(userCredentials)
        return ResponseEntity.ok()
            .body(
                TokenRS(
                    data = Data(
                        tokens = Tokens(
                            access = authTokens.accessToken,
                            refresh = authTokens.refreshToken
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [NoSuchAuthHeaderException::class])
    fun noSuchAuthHeader(e: NoSuchAuthHeaderException): ResponseEntity<ErrorRS> {
        log.warn(e.message!!)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(WWW_AUTHENTICATE_HEADER_NAME, BASIC_REALM)
            .body(
                ErrorRS(
                    listOf(
                        com.procurement.auth.model.response.Error(
                            code = CodesOfErrors.AUTH_HEADER_NO_SUCH.code,
                            description = "The authentication header is missing."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [InvalidAuthHeaderTypeException::class])
    fun invalidAuthHeaderType(e: InvalidAuthHeaderTypeException): ResponseEntity<ErrorRS> {
        log.warn(e.message!!)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(WWW_AUTHENTICATE_HEADER_NAME, BASIC_REALM)
            .body(
                ErrorRS(
                    listOf(
                        com.procurement.auth.model.response.Error(
                            code = CodesOfErrors.AUTH_HEADER_INVALID_TYPE.code,
                            description = "Invalid type of the authentication token. Expected type is 'Basic'."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [EmptyAuthTokenException::class])
    fun emptyAuthToken(e: EmptyAuthTokenException): ResponseEntity<ErrorRS> {
        log.warn(e.message!!)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(WWW_AUTHENTICATE_HEADER_NAME, BASIC_REALM)
            .body(
                ErrorRS(
                    listOf(
                        com.procurement.auth.model.response.Error(
                            code = CodesOfErrors.AUTH_TOKEN_EMPTY.code,
                            description = "The authentication token is empty."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [InvalidAuthTokenFormatException::class])
    fun invalidAuthTokenFormat(e: InvalidAuthTokenFormatException): ResponseEntity<ErrorRS> {
        log.warn(e.message!!)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(WWW_AUTHENTICATE_HEADER_NAME, BASIC_REALM)
            .body(
                ErrorRS(
                    listOf(
                        com.procurement.auth.model.response.Error(
                            code = CodesOfErrors.AUTH_TOKEN_INVALID_FORMAT.code,
                            description = "Invalid format of the authentication token."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [InvalidCredentialsException::class])
    fun invalidPassword(e: InvalidCredentialsException): ResponseEntity<ErrorRS> {
        log.warn(e.message!!)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(WWW_AUTHENTICATE_HEADER_NAME, BASIC_REALM)
            .body(
                ErrorRS(
                    listOf(
                        com.procurement.auth.model.response.Error(
                            code = CodesOfErrors.ACCOUNT_INVALID_CREDENTIALS.code,
                            description = "Invalid credentials."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [AccountRevokedException::class])
    fun accountRevoked(e: AccountRevokedException): ResponseEntity<ErrorRS> {
        log.warn(e.message!!)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(
                WWW_AUTHENTICATE_HEADER_NAME,
                """$BASIC_REALM, error_message="The account is revoked.""""
            )
            .body(
                ErrorRS(
                    listOf(
                        com.procurement.auth.model.response.Error(
                            code = CodesOfErrors.ACCOUNT_REVOKED.code,
                            description = "The account is revoked."
                        )
                    )
                )
            )
    }
}