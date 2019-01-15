package com.procurement.auth.controller

import com.procurement.auth.exception.security.AccountRevokedException
import com.procurement.auth.exception.security.EmptyAuthTokenException
import com.procurement.auth.exception.security.InvalidAuthHeaderTypeException
import com.procurement.auth.exception.security.NoSuchAuthHeaderException
import com.procurement.auth.exception.security.PlatformUnknownException
import com.procurement.auth.exception.security.TokenExpiredException
import com.procurement.auth.exception.security.VerificationTokenException
import com.procurement.auth.exception.security.WrongTypeRefreshTokenException
import com.procurement.auth.helper.getBearerTokenByAuthHeader
import com.procurement.auth.infrastructure.logger.Slf4jLogger
import com.procurement.auth.model.AUTHORIZATION_HEADER_NAME
import com.procurement.auth.model.BEARER_REALM
import com.procurement.auth.model.CodesOfErrors
import com.procurement.auth.model.ERROR_CODE_INVALID_TOKEN
import com.procurement.auth.model.WWW_AUTHENTICATE_HEADER_NAME
import com.procurement.auth.model.response.Data
import com.procurement.auth.model.response.Error
import com.procurement.auth.model.response.ErrorRS
import com.procurement.auth.model.response.TokenRS
import com.procurement.auth.model.response.Tokens
import com.procurement.auth.model.response.VerificationSuccessRS
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
class TokenController(
    private val tokenService: TokenService
) {

    companion object {
        val log: com.procurement.auth.logging.Logger = Slf4jLogger()
    }

    @GetMapping(value = ["/refresh"])
    fun refresh(
        @RequestHeader(
            value = AUTHORIZATION_HEADER_NAME,
            required = false,
            defaultValue = "") authorizationHeader: String): ResponseEntity<TokenRS> {

        val token = getBearerTokenByAuthHeader(authorizationHeader)
        val authTokens = tokenService.getTokensByRefreshToken(token)
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

    @GetMapping("/verification")
    fun verification(
        @RequestHeader(
            value = AUTHORIZATION_HEADER_NAME,
            required = false,
            defaultValue = "") authorizationHeader: String): ResponseEntity<VerificationSuccessRS> {

        val token = getBearerTokenByAuthHeader(authorizationHeader)
        tokenService.verification(token)
        return ResponseEntity.ok(VerificationSuccessRS())
    }

    @ExceptionHandler(value = [NoSuchAuthHeaderException::class])
    fun noSuchAuthHeader(e: NoSuchAuthHeaderException): ResponseEntity<ErrorRS> {
        log.warn(e.message!!)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(WWW_AUTHENTICATE_HEADER_NAME, BEARER_REALM)
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
            .header(WWW_AUTHENTICATE_HEADER_NAME, BEARER_REALM)
            .body(
                ErrorRS(
                    listOf(
                        com.procurement.auth.model.response.Error(
                            code = CodesOfErrors.AUTH_HEADER_INVALID_TYPE.code,
                            description = "Invalid type of the authentication token. Expected type is 'Bearer'."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [EmptyAuthTokenException::class])
    fun emptyAuthToken(e: EmptyAuthTokenException): ResponseEntity<ErrorRS> {
        log.warn(e.message!!)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(WWW_AUTHENTICATE_HEADER_NAME, BEARER_REALM)
            .body(
                ErrorRS(
                    listOf(
                        Error(
                            code = CodesOfErrors.AUTH_TOKEN_EMPTY.code,
                            description = "The authentication token is empty."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [VerificationTokenException::class])
    fun verificationToken(e: VerificationTokenException): ResponseEntity<ErrorRS> {
        log.warn(e.message!!)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(WWW_AUTHENTICATE_HEADER_NAME, BEARER_REALM)
            .body(
                ErrorRS(
                    listOf(
                        Error(
                            code = CodesOfErrors.AUTH_TOKEN_VERIFICATION.code,
                            description = "The error of verification of the authentication token."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [WrongTypeRefreshTokenException::class])
    fun wrongTypeToken(e: WrongTypeRefreshTokenException): ResponseEntity<ErrorRS> {
        log.warn(e.message!!)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(
                WWW_AUTHENTICATE_HEADER_NAME,
                """$BEARER_REALM, $ERROR_CODE_INVALID_TOKEN, error_message="Invalid the token type.""""
            )
            .body(
                ErrorRS(
                    listOf(
                        Error(
                            code = CodesOfErrors.AUTH_TOKEN_INVALID_TYPE.code,
                            description = "Invalid the token type."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [PlatformUnknownException::class])
    fun platformNotFound(e: PlatformUnknownException): ResponseEntity<ErrorRS> {
        log.warn(e.message!!)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(
                WWW_AUTHENTICATE_HEADER_NAME,
                """$BEARER_REALM, $ERROR_CODE_INVALID_TOKEN, error_message="The platform is unknown.""""
            )
            .body(
                ErrorRS(
                    listOf(
                        Error(
                            code = CodesOfErrors.ACCOUNT_PLATFORM_UNKNOWN.code,
                            description = "The platform is unknown."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [TokenExpiredException::class])
    fun tokenExpired(e: TokenExpiredException): ResponseEntity<ErrorRS> {
        log.warn(e.message!!)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(
                WWW_AUTHENTICATE_HEADER_NAME,
                """$BEARER_REALM, $ERROR_CODE_INVALID_TOKEN, error_message="The token is expired.""""
            )
            .body(
                ErrorRS(
                    listOf(
                        Error(
                            code = CodesOfErrors.AUTH_TOKEN_EXPIRED.code,
                            description = "The authentication token is expired."
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
                """$BEARER_REALM, $ERROR_CODE_INVALID_TOKEN, error_message="The account is revoked.""""
            )
            .body(
                ErrorRS(
                    listOf(
                        Error(
                            code = CodesOfErrors.ACCOUNT_REVOKED.code,
                            description = "The account is revoked."
                        )
                    )
                )
            )
    }
}