package com.procurement.auth.controller

import com.procurement.auth.exception.security.*
import com.procurement.auth.helper.getBearerTokenByAuthHeader
import com.procurement.auth.model.*
import com.procurement.auth.model.response.*
import com.procurement.auth.service.TokenService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/auth")
class TokenController(
    private val tokenService: TokenService
) {

    companion object {
        val log: Logger = LoggerFactory.getLogger(TokenController::class.java)
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
        log.warn(e.message)
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
        log.warn(e.message)
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
        SignInController.log.warn(e.message)
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
        SignInController.log.warn(e.message)
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
        log.warn(e.message)
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
        log.warn(e.message)
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
        log.warn(e.message)
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
        log.warn(e.message)
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