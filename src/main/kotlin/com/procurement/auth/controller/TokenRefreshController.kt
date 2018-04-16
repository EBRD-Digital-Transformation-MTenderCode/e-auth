package com.procurement.auth.controller

import com.procurement.auth.exception.security.*
import com.procurement.auth.helper.getBearerTokenByAuthHeader
import com.procurement.auth.model.AUTHORIZATION_HEADER_NAME
import com.procurement.auth.model.BEARER_REALM
import com.procurement.auth.model.ERROR_CODE_INVALID_TOKEN
import com.procurement.auth.model.WWW_AUTHENTICATE_HEADER_NAME
import com.procurement.auth.model.response.*
import com.procurement.auth.service.TokenService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/auth")
class TokenRefreshController(
    private val tokenService: TokenService
) {

    companion object {
        val log: Logger = LoggerFactory.getLogger(TokenRefreshController::class.java)
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

    @ExceptionHandler(value = [NoSuchAuthHeaderException::class])
    fun noSuchAuthHeader(e: NoSuchAuthHeaderException): ResponseEntity<BaseRS> {
        log.warn(e.message)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(WWW_AUTHENTICATE_HEADER_NAME, BEARER_REALM)
            .body(
                ErrorRS(
                    listOf(
                        com.procurement.auth.model.response.Error(
                            code = "auth.header.noSuch",
                            description = "The authentication header is missing."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [InvalidAuthHeaderTypeException::class])
    fun invalidAuthHeaderType(e: InvalidAuthHeaderTypeException): ResponseEntity<BaseRS> {
        log.warn(e.message)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(WWW_AUTHENTICATE_HEADER_NAME, BEARER_REALM)
            .body(
                ErrorRS(
                    listOf(
                        com.procurement.auth.model.response.Error(
                            code = "auth.header.invalidType",
                            description = "Invalid type of the authentication token. Expected type is 'Bearer'."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [EmptyAuthTokenException::class])
    fun emptyAuthToken(e: EmptyAuthTokenException): ResponseEntity<BaseRS> {
        SignInController.log.warn(e.message)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(WWW_AUTHENTICATE_HEADER_NAME, BEARER_REALM)
            .body(
                ErrorRS(
                    listOf(
                        Error(
                            code = "auth.token.empty",
                            description = "The authentication token is empty."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [VerificationTokenException::class])
    fun verificationToken(e: VerificationTokenException): ResponseEntity<BaseRS> {
        SignInController.log.warn(e.message)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
            .header(WWW_AUTHENTICATE_HEADER_NAME, BEARER_REALM)
            .body(
                ErrorRS(
                    listOf(
                        Error(
                            code = "auth.token.verification",
                            description = "The error of verification of the authentication token."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [WrongTypeRefreshTokenException::class])
    fun wrongTypeRefreshToken(e: WrongTypeRefreshTokenException): ResponseEntity<BaseRS> {
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
                            code = "auth.token.invalidType",
                            description = "Invalid the token type."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [PlatformUnknownException::class])
    fun platformNotFound(e: PlatformUnknownException): ResponseEntity<BaseRS> {
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
                            code = "account.platform.unknown",
                            description = "The platform is unknown."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [TokenExpiredException::class])
    fun refreshTokenExpired(e: TokenExpiredException): ResponseEntity<BaseRS> {
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
                            code = "auth.token.expired",
                            description = "The authentication token is expired."
                        )
                    )
                )
            )
    }

    @ExceptionHandler(value = [AccountRevokedException::class])
    fun accountRevoked(e: AccountRevokedException): ResponseEntity<BaseRS> {
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
                            code = "account.revoked",
                            description = "The account is revoked."
                        )
                    )
                )
            )
    }
}