package com.procurement.auth.service

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.nhaarman.mockito_kotlin.*
import com.procurement.auth.USER_ID
import com.procurement.auth.USER_NAME
import com.procurement.auth.USER_PASSWORD
import com.procurement.auth.configuration.properties.LifeTime
import com.procurement.auth.configuration.properties.RSAKeyProperties
import com.procurement.auth.exception.security.*
import com.procurement.auth.helper.genAccessToken
import com.procurement.auth.helper.genExpiresOn
import com.procurement.auth.helper.genRefreshToken
import com.procurement.auth.model.*
import com.procurement.auth.model.rsa.RSAKeyPair
import com.procurement.auth.security.KeyFactoryServiceImpl
import com.procurement.auth.security.RSAKeyGenerator
import com.procurement.auth.security.RSAServiceImpl
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import java.time.LocalDateTime
import java.util.*

class TokenServiceTest {
    companion object {
        private val PLATFORM_ID = UUID.randomUUID()
    }

    private val crypt = BCryptPasswordEncoder()
    private val rsaService = RSAServiceImpl(KeyFactoryServiceImpl())
    private val rsaKeyPair: RSAKeyPair
    private val rsaKeyProperties: RSAKeyProperties
    private val algorithm: Algorithm

    private lateinit var accountService: AccountService
    private lateinit var service: TokenService

    init {
        rsaKeyPair = genRSAKey()

        rsaKeyProperties = RSAKeyProperties(
            publicKey = rsaKeyPair.publicKey,
            privateKey = rsaKeyPair.privateKey,
            lifeTime = LifeTime(
                access = 1000,
                refresh = 10000
            )
        )

        val publicKey = rsaService.toPublicKey(rsaKeyPair.publicKey)
        val privateKey = rsaService.toPrivateKey(rsaKeyPair.privateKey)
        algorithm = Algorithm.RSA256(publicKey, privateKey)
    }

    @BeforeEach
    fun init() {
        accountService = mock()
        service = TokenServiceImpl(
            rsaKeyProperties = rsaKeyProperties,
            accountService = accountService,
            rsaService = rsaService
        )
    }

    @Test
    @DisplayName("getTokensByUserCredentials - OK")
    fun getTokensByUserCredentials() {
        val userCredentials = UserCredentials(USER_NAME, USER_PASSWORD)
        val account = Account(
            id = USER_ID,
            username = USER_NAME,
            hashPassword = crypt.encode(USER_PASSWORD),
            enabled = true,
            platformId = PLATFORM_ID
        )
        whenever(accountService.findByUserCredentials(eq(userCredentials)))
            .thenReturn(account)

        val tokens = service.getTokensByUserCredentials(userCredentials)
        assertNotNull(tokens)

        val verifier = getVerifier()

        val jwtAccess = verifier.verify(tokens.accessToken)
        assertEquals(PLATFORM_ID.toString(), jwtAccess.getClaim(CLAIM_NAME_PLATFORM_ID).asString())
        assertEquals(ACCESS_TOKEN_TYPE, jwtAccess.getHeaderClaim(HEADER_NAME_TOKEN_TYPE).asString())

        val jwtRefresh = verifier.verify(tokens.refreshToken)
        assertEquals(PLATFORM_ID.toString(), jwtRefresh.getClaim(CLAIM_NAME_PLATFORM_ID).asString())
        assertEquals(REFRESH_TOKEN_TYPE, jwtRefresh.getHeaderClaim(HEADER_NAME_TOKEN_TYPE).asString())
    }

    @Test
    @DisplayName("getTokensByUserCredentials - AccountRevokedException")
    fun getTokensByUserCredentials5() {
        doThrow(
            AccountRevokedException(message = ""))
            .whenever(accountService)
            .findByUserCredentials(any())

        assertEquals(
            "",
            assertThrows(
                AccountRevokedException::class.java,
                {
                    val userCredentials = UserCredentials(USER_NAME, USER_PASSWORD)
                    service.getTokensByUserCredentials(userCredentials)
                }
            ).message
        )
    }

    @Test
    @DisplayName("getTokensByRefreshToken - OK")
    fun getTokensByRefreshToken() {
        val account = Account(
            id = USER_ID,
            username = USER_NAME,
            hashPassword = crypt.encode(USER_PASSWORD),
            enabled = true,
            platformId = PLATFORM_ID
        )
        whenever(accountService.findByPlatformId(any()))
            .thenReturn(account)

        val refreshToken = genRefreshToken(LocalDateTime.now())
        val tokens = service.getTokensByRefreshToken(refreshToken)
        assertNotNull(tokens)

        val verifier = getVerifier()

        val jwtAccess = verifier.verify(tokens.accessToken)
        assertEquals(PLATFORM_ID.toString(), jwtAccess.getClaim(CLAIM_NAME_PLATFORM_ID).asString())
        assertEquals("ACCESS", jwtAccess.getHeaderClaim(HEADER_NAME_TOKEN_TYPE).asString())

        val jwtRefresh = verifier.verify(tokens.refreshToken)
        assertEquals(PLATFORM_ID.toString(), jwtRefresh.getClaim(CLAIM_NAME_PLATFORM_ID).asString())
        assertEquals("REFRESH", jwtRefresh.getHeaderClaim(HEADER_NAME_TOKEN_TYPE).asString())
    }

    @Test
    @DisplayName("getTokensByRefreshToken - TokenExpiredException")
    fun tokenExpired() {
        assertEquals(
            "The refresh token is expired.",
            assertThrows(
                TokenExpiredException::class.java,
                {
                    val refreshToken = genRefreshToken(LocalDateTime.now().minusDays(1))
                    service.getTokensByRefreshToken(refreshToken)
                }
            ).message
        )
    }

    @Test
    @DisplayName("getTokensByRefreshToken - WrongTypeRefreshTokenException")
    fun bearerTokenWrongType() {
        assertEquals(
            "Invalid the token type.",
            assertThrows(
                WrongTypeRefreshTokenException::class.java,
                {
                    val refreshToken = genAccessToken(LocalDateTime.now())
                    service.getTokensByRefreshToken(refreshToken)
                }
            ).message
        )
    }

    @Test
    @DisplayName("getTokensByRefreshToken - VerificationTokenException")
    fun bearerTokenWrongType2() {
        assertEquals(
            "Error of verification the token.",
            assertThrows(
                VerificationTokenException::class.java,
                {
                    val refreshToken = genAccessToken(LocalDateTime.now()).substring(1)
                    service.getTokensByRefreshToken(refreshToken)
                }
            ).message
        )
    }

    @Test
    @DisplayName("getTokensByRefreshToken - AccountRevokedException")
    fun accountRevoked() {
        doThrow(
            AccountRevokedException(message = ""))
            .whenever(accountService)
            .findByPlatformId(eq(PLATFORM_ID))

        assertEquals(
            "",
            assertThrows(
                AccountRevokedException::class.java,
                {
                    val refreshToken = genRefreshToken(LocalDateTime.now())
                    service.getTokensByRefreshToken(refreshToken)
                }
            ).message
        )
    }

    @Test
    @DisplayName("getTokensByRefreshToken - PlatformUnknownException")
    fun platformNotFound() {
        doThrow(PlatformUnknownException(message = ""))
            .whenever(accountService)
            .findByPlatformId(eq(PLATFORM_ID))

        assertEquals(
            "",
            assertThrows(
                PlatformUnknownException::class.java,
                {
                    val refreshToken = genRefreshToken(LocalDateTime.now())
                    service.getTokensByRefreshToken(refreshToken)
                }
            ).message
        )
    }

    private fun genRSAKey() = RSAKeyGenerator().generate(2048)

    private fun genAccessToken(dateTime: LocalDateTime): String =
        genAccessToken(
            PLATFORM_ID,
            dateTime.genExpiresOn(rsaKeyProperties.lifeTime.access),
            algorithm
        )

    private fun genRefreshToken(dateTime: LocalDateTime): String =
        genRefreshToken(
            PLATFORM_ID,
            dateTime.genExpiresOn(rsaKeyProperties.lifeTime.refresh),
            algorithm
        )

    private fun getVerifier(): JWTVerifier = JWT.require(algorithm).build()
}