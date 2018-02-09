package com.procurement.auth.service

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.nhaarman.mockito_kotlin.*
import com.procurement.auth.configuration.properties.LifeTime
import com.procurement.auth.configuration.properties.RSAKeyProperties
import com.procurement.auth.exception.security.*
import com.procurement.auth.helper.*
import com.procurement.auth.model.*
import com.procurement.auth.model.rsa.RSAKeyPair
import com.procurement.auth.model.token.AuthTokenType
import com.procurement.auth.security.KeyFactoryServiceImpl
import com.procurement.auth.security.RSAKeyGenerator
import com.procurement.auth.security.RSAServiceImpl
import org.apache.commons.codec.binary.Base64
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import java.time.LocalDateTime
import java.util.*

class TokenServiceTest {
    companion object {
        private val ID = 1L
        private const val USERNAME = "USERNAME"
        private const val PASSWORD = "PASSWORD"
        private val PLATFORM_ID = UUID.randomUUID()
    }

    private val crypt = BCryptPasswordEncoder()
    private val rsaService = RSAServiceImpl(KeyFactoryServiceImpl())
    private val rsaKeyPair: RSAKeyPair
    private val rsaKeyProperties: RSAKeyProperties
    private val algorithm: Algorithm

    private lateinit var accountService: AccountService
    private lateinit var httpServletRequest: MockHttpServletRequest
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
    fun setUp() {
        accountService = mock()
        httpServletRequest = MockHttpServletRequest()
        service = TokenServiceImpl(
            rsaKeyProperties = rsaKeyProperties,
            accountService = accountService,
            rsaService = rsaService
        )
    }

    @Test
    @DisplayName("getTokensByUserCredentials - OK")
    fun getTokensByUserCredentials() {
        val request = MockHttpServletRequest()
        request.addHeader(HEADER_NAME_AUTHORIZATION, genBasicToken())

        val account = Account(id = ID,
                              username = USERNAME,
                              hashPassword = crypt.encode(PASSWORD),
                              enabled = true,
                              platformId = PLATFORM_ID
        )
        whenever(accountService.findByUserCredentials(any(), any()))
            .thenReturn(account)

        val tokens = service.getTokensByUserCredentials(request)
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
    @DisplayName("getTokensByUserCredentials - NoSuchAuthHeaderException")
    fun getTokensByUserCredentials1() {
        val exception = assertThrows(
            NoSuchAuthHeaderException::class.java,
            {
                service.getTokensByUserCredentials(httpServletRequest)
            }
        )
        assertEquals(httpServletRequest, exception.request)
        assertEquals(AuthTokenType.BASIC, exception.authTokenType)
    }

    @Test
    @DisplayName("getTokensByUserCredentials - InvalidBasicAuthHeaderTypeException")
    fun getTokensByUserCredentials2() {
        httpServletRequest.addHeader(HEADER_NAME_AUTHORIZATION, AUTHORIZATION_PREFIX_BEARER + "INVALID_TOKEN")

        val exception = assertThrows(
            InvalidAuthHeaderTypeException::class.java,
            {
                service.getTokensByUserCredentials(httpServletRequest)
            }
        )
        assertEquals(httpServletRequest, exception.request)
        assertEquals(AuthTokenType.BASIC, exception.authTokenType)
    }

    @Test
    @DisplayName("getTokensByUserCredentials - InvalidUserCredentialsTokenException")
    fun getTokensByUserCredentials3() {
        httpServletRequest.addHeader(HEADER_NAME_AUTHORIZATION, AUTHORIZATION_PREFIX_BASIC + "INVALID_CREDENTIALS")

        val exception = assertThrows(
            InvalidUserCredentialsTokenException::class.java,
            {
                service.getTokensByUserCredentials(httpServletRequest)
            }
        )
        assertEquals(httpServletRequest, exception.request)
    }

    @Test
    @DisplayName("getTokensByUserCredentials - AccountNotFoundException")
    fun getTokensByUserCredentials4() {
        httpServletRequest.addHeader(HEADER_NAME_AUTHORIZATION, genBasicToken())

        doThrow(AccountNotFoundException(message = "", request = httpServletRequest))
            .whenever(accountService)
            .findByUserCredentials(any(), any())

        val exception = assertThrows(
            AccountNotFoundException::class.java,
            {
                service.getTokensByUserCredentials(httpServletRequest)
            }
        )
        assertEquals(httpServletRequest, exception.request)
    }

    @Test
    @DisplayName("getTokensByUserCredentials - AccountRevokedException")
    fun getTokensByUserCredentials5() {
        httpServletRequest.addHeader(HEADER_NAME_AUTHORIZATION, genBasicToken())

        doThrow(AccountRevokedException(message = "", request = httpServletRequest, authTokenType = AuthTokenType.BASIC))
            .whenever(accountService)
            .findByUserCredentials(any(), any())

        val exception = assertThrows(
            AccountRevokedException::class.java,
            {
                service.getTokensByUserCredentials(httpServletRequest)
            }
        )
        assertEquals(httpServletRequest, exception.request)
        assertEquals(AuthTokenType.BASIC, exception.authTokenType)
    }

    @Test
    @DisplayName("getTokensByRefreshToken - OK")
    fun getTokensByRefreshToken() {
        httpServletRequest.addHeader(HEADER_NAME_AUTHORIZATION,
                                     AUTHORIZATION_PREFIX_BEARER + genRefreshToken(LocalDateTime.now())
        )

        val account = Account(id = ID,
                              username = USERNAME,
                              hashPassword = crypt.encode(PASSWORD),
                              enabled = true,
                              platformId = PLATFORM_ID
        )
        whenever(accountService.findByPlatformId(any(), any()))
            .thenReturn(account)

        val tokens = service.getTokensByRefreshToken(httpServletRequest)
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
    @DisplayName("getTokensByRefreshToken - NoSuchAuthorizationHeaderException")
    fun getTokensByRefreshToken1() {
        val exception = assertThrows(
            NoSuchAuthHeaderException::class.java,
            {
                service.getTokensByRefreshToken(httpServletRequest)
            }
        )
        assertEquals(httpServletRequest, exception.request)
        assertEquals(AuthTokenType.BEARER, exception.authTokenType)
    }

    @Test
    @DisplayName("getTokensByRefreshToken - InvalidBasicAuthHeaderTypeException")
    fun getTokensByRefreshToken2() {
        httpServletRequest.addHeader(HEADER_NAME_AUTHORIZATION, AUTHORIZATION_PREFIX_BASIC + "INVALID_TOKEN")

        val exception = assertThrows(
            InvalidAuthHeaderTypeException::class.java,
            {
                service.getTokensByRefreshToken(httpServletRequest)
            }
        )
        assertEquals(httpServletRequest, exception.request)
        assertEquals(AuthTokenType.BEARER, exception.authTokenType)
    }

    @Test
    @DisplayName("getTokensByRefreshToken - RefreshTokenExpiredException")
    fun getTokensByRefreshToken3() {
        httpServletRequest.addHeader(HEADER_NAME_AUTHORIZATION,
                                     AUTHORIZATION_PREFIX_BEARER + genRefreshToken(LocalDateTime.now().minusDays(1))
        )

        val exception = assertThrows(
            RefreshTokenExpiredException::class.java,
            {
                service.getTokensByRefreshToken(httpServletRequest)
            }
        )
        assertEquals(httpServletRequest, exception.request)
    }

    @Test
    @DisplayName("getTokensByRefreshToken - BearerTokenWrongTypeException")
    fun getTokensByRefreshToken4() {
        httpServletRequest.addHeader(HEADER_NAME_AUTHORIZATION,
                                     AUTHORIZATION_PREFIX_BEARER + genAccessToken(LocalDateTime.now())
        )

        val exception = assertThrows(
            BearerTokenWrongTypeException::class.java,
            {
                service.getTokensByRefreshToken(httpServletRequest)
            }
        )
        assertEquals(httpServletRequest, exception.request)
    }

    @Test
    @DisplayName("getTokensByRefreshToken - AccountRevokedException")
    fun getTokensByRefreshToken5() {
        httpServletRequest.addHeader(HEADER_NAME_AUTHORIZATION,
                                     AUTHORIZATION_PREFIX_BEARER + genRefreshToken(LocalDateTime.now())
        )

        doThrow(AccountRevokedException(message = "", request = httpServletRequest, authTokenType = AuthTokenType.BEARER))
            .whenever(accountService)
            .findByPlatformId(eq(httpServletRequest), eq(PLATFORM_ID))

        val exception = assertThrows(
            AccountRevokedException::class.java,
            {
                service.getTokensByRefreshToken(httpServletRequest)
            }
        )
        assertEquals(httpServletRequest, exception.request)
        assertEquals(AuthTokenType.BEARER, exception.authTokenType)
    }

    @Test
    @DisplayName("getTokensByRefreshToken - PlatformNotFoundException")
    fun getTokensByRefreshToken6() {
        httpServletRequest.addHeader(HEADER_NAME_AUTHORIZATION,
                                     AUTHORIZATION_PREFIX_BEARER + genRefreshToken(LocalDateTime.now())
        )

        doThrow(PlatformNotFoundException(message = "", request = httpServletRequest))
            .whenever(accountService)
            .findByPlatformId(eq(httpServletRequest), eq(PLATFORM_ID))

        val exception = assertThrows(
            PlatformNotFoundException::class.java,
            {
                service.getTokensByRefreshToken(httpServletRequest)
            }
        )
        assertEquals(httpServletRequest, exception.request)
    }

    private fun genRSAKey() = RSAKeyGenerator().generate(2048)

    private fun genBasicToken() = AUTHORIZATION_PREFIX_BASIC + Base64.encodeBase64String("$USERNAME:$PASSWORD".toByteArray())

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