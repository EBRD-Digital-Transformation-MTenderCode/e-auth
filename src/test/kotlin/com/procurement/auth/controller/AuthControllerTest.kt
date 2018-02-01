package com.procurement.auth.controller

import com.nhaarman.mockito_kotlin.any
import com.nhaarman.mockito_kotlin.doThrow
import com.nhaarman.mockito_kotlin.mock
import com.nhaarman.mockito_kotlin.whenever
import com.procurement.auth.exception.security.*
import com.procurement.auth.model.*
import com.procurement.auth.model.token.AuthTokenType
import com.procurement.auth.model.token.AuthTokens
import com.procurement.auth.service.TokenService
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import javax.servlet.http.HttpServletRequest

class AuthControllerTest {
    companion object {
        private const val URL_TOKENS = "/auth/tokens"
        private const val URL_REFRESH = "/auth/refresh"

        private const val ACCESS_TOKEN_VALUE = "ACCESS_TOKEN_VALUE"
        private const val REFRESH_TOKEN_VALUE = "REFRESH_TOKEN_VALUE"
    }

    private lateinit var mockMvc: MockMvc
    private lateinit var tokenService: TokenService

    private val httpServletRequest: HttpServletRequest
        get() {
            val request = MockHttpServletRequest()
            request.remoteAddr = "127.0.0.1"
            request.remoteHost = "localhost"
            return request
        }

    @BeforeEach
    fun setUp() {
        tokenService = mock()

        val controller = AuthController(tokenService = tokenService)
        val exceptionHandler = WebExceptionHandler()
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
            .setControllerAdvice(exceptionHandler)
            .build()
    }

    @Test
    @DisplayName("tokens - OK")
    fun tokens() {
        val authTokens = AuthTokens(ACCESS_TOKEN_VALUE, REFRESH_TOKEN_VALUE)
        whenever(tokenService.getTokensByUserCredentials(any()))
            .thenReturn(authTokens)

        mockMvc.perform(get(URL_TOKENS))
            .andExpect(status().isOk)
            .andExpect(header().string(HEADER_NAME_ACCESS_TOKEN, ACCESS_TOKEN_VALUE))
            .andExpect(header().string(HEADER_NAME_REFRESH_TOKEN, REFRESH_TOKEN_VALUE))
    }

    @Test
    @DisplayName("tokens - NoSuchAuthHeaderException")
    fun tokens1() {
        doThrow(NoSuchAuthHeaderException(request = httpServletRequest, authTokenType = AuthTokenType.BASIC))
            .whenever(tokenService)
            .getTokensByUserCredentials(any())

        mockMvc.perform(get(URL_TOKENS))
            .andExpect(status().isUnauthorized)
            .andExpect(
                header().string(HEADER_NAME_WWW_AUTHENTICATE, BASIC_REALM)
            )
    }

    @Test
    @DisplayName("tokens - InvalidAuthHeaderTypeException")
    fun tokens2() {
        doThrow(InvalidAuthHeaderTypeException(request = httpServletRequest, authTokenType = AuthTokenType.BASIC))
            .whenever(tokenService)
            .getTokensByUserCredentials(any())

        mockMvc.perform(get(URL_TOKENS))
            .andExpect(status().isUnauthorized)
            .andExpect(
                header().string(HEADER_NAME_WWW_AUTHENTICATE, BASIC_REALM)
            )
    }

    @Test
    @DisplayName("tokens - InvalidUserCredentialsTokenException")
    fun tokens3() {
        doThrow(InvalidUserCredentialsTokenException(request = httpServletRequest))
            .whenever(tokenService)
            .getTokensByUserCredentials(any())

        mockMvc.perform(get(URL_TOKENS))
            .andExpect(status().isUnauthorized)
            .andExpect(
                header().string(HEADER_NAME_WWW_AUTHENTICATE, BASIC_REALM)
            )
    }

    @Test
    @DisplayName("tokens - AccountNotFoundException")
    fun tokens4() {
        doThrow(AccountNotFoundException(request = httpServletRequest))
            .whenever(tokenService)
            .getTokensByUserCredentials(any())

        mockMvc.perform(get(URL_TOKENS))
            .andExpect(status().isUnauthorized)
            .andExpect(
                header().string(HEADER_NAME_WWW_AUTHENTICATE, BASIC_REALM)
            )
    }

    @Test
    @DisplayName("tokens - InvalidUserCredentialsException")
    fun tokens5() {
        doThrow(InvalidUserCredentialsException(request = httpServletRequest))
            .whenever(tokenService)
            .getTokensByUserCredentials(any())

        mockMvc.perform(get(URL_TOKENS))
            .andExpect(status().isUnauthorized)
            .andExpect(
                header().string(HEADER_NAME_WWW_AUTHENTICATE, BASIC_REALM)
            )
    }

    @Test
    @DisplayName("tokens - AccountRevokedException")
    fun tokens6() {
        doThrow(AccountRevokedException(request = httpServletRequest, authTokenType = AuthTokenType.BASIC))
            .whenever(tokenService)
            .getTokensByUserCredentials(any())

        mockMvc.perform(get(URL_TOKENS))
            .andExpect(status().isUnauthorized)
            .andExpect(
                header().string(HEADER_NAME_WWW_AUTHENTICATE, """$BASIC_REALM, error_message="The account revoked"""")
            )
    }

    @Test
    @DisplayName("refresh - OK")
    fun refresh() {
        val authTokens = AuthTokens(ACCESS_TOKEN_VALUE, REFRESH_TOKEN_VALUE)
        whenever(tokenService.getTokensByRefreshToken(any()))
            .thenReturn(authTokens)

        mockMvc.perform(get(URL_REFRESH))
            .andExpect(status().isOk)
            .andExpect(header().string(HEADER_NAME_ACCESS_TOKEN, ACCESS_TOKEN_VALUE))
            .andExpect(header().string(HEADER_NAME_REFRESH_TOKEN, REFRESH_TOKEN_VALUE))
    }

    @Test
    @DisplayName("refresh - NoSuchAuthHeaderException")
    fun refresh2() {
        doThrow(NoSuchAuthHeaderException(request = httpServletRequest, authTokenType = AuthTokenType.BEARER))
            .whenever(tokenService)
            .getTokensByRefreshToken(any())

        mockMvc.perform(get(URL_REFRESH))
            .andExpect(status().isUnauthorized)
            .andExpect(
                header().string(HEADER_NAME_WWW_AUTHENTICATE, BEARER_REALM)
            )
    }

    @Test
    @DisplayName("refresh - InvalidAuthHeaderTypeException")
    fun refresh3() {
        doThrow(InvalidAuthHeaderTypeException(request = httpServletRequest, authTokenType = AuthTokenType.BEARER))
            .whenever(tokenService)
            .getTokensByRefreshToken(any())

        mockMvc.perform(get(URL_REFRESH))
            .andExpect(status().isUnauthorized)
            .andExpect(
                header().string(HEADER_NAME_WWW_AUTHENTICATE, BEARER_REALM)
            )
    }

    @Test
    @DisplayName("refresh - PlatformNotFoundException")
    fun refresh4() {
        doThrow(PlatformNotFoundException(request = httpServletRequest))
            .whenever(tokenService)
            .getTokensByRefreshToken(any())

        mockMvc.perform(get(URL_REFRESH))
            .andExpect(status().isUnauthorized)
            .andExpect(
                header()
                    .string(HEADER_NAME_WWW_AUTHENTICATE,
                            """$BEARER_REALM, error_code="invalid_token", error_message="Invalid platform id""""
                    )
            )
    }

    @Test
    @DisplayName("refresh - AccountRevokedException")
    fun refresh5() {
        doThrow(AccountRevokedException(request = httpServletRequest, authTokenType = AuthTokenType.BEARER))
            .whenever(tokenService)
            .getTokensByRefreshToken(any())

        mockMvc.perform(get(URL_REFRESH))
            .andExpect(status().isUnauthorized)
            .andExpect(
                header()
                    .string(HEADER_NAME_WWW_AUTHENTICATE,
                            """$BEARER_REALM, error_code="invalid_token", error_message="The account revoked""""
                    )
            )
    }

    @Test
    @DisplayName("refresh - BearerTokenWrongTypeException")
    fun refresh6() {
        doThrow(BearerTokenWrongTypeException(request = httpServletRequest))
            .whenever(tokenService)
            .getTokensByRefreshToken(any())

        mockMvc.perform(get(URL_REFRESH))
            .andExpect(status().isUnauthorized)
            .andExpect(
                header()
                    .string(HEADER_NAME_WWW_AUTHENTICATE,
                            """$BEARER_REALM, error_code="invalid_token", error_message="The token of wrong type""""
                    )
            )
    }

    @Test
    @DisplayName("refresh - RefreshTokenExpiredException")
    fun refresh7() {
        doThrow(RefreshTokenExpiredException(request = httpServletRequest))
            .whenever(tokenService)
            .getTokensByRefreshToken(any())

        mockMvc.perform(get(URL_REFRESH))
            .andExpect(status().isUnauthorized)
            .andExpect(
                header()
                    .string(
                        HEADER_NAME_WWW_AUTHENTICATE,
                        """$BEARER_REALM, error_code="invalid_token", error_message="The token expired""""
                    )
            )
    }
}
