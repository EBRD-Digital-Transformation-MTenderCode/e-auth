package com.procurement.auth.controller

import com.nhaarman.mockito_kotlin.any
import com.nhaarman.mockito_kotlin.doThrow
import com.nhaarman.mockito_kotlin.mock
import com.nhaarman.mockito_kotlin.whenever
import com.procurement.auth.ACCESS_TOKEN
import com.procurement.auth.REFRESH_TOKEN
import com.procurement.auth.exception.security.*
import com.procurement.auth.model.*
import com.procurement.auth.model.token.AuthTokens
import com.procurement.auth.service.TokenService
import org.hamcrest.core.IsEqual
import org.hamcrest.core.IsEqual.equalTo
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.restdocs.RestDocumentationContextProvider
import org.springframework.restdocs.RestDocumentationExtension
import org.springframework.restdocs.headers.HeaderDocumentation
import org.springframework.restdocs.headers.HeaderDocumentation.headerWithName
import org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders
import org.springframework.restdocs.http.HttpDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.operation.preprocess.Preprocessors
import org.springframework.restdocs.payload.PayloadDocumentation.responseFields
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.test.web.servlet.setup.StandaloneMockMvcBuilder

@ExtendWith(RestDocumentationExtension::class)
class TokenVerificationControllerTest {
    companion object {
        private const val URL = "/auth/refresh"
    }

    private lateinit var mockMvc: MockMvc
    private lateinit var tokenService: TokenService

    @BeforeEach
    fun init(restDocumentation: RestDocumentationContextProvider) {
        tokenService = mock()

        val controller = TokenController(tokenService = tokenService)
        val exceptionHandler = WebExceptionHandler()
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
            .setControllerAdvice(exceptionHandler)
            .apply<StandaloneMockMvcBuilder>(
                MockMvcRestDocumentation.documentationConfiguration(restDocumentation)
                    .uris()
                    .withScheme("https")
                    .withHost("eprocurement.systems")
                    .and()
                    .snippets()
                    .withDefaults(HttpDocumentation.httpRequest(), HttpDocumentation.httpResponse())
                    .and()
                    .operationPreprocessors()
                    .withRequestDefaults(Preprocessors.prettyPrint())
                    .withResponseDefaults(Preprocessors.prettyPrint())
            )
            .build()
    }

    @Test
    @DisplayName("The token refreshed successfully")
    fun refresh() {
        val authTokens = AuthTokens(ACCESS_TOKEN, REFRESH_TOKEN)
        whenever(tokenService.getTokensByRefreshToken(any()))
            .thenReturn(authTokens)

        val authHeaderValue = AUTHORIZATION_PREFIX_BEARER + REFRESH_TOKEN
        mockMvc.perform(
            get(URL)
                .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
            .andExpect(status().isOk)
            .andExpect(MockMvcResultMatchers.content().contentType("application/json;charset=UTF-8"))
            .andExpect(MockMvcResultMatchers.jsonPath("$.success", IsEqual.equalTo(true)))
            .andExpect(MockMvcResultMatchers.jsonPath("$.data.tokens.access", equalTo(ACCESS_TOKEN)))
            .andExpect(MockMvcResultMatchers.jsonPath("$.data.tokens.refresh", equalTo(REFRESH_TOKEN)))
            .andDo(
                document(
                    "refresh/success",
                    requestHeaders(
                        headerWithName(AUTHORIZATION_HEADER_NAME)
                            .description("Bearer refresh token.")
                    ),
                    responseFields(ModelDescription.Refresh.responseSuccessful())
                )
            )
    }

    @Test
    @DisplayName("No such the authentication header")
    fun noSuchAuthHeader() {
        val authHeaderValue = ""
        val wwwAuthHeaderValue = BEARER_REALM
        mockMvc.perform(
            get(URL)
                .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
            .andExpect(status().isUnauthorized)
            .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.success", equalTo(false)))
            .andExpect(jsonPath("$.errors.length()", equalTo(1)))
            .andExpect(jsonPath("$.errors[0].code", equalTo("auth.header.noSuch")))
            .andExpect(jsonPath("$.errors[0].description", equalTo("The authentication header is missing.")))
            .andDo(
                document(
                    "refresh/errors/no_such_auth_header",
                    requestHeaders(
                        ModelDescription.authHeader()
                    ),
                    HeaderDocumentation.responseHeaders(
                        ModelDescription.wwwAuthHeader(wwwAuthHeaderValue)
                    ),
                    responseFields(ModelDescription.responseError())
                )
            )
    }

    @Test
    @DisplayName("Invalid type of the authentication header")
    fun invalidAuthHeaderType() {
        val authHeaderValue = BASIC_REALM + REFRESH_TOKEN
        val wwwAuthHeaderValue = BEARER_REALM
        mockMvc.perform(
            get(URL)
                .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
            .andExpect(status().isUnauthorized)
            .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.success", equalTo(false)))
            .andExpect(jsonPath("$.errors.length()", equalTo(1)))
            .andExpect(jsonPath("$.errors[0].code", equalTo("auth.header.invalidType")))
            .andExpect(
                jsonPath(
                    "$.errors[0].description",
                    equalTo("Invalid type of the authentication token. Expected type is 'Bearer'.")
                )
            )
            .andDo(
                document(
                    "refresh/errors/invalid_type_auth_header",
                    requestHeaders(
                        ModelDescription.authHeader()
                    ),
                    HeaderDocumentation.responseHeaders(
                        ModelDescription.wwwAuthHeader(wwwAuthHeaderValue)
                    ),
                    responseFields(ModelDescription.responseError())
                )
            )
    }

    @Test
    @DisplayName("The authentication token is empty")
    fun emptyAuthToken() {
        val authHeaderValue = AUTHORIZATION_PREFIX_BEARER
        val wwwAuthHeaderValue = BEARER_REALM
        mockMvc.perform(
            get(URL)
                .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
            .andExpect(status().isUnauthorized)
            .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.success", equalTo(false)))
            .andExpect(jsonPath("$.errors.length()", equalTo(1)))
            .andExpect(jsonPath("$.errors[0].code", equalTo("auth.token.empty")))
            .andExpect(jsonPath("$.errors[0].description", equalTo("The authentication token is empty.")))
            .andDo(
                document(
                    "refresh/errors/auth_token_is_empty",
                    requestHeaders(
                        ModelDescription.authHeader()
                    ),
                    HeaderDocumentation.responseHeaders(
                        ModelDescription.wwwAuthHeader(wwwAuthHeaderValue)
                    ),
                    responseFields(ModelDescription.responseError())
                )
            )
    }

    @Test
    @DisplayName("The error of verification token")
    fun verificationToken() {
        doThrow(VerificationTokenException::class)
            .whenever(tokenService)
            .getTokensByRefreshToken(any())

        val authHeaderValue = AUTHORIZATION_PREFIX_BEARER + REFRESH_TOKEN
        val wwwAuthHeaderValue = BEARER_REALM
        mockMvc.perform(
            get(URL)
                .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
            .andExpect(status().isUnauthorized)
            .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.success", equalTo(false)))
            .andExpect(jsonPath("$.errors.length()", equalTo(1)))
            .andExpect(jsonPath("$.errors[0].code", equalTo("auth.token.verification")))
            .andExpect(
                jsonPath(
                    "$.errors[0].description",
                    equalTo("The error of verification of the authentication token.")
                )
            )
            .andDo(
                document(
                    "refresh/errors/invalid_signature",
                    requestHeaders(
                        ModelDescription.authHeader()
                    ),
                    HeaderDocumentation.responseHeaders(
                        ModelDescription.wwwAuthHeader(wwwAuthHeaderValue)
                    ),
                    responseFields(ModelDescription.responseError())
                )
            )
    }

    @Test
    @DisplayName("The refresh-token has expired")
    fun tokenExpired() {
        doThrow(TokenExpiredException(message = ""))
            .whenever(tokenService)
            .getTokensByRefreshToken(any())

        val authHeaderValue = AUTHORIZATION_PREFIX_BEARER + REFRESH_TOKEN
        val wwwAuthHeaderValue = """$BEARER_REALM, $ERROR_CODE_INVALID_TOKEN, error_message="The token is expired.""""
        mockMvc.perform(
            get(URL)
                .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
            .andExpect(status().isUnauthorized)
            .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.success", equalTo(false)))
            .andExpect(jsonPath("$.errors.length()", equalTo(1)))
            .andExpect(jsonPath("$.errors[0].code", equalTo("auth.token.expired")))
            .andExpect(jsonPath("$.errors[0].description", equalTo("The authentication token is expired.")))
            .andDo(
                document(
                    "refresh/errors/auth_token_is_expired",
                    requestHeaders(
                        ModelDescription.authHeader()
                    ),
                    HeaderDocumentation.responseHeaders(
                        ModelDescription.wwwAuthHeader(wwwAuthHeaderValue)
                    ),
                    responseFields(ModelDescription.responseError())
                )
            )
    }

    @Test
    @DisplayName("The platform is unknown")
    fun platformNotFound() {
        doThrow(PlatformUnknownException(message = ""))
            .whenever(tokenService)
            .getTokensByRefreshToken(any())

        val authHeaderValue = AUTHORIZATION_PREFIX_BEARER + REFRESH_TOKEN
        val wwwAuthHeaderValue = """$BEARER_REALM, $ERROR_CODE_INVALID_TOKEN, error_message="The platform is unknown.""""
        mockMvc.perform(
            get(URL)
                .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
            .andExpect(status().isUnauthorized)
            .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME,wwwAuthHeaderValue))
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.success", equalTo(false)))
            .andExpect(jsonPath("$.errors.length()", equalTo(1)))
            .andExpect(jsonPath("$.errors[0].code", equalTo("account.platform.unknown")))
            .andExpect(jsonPath("$.errors[0].description", equalTo("The platform is unknown.")))
            .andDo(
                document(
                    "refresh/errors/platform_is_unknown",
                    requestHeaders(
                        ModelDescription.authHeader()
                    ),
                    HeaderDocumentation.responseHeaders(
                        ModelDescription.wwwAuthHeader(wwwAuthHeaderValue)
                    ),
                    responseFields(ModelDescription.responseError())
                )
            )
    }

    @Test
    @DisplayName("Wrong type of the token type")
    fun bearerTokenWrongType() {
        doThrow(WrongTypeRefreshTokenException(message = ""))
            .whenever(tokenService)
            .getTokensByRefreshToken(any())

        val authHeaderValue = AUTHORIZATION_PREFIX_BEARER + ACCESS_TOKEN
        val wwwAuthHeaderValue = """$BEARER_REALM, $ERROR_CODE_INVALID_TOKEN, error_message="Invalid the token type.""""
        mockMvc.perform(
            get(URL)
                .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
            .andExpect(status().isUnauthorized)
            .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME,wwwAuthHeaderValue))
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.success", equalTo(false)))
            .andExpect(jsonPath("$.errors.length()", equalTo(1)))
            .andExpect(jsonPath("$.errors[0].code", equalTo("auth.token.invalidType")))
            .andExpect(jsonPath("$.errors[0].description", equalTo("Invalid the token type.")))
            .andDo(
                document(
                    "refresh/errors/invalid_type_token",
                    requestHeaders(
                        ModelDescription.authHeader()
                    ),
                    HeaderDocumentation.responseHeaders(
                        ModelDescription.wwwAuthHeader(wwwAuthHeaderValue)
                    ),
                    responseFields(ModelDescription.responseError())
                )
            )
    }

    @Test
    @DisplayName("The account is revoked")
    fun accountRevoked() {
        doThrow(AccountRevokedException(message = ""))
            .whenever(tokenService)
            .getTokensByRefreshToken(any())

        val authHeaderValue = AUTHORIZATION_PREFIX_BEARER + REFRESH_TOKEN
        val wwwAuthHeaderValue = """$BEARER_REALM, $ERROR_CODE_INVALID_TOKEN, error_message="The account is revoked.""""
        mockMvc.perform(
            get(URL)
                .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
            .andExpect(status().isUnauthorized)
            .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.success", equalTo(false)))
            .andExpect(jsonPath("$.errors.length()", equalTo(1)))
            .andExpect(jsonPath("$.errors[0].code", equalTo("account.revoked")))
            .andExpect(jsonPath("$.errors[0].description", equalTo("The account is revoked.")))
            .andDo(
                document(
                    "refresh/errors/account_is_revoked",
                    requestHeaders(
                        ModelDescription.authHeader()
                    ),
                    HeaderDocumentation.responseHeaders(
                        ModelDescription.wwwAuthHeader(wwwAuthHeaderValue)
                    ),
                    responseFields(ModelDescription.responseError())
                )
            )
    }
}
