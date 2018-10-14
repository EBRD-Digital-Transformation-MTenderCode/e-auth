package com.procurement.auth.controller

import com.nhaarman.mockito_kotlin.doNothing
import com.nhaarman.mockito_kotlin.doThrow
import com.nhaarman.mockito_kotlin.mock
import com.nhaarman.mockito_kotlin.whenever
import com.procurement.auth.ACCESS_TOKEN
import com.procurement.auth.REFRESH_TOKEN
import com.procurement.auth.exception.security.*
import com.procurement.auth.model.*
import com.procurement.auth.model.token.AuthTokens
import com.procurement.auth.service.TokenService
import org.apache.commons.codec.binary.Base64
import org.apache.commons.codec.binary.StringUtils
import org.hamcrest.core.IsEqual
import org.hamcrest.core.IsEqual.equalTo
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
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
class TokenControllerTest {
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

    @Nested
    inner class Refresh {
        val URL = "/auth/refresh"

        @Test
        @DisplayName("The token refreshed successfully")
        fun refresh() {
            val authTokens = AuthTokens(ACCESS_TOKEN, REFRESH_TOKEN)
            whenever(tokenService.getTokensByRefreshToken(REFRESH_TOKEN))
                .thenReturn(authTokens)

            val authHeaderValue = "$AUTHORIZATION_PREFIX_BEARER $REFRESH_TOKEN"
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
                .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.02.01")))
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
            val authHeaderValue =
                AUTHORIZATION_PREFIX_BASIC + " " + Base64.encodeBase64String(StringUtils.getBytesUtf8(REFRESH_TOKEN))
            val wwwAuthHeaderValue = BEARER_REALM
            mockMvc.perform(
                get(URL)
                    .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
                .andExpect(status().isUnauthorized)
                .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
                .andExpect(content().contentType("application/json;charset=UTF-8"))
                .andExpect(jsonPath("$.success", equalTo(false)))
                .andExpect(jsonPath("$.errors.length()", equalTo(1)))
                .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.02.02")))
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
                .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.03.01")))
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
                .getTokensByRefreshToken(REFRESH_TOKEN)

            val authHeaderValue = "$AUTHORIZATION_PREFIX_BEARER $REFRESH_TOKEN"
            val wwwAuthHeaderValue = BEARER_REALM
            mockMvc.perform(
                get(URL)
                    .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
                .andExpect(status().isUnauthorized)
                .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
                .andExpect(content().contentType("application/json;charset=UTF-8"))
                .andExpect(jsonPath("$.success", equalTo(false)))
                .andExpect(jsonPath("$.errors.length()", equalTo(1)))
                .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.03.04")))
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
            doThrow(TokenExpiredException::class)
                .whenever(tokenService)
                .getTokensByRefreshToken(REFRESH_TOKEN)

            val authHeaderValue = "$AUTHORIZATION_PREFIX_BEARER $REFRESH_TOKEN"
            val wwwAuthHeaderValue =
                """$BEARER_REALM, $ERROR_CODE_INVALID_TOKEN, error_message="The token is expired.""""
            mockMvc.perform(
                get(URL)
                    .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
                .andExpect(status().isUnauthorized)
                .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
                .andExpect(content().contentType("application/json;charset=UTF-8"))
                .andExpect(jsonPath("$.success", equalTo(false)))
                .andExpect(jsonPath("$.errors.length()", equalTo(1)))
                .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.03.05")))
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
            doThrow(PlatformUnknownException::class)
                .whenever(tokenService)
                .getTokensByRefreshToken(REFRESH_TOKEN)

            val authHeaderValue = "$AUTHORIZATION_PREFIX_BEARER $REFRESH_TOKEN"
            val wwwAuthHeaderValue =
                """$BEARER_REALM, $ERROR_CODE_INVALID_TOKEN, error_message="The platform is unknown.""""
            mockMvc.perform(
                get(URL)
                    .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
                .andExpect(status().isUnauthorized)
                .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
                .andExpect(content().contentType("application/json;charset=UTF-8"))
                .andExpect(jsonPath("$.success", equalTo(false)))
                .andExpect(jsonPath("$.errors.length()", equalTo(1)))
                .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.01.03")))
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
            doThrow(WrongTypeRefreshTokenException::class)
                .whenever(tokenService)
                .getTokensByRefreshToken(ACCESS_TOKEN)

            val authHeaderValue = "$AUTHORIZATION_PREFIX_BEARER $ACCESS_TOKEN"
            val wwwAuthHeaderValue =
                """$BEARER_REALM, $ERROR_CODE_INVALID_TOKEN, error_message="Invalid the token type.""""
            mockMvc.perform(
                get(URL)
                    .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
                .andExpect(status().isUnauthorized)
                .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
                .andExpect(content().contentType("application/json;charset=UTF-8"))
                .andExpect(jsonPath("$.success", equalTo(false)))
                .andExpect(jsonPath("$.errors.length()", equalTo(1)))
                .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.03.02")))
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
            doThrow(AccountRevokedException::class)
                .whenever(tokenService)
                .getTokensByRefreshToken(REFRESH_TOKEN)

            val authHeaderValue = "$AUTHORIZATION_PREFIX_BEARER $REFRESH_TOKEN"
            val wwwAuthHeaderValue =
                """$BEARER_REALM, $ERROR_CODE_INVALID_TOKEN, error_message="The account is revoked.""""
            mockMvc.perform(
                get(URL)
                    .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
                .andExpect(status().isUnauthorized)
                .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
                .andExpect(content().contentType("application/json;charset=UTF-8"))
                .andExpect(jsonPath("$.success", equalTo(false)))
                .andExpect(jsonPath("$.errors.length()", equalTo(1)))
                .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.01.02")))
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

    @Nested
    inner class Verification {
        val URL = "/auth/verification"

        @Test
        @DisplayName("The token access successfully")
        fun verification() {
            doNothing()
                .whenever(tokenService)
                .verification(ACCESS_TOKEN)

            val authHeaderValue = "$AUTHORIZATION_PREFIX_BEARER $ACCESS_TOKEN"
            mockMvc.perform(
                get(URL)
                    .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
                .andExpect(status().isOk)
                .andExpect(MockMvcResultMatchers.content().contentType("application/json;charset=UTF-8"))
                .andExpect(MockMvcResultMatchers.jsonPath("$.success", IsEqual.equalTo(true)))
                .andDo(
                    document(
                        "verification/success",
                        requestHeaders(
                            headerWithName(AUTHORIZATION_HEADER_NAME)
                                .description("Bearer access token.")
                        ),
                        responseFields(ModelDescription.Verification.responseSuccessful())
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
                .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.02.01")))
                .andExpect(jsonPath("$.errors[0].description", equalTo("The authentication header is missing.")))
                .andDo(
                    document(
                        "verification/errors/no_such_auth_header",
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
            val authHeaderValue =
                AUTHORIZATION_PREFIX_BASIC + " " + Base64.encodeBase64String(StringUtils.getBytesUtf8(ACCESS_TOKEN))
            val wwwAuthHeaderValue = BEARER_REALM
            mockMvc.perform(
                get(URL)
                    .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
                .andExpect(status().isUnauthorized)
                .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
                .andExpect(content().contentType("application/json;charset=UTF-8"))
                .andExpect(jsonPath("$.success", equalTo(false)))
                .andExpect(jsonPath("$.errors.length()", equalTo(1)))
                .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.02.02")))
                .andExpect(
                    jsonPath(
                        "$.errors[0].description",
                        equalTo("Invalid type of the authentication token. Expected type is 'Bearer'.")
                    )
                )
                .andDo(
                    document(
                        "verification/errors/invalid_type_auth_header",
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
                .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.03.01")))
                .andExpect(jsonPath("$.errors[0].description", equalTo("The authentication token is empty.")))
                .andDo(
                    document(
                        "verification/errors/auth_token_is_empty",
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
                .verification(ACCESS_TOKEN)

            val authHeaderValue = "$AUTHORIZATION_PREFIX_BEARER $ACCESS_TOKEN"
            val wwwAuthHeaderValue = BEARER_REALM
            mockMvc.perform(
                get(URL)
                    .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
                .andExpect(status().isUnauthorized)
                .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
                .andExpect(content().contentType("application/json;charset=UTF-8"))
                .andExpect(jsonPath("$.success", equalTo(false)))
                .andExpect(jsonPath("$.errors.length()", equalTo(1)))
                .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.03.04")))
                .andExpect(
                    jsonPath(
                        "$.errors[0].description",
                        equalTo("The error of verification of the authentication token.")
                    )
                )
                .andDo(
                    document(
                        "verification/errors/invalid_signature",
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
        @DisplayName("The access-token has expired")
        fun tokenExpired() {
            doThrow(TokenExpiredException::class)
                .whenever(tokenService)
                .verification(ACCESS_TOKEN)

            val authHeaderValue = "$AUTHORIZATION_PREFIX_BEARER $ACCESS_TOKEN"
            val wwwAuthHeaderValue =
                """$BEARER_REALM, $ERROR_CODE_INVALID_TOKEN, error_message="The token is expired.""""
            mockMvc.perform(
                get(URL)
                    .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
                .andExpect(status().isUnauthorized)
                .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
                .andExpect(content().contentType("application/json;charset=UTF-8"))
                .andExpect(jsonPath("$.success", equalTo(false)))
                .andExpect(jsonPath("$.errors.length()", equalTo(1)))
                .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.03.05")))
                .andExpect(jsonPath("$.errors[0].description", equalTo("The authentication token is expired.")))
                .andDo(
                    document(
                        "verification/errors/auth_token_is_expired",
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
            doThrow(WrongTypeRefreshTokenException::class)
                .whenever(tokenService)
                .verification(REFRESH_TOKEN)

            val authHeaderValue = "$AUTHORIZATION_PREFIX_BEARER $REFRESH_TOKEN"
            val wwwAuthHeaderValue =
                """$BEARER_REALM, $ERROR_CODE_INVALID_TOKEN, error_message="Invalid the token type.""""
            mockMvc.perform(
                get(URL)
                    .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
                .andExpect(status().isUnauthorized)
                .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
                .andExpect(content().contentType("application/json;charset=UTF-8"))
                .andExpect(jsonPath("$.success", equalTo(false)))
                .andExpect(jsonPath("$.errors.length()", equalTo(1)))
                .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.03.02")))
                .andExpect(jsonPath("$.errors[0].description", equalTo("Invalid the token type.")))
                .andDo(
                    document(
                        "verification/errors/invalid_type_token",
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
}
