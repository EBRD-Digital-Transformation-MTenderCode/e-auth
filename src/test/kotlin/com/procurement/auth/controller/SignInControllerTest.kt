package com.procurement.auth.controller

import com.nhaarman.mockito_kotlin.any
import com.nhaarman.mockito_kotlin.doThrow
import com.nhaarman.mockito_kotlin.mock
import com.nhaarman.mockito_kotlin.whenever
import com.procurement.auth.*
import com.procurement.auth.exception.security.AccountRevokedException
import com.procurement.auth.exception.security.InvalidCredentialsException
import com.procurement.auth.model.*
import com.procurement.auth.model.token.AuthTokens
import com.procurement.auth.service.TokenService
import org.apache.commons.codec.binary.Base64
import org.hamcrest.core.IsEqual.equalTo
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.restdocs.RestDocumentationContextProvider
import org.springframework.restdocs.RestDocumentationExtension
import org.springframework.restdocs.headers.HeaderDocumentation.*
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration
import org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint
import org.springframework.restdocs.payload.PayloadDocumentation.responseFields
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.test.web.servlet.setup.StandaloneMockMvcBuilder

@ExtendWith(RestDocumentationExtension::class)
class SignInControllerTest {
    companion object {
        private const val URL = "/auth/signin"
    }

    private lateinit var mockMvc: MockMvc
    private lateinit var tokenService: TokenService

    @BeforeEach
    fun init(restDocumentation: RestDocumentationContextProvider) {
        tokenService = mock()

        val controller = SignInController(tokenService = tokenService)
        val exceptionHandler = WebExceptionHandler()
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
            .setControllerAdvice(exceptionHandler)
            .apply<StandaloneMockMvcBuilder>(
                documentationConfiguration(restDocumentation)
                    .uris()
                    .withScheme("https")
                    .withHost("eprocurement.systems")
                    .and()
                    .snippets()
                    .and()
                    .operationPreprocessors()
                    .withRequestDefaults(prettyPrint())
                    .withResponseDefaults(prettyPrint())
            )
            .build()
    }

    @Test
    @DisplayName("The sign-in was successful")
    fun signIn() {
        val authTokens = AuthTokens(ACCESS_TOKEN, REFRESH_TOKEN)
        whenever(tokenService.getTokensByUserCredentials(any()))
            .thenReturn(authTokens)

        val authHeaderValue = AUTHORIZATION_PREFIX_BASIC + " " + Base64.encodeBase64String(BASIC_CREDENTIALS.toByteArray())
        mockMvc.perform(
            get(URL)
                .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
            .andExpect(status().isOk)
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.success", equalTo(true)))
            .andExpect(jsonPath("$.data.tokens.access", equalTo(ACCESS_TOKEN)))
            .andExpect(jsonPath("$.data.tokens.refresh", equalTo(REFRESH_TOKEN)))
            .andDo(
                document(
                    "sign-in/success",
                    requestHeaders(
                        headerWithName(AUTHORIZATION_HEADER_NAME)
                            .description("Basic auth credentials.")
                    ),
                    responseFields(ModelDescription.SignIn.responseSuccessful())
                )
            )
    }

    @Test
    @DisplayName("No such the authentication header")
    fun noSuchAuthHeader() {
        val authHeaderValue = ""
        val wwwAuthHeaderValue = BASIC_REALM
        mockMvc.perform(
            get(URL)
                .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
            .andExpect(status().isUnauthorized)
            .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.success", equalTo(false)))
            .andExpect(jsonPath("$.errors.length()", equalTo(1)))
            .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.02.01")))
            .andExpect(
                jsonPath(
                    "$.errors[0].description",
                    equalTo("The authentication header is missing.")
                )
            )
            .andDo(
                document(
                    "sign-in/errors/no_such_auth_header",
                    requestHeaders(
                        ModelDescription.authHeader()
                    ),
                    responseHeaders(
                        ModelDescription.wwwAuthHeader(wwwAuthHeaderValue)
                    ),
                    responseFields(ModelDescription.responseError())
                )
            )
    }

    @Test
    @DisplayName("Invalid type the authentication header")
    fun invalidAuthHeaderType() {
        val authHeaderValue = AUTHORIZATION_PREFIX_BEARER + " " + Base64.encodeBase64String(BASIC_CREDENTIALS.toByteArray())
        val wwwAuthHeaderValue = BASIC_REALM
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
                    equalTo("Invalid type of the authentication token. Expected type is 'Basic'.")
                )
            )
            .andDo(
                document(
                    "sign-in/errors/invalid_type_auth_header",
                    requestHeaders(
                        ModelDescription.authHeader()
                    ),
                    responseHeaders(
                        ModelDescription.wwwAuthHeader(wwwAuthHeaderValue)
                    ),
                    responseFields(ModelDescription.responseError())
                )
            )
    }

    @Test
    @DisplayName("The authentication token is empty")
    fun emptyAuthToken() {
        val authHeaderValue = AUTHORIZATION_PREFIX_BASIC
        val wwwAuthHeaderValue = BASIC_REALM
        mockMvc.perform(
            get(URL)
                .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
            .andExpect(status().isUnauthorized)
            .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.success", equalTo(false)))
            .andExpect(jsonPath("$.errors.length()", equalTo(1)))
            .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.03.01")))
            .andExpect(
                jsonPath(
                    "$.errors[0].description",
                    equalTo("The authentication token is empty.")
                )
            )
            .andDo(
                document(
                    "sign-in/errors/auth_token_is_empty",
                    requestHeaders(
                        ModelDescription.authHeader()
                    ),
                    responseHeaders(
                        ModelDescription.wwwAuthHeader(wwwAuthHeaderValue)
                    ),
                    responseFields(ModelDescription.responseError())
                )
            )
    }

    @Test
    @DisplayName("Invalid format the authentication token")
    fun invalidFormatAuthToken() {
        val authHeaderValue =
            AUTHORIZATION_PREFIX_BASIC + " " + Base64.encodeBase64String(INVALID_FORMAT_BASIC_CREDENTIALS.toByteArray())
        val wwwAuthHeaderValue = BASIC_REALM
        mockMvc.perform(
            get(URL)
                .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
            .andExpect(status().isUnauthorized)
            .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.success", equalTo(false)))
            .andExpect(jsonPath("$.errors.length()", equalTo(1)))
            .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.03.03")))
            .andExpect(
                jsonPath(
                    "$.errors[0].description",
                    equalTo("Invalid format of the authentication token.")
                )
            )
            .andDo(
                document(
                    "sign-in/errors/invalid_format_auth_token",
                    requestHeaders(
                        ModelDescription.authHeader()
                    ),
                    responseHeaders(
                        ModelDescription.wwwAuthHeader(wwwAuthHeaderValue)
                    ),
                    responseFields(ModelDescription.responseError())
                )
            )
    }

    @Test
    @DisplayName("Invalid credentials")
    fun invalidCredentials() {
        doThrow(InvalidCredentialsException(message = ""))
            .whenever(tokenService)
            .getTokensByUserCredentials(any())

        val authHeaderValue =
            AUTHORIZATION_PREFIX_BASIC + " " + Base64.encodeBase64String(INVALID_BASIC_CREDENTIALS.toByteArray())
        val wwwAuthHeaderValue = BASIC_REALM
        mockMvc.perform(
            get(URL)
                .header(AUTHORIZATION_HEADER_NAME, authHeaderValue))
            .andExpect(status().isUnauthorized)
            .andExpect(header().string(WWW_AUTHENTICATE_HEADER_NAME, wwwAuthHeaderValue))
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.success", equalTo(false)))
            .andExpect(jsonPath("$.errors.length()", equalTo(1)))
            .andExpect(jsonPath("$.errors[0].code", equalTo("401.81.01.01")))
            .andExpect(jsonPath("$.errors[0].description", equalTo("Invalid credentials.")))
            .andDo(
                document(
                    "sign-in/errors/invalid_credentials",
                    requestHeaders(
                        ModelDescription.authHeader()
                    ),
                    responseHeaders(
                        ModelDescription.wwwAuthHeader(wwwAuthHeaderValue)
                    ),
                    responseFields(ModelDescription.responseError())
                )
            )
    }

    @Test
    @DisplayName("Account is revoked")
    fun accountRevoked() {
        doThrow(AccountRevokedException(message = ""))
            .whenever(tokenService)
            .getTokensByUserCredentials(any())

        val authHeaderValue =
            AUTHORIZATION_PREFIX_BASIC + " " + Base64.encodeBase64String(BASIC_CREDENTIALS.toByteArray())
        val wwwAuthHeaderValue = """$BASIC_REALM, error_message="The account is revoked.""""
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
                    "sign-in/errors/account_is_revoked",
                    requestHeaders(
                        ModelDescription.authHeader()
                    ),
                    responseHeaders(
                        ModelDescription.wwwAuthHeader(wwwAuthHeaderValue)
                    ),
                    responseFields(ModelDescription.responseError())
                )
            )
    }
}
