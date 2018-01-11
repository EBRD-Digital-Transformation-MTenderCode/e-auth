package com.procurement.auth.service

import com.nhaarman.mockito_kotlin.doThrow
import com.nhaarman.mockito_kotlin.mock
import com.nhaarman.mockito_kotlin.whenever
import com.procurement.auth.exception.security.AccountNotFoundException
import com.procurement.auth.exception.security.AccountRevokedException
import com.procurement.auth.exception.security.InvalidUserCredentialsException
import com.procurement.auth.exception.security.PlatformNotFoundException
import com.procurement.auth.model.Account
import com.procurement.auth.model.UserCredentials
import com.procurement.auth.repository.AccountRepository
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.anyString
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import java.util.*
import javax.servlet.http.HttpServletRequest

class AccountServiceTest {
    companion object {
        private const val ID = 1L
        private const val USERNAME = "USERNAME"
        private const val PASSWORD = "PASSWORD"
        private const val INVALID_PASSWORD = "INVALID_PASSWORD"
        private val PLATFORM_ID = UUID.randomUUID()
    }

    private val crypt = BCryptPasswordEncoder()
    private val credentials = UserCredentials(USERNAME, PASSWORD)

    private lateinit var accountRepository: AccountRepository
    private lateinit var httpServletRequest: HttpServletRequest
    private lateinit var service: AccountService

    @BeforeEach
    fun setUp() {
        accountRepository = mock()
        httpServletRequest = MockHttpServletRequest()
        service = AccountServiceImpl(cryptPasswordEncoder = crypt,
                                     accountRepository = accountRepository
        )
    }

    @Test
    @DisplayName("findByUserCredentials - OK")
    fun findByUserCredentials() {
        val accountEntity = Account(id = ID,
                                    username = USERNAME,
                                    hashPassword = crypt.encode(PASSWORD),
                                    enabled = true,
                                    platformId = PLATFORM_ID
        )
        val accountRepository = mock<AccountRepository>()
        whenever(accountRepository.findByUserCredentials(anyString()))
            .thenReturn(accountEntity)

        val service = AccountServiceImpl(crypt, accountRepository)

        val account = service.findByUserCredentials(MockHttpServletRequest(), credentials)

        assertNotNull(account)
        assertEquals(accountEntity, account)
    }

    @Test
    @DisplayName("findByUserCredentials - AccountNotFoundException")
    fun findByUserCredentials1() {
        doThrow(AccountNotFoundException(request = httpServletRequest))
            .whenever(accountRepository)
            .findByUserCredentials(anyString())

        val exception = assertThrows(
            AccountNotFoundException::class.java,
            {
                service.findByUserCredentials(httpServletRequest, credentials)
            }
        )

        assertEquals(httpServletRequest, exception.request)
    }

    @Test
    @DisplayName("findByUserCredentials - InvalidUserCredentialsException")
    fun findByUserCredentials2() {
        val accountEntity = Account(id = ID,
                                    username = USERNAME,
                                    hashPassword = crypt.encode(INVALID_PASSWORD),
                                    enabled = true,
                                    platformId = PLATFORM_ID
        )
        whenever(accountRepository.findByUserCredentials(anyString()))
            .thenReturn(accountEntity)

        val exception = assertThrows(
            InvalidUserCredentialsException::class.java,
            {
                service.findByUserCredentials(httpServletRequest, credentials)
            }
        )
        assertEquals(httpServletRequest, exception.request)
    }

    @Test
    @DisplayName("findByUserCredentials - AccountRevokedException")
    fun findByUserCredentials3() {
        val accountEntity = Account(id = ID,
                                    username = USERNAME,
                                    hashPassword = crypt.encode(PASSWORD),
                                    enabled = false,
                                    platformId = PLATFORM_ID
        )
        whenever(accountRepository.findByUserCredentials(anyString()))
            .thenReturn(accountEntity)

        val exception = assertThrows(
            AccountRevokedException::class.java,
            {
                service.findByUserCredentials(httpServletRequest, credentials)
            }
        )
        assertEquals(httpServletRequest, exception.request)
    }

    @Test
    @DisplayName("findByPlatformId - OK")
    fun findByPlatformId() {
        val accountEntity = Account(id = ID,
                                    username = USERNAME,
                                    hashPassword = crypt.encode(PASSWORD),
                                    enabled = true,
                                    platformId = PLATFORM_ID
        )
        val accountRepository = mock<AccountRepository>()
        whenever(accountRepository.findByPlatformId(PLATFORM_ID))
            .thenReturn(accountEntity)

        val service = AccountServiceImpl(crypt, accountRepository)

        val account = service.findByPlatformId(MockHttpServletRequest(), PLATFORM_ID)

        assertNotNull(account)
        assertEquals(accountEntity, account)
    }

    @Test
    @DisplayName("findByPlatformId - PlatformNotFoundException")
    fun findByPlatformId1() {
        doThrow(PlatformNotFoundException(request = httpServletRequest))
            .whenever(accountRepository)
            .findByPlatformId(PLATFORM_ID)

        val exception = assertThrows(
            PlatformNotFoundException::class.java,
            {
                service.findByPlatformId(httpServletRequest, PLATFORM_ID)
            }
        )

        assertEquals(httpServletRequest, exception.request)
    }

    @Test
    @DisplayName("findByPlatformId - AccountRevokedException")
    fun findByPlatformId2() {
        val accountEntity = Account(id = ID,
                                    username = USERNAME,
                                    hashPassword = crypt.encode(PASSWORD),
                                    enabled = false,
                                    platformId = PLATFORM_ID
        )
        whenever(accountRepository.findByPlatformId(PLATFORM_ID))
            .thenReturn(accountEntity)

        val exception = assertThrows(
            AccountRevokedException::class.java,
            {
                service.findByPlatformId(httpServletRequest, PLATFORM_ID)
            }
        )
        assertEquals(httpServletRequest, exception.request)
    }
}