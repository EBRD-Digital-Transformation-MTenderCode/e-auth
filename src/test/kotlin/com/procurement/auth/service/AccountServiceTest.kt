package com.procurement.auth.service

import com.nhaarman.mockito_kotlin.mock
import com.nhaarman.mockito_kotlin.whenever
import com.procurement.auth.exception.security.AccountRevokedException
import com.procurement.auth.exception.security.InvalidCredentialsException
import com.procurement.auth.exception.security.PlatformUnknownException
import com.procurement.auth.model.Account
import com.procurement.auth.model.UserCredentials
import com.procurement.auth.repository.AccountRepository
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.anyString
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import java.util.*

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
    private lateinit var service: AccountService

    @BeforeEach
    fun setUp() {
        accountRepository = mock()
        service = AccountServiceImpl(
            cryptPasswordEncoder = crypt,
            accountRepository = accountRepository
        )
    }

    @Test
    @DisplayName("findByUserCredentials - OK")
    fun findByUserCredentials() {
        val accountEntity = Account(
            id = ID,
            username = USERNAME,
            hashPassword = crypt.encode(PASSWORD),
            enabled = true,
            platformId = PLATFORM_ID
        )
        val accountRepository = mock<AccountRepository>()
        whenever(accountRepository.findByUserCredentials(anyString()))
            .thenReturn(accountEntity)

        val service = AccountServiceImpl(crypt, accountRepository)

        val account = service.findByUserCredentials(credentials)

        assertNotNull(account)
        assertEquals(accountEntity, account)
    }

    @Test
    @DisplayName("The account is unknown (InvalidCredentialsException)")
    fun findByUserCredentials1() {
        whenever(accountRepository.findByUserCredentials(anyString()))
            .thenReturn(null)

        assertThrows(
            InvalidCredentialsException::class.java,
            {
                service.findByUserCredentials(credentials)
            }
        )
    }

    @Test
    @DisplayName("Invalid password (InvalidCredentialsException)")
    fun findByUserCredentials2() {
        val accountEntity = Account(
            id = ID,
            username = USERNAME,
            hashPassword = crypt.encode(INVALID_PASSWORD),
            enabled = true,
            platformId = PLATFORM_ID
        )
        whenever(accountRepository.findByUserCredentials(anyString()))
            .thenReturn(accountEntity)

        assertThrows(
            InvalidCredentialsException::class.java,
            {
                service.findByUserCredentials(credentials)
            }
        )
    }

    @Test
    @DisplayName("The account is revoked")
    fun findByUserCredentials3() {
        val accountEntity = Account(
            id = ID,
            username = USERNAME,
            hashPassword = crypt.encode(PASSWORD),
            enabled = false,
            platformId = PLATFORM_ID
        )
        whenever(accountRepository.findByUserCredentials(anyString()))
            .thenReturn(accountEntity)

        assertThrows(
            AccountRevokedException::class.java,
            {
                service.findByUserCredentials(credentials)
            }
        )
    }

    @Test
    @DisplayName("findByPlatformId - OK")
    fun findByPlatformId() {
        val accountEntity = Account(
            id = ID,
            username = USERNAME,
            hashPassword = crypt.encode(PASSWORD),
            enabled = true,
            platformId = PLATFORM_ID
        )
        val accountRepository = mock<AccountRepository>()
        whenever(accountRepository.findByPlatformId(PLATFORM_ID))
            .thenReturn(accountEntity)

        val service = AccountServiceImpl(crypt, accountRepository)

        val account = service.findByPlatformId(PLATFORM_ID)

        assertNotNull(account)
        assertEquals(accountEntity, account)
    }

    @Test
    @DisplayName("The platform is unknown")
    fun findByPlatformId1() {
        whenever(accountRepository.findByPlatformId(PLATFORM_ID))
            .thenReturn(null)

        assertThrows(
            PlatformUnknownException::class.java,
            {
                service.findByPlatformId(PLATFORM_ID)
            }
        )
    }

    @Test
    @DisplayName("findByPlatformId - AccountRevokedException")
    fun findByPlatformId2() {
        val accountEntity = Account(
            id = ID,
            username = USERNAME,
            hashPassword = crypt.encode(PASSWORD),
            enabled = false,
            platformId = PLATFORM_ID
        )
        whenever(accountRepository.findByPlatformId(PLATFORM_ID))
            .thenReturn(accountEntity)

        assertThrows(
            AccountRevokedException::class.java,
            {
                service.findByPlatformId(PLATFORM_ID)
            }
        )
    }
}