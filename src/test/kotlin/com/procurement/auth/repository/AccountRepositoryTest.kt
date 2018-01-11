package com.procurement.auth.repository

import com.procurement.auth.configuration.DatabaseTestConfiguration
import liquibase.Contexts
import liquibase.Liquibase
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension
import java.util.*
import javax.sql.DataSource

@ExtendWith(SpringExtension::class)
@ContextConfiguration(classes = [DatabaseTestConfiguration::class])
class AccountRepositoryTest {
    companion object {
        private const val ID = 1L
        private const val USERNAME = "USER-1"
        private const val PASSWORD = "PASSWORD"
        private val PLATFORM_ID = UUID.randomUUID()
    }

    @Autowired
    private lateinit var datasource: DataSource

    @Autowired
    private lateinit var liquibase: Liquibase

    @Autowired
    private lateinit var accountRepository: AccountRepository

    private val crypt = BCryptPasswordEncoder()

    @BeforeEach
    fun setup() {
        println("The database is initializing...")
        liquibase.update(Contexts())
        println("The database was initialized.")
    }

    @AfterEach
    fun clear() {
        println("The database is clearing...")
        liquibase.dropAll()
        println("The database was cleared.")
    }

    @Test
    @DisplayName("Testing the method findByUserCredentials.")
    fun findByUserCredentials() {
        appendAccount()

        val account = accountRepository.findByUserCredentials(USERNAME)

        assertNotNull(account)
        assertEquals(ID, account!!.id)
        assertEquals(USERNAME, account.username)
        assertTrue(crypt.matches(PASSWORD, account.hashPassword))
        assertEquals(PLATFORM_ID, account.platformId)
        assertTrue(account.enabled)
    }

    @Test
    @DisplayName("Testing the method findByUserCredentials (Invalid username).")
    fun findByUserCredentials1() {
        val account = accountRepository.findByUserCredentials("UNKNOWN_USERNAME")
        assertNull(account)
    }

    @Test
    @DisplayName("Testing the method findByUserCredentials.")
    fun findByPlatformId() {
        appendAccount()

        val account = accountRepository.findByPlatformId(PLATFORM_ID)

        assertNotNull(account)
        assertEquals(ID, account!!.id)
        assertEquals(USERNAME, account.username)
        assertTrue(crypt.matches(PASSWORD, account.hashPassword))
        assertEquals(PLATFORM_ID, account.platformId)
        assertTrue(account.enabled)
    }

    @Test
    @DisplayName("Testing the method findByUserCredentials (Invalid platform id).")
    fun findByPlatformId1() {
        val account = accountRepository.findByPlatformId(UUID.randomUUID())
        assertNull(account)
    }




    private fun appendAccount() {
        execute("""
            INSERT INTO accounts(id, username, hash_password, platform_id, enabled)
            VALUES($ID, '$USERNAME', '${crypt.encode(PASSWORD)}', '$PLATFORM_ID', true)
            """.trimIndent()
        )
    }

    private fun execute(sql: String) {
        JdbcTemplate(datasource).apply { execute(sql) }
    }
}