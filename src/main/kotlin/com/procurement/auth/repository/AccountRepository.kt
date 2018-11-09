package com.procurement.auth.repository

import com.procurement.auth.model.Account
import org.intellij.lang.annotations.Language
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.util.*

interface AccountRepository {
    fun findByUserCredentials(username: String): Account?

    fun findByPlatformId(platformId: UUID): Account?
}

@Repository
class AccountRepositoryImpl @Autowired constructor(
    private val jdbcTemplate: NamedParameterJdbcTemplate
) : AccountRepository {
    companion object {
        @Language("PostgreSQL")
        const val FIND_BY_USERNAME_SQL = """SELECT id, username, hash_password, platform_id, enabled FROM accounts WHERE username = :username"""

        @Language("PostgreSQL")
        const val FIND_BY_PLATFORM_ID_SQL = """SELECT id, username, hash_password, platform_id, enabled FROM accounts WHERE platform_id = :platformId"""
    }

    @Transactional(readOnly = true)
    override fun findByUserCredentials(username: String): Account? = try {
        jdbcTemplate.queryForObject(
            FIND_BY_USERNAME_SQL,
            mapOf("username" to username),
            ::mappingAccount
        )
    } catch (ex: EmptyResultDataAccessException) {
        null
    }

    @Transactional(readOnly = true)
    override fun findByPlatformId(platformId: UUID): Account? = try {
        jdbcTemplate.queryForObject(
            FIND_BY_PLATFORM_ID_SQL,
            mapOf("platformId" to platformId),
            ::mappingAccount
        )
    } catch (ex: EmptyResultDataAccessException) {
        null
    }

    private fun mappingAccount(rs: ResultSet, rowNum: Int): Account = Account(
        id = rs.getId(),
        username = rs.getUsername(),
        hashPassword = rs.getHashPassword(),
        platformId = rs.getPlatformId(),
        enabled = rs.getEnabled()
    )

    private fun ResultSet.getId() = this.getLong(1)
    private fun ResultSet.getUsername() = this.getString(2)
    private fun ResultSet.getHashPassword() = this.getString(3)
    private fun ResultSet.getPlatformId() = UUID.fromString(this.getString(4))
    private fun ResultSet.getEnabled() = this.getBoolean(5)
}