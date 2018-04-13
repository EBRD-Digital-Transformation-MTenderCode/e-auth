package com.procurement.auth.service

import com.procurement.auth.exception.security.AccountNotFoundException
import com.procurement.auth.exception.security.AccountRevokedException
import com.procurement.auth.exception.security.InvalidCredentialsException
import com.procurement.auth.exception.security.PlatformNotFoundException
import com.procurement.auth.logging.MDCKey
import com.procurement.auth.logging.mdc
import com.procurement.auth.model.Account
import com.procurement.auth.model.UserCredentials
import com.procurement.auth.repository.AccountRepository
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import java.util.*
import javax.servlet.http.HttpServletRequest

interface AccountService {
    fun findByUserCredentials(credentials: UserCredentials): Account
    fun findByPlatformId(platformId: UUID): Account
}

class AccountServiceImpl(
    private val cryptPasswordEncoder: BCryptPasswordEncoder,
    private val accountRepository: AccountRepository
) : AccountService {

    override fun findByUserCredentials(credentials: UserCredentials): Account {
        mdc(MDCKey.USERNAME, credentials.username)
        return accountRepository.findByUserCredentials(credentials.username)
            ?.also {
                it.validatePassword(credentials.password)
                it.checkRevoked()
            }
            ?: throw AccountNotFoundException("Account not found.")
    }

    override fun findByPlatformId(platformId: UUID): Account {
        mdc(MDCKey.PLATFORM_ID, platformId.toString())
        return accountRepository.findByPlatformId(platformId)
            ?.also {
                it.checkRevoked()
            }
            ?: throw PlatformNotFoundException("Platform not found.")
    }

    private fun Account.validatePassword(password: String) {
        if (!cryptPasswordEncoder.matches(password, this.hashPassword)) {
            throw InvalidCredentialsException("Invalid credentials.")
        }
    }

    private fun Account.checkRevoked() {
        if (!this.enabled) {
            throw AccountRevokedException("The account is revoked.")
        }
    }
}