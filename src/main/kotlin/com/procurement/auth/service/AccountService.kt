package com.procurement.auth.service

import com.procurement.auth.exception.security.AccountNotFoundException
import com.procurement.auth.exception.security.AccountRevokedException
import com.procurement.auth.exception.security.InvalidUserCredentialsException
import com.procurement.auth.exception.security.PlatformNotFoundException
import com.procurement.auth.logging.MDCKey
import com.procurement.auth.logging.mdc
import com.procurement.auth.model.Account
import com.procurement.auth.model.UserCredentials
import com.procurement.auth.model.token.AuthTokenType
import com.procurement.auth.repository.AccountRepository
import org.slf4j.MDC
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import java.util.*
import javax.servlet.http.HttpServletRequest

interface AccountService {
    fun findByUserCredentials(request: HttpServletRequest, credentials: UserCredentials): Account
    fun findByPlatformId(request: HttpServletRequest, platformId: UUID): Account
}

class AccountServiceImpl(private val cryptPasswordEncoder: BCryptPasswordEncoder,
                         private val accountRepository: AccountRepository
) : AccountService {

    override fun findByUserCredentials(request: HttpServletRequest, credentials: UserCredentials): Account {
        mdc(MDCKey.USERNAME, credentials.username)
        return accountRepository.findByUserCredentials(credentials.username)?.also {
            it.validatePassword(request, credentials.password)
            it.checkRevoked(request, AuthTokenType.BASIC)
        } ?: throw AccountNotFoundException("Account not found.", request)
    }

    override fun findByPlatformId(request: HttpServletRequest, platformId: UUID): Account {
        mdc(MDCKey.PLATFORM_ID, platformId.toString())
        return accountRepository.findByPlatformId(platformId)?.also {
            it.checkRevoked(request, AuthTokenType.BEARER)
        } ?: throw PlatformNotFoundException("Platform not found.", request)
    }

    private fun Account.validatePassword(request: HttpServletRequest, password: String) {
        if (!cryptPasswordEncoder.matches(password, this.hashPassword)) {
            throw InvalidUserCredentialsException("Invalid credentials.", request)
        }
    }

    private fun Account.checkRevoked(request: HttpServletRequest, authTokenType: AuthTokenType) {
        if (!this.enabled) {
            throw AccountRevokedException("The account is revoked.", request, authTokenType)
        }
    }
}