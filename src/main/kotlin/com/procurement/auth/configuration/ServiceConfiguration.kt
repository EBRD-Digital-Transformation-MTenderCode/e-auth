package com.procurement.auth.configuration

import com.procurement.auth.configuration.properties.RSAKeyProperties
import com.procurement.auth.repository.AccountRepository
import com.procurement.auth.security.KeyFactoryService
import com.procurement.auth.security.KeyFactoryServiceImpl
import com.procurement.auth.security.RSAService
import com.procurement.auth.security.RSAServiceImpl
import com.procurement.auth.service.AccountService
import com.procurement.auth.service.AccountServiceImpl
import com.procurement.auth.service.TokenService
import com.procurement.auth.service.TokenServiceImpl
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder

@Configuration
@EnableConfigurationProperties(
    value = [
        RSAKeyProperties::class
    ]
)
class ServiceConfiguration(
    private val rsaKeyProperties: RSAKeyProperties,
    private val accountRepository: AccountRepository
) {
    @Bean
    fun cryptPasswordEncoder(): BCryptPasswordEncoder {
        return BCryptPasswordEncoder()
    }

    @Bean
    fun keyFactoryService(): KeyFactoryService = KeyFactoryServiceImpl()

    @Bean
    fun rsaService(): RSAService = RSAServiceImpl(keyFactoryService())

    @Bean
    fun accountService(): AccountService {
        return AccountServiceImpl(cryptPasswordEncoder(), accountRepository)
    }

    @Bean
    fun tokenService(): TokenService {
        return TokenServiceImpl(rsaKeyProperties, accountService(), rsaService())
    }
}
