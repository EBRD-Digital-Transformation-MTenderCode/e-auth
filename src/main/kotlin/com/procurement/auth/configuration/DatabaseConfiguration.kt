package com.procurement.auth.configuration

import com.procurement.auth.repository.AccountRepository
import com.procurement.auth.repository.AccountRepositoryImpl
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.transaction.annotation.EnableTransactionManagement
import javax.sql.DataSource

@Configuration
@EnableTransactionManagement
class DatabaseConfiguration @Autowired constructor(
    private val dataSource: DataSource
) {
    @Bean
    fun accountRepository(): AccountRepository =
        AccountRepositoryImpl(
            jdbcTemplate = NamedParameterJdbcTemplate(dataSource)
        )
}
