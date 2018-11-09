package com.procurement.auth.configuration

import com.procurement.auth.repository.AccountRepository
import com.procurement.auth.repository.AccountRepositoryImpl
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import liquibase.Liquibase
import liquibase.database.DatabaseFactory
import liquibase.database.jvm.JdbcConnection
import liquibase.resource.FileSystemResourceAccessor
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.jdbc.datasource.DataSourceTransactionManager
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.annotation.EnableTransactionManagement
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.containers.PostgreSQLContainerProvider
import javax.sql.DataSource

@TestConfiguration
@EnableTransactionManagement
class DatabaseTestConfiguration {
    companion object {
        private const val changeLogFile = "liquibase.changelog-master.xml"
    }

    private val postgreSQLContainer =
        (PostgreSQLContainerProvider().newInstance("9.6") as PostgreSQLContainer)
            .also { it.start() }

    @Bean
    fun transactionManager(): PlatformTransactionManager = DataSourceTransactionManager(dataSource())

    @Bean
    fun dataSource(): DataSource = HikariDataSource(hikariConfig())

    @Bean
    fun jdbcTemplate(): NamedParameterJdbcTemplate = NamedParameterJdbcTemplate(dataSource())

    @Bean
    fun accountRepository(): AccountRepository = AccountRepositoryImpl(jdbcTemplate())

    @Bean
    fun liquibase() = Liquibase(changeLogFile, FileSystemResourceAccessor(liquibaseDir()), database(dataSource()))

    private fun hikariConfig() = HikariConfig().apply {
        jdbcUrl = postgreSQLContainer.getJdbcUrl()
        username = postgreSQLContainer.getUsername()
        password = postgreSQLContainer.getPassword()
        driverClassName = "org.postgresql.Driver"
    }

    private fun liquibaseDir() = this::class.java
        .getResource("/")
        .getPath()
        .let { path ->
            path.substring(0, path.indexOf("target"))
        }
        .let { baseDir ->
            baseDir + "src/main/resources/liquibase/"
        }

    private fun database(dataSource: DataSource) = DatabaseFactory.getInstance()
        .findCorrectDatabaseImplementation(JdbcConnection(dataSource.connection))
}
