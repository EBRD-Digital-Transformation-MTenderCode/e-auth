package com.procurement.auth

import com.procurement.auth.configuration.ApplicationConfiguration
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication(
    scanBasePackageClasses = [
        ApplicationConfiguration::class
    ]
)
class AuthApplication

fun main(args: Array<String>) {
    runApplication<AuthApplication>(*args)
}
