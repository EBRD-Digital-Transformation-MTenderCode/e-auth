package com.procurement.auth.configuration

import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import

@Configuration
@Import(
    value = [
        WebConfiguration::class,
        ServiceConfiguration::class,
        DatabaseConfiguration::class
    ]
)
class ApplicationConfiguration
