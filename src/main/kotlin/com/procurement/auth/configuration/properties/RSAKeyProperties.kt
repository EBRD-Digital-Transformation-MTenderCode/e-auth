package com.procurement.auth.configuration.properties

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "jwt")
data class RSAKeyProperties(
    var publicKey: String = "",
    var privateKey: String = "",
    var lifeTime: LifeTime = LifeTime()
)

data class LifeTime(
    var access: Long = 0,
    var refresh: Long = 0
)