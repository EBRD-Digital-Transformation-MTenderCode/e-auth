package com.procurement.auth.helper

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.procurement.auth.model.CLAIM_NAME_PLATFORM_ID
import com.procurement.auth.model.HEADER_NAME_TOKEN_TYPE
import com.procurement.auth.model.TokenType
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.*

fun genAccessToken(platformId: UUID, expiresOn: Date, algorithm: Algorithm): String =
    genToken(
        claims = mapOf<String, Any>(CLAIM_NAME_PLATFORM_ID to platformId),
        header = mapOf<String, Any>(HEADER_NAME_TOKEN_TYPE to TokenType.ACCESS),
        expiresOn = expiresOn,
        algorithm = algorithm
    )

fun genRefreshToken(platformId: UUID, expiresOn: Date, algorithm: Algorithm): String =
    genToken(
        claims = mapOf<String, Any>(CLAIM_NAME_PLATFORM_ID to platformId),
        header = mapOf<String, Any>(HEADER_NAME_TOKEN_TYPE to TokenType.REFRESH),
        expiresOn = expiresOn,
        algorithm = algorithm
    )

fun genToken(claims: Map<String, Any>, header: Map<String, Any>, expiresOn: Date, algorithm: Algorithm): String =
    JWT.create()
        .also {
            claims.forEach { key, value ->
                when (value) {
                    is Date -> it.withClaim(key, value)
                    is Boolean -> it.withClaim(key, value)
                    is Int -> it.withClaim(key, value)
                    is Long -> it.withClaim(key, value)
                    is Double -> it.withClaim(key, value)
                    is String -> it.withClaim(key, value)
                    else -> it.withClaim(key, value.toString())
                }

            }
        }
        .withHeader(header)
        .withExpiresAt(expiresOn)
        .sign(algorithm)

fun LocalDateTime.genExpiresOn(lifeTime: Long): Date =
    Date.from(this.genExpiredZonedDateTime(lifeTime).toInstant())

private fun LocalDateTime.genExpiredZonedDateTime(expired: Long): ZonedDateTime =
    ZonedDateTime.of(this.plusSeconds(expired), ZoneId.systemDefault())