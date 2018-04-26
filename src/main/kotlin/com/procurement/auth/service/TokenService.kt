package com.procurement.auth.service

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import com.procurement.auth.configuration.properties.RSAKeyProperties
import com.procurement.auth.exception.security.TokenExpiredException
import com.procurement.auth.exception.security.VerificationTokenException
import com.procurement.auth.exception.security.WrongTypeRefreshTokenException
import com.procurement.auth.helper.genAccessToken
import com.procurement.auth.helper.genExpiresOn
import com.procurement.auth.helper.genRefreshToken
import com.procurement.auth.model.*
import com.procurement.auth.model.token.AuthTokens
import com.procurement.auth.security.RSAService
import java.security.spec.InvalidKeySpecException
import java.time.LocalDateTime
import java.util.*

interface TokenService {
    fun getTokensByUserCredentials(userCredentials: UserCredentials): AuthTokens

    fun getTokensByRefreshToken(token: String): AuthTokens

    fun verification(token: String)
}

class TokenServiceImpl
@Throws(InvalidKeySpecException::class)
constructor(
    private val rsaKeyProperties: RSAKeyProperties,
    private val accountService: AccountService,
    rsaService: RSAService
) : TokenService {
    private val algorithm: Algorithm
    private val verifier: JWTVerifier

    init {
        val publicKey = rsaService.toPublicKey(rsaKeyProperties.publicKey)
        val privateKey = rsaService.toPrivateKey(rsaKeyProperties.privateKey)
        algorithm = Algorithm.RSA256(publicKey, privateKey)
        verifier = JWT.require(algorithm).build()
    }

    override fun getTokensByUserCredentials(userCredentials: UserCredentials): AuthTokens {
        val account = accountService.findByUserCredentials(userCredentials)
        return genTokens(account)
    }

    override fun getTokensByRefreshToken(token: String): AuthTokens {
        val jwt = token.toJWT()
        jwt.checkTypeToken(TokenType.REFRESH)
        val platformId = jwt.getPlatformId()
        val account = accountService.findByPlatformId(platformId)
        return genTokens(account)
    }

    override fun verification(token: String) {
        val jwt = token.toJWT()
        jwt.checkTypeToken(TokenType.ACCESS)
    }

    private fun String.toJWT() =
        try {
            verifier.verify(this)
        } catch (ex: com.auth0.jwt.exceptions.TokenExpiredException) {
            throw TokenExpiredException("The refresh token is expired.")
        } catch (ex: Exception) {
            throw VerificationTokenException("Error of verification the token.", ex)
        }

    private fun DecodedJWT.checkTypeToken(tokenType: TokenType) {
        val valueTokenTypeHeader = this.getHeaderClaim(HEADER_NAME_TOKEN_TYPE).asString()
        if(tokenType.toString() != valueTokenTypeHeader) {
            throw WrongTypeRefreshTokenException("Invalid the token type. Expected type of token is '$tokenType'.")
        }
    }

    private fun DecodedJWT.getPlatformId(): UUID =
        UUID.fromString(this.getClaim(CLAIM_NAME_PLATFORM_ID).asString())

    private fun genTokens(account: Account): AuthTokens {
        val currentDate = LocalDateTime.now()
        val accessToken = genAccessToken(
            account.platformId,
            currentDate.genExpiresOn(rsaKeyProperties.lifeTime.access),
            algorithm
        )
        val refreshToken = genRefreshToken(
            account.platformId,
            currentDate.genExpiresOn(rsaKeyProperties.lifeTime.refresh),
            algorithm
        )
        return AuthTokens(accessToken, refreshToken)
    }
}
