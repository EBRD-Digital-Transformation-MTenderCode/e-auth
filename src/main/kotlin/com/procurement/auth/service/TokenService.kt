package com.procurement.auth.service

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.TokenExpiredException
import com.auth0.jwt.interfaces.DecodedJWT
import com.procurement.auth.configuration.properties.RSAKeyProperties
import com.procurement.auth.exception.security.BearerTokenWrongTypeException
import com.procurement.auth.exception.security.InvalidUserCredentialsTokenException
import com.procurement.auth.exception.security.RefreshTokenExpiredException
import com.procurement.auth.helper.*
import com.procurement.auth.model.*
import com.procurement.auth.model.token.AuthTokens
import com.procurement.auth.security.RSAService
import org.apache.commons.codec.binary.Base64
import java.security.spec.InvalidKeySpecException
import java.time.LocalDateTime
import java.util.*
import javax.servlet.http.HttpServletRequest

interface TokenService {
    fun getTokensByUserCredentials(request: HttpServletRequest): AuthTokens

    fun getTokensByRefreshToken(request: HttpServletRequest): AuthTokens
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

    override fun getTokensByUserCredentials(request: HttpServletRequest): AuthTokens {
        val token = request.getBasicToken()
        val userCredentials = getUserCredentials(request, token)
        val account = accountService.findByUserCredentials(request, userCredentials)
        return genTokens(account)
    }

    override fun getTokensByRefreshToken(request: HttpServletRequest): AuthTokens {
        val jwt = request.getJWT()
        val platformId = jwt.getPlatformId()
        val account = accountService.findByPlatformId(request, platformId)
        return genTokens(account)
    }

    private fun getUserCredentials(requet: HttpServletRequest, token: String): UserCredentials {
        val decodedToken = String(Base64.decodeBase64(token))
        val colonPosition = decodedToken.indexOf(":")
        if (colonPosition == -1) {
            throw InvalidUserCredentialsTokenException("Invalid format 'Basic' token.", requet)
        }
        val username = decodedToken.substring(0, colonPosition)
        val password = decodedToken.substring(colonPosition + 1)
        return UserCredentials(username, password)
    }

    private fun HttpServletRequest.getJWT() =
        try {
            verifier.verify(this.getBearerToken())
        } catch (ex: TokenExpiredException) {
            throw RefreshTokenExpiredException("The refresh token expired.", this)
        }.also {
            if (it.isNotRefreshToken()) {
                throw BearerTokenWrongTypeException("The bearer token of wrong type.", this)
            }
        }

    private fun DecodedJWT.isNotRefreshToken(): Boolean =
        this.getHeaderClaim(HEADER_NAME_TOKEN_TYPE).asString() != REFRESH_TOKEN_TYPE

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
