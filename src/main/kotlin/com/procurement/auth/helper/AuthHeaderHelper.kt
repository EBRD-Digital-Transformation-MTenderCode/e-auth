package com.procurement.auth.helper

import com.procurement.auth.exception.security.EmptyAuthTokenException
import com.procurement.auth.exception.security.InvalidAuthHeaderTypeException
import com.procurement.auth.exception.security.InvalidAuthTokenFormatException
import com.procurement.auth.exception.security.NoSuchAuthHeaderException
import com.procurement.auth.model.AUTHORIZATION_PREFIX_BASIC
import com.procurement.auth.model.AUTHORIZATION_PREFIX_BEARER
import com.procurement.auth.model.UserCredentials
import org.apache.commons.codec.binary.Base64
import javax.servlet.http.HttpServletRequest

fun getUserCredentialsByAuthHeader(authorizationHeader: String): UserCredentials {
    checkAuthHeader(authorizationHeader)
    if (!authorizationHeader.startsWith(AUTHORIZATION_PREFIX_BASIC)) {
        throw InvalidAuthHeaderTypeException(
            "Invalid type the authentication header. Requires 'Basic' type of the authentication header."
        )
    }
    val basicToken = getToken(authorizationHeader, AUTHORIZATION_PREFIX_BASIC)
    return toUserCredentials(basicToken)
}



fun getBearerTokenByAuthHeader(authorizationHeader: String): String {
    checkAuthHeader(authorizationHeader)
    if (!authorizationHeader.startsWith(AUTHORIZATION_PREFIX_BEARER)) {
        throw InvalidAuthHeaderTypeException(
            "Invalid type the authentication header. Requires 'Bearer' type of the authentication header."
        )
    }
    return getToken(authorizationHeader, AUTHORIZATION_PREFIX_BEARER)
}

private fun checkAuthHeader(authorizationHeader: String) {
    if (authorizationHeader.isEmpty())
        throw NoSuchAuthHeaderException("There is not the authentication header.")
}

private fun getToken(header: String, headerType: String): String {
    val token = header.substring(headerType.length).trim()
    if (token.isEmpty()) {
        throw EmptyAuthTokenException("The authentication token is empty.")
    }
    return token
}

private fun toUserCredentials(token: String): UserCredentials {
    val decodedToken = String(Base64.decodeBase64(token))
    val colonPosition = decodedToken.indexOf(":")
    if (colonPosition == -1) {
        throw InvalidAuthTokenFormatException("Invalid format 'Basic' token.")
    }
    val username = decodedToken.substring(0, colonPosition)
    val password = decodedToken.substring(colonPosition + 1)
    return UserCredentials(username, password)
}
