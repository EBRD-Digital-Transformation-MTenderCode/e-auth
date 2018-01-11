package com.procurement.auth.exception.security

import com.procurement.auth.model.token.AuthTokenType
import javax.servlet.http.HttpServletRequest

class InvalidAuthHeaderTypeException(val request: HttpServletRequest, val authTokenType: AuthTokenType) : RuntimeException()