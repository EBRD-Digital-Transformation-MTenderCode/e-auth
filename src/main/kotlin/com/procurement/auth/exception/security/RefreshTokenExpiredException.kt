package com.procurement.auth.exception.security

import javax.servlet.http.HttpServletRequest

class RefreshTokenExpiredException(message: String, request: HttpServletRequest) :
    SecurityBaseException(message, request)