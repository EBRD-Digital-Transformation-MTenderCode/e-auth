package com.procurement.auth.exception.security

import javax.servlet.http.HttpServletRequest

class InvalidUserCredentialsTokenException(message: String, request: HttpServletRequest) :
    SecurityBaseException(message, request)
