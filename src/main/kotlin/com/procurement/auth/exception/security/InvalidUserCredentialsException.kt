package com.procurement.auth.exception.security

import javax.servlet.http.HttpServletRequest

class InvalidUserCredentialsException(message: String, request: HttpServletRequest) :
    SecurityBaseException(message, request)