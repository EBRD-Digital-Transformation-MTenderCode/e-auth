package com.procurement.auth.exception.security

import javax.servlet.http.HttpServletRequest

class InvalidUserCredentialsTokenException(val request: HttpServletRequest) : RuntimeException()
