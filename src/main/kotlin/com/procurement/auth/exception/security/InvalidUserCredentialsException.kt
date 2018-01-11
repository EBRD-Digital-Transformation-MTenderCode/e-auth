package com.procurement.auth.exception.security

import javax.servlet.http.HttpServletRequest

class InvalidUserCredentialsException(val request: HttpServletRequest) : RuntimeException()