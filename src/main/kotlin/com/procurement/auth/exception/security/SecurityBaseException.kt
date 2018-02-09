package com.procurement.auth.exception.security

import javax.servlet.http.HttpServletRequest

open class SecurityBaseException(message: String, val request: HttpServletRequest) : RuntimeException(message)