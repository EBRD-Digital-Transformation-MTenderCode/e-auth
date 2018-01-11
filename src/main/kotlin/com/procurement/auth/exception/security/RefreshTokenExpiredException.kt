package com.procurement.auth.exception.security

import javax.servlet.http.HttpServletRequest

class RefreshTokenExpiredException(val request: HttpServletRequest) : RuntimeException()