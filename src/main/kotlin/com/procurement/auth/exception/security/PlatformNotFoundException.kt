package com.procurement.auth.exception.security

import javax.servlet.http.HttpServletRequest

class PlatformNotFoundException(message: String, request: HttpServletRequest) :
    SecurityBaseException(message, request)
