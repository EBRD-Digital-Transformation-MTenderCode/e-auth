package com.procurement.auth.exception.security

import javax.servlet.http.HttpServletRequest

class PlatformNotFoundException(val request: HttpServletRequest) : RuntimeException()
