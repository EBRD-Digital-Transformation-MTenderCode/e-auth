package com.procurement.auth.exception.security

import javax.servlet.http.HttpServletRequest

class BearerTokenWrongTypeException(val request: HttpServletRequest) : RuntimeException()
