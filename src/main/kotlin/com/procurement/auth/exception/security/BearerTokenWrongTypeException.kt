package com.procurement.auth.exception.security

import javax.servlet.http.HttpServletRequest

class BearerTokenWrongTypeException(message: String, request: HttpServletRequest) :
    SecurityBaseException(message, request)
