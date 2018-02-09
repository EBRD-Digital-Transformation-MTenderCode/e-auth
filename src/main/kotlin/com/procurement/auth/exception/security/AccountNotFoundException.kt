package com.procurement.auth.exception.security

import javax.servlet.http.HttpServletRequest

class AccountNotFoundException(message: String, request: HttpServletRequest) : SecurityBaseException(message, request)
