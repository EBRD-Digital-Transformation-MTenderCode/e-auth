package com.procurement.auth.exception.security

import javax.servlet.http.HttpServletRequest

class AccountNotFoundException(val request: HttpServletRequest) : RuntimeException()
