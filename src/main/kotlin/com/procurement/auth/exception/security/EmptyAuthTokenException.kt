package com.procurement.auth.exception.security

/**
 * The EmptyAuthTokenException is thrown when authorization header is empty.
 */
class EmptyAuthTokenException(message: String) : RuntimeException(message)