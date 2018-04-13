package com.procurement.auth.exception.security

/**
 * The VerificationTokenException  is thrown when the verification token is failed.
 */
class VerificationTokenException(message: String, cause: Throwable) : RuntimeException(message, cause)