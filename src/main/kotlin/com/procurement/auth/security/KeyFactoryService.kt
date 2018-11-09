package com.procurement.auth.security

import com.procurement.auth.exception.crypto.NotSupportAlgorithmException
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException

interface KeyFactoryService {
    fun getKeyFactory(algorithm: String): KeyFactory
}

class KeyFactoryServiceImpl : KeyFactoryService {
    override fun getKeyFactory(algorithm: String): KeyFactory = try {
        KeyFactory.getInstance(algorithm)
    } catch (e: NoSuchAlgorithmException) {
        throw NotSupportAlgorithmException("KeyFactory not support specified algorithm: " + algorithm, e)
    }
}