package com.procurement.auth.security

import com.procurement.auth.exception.crypto.NotSupportAlgorithmException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class KeyFactoryServiceTest {
    @Test
    fun notSupportAlgorithmException() {
        val factory = KeyFactoryServiceImpl()

        Assertions.assertThrows(
            NotSupportAlgorithmException::class.java,
            {
                factory.getKeyFactory("UNKNOWN")
            }
        )
    }
}