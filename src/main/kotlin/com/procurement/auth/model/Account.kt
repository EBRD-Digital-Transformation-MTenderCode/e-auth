package com.procurement.auth.model

import java.util.*

data class Account(
    var id: Long,
    var username: String,
    var hashPassword: String,
    var enabled: Boolean,
    var platformId: UUID
)