package com.procurement.auth.model.response

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty

open class BaseRS @JsonCreator constructor(
    @field:JsonProperty("success")
    @param:JsonProperty("success") val success: Boolean
)