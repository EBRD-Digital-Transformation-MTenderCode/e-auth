package com.procurement.auth.model.response

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyOrder

@JsonPropertyOrder("success", "data")
data class TokenRS @JsonCreator constructor(
    @field:JsonProperty("data")
    @param:JsonProperty("data") val data: Data
) : BaseRS(true)

data class Data @JsonCreator
constructor(
    @field:JsonProperty("tokens")
    @param:JsonProperty("tokens")
    private val tokens: Tokens
)

@JsonPropertyOrder("access", "refresh")
data class Tokens @JsonCreator
constructor(
    @field:JsonProperty("access")
    @param:JsonProperty("access")
    private val access: String,

    @field:JsonProperty("refresh")
    @param:JsonProperty("refresh")
    private val refresh: String
)