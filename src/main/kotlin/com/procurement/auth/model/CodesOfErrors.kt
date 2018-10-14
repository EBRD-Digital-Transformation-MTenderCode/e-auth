package com.procurement.auth.model

import com.procurement.auth.configuration.properties.GlobalProperties
import org.springframework.http.HttpStatus

//interface CodeError {
//    val code: String
//}

enum class CodesOfErrors(val httpStatus: HttpStatus, group: String, id: String) {
    ACCOUNT_INVALID_CREDENTIALS(httpStatus = HttpStatus.UNAUTHORIZED, group = "01", id = "01"),
    ACCOUNT_REVOKED(httpStatus = HttpStatus.UNAUTHORIZED, group = "01", id = "02"),
    ACCOUNT_PLATFORM_UNKNOWN(httpStatus = HttpStatus.UNAUTHORIZED, group = "01", id = "03"),
    AUTH_HEADER_NO_SUCH(httpStatus = HttpStatus.UNAUTHORIZED, group = "02", id = "01"),
    AUTH_HEADER_INVALID_TYPE(httpStatus = HttpStatus.UNAUTHORIZED, group = "02", id = "02"),
    AUTH_TOKEN_EMPTY(httpStatus = HttpStatus.UNAUTHORIZED, group = "03", id = "01"),
    AUTH_TOKEN_INVALID_TYPE(httpStatus = HttpStatus.UNAUTHORIZED, group = "03", id = "02"),
    AUTH_TOKEN_INVALID_FORMAT(httpStatus = HttpStatus.UNAUTHORIZED, group = "03", id = "03"),
    AUTH_TOKEN_VERIFICATION(httpStatus = HttpStatus.UNAUTHORIZED, group = "03", id = "04"),
    AUTH_TOKEN_EXPIRED(httpStatus = HttpStatus.UNAUTHORIZED, group = "03", id = "05");

    val code: String = "${httpStatus.value()}.${GlobalProperties.serviceId}.$group.$id"

    override fun toString(): String = code
}