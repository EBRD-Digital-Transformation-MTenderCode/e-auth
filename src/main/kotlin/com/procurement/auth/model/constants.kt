package com.procurement.auth.model

const val AUTHORIZATION_HEADER_NAME = "Authorization"
const val AUTHORIZATION_PREFIX_BASIC = "Basic "
const val AUTHORIZATION_PREFIX_BEARER = "Bearer "
const val REALM = """realm="yoda""""
const val BASIC_REALM = AUTHORIZATION_PREFIX_BASIC + REALM
const val BEARER_REALM = AUTHORIZATION_PREFIX_BEARER + REALM

const val CLAIM_NAME_PLATFORM_ID = "idPlatform"
const val HEADER_NAME_TOKEN_TYPE = "tid"
const val ACCESS_TOKEN_TYPE = "ACCESS"
const val REFRESH_TOKEN_TYPE = "REFRESH"

const val WWW_AUTHENTICATE_HEADER_NAME = "WWW-Authenticate"
const val ERROR_CODE_INVALID_TOKEN = """error_code="invalid_token""""
