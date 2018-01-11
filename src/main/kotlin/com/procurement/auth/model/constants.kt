package com.procurement.auth.model

const val HEADER_NAME_AUTHORIZATION = "Authorization"
const val AUTHORIZATION_PREFIX_BASIC = "Basic "
const val AUTHORIZATION_PREFIX_BEARER = "Bearer "
const val REALM = """realm="yoda""""
const val BASIC_REALM = AUTHORIZATION_PREFIX_BASIC + REALM
const val BEARER_REALM = AUTHORIZATION_PREFIX_BEARER + REALM

const val CLAIM_NAME_PLATFORM_ID = "idPlatform"
const val HEADER_NAME_TOKEN_TYPE = "typToken"
const val ACCESS_TOKEN_TYPE = "ACCESS"
const val REFRESH_TOKEN_TYPE = "REFRESH"

const val HEADER_NAME_WWW_AUTHENTICATE = "WWW-Authenticate"

const val HEADER_NAME_ACCESS_TOKEN = "X-Access-Token"
const val HEADER_NAME_REFRESH_TOKEN = "X-Refresh-Token"
