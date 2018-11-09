package com.procurement.auth

const val AUTHORIZATION_HEADER_DESCRIPTION = "Basic auth credentials."
const val WWW_AUTHENTICATE_HEADER_DESCRIPTION =
    "The HTTP WWW-Authenticate response header defines the authentication method that should be used to gain access to a resource."

const val USER_ID = 1L
const val USER_NAME = "USER"
const val USER_PASSWORD = "USER"

const val BASIC_CREDENTIALS = "$USER_NAME:$USER_PASSWORD"
const val INVALID_FORMAT_BASIC_CREDENTIALS = "$USER_NAME$USER_PASSWORD"
const val INVALID_BASIC_CREDENTIALS = "UNKNOWN:$USER_PASSWORD"
const val ACCESS_TOKEN = "ACCESS_TOKEN"
const val REFRESH_TOKEN = "REFRESH_TOKEN"
