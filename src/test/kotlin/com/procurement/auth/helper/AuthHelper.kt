package com.procurement.auth.helper

import org.springframework.mock.web.MockHttpServletRequest
import javax.servlet.http.HttpServletRequest

fun genHttpServletRequest(): HttpServletRequest {
    val request = MockHttpServletRequest()
    request.remoteAddr = "127.0.0.1"
    request.remoteHost = "localhost"
    return request
}