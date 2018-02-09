package com.procurement.auth.filter

import com.procurement.auth.model.HEADER_NAME_AUTHORIZATION
import org.slf4j.MDC
import javax.servlet.*
import javax.servlet.annotation.WebFilter
import javax.servlet.http.HttpServletRequest

@WebFilter(urlPatterns = ["/*"])
class AuthorizationInfoServletFilter : Filter {
    companion object {
        private const val REMOTE_ADDRESS = "remoteAddr"
        private const val AUTHORIZATION = "authorization"
    }

    override fun init(arg0: FilterConfig) {}

    override fun destroy() {}

    override fun doFilter(
        request: ServletRequest,
        response: ServletResponse,
        chain: FilterChain
    ) {
        with(request as HttpServletRequest) {
            MDC.put(REMOTE_ADDRESS, remoteAddr)
            MDC.put(AUTHORIZATION, getHeader(HEADER_NAME_AUTHORIZATION) ?: "none")
        }

        try {
            chain.doFilter(request, response)
        } finally {
            MDC.remove(REMOTE_ADDRESS)
            MDC.remove(AUTHORIZATION)
        }
    }
}