package com.procurement.auth.controller

import com.procurement.auth.model.HEADER_NAME_ACCESS_TOKEN
import com.procurement.auth.model.HEADER_NAME_REFRESH_TOKEN
import com.procurement.auth.service.TokenService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RestController
import javax.servlet.http.HttpServletRequest

@RestController
@RequestMapping("/auth")
class AuthController(
    private val tokenService: TokenService
) {
    @GetMapping(value = ["/tokens"])
    fun tokens(request: HttpServletRequest): ResponseEntity<Void> {
        val authTokens = tokenService.getTokensByUserCredentials(request)
        return ResponseEntity.ok()
            .header(HEADER_NAME_ACCESS_TOKEN, authTokens.accessToken)
            .header(HEADER_NAME_REFRESH_TOKEN, authTokens.refreshToken)
            .build()
    }

    @GetMapping(value = ["/refresh"])
    fun refresh(request: HttpServletRequest): ResponseEntity<Void> {
        val authTokens = tokenService.getTokensByRefreshToken(request)
        return ResponseEntity
            .ok()
            .header(HEADER_NAME_ACCESS_TOKEN, authTokens.accessToken)
            .header(HEADER_NAME_REFRESH_TOKEN, authTokens.refreshToken)
            .build()
    }
}