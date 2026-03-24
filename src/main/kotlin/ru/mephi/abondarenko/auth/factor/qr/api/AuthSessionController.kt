package ru.mephi.abondarenko.auth.factor.qr.api

import jakarta.validation.Valid
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import ru.mephi.abondarenko.auth.factor.qr.api.dto.CreateChallengeRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.CreateChallengeResponse
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ResponseQrPayload
import ru.mephi.abondarenko.auth.factor.qr.api.dto.SessionInfoResponse
import ru.mephi.abondarenko.auth.factor.qr.api.dto.VerifyQrResponseResult
import ru.mephi.abondarenko.auth.factor.qr.service.AuthSessionService
import java.util.UUID

@RestController
@RequestMapping("/api/v1/auth")
class AuthSessionController(
    private val authSessionService: AuthSessionService
) {

    @PostMapping("/challenge")
    fun createChallenge(
        @Valid @RequestBody request: CreateChallengeRequest
    ): CreateChallengeResponse {
        return authSessionService.createChallenge(request)
    }

    @PostMapping("/verify-qr-response")
    fun verifyQrResponse(
        @Valid @RequestBody request: ResponseQrPayload
    ): VerifyQrResponseResult {
        return authSessionService.verifyResponse(request)
    }

    @GetMapping("/sessions/{sessionId}")
    fun getSessionInfo(
        @PathVariable sessionId: UUID
    ): SessionInfoResponse {
        return authSessionService.getSessionInfo(sessionId)
    }
}