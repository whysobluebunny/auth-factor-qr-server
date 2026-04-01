package ru.mephi.abondarenko.auth.factor.qr.api.dto

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import ru.mephi.abondarenko.auth.factor.qr.domain.SessionStatus
import java.time.Instant
import java.util.*

data class CreateChallengeRequest(
    @field:NotBlank
    @field:Size(max = 128)
    val externalUserId: String,

    @field:Size(max = 255)
    val firstFactorRef: String? = null
)

data class CreateChallengeResponse(
    val sessionId: UUID,
    val status: SessionStatus,
    val expiresAt: Instant,
    val qrPayload: ChallengeQrPayload,
    val qrPayloadRaw: String
)

data class VerifyQrResponseResult(
    val sessionId: UUID,
    val status: SessionStatus,
    val approved: Boolean,
    val attemptCount: Int,
    val maxAttempts: Int,
    val verifiedAt: Instant?
)

data class SessionInfoResponse(
    val sessionId: UUID,
    val userId: UUID,
    val deviceId: UUID?,
    val status: SessionStatus,
    val createdAt: Instant,
    val expiresAt: Instant,
    val verifiedAt: Instant?,
    val attemptCount: Int,
    val maxAttempts: Int
)
