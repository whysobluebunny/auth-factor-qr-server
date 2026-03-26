package ru.mephi.abondarenko.auth.factor.qr.ui.hosted

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Pattern
import jakarta.validation.constraints.Size
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceInfoResponse
import ru.mephi.abondarenko.auth.factor.qr.domain.SessionStatus
import ru.mephi.abondarenko.auth.factor.qr.domain.TotpAlgorithm
import java.time.Instant
import java.util.*

data class HostedEnrollmentForm(
    @field:NotBlank
    @field:Size(max = 128)
    val externalUserId: String = "",

    @field:Size(max = 255)
    val displayName: String? = null,

    @field:NotBlank
    @field:Size(max = 255)
    val deviceLabel: String = ""
)

data class HostedChallengeForm(
    @field:NotBlank
    @field:Size(max = 128)
    val externalUserId: String = "",

    @field:NotNull
    val deviceId: UUID? = null,

    @field:Size(max = 255)
    val firstFactorRef: String? = null,

    @field:Size(max = 1024)
    val returnUrl: String? = null
)

data class HostedVerifyForm(
    @field:NotBlank
    val responsePayloadRaw: String = "",

    @field:Size(max = 1024)
    val returnUrl: String? = null
)

data class HostedEnrollmentViewModel(
    val externalUserId: String,
    val deviceId: UUID,
    val deviceStatus: String,
    val secret: String,
    val period: Int,
    val digits: Int,
    val algorithm: TotpAlgorithm,
    val qrPayloadRaw: String,
    val qrCodeDataUrl: String
)

data class HostedEnrollmentConfirmForm(
    @field:NotNull
    val deviceId: UUID? = null,

    @field:Pattern(regexp = "^[0-9]{6,8}$")
    val totpCode: String = ""
)

data class HostedAuthSessionViewModel(
    val sessionId: UUID,
    val status: SessionStatus,
    val createdAt: Instant,
    val expiresAt: Instant,
    val verifiedAt: Instant?,
    val attemptCount: Int,
    val maxAttempts: Int,
    val qrPayloadRaw: String,
    val qrCodeDataUrl: String,
    val returnUrl: String?
)

data class HostedDeviceListViewModel(
    val externalUserId: String,
    val devices: List<DeviceInfoResponse>
)

data class HostedDeviceSimulatorForm(
    @field:NotBlank
    val secret: String = "",

    val deviceId: UUID? = null,

    val sessionId: UUID? = null,

    @field:Size(max = 4096)
    val challengePayloadRaw: String = "",

    @field:NotNull
    val period: Int? = 30,

    @field:NotNull
    val digits: Int? = 6,

    @field:NotNull
    val algorithm: TotpAlgorithm? = TotpAlgorithm.SHA1,

    @field:Size(max = 1024)
    val returnUrl: String? = null
)

data class HostedDeviceSimulatorViewModel(
    val generatedAt: Instant,
    val currentTotpCode: String,
    val responsePayloadRaw: String?
)
