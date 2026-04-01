package ru.mephi.abondarenko.auth.factor.qr.api.dto

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Pattern
import jakarta.validation.constraints.Size
import ru.mephi.abondarenko.auth.factor.qr.domain.DeviceStatus
import java.time.Instant
import java.util.UUID

data class StartEnrollmentRequest(
    @field:NotBlank
    @field:Size(max = 128)
    val externalUserId: String,

    @field:Size(max = 255)
    val displayName: String? = null,

    @field:NotBlank
    @field:Size(max = 255)
    val deviceLabel: String
)

data class StartEnrollmentResponse(
    val userId: UUID,
    val deviceId: UUID,
    val deviceStatus: DeviceStatus,
    val qrPayload: EnrollmentQrPayload,
    val qrPayloadRaw: String
)

data class ConfirmEnrollmentRequest(
    @field:NotNull
    val deviceId: UUID,

    @field:Pattern(regexp = "^[0-9]{6,8}$")
    val totpCode: String
)

data class ConfirmEnrollmentResponse(
    val deviceId: UUID,
    val deviceStatus: DeviceStatus,
    val confirmedAt: Instant
)

data class DeviceInfoResponse(
    val deviceId: UUID,
    val deviceLabel: String,
    val serviceId: String,
    val deviceStatus: DeviceStatus,
    val createdAt: Instant,
    val confirmedAt: Instant?,
    val revokedAt: Instant?,
    val lastUsedAt: Instant?
)

data class RevokeDeviceRequest(
    @field:NotBlank
    @field:Size(max = 128)
    val externalUserId: String
)

data class RevokeDeviceResponse(
    val deviceId: UUID,
    val deviceStatus: DeviceStatus,
    val revokedAt: Instant
)

data class DeviceRevokeRequest(
    @field:Pattern(regexp = "^[0-9]{6,8}$")
    val totpCode: String
)
