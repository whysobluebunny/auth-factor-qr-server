package ru.mephi.abondarenko.auth.factor.qr.api.dto

import com.fasterxml.jackson.annotation.JsonProperty
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Pattern
import jakarta.validation.constraints.Size
import java.util.UUID

data class EnrollmentQrPayload(
    @JsonProperty("type")
    val type: String = "enroll",

    @JsonProperty("service_id")
    val serviceId: String,

    @JsonProperty("base_url")
    val baseUrl: String,

    @JsonProperty("user_id")
    val userId: String,

    @JsonProperty("device_id")
    val deviceId: String,

    @JsonProperty("secret")
    val secret: String,

    @JsonProperty("enrollment_token")
    val enrollmentToken: String,

    @JsonProperty("period")
    val period: Int,

    @JsonProperty("digits")
    val digits: Int,

    @JsonProperty("algorithm")
    val algorithm: String
)

data class ChallengeQrPayload(
    @JsonProperty("type")
    val type: String = "challenge",

    @JsonProperty("session_id")
    val sessionId: UUID,

    @JsonProperty("challenge")
    val challenge: String,

    @JsonProperty("service_id")
    val serviceId: String,

    @JsonProperty("timestamp")
    val timestamp: Long,

    @JsonProperty("response_token")
    val responseToken: String
)

data class ResponseQrPayload(
    @JsonProperty("type")
    @field:NotBlank
    val type: String,

    @JsonProperty("session_id")
    @field:NotNull
    val sessionId: UUID,

    @JsonProperty("challenge")
    @field:NotBlank
    val challenge: String,

    @JsonProperty("totp")
    @field:Pattern(regexp = "^[0-9]{6,8}$")
    val totp: String,

    @JsonProperty("timestamp")
    val timestamp: Long,

    @JsonProperty("device_id")
    @field:NotNull
    val deviceId: UUID
)

data class DeviceEnrollmentConfirmRequest(
    @JsonProperty("device_id")
    @field:NotNull
    val deviceId: UUID,

    @JsonProperty("enrollment_token")
    @field:NotBlank
    val enrollmentToken: String,

    @JsonProperty("device_label")
    @field:NotBlank
    @field:Size(max = 255)
    val deviceLabel: String,

    @JsonProperty("totp_code")
    @field:Pattern(regexp = "^[0-9]{6,8}$")
    val totpCode: String
)

data class DeviceAuthResponseRequest(
    @JsonProperty("session_id")
    @field:NotNull
    val sessionId: UUID,

    @JsonProperty("response_token")
    @field:NotBlank
    val responseToken: String,

    @JsonProperty("challenge")
    @field:NotBlank
    val challenge: String,

    @JsonProperty("totp")
    @field:Pattern(regexp = "^[0-9]{6,8}$")
    val totp: String,

    @JsonProperty("timestamp")
    val timestamp: Long,

    @JsonProperty("device_id")
    @field:NotNull
    val deviceId: UUID
)
