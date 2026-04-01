package ru.mephi.abondarenko.auth.factor.qr

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import tools.jackson.databind.json.JsonMapper
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceEnrollmentConfirmRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceRevokeRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.StartEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.service.EnrollmentService
import ru.mephi.abondarenko.auth.factor.qr.service.totp.TotpService
import ru.mephi.abondarenko.auth.factor.qr.domain.TotpAlgorithm
import java.time.Clock
import java.time.Instant

@AutoConfigureMockMvc
class ApiSecurityIntegrationTest : AbstractIntegrationTest() {

    @Autowired
    lateinit var mockMvc: MockMvc

    @Autowired
    lateinit var enrollmentService: EnrollmentService

    @Autowired
    lateinit var totpService: TotpService

    @Autowired
    lateinit var objectMapper: JsonMapper

    @Autowired
    lateinit var clock: Clock

    @Test
    fun `should reject api request without api key`() {
        val response = mockMvc.perform(
            get("/api/v1/enrollments/devices")
                .queryParam("externalUserId", "user-sec-001")
        ).andReturn().response

        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.status)
        assertEquals(true, response.contentAsString.contains("invalid API key"))
    }

    @Test
    fun `should allow api request with valid api key and expose audit events`() {
        enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "user-sec-002",
                displayName = "Secured User",
                deviceLabel = "Protected Device"
            )
        )

        mockMvc.perform(
            get("/api/v1/enrollments/devices")
                .queryParam("externalUserId", "user-sec-002")
                .header("X-Auth-Factor-Api-Key", "test-api-key")
        )
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Protected Device")))

        mockMvc.perform(
            get("/api/v1/audit-events")
                .queryParam("externalUserId", "user-sec-002")
                .queryParam("limit", "10")
                .header("X-Auth-Factor-Api-Key", "test-api-key")
        )
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("ENROLLMENT_STARTED")))
    }

    @Test
    fun `should allow device api without integration api key`() {
        val enrollment = enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "user-device-sec-001",
                displayName = "Device User",
                deviceLabel = "Phone"
            )
        )

        val enrollmentCode = totpService.generate(
            secretBase32 = enrollment.qrPayload.secret,
            timestamp = Instant.now(clock),
            digits = enrollment.qrPayload.digits,
            periodSeconds = enrollment.qrPayload.period,
            algorithm = TotpAlgorithm.valueOf(enrollment.qrPayload.algorithm)
        )

        mockMvc.perform(
            post("/api/v1/device/enrollments/confirm")
                .contentType("application/json")
                .content(
                    objectMapper.writeValueAsString(
                        DeviceEnrollmentConfirmRequest(
                            deviceId = enrollment.deviceId,
                            enrollmentToken = enrollment.qrPayload.enrollmentToken,
                            deviceLabel = "Phone",
                            totpCode = enrollmentCode
                        )
                    )
                )
        )
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("ACTIVE")))

        val revokeCode = totpService.generate(
            secretBase32 = enrollment.qrPayload.secret,
            timestamp = Instant.now(clock),
            digits = enrollment.qrPayload.digits,
            periodSeconds = enrollment.qrPayload.period,
            algorithm = TotpAlgorithm.valueOf(enrollment.qrPayload.algorithm)
        )

        mockMvc.perform(
            post("/api/v1/device/devices/${enrollment.deviceId}/revoke")
                .contentType("application/json")
                .content(
                    objectMapper.writeValueAsString(
                        DeviceRevokeRequest(
                            totpCode = revokeCode
                        )
                    )
                )
        )
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("REVOKED")))
    }
}
