package ru.mephi.abondarenko.auth.factor.qr

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.mock.web.MockHttpSession
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ChallengeQrPayload
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.CreateChallengeRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.StartEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.domain.TotpAlgorithm
import ru.mephi.abondarenko.auth.factor.qr.service.AuthSessionService
import ru.mephi.abondarenko.auth.factor.qr.service.EnrollmentService
import ru.mephi.abondarenko.auth.factor.qr.service.totp.TotpService
import tools.jackson.databind.json.JsonMapper
import java.time.Clock
import java.time.Instant
import java.util.*

@AutoConfigureMockMvc
class HostedUiIntegrationTest : AbstractIntegrationTest() {

    @Autowired
    lateinit var mockMvc: MockMvc

    @Autowired
    lateinit var enrollmentService: EnrollmentService

    @Autowired
    lateinit var authSessionService: AuthSessionService

    @Autowired
    lateinit var totpService: TotpService

    @Autowired
    lateinit var clock: Clock

    @Autowired
    lateinit var objectMapper: JsonMapper

    @Test
    fun `should render hosted enrollment page and enrollment result`() {
        mockMvc.perform(get("/ui/enrollments"))
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Device Enrollment")))

        mockMvc.perform(
            post("/ui/enrollments")
                .param("externalUserId", "ui-user-001")
                .param("displayName", "UI User")
        )
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Enrollment Session")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("ui-user-001")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("data:image/png;base64")))
    }

    @Test
    fun `should render hosted auth session page and verify response`() {
        val enrollment = enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "ui-user-002",
                displayName = "UI User",
                deviceLabel = "Android Phone"
            )
        )

        val enrollmentCode = totpService.generate(
            secretBase32 = enrollment.qrPayload.secret,
            timestamp = Instant.now(clock),
            digits = enrollment.qrPayload.digits,
            periodSeconds = enrollment.qrPayload.period,
            algorithm = TotpAlgorithm.valueOf(enrollment.qrPayload.algorithm)
        )

        enrollmentService.confirmEnrollment(
            ConfirmEnrollmentRequest(
                deviceId = enrollment.deviceId,
                totpCode = enrollmentCode
            )
        )

        val challenge = authSessionService.createChallenge(
            CreateChallengeRequest(
                externalUserId = "ui-user-002",
                deviceId = enrollment.deviceId,
                firstFactorRef = "ui-auth-test"
            )
        )

        val responseTimestamp = Instant.now(clock)
        val responseCode = totpService.generate(
            secretBase32 = enrollment.qrPayload.secret,
            timestamp = responseTimestamp,
            digits = enrollment.qrPayload.digits,
            periodSeconds = enrollment.qrPayload.period,
            algorithm = TotpAlgorithm.valueOf(enrollment.qrPayload.algorithm)
        )

        val responsePayload = """
            {
              "type": "response",
              "session_id": "${challenge.sessionId}",
              "challenge": "${challenge.qrPayload.challenge}",
              "totp": "$responseCode",
              "timestamp": ${responseTimestamp.epochSecond},
              "device_id": "${enrollment.deviceId}"
            }
        """.trimIndent()

        mockMvc.perform(get("/ui/auth/sessions/${challenge.sessionId}"))
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Authentication Session")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString(challenge.sessionId.toString())))

        mockMvc.perform(
            post("/ui/auth/sessions/${challenge.sessionId}/verify")
                .param("responsePayloadRaw", responsePayload)
                .param("returnUrl", "https://demo-app/callback")
        )
            .andExpect(status().is3xxRedirection)
            .andExpect(
                org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl(
                    "https://demo-app/callback?sessionId=${challenge.sessionId}"
                )
            )

        mockMvc.perform(get("/ui/auth/sessions/${challenge.sessionId}"))
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("APPROVED")))
    }

    @Test
    fun `should complete redirect based demo flow`() {
        val loginResult = mockMvc.perform(
            post("/demo/login")
                .param("username", "demo-user")
                .param("password", "password")
        )
            .andExpect(status().is3xxRedirection)
            .andReturn()

        val redirectUrl = loginResult.response.redirectedUrl!!
        val demoSession = loginResult.request.session as MockHttpSession
        org.assertj.core.api.Assertions.assertThat(redirectUrl).isEqualTo("/demo/home")

        mockMvc.perform(
            get("/demo/home")
                .session(demoSession)
        )
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Signed In")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("demo-user")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Register Device For Second Factor")))
    }

    @Test
    fun `should redirect enrolled demo user into hosted 2fa flow`() {
        val enrollment = enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "demo-user",
                displayName = "Demo User",
                deviceLabel = "Demo Phone"
            )
        )

        val enrollmentCode = totpService.generate(
            secretBase32 = enrollment.qrPayload.secret,
            timestamp = Instant.now(clock),
            digits = enrollment.qrPayload.digits,
            periodSeconds = enrollment.qrPayload.period,
            algorithm = TotpAlgorithm.valueOf(enrollment.qrPayload.algorithm)
        )

        enrollmentService.confirmEnrollment(
            ConfirmEnrollmentRequest(
                deviceId = enrollment.deviceId,
                totpCode = enrollmentCode
            )
        )

        val loginResult = mockMvc.perform(
            post("/demo/login")
                .param("username", "demo-user")
                .param("password", "password")
        )
            .andExpect(status().is3xxRedirection)
            .andReturn()

        val redirectUrl = loginResult.response.redirectedUrl!!
        val demoSession = loginResult.request.session as MockHttpSession
        org.assertj.core.api.Assertions.assertThat(redirectUrl).startsWith("/ui/auth/sessions/")
        org.assertj.core.api.Assertions.assertThat(redirectUrl).contains("returnUrl=/demo/callback")
        val sessionId = UUID.fromString(redirectUrl.substringAfter("/ui/auth/sessions/").substringBefore("?"))
        val challengePayload = objectMapper.readValue(
            authSessionService.getChallengePayloadRaw(sessionId),
            ChallengeQrPayload::class.java
        )

        val responseTimestamp = Instant.now(clock)
        val responseCode = totpService.generate(
            secretBase32 = enrollment.qrPayload.secret,
            timestamp = responseTimestamp,
            digits = enrollment.qrPayload.digits,
            periodSeconds = enrollment.qrPayload.period,
            algorithm = TotpAlgorithm.valueOf(enrollment.qrPayload.algorithm)
        )

        val responsePayload = """
            {
              "type": "response",
              "session_id": "$sessionId",
              "challenge": "${challengePayload.challenge}",
              "totp": "$responseCode",
              "timestamp": ${responseTimestamp.epochSecond},
              "device_id": "${enrollment.deviceId}"
            }
        """.trimIndent()

        mockMvc.perform(
            post("/ui/auth/sessions/$sessionId/verify")
                .session(demoSession)
                .param("responsePayloadRaw", responsePayload)
                .param("returnUrl", "/demo/callback")
        )
            .andExpect(status().is3xxRedirection)
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl("/demo/callback?sessionId=$sessionId"))

        mockMvc.perform(
            get("/demo/callback")
                .session(demoSession)
                .param("sessionId", sessionId.toString())
        )
            .andExpect(status().is3xxRedirection)
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl("/demo/home"))

        mockMvc.perform(
            get("/demo/home")
                .session(demoSession)
        )
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("demo-user")))
    }

    @Test
    fun `should refresh demo home after device enrollment in same session`() {
        val loginResult = mockMvc.perform(
            post("/demo/login")
                .param("username", "alice")
                .param("password", "password")
        )
            .andExpect(status().is3xxRedirection)
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl("/demo/home"))
            .andReturn()

        val demoSession = loginResult.request.session as MockHttpSession

        val enrollment = enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "alice",
                displayName = "alice",
                deviceLabel = "Alice Phone"
            )
        )

        val enrollmentCode = totpService.generate(
            secretBase32 = enrollment.qrPayload.secret,
            timestamp = Instant.now(clock),
            digits = enrollment.qrPayload.digits,
            periodSeconds = enrollment.qrPayload.period,
            algorithm = TotpAlgorithm.valueOf(enrollment.qrPayload.algorithm)
        )

        enrollmentService.confirmEnrollment(
            ConfirmEnrollmentRequest(
                deviceId = enrollment.deviceId,
                totpCode = enrollmentCode
            )
        )

        mockMvc.perform(
            get("/demo/home")
                .session(demoSession)
        )
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Second Factor Ready")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Registered Second-Factor Devices")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Alice Phone")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("ACTIVE")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Add New Device")))
    }

    @Test
    fun `should allow revoking pending device from demo home`() {
        val loginResult = mockMvc.perform(
            post("/demo/login")
                .param("username", "alice")
                .param("password", "password")
        )
            .andExpect(status().is3xxRedirection)
            .andExpect(redirectedUrl("/demo/home"))
            .andReturn()

        val demoSession = loginResult.request.session as MockHttpSession

        val enrollment = enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "alice",
                displayName = "alice",
                deviceLabel = "Pending Device"
            )
        )

        mockMvc.perform(
            post("/demo/devices/${enrollment.deviceId}/revoke")
                .session(demoSession)
        )
            .andExpect(status().is3xxRedirection)
            .andExpect(redirectedUrl("/demo/home"))

        mockMvc.perform(
            get("/demo/home")
                .session(demoSession)
        )
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("Pending Device"))))
    }
}
