package ru.mephi.abondarenko.auth.factor.qr

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.CreateChallengeRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ResponseQrPayload
import ru.mephi.abondarenko.auth.factor.qr.api.dto.StartEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.domain.SessionStatus
import ru.mephi.abondarenko.auth.factor.qr.domain.TotpAlgorithm
import ru.mephi.abondarenko.auth.factor.qr.service.AuthSessionService
import ru.mephi.abondarenko.auth.factor.qr.service.EnrollmentService
import ru.mephi.abondarenko.auth.factor.qr.service.totp.TotpService
import java.time.Clock
import java.time.Instant

class AuthFlowIntegrationTest : AbstractIntegrationTest() {

    @Autowired
    lateinit var enrollmentService: EnrollmentService

    @Autowired
    lateinit var authSessionService: AuthSessionService

    @Autowired
    lateinit var totpService: TotpService

    @Autowired
    lateinit var clock: Clock

    @Test
    fun `should approve valid qr response`() {
        val enrollment = enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "user-002",
                displayName = "Test User",
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
                externalUserId = "user-002",
                deviceId = enrollment.deviceId,
                firstFactorRef = "login-attempt-1"
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

        val verifyResult = authSessionService.verifyResponse(
            ResponseQrPayload(
                type = "response",
                sessionId = challenge.sessionId,
                challenge = challenge.qrPayload.challenge,
                totp = responseCode,
                timestamp = responseTimestamp.epochSecond,
                deviceId = enrollment.deviceId
            )
        )

        assertTrue(verifyResult.approved)
        assertEquals(SessionStatus.APPROVED, verifyResult.status)
        assertNotNull(verifyResult.verifiedAt)

        val sessionInfo = authSessionService.getSessionInfo(challenge.sessionId)
        assertEquals(SessionStatus.APPROVED, sessionInfo.status)
    }

    @Test
    fun `should block session after invalid attempts`() {
        val enrollment = enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "user-003",
                displayName = "Blocked User",
                deviceLabel = "Samsung"
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
                externalUserId = "user-003",
                deviceId = enrollment.deviceId
            )
        )

        repeat(2) { attempt ->
            val result = authSessionService.verifyResponse(
                ResponseQrPayload(
                    type = "response",
                    sessionId = challenge.sessionId,
                    challenge = challenge.qrPayload.challenge,
                    totp = "000000",
                    timestamp = Instant.now(clock).epochSecond,
                    deviceId = enrollment.deviceId
                )
            )

            assertFalse(result.approved)
            assertEquals(attempt + 1, result.attemptCount)
        }

        val thirdResult = authSessionService.verifyResponse(
            ResponseQrPayload(
                type = "response",
                sessionId = challenge.sessionId,
                challenge = challenge.qrPayload.challenge,
                totp = "000000",
                timestamp = Instant.now(clock).epochSecond,
                deviceId = enrollment.deviceId
            )
        )

        assertFalse(thirdResult.approved)
        assertEquals(SessionStatus.BLOCKED, thirdResult.status)
        assertEquals(3, thirdResult.attemptCount)
        assertEquals(3, thirdResult.maxAttempts)
    }
}