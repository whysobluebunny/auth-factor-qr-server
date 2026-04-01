package ru.mephi.abondarenko.auth.factor.qr

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.CreateChallengeRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceAuthResponseRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceEnrollmentConfirmRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceRevokeRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ResponseQrPayload
import ru.mephi.abondarenko.auth.factor.qr.api.dto.StartEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.error.TooManyRequestsException
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
    fun `should confirm enrollment and approve auth response through device facing flow`() {
        val enrollment = enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "user-device-001",
                displayName = "Device Flow User",
                deviceLabel = "Android Device"
            )
        )

        val enrollmentCode = totpService.generate(
            secretBase32 = enrollment.qrPayload.secret,
            timestamp = Instant.now(clock),
            digits = enrollment.qrPayload.digits,
            periodSeconds = enrollment.qrPayload.period,
            algorithm = TotpAlgorithm.valueOf(enrollment.qrPayload.algorithm)
        )

        val confirmResult = enrollmentService.confirmEnrollmentFromDevice(
            DeviceEnrollmentConfirmRequest(
                deviceId = enrollment.deviceId,
                enrollmentToken = enrollment.qrPayload.enrollmentToken,
                deviceLabel = "Android Device",
                totpCode = enrollmentCode
            )
        )

        assertEquals(enrollment.deviceId, confirmResult.deviceId)

        val challenge = authSessionService.createChallenge(
            CreateChallengeRequest(
                externalUserId = "user-device-001",
                firstFactorRef = "first-factor-device-flow"
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

        val verifyResult = authSessionService.verifyResponseFromDevice(
            DeviceAuthResponseRequest(
                sessionId = challenge.sessionId,
                responseToken = challenge.qrPayload.responseToken,
                challenge = challenge.qrPayload.challenge,
                totp = responseCode,
                timestamp = responseTimestamp.epochSecond,
                deviceId = enrollment.deviceId
            )
        )

        assertTrue(verifyResult.approved)
        assertEquals(SessionStatus.APPROVED, verifyResult.status)
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
                externalUserId = "user-003"
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

    @Test
    fun `should rate limit challenge creation per user`() {
        val enrollment = activeEnrollment("user-rl-001", "Challenge Limited User", "Phone")

        repeat(5) {
            authSessionService.createChallenge(
                CreateChallengeRequest(
                    externalUserId = "user-rl-001",
                    firstFactorRef = "challenge-$it"
                )
            )
        }

        assertThrows(TooManyRequestsException::class.java) {
            authSessionService.createChallenge(
                CreateChallengeRequest(
                    externalUserId = "user-rl-001",
                    firstFactorRef = "challenge-5"
                )
            )
        }
    }

    @Test
    fun `should rate limit verify attempts per user and device`() {
        val enrollment = activeEnrollment("user-rl-002", "Verify Limited User", "Phone")

        repeat(3) {
            val challenge = authSessionService.createChallenge(
                CreateChallengeRequest(
                    externalUserId = "user-rl-002",
                    firstFactorRef = "verify-rate-limit-$it"
                )
            )

            authSessionService.verifyResponse(
                ResponseQrPayload(
                    type = "response",
                    sessionId = challenge.sessionId,
                    challenge = challenge.qrPayload.challenge,
                    totp = "000000",
                    timestamp = Instant.now(clock).epochSecond,
                    deviceId = enrollment.deviceId
                )
            )
        }

        assertThrows(TooManyRequestsException::class.java) {
            val challenge = authSessionService.createChallenge(
                CreateChallengeRequest(
                    externalUserId = "user-rl-002",
                    firstFactorRef = "verify-rate-limit-3"
                )
            )

            authSessionService.verifyResponse(
                ResponseQrPayload(
                    type = "response",
                    sessionId = challenge.sessionId,
                    challenge = challenge.qrPayload.challenge,
                    totp = "000000",
                    timestamp = Instant.now(clock).epochSecond,
                    deviceId = enrollment.deviceId
                )
            )
        }
    }

    @Test
    fun `should allow device to revoke itself with valid totp`() {
        val enrollment = activeEnrollment("user-revoke-001", "Revoke User", "Phone")

        val revokeCode = totpService.generate(
            secretBase32 = enrollment.qrPayload.secret,
            timestamp = Instant.now(clock),
            digits = enrollment.qrPayload.digits,
            periodSeconds = enrollment.qrPayload.period,
            algorithm = TotpAlgorithm.valueOf(enrollment.qrPayload.algorithm)
        )

        val revokeResult = enrollmentService.revokeDeviceFromDevice(
            deviceId = enrollment.deviceId,
            request = DeviceRevokeRequest(
                totpCode = revokeCode
            )
        )

        assertEquals(enrollment.deviceId, revokeResult.deviceId)
        assertEquals(ru.mephi.abondarenko.auth.factor.qr.domain.DeviceStatus.REVOKED, revokeResult.deviceStatus)
    }

    private fun activeEnrollment(externalUserId: String, displayName: String, deviceLabel: String) =
        enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = externalUserId,
                displayName = displayName,
                deviceLabel = deviceLabel
            )
        ).also { enrollment ->
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
        }
}
