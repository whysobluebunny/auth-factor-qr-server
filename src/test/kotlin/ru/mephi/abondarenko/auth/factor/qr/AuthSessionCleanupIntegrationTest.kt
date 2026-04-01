package ru.mephi.abondarenko.auth.factor.qr

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.CreateChallengeRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ResponseQrPayload
import ru.mephi.abondarenko.auth.factor.qr.api.dto.StartEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.domain.TotpAlgorithm
import ru.mephi.abondarenko.auth.factor.qr.repository.AuthSessionRepository
import ru.mephi.abondarenko.auth.factor.qr.service.AuthSessionCleanupService
import ru.mephi.abondarenko.auth.factor.qr.service.AuthSessionService
import ru.mephi.abondarenko.auth.factor.qr.service.EnrollmentService
import ru.mephi.abondarenko.auth.factor.qr.service.totp.TotpService
import java.time.Clock
import java.time.Instant

class AuthSessionCleanupIntegrationTest : AbstractIntegrationTest() {

    @Autowired
    lateinit var enrollmentService: EnrollmentService

    @Autowired
    lateinit var authSessionService: AuthSessionService

    @Autowired
    lateinit var authSessionCleanupService: AuthSessionCleanupService

    @Autowired
    lateinit var authSessionRepository: AuthSessionRepository

    @Autowired
    lateinit var totpService: TotpService

    @Autowired
    lateinit var clock: Clock

    @Test
    fun `should delete obsolete approved and expired sessions while keeping recent ones`() {
        val enrollment = enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "cleanup-user-001",
                displayName = "Cleanup User",
                deviceLabel = "Cleanup Device"
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

        val approvedSession = authSessionService.createChallenge(
            CreateChallengeRequest(
                externalUserId = "cleanup-user-001",
                firstFactorRef = "approved-session"
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

        authSessionService.verifyResponse(
            ResponseQrPayload(
                type = "response",
                sessionId = approvedSession.sessionId,
                challenge = approvedSession.qrPayload.challenge,
                totp = responseCode,
                timestamp = responseTimestamp.epochSecond,
                deviceId = enrollment.deviceId
            )
        )

        val obsoletePendingSession = authSessionService.createChallenge(
            CreateChallengeRequest(
                externalUserId = "cleanup-user-001",
                firstFactorRef = "obsolete-pending-session"
            )
        )

        val recentSession = authSessionService.createChallenge(
            CreateChallengeRequest(
                externalUserId = "cleanup-user-001",
                firstFactorRef = "recent-session"
            )
        )

        val oldInstant = Instant.now(clock).minusSeconds(3600)
        val approvedEntity = authSessionRepository.findById(approvedSession.sessionId).orElseThrow().apply {
            verifiedAt = oldInstant
            expiresAt = oldInstant
        }
        val obsoletePendingEntity = authSessionRepository.findById(obsoletePendingSession.sessionId).orElseThrow().apply {
            expiresAt = oldInstant
        }
        authSessionRepository.save(approvedEntity)
        authSessionRepository.save(obsoletePendingEntity)

        val deleted = authSessionCleanupService.cleanupObsoleteSessions(Instant.now(clock))

        assertEquals(2, deleted)
        assertFalse(authSessionRepository.findById(approvedSession.sessionId).isPresent)
        assertFalse(authSessionRepository.findById(obsoletePendingSession.sessionId).isPresent)
        assertTrue(authSessionRepository.findById(recentSession.sessionId).isPresent)
    }
}
