package ru.mephi.abondarenko.auth.factor.qr

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.CreateChallengeRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.RevokeDeviceRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.StartEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.error.ConflictException
import ru.mephi.abondarenko.auth.factor.qr.domain.DeviceStatus
import ru.mephi.abondarenko.auth.factor.qr.service.AuthSessionService
import ru.mephi.abondarenko.auth.factor.qr.service.EnrollmentService
import ru.mephi.abondarenko.auth.factor.qr.service.totp.TotpService
import java.time.Clock
import java.time.Instant

class EnrollmentFlowIntegrationTest : AbstractIntegrationTest() {

    @Autowired
    lateinit var enrollmentService: EnrollmentService

    @Autowired
    lateinit var totpService: TotpService

    @Autowired
    lateinit var authSessionService: AuthSessionService

    @Autowired
    lateinit var clock: Clock

    @Test
    fun `should start and confirm enrollment`() {
        val startResponse = enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "user-001",
                displayName = "Artyom Bondarenko",
                deviceLabel = "Pixel 8"
            )
        )

        assertNotNull(startResponse.userId)
        assertNotNull(startResponse.deviceId)
        assertEquals(DeviceStatus.PENDING, startResponse.deviceStatus)
        assertEquals("enroll", startResponse.qrPayload.type)
        assertEquals("user-001", startResponse.qrPayload.userId)
        assertTrue(startResponse.qrPayload.secret.isNotBlank())

        val code = totpService.generate(
            secretBase32 = startResponse.qrPayload.secret,
            timestamp = Instant.now(clock),
            digits = startResponse.qrPayload.digits,
            periodSeconds = startResponse.qrPayload.period,
            algorithm = ru.mephi.abondarenko.auth.factor.qr.domain.TotpAlgorithm.valueOf(
                startResponse.qrPayload.algorithm
            )
        )

        val confirmResponse = enrollmentService.confirmEnrollment(
            ConfirmEnrollmentRequest(
                deviceId = startResponse.deviceId,
                totpCode = code
            )
        )

        assertEquals(startResponse.deviceId, confirmResponse.deviceId)
        assertEquals(DeviceStatus.ACTIVE, confirmResponse.deviceStatus)
        assertNotNull(confirmResponse.confirmedAt)
    }

    @Test
    fun `should list and revoke user devices`() {
        val firstDevice = enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "user-004",
                displayName = "Device Owner",
                deviceLabel = "Pixel 8"
            )
        )
        val secondDevice = enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "user-004",
                displayName = "Device Owner",
                deviceLabel = "Tablet"
            )
        )

        val listedBeforeRevoke = enrollmentService.listDevices("user-004")

        assertEquals(2, listedBeforeRevoke.size)
        assertEquals(secondDevice.deviceId, listedBeforeRevoke[0].deviceId)
        assertEquals(firstDevice.deviceId, listedBeforeRevoke[1].deviceId)

        val revokeResponse = enrollmentService.revokeDevice(
            firstDevice.deviceId,
            RevokeDeviceRequest(externalUserId = "user-004")
        )

        assertEquals(DeviceStatus.REVOKED, revokeResponse.deviceStatus)
        assertNotNull(revokeResponse.revokedAt)

        val listedAfterRevoke = enrollmentService.listDevices("user-004")
        val revokedDevice = listedAfterRevoke.first { it.deviceId == firstDevice.deviceId }
        assertEquals(DeviceStatus.REVOKED, revokedDevice.deviceStatus)
        assertNotNull(revokedDevice.revokedAt)
    }

    @Test
    fun `should reject challenge creation for revoked device`() {
        val enrollment = enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "user-005",
                displayName = "Revoked Owner",
                deviceLabel = "Phone"
            )
        )

        val enrollmentCode = totpService.generate(
            secretBase32 = enrollment.qrPayload.secret,
            timestamp = Instant.now(clock),
            digits = enrollment.qrPayload.digits,
            periodSeconds = enrollment.qrPayload.period,
            algorithm = ru.mephi.abondarenko.auth.factor.qr.domain.TotpAlgorithm.valueOf(
                enrollment.qrPayload.algorithm
            )
        )

        enrollmentService.confirmEnrollment(
            ConfirmEnrollmentRequest(
                deviceId = enrollment.deviceId,
                totpCode = enrollmentCode
            )
        )

        enrollmentService.revokeDevice(
            enrollment.deviceId,
            RevokeDeviceRequest(externalUserId = "user-005")
        )

        assertThrows(ConflictException::class.java) {
            authSessionService.createChallenge(
                CreateChallengeRequest(
                    externalUserId = "user-005"
                )
            )
        }
    }

    @Test
    fun `should reject third pending enrollment for same user`() {
        enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "user-006",
                displayName = "Pending Policy User",
                deviceLabel = "Phone"
            )
        )
        enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "user-006",
                displayName = "Pending Policy User",
                deviceLabel = "Tablet"
            )
        )

        assertThrows(ConflictException::class.java) {
            enrollmentService.startEnrollment(
                StartEnrollmentRequest(
                    externalUserId = "user-006",
                    displayName = "Pending Policy User",
                    deviceLabel = "Laptop"
                )
            )
        }
    }

    @Test
    fun `should reject duplicate device label among non revoked devices`() {
        enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = "user-007",
                displayName = "Duplicate Label User",
                deviceLabel = "Pixel 8"
            )
        )

        assertThrows(ConflictException::class.java) {
            enrollmentService.startEnrollment(
                StartEnrollmentRequest(
                    externalUserId = "user-007",
                    displayName = "Duplicate Label User",
                    deviceLabel = "pixel 8"
                )
            )
        }
    }

    @Test
    fun `should reject enrollment when active device limit is reached`() {
        activateDevice("user-008", "Active Limit User", "Phone")
        activateDevice("user-008", "Active Limit User", "Tablet")

        assertThrows(ConflictException::class.java) {
            enrollmentService.startEnrollment(
                StartEnrollmentRequest(
                    externalUserId = "user-008",
                    displayName = "Active Limit User",
                    deviceLabel = "Laptop"
                )
            )
        }
    }

    private fun activateDevice(externalUserId: String, displayName: String, deviceLabel: String) {
        val enrollment = enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = externalUserId,
                displayName = displayName,
                deviceLabel = deviceLabel
            )
        )

        val enrollmentCode = totpService.generate(
            secretBase32 = enrollment.qrPayload.secret,
            timestamp = Instant.now(clock),
            digits = enrollment.qrPayload.digits,
            periodSeconds = enrollment.qrPayload.period,
            algorithm = ru.mephi.abondarenko.auth.factor.qr.domain.TotpAlgorithm.valueOf(
                enrollment.qrPayload.algorithm
            )
        )

        enrollmentService.confirmEnrollment(
            ConfirmEnrollmentRequest(
                deviceId = enrollment.deviceId,
                totpCode = enrollmentCode
            )
        )
    }
}
