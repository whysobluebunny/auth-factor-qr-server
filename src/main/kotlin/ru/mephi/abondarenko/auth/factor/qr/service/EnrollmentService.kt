package ru.mephi.abondarenko.auth.factor.qr.service

import tools.jackson.databind.json.JsonMapper
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentResponse
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceEnrollmentConfirmRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceInfoResponse
import ru.mephi.abondarenko.auth.factor.qr.api.dto.EnrollmentQrPayload
import ru.mephi.abondarenko.auth.factor.qr.api.dto.RevokeDeviceRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.RevokeDeviceResponse
import ru.mephi.abondarenko.auth.factor.qr.api.dto.StartEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.StartEnrollmentResponse
import ru.mephi.abondarenko.auth.factor.qr.api.error.BadRequestException
import ru.mephi.abondarenko.auth.factor.qr.api.error.ConflictException
import ru.mephi.abondarenko.auth.factor.qr.api.error.NotFoundException
import ru.mephi.abondarenko.auth.factor.qr.config.AuthFactorProperties
import ru.mephi.abondarenko.auth.factor.qr.domain.AuditEventType
import ru.mephi.abondarenko.auth.factor.qr.domain.AuditOutcome
import ru.mephi.abondarenko.auth.factor.qr.domain.DeviceStatus
import ru.mephi.abondarenko.auth.factor.qr.domain.TotpAlgorithm
import ru.mephi.abondarenko.auth.factor.qr.entity.RegisteredDevice
import ru.mephi.abondarenko.auth.factor.qr.repository.RegisteredDeviceRepository
import ru.mephi.abondarenko.auth.factor.qr.service.crypto.RandomTokenService
import ru.mephi.abondarenko.auth.factor.qr.service.crypto.SecretCryptoService
import ru.mephi.abondarenko.auth.factor.qr.service.totp.TotpService
import java.time.Clock
import java.time.Instant
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID

@Service
class EnrollmentService(
    private val auditLogService: AuditLogService,
    private val deviceManagementPolicyService: DeviceManagementPolicyService,
    private val userService: UserService,
    private val registeredDeviceRepository: RegisteredDeviceRepository,
    private val secretCryptoService: SecretCryptoService,
    private val randomTokenService: RandomTokenService,
    private val totpService: TotpService,
    private val objectMapper: JsonMapper,
    private val properties: AuthFactorProperties,
    private val clock: Clock
) {

    @Transactional(readOnly = true)
    fun listDevices(externalUserId: String): List<DeviceInfoResponse> {
        userService.getByExternalUserId(externalUserId)

        return registeredDeviceRepository.findAllByUserExternalUserIdOrderByCreatedAtDesc(externalUserId)
            .map { device ->
                DeviceInfoResponse(
                    deviceId = device.id,
                    deviceLabel = device.deviceLabel,
                    serviceId = device.serviceId,
                    deviceStatus = device.status,
                    createdAt = device.createdAt,
                    confirmedAt = device.confirmedAt,
                    revokedAt = device.revokedAt,
                    lastUsedAt = device.lastUsedAt
                )
            }
    }

    @Transactional
    fun startEnrollment(request: StartEnrollmentRequest): StartEnrollmentResponse {
        val user = userService.getOrCreate(request.externalUserId, request.displayName)
        val existingDevices = registeredDeviceRepository.findAllByUserExternalUserIdOrderByCreatedAtDesc(user.externalUserId)
        deviceManagementPolicyService.enforceEnrollmentPolicy(user, request.deviceLabel, existingDevices)

        val secret = randomTokenService.randomBase32Secret()
        val encryptedSecret = secretCryptoService.encrypt(secret)
        val enrollmentToken = randomTokenService.randomUrlSafeToken()
        val now = Instant.now(clock)

        val device = registeredDeviceRepository.save(
            RegisteredDevice(
                user = user,
                deviceLabel = request.deviceLabel,
                serviceId = properties.serviceId,
                status = DeviceStatus.PENDING,
                secretCiphertext = encryptedSecret.ciphertext,
                secretNonce = encryptedSecret.nonce,
                algorithm = TotpAlgorithm.SHA1,
                digits = properties.otpDigits,
                periodSeconds = properties.otpPeriod.seconds.toInt(),
                enrollmentTokenHash = sha256(enrollmentToken),
                enrollmentTokenExpiresAt = now.plus(properties.enrollmentTokenTtl)
            )
        )

        val qrPayload = EnrollmentQrPayload(
            serviceId = properties.serviceId,
            userId = user.externalUserId,
            deviceId = device.id.toString(),
            secret = secret,
            enrollmentToken = enrollmentToken,
            period = device.periodSeconds,
            digits = device.digits,
            algorithm = device.algorithm.name
        )

        auditLogService.logEvent(
            eventType = AuditEventType.ENROLLMENT_STARTED,
            outcome = AuditOutcome.SUCCESS,
            externalUserId = user.externalUserId,
            deviceId = device.id,
            details = "Enrollment started for deviceLabel=${device.deviceLabel}"
        )

        return StartEnrollmentResponse(
            userId = user.id,
            deviceId = device.id,
            deviceStatus = device.status,
            qrPayload = qrPayload,
            qrPayloadRaw = objectMapper.writeValueAsString(qrPayload)
        )
    }

    @Transactional
    fun confirmEnrollment(request: ConfirmEnrollmentRequest): ConfirmEnrollmentResponse {
        val device = registeredDeviceRepository.findById(request.deviceId)
            .orElseThrow { NotFoundException("Device ${request.deviceId} not found") }
        return confirmEnrollmentInternal(device, request.totpCode, requireDeviceToken = false, suppliedToken = null)
    }

    @Transactional
    fun confirmEnrollmentFromDevice(request: DeviceEnrollmentConfirmRequest): ConfirmEnrollmentResponse {
        val device = registeredDeviceRepository.findByIdAndEnrollmentTokenHash(request.deviceId, sha256(request.enrollmentToken))
            ?: run {
                auditLogService.logEvent(
                    eventType = AuditEventType.ENROLLMENT_DEVICE_TOKEN_REJECTED,
                    outcome = AuditOutcome.FAILURE,
                    deviceId = request.deviceId,
                    details = "Enrollment confirmation rejected due to invalid device token"
                )
                throw NotFoundException("Enrollment confirmation context not found")
            }

        return confirmEnrollmentInternal(
            device = device,
            totpCode = request.totpCode,
            requireDeviceToken = true,
            suppliedToken = request.enrollmentToken
        )
    }

    private fun confirmEnrollmentInternal(
        device: RegisteredDevice,
        totpCode: String,
        requireDeviceToken: Boolean,
        suppliedToken: String?
    ): ConfirmEnrollmentResponse {
        val now = Instant.now(clock)

        if (requireDeviceToken) {
            val tokenHash = device.enrollmentTokenHash
            val tokenExpiresAt = device.enrollmentTokenExpiresAt

            if (tokenHash == null || tokenExpiresAt == null) {
                auditLogService.logEvent(
                    eventType = AuditEventType.ENROLLMENT_DEVICE_TOKEN_REJECTED,
                    outcome = AuditOutcome.FAILURE,
                    externalUserId = device.user.externalUserId,
                    deviceId = device.id,
                    details = "Enrollment confirmation token context is missing"
                )
                throw ConflictException("Enrollment confirmation token is not available")
            }
            if (now.isAfter(tokenExpiresAt)) {
                auditLogService.logEvent(
                    eventType = AuditEventType.ENROLLMENT_DEVICE_TOKEN_REJECTED,
                    outcome = AuditOutcome.FAILURE,
                    externalUserId = device.user.externalUserId,
                    deviceId = device.id,
                    details = "Enrollment confirmation token expired"
                )
                throw ConflictException("Enrollment confirmation token expired")
            }
            if (suppliedToken == null || !constantTimeEquals(tokenHash, sha256(suppliedToken))) {
                auditLogService.logEvent(
                    eventType = AuditEventType.ENROLLMENT_DEVICE_TOKEN_REJECTED,
                    outcome = AuditOutcome.FAILURE,
                    externalUserId = device.user.externalUserId,
                    deviceId = device.id,
                    details = "Enrollment confirmation token mismatch"
                )
                throw NotFoundException("Enrollment confirmation context not found")
            }
        }

        when (device.status) {
            DeviceStatus.ACTIVE -> {
                return ConfirmEnrollmentResponse(
                    deviceId = device.id,
                    deviceStatus = device.status,
                    confirmedAt = device.confirmedAt ?: Instant.now(clock)
                )
            }
            DeviceStatus.REVOKED -> throw ConflictException("Device ${device.id} is revoked")
            DeviceStatus.PENDING -> Unit
        }

        val secret = secretCryptoService.decrypt(device.secretCiphertext, device.secretNonce)

        val valid = totpService.verify(
            secretBase32 = secret,
            code = totpCode,
            timestamp = now,
            digits = device.digits,
            periodSeconds = device.periodSeconds,
            algorithm = device.algorithm,
            allowedClockSkewSteps = properties.allowedClockSkewSteps
        )

        if (!valid) {
            auditLogService.logEvent(
                eventType = AuditEventType.ENROLLMENT_CONFIRM_FAILED,
                outcome = AuditOutcome.FAILURE,
                externalUserId = device.user.externalUserId,
                deviceId = device.id,
                details = "Invalid TOTP code supplied during enrollment confirmation"
            )
            throw BadRequestException("Provided TOTP code is invalid")
        }

        device.status = DeviceStatus.ACTIVE
        device.confirmedAt = now
        device.enrollmentTokenHash = null
        device.enrollmentTokenExpiresAt = null

        auditLogService.logEvent(
            eventType = AuditEventType.ENROLLMENT_CONFIRMED,
            outcome = AuditOutcome.SUCCESS,
            externalUserId = device.user.externalUserId,
            deviceId = device.id,
            details = "Device enrollment confirmed"
        )

        return ConfirmEnrollmentResponse(
            deviceId = device.id,
            deviceStatus = device.status,
            confirmedAt = device.confirmedAt!!
        )
    }

    private fun sha256(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(StandardCharsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun constantTimeEquals(expectedHash: String, actualHash: String): Boolean {
        return MessageDigest.isEqual(
            expectedHash.toByteArray(StandardCharsets.UTF_8),
            actualHash.toByteArray(StandardCharsets.UTF_8)
        )
    }

    @Transactional
    fun revokeDevice(deviceId: UUID, request: RevokeDeviceRequest): RevokeDeviceResponse {
        val device = registeredDeviceRepository.findByIdAndUserExternalUserId(deviceId, request.externalUserId)
            ?: throw NotFoundException("Device $deviceId not found for user ${request.externalUserId}")

        if (device.status == DeviceStatus.REVOKED) {
            return RevokeDeviceResponse(
                deviceId = device.id,
                deviceStatus = device.status,
                revokedAt = device.revokedAt ?: Instant.now(clock)
            )
        }

        device.status = DeviceStatus.REVOKED
        device.revokedAt = Instant.now(clock)

        auditLogService.logEvent(
            eventType = AuditEventType.DEVICE_REVOKED,
            outcome = AuditOutcome.SUCCESS,
            externalUserId = request.externalUserId,
            deviceId = device.id,
            details = "Device revoked"
        )

        return RevokeDeviceResponse(
            deviceId = device.id,
            deviceStatus = device.status,
            revokedAt = device.revokedAt!!
        )
    }
}
