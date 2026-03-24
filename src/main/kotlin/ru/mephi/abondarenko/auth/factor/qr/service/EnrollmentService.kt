package ru.mephi.abondarenko.auth.factor.qr.service

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentResponse
import ru.mephi.abondarenko.auth.factor.qr.api.dto.EnrollmentQrPayload
import ru.mephi.abondarenko.auth.factor.qr.api.dto.StartEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.StartEnrollmentResponse
import ru.mephi.abondarenko.auth.factor.qr.api.error.BadRequestException
import ru.mephi.abondarenko.auth.factor.qr.api.error.ConflictException
import ru.mephi.abondarenko.auth.factor.qr.api.error.NotFoundException
import ru.mephi.abondarenko.auth.factor.qr.config.AuthFactorProperties
import ru.mephi.abondarenko.auth.factor.qr.domain.DeviceStatus
import ru.mephi.abondarenko.auth.factor.qr.domain.TotpAlgorithm
import ru.mephi.abondarenko.auth.factor.qr.entity.RegisteredDevice
import ru.mephi.abondarenko.auth.factor.qr.repository.RegisteredDeviceRepository
import ru.mephi.abondarenko.auth.factor.qr.service.crypto.RandomTokenService
import ru.mephi.abondarenko.auth.factor.qr.service.crypto.SecretCryptoService
import ru.mephi.abondarenko.auth.factor.qr.service.totp.TotpService
import java.time.Clock
import java.time.Instant

@Service
class EnrollmentService(
    private val userService: UserService,
    private val registeredDeviceRepository: RegisteredDeviceRepository,
    private val secretCryptoService: SecretCryptoService,
    private val randomTokenService: RandomTokenService,
    private val totpService: TotpService,
    private val objectMapper: ObjectMapper,
    private val properties: AuthFactorProperties,
    private val clock: Clock
) {

    @Transactional
    fun startEnrollment(request: StartEnrollmentRequest): StartEnrollmentResponse {
        val user = userService.getOrCreate(request.externalUserId, request.displayName)
        val secret = randomTokenService.randomBase32Secret()
        val encryptedSecret = secretCryptoService.encrypt(secret)

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
                periodSeconds = properties.otpPeriod.seconds.toInt()
            )
        )

        val qrPayload = EnrollmentQrPayload(
            serviceId = properties.serviceId,
            userId = user.externalUserId,
            deviceId = device.id.toString(),
            secret = secret,
            period = device.periodSeconds,
            digits = device.digits,
            algorithm = device.algorithm.name
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
        val now = Instant.now(clock)

        val valid = totpService.verify(
            secretBase32 = secret,
            code = request.totpCode,
            timestamp = now,
            digits = device.digits,
            periodSeconds = device.periodSeconds,
            algorithm = device.algorithm,
            allowedClockSkewSteps = properties.allowedClockSkewSteps
        )

        if (!valid) {
            throw BadRequestException("Provided TOTP code is invalid")
        }

        device.status = DeviceStatus.ACTIVE
        device.confirmedAt = now

        return ConfirmEnrollmentResponse(
            deviceId = device.id,
            deviceStatus = device.status,
            confirmedAt = device.confirmedAt!!
        )
    }
}