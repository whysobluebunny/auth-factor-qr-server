package ru.mephi.abondarenko.auth.factor.qr.service

import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import ru.mephi.abondarenko.auth.factor.qr.api.dto.*
import ru.mephi.abondarenko.auth.factor.qr.api.error.BadRequestException
import ru.mephi.abondarenko.auth.factor.qr.api.error.ConflictException
import ru.mephi.abondarenko.auth.factor.qr.api.error.NotFoundException
import ru.mephi.abondarenko.auth.factor.qr.api.error.TooManyRequestsException
import ru.mephi.abondarenko.auth.factor.qr.config.AuthFactorProperties
import ru.mephi.abondarenko.auth.factor.qr.domain.AuditEventType
import ru.mephi.abondarenko.auth.factor.qr.domain.AuditOutcome
import ru.mephi.abondarenko.auth.factor.qr.domain.DeviceStatus
import ru.mephi.abondarenko.auth.factor.qr.domain.SessionStatus
import ru.mephi.abondarenko.auth.factor.qr.entity.AuthSession
import ru.mephi.abondarenko.auth.factor.qr.repository.AuthSessionRepository
import ru.mephi.abondarenko.auth.factor.qr.repository.RegisteredDeviceRepository
import ru.mephi.abondarenko.auth.factor.qr.service.crypto.RandomTokenService
import ru.mephi.abondarenko.auth.factor.qr.service.crypto.SecretCryptoService
import ru.mephi.abondarenko.auth.factor.qr.service.totp.TotpService
import tools.jackson.databind.json.JsonMapper
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant

@Service
class AuthSessionService(
    private val auditLogService: AuditLogService,
    private val rateLimitService: RateLimitService,
    private val userService: UserService,
    private val registeredDeviceRepository: RegisteredDeviceRepository,
    private val authSessionRepository: AuthSessionRepository,
    private val randomTokenService: RandomTokenService,
    private val secretCryptoService: SecretCryptoService,
    private val totpService: TotpService,
    private val objectMapper: JsonMapper,
    private val properties: AuthFactorProperties,
    private val clock: Clock
) {

    @Transactional
    fun createChallenge(request: CreateChallengeRequest): CreateChallengeResponse {
        val user = userService.getByExternalUserId(request.externalUserId)
        val device = registeredDeviceRepository.findByIdAndUserExternalUserId(request.deviceId, request.externalUserId)
            ?: throw NotFoundException("Device ${request.deviceId} not found for user ${request.externalUserId}")

        enforceChallengeRateLimit(user.externalUserId, device.id)

        if (device.status != DeviceStatus.ACTIVE) {
            throw ConflictException("Device ${device.id} is not active")
        }

        val now = Instant.now(clock)
        val session = authSessionRepository.save(
            AuthSession(
                user = user,
                device = device,
                challenge = randomTokenService.randomUrlSafeToken(),
                status = SessionStatus.PENDING,
                firstFactorRef = request.firstFactorRef,
                createdAt = now,
                expiresAt = now.plus(properties.challengeTtl),
                maxAttempts = properties.maxVerifyAttempts
            )
        )

        val qrPayload = ChallengeQrPayload(
            sessionId = session.id,
            challenge = session.challenge,
            serviceId = properties.serviceId,
            timestamp = session.createdAt.epochSecond
        )

        auditLogService.logEvent(
            eventType = AuditEventType.AUTH_CHALLENGE_CREATED,
            outcome = AuditOutcome.SUCCESS,
            externalUserId = user.externalUserId,
            deviceId = device.id,
            sessionId = session.id,
            details = "Authentication challenge created"
        )

        return CreateChallengeResponse(
            sessionId = session.id,
            status = session.status,
            expiresAt = session.expiresAt,
            qrPayload = qrPayload,
            qrPayloadRaw = objectMapper.writeValueAsString(qrPayload)
        )
    }

    @Transactional
    fun verifyResponse(request: ResponseQrPayload): VerifyQrResponseResult {
        if (request.type != "response") {
            throw BadRequestException("QR payload type must be 'response'")
        }

        val now = Instant.now(clock)
        val session = authSessionRepository.findById(request.sessionId)
            .orElseThrow { NotFoundException("Auth session ${request.sessionId} not found") }

        if (session.status == SessionStatus.APPROVED) {
            throw ConflictException("Auth session ${request.sessionId} already approved")
        }

        if (session.status == SessionStatus.EXPIRED || session.status == SessionStatus.BLOCKED) {
            return session.toVerifyResult(approved = false)
        }

        if (now.isAfter(session.expiresAt)) {
            session.status = SessionStatus.EXPIRED
            auditLogService.logEvent(
                eventType = AuditEventType.AUTH_SESSION_EXPIRED,
                outcome = AuditOutcome.FAILURE,
                externalUserId = session.user.externalUserId,
                deviceId = session.device.id,
                sessionId = session.id,
                details = "Authentication session expired before verification"
            )
            return session.toVerifyResult(approved = false)
        }

        if (session.attemptCount >= session.maxAttempts) {
            session.status = SessionStatus.BLOCKED
            auditLogService.logEvent(
                eventType = AuditEventType.AUTH_SESSION_BLOCKED,
                outcome = AuditOutcome.FAILURE,
                externalUserId = session.user.externalUserId,
                deviceId = session.device.id,
                sessionId = session.id,
                details = "Authentication session already blocked"
            )
            return session.toVerifyResult(approved = false)
        }

        val device = session.device
        enforceVerifyRateLimit(session.user.externalUserId, device.id, session.id)

        val timestampIsFresh = kotlin.math.abs(now.epochSecond - request.timestamp) <= properties.responseMaxAge.seconds
        val challengeMatches = session.challenge == request.challenge
        val deviceMatches = device.id == request.deviceId
        val deviceActive = device.status == DeviceStatus.ACTIVE

        if (!timestampIsFresh || !challengeMatches || !deviceMatches || !deviceActive) {
            return rejectAttempt(session, "QR response validation failed before TOTP verification")
        }

        val secret = secretCryptoService.decrypt(device.secretCiphertext, device.secretNonce)
        val requestTime = Instant.ofEpochSecond(request.timestamp)

        val totpValid = totpService.verify(
            secretBase32 = secret,
            code = request.totp,
            timestamp = requestTime,
            digits = device.digits,
            periodSeconds = device.periodSeconds,
            algorithm = device.algorithm,
            allowedClockSkewSteps = properties.allowedClockSkewSteps
        )

        if (!totpValid) {
            return rejectAttempt(session, "Invalid TOTP in QR response")
        }

        session.status = SessionStatus.APPROVED
        session.verifiedAt = now
        session.acceptedResponseHash = sha256(
            "${request.sessionId}|${request.challenge}|${request.totp}|${request.timestamp}|${request.deviceId}"
        )
        device.lastUsedAt = now

        auditLogService.logEvent(
            eventType = AuditEventType.AUTH_RESPONSE_APPROVED,
            outcome = AuditOutcome.SUCCESS,
            externalUserId = session.user.externalUserId,
            deviceId = device.id,
            sessionId = session.id,
            details = "Authentication response approved"
        )

        return session.toVerifyResult(approved = true)
    }

    @Transactional(readOnly = true)
    fun getSessionInfo(sessionId: java.util.UUID): SessionInfoResponse {
        val session = authSessionRepository.findById(sessionId)
            .orElseThrow { NotFoundException("Auth session $sessionId not found") }

        return SessionInfoResponse(
            sessionId = session.id,
            userId = session.user.id,
            deviceId = session.device.id,
            status = session.status,
            createdAt = session.createdAt,
            expiresAt = session.expiresAt,
            verifiedAt = session.verifiedAt,
            attemptCount = session.attemptCount,
            maxAttempts = session.maxAttempts
        )
    }

    @Transactional(readOnly = true)
    fun getChallengePayloadRaw(sessionId: java.util.UUID): String {
        val session = authSessionRepository.findById(sessionId)
            .orElseThrow { NotFoundException("Auth session $sessionId not found") }

        val qrPayload = ChallengeQrPayload(
            sessionId = session.id,
            challenge = session.challenge,
            serviceId = properties.serviceId,
            timestamp = session.createdAt.epochSecond
        )

        return objectMapper.writeValueAsString(qrPayload)
    }

    private fun enforceChallengeRateLimit(externalUserId: String, deviceId: java.util.UUID) {
        val allowed = rateLimitService.tryAcquire(
            key = "challenge:$externalUserId",
            limit = properties.challengeRateLimitRequests,
            window = properties.challengeRateLimitWindow
        )

        if (!allowed) {
            auditLogService.logEvent(
                eventType = AuditEventType.AUTH_CHALLENGE_RATE_LIMITED,
                outcome = AuditOutcome.FAILURE,
                externalUserId = externalUserId,
                deviceId = deviceId,
                details = "Challenge rate limit exceeded"
            )
            throw TooManyRequestsException("Challenge rate limit exceeded for user $externalUserId")
        }
    }

    private fun enforceVerifyRateLimit(externalUserId: String, deviceId: java.util.UUID, sessionId: java.util.UUID) {
        val allowed = rateLimitService.tryAcquire(
            key = "verify:$externalUserId:$deviceId",
            limit = properties.verifyRateLimitRequests,
            window = properties.verifyRateLimitWindow
        )

        if (!allowed) {
            auditLogService.logEvent(
                eventType = AuditEventType.AUTH_VERIFY_RATE_LIMITED,
                outcome = AuditOutcome.FAILURE,
                externalUserId = externalUserId,
                deviceId = deviceId,
                sessionId = sessionId,
                details = "Verify rate limit exceeded"
            )
            throw TooManyRequestsException("Verify rate limit exceeded for user $externalUserId")
        }
    }

    private fun rejectAttempt(session: AuthSession, reason: String): VerifyQrResponseResult {
        session.attemptCount += 1
        val blocked = session.attemptCount >= session.maxAttempts
        if (blocked) {
            session.status = SessionStatus.BLOCKED
        }

        auditLogService.logEvent(
            eventType = if (blocked) AuditEventType.AUTH_SESSION_BLOCKED else AuditEventType.AUTH_RESPONSE_REJECTED,
            outcome = AuditOutcome.FAILURE,
            externalUserId = session.user.externalUserId,
            deviceId = session.device.id,
            sessionId = session.id,
            details = reason
        )

        return session.toVerifyResult(approved = false)
    }

    private fun AuthSession.toVerifyResult(approved: Boolean): VerifyQrResponseResult {
        return VerifyQrResponseResult(
            sessionId = id,
            status = status,
            approved = approved,
            attemptCount = attemptCount,
            maxAttempts = maxAttempts,
            verifiedAt = verifiedAt
        )
    }

    private fun sha256(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(StandardCharsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }
}
