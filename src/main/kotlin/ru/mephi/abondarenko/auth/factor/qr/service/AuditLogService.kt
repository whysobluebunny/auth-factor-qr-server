package ru.mephi.abondarenko.auth.factor.qr.service

import org.springframework.data.domain.PageRequest
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import ru.mephi.abondarenko.auth.factor.qr.api.dto.AuditEventResponse
import ru.mephi.abondarenko.auth.factor.qr.domain.AuditEventType
import ru.mephi.abondarenko.auth.factor.qr.domain.AuditOutcome
import ru.mephi.abondarenko.auth.factor.qr.entity.AuditEvent
import ru.mephi.abondarenko.auth.factor.qr.repository.AuditEventRepository
import java.time.Clock
import java.time.Instant
import java.util.UUID

@Service
class AuditLogService(
    private val auditEventRepository: AuditEventRepository,
    private val clock: Clock
) {

    @Transactional
    fun logEvent(
        eventType: AuditEventType,
        outcome: AuditOutcome,
        externalUserId: String? = null,
        deviceId: UUID? = null,
        sessionId: UUID? = null,
        details: String? = null
    ) {
        auditEventRepository.save(
            AuditEvent(
                eventType = eventType,
                outcome = outcome,
                externalUserId = externalUserId,
                deviceId = deviceId,
                sessionId = sessionId,
                details = details,
                occurredAt = Instant.now(clock)
            )
        )
    }

    @Transactional(readOnly = true)
    fun listEvents(externalUserId: String?, limit: Int): List<AuditEventResponse> {
        val pageRequest = PageRequest.of(0, limit.coerceIn(1, 100))
        val events = if (externalUserId.isNullOrBlank()) {
            auditEventRepository.findAllByOrderByOccurredAtDesc(pageRequest)
        } else {
            auditEventRepository.findAllByExternalUserIdOrderByOccurredAtDesc(externalUserId, pageRequest)
        }

        return events.map { event ->
            AuditEventResponse(
                id = event.id,
                eventType = event.eventType,
                outcome = event.outcome,
                externalUserId = event.externalUserId,
                deviceId = event.deviceId,
                sessionId = event.sessionId,
                details = event.details,
                occurredAt = event.occurredAt
            )
        }
    }
}
