package ru.mephi.abondarenko.auth.factor.qr.api.dto

import ru.mephi.abondarenko.auth.factor.qr.domain.AuditEventType
import ru.mephi.abondarenko.auth.factor.qr.domain.AuditOutcome
import java.time.Instant
import java.util.UUID

data class AuditEventResponse(
    val id: UUID,
    val eventType: AuditEventType,
    val outcome: AuditOutcome,
    val externalUserId: String?,
    val deviceId: UUID?,
    val sessionId: UUID?,
    val details: String?,
    val occurredAt: Instant
)
