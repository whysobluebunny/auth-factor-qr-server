package ru.mephi.abondarenko.auth.factor.qr.entity

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Id
import jakarta.persistence.Table
import ru.mephi.abondarenko.auth.factor.qr.domain.AuditEventType
import ru.mephi.abondarenko.auth.factor.qr.domain.AuditOutcome
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "audit_events")
class AuditEvent(

    @Id
    var id: UUID = UUID.randomUUID(),

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 64)
    var eventType: AuditEventType,

    @Enumerated(EnumType.STRING)
    @Column(name = "outcome", nullable = false, length = 16)
    var outcome: AuditOutcome,

    @Column(name = "external_user_id", length = 128)
    var externalUserId: String? = null,

    @Column(name = "device_id")
    var deviceId: UUID? = null,

    @Column(name = "session_id")
    var sessionId: UUID? = null,

    @Column(name = "details", columnDefinition = "text")
    var details: String? = null,

    @Column(name = "occurred_at", nullable = false)
    var occurredAt: Instant = Instant.now()
)
