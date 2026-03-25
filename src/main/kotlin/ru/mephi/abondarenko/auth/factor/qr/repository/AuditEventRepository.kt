package ru.mephi.abondarenko.auth.factor.qr.repository

import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.repository.JpaRepository
import ru.mephi.abondarenko.auth.factor.qr.entity.AuditEvent
import java.util.UUID

interface AuditEventRepository : JpaRepository<AuditEvent, UUID> {
    fun findAllByExternalUserIdOrderByOccurredAtDesc(externalUserId: String, pageable: Pageable): List<AuditEvent>
    fun findAllByOrderByOccurredAtDesc(pageable: Pageable): List<AuditEvent>
}
