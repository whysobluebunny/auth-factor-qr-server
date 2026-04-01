package ru.mephi.abondarenko.auth.factor.qr.api

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import ru.mephi.abondarenko.auth.factor.qr.api.dto.AuditEventResponse
import ru.mephi.abondarenko.auth.factor.qr.service.AuditLogService

@RestController
@RequestMapping("/api/v1/audit-events")
class AuditController(
    private val auditLogService: AuditLogService
) {

    @GetMapping
    fun listAuditEvents(
        @RequestParam(required = false) externalUserId: String?,
        @RequestParam(defaultValue = "50") limit: Int
    ): List<AuditEventResponse> {
        return auditLogService.listEvents(externalUserId, limit)
    }
}
