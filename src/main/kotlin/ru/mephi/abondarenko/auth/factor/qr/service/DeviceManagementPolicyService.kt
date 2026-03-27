package ru.mephi.abondarenko.auth.factor.qr.service

import org.springframework.stereotype.Service
import ru.mephi.abondarenko.auth.factor.qr.api.error.ConflictException
import ru.mephi.abondarenko.auth.factor.qr.config.AuthFactorProperties
import ru.mephi.abondarenko.auth.factor.qr.domain.AuditEventType
import ru.mephi.abondarenko.auth.factor.qr.domain.AuditOutcome
import ru.mephi.abondarenko.auth.factor.qr.domain.DeviceStatus
import ru.mephi.abondarenko.auth.factor.qr.entity.AppUser
import ru.mephi.abondarenko.auth.factor.qr.entity.RegisteredDevice

@Service
class DeviceManagementPolicyService(
    private val auditLogService: AuditLogService,
    private val properties: AuthFactorProperties
) {

    fun enforceEnrollmentPolicy(user: AppUser, deviceLabel: String?, existingDevices: List<RegisteredDevice>) {
        val activeDevices = existingDevices.count { it.status == DeviceStatus.ACTIVE }
        val pendingDevices = existingDevices.count { it.status == DeviceStatus.PENDING }

        if (activeDevices >= properties.maxActiveDevicesPerUser) {
            rejectPolicy(
                externalUserId = user.externalUserId,
                details = "Active device limit exceeded for deviceLabel=${deviceLabel ?: "<pending>"}"
            )
        }

        if (pendingDevices >= properties.maxPendingDevicesPerUser) {
            rejectPolicy(
                externalUserId = user.externalUserId,
                details = "Pending device limit exceeded for deviceLabel=${deviceLabel ?: "<pending>"}"
            )
        }

        if (!deviceLabel.isNullOrBlank()) {
            enforceDeviceLabelPolicy(user, deviceLabel, existingDevices)
        }
    }

    fun enforceDeviceLabelPolicy(
        user: AppUser,
        deviceLabel: String,
        existingDevices: List<RegisteredDevice>,
        excludeDeviceId: java.util.UUID? = null
    ) {
        if (!properties.allowDuplicateDeviceLabels) {
            val duplicateLabelExists = existingDevices.any {
                it.id != excludeDeviceId &&
                    it.status != DeviceStatus.REVOKED &&
                    it.deviceLabel.equals(deviceLabel, ignoreCase = true)
            }

            if (duplicateLabelExists) {
                rejectPolicy(
                    externalUserId = user.externalUserId,
                    details = "Duplicate deviceLabel rejected: $deviceLabel"
                )
            }
        }
    }

    private fun rejectPolicy(externalUserId: String, details: String): Nothing {
        auditLogService.logEvent(
            eventType = AuditEventType.DEVICE_POLICY_REJECTED,
            outcome = AuditOutcome.FAILURE,
            externalUserId = externalUserId,
            details = details
        )
        throw ConflictException(details)
    }
}
