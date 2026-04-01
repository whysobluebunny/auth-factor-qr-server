package ru.mephi.abondarenko.auth.factor.qr.api

import jakarta.validation.Valid
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentResponse
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceEnrollmentConfirmRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceRevokeRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.RevokeDeviceResponse
import ru.mephi.abondarenko.auth.factor.qr.service.EnrollmentService
import java.util.UUID

@RestController
@RequestMapping("/api/v1/device")
class DeviceAuthController(
    private val enrollmentService: EnrollmentService
) {

    @PostMapping("/enrollments/confirm")
    fun confirmEnrollment(
        @Valid @RequestBody request: DeviceEnrollmentConfirmRequest
    ): ConfirmEnrollmentResponse {
        return enrollmentService.confirmEnrollmentFromDevice(request)
    }

    @PostMapping("/devices/{deviceId}/revoke")
    fun revokeDevice(
        @PathVariable deviceId: UUID,
        @Valid @RequestBody request: DeviceRevokeRequest
    ): RevokeDeviceResponse {
        return enrollmentService.revokeDeviceFromDevice(deviceId, request)
    }
}
