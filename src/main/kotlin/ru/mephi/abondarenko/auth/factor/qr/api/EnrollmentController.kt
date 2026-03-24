package ru.mephi.abondarenko.auth.factor.qr.api

import jakarta.validation.Valid
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentResponse
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceInfoResponse
import ru.mephi.abondarenko.auth.factor.qr.api.dto.RevokeDeviceRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.RevokeDeviceResponse
import ru.mephi.abondarenko.auth.factor.qr.api.dto.StartEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.StartEnrollmentResponse
import ru.mephi.abondarenko.auth.factor.qr.service.EnrollmentService
import java.util.UUID

@RestController
@RequestMapping("/api/v1/enrollments")
class EnrollmentController(
    private val enrollmentService: EnrollmentService
) {

    @GetMapping("/devices")
    fun listDevices(
        @RequestParam externalUserId: String
    ): List<DeviceInfoResponse> {
        return enrollmentService.listDevices(externalUserId)
    }

    @PostMapping("/start")
    fun startEnrollment(
        @Valid @RequestBody request: StartEnrollmentRequest
    ): StartEnrollmentResponse {
        return enrollmentService.startEnrollment(request)
    }

    @PostMapping("/confirm")
    fun confirmEnrollment(
        @Valid @RequestBody request: ConfirmEnrollmentRequest
    ): ConfirmEnrollmentResponse {
        return enrollmentService.confirmEnrollment(request)
    }

    @PostMapping("/devices/{deviceId}/revoke")
    fun revokeDevice(
        @PathVariable deviceId: UUID,
        @Valid @RequestBody request: RevokeDeviceRequest
    ): RevokeDeviceResponse {
        return enrollmentService.revokeDevice(deviceId, request)
    }
}
