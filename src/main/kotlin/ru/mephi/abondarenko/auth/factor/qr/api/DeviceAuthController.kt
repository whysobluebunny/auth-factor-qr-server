package ru.mephi.abondarenko.auth.factor.qr.api

import jakarta.validation.Valid
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentResponse
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceAuthResponseRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceEnrollmentConfirmRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.VerifyQrResponseResult
import ru.mephi.abondarenko.auth.factor.qr.service.AuthSessionService
import ru.mephi.abondarenko.auth.factor.qr.service.EnrollmentService

@RestController
@RequestMapping("/api/v1/device")
class DeviceAuthController(
    private val enrollmentService: EnrollmentService,
    private val authSessionService: AuthSessionService
) {

    @PostMapping("/enrollments/confirm")
    fun confirmEnrollment(
        @Valid @RequestBody request: DeviceEnrollmentConfirmRequest
    ): ConfirmEnrollmentResponse {
        return enrollmentService.confirmEnrollmentFromDevice(request)
    }

    @PostMapping("/auth/respond")
    fun respondToChallenge(
        @Valid @RequestBody request: DeviceAuthResponseRequest
    ): VerifyQrResponseResult {
        return authSessionService.verifyResponseFromDevice(request)
    }
}
