package ru.mephi.abondarenko.auth.factor.qr.api

import jakarta.validation.Valid
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentResponse
import ru.mephi.abondarenko.auth.factor.qr.api.dto.StartEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.StartEnrollmentResponse
import ru.mephi.abondarenko.auth.factor.qr.service.EnrollmentService

@RestController
@RequestMapping("/api/v1/enrollments")
class EnrollmentController(
    private val enrollmentService: EnrollmentService
) {

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
}