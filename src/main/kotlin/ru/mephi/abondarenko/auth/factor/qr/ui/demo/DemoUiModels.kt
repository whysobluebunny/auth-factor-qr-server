package ru.mephi.abondarenko.auth.factor.qr.ui.demo

import jakarta.validation.constraints.NotBlank
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceInfoResponse

data class DemoLoginForm(
    @field:NotBlank
    val username: String = "",

    @field:NotBlank
    val password: String = ""
)

data class DemoHomeViewModel(
    val username: String,
    val secondFactorConfigured: Boolean,
    val enrollmentUrl: String?,
    val devices: List<DeviceInfoResponse>
)
