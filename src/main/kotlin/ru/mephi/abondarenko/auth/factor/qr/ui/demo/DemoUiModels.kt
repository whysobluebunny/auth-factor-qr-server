package ru.mephi.abondarenko.auth.factor.qr.ui.demo

import jakarta.validation.constraints.NotBlank

data class DemoLoginForm(
    @field:NotBlank
    val username: String = "",

    @field:NotBlank
    val password: String = ""
)
