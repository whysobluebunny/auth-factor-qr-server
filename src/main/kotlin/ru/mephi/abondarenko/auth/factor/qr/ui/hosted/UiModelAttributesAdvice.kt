package ru.mephi.abondarenko.auth.factor.qr.ui.hosted

import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ModelAttribute
import ru.mephi.abondarenko.auth.factor.qr.config.AuthFactorProperties

@ControllerAdvice
class UiModelAttributesAdvice(
    private val properties: AuthFactorProperties
) {

    @ModelAttribute("uiDebugEnabled")
    fun uiDebugEnabled(): Boolean = properties.debugUiEnabled
}
