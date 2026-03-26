package ru.mephi.abondarenko.auth.factor.qr.ui.hosted

import jakarta.validation.Valid
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.validation.BindingResult
import org.springframework.web.bind.annotation.*
import org.springframework.web.servlet.mvc.support.RedirectAttributes
import org.springframework.web.util.UriComponentsBuilder
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ResponseQrPayload
import ru.mephi.abondarenko.auth.factor.qr.service.AuthSessionService
import tools.jackson.databind.json.JsonMapper
import java.util.*

@Controller
@RequestMapping("/ui/auth")
class HostedAuthController(
    private val authSessionService: AuthSessionService,
    private val qrCodeRenderingService: QrCodeRenderingService,
    private val objectMapper: JsonMapper
) {

    @GetMapping("/sessions/{sessionId}")
    fun sessionPage(
        @PathVariable sessionId: UUID,
        @ModelAttribute("verifyForm") verifyForm: HostedVerifyForm?,
        @ModelAttribute("message") message: String?,
        @ModelAttribute("errorMessage") errorMessage: String?,
        @ModelAttribute("returnUrl") returnUrl: String?,
        model: Model
    ): String {
        populateSessionModel(sessionId, returnUrl, model)
        if (!model.containsAttribute("verifyForm")) {
            model.addAttribute("verifyForm", verifyForm ?: HostedVerifyForm(returnUrl = returnUrl))
        }
        if (!message.isNullOrBlank()) {
            model.addAttribute("message", message)
        }
        if (!errorMessage.isNullOrBlank()) {
            model.addAttribute("errorMessage", errorMessage)
        }
        return "ui/hosted/auth-session"
    }

    @PostMapping("/sessions/{sessionId}/verify")
    fun verifySession(
        @PathVariable sessionId: UUID,
        @Valid @ModelAttribute("verifyForm") verifyForm: HostedVerifyForm,
        bindingResult: BindingResult,
        redirectAttributes: RedirectAttributes
    ): String {
        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute(
                "org.springframework.validation.BindingResult.verifyForm",
                bindingResult
            )
            redirectAttributes.addFlashAttribute("verifyForm", verifyForm)
            redirectAttributes.addFlashAttribute("errorMessage", "Response payload is required")
            if (!verifyForm.returnUrl.isNullOrBlank()) {
                redirectAttributes.addFlashAttribute("returnUrl", verifyForm.returnUrl)
            }
            return "redirect:/ui/auth/sessions/$sessionId"
        }

        val payload = objectMapper.readValue(verifyForm.responsePayloadRaw, ResponseQrPayload::class.java)
        val result = authSessionService.verifyResponse(payload)

        if (result.approved && !verifyForm.returnUrl.isNullOrBlank()) {
            val redirectUrl = UriComponentsBuilder.fromUriString(verifyForm.returnUrl)
                .queryParam("sessionId", sessionId)
                .build()
                .toUriString()
            return "redirect:$redirectUrl"
        }

        redirectAttributes.addFlashAttribute("verifyForm", HostedVerifyForm(returnUrl = verifyForm.returnUrl))
        redirectAttributes.addFlashAttribute(
            "message",
            if (result.approved) "Second factor approved." else "Second factor was not approved."
        )
        if (!verifyForm.returnUrl.isNullOrBlank()) {
            redirectAttributes.addFlashAttribute("returnUrl", verifyForm.returnUrl)
        }

        return "redirect:/ui/auth/sessions/$sessionId"
    }

    private fun populateSessionModel(sessionId: UUID, returnUrl: String?, model: Model) {
        val sessionInfo = authSessionService.getSessionInfo(sessionId)
        val qrPayloadRaw = authSessionService.getChallengePayloadRaw(sessionId)

        model.addAttribute(
            "authSessionView",
            HostedAuthSessionViewModel(
                sessionId = sessionInfo.sessionId,
                status = sessionInfo.status,
                createdAt = sessionInfo.createdAt,
                expiresAt = sessionInfo.expiresAt,
                verifiedAt = sessionInfo.verifiedAt,
                attemptCount = sessionInfo.attemptCount,
                maxAttempts = sessionInfo.maxAttempts,
                qrPayloadRaw = qrPayloadRaw,
                qrCodeDataUrl = qrCodeRenderingService.renderDataUrl(qrPayloadRaw),
                returnUrl = returnUrl
            )
        )
    }
}
