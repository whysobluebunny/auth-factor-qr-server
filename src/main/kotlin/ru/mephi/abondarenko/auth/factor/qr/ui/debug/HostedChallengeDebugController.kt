package ru.mephi.abondarenko.auth.factor.qr.ui.debug

import jakarta.validation.Valid
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.validation.BindingResult
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ModelAttribute
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.servlet.mvc.support.RedirectAttributes
import ru.mephi.abondarenko.auth.factor.qr.api.dto.CreateChallengeRequest
import ru.mephi.abondarenko.auth.factor.qr.service.AuthSessionService
import ru.mephi.abondarenko.auth.factor.qr.ui.hosted.HostedChallengeForm

@Controller
@ConditionalOnProperty(prefix = "app.auth-factor", name = ["debug-ui-enabled"], havingValue = "true")
@RequestMapping("/ui/auth/challenges")
class HostedChallengeDebugController(
    private val authSessionService: AuthSessionService
) {

    @GetMapping
    fun challengeStartPage(model: Model): String {
        if (!model.containsAttribute("form")) {
            model.addAttribute("form", HostedChallengeForm())
        }
        return "ui/debug/challenge-start"
    }

    @PostMapping
    fun createChallenge(
        @Valid @ModelAttribute("form") form: HostedChallengeForm,
        bindingResult: BindingResult,
        redirectAttributes: RedirectAttributes
    ): String {
        if (bindingResult.hasErrors()) {
            return "ui/debug/challenge-start"
        }

        val response = authSessionService.createChallenge(
            CreateChallengeRequest(
                externalUserId = form.externalUserId,
                deviceId = form.deviceId!!,
                firstFactorRef = form.firstFactorRef
            )
        )

        if (!form.returnUrl.isNullOrBlank()) {
            redirectAttributes.addAttribute("returnUrl", form.returnUrl)
        }

        return "redirect:/ui/auth/sessions/${response.sessionId}"
    }
}
