package ru.mephi.abondarenko.auth.factor.qr.ui.demo

import jakarta.servlet.http.HttpSession
import jakarta.validation.Valid
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.validation.BindingResult
import org.springframework.web.bind.annotation.*
import org.springframework.web.servlet.mvc.support.RedirectAttributes
import ru.mephi.abondarenko.auth.factor.qr.api.dto.CreateChallengeRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceInfoResponse
import ru.mephi.abondarenko.auth.factor.qr.api.dto.RevokeDeviceRequest
import ru.mephi.abondarenko.auth.factor.qr.api.error.NotFoundException
import ru.mephi.abondarenko.auth.factor.qr.domain.DeviceStatus
import ru.mephi.abondarenko.auth.factor.qr.domain.SessionStatus
import ru.mephi.abondarenko.auth.factor.qr.service.AuthSessionService
import ru.mephi.abondarenko.auth.factor.qr.service.EnrollmentService
import java.time.Clock
import java.time.Instant
import java.util.*

@Controller
@ConditionalOnProperty(prefix = "app.auth-factor", name = ["demo-ui-enabled"], havingValue = "true")
@RequestMapping("/demo")
class DemoAppController(
    private val enrollmentService: EnrollmentService,
    private val authSessionService: AuthSessionService,
    private val clock: Clock
) {
    private val demoUsers = mapOf(
        "demo-user" to "password",
        "alice" to "password"
    )

    @GetMapping
    fun landing(): String = "ui/demo/index"

    @GetMapping("/login")
    fun loginPage(model: Model): String {
        if (!model.containsAttribute("form")) {
            model.addAttribute("form", DemoLoginForm())
        }
        return "ui/demo/login"
    }

    @PostMapping("/login")
    fun login(
        @Valid @ModelAttribute("form") form: DemoLoginForm,
        bindingResult: BindingResult,
        session: HttpSession,
        model: Model
    ): String {
        if (bindingResult.hasErrors()) {
            return "ui/demo/login"
        }

        val passwordMatches = demoUsers[form.username] == form.password
        if (!passwordMatches) {
            model.addAttribute("errorMessage", "Invalid demo credentials")
            return "ui/demo/login"
        }

        if (activeDevices(form.username).isEmpty()) {
            session.setAttribute("demo.authenticated.username", form.username)
            session.setAttribute("demo.authenticated.secondFactorConfigured", false)
            return "redirect:/demo/home"
        }

        val challenge = authSessionService.createChallenge(
            CreateChallengeRequest(
                externalUserId = form.username,
                firstFactorRef = "demo-login-${Instant.now(clock).epochSecond}"
            )
        )

        session.setAttribute("demo.pending.username", form.username)
        session.setAttribute("demo.pending.sessionId", challenge.sessionId.toString())

        return "redirect:/ui/auth/sessions/${challenge.sessionId}?returnUrl=/demo/callback"
    }

    @GetMapping("/callback")
    fun callback(
        @RequestParam sessionId: UUID,
        session: HttpSession,
        model: Model
    ): String {
        val pendingSessionId = session.getAttribute("demo.pending.sessionId") as String?
        val pendingUsername = session.getAttribute("demo.pending.username") as String?

        if (pendingSessionId == null || pendingUsername == null || pendingSessionId != sessionId.toString()) {
            model.addAttribute("errorMessage", "Demo login context is missing or does not match the callback session.")
            return "ui/demo/login"
        }

        val sessionInfo = authSessionService.getSessionInfo(sessionId)
        if (sessionInfo.status != SessionStatus.APPROVED) {
            model.addAttribute("errorMessage", "Second factor has not been approved yet.")
            model.addAttribute("form", DemoLoginForm(username = pendingUsername))
            return "ui/demo/login"
        }

        session.setAttribute("demo.authenticated.username", pendingUsername)
        session.setAttribute("demo.authenticated.secondFactorConfigured", true)
        session.removeAttribute("demo.pending.username")
        session.removeAttribute("demo.pending.sessionId")
        return "redirect:/demo/home"
    }

    @GetMapping("/home")
    fun home(session: HttpSession, model: Model): String {
        val username = session.getAttribute("demo.authenticated.username") as String?
        if (username == null) {
            return "redirect:/demo/login"
        }

        val devices = visibleDevices(username)
        val secondFactorConfigured = devices.any { it.deviceStatus == DeviceStatus.ACTIVE }
        session.setAttribute("demo.authenticated.secondFactorConfigured", secondFactorConfigured)
        model.addAttribute(
            "home",
            DemoHomeViewModel(
                username = username,
                secondFactorConfigured = secondFactorConfigured,
                enrollmentUrl = "/ui/enrollments?externalUserId=$username&displayName=$username&returnUrl=/demo/home",
                devices = devices
            )
        )
        return "ui/demo/home"
    }

    @PostMapping("/devices/{deviceId}/revoke")
    fun revokeDevice(
        @PathVariable deviceId: UUID,
        session: HttpSession,
        redirectAttributes: RedirectAttributes
    ): String {
        val username = session.getAttribute("demo.authenticated.username") as String?
            ?: return "redirect:/demo/login"

        val result = enrollmentService.revokeDevice(
            deviceId = deviceId,
            request = RevokeDeviceRequest(externalUserId = username)
        )

        redirectAttributes.addFlashAttribute(
            "deviceActionMessage",
            "Device ${result.deviceId} has been moved to ${result.deviceStatus}"
        )
        return "redirect:/demo/home"
    }

    @PostMapping("/logout")
    fun logout(session: HttpSession): String {
        session.invalidate()
        return "redirect:/demo/login"
    }

    private fun activeDevices(externalUserId: String) =
        visibleDevices(externalUserId)
            .filter { it.deviceStatus == DeviceStatus.ACTIVE }

    private fun visibleDevices(externalUserId: String): List<DeviceInfoResponse> =
        try {
            enrollmentService.listDevices(externalUserId)
                .filter { it.deviceStatus != DeviceStatus.REVOKED }
        } catch (_: NotFoundException) {
            emptyList()
        }
}
