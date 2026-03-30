package ru.mephi.abondarenko.auth.factor.qr.ui.debug

import jakarta.validation.Valid
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.validation.BindingResult
import org.springframework.web.bind.annotation.*
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ChallengeQrPayload
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceAuthResponseRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.DeviceEnrollmentConfirmRequest
import ru.mephi.abondarenko.auth.factor.qr.service.AuthSessionService
import ru.mephi.abondarenko.auth.factor.qr.service.totp.TotpService
import ru.mephi.abondarenko.auth.factor.qr.ui.hosted.HostedDeviceSimulatorForm
import ru.mephi.abondarenko.auth.factor.qr.ui.hosted.HostedDeviceSimulatorViewModel
import tools.jackson.databind.json.JsonMapper
import java.time.Clock
import java.time.Instant
import java.util.*

@Controller
@ConditionalOnProperty(prefix = "app.auth-factor", name = ["debug-ui-enabled"], havingValue = "true")
@RequestMapping("/ui/tools/device-simulator")
class HostedDeviceSimulatorController(
    private val authSessionService: AuthSessionService,
    private val totpService: TotpService,
    private val qrCodeRenderingService: ru.mephi.abondarenko.auth.factor.qr.ui.hosted.QrCodeRenderingService,
    private val objectMapper: JsonMapper,
    private val clock: Clock
) {

    @GetMapping
    fun simulatorPage(
        @RequestParam(required = false) sessionId: UUID?,
        @RequestParam(required = false) deviceId: UUID?,
        @RequestParam(required = false) enrollmentToken: String?,
        @RequestParam(required = false) returnUrl: String?,
        model: Model
    ): String {
        if (!model.containsAttribute("form")) {
            model.addAttribute(
                "form",
                HostedDeviceSimulatorForm(
                    deviceId = deviceId,
                    sessionId = sessionId,
                    enrollmentToken = enrollmentToken ?: "",
                    deviceLabel = "Demo Phone",
                    challengePayloadRaw = sessionId?.let(authSessionService::getChallengePayloadRaw) ?: "",
                    digits = 6,
                    period = 30,
                    algorithm = ru.mephi.abondarenko.auth.factor.qr.domain.TotpAlgorithm.SHA1,
                    returnUrl = returnUrl
                )
            )
        }
        return "ui/debug/device-simulator"
    }

    @PostMapping
    fun generate(
        @Valid @ModelAttribute("form") form: HostedDeviceSimulatorForm,
        bindingResult: BindingResult,
        model: Model
    ): String {
        if (bindingResult.hasErrors()) {
            return "ui/debug/device-simulator"
        }

        val now = Instant.now(clock)
        val currentTotpCode = totpService.generate(
            secretBase32 = form.secret,
            timestamp = now,
            digits = form.digits!!,
            periodSeconds = form.period!!,
            algorithm = form.algorithm!!
        )

        val enrollmentConfirmPayloadRaw = if (form.deviceId != null && form.enrollmentToken.isNotBlank()) {
            objectMapper.writeValueAsString(
                DeviceEnrollmentConfirmRequest(
                    deviceId = form.deviceId,
                    enrollmentToken = form.enrollmentToken,
                    deviceLabel = form.deviceLabel,
                    totpCode = currentTotpCode
                )
            )
        } else {
            null
        }

        val responsePayloadRaw = if (form.sessionId != null || form.challengePayloadRaw.isNotBlank()) {
            val challengePayload = parseChallengePayload(form)
            objectMapper.writeValueAsString(
                DeviceAuthResponseRequest(
                    sessionId = challengePayload.sessionId,
                    responseToken = challengePayload.responseToken,
                    challenge = challengePayload.challenge,
                    totp = currentTotpCode,
                    timestamp = now.epochSecond,
                    deviceId = requireNotNull(form.deviceId) { "deviceId is required when generating a response payload" }
                )
            )
        } else {
            null
        }

        model.addAttribute(
            "simulatorResult",
            HostedDeviceSimulatorViewModel(
                generatedAt = now,
                currentTotpCode = currentTotpCode,
                enrollmentConfirmPayloadRaw = enrollmentConfirmPayloadRaw,
                responsePayloadRaw = responsePayloadRaw,
                enrollmentSubmitUrl = if (enrollmentConfirmPayloadRaw != null) "/api/v1/device/enrollments/confirm" else null,
                responseQrCodeDataUrl = responsePayloadRaw?.let(qrCodeRenderingService::renderDataUrl)
            )
        )
        return "ui/debug/device-simulator"
    }

    private fun parseChallengePayload(form: HostedDeviceSimulatorForm): ChallengeQrPayload {
        val challengePayloadRaw = when {
            form.challengePayloadRaw.isNotBlank() -> form.challengePayloadRaw
            form.sessionId != null -> authSessionService.getChallengePayloadRaw(form.sessionId)
            else -> error("Challenge payload is missing")
        }

        return objectMapper.readValue(challengePayloadRaw, ChallengeQrPayload::class.java)
    }
}
