package ru.mephi.abondarenko.auth.factor.qr.ui.hosted

import jakarta.validation.Valid
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.validation.BindingResult
import org.springframework.web.bind.annotation.*
import org.springframework.web.servlet.mvc.support.RedirectAttributes
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.dto.StartEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.service.EnrollmentService

@Controller
@RequestMapping("/ui")
class HostedEnrollmentController(
    private val enrollmentService: EnrollmentService,
    private val qrCodeRenderingService: QrCodeRenderingService
) {

    @GetMapping("/enrollments")
    fun enrollmentPage(model: Model): String {
        if (!model.containsAttribute("form")) {
            model.addAttribute("form", HostedEnrollmentForm())
        }
        if (!model.containsAttribute("confirmForm")) {
            model.addAttribute("confirmForm", HostedEnrollmentConfirmForm())
        }
        return "ui/hosted/enrollment"
    }

    @PostMapping("/enrollments")
    fun startEnrollment(
        @Valid @ModelAttribute("form") form: HostedEnrollmentForm,
        bindingResult: BindingResult,
        model: Model
    ): String {
        if (bindingResult.hasErrors()) {
            return "ui/hosted/enrollment"
        }

        val response = enrollmentService.startEnrollment(
            StartEnrollmentRequest(
                externalUserId = form.externalUserId,
                displayName = form.displayName,
                deviceLabel = form.deviceLabel
            )
        )

        model.addAttribute(
            "enrollment",
            HostedEnrollmentViewModel(
                externalUserId = form.externalUserId,
                deviceId = response.deviceId,
                deviceStatus = response.deviceStatus.name,
                secret = response.qrPayload.secret,
                enrollmentToken = response.qrPayload.enrollmentToken,
                period = response.qrPayload.period,
                digits = response.qrPayload.digits,
                algorithm = ru.mephi.abondarenko.auth.factor.qr.domain.TotpAlgorithm.valueOf(response.qrPayload.algorithm),
                qrPayloadRaw = response.qrPayloadRaw,
                qrCodeDataUrl = qrCodeRenderingService.renderDataUrl(response.qrPayloadRaw)
            )
        )
        model.addAttribute("confirmForm", HostedEnrollmentConfirmForm(deviceId = response.deviceId))
        model.addAttribute("devicesUrl", "/ui/devices?externalUserId=${form.externalUserId}")
        return "ui/hosted/enrollment"
    }

    @PostMapping("/enrollments/confirm")
    fun confirmEnrollment(
        @Valid @ModelAttribute("confirmForm") form: HostedEnrollmentConfirmForm,
        bindingResult: BindingResult,
        redirectAttributes: RedirectAttributes
    ): String {
        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute(
                "org.springframework.validation.BindingResult.confirmForm",
                bindingResult
            )
            redirectAttributes.addFlashAttribute("confirmForm", form)
            redirectAttributes.addFlashAttribute(
                "confirmErrorMessage",
                "A valid TOTP code is required to confirm enrollment"
            )
            return "redirect:/ui/enrollments"
        }

        val result = enrollmentService.confirmEnrollment(
            ConfirmEnrollmentRequest(
                deviceId = form.deviceId!!,
                totpCode = form.totpCode
            )
        )

        redirectAttributes.addFlashAttribute(
            "confirmMessage",
            "Device ${result.deviceId} is now ${result.deviceStatus}"
        )
        redirectAttributes.addFlashAttribute("confirmForm", HostedEnrollmentConfirmForm(deviceId = result.deviceId))
        return "redirect:/ui/enrollments"
    }

    @GetMapping("/devices")
    fun devicesPage(
        @RequestParam externalUserId: String,
        model: Model
    ): String {
        val devices = enrollmentService.listDevices(externalUserId)
        model.addAttribute(
            "deviceList",
            HostedDeviceListViewModel(
                externalUserId = externalUserId,
                devices = devices
            )
        )
        return "ui/hosted/devices"
    }
}
