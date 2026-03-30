package ru.mephi.abondarenko.auth.factor.qr.ui.hosted

import jakarta.validation.Valid
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.validation.BindingResult
import org.springframework.web.bind.annotation.*
import org.springframework.web.servlet.mvc.support.RedirectAttributes
import ru.mephi.abondarenko.auth.factor.qr.api.dto.ConfirmEnrollmentRequest
import ru.mephi.abondarenko.auth.factor.qr.api.error.ApiException
import ru.mephi.abondarenko.auth.factor.qr.service.EnrollmentService

@Controller
@RequestMapping("/ui")
class HostedEnrollmentController(
    private val enrollmentService: EnrollmentService,
    private val qrCodeRenderingService: QrCodeRenderingService
) {

    @GetMapping("/enrollments")
    fun enrollmentPage(
        @RequestParam(required = false) externalUserId: String?,
        @RequestParam(required = false) displayName: String?,
        @RequestParam(required = false) returnUrl: String?,
        @ModelAttribute("startErrorMessage") startErrorMessage: String?,
        model: Model
    ): String {
        if (!model.containsAttribute("form")) {
            model.addAttribute(
                "form",
                HostedEnrollmentForm(
                    externalUserId = externalUserId ?: "",
                    displayName = displayName,
                    returnUrl = returnUrl
                )
            )
        }
        if (!model.containsAttribute("confirmForm")) {
            model.addAttribute("confirmForm", HostedEnrollmentConfirmForm())
        }
        if (!startErrorMessage.isNullOrBlank()) {
            model.addAttribute("startErrorMessage", startErrorMessage)
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

        val response = try {
            enrollmentService.startOrResumeHostedEnrollment(
                externalUserId = form.externalUserId,
                displayName = form.displayName
            )
        } catch (ex: ApiException) {
            model.addAttribute("startErrorMessage", ex.message)
            return "ui/hosted/enrollment"
        }

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
                qrCodeDataUrl = qrCodeRenderingService.renderDataUrl(response.qrPayloadRaw),
                returnUrl = form.returnUrl
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

        val result = try {
            enrollmentService.confirmEnrollment(
                ConfirmEnrollmentRequest(
                    deviceId = form.deviceId!!,
                    totpCode = form.totpCode
                )
            )
        } catch (ex: ApiException) {
            redirectAttributes.addFlashAttribute("confirmErrorMessage", ex.message)
            redirectAttributes.addFlashAttribute("confirmForm", form)
            return "redirect:/ui/enrollments"
        }

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
