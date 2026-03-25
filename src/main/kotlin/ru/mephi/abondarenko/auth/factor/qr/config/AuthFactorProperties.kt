package ru.mephi.abondarenko.auth.factor.qr.config

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

@ConfigurationProperties(prefix = "app.auth-factor")
data class AuthFactorProperties(
    var serviceId: String = "auth-factor-qr",
    var otpPeriod: Duration = Duration.ofSeconds(30),
    var otpDigits: Int = 6,
    var allowedClockSkewSteps: Long = 1,
    var challengeTtl: Duration = Duration.ofMinutes(2),
    var challengeRateLimitWindow: Duration = Duration.ofMinutes(1),
    var challengeRateLimitRequests: Int = 5,
    var responseMaxAge: Duration = Duration.ofMinutes(2),
    var verifyRateLimitWindow: Duration = Duration.ofMinutes(1),
    var verifyRateLimitRequests: Int = 10,
    var maxVerifyAttempts: Int = 5,
    var authSessionRetention: Duration = Duration.ofDays(7),
    var authSessionCleanupInterval: Duration = Duration.ofMinutes(15),
    var masterKeyBase64: String = "",
    var apiKeyHeaderName: String = "X-Auth-Factor-Api-Key",
    var apiKey: String = ""
)
