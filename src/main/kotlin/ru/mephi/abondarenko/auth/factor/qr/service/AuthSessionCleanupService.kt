package ru.mephi.abondarenko.auth.factor.qr.service

import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import ru.mephi.abondarenko.auth.factor.qr.config.AuthFactorProperties
import ru.mephi.abondarenko.auth.factor.qr.repository.AuthSessionRepository
import java.time.Clock
import java.time.Instant

@Service
class AuthSessionCleanupService(
    private val authSessionRepository: AuthSessionRepository,
    private val properties: AuthFactorProperties,
    private val clock: Clock
) {

    @Scheduled(fixedDelayString = "\${app.auth-factor.auth-session-cleanup-interval:15m}")
    @Transactional
    fun cleanupObsoleteSessions() {
        cleanupObsoleteSessions(Instant.now(clock))
    }

    @Transactional
    fun cleanupObsoleteSessions(now: Instant): Int {
        val cutoff = now.minus(properties.authSessionRetention)
        return authSessionRepository.deleteObsoleteSessions(cutoff)
    }
}
