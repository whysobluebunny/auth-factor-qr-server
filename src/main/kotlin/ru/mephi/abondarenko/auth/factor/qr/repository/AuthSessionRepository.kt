package ru.mephi.abondarenko.auth.factor.qr.repository

import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import ru.mephi.abondarenko.auth.factor.qr.entity.AuthSession
import java.time.Instant
import java.util.UUID

interface AuthSessionRepository : JpaRepository<AuthSession, UUID> {
    fun findByIdAndDeviceResponseTokenHash(id: UUID, deviceResponseTokenHash: String): AuthSession?

    @Modifying
    @Query(
        """
        delete from AuthSession s
        where
            (s.verifiedAt is not null and s.verifiedAt < :cutoff)
            or
            (s.verifiedAt is null and s.expiresAt < :cutoff)
        """
    )
    fun deleteObsoleteSessions(cutoff: Instant): Int
}
