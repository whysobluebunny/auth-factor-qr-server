package ru.mephi.abondarenko.auth.factor.qr.entity

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.FetchType
import jakarta.persistence.Id
import jakarta.persistence.JoinColumn
import jakarta.persistence.ManyToOne
import jakarta.persistence.Table
import ru.mephi.abondarenko.auth.factor.qr.domain.SessionStatus
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "auth_sessions")
class AuthSession(

    @Id
    var id: UUID = UUID.randomUUID(),

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    var user: AppUser,

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "device_id", nullable = false)
    var device: RegisteredDevice,

    @Column(name = "challenge", nullable = false, unique = true, length = 128)
    var challenge: String,

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    var status: SessionStatus = SessionStatus.PENDING,

    @Column(name = "first_factor_ref", length = 255)
    var firstFactorRef: String? = null,

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),

    @Column(name = "expires_at", nullable = false)
    var expiresAt: Instant,

    @Column(name = "verified_at")
    var verifiedAt: Instant? = null,

    @Column(name = "attempt_count", nullable = false)
    var attemptCount: Int = 0,

    @Column(name = "max_attempts", nullable = false)
    var maxAttempts: Int = 5,

    @Column(name = "accepted_response_hash", length = 64)
    var acceptedResponseHash: String? = null,

    @Column(name = "device_response_token", length = 255)
    var deviceResponseToken: String? = null,

    @Column(name = "device_response_token_hash", length = 64)
    var deviceResponseTokenHash: String? = null,

    @Column(name = "device_response_token_expires_at")
    var deviceResponseTokenExpiresAt: Instant? = null
)
