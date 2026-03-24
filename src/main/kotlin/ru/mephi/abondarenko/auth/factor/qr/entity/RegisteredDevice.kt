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
import ru.mephi.abondarenko.auth.factor.qr.domain.DeviceStatus
import ru.mephi.abondarenko.auth.factor.qr.domain.TotpAlgorithm
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "registered_devices")
class RegisteredDevice(

    @Id
    var id: UUID = UUID.randomUUID(),

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    var user: AppUser,

    @Column(name = "device_label", nullable = false, length = 255)
    var deviceLabel: String,

    @Column(name = "service_id", nullable = false, length = 128)
    var serviceId: String,

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    var status: DeviceStatus = DeviceStatus.PENDING,

    @Column(name = "secret_ciphertext", nullable = false, columnDefinition = "text")
    var secretCiphertext: String,

    @Column(name = "secret_nonce", nullable = false, length = 128)
    var secretNonce: String,

    @Enumerated(EnumType.STRING)
    @Column(name = "algorithm", nullable = false, length = 16)
    var algorithm: TotpAlgorithm = TotpAlgorithm.SHA1,

    @Column(name = "digits", nullable = false)
    var digits: Int = 6,

    @Column(name = "period_seconds", nullable = false)
    var periodSeconds: Int = 30,

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),

    @Column(name = "confirmed_at")
    var confirmedAt: Instant? = null,

    @Column(name = "revoked_at")
    var revokedAt: Instant? = null,

    @Column(name = "last_used_at")
    var lastUsedAt: Instant? = null
)