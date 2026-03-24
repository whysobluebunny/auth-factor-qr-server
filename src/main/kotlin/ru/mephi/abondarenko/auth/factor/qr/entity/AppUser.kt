package ru.mephi.abondarenko.auth.factor.qr.entity

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "app_users")
class AppUser(

    @Id
    var id: UUID = UUID.randomUUID(),

    @Column(name = "external_user_id", nullable = false, unique = true, length = 128)
    var externalUserId: String,

    @Column(name = "display_name", length = 255)
    var displayName: String? = null,

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now()
)