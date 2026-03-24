package ru.mephi.abondarenko.auth.factor.qr.repository

import org.springframework.data.jpa.repository.JpaRepository
import ru.mephi.abondarenko.auth.factor.qr.entity.AppUser
import java.util.UUID

interface AppUserRepository : JpaRepository<AppUser, UUID> {
    fun findByExternalUserId(externalUserId: String): AppUser?
}