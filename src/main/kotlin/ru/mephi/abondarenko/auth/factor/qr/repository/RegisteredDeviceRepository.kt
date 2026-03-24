package ru.mephi.abondarenko.auth.factor.qr.repository

import org.springframework.data.jpa.repository.JpaRepository
import ru.mephi.abondarenko.auth.factor.qr.entity.RegisteredDevice
import java.util.UUID

interface RegisteredDeviceRepository : JpaRepository<RegisteredDevice, UUID> {
    fun findByIdAndUserExternalUserId(id: UUID, externalUserId: String): RegisteredDevice?
}