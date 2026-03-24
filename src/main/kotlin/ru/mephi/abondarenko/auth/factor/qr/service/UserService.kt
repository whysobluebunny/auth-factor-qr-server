package ru.mephi.abondarenko.auth.factor.qr.service

import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import ru.mephi.abondarenko.auth.factor.qr.api.error.NotFoundException
import ru.mephi.abondarenko.auth.factor.qr.entity.AppUser
import ru.mephi.abondarenko.auth.factor.qr.repository.AppUserRepository

@Service
class UserService(
    private val appUserRepository: AppUserRepository
) {

    @Transactional
    fun getOrCreate(externalUserId: String, displayName: String?): AppUser {
        val existing = appUserRepository.findByExternalUserId(externalUserId)
        if (existing != null) {
            if (!displayName.isNullOrBlank() && existing.displayName != displayName) {
                existing.displayName = displayName
            }
            return existing
        }

        return appUserRepository.save(
            AppUser(
                externalUserId = externalUserId,
                displayName = displayName
            )
        )
    }

    @Transactional(readOnly = true)
    fun getByExternalUserId(externalUserId: String): AppUser {
        return appUserRepository.findByExternalUserId(externalUserId)
            ?: throw NotFoundException("User with externalUserId=$externalUserId not found")
    }
}