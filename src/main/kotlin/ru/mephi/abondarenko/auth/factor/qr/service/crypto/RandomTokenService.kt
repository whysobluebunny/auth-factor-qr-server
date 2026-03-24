package ru.mephi.abondarenko.auth.factor.qr.service.crypto

import org.springframework.stereotype.Service
import java.security.SecureRandom
import java.util.Base64

@Service
class RandomTokenService {
    private val secureRandom = SecureRandom()

    fun randomUrlSafeToken(byteLength: Int = 32): String {
        val bytes = ByteArray(byteLength)
        secureRandom.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    fun randomBase32Secret(byteLength: Int = 20): String {
        val bytes = ByteArray(byteLength)
        secureRandom.nextBytes(bytes)
        return Base32Codec.encode(bytes)
    }
}