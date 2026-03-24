package ru.mephi.abondarenko.auth.factor.qr.service.crypto

import jakarta.annotation.PostConstruct
import org.springframework.stereotype.Service
import ru.mephi.abondarenko.auth.factor.qr.api.error.InternalConfigurationException
import ru.mephi.abondarenko.auth.factor.qr.config.AuthFactorProperties
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class EncryptedSecret(
    val ciphertext: String,
    val nonce: String
)

@Service
class SecretCryptoService(
    private val properties: AuthFactorProperties
) {
    private val secureRandom = SecureRandom()
    private lateinit var keySpec: SecretKeySpec

    @PostConstruct
    fun init() {
        val keyBytes = try {
            Base64.getDecoder().decode(properties.masterKeyBase64)
        } catch (_: IllegalArgumentException) {
            throw InternalConfigurationException("AUTH_FACTOR_MASTER_KEY_BASE64 is not valid Base64")
        }

        if (keyBytes.size !in setOf(16, 24, 32)) {
            throw InternalConfigurationException("Master key must be 16, 24 or 32 bytes after Base64 decoding")
        }

        keySpec = SecretKeySpec(keyBytes, "AES")
    }

    fun encrypt(plainText: String): EncryptedSecret {
        val nonce = ByteArray(12)
        secureRandom.nextBytes(nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(128, nonce))
        val ciphertext = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

        return EncryptedSecret(
            ciphertext = Base64.getEncoder().encodeToString(ciphertext),
            nonce = Base64.getEncoder().encodeToString(nonce)
        )
    }

    fun decrypt(ciphertext: String, nonce: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            keySpec,
            GCMParameterSpec(128, Base64.getDecoder().decode(nonce))
        )
        val plain = cipher.doFinal(Base64.getDecoder().decode(ciphertext))
        return plain.toString(Charsets.UTF_8)
    }
}