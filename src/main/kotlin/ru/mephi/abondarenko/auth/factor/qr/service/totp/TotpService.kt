package ru.mephi.abondarenko.auth.factor.qr.service.totp

import org.springframework.stereotype.Service
import ru.mephi.abondarenko.auth.factor.qr.domain.TotpAlgorithm
import ru.mephi.abondarenko.auth.factor.qr.service.crypto.Base32Codec
import java.nio.ByteBuffer
import java.time.Instant
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

@Service
class TotpService {

    fun generate(
        secretBase32: String,
        timestamp: Instant,
        digits: Int,
        periodSeconds: Int,
        algorithm: TotpAlgorithm
    ): String {
        require(digits in 6..8) { "Supported OTP length is 6..8 digits" }
        require(periodSeconds > 0) { "periodSeconds must be positive" }

        val secretBytes = Base32Codec.decode(secretBase32)
        val timeStep = timestamp.epochSecond / periodSeconds
        val counter = ByteBuffer.allocate(8).putLong(timeStep).array()

        val mac = Mac.getInstance(algorithm.hmacName)
        mac.init(SecretKeySpec(secretBytes, algorithm.hmacName))
        val hash = mac.doFinal(counter)

        val offset = hash.last().toInt() and 0x0F
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)

        val otp = binary % 10.0.pow(digits.toDouble()).toInt()
        return otp.toString().padStart(digits, '0')
    }

    fun verify(
        secretBase32: String,
        code: String,
        timestamp: Instant,
        digits: Int,
        periodSeconds: Int,
        algorithm: TotpAlgorithm,
        allowedClockSkewSteps: Long
    ): Boolean {
        for (delta in -allowedClockSkewSteps..allowedClockSkewSteps) {
            val candidateTime = timestamp.plusSeconds(delta * periodSeconds.toLong())
            val candidateCode = generate(
                secretBase32 = secretBase32,
                timestamp = candidateTime,
                digits = digits,
                periodSeconds = periodSeconds,
                algorithm = algorithm
            )
            if (candidateCode == code) {
                return true
            }
        }
        return false
    }
}