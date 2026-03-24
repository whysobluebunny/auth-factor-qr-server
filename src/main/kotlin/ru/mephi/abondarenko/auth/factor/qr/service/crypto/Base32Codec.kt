package ru.mephi.abondarenko.auth.factor.qr.service.crypto

object Base32Codec {

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private val LOOKUP = ALPHABET.withIndex().associate { it.value to it.index }

    fun encode(input: ByteArray): String {
        if (input.isEmpty()) return ""

        val output = StringBuilder()
        var buffer = 0
        var bitsLeft = 0

        for (byte in input) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xFF)
            bitsLeft += 8

            while (bitsLeft >= 5) {
                val index = (buffer shr (bitsLeft - 5)) and 0x1F
                bitsLeft -= 5
                output.append(ALPHABET[index])
            }
        }

        if (bitsLeft > 0) {
            val index = (buffer shl (5 - bitsLeft)) and 0x1F
            output.append(ALPHABET[index])
        }

        return output.toString()
    }

    fun decode(input: String): ByteArray {
        val normalized = input.uppercase().replace("=", "").replace("\\s".toRegex(), "")
        if (normalized.isEmpty()) return ByteArray(0)

        var buffer = 0
        var bitsLeft = 0
        val output = ArrayList<Byte>()

        for (char in normalized) {
            val value = LOOKUP[char]
                ?: throw IllegalArgumentException("Invalid Base32 character: $char")

            buffer = (buffer shl 5) or value
            bitsLeft += 5

            if (bitsLeft >= 8) {
                val byte = (buffer shr (bitsLeft - 8)) and 0xFF
                bitsLeft -= 8
                output.add(byte.toByte())
            }
        }

        return output.toByteArray()
    }
}