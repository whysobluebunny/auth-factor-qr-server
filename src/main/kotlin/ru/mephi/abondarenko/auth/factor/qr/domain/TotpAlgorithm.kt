package ru.mephi.abondarenko.auth.factor.qr.domain

enum class TotpAlgorithm(val hmacName: String) {
    SHA1("HmacSHA1"),
    SHA256("HmacSHA256"),
    SHA512("HmacSHA512")
}