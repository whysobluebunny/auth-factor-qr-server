package ru.mephi.abondarenko.auth.factor.qr.domain

enum class SessionStatus {
    PENDING,
    APPROVED,
    EXPIRED,
    BLOCKED
}