package ru.mephi.abondarenko.auth.factor.qr.repository

import org.springframework.data.jpa.repository.JpaRepository
import ru.mephi.abondarenko.auth.factor.qr.entity.AuthSession
import java.util.UUID

interface AuthSessionRepository : JpaRepository<AuthSession, UUID>