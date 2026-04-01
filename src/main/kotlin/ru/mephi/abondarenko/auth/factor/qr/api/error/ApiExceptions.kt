package ru.mephi.abondarenko.auth.factor.qr.api.error

import org.springframework.http.HttpStatus

open class ApiException(
    message: String,
    val status: HttpStatus
) : RuntimeException(message)

class NotFoundException(message: String) : ApiException(message, HttpStatus.NOT_FOUND)
class BadRequestException(message: String) : ApiException(message, HttpStatus.BAD_REQUEST)
class ConflictException(message: String) : ApiException(message, HttpStatus.CONFLICT)
class TooManyRequestsException(message: String) : ApiException(message, HttpStatus.TOO_MANY_REQUESTS)
class InternalConfigurationException(message: String) : ApiException(message, HttpStatus.INTERNAL_SERVER_ERROR)
