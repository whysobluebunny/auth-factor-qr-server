package ru.mephi.abondarenko.auth.factor.qr.api.error

import jakarta.validation.ConstraintViolationException
import org.springframework.http.HttpStatus
import org.springframework.http.ProblemDetail
import org.springframework.validation.BindException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

@RestControllerAdvice
class RestExceptionHandler {

    @ExceptionHandler(ApiException::class)
    fun handleApiException(ex: ApiException): ProblemDetail {
        val detail = ProblemDetail.forStatusAndDetail(ex.status, ex.message ?: "Unexpected error")
        detail.title = ex.status.reasonPhrase
        return detail
    }

    @ExceptionHandler(
        MethodArgumentNotValidException::class,
        BindException::class,
        ConstraintViolationException::class
    )
    fun handleValidationException(ex: Exception): ProblemDetail {
        val detail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Validation failed")
        detail.title = "Bad Request"
        return detail
    }

    @ExceptionHandler(Exception::class)
    fun handleUnexpected(ex: Exception): ProblemDetail {
        val detail = ProblemDetail.forStatusAndDetail(
            HttpStatus.INTERNAL_SERVER_ERROR,
            ex.message ?: "Unexpected internal error"
        )
        detail.title = "Internal Server Error"
        return detail
    }
}