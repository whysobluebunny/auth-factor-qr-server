package ru.mephi.abondarenko.auth.factor.qr

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan
import org.springframework.boot.runApplication

@SpringBootApplication
@ConfigurationPropertiesScan
class AuthFactorQrServerApplication

fun main(args: Array<String>) {
    runApplication<AuthFactorQrServerApplication>(*args)
}