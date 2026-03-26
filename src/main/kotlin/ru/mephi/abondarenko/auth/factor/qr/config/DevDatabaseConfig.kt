package ru.mephi.abondarenko.auth.factor.qr.config

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.testcontainers.service.connection.ServiceConnection
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.testcontainers.containers.PostgreSQLContainer

@Configuration(proxyBeanMethods = false)
@Profile("dev")
@ConditionalOnProperty(name = ["spring.testcontainers.enabled"], matchIfMissing = true)
class DevDatabaseConfig {

    @Bean
    @ServiceConnection
    fun postgresContainer(): PostgreSQLContainer<*> =
        PostgreSQLContainer("postgres:18-alpine")
            .withDatabaseName("auth_factor_qr")
            .withUsername("auth_factor_qr")
            .withPassword("auth_factor_qr")
}
