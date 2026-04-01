package ru.mephi.abondarenko.auth.factor.qr.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.scheduling.annotation.EnableScheduling
import java.time.Clock

@Configuration
@EnableScheduling
class AppConfig {

    @Bean
    fun clock(): Clock = Clock.systemUTC()
}
