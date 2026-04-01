package ru.mephi.abondarenko.auth.factor.qr.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter

@Configuration
class SecurityConfig(
    private val apiKeySecurityFilter: ApiKeySecurityFilter
) {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .httpBasic { it.disable() }
            .formLogin { it.disable() }
            .logout { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .authorizeHttpRequests {
                it.requestMatchers("/actuator/health", "/actuator/info").permitAll()
                it.requestMatchers("/api/v1/device/**").permitAll()
                it.requestMatchers("/api/**", "/actuator/**").authenticated()
                it.anyRequest().permitAll()
            }
            .addFilterBefore(apiKeySecurityFilter, AnonymousAuthenticationFilter::class.java)
            .anonymous(Customizer.withDefaults())

        return http.build()
    }
}
