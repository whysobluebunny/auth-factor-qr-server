package ru.mephi.abondarenko.auth.factor.qr.config

import jakarta.annotation.PostConstruct
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.MediaType
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import ru.mephi.abondarenko.auth.factor.qr.api.error.InternalConfigurationException
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

@Component
class ApiKeySecurityFilter(
    private val properties: AuthFactorProperties
) : OncePerRequestFilter() {

    @PostConstruct
    fun validateConfiguration() {
        if (properties.apiKeyHeaderName.isBlank()) {
            throw InternalConfigurationException("app.auth-factor.api-key-header-name must not be blank")
        }
        if (properties.apiKey.isBlank() || properties.apiKey.startsWith("REPLACE_WITH")) {
            throw InternalConfigurationException("AUTH_FACTOR_API_KEY must be configured with a non-placeholder value")
        }
    }

    override fun shouldNotFilter(request: HttpServletRequest): Boolean {
        val path = request.requestURI
        if (path == "/error" || path == "/actuator/health" || path == "/actuator/info") {
            return true
        }
        return !path.startsWith("/api/") && !path.startsWith("/actuator/")
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val providedApiKey = request.getHeader(properties.apiKeyHeaderName)
        if (!apiKeyMatches(providedApiKey)) {
            response.status = HttpServletResponse.SC_UNAUTHORIZED
            response.contentType = MediaType.APPLICATION_JSON_VALUE
            response.writer.write("""{"title":"Unauthorized","status":401,"detail":"Missing or invalid API key"}""")
            return
        }

        val authentication = UsernamePasswordAuthenticationToken(
            "integration-client",
            providedApiKey,
            listOf(SimpleGrantedAuthority("ROLE_API_CLIENT"))
        )
        SecurityContextHolder.getContext().authentication = authentication

        try {
            filterChain.doFilter(request, response)
        } finally {
            SecurityContextHolder.clearContext()
        }
    }

    private fun apiKeyMatches(providedApiKey: String?): Boolean {
        if (providedApiKey == null) {
            return false
        }

        val expectedBytes = properties.apiKey.toByteArray(StandardCharsets.UTF_8)
        val providedBytes = providedApiKey.toByteArray(StandardCharsets.UTF_8)
        return MessageDigest.isEqual(expectedBytes, providedBytes)
    }
}
