package ru.mephi.abondarenko.auth.factor.qr.service

import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

@Service
class RateLimitService(
    private val clock: Clock
) {
    private val counters = ConcurrentHashMap<String, WindowCounter>()

    @Transactional(readOnly = true)
    fun tryAcquire(key: String, limit: Int, window: Duration): Boolean {
        require(limit > 0) { "limit must be positive" }
        require(!window.isNegative && !window.isZero) { "window must be positive" }

        val now = Instant.now(clock)
        synchronized(counters) {
            val current = counters[key]
            val updated = if (current == null || Duration.between(current.windowStart, now) >= window) {
                WindowCounter(windowStart = now, requestCount = 1)
            } else {
                if (current.requestCount >= limit) {
                    return false
                }
                current.copy(requestCount = current.requestCount + 1)
            }

            counters[key] = updated
            return true
        }
    }

    private data class WindowCounter(
        val windowStart: Instant,
        val requestCount: Int
    )
}
