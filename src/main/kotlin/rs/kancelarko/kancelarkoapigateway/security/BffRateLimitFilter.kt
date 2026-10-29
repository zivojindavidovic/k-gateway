package rs.kancelarko.kancelarkoapigateway.security

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.core.Ordered
import org.springframework.data.redis.core.ReactiveStringRedisTemplate
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import org.springframework.web.util.pattern.PathPattern
import org.springframework.web.util.pattern.PathPatternParser
import reactor.core.publisher.Mono
import rs.kancelarko.kancelarkoapigateway.gateway.RejectReason
import rs.kancelarko.kancelarkoapigateway.gateway.reject
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.util.HexFormat

/**
 * Ograničenje broja zahteva ka putanjama gateway-a, fiksni prozor od minut u Redis-u (deli se između instanci):
 *
 *   k-gateway:rate:{pravilo}:{ključ}:{minut}   brojač, ističe posle 70 s
 *
 * Ključ je adresa klijenta, a za `/bff/session` sesija (iza jedne adrese kancelarije je mnogo korisnika).
 * Id sesije ide u ključ samo kao heš. Kad Redis ne radi, zahtev prolazi.
 */
@Component
class BffRateLimitFilter(
    private val redis: ReactiveStringRedisTemplate,
    gateway: GatewayProperties,
    @Value("\${server.reactive.session.cookie.name:SESSION}") private val sessionCookieName: String,
) : WebFilter, Ordered {

    private val log = LoggerFactory.getLogger(javaClass)

    private val settings = gateway.rateLimit

    private val rules = PathPatternParser.defaultInstance.let { parser ->
        listOf(
            Rule("login", settings.loginPerMinute, false, listOf("/bff/login", "/bff/oauth2/authorization/**", "/bff/login/oauth2/code/**").map(parser::parse)),
            Rule("session", settings.sessionPerMinute, true, listOf(parser.parse("/bff/session"))),
            Rule("logout", settings.logoutPerMinute, false, listOf(parser.parse("/logout"))),
        )
    }

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        val path = exchange.request.path.pathWithinApplication()
        val rule = rules.firstOrNull { rule -> rule.patterns.any { it.matches(path) } }
        if (!settings.enabled || rule == null) {
            return chain.filter(exchange)
        }
        val minute = Instant.now().epochSecond / 60
        val key = "$PREFIX:${rule.name}:${clientKey(exchange, rule.perSession)}:$minute"

        return redis.opsForValue().increment(key)
            .flatMap { count -> if (count == 1L) redis.expire(key, WINDOW_TTL).thenReturn(count) else Mono.just(count) }
            .timeout(REDIS_TIMEOUT)
            .onErrorResume { ex ->
                log.warn("Ograničenje zahteva nije provereno (Redis): {}", ex.toString())
                Mono.just(0L)
            }
            .flatMap { count ->
                if (count <= rule.perMinute) {
                    chain.filter(exchange)
                } else {
                    exchange.response.headers.set("Retry-After", (60 - Instant.now().epochSecond % 60).toString())
                    reject(exchange, HttpStatus.TOO_MANY_REQUESTS, "too_many_requests", RejectReason.RATE_LIMITED)
                }
            }
    }

    // Pre provere istog origin-a i Spring Security-ja.
    override fun getOrder(): Int = -210

    private fun clientKey(exchange: ServerWebExchange, perSession: Boolean): String {
        val session = exchange.request.cookies.getFirst(sessionCookieName)?.value
        if (perSession && !session.isNullOrEmpty()) {
            return "s-" + sha256(session)
        }
        val ip = exchange.request.headers.getFirst(settings.clientIpHeader)?.trim()?.takeIf { it.isNotEmpty() }
            ?: exchange.request.remoteAddress?.address?.hostAddress
            ?: "unknown"

        return "ip-$ip"
    }

    private fun sha256(value: String): String =
        HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.toByteArray())).take(32)

    private data class Rule(
        val name: String,
        val perMinute: Long,
        val perSession: Boolean,
        val patterns: List<PathPattern>,
    )

    private companion object {
        const val PREFIX = "k-gateway:rate"
        val WINDOW_TTL: Duration = Duration.ofSeconds(70)
        val REDIS_TIMEOUT: Duration = Duration.ofMillis(300)
    }
}
