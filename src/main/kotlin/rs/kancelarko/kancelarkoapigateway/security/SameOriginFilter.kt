package rs.kancelarko.kancelarkoapigateway.security

import org.springframework.beans.factory.annotation.Value
import org.springframework.core.Ordered
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import rs.kancelarko.kancelarkoapigateway.gateway.RejectReason
import rs.kancelarko.kancelarkoapigateway.gateway.reject
import java.net.URI

/**
 * Zahtev koji menja stanje (POST, PUT, PATCH, DELETE) sa cookie-jem sesije gateway-a mora doći sa iste
 * adrese (origin) na koju ide; inače 403.
 *
 * Sve aplikacije su poddomeni istog sajta, pa `SameSite=Lax` cookie ide i uz zahtev koji jedna aplikacija
 * pošalje drugoj (npr. XSS u jednoj → POST u drugu, ili tuđa forma na `/logout`).
 *
 * Prvo se gleda `Sec-Fetch-Site` (postavlja ga browser, strana ne može da ga promeni): prolaze samo
 * `same-origin` i `none` (korisnik sam otvorio adresu). Tek kad ga nema (stariji browser), `Origin` mora biti
 * isti kao adresa zahteva. Na `Origin` se ne može osloniti uvek: uz `Referrer-Policy: no-referrer` (Spring
 * Security ga stavlja na sve odgovore, i strane aplikacija) browser i za formu sa iste strane šalje `Origin: null`.
 * Zahtev bez oba zaglavlja ne dolazi iz browser-a sa tuđe strane (server-server, back-channel odjava,
 * interni poziv gateway-a), pa prolazi.
 */
@Component
class SameOriginFilter(
    @Value("\${server.reactive.session.cookie.name:SESSION}") private val sessionCookieName: String,
) : WebFilter, Ordered {

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        val request = exchange.request
        if (request.method !in UNSAFE_METHODS || !request.cookies.containsKey(sessionCookieName) || isSameOrigin(request)) {
            return chain.filter(exchange)
        }

        return reject(exchange, HttpStatus.FORBIDDEN, "forbidden", RejectReason.CROSS_ORIGIN)
    }

    // Pre Spring Security-ja (-100), da tuđ POST na /logout ne stigne do odjave.
    override fun getOrder(): Int = -200

    private fun isSameOrigin(request: ServerHttpRequest): Boolean {
        val site = request.headers.getFirst(SEC_FETCH_SITE)
        if (site != null) {
            return site == "same-origin" || site == "none"
        }
        val origin = request.headers.origin ?: return true

        return origin(runCatching { URI(origin) }.getOrNull()) == origin(request.uri)
    }

    // scheme://host[:port], bez podrazumevanog porta; null za "null" i neispravne vrednosti.
    private fun origin(uri: URI?): String? {
        val scheme = uri?.scheme?.lowercase() ?: return null
        val host = uri.host?.lowercase() ?: return null
        val port = uri.port.takeUnless { it == -1 || it == DEFAULT_PORTS[scheme] }

        return "$scheme://$host" + (port?.let { ":$it" } ?: "")
    }

    private companion object {
        const val SEC_FETCH_SITE = "Sec-Fetch-Site"
        val UNSAFE_METHODS = setOf(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE)
        val DEFAULT_PORTS = mapOf("http" to 80, "https" to 443)
    }
}
