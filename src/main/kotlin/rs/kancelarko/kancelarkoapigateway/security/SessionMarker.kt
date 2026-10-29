package rs.kancelarko.kancelarkoapigateway.security

import org.springframework.beans.factory.annotation.Value
import org.springframework.http.ResponseCookie
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebSession
import reactor.core.publisher.Mono
import java.security.SecureRandom
import java.time.Duration
import java.util.Base64

/**
 * Cookie `K_GATEWAY_STATE`: nasumična vrednost po prijavi, za ceo roditeljski domen, čitljiva iz JS-a.
 * Ne nosi nikakav pristup (sesija je u `K_GATEWAY_SESSION`, HttpOnly).
 *
 * Browser klijent (`/bff/sdk.js`) ga gleda svake sekunde, bez poziva gateway-u: nestao znači odjavu,
 * promenjen znači novu prijavu (možda drugog korisnika), u bilo kojoj aplikaciji i bilo kom tabu.
 * Odjavu preko back-channel-a (bez browser-a) ne vidi; nju klijent hvata preko `/bff/session`.
 */
@Component
class SessionMarker(
    gateway: GatewayProperties,
    @Value("\${server.reactive.session.cookie.secure:true}") private val secure: Boolean,
) {

    private val domain = gateway.parentDomain

    private val random = SecureRandom()

    /** Posle prijave: nova vrednost u sesiji i u cookie-ju. */
    fun start(exchange: ServerWebExchange): Mono<Void> =
        exchange.session.doOnNext { session ->
            val value = newValue()
            session.attributes[ATTRIBUTE] = value
            write(exchange, value, null)
        }.then()

    /** Cookie usklađen sa sesijom (npr. sesija nastala pre uvođenja cookie-ja ili ga je browser obrisao). */
    fun sync(exchange: ServerWebExchange, session: WebSession) {
        val value = session.getAttribute<String>(ATTRIBUTE) ?: newValue().also { session.attributes[ATTRIBUTE] = it }
        if (exchange.request.cookies.getFirst(NAME)?.value != value) {
            write(exchange, value, null)
        }
    }

    fun clear(exchange: ServerWebExchange) {
        if (exchange.request.cookies.containsKey(NAME)) {
            write(exchange, "", Duration.ZERO)
        }
    }

    private fun write(exchange: ServerWebExchange, value: String, maxAge: Duration?) {
        val cookie = ResponseCookie.from(NAME, value)
            .domain(domain)
            .path("/")
            .secure(secure)
            .httpOnly(false)
            .sameSite("Lax")
            .apply { if (maxAge != null) maxAge(maxAge) }
            .build()
        exchange.response.addCookie(cookie)
    }

    private fun newValue(): String = ByteArray(16).also(random::nextBytes).let(Base64.getUrlEncoder().withoutPadding()::encodeToString)

    companion object {
        const val NAME = "K_GATEWAY_STATE"
        private const val ATTRIBUTE = "K_GATEWAY_STATE"
    }
}
