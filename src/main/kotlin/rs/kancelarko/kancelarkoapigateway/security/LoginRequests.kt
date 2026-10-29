package rs.kancelarko.kancelarkoapigateway.security

import org.springframework.beans.factory.annotation.Value
import org.springframework.data.redis.core.ReactiveStringRedisTemplate
import org.springframework.http.ResponseCookie
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.io.Serializable
import java.security.SecureRandom
import java.time.Duration
import java.util.Base64

/**
 * Započete prijave na k-auth-u, u Redis-u po `state` (10 min), a ne u sesiji gateway-a:
 *
 *   k-gateway:login:{state}   zahtev za prijavu + browser + adresa aplikacije za povratak
 *
 * U sesiji su se gubile: posle odjave više tabova istovremeno pravi novu sesiju (tab koji se vraća na prijavu,
 * popup za prijavu u drugom tabu), a browser zadrži samo poslednji Set-Cookie, pa povratak sa k-auth-a u
 * ostalima završi sa `authorization_request_not_found`.
 *
 * Prijava je vezana za browser cookie-jem `K_GATEWAY_BROWSER` (HttpOnly, samo host gateway-a, odjava ga ne
 * briše): povratak sa tuđim `state`-om ne prolazi (login CSRF). Adresa za povratak stiže kao `returnTo` na
 * početak prijave (entry point je dodaje) i prihvata se samo ako je adresa aplikacije ([AppUrls]).
 */
@Component
class LoginRequests(
    private val redis: ReactiveStringRedisTemplate,
    private val appUrls: AppUrls,
    @Value("\${server.reactive.session.cookie.secure:true}") private val secure: Boolean,
) : ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private val random = SecureRandom()

    override fun saveAuthorizationRequest(authorizationRequest: OAuth2AuthorizationRequest, exchange: ServerWebExchange): Mono<Void> {
        val state = authorizationRequest.state ?: return Mono.empty()
        val browser = browserOf(exchange) ?: newBrowserId().also { writeBrowserCookie(exchange, it) }
        val returnTo = exchange.request.queryParams.getFirst(RETURN_TO)?.takeIf(appUrls::isAppUrl)
        val pending = Pending(browser, returnTo, authorizationRequest)

        return redis.opsForValue().set(key(state), encode(pending), TTL).then()
    }

    override fun loadAuthorizationRequest(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest> =
        find(exchange) { redis.opsForValue().get(it) }.map { it.request }

    /** Pri povratku sa k-auth-a (jednom): zahtev se briše, a adresa za povratak ostaje na zahtevu za [returnTo]. */
    override fun removeAuthorizationRequest(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest> =
        find(exchange) { redis.opsForValue().getAndDelete(it) }.map { pending ->
            pending.returnTo?.let { exchange.attributes[RETURN_TO_ATTRIBUTE] = it }
            pending.request
        }

    /** Adresa aplikacije sa koje je prijava počela (posle [removeAuthorizationRequest] na istom zahtevu). */
    fun returnTo(exchange: ServerWebExchange): String? = exchange.getAttribute<String>(RETURN_TO_ATTRIBUTE)?.takeIf(appUrls::isAppUrl)

    private fun find(exchange: ServerWebExchange, read: (String) -> Mono<String>): Mono<Pending> {
        val state = exchange.request.queryParams.getFirst(OAuth2ParameterNames.STATE) ?: return Mono.empty()
        val browser = browserOf(exchange) ?: return Mono.empty()

        return read(key(state)).mapNotNull { decode(it) }.filter { it.browser == browser }
    }

    private fun browserOf(exchange: ServerWebExchange): String? =
        exchange.request.cookies.getFirst(BROWSER_COOKIE)?.value?.takeIf { it.length in 16..64 }

    private fun writeBrowserCookie(exchange: ServerWebExchange, value: String) {
        exchange.response.addCookie(
            ResponseCookie.from(BROWSER_COOKIE, value)
                .path("/bff")
                .httpOnly(true)
                .secure(secure)
                .sameSite("Lax")
                .maxAge(BROWSER_COOKIE_AGE)
                .build(),
        )
    }

    private fun newBrowserId(): String = ByteArray(24).also(random::nextBytes).let(Base64.getUrlEncoder().withoutPadding()::encodeToString)

    private fun key(state: String) = "$PREFIX:$state"

    // Zahtev je Serializable (Spring ga i inače tako čuva u sesiji); Redis je samo gateway-a.
    private fun encode(pending: Pending): String =
        ByteArrayOutputStream().use { bytes ->
            ObjectOutputStream(bytes).use { it.writeObject(pending) }
            Base64.getEncoder().encodeToString(bytes.toByteArray())
        }

    private fun decode(value: String): Pending? =
        runCatching { ObjectInputStream(ByteArrayInputStream(Base64.getDecoder().decode(value))).use { it.readObject() as Pending } }.getOrNull()

    private class Pending(
        val browser: String,
        val returnTo: String?,
        val request: OAuth2AuthorizationRequest,
    ) : Serializable

    companion object {
        const val RETURN_TO = "returnTo"
        const val BROWSER_COOKIE = "K_GATEWAY_BROWSER"
        private const val PREFIX = "k-gateway:login"
        private const val RETURN_TO_ATTRIBUTE = "K_GATEWAY_RETURN_TO"
        private val TTL: Duration = Duration.ofMinutes(10)
        private val BROWSER_COOKIE_AGE: Duration = Duration.ofDays(365)
    }
}
