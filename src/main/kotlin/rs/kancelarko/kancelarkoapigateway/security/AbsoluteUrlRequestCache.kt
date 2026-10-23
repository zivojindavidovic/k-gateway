package rs.kancelarko.kancelarkoapigateway.security

import org.springframework.http.HttpMethod
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.net.URI

/**
 * Pamti ceo URL zahteva (sa hostom aplikacije), ne samo putanju kao podrazumevani
 * WebSessionServerRequestCache: prijava se završava na hostu gateway-a, a korisnik treba
 * da se vrati na aplikaciju sa koje je došao. Pamte se samo GET zahtevi ka aplikacijama.
 */
class AbsoluteUrlRequestCache(
    private val gateway: GatewayProperties,
) : ServerRequestCache {

    override fun saveRequest(exchange: ServerWebExchange): Mono<Void> {
        val url = exchange.request.uri.toString()
        if (exchange.request.method != HttpMethod.GET || !gateway.isAppUrl(url)) {
            return Mono.empty()
        }

        return exchange.session.doOnNext { it.attributes[ATTRIBUTE] = url }.then()
    }

    override fun getRedirectUri(exchange: ServerWebExchange): Mono<URI> =
        exchange.session.mapNotNull { session ->
            session.getAttribute<String>(ATTRIBUTE)?.takeIf { gateway.isAppUrl(it) }?.let(URI::create)
        }

    override fun removeMatchingRequest(exchange: ServerWebExchange): Mono<ServerHttpRequest> =
        exchange.session.mapNotNull { session ->
            if (session.getAttribute<String>(ATTRIBUTE) == exchange.request.uri.toString()) {
                session.attributes.remove(ATTRIBUTE)
                exchange.request
            } else {
                null
            }
        }

    private companion object {
        const val ATTRIBUTE = "K_GATEWAY_SAVED_URL"
    }
}
