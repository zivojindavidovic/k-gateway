package rs.kancelarko.kancelarkoapigateway.gateway

import org.springframework.beans.factory.annotation.Value
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.cloud.gateway.filter.RouteToRequestUrlFilter
import org.springframework.core.Ordered
import org.springframework.http.HttpHeaders
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import rs.kancelarko.kancelarkoapigateway.security.SessionMarker

/**
 * Cookie-ji gateway-a ne idu aplikacijama: sesija (nosi pristup tokenima) i `K_GATEWAY_STATE`
 * (samo za browser klijent). Ostali cookie-ji (npr. Laravel sesija aplikacije) prolaze.
 */
@Component
class StripGatewayCookiesFilter(
    @Value("\${server.reactive.session.cookie.name:SESSION}") private val sessionCookieName: String,
) : GlobalFilter, Ordered {

    private val gatewayCookies = setOf(sessionCookieName, SessionMarker.NAME)

    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        val cookies = exchange.request.headers[HttpHeaders.COOKIE] ?: return chain.filter(exchange)
        val kept = cookies
            .flatMap { it.split(';') }
            .map { it.trim() }
            .filter { it.isNotEmpty() && it.substringBefore('=') !in gatewayCookies }

        return chain.filter(
            exchange.mutate()
                .request { request ->
                    request.headers { headers ->
                        if (kept.isEmpty()) headers.remove(HttpHeaders.COOKIE) else headers.set(HttpHeaders.COOKIE, kept.joinToString("; "))
                    }
                }
                .build(),
        )
    }

    override fun getOrder(): Int = RouteToRequestUrlFilter.ROUTE_TO_URL_FILTER_ORDER - 2
}
