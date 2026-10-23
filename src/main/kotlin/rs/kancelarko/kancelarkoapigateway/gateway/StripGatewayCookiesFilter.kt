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

/**
 * Cookie sesije gateway-a ne ide aplikacijama (nosi pristup tokenima); ostali cookie-ji
 * (npr. Laravel sesija aplikacije) prolaze.
 */
@Component
class StripGatewayCookiesFilter(
    @Value("\${server.reactive.session.cookie.name:SESSION}") private val sessionCookieName: String,
) : GlobalFilter, Ordered {

    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        val cookies = exchange.request.headers[HttpHeaders.COOKIE] ?: return chain.filter(exchange)
        val kept = cookies
            .flatMap { it.split(';') }
            .map { it.trim() }
            .filter { it.isNotEmpty() && it.substringBefore('=') != sessionCookieName }

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
