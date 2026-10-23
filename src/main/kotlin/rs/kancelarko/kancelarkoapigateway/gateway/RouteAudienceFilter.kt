package rs.kancelarko.kancelarkoapigateway.gateway

import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.cloud.gateway.route.Route
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR
import org.springframework.core.Ordered
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import rs.kancelarko.kancelarkoapigateway.security.KAuthProperties

/**
 * Sme li token na ovu rutu: `aud` tokena (klijent kome je izdat) mora biti u metapodacima rute
 * `audiences`. Ruta bez `audiences` ne prima nikog, osim javne (`metadata.public=true`).
 *
 * Kod prijave preko gateway-a (BFF) token je izdat samom gateway-u, pa se gleda njegov client_id.
 */
@Component
class RouteAudienceFilter(
    private val properties: KAuthProperties,
) : GlobalFilter, Ordered {

    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        val route = exchange.getAttribute<Route>(GATEWAY_ROUTE_ATTR) ?: return chain.filter(exchange)
        if (isPublicRoute(exchange)) {
            return chain.filter(exchange)
        }
        val allowed = allowedAudiences(route)

        return exchange.getPrincipal<Authentication>()
            .map { audiencesOf(it) }
            .defaultIfEmpty(emptyList())
            .flatMap { audiences ->
                if (audiences.any { it in allowed }) chain.filter(exchange) else rejectForbidden(exchange)
            }
    }

    override fun getOrder(): Int = Ordered.HIGHEST_PRECEDENCE + 1

    private fun audiencesOf(authentication: Authentication): List<String> = when (authentication) {
        is JwtAuthenticationToken -> authentication.token.audience.orEmpty()
        is OAuth2AuthenticationToken -> listOf(properties.client.id)
        else -> emptyList()
    }

    private fun allowedAudiences(route: Route): Set<String> = when (val value = route.metadata[AUDIENCES]) {
        is String -> value.split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        is Map<*, *> -> value.values.map { it.toString() }.toSet()
        is Collection<*> -> value.map { it.toString() }.toSet()
        else -> emptySet()
    }

    private companion object {
        const val AUDIENCES = "audiences"
    }
}
