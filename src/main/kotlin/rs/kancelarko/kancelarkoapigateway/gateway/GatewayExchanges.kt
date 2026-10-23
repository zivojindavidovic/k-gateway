package rs.kancelarko.kancelarkoapigateway.gateway

import org.springframework.cloud.gateway.route.Route
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * Ruta bez prijave (`metadata.public=true`), npr. JWKS: ne proveravaju se token ni `aud`.
 */
internal fun isPublicRoute(exchange: ServerWebExchange): Boolean =
    exchange.getAttribute<Route>(GATEWAY_ROUTE_ATTR)?.metadata?.get("public")?.toString() == "true"

/**
 * 401 uz gašenje sesije gateway-a (ako postoji), da sledeća navigacija browsera ode na prijavu.
 */
internal fun rejectUnauthorized(exchange: ServerWebExchange): Mono<Void> =
    exchange.session
        .flatMap { it.invalidate() }
        .then(Mono.defer { reject(exchange, HttpStatus.UNAUTHORIZED, "invalid_token") })

internal fun rejectForbidden(exchange: ServerWebExchange): Mono<Void> =
    reject(exchange, HttpStatus.FORBIDDEN, "insufficient_scope")

private fun reject(exchange: ServerWebExchange, status: HttpStatus, bearerError: String): Mono<Void> {
    exchange.response.statusCode = status
    exchange.response.headers.set(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"$bearerError\"")
    return exchange.response.setComplete()
}
