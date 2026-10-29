package rs.kancelarko.kancelarkoapigateway.gateway

import org.springframework.cloud.gateway.route.Route
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import rs.kancelarko.kancelarkoapigateway.security.SessionMarker

/**
 * Razlozi odbijanja u telu odgovora (`{"error": …, "reason": …}`), da browser klijent zna šta se desilo.
 */
object RejectReason {
    const val NO_SESSION = "no_session"
    const val SESSION_REVOKED = "session_revoked"
    const val REFRESH_FAILED = "refresh_failed"
    const val INVALID_TOKEN = "invalid_token"
    const val USER_CHANGED = "user_changed"
    const val CROSS_ORIGIN = "cross_origin"
    const val RATE_LIMITED = "rate_limited"
    const val REVOCATION_UNAVAILABLE = "revocation_unavailable"
}

/**
 * Ruta bez prijave (`metadata.public=true`), npr. JWKS: ne proveravaju se token ni `aud`.
 */
internal fun isPublicRoute(exchange: ServerWebExchange): Boolean =
    exchange.getAttribute<Route>(GATEWAY_ROUTE_ATTR)?.metadata?.get("public")?.toString() == "true"

/**
 * 401 uz gašenje sesije gateway-a (ako postoji) i brisanje `K_GATEWAY_STATE`, da sledeća navigacija
 * browsera ode na prijavu, a ostali tabovi i aplikacije odmah vide odjavu.
 */
internal fun rejectUnauthorized(exchange: ServerWebExchange, reason: String, marker: SessionMarker): Mono<Void> =
    exchange.session
        .flatMap { it.invalidate() }
        .then(
            Mono.defer {
                marker.clear(exchange)
                reject(exchange, HttpStatus.UNAUTHORIZED, "invalid_token", reason, bearer = true)
            },
        )

internal fun rejectForbidden(exchange: ServerWebExchange): Mono<Void> =
    reject(exchange, HttpStatus.FORBIDDEN, "insufficient_scope", null, bearer = true)

/**
 * Odbijanje sa JSON telom; `bearer` dodaje i `WWW-Authenticate` (RFC 6750). Vrednosti su konstante, bez escape-ovanja.
 */
internal fun reject(exchange: ServerWebExchange, status: HttpStatus, error: String, reason: String?, bearer: Boolean = false): Mono<Void> {
    val response = exchange.response
    response.statusCode = status
    response.headers.contentType = MediaType.APPLICATION_JSON
    response.headers.cacheControl = "no-store"
    if (bearer) {
        response.headers.set(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"$error\"" + (reason?.let { ", error_description=\"$it\"" } ?: ""))
    }
    val body = "{\"error\":\"$error\"" + (reason?.let { ",\"reason\":\"$it\"" } ?: "") + "}"

    return response.writeWith(Mono.just(response.bufferFactory().wrap(body.toByteArray())))
}
