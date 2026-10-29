package rs.kancelarko.kancelarkoapigateway.gateway

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.cloud.gateway.filter.RouteToRequestUrlFilter
import org.springframework.core.Ordered
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import rs.kancelarko.kancelarkoapigateway.security.RevocationList
import rs.kancelarko.kancelarkoapigateway.security.RevocationUnavailableException
import rs.kancelarko.kancelarkoapigateway.security.SessionMarker
import java.net.URLEncoder
import java.util.Optional

/**
 * Poslednja provera pre prosleđivanja aplikaciji, nad tokenom koji stvarno odlazi
 * (Bearer od klijenta ili token iz sesije koji je dodao TokenRelay, posle eventualnog osvežavanja):
 *
 * - opozvana sesija (`sid`) ili token (`jti`) u k-auth-u → 401; lista opoziva nedostupna (fail-closed) → 503;
 * - `X-Kancelarko-Sub` (korisnik za koga je strana učitana, šalje ga browser klijent) različit od `sub` tokena → 409:
 *   u drugom tabu se prijavio drugi korisnik ili ista osoba na drugu licencu, a zahtev bi otišao sa njegovim tokenom;
 * - zaglavlja samo za logove i prikaz (dolazna se uvek brišu): `X-User-Id` i `X-License-Id` iz tokena,
 *   `X-User-Name` i `X-User-Email` (percent-encoded UTF-8) iz prijave preko gateway-a.
 *
 * Potpis Bearer tokena je već proveren (resource server); token iz sesije je gateway sam dobio od k-auth-a.
 * Javne rute (`metadata.public=true`) se preskaču.
 */
@Component
class RelayedTokenFilter(
    private val revocations: RevocationList,
    private val marker: SessionMarker,
) : GlobalFilter, Ordered {

    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        if (isPublicRoute(exchange)) {
            return chain.filter(withoutUserHeaders(exchange))
        }
        val claims = bearerClaims(exchange) ?: return rejectUnauthorized(exchange, RejectReason.INVALID_TOKEN, marker)
        val expectedSubject = exchange.request.headers.getFirst(EXPECTED_SUBJECT_HEADER)
        if (expectedSubject != null && expectedSubject != claims.subject) {
            return reject(exchange, HttpStatus.CONFLICT, RejectReason.USER_CHANGED, null)
        }

        return revocations.isRevoked(claims.getStringClaim(SID), claims.jwtid)
            .flatMap { revoked ->
                if (revoked) {
                    rejectUnauthorized(exchange, RejectReason.SESSION_REVOKED, marker)
                } else {
                    exchange.getPrincipal<Authentication>()
                        .map { Optional.ofNullable(it.principal as? OidcUser) }
                        .defaultIfEmpty(Optional.empty())
                        .flatMap { user -> chain.filter(withUserHeaders(exchange, claims, user.orElse(null))) }
                }
            }
            .onErrorResume(RevocationUnavailableException::class.java) {
                reject(exchange, HttpStatus.SERVICE_UNAVAILABLE, "temporarily_unavailable", RejectReason.REVOCATION_UNAVAILABLE)
            }
    }

    // Posle filtera ruta (TokenRelay), pre određivanja adrese aplikacije.
    override fun getOrder(): Int = RouteToRequestUrlFilter.ROUTE_TO_URL_FILTER_ORDER - 1

    private fun bearerClaims(exchange: ServerWebExchange): JWTClaimsSet? {
        val authorization = exchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION) ?: return null
        if (!authorization.startsWith(BEARER, ignoreCase = true)) {
            return null
        }

        return runCatching { JWTParser.parse(authorization.substring(BEARER.length)).jwtClaimsSet }.getOrNull()
    }

    private fun withUserHeaders(exchange: ServerWebExchange, claims: JWTClaimsSet, user: OidcUser?): ServerWebExchange =
        exchange.mutate()
            .request { request ->
                request.headers { headers ->
                    REMOVED_HEADERS.forEach(headers::remove)
                    claims.getClaim(USER_ID)?.let { headers.set(USER_ID_HEADER, it.toString()) }
                    claims.getClaim(LICENSE_ID)?.let { headers.set(LICENSE_ID_HEADER, it.toString()) }
                    user?.fullName?.let { headers.set(USER_NAME_HEADER, encode(it)) }
                    user?.email?.let { headers.set(USER_EMAIL_HEADER, encode(it)) }
                }
            }
            .build()

    private fun withoutUserHeaders(exchange: ServerWebExchange): ServerWebExchange =
        exchange.mutate().request { request -> request.headers { headers -> REMOVED_HEADERS.forEach(headers::remove) } }.build()

    // Zaglavlja su ASCII; imena imaju naša slova.
    private fun encode(value: String) = URLEncoder.encode(value, Charsets.UTF_8).replace("+", "%20")

    private companion object {
        const val BEARER = "Bearer "
        const val SID = "sid"
        const val USER_ID = "user_id"
        const val LICENSE_ID = "license_id"
        const val USER_ID_HEADER = "X-User-Id"
        const val LICENSE_ID_HEADER = "X-License-Id"
        const val USER_NAME_HEADER = "X-User-Name"
        const val USER_EMAIL_HEADER = "X-User-Email"
        const val EXPECTED_SUBJECT_HEADER = "X-Kancelarko-Sub"
        val REMOVED_HEADERS = listOf(USER_ID_HEADER, LICENSE_ID_HEADER, USER_NAME_HEADER, USER_EMAIL_HEADER, EXPECTED_SUBJECT_HEADER)
    }
}
