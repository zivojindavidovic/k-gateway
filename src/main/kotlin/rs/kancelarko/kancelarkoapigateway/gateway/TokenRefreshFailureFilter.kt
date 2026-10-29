package rs.kancelarko.kancelarkoapigateway.gateway

import org.slf4j.LoggerFactory
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.core.Ordered
import org.springframework.security.oauth2.client.ClientAuthorizationException
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import rs.kancelarko.kancelarkoapigateway.security.SessionMarker

/**
 * TokenRelay ne obrađuje neuspelo osvežavanje tokena (npr. refresh token opozvan ili istekao u k-auth-u),
 * pa bi zahtev završio sa 500. Umesto toga: 401 i gašenje sesije, da korisnik ponovo prođe kroz prijavu.
 */
@Component
class TokenRefreshFailureFilter(
    private val marker: SessionMarker,
) : GlobalFilter, Ordered {

    private val log = LoggerFactory.getLogger(javaClass)

    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> =
        chain.filter(exchange).onErrorResume(ClientAuthorizationException::class.java) { ex ->
            log.info("Osvežavanje tokena nije uspelo ({}), sesija se gasi", ex.error.errorCode)
            rejectUnauthorized(exchange, RejectReason.REFRESH_FAILED, marker)
        }

    override fun getOrder(): Int = Ordered.HIGHEST_PRECEDENCE
}
