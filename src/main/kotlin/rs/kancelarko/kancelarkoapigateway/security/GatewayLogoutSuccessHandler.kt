package rs.kancelarko.kancelarkoapigateway.security

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono

/**
 * Posle lokalne odjave šalje browser na odjavu u k-auth-u (RP-Initiated Logout).
 *
 * k-auth zna samo za jednu adresu za povratak (`/bff/logged-out` na gateway-u); aplikacija sa koje
 * je korisnik kliknuo "Odjava" putuje kroz `state`, koji k-auth vraća nepromenjen.
 */
class GatewayLogoutSuccessHandler(
    private val auth: KAuthProperties,
    private val gateway: GatewayProperties,
) : ServerLogoutSuccessHandler {

    private val redirectStrategy = DefaultServerRedirectStrategy()

    override fun onLogoutSuccess(exchange: WebFilterExchange, authentication: Authentication): Mono<Void> {
        val request = exchange.exchange.request
        val appUrl = UriComponentsBuilder.fromUri(request.uri).replacePath("/").replaceQuery(null).build().toUriString()
        val idToken = (authentication.principal as? OidcUser)?.idToken?.tokenValue

        val location = UriComponentsBuilder.fromUriString("${auth.issuer}/oauth/logout")
            .queryParam("client_id", auth.client.id)
            .queryParam("post_logout_redirect_uri", "${gateway.publicUrl}$LOGGED_OUT_PATH")
            .apply { if (idToken != null) queryParam("id_token_hint", idToken) }
            .apply { if (gateway.isAppUrl(appUrl)) queryParam("state", appUrl) }
            .encode()
            .build()
            .toUri()

        return redirectStrategy.sendRedirect(exchange.exchange, location)
    }

    companion object {
        const val LOGGED_OUT_PATH = "/bff/logged-out"
    }
}
