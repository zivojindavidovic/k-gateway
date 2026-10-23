package rs.kancelarko.kancelarkoapigateway.security

import com.nimbusds.jwt.JWTParser
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.net.URI

/**
 * Putanje gateway-a koje važe na svakom hostu aplikacije (aplikacije ih ne dobijaju):
 *
 * - `/bff/login?returnTo=` — prijava sa stranice aplikacije; ruta je zaštićena, pa entry point
 *   vodi na k-auth i posle prijave vraća ovde, a odavde na `returnTo`;
 * - `/bff/logged-out?state=` — povratak sa odjave u k-auth-u na aplikaciju iz `state`;
 * - `/bff/session` — da li je korisnik prijavljen (za proveru iz JS-a aplikacije);
 * - `/account` — "Moj nalog" u k-auth-u, da aplikacija ne zna njegovu adresu.
 */
@RestController
class BffController(
    private val auth: KAuthProperties,
    private val gateway: GatewayProperties,
    private val authorizedClients: ServerOAuth2AuthorizedClientRepository,
) {

    @GetMapping("/bff/login")
    fun login(@RequestParam(required = false) returnTo: String?, exchange: ServerWebExchange): ResponseEntity<Void> =
        redirect(safeReturnTo(returnTo, exchange))

    @GetMapping(GatewayLogoutSuccessHandler.LOGGED_OUT_PATH)
    fun loggedOut(@RequestParam(required = false) state: String?): ResponseEntity<Void> =
        redirect(if (gateway.isAppUrl(state)) state!! else gateway.homeUrl)

    @GetMapping("/account")
    fun account(): ResponseEntity<Void> = redirect("${auth.issuer}/account")

    @GetMapping("/bff/session")
    fun session(exchange: ServerWebExchange): Mono<SessionResponse> =
        exchange.getPrincipal<Authentication>()
            .filter { it is OAuth2AuthenticationToken && it.isAuthenticated }
            .cast(OAuth2AuthenticationToken::class.java)
            .flatMap { authentication ->
                authorizedClients.loadAuthorizedClient<OAuth2AuthorizedClient>(authentication.authorizedClientRegistrationId, authentication, exchange)
                    .map { SessionResponse(true, sessionUser(authentication.principal as? OidcUser, it.accessToken.tokenValue)) }
            }
            .defaultIfEmpty(SessionResponse(false, null))

    // Putanja na istom hostu ili adresa aplikacije pod parentDomain; sve ostalo vodi na početnu.
    private fun safeReturnTo(returnTo: String?, exchange: ServerWebExchange): String {
        val isLocalPath = returnTo != null &&
            returnTo.startsWith("/") &&
            !returnTo.startsWith("//") &&
            !returnTo.contains('\\') &&
            returnTo.none { it.isISOControl() } &&
            runCatching { URI.create(returnTo) }.isSuccess

        return when {
            isLocalPath -> returnTo
            gateway.isAppUrl(returnTo) -> returnTo!!
            gateway.isAppUrl(exchange.request.uri.toString()) -> "/"
            else -> gateway.homeUrl
        }
    }

    private fun redirect(location: String): ResponseEntity<Void> =
        ResponseEntity.status(HttpStatus.FOUND).location(URI.create(location)).build()

    // Access token je gateway sam dobio od k-auth-a; ovde se samo čitaju claim-ovi za prikaz.
    private fun sessionUser(oidcUser: OidcUser?, accessToken: String): SessionUser {
        val claims = JWTParser.parse(accessToken).jwtClaimsSet

        return SessionUser(
            sub = claims.subject,
            licenseId = claims.getClaim("license_id"),
            userId = claims.getClaim("user_id"),
            role = claims.getClaim("role")?.toString(),
            modules = claims.getClaim("modules"),
            name = oidcUser?.fullName,
            email = oidcUser?.email,
        )
    }

    data class SessionResponse(
        val authenticated: Boolean,
        val user: SessionUser?,
    )

    data class SessionUser(
        val sub: String?,
        val licenseId: Any?,
        val userId: Any?,
        val role: String?,
        val modules: Any?,
        val name: String?,
        val email: String?,
    )
}
