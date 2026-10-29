package rs.kancelarko.kancelarkoapigateway.security

import com.nimbusds.jwt.JWTParser
import org.springframework.core.io.ClassPathResource
import org.springframework.http.CacheControl
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.ClientAuthorizationException
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import rs.kancelarko.kancelarkoapigateway.gateway.RejectReason
import java.net.URI
import java.security.MessageDigest
import java.util.Base64
import java.util.HexFormat

/**
 * Putanje gateway-a koje važe na svakom hostu aplikacije (aplikacije ih ne dobijaju):
 *
 * - `/bff/login?returnTo=` — prijava sa stranice aplikacije; ruta je zaštićena, pa entry point
 *   vodi na k-auth i posle prijave vraća ovde, a odavde na `returnTo`;
 * - `/bff/logged-out?state=` — povratak sa odjave u k-auth-u na aplikaciju iz `state`;
 * - `/bff/session` — da li je korisnik prijavljen, za browser klijent (vidi [session]);
 * - `/bff/popup-done` — kraj prijave u popup prozoru: javlja strani koja ga je otvorila i zatvara se;
 * - `/bff/sdk.js` — browser klijent (`src/main/frontend`), isti za sve aplikacije;
 * - `GET /logout` — potvrda odjave (odjava je samo POST, da je tuđ link ili slika ne pokrenu);
 * - `/account` — "Moj nalog" u k-auth-u, da aplikacija ne zna njegovu adresu.
 */
@RestController
class BffController(
    private val auth: KAuthProperties,
    private val gateway: GatewayProperties,
    private val appUrls: AppUrls,
    private val marker: SessionMarker,
    private val revocations: RevocationList,
    private val authorizedClientManager: ReactiveOAuth2AuthorizedClientManager,
) {

    private val sdk: ByteArray? = ClassPathResource(SDK_RESOURCE).takeIf { it.exists() }?.inputStream?.use { it.readAllBytes() }

    private val sdkEtag = sdk?.let { "\"" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(it)).take(32) + "\"" }

    @GetMapping("/bff/login")
    fun login(@RequestParam(required = false) returnTo: String?, exchange: ServerWebExchange): ResponseEntity<Void> =
        redirect(safeReturnTo(returnTo, exchange))

    @GetMapping(GatewayLogoutSuccessHandler.LOGGED_OUT_PATH)
    fun loggedOut(@RequestParam(required = false) state: String?): ResponseEntity<Void> =
        redirect(if (appUrls.isAppUrl(state)) state!! else gateway.homeUrl)

    @GetMapping("/account")
    fun account(): ResponseEntity<Void> = redirect("${auth.issuer}/account")

    /**
     * Stanje sesije kako ga vidi zahtev ka aplikaciji: access token se osvežava ako je pri isteku, a opozvana
     * sesija u k-auth-u se gasi odmah, ne tek kad stigne back-channel. Kad sesije nema, `reason` kaže zašto.
     *
     * Svaki poziv pomera istek neaktivnosti sesije gateway-a; zato ga browser klijent periodično zove
     * samo dok korisnik nešto radi na strani.
     */
    @GetMapping("/bff/session")
    fun session(exchange: ServerWebExchange): Mono<ResponseEntity<SessionResponse>> =
        exchange.getPrincipal<Authentication>()
            .filter { it is OAuth2AuthenticationToken && it.isAuthenticated }
            .cast(OAuth2AuthenticationToken::class.java)
            .flatMap { authenticated(it, exchange) }
            .switchIfEmpty(Mono.fromSupplier { anonymous(exchange, RejectReason.NO_SESSION) })

    @GetMapping("/bff/popup-done", produces = [MediaType.TEXT_HTML_VALUE])
    fun popupDone(): ResponseEntity<String> = html(POPUP_DONE_PAGE, "default-src 'none'; script-src '$POPUP_SCRIPT_HASH'")

    @GetMapping("/logout", produces = [MediaType.TEXT_HTML_VALUE])
    fun logoutConfirm(): ResponseEntity<String> = html(LOGOUT_PAGE, "default-src 'none'; style-src 'unsafe-inline'")

    @GetMapping("/bff/sdk.js")
    fun sdk(exchange: ServerWebExchange): ResponseEntity<ByteArray> {
        val etag = sdkEtag ?: return ResponseEntity.notFound().build()
        // Bez dugog keša: izmena gateway-a odmah stiže u sve aplikacije; ETag štedi prenos.
        if (exchange.checkNotModified(etag)) {
            return ResponseEntity.status(HttpStatus.NOT_MODIFIED).eTag(etag).build()
        }

        return ResponseEntity.ok()
            .contentType(JAVASCRIPT)
            .eTag(etag)
            .cacheControl(CacheControl.noCache())
            .header("X-Content-Type-Options", "nosniff")
            .body(sdk)
    }

    private fun authenticated(authentication: OAuth2AuthenticationToken, exchange: ServerWebExchange): Mono<ResponseEntity<SessionResponse>> {
        val request = OAuth2AuthorizeRequest.withClientRegistrationId(authentication.authorizedClientRegistrationId)
            .principal(authentication)
            .attribute(ServerWebExchange::class.java.name, exchange)
            .build()

        return authorizedClientManager.authorize(request)
            .flatMap { client -> verified(authentication, client, exchange) }
            .switchIfEmpty(Mono.defer { ended(exchange, RejectReason.NO_SESSION) })
            .onErrorResume(ClientAuthorizationRequiredException::class.java) { ended(exchange, RejectReason.NO_SESSION) }
            .onErrorResume(ClientAuthorizationException::class.java) { ended(exchange, RejectReason.REFRESH_FAILED) }
            .onErrorResume(RevocationUnavailableException::class.java) {
                Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).cacheControl(CacheControl.noStore()).build())
            }
    }

    private fun verified(
        authentication: OAuth2AuthenticationToken,
        client: OAuth2AuthorizedClient,
        exchange: ServerWebExchange,
    ): Mono<ResponseEntity<SessionResponse>> {
        val claims = JWTParser.parse(client.accessToken.tokenValue).jwtClaimsSet
        val sid = claims.getStringClaim("sid")

        return revocations.isRevoked(sid, claims.jwtid).flatMap { revoked ->
            if (revoked) {
                ended(exchange, RejectReason.SESSION_REVOKED)
            } else {
                exchange.session.map { session ->
                    marker.sync(exchange, session)
                    val oidcUser = authentication.principal as? OidcUser
                    // Access token je gateway sam dobio od k-auth-a; ovde se samo čitaju claim-ovi za prikaz.
                    val user = SessionUser(
                        sub = claims.subject,
                        sid = sid,
                        licenseId = claims.getClaim("license_id"),
                        userId = claims.getClaim("user_id"),
                        role = claims.getClaim("role")?.toString(),
                        modules = claims.getClaim("modules"),
                        name = oidcUser?.fullName,
                        email = oidcUser?.email,
                    )
                    val info = SessionInfo(
                        authTime = oidcUser?.authenticatedAt?.epochSecond,
                        accessTokenExpiresAt = client.accessToken.expiresAt?.epochSecond,
                        idleTimeout = session.maxIdleTime.seconds,
                    )
                    noStore(SessionResponse(authenticated = true, reason = null, user = user, session = info))
                }
            }
        }
    }

    private fun ended(exchange: ServerWebExchange, reason: String): Mono<ResponseEntity<SessionResponse>> =
        exchange.session
            .flatMap { it.invalidate() }
            .then(Mono.fromSupplier { anonymous(exchange, reason) })

    private fun anonymous(exchange: ServerWebExchange, reason: String): ResponseEntity<SessionResponse> {
        marker.clear(exchange)
        return noStore(SessionResponse(authenticated = false, reason = reason, user = null, session = null))
    }

    private fun noStore(body: SessionResponse): ResponseEntity<SessionResponse> =
        ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(body)

    // Putanja na istom hostu ili adresa aplikacije iz ruta; sve ostalo vodi na početnu.
    private fun safeReturnTo(returnTo: String?, exchange: ServerWebExchange): String {
        val isLocalPath = returnTo != null &&
            returnTo.startsWith("/") &&
            !returnTo.startsWith("//") &&
            !returnTo.contains('\\') &&
            returnTo.none { it.isISOControl() } &&
            runCatching { URI.create(returnTo) }.isSuccess

        return when {
            isLocalPath -> returnTo
            appUrls.isAppUrl(returnTo) -> returnTo!!
            appUrls.isAppUrl(exchange.request.uri.toString()) -> "/"
            else -> gateway.homeUrl
        }
    }

    private fun redirect(location: String): ResponseEntity<Void> =
        ResponseEntity.status(HttpStatus.FOUND).location(URI.create(location)).build()

    private fun html(body: String, csp: String): ResponseEntity<String> =
        ResponseEntity.ok()
            .contentType(MediaType("text", "html", Charsets.UTF_8))
            .cacheControl(CacheControl.noStore())
            .header("Content-Security-Policy", "$csp; frame-ancestors 'none'; base-uri 'none'")
            .header("X-Content-Type-Options", "nosniff")
            .body(body)

    data class SessionResponse(
        // Verzija odgovora, da browser klijent zna koja polja sme da očekuje.
        val v: Int = 1,
        val authenticated: Boolean,
        val reason: String?,
        val user: SessionUser?,
        val session: SessionInfo?,
    )

    data class SessionUser(
        val sub: String?,
        val sid: String?,
        val licenseId: Any?,
        val userId: Any?,
        val role: String?,
        val modules: Any?,
        val name: String?,
        val email: String?,
    )

    // Unix sekunde; idleTimeout u sekundama (sesija gateway-a bez aktivnosti).
    data class SessionInfo(
        val authTime: Long?,
        val accessTokenExpiresAt: Long?,
        val idleTimeout: Long,
    )

    private companion object {
        const val SDK_RESOURCE = "bff/sdk.js"
        val JAVASCRIPT = MediaType("text", "javascript", Charsets.UTF_8)

        // Strana sa istog origin-a kao aplikacija; ako je k-auth prekinuo vezu sa prozorom koji je otvorio popup
        // (COOP), klijent prijavu vidi i po promeni K_GATEWAY_STATE.
        const val POPUP_SCRIPT = "if(window.opener){window.opener.postMessage({type:'kancelarko:login'},location.origin);window.close();}"
        val POPUP_SCRIPT_HASH = "sha256-" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(POPUP_SCRIPT.toByteArray()))

        val POPUP_DONE_PAGE = """
            <!doctype html>
            <html lang="sr"><head><meta charset="utf-8"><title>Prijava</title></head>
            <body><p>Prijava je završena. Možete zatvoriti ovaj prozor.</p><script>$POPUP_SCRIPT</script></body></html>
        """.trimIndent()

        val LOGOUT_PAGE = """
            <!doctype html>
            <html lang="sr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Odjava</title>
            <style>body{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0}
            form{text-align:center}button{font:inherit;padding:.5rem 1.25rem;cursor:pointer}</style></head>
            <body><form method="post" action="/logout"><p>Odjava iz svih Kancelarko aplikacija?</p><button type="submit">Odjavi se</button></form></body></html>
        """.trimIndent()
    }
}
