package rs.kancelarko.kancelarkoapigateway.security

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.OidcBackChannelServerLogoutHandler
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder
import org.springframework.security.oauth2.client.oidc.server.session.ReactiveOidcSessionRegistry
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistration.ClientSettings
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.jwt.JwtIssuerValidator
import org.springframework.security.oauth2.jwt.JwtTimestampValidator
import org.springframework.security.oauth2.jwt.JwtTypeValidator
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import org.springframework.security.oauth2.server.resource.web.server.BearerTokenServerAuthenticationEntryPoint
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint.DelegateEntry
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache
import org.springframework.security.web.server.util.matcher.AndServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher.MatchResult
import org.springframework.web.util.UriComponentsBuilder
import rs.kancelarko.kancelarkoapigateway.gateway.RejectReason
import rs.kancelarko.kancelarkoapigateway.gateway.reject
import java.net.URI

/**
 * Gateway kao BFF (G1-A) i resource server; jedina veza aplikacija sa k-auth-om.
 *
 * - Browser: sve aplikacije su na poddomenima `kancelarko.gateway.parent-domain` i idu kroz gateway.
 *   Prijava preko k-auth-a (`oauth2Login`, PKCE) se završava na `kancelarko.gateway.public-url`;
 *   tokeni su u sesiji gateway-a (Redis), čiji cookie važi za ceo roditeljski domen.
 *   Aplikacijama ide access token iz sesije (TokenRelay).
 * - Server-server: `Authorization: Bearer` (at+jwt od k-auth-a) se proverava i prosleđuje dalje.
 *
 * Gateway nema svoj CSRF: jedine akcije sa sesijom su odjava (prinudna odjava nije opasna) i
 * zahtevi ka aplikacijama, a njih štiti CSRF aplikacije i `SameSite=Lax` cookie gateway-a.
 */
@Configuration
@EnableWebFluxSecurity
@EnableConfigurationProperties(KAuthProperties::class, GatewayProperties::class)
class SecurityConfig(
    private val properties: KAuthProperties,
    private val gateway: GatewayProperties,
) {

    @Bean
    fun securityWebFilterChain(
        http: ServerHttpSecurity,
        clientRegistrations: ReactiveClientRegistrationRepository,
        oidcSessionRegistry: ReactiveOidcSessionRegistry,
        @Value("\${server.port}") port: Int,
        @Value("\${server.reactive.session.cookie.name:SESSION}") sessionCookieName: String,
        appUrls: AppUrls,
        marker: SessionMarker,
        loginRequests: LoginRequests,
    ): SecurityWebFilterChain {
        val redirects = DefaultServerRedirectStrategy()

        return http {
            authorizeExchange {
                authorize("/ping", permitAll)
                authorize(JWKS_PATH, permitAll)
                authorize("/bff/session", permitAll)
                authorize(GatewayLogoutSuccessHandler.LOGGED_OUT_PATH, permitAll)
                authorize("/account", permitAll)
                authorize("/bff/sdk.js", permitAll)
                authorize("/bff/popup-done", permitAll)
                authorize(PathPatternParserServerWebExchangeMatcher(LOGOUT_PATH, HttpMethod.GET), permitAll)
                authorize(anyExchange, authenticated)
            }
            // Adresa za povratak ne čeka u sesiji, putuje uz prijavu (`returnTo`, LoginRequests).
            requestCache {
                requestCache = NoOpServerRequestCache.getInstance()
            }
            oauth2Login {
                // Započete prijave po `state` u Redis-u, ne u sesiji: više tabova i popup prijavljuju se u isto vreme.
                authorizationRequestRepository = loginRequests
                authorizationRequestResolver = DefaultServerOAuth2AuthorizationRequestResolver(
                    clientRegistrations,
                    PathPatternParserServerWebExchangeMatcher(AUTHORIZATION_PATH),
                )
                authenticationMatcher = PathPatternParserServerWebExchangeMatcher(CALLBACK_PATH)
                // Nova vrednost K_GATEWAY_STATE: ostali tabovi i aplikacije vide da je neko prijavljen.
                authenticationSuccessHandler = ServerAuthenticationSuccessHandler { webFilterExchange, _ ->
                    val exchange = webFilterExchange.exchange
                    marker.start(exchange).then(redirects.sendRedirect(exchange, URI.create(loginRequests.returnTo(exchange) ?: gateway.homeUrl)))
                }
                authenticationFailureHandler = loginFailureHandler()
            }
            oauth2ResourceServer {
                jwt { }
            }
            oidcLogout {
                backChannel {
                    // Gateway gasi sesiju internim pozivom samom sebi; u kontejneru javna adresa ne mora da radi.
                    logoutHandler = OidcBackChannelServerLogoutHandler(oidcSessionRegistry).apply {
                        setLogoutUri("http://localhost:$port/logout/connect/back-channel/{registrationId}")
                        setSessionCookieName(sessionCookieName)
                    }
                }
            }
            logout {
                // Samo forma (POST) sa iste adrese (SameOriginFilter); GET /logout je strana sa potvrdom (BffController),
                // da odjavu ne pokrene tuđ link, slika ili druga aplikacija.
                requiresLogout = PathPatternParserServerWebExchangeMatcher(LOGOUT_PATH, HttpMethod.POST)
                logoutSuccessHandler = GatewayLogoutSuccessHandler(properties, gateway, appUrls, marker)
            }
            csrf {
                disable()
            }
            exceptionHandling {
                authenticationEntryPoint = entryPoint(appUrls, marker)
            }
        }
    }

    /**
     * Krajnje tačke k-auth-a su zadate direktno (ugovor iz njegovog discovery dokumenta), a ne preko
     * `issuer-uri`, da gateway može da se pokrene i kad k-auth još nije podignut.
     */
    @Bean
    fun clientRegistrations(): ReactiveClientRegistrationRepository {
        val issuer = properties.issuer

        return InMemoryReactiveClientRegistrationRepository(
            ClientRegistration.withRegistrationId(REGISTRATION_ID)
                .clientId(properties.client.id)
                .clientSecret(properties.client.secret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // Jedna adresa za povratak za sve aplikacije (k-auth zna samo za gateway).
                .redirectUri("${gateway.publicUrl}$CALLBACK_PATH")
                .scope("openid", "profile", "email")
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .issuerUri(issuer)
                .authorizationUri("$issuer/oauth/authorize")
                .tokenUri("$issuer/oauth/token")
                .jwkSetUri(jwkSetUri())
                // Ime i email za prikaz u aplikacijama (X-User-Name, X-User-Email).
                .userInfoUri("$issuer/oauth/userinfo")
                .userNameAttributeName("sub")
                .providerConfigurationMetadata(mapOf("end_session_endpoint" to "$issuer/oauth/logout"))
                .build(),
        )
    }

    // Tokeni u sesiji (Redis), ne u memoriji gateway-a: rade sve instance i preživljavaju restart.
    @Bean
    fun authorizedClientRepository(): ServerOAuth2AuthorizedClientRepository = WebSessionServerOAuth2AuthorizedClientRepository()

    // TokenRelay preko ovoga osvežava access token pre isteka (refresh token iz sesije).
    @Bean
    fun authorizedClientManager(
        clientRegistrations: ReactiveClientRegistrationRepository,
        authorizedClients: ServerOAuth2AuthorizedClientRepository,
    ): ReactiveOAuth2AuthorizedClientManager =
        DefaultReactiveOAuth2AuthorizedClientManager(clientRegistrations, authorizedClients).apply {
            setAuthorizedClientProvider(
                ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
                    .authorizationCode()
                    .refreshToken { it.clockSkew(properties.clockSkew) }
                    .build(),
            )
        }

    /**
     * Access tokeni k-auth-a su `typ: at+jwt` (RFC 9068). Nimbus podrazumevano prihvata samo
     * `JWT` ili bez `typ`, zato se njegova provera isključuje i radi se Spring-ovim validatorom.
     * `aud` se proverava po ruti (RouteAudienceFilter).
     */
    @Bean
    fun jwtDecoder(): ReactiveJwtDecoder =
        NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri())
            .validateType(false)
            .build()
            .apply {
                setJwtValidator(
                    DelegatingOAuth2TokenValidator(
                        JwtTimestampValidator(properties.clockSkew),
                        JwtIssuerValidator(properties.issuer),
                        JwtTypeValidator(ACCESS_TOKEN_TYPE),
                    ),
                )
            }

    private fun jwkSetUri() = "${properties.issuer}$JWKS_PATH"

    /**
     * Navigacija browsera ide na prijavu na hostu gateway-a, sa `returnTo` (posle nje nazad na istu adresu aplikacije);
     * pozivi sa Bearer tokenom dobijaju 401 po RFC 6750, a fetch/XHR 401 sa razlogom `no_session` u telu
     * (i brisanje K_GATEWAY_STATE, ako je ostao posle isteka sesije).
     */
    private fun entryPoint(appUrls: AppUrls, marker: SessionMarker): ServerAuthenticationEntryPoint {
        val pageNavigation = AndServerWebExchangeMatcher(
            MediaTypeServerWebExchangeMatcher(MediaType.TEXT_HTML).apply { setIgnoredMediaTypes(setOf(MediaType.ALL)) },
            NegatedServerWebExchangeMatcher(xhrRequest),
            NegatedServerWebExchangeMatcher(bearerRequest),
        )
        val login = gateway.publicUrl + AUTHORIZATION_PATH.replace("{registrationId}", REGISTRATION_ID)
        val redirects = DefaultServerRedirectStrategy()
        val toLogin = ServerAuthenticationEntryPoint { exchange, _ ->
            val url = exchange.request.uri.toString()
            val returnTo = url.takeIf { exchange.request.method == HttpMethod.GET && appUrls.isAppUrl(it) }
            // Kao promenljiva šablona, da se kodira cela (i `?`, `&` iz adrese strane).
            val location = if (returnTo == null) {
                URI.create(login)
            } else {
                UriComponentsBuilder.fromUriString(login).queryParam(LoginRequests.RETURN_TO, "{returnTo}").encode().buildAndExpand(returnTo).toUri()
            }
            redirects.sendRedirect(exchange, location)
        }

        return DelegatingServerAuthenticationEntryPoint(
            DelegateEntry(pageNavigation, toLogin),
            DelegateEntry(bearerRequest, BearerTokenServerAuthenticationEntryPoint()),
        ).apply {
            setDefaultEntryPoint { exchange, _ ->
                marker.clear(exchange)
                reject(exchange, HttpStatus.UNAUTHORIZED, "unauthorized", RejectReason.NO_SESSION)
            }
        }
    }

    // Podrazumevano bi preusmerilo na /login?error, a to je na domenu aplikacije njena stranica.
    private fun loginFailureHandler() = ServerAuthenticationFailureHandler { webFilterExchange, exception ->
        log.warn("Prijava preko k-auth-a nije uspela: {}", exception.message)
        webFilterExchange.exchange.response.statusCode = HttpStatus.UNAUTHORIZED
        webFilterExchange.exchange.response.setComplete()
    }

    companion object {
        private val log = LoggerFactory.getLogger(SecurityConfig::class.java)

        const val REGISTRATION_ID = "k-auth"
        const val ACCESS_TOKEN_TYPE = "at+jwt"
        const val AUTHORIZATION_PATH = "/bff/oauth2/authorization/{registrationId}"
        const val CALLBACK_PATH = "/bff/login/oauth2/code/{registrationId}"
        const val LOGOUT_PATH = "/logout"
        const val JWKS_PATH = "/.well-known/jwks.json"

        private val bearerRequest = ServerWebExchangeMatcher { exchange ->
            val authorization = exchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION)
            if (authorization?.startsWith("Bearer ", ignoreCase = true) == true) MatchResult.match() else MatchResult.notMatch()
        }

        private val xhrRequest = ServerWebExchangeMatcher { exchange ->
            if (exchange.request.headers.getFirst("X-Requested-With") == "XMLHttpRequest") MatchResult.match() else MatchResult.notMatch()
        }
    }
}
