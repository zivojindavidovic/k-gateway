package rs.kancelarko.kancelarkoapigateway

import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.data.redis.core.ReactiveStringRedisTemplate
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.reactive.server.EntityExchangeResult
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.util.UriComponentsBuilder
import rs.kancelarko.kancelarkoapigateway.support.EchoService
import rs.kancelarko.kancelarkoapigateway.support.FakeKAuth
import java.net.ServerSocket
import java.net.URLDecoder
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Gateway nad lažnim k-auth-om, aplikacijom (fakture) i servisom (adresar);
 * Redis iz k-docker-a (localhost:6379), test baza 15.
 *
 * Host zaglavlje predstavlja javni domen (nginx ga prosleđuje nepromenjenog).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
class GatewayAuthTests {

    @Autowired
    private lateinit var redis: ReactiveStringRedisTemplate

    private val client = WebTestClient.bindToServer()
        .baseUrl("http://localhost:$PORT")
        .responseTimeout(Duration.ofSeconds(10))
        .build()

    @BeforeEach
    fun reset() {
        redis.execute { it.serverCommands().flushDb() }.blockLast()
        kAuth.tokenStatus = 200
    }

    @Test
    fun `navigacija bez sesije ide na prijavu na gateway-u, fetch dobija 401`() {
        page(FAKTURE, "/invoices", cookie = null)
            .expectStatus().isFound
            .expectHeader().location("$GATEWAY_URL/bff/oauth2/authorization/k-auth")

        fetch(FAKTURE, "/invoices", cookie = null).expectStatus().isUnauthorized
    }

    @Test
    fun `prijava sa aplikacije, relay tokena i back-channel odjava`() {
        val accessToken = kAuth.accessToken()
        val session = login(accessToken)

        // Ceo sajt aplikacije ide kroz gateway; aplikacija dobija Bearer, svoj Host i svoje cookie-je.
        fetch(FAKTURE, "/invoices", "$session; laravel_session=abc").expectStatus().isOk
        assertEquals("Bearer $accessToken", fakture.lastHeaders["authorization"])
        assertEquals(FAKTURE, fakture.lastHeaders["host"])
        assertEquals("7", fakture.lastHeaders["x-user-id"])
        assertEquals("3", fakture.lastHeaders["x-license-id"])
        assertEquals("Živojin Đurić", URLDecoder.decode(fakture.lastHeaders["x-user-name"], Charsets.UTF_8))
        assertEquals("zivojin@example.rs", URLDecoder.decode(fakture.lastHeaders["x-user-email"], Charsets.UTF_8))
        assertEquals("laravel_session=abc", fakture.lastHeaders["cookie"])

        // Ista sesija važi i za servise po putanji.
        fetch(FAKTURE, "/api/adresar/subjekti", session).expectStatus().isOk
        assertEquals("Bearer $accessToken", adresar.lastHeaders["authorization"])
        assertNull(adresar.lastHeaders["cookie"])

        // Odjava na k-auth-u → back-channel → sesija gateway-a ugašena.
        client.post().uri("/logout/connect/back-channel/k-auth")
            .body(BodyInserters.fromFormData("logout_token", kAuth.logoutToken()))
            .exchange()
            .expectStatus().isOk

        fetch(FAKTURE, "/invoices", session).expectStatus().isUnauthorized
    }

    @Test
    fun `forma aplikacije (POST) ne trazi CSRF gateway-a`() {
        val session = login(kAuth.accessToken())

        client.post().uri("/invoices")
            .header(HttpHeaders.HOST, FAKTURE)
            .header(HttpHeaders.COOKIE, session)
            .body(BodyInserters.fromFormData("_token", "laravel-csrf"))
            .exchange()
            .expectStatus().isOk
        assertEquals("POST", fakture.lastMethod)
    }

    @Test
    fun `access token pred istekom se osvezava refresh tokenom`() {
        // Ističe za 30 s, a tolerancija je 60 s → već pri prvom pozivu ide osvežavanje.
        val session = login(kAuth.accessToken(expiresIn = 30), expiresIn = 30)
        val refreshed = kAuth.accessToken()
        kAuth.tokenResponse = { """{"access_token":"$refreshed","token_type":"Bearer","expires_in":600,"refresh_token":"rt-2"}""" }

        fetch(FAKTURE, "/invoices", session).expectStatus().isOk

        assertEquals("refresh_token", kAuth.lastTokenRequest["grant_type"])
        assertEquals("rt-1", kAuth.lastTokenRequest["refresh_token"])
        assertEquals("Bearer $refreshed", fakture.lastHeaders["authorization"])
    }

    @Test
    fun `neuspelo osvezavanje gasi sesiju`() {
        val session = login(kAuth.accessToken(expiresIn = 30), expiresIn = 30)
        kAuth.tokenStatus = 400
        kAuth.tokenResponse = { """{"error":"invalid_grant"}""" }

        fetch(FAKTURE, "/invoices", session).expectStatus().isUnauthorized

        kAuth.tokenStatus = 200
        page(FAKTURE, "/invoices", session).expectStatus().isFound
            .expectHeader().location("$GATEWAY_URL/bff/oauth2/authorization/k-auth")
    }

    @Test
    fun `bff login vraca samo na putanju ili aplikaciju pod roditeljskim domenom`() {
        val session = login(kAuth.accessToken())

        page(FAKTURE, "/bff/login?returnTo=/invoices/5?tab=stavke", session).expectHeader().location("/invoices/5?tab=stavke")
        page(FAKTURE, "/bff/login?returnTo=http://otpremnice.$PARENT/lista", session).expectHeader().location("http://otpremnice.$PARENT/lista")
        page(FAKTURE, "/bff/login?returnTo=https://zli.example", session).expectHeader().location("/")
        page(FAKTURE, "/bff/login?returnTo=//zli.example", session).expectHeader().location("/")
        page(FAKTURE, "/bff/login?returnTo=http://$PARENT/", session).expectHeader().location("/")
    }

    @Test
    fun `bff session kaze da li je korisnik prijavljen`() {
        fetch(FAKTURE, "/bff/session", cookie = null).expectStatus().isOk
            .expectBody().jsonPath("$.authenticated").isEqualTo(false)

        val session = login(kAuth.accessToken())

        fetch(FAKTURE, "/bff/session", session).expectStatus().isOk
            .expectBody()
            .jsonPath("$.authenticated").isEqualTo(true)
            .jsonPath("$.user.licenseId").isEqualTo(3)
            .jsonPath("$.user.role").isEqualTo("ADMIN")
            .jsonPath("$.user.name").isEqualTo("Živojin Đurić")
    }

    @Test
    fun `odjava iz aplikacije ide na k-auth i vraca se na aplikaciju preko state`() {
        val session = login(kAuth.accessToken())

        val logout = page(FAKTURE, "/logout", session).expectStatus().isFound.expectBody().returnResult()
        val location = logout.responseHeaders.location!!.toString()
        val params = queryParams(location)
        assertTrue(location.startsWith("${kAuth.issuer}/oauth/logout?"))
        assertEquals("k-gateway", params["client_id"])
        assertEquals("$GATEWAY_URL/bff/logged-out", params["post_logout_redirect_uri"])
        assertEquals("http://$FAKTURE/", params["state"])
        assertNotNull(params["id_token_hint"])

        fetch(FAKTURE, "/invoices", session).expectStatus().isUnauthorized

        // k-auth vraća na gateway sa istim state-om.
        page(GATEWAY, "/bff/logged-out?state=http://$FAKTURE/", cookie = null).expectHeader().location("http://$FAKTURE/")
        page(GATEWAY, "/bff/logged-out?state=https://zli.example/", cookie = null).expectHeader().location("http://$FAKTURE/")
    }

    @Test
    fun `moj nalog vodi na k-auth`() {
        page(FAKTURE, "/account", cookie = null).expectStatus().isFound
            .expectHeader().location("${kAuth.issuer}/account")
    }

    @Test
    fun `javni kljucevi k-auth-a su dostupni preko gateway-a bez prijave`() {
        client.get().uri("/.well-known/jwks.json")
            .exchange()
            .expectStatus().isOk
            .expectBody().jsonPath("$.keys[0].kid").isEqualTo("test-key")
    }

    @Test
    fun `bearer at+jwt za dozvoljen aud prolazi`() {
        bearer(kAuth.accessToken()).expectStatus().isOk
        assertEquals("7", adresar.lastHeaders["x-user-id"])
    }

    @Test
    fun `bearer sa pogresnim typ, iss ili isteklim tokenom se odbija`() {
        bearer(kAuth.accessToken(type = "JWT")).expectStatus().isUnauthorized
        bearer(kAuth.accessToken(issuer = "http://drugi-idp.local")).expectStatus().isUnauthorized
        bearer(kAuth.accessToken(expiresIn = -120)).expectStatus().isUnauthorized
    }

    @Test
    fun `bearer za klijenta koji nije u audiences rute dobija 403`() {
        bearer(kAuth.accessToken(aud = "k-drugi")).expectStatus().isForbidden
    }

    @Test
    fun `opozvana sesija u k-auth-u se odbija`() {
        redis.opsForValue().set("${REVOCATION_PREFIX}revoked-sid:sid-revoked", "1").block()

        bearer(kAuth.accessToken(sid = "sid-revoked")).expectStatus().isUnauthorized
        bearer(kAuth.accessToken(sid = "sid-active")).expectStatus().isOk
    }

    @Test
    fun `lazna X-User zaglavlja od klijenta ne stizu do servisa`() {
        client.get().uri("/api/adresar/subjekti")
            .header(HttpHeaders.AUTHORIZATION, "Bearer ${kAuth.accessToken()}")
            .header("X-User-Id", "999")
            .header("X-User-Name", "Neko%20Drugi")
            .exchange()
            .expectStatus().isOk
        assertEquals("7", adresar.lastHeaders["x-user-id"])
        assertNull(adresar.lastHeaders["x-user-name"])
    }

    /**
     * Ceo tok prijave sa stranice aplikacije; korisnik već ima SSO sesiju na k-auth-u.
     * Vraća cookie sesije gateway-a (važi za ceo roditeljski domen).
     */
    private fun login(accessToken: String, expiresIn: Long = 600): String {
        // 1. Stranica aplikacije, sesije nema → prijava na hostu gateway-a (zahtev se pamti).
        val entry = page(FAKTURE, "/invoices", cookie = null).expectStatus().isFound.expectBody().returnResult()
        val session = sessionCookie(entry)

        // 2. Gateway šalje browser na k-auth: PKCE, state, nonce, jedna redirect_uri za sve aplikacije.
        val authorize = page(GATEWAY, "/bff/oauth2/authorization/k-auth", session).expectStatus().isFound.expectBody().returnResult()
        val authorizeUrl = authorize.responseHeaders.location!!.toString()
        val params = queryParams(authorizeUrl)
        assertTrue(authorizeUrl.startsWith("${kAuth.issuer}/oauth/authorize?"))
        assertEquals("S256", params["code_challenge_method"])
        assertNotNull(params["code_challenge"])
        assertEquals("$GATEWAY_URL/bff/login/oauth2/code/k-auth", params["redirect_uri"])

        // 3. k-auth vraća kod na gateway; gateway ga menja za tokene i vraća browser na aplikaciju.
        kAuth.tokenResponse = {
            """{"access_token":"$accessToken","token_type":"Bearer","expires_in":$expiresIn,
               "refresh_token":"rt-1","id_token":"${kAuth.idToken(params.getValue("nonce"))}","scope":"openid profile email"}"""
        }
        val callback = page(GATEWAY, "/bff/login/oauth2/code/k-auth?code=c-1&state=${params["state"]}", session)
            .expectStatus().isFound
            .expectBody().returnResult()
        assertEquals("http://$FAKTURE/invoices", callback.responseHeaders.location.toString())
        assertEquals("authorization_code", kAuth.lastTokenRequest["grant_type"])
        assertNotNull(kAuth.lastTokenRequest["code_verifier"])
        assertTrue(kAuth.lastTokenAuthorization!!.startsWith("Basic "))

        return sessionCookie(callback)
    }

    private fun page(host: String, uri: String, cookie: String?) = request(host, uri, cookie, MediaType.TEXT_HTML)

    private fun fetch(host: String, uri: String, cookie: String?) = request(host, uri, cookie, MediaType.APPLICATION_JSON)

    private fun request(host: String, uri: String, cookie: String?, accept: MediaType) = client.get().uri(uri)
        .accept(accept)
        .header(HttpHeaders.HOST, host)
        .apply { if (cookie != null) header(HttpHeaders.COOKIE, cookie) }
        .exchange()

    private fun bearer(token: String) = client.get().uri("/api/adresar/subjekti")
        .header(HttpHeaders.AUTHORIZATION, "Bearer $token")
        .exchange()

    private fun sessionCookie(result: EntityExchangeResult<*>): String {
        val cookie = result.responseHeaders[HttpHeaders.SET_COOKIE].orEmpty().single { it.startsWith("K_GATEWAY_SESSION=") }
        assertTrue(cookie.contains("Domain=$PARENT"), cookie)
        assertFalse(cookie.contains("Max-Age=0"), cookie)

        return cookie.substringBefore(';')
    }

    private fun queryParams(url: String): Map<String, String> =
        UriComponentsBuilder.fromUriString(url).build().queryParams.toSingleValueMap()
            .mapValues { URLDecoder.decode(it.value, Charsets.UTF_8) }

    companion object {
        private const val PARENT = "kancelarko.local"
        private const val FAKTURE = "fakture.$PARENT"
        private const val GATEWAY = "gateway.$PARENT"
        private const val GATEWAY_URL = "http://$GATEWAY"
        private const val REVOCATION_PREFIX = "k-gateway-test:"

        private val PORT = ServerSocket(0).use { it.localPort }

        private val kAuth = FakeKAuth()

        private val fakture = EchoService()

        private val adresar = EchoService()

        @JvmStatic
        @DynamicPropertySource
        fun properties(registry: DynamicPropertyRegistry) {
            registry.add("server.port") { PORT }
            registry.add("kancelarko.auth.issuer") { kAuth.issuer }
            registry.add("kancelarko.auth.client.secret") { "test-secret" }
            registry.add("kancelarko.auth.revocation.redis-database") { 15 }
            registry.add("kancelarko.auth.revocation.key-prefix") { REVOCATION_PREFIX }
            registry.add("spring.data.redis.database") { 15 }
            // Lista ruta se ne može delimično pregaziti po indeksu, pa preko placeholder-a.
            registry.add("K_ADRESAR_URI") { adresar.url }
            registry.add("K_FAKTURE_URI") { fakture.url }
        }

        @JvmStatic
        @AfterAll
        fun stopServers() {
            kAuth.close()
            fakture.close()
            adresar.close()
        }
    }
}
