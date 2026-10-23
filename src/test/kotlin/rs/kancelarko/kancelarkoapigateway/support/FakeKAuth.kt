package rs.kancelarko.kancelarkoapigateway.support

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.time.Instant
import java.util.Date
import java.util.UUID

/**
 * Minimalni k-auth za testove: JWKS, token endpoint i potpisivanje tokena.
 */
class FakeKAuth : AutoCloseable {

    private val key = RSAKeyGenerator(2048).keyID("test-key").generate()

    private val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)

    val issuer: String get() = "http://localhost:${server.address.port}"

    /** Odgovor token endpoint-a (form parametri zahteva → JSON). */
    @Volatile
    var tokenResponse: (Map<String, String>) -> String = { "{}" }

    @Volatile
    var tokenStatus: Int = 200

    @Volatile
    var lastTokenRequest: Map<String, String> = emptyMap()

    @Volatile
    var lastTokenAuthorization: String? = null

    init {
        server.createContext("/.well-known/jwks.json") { respond(it, JWKSet(key.toPublicJWK()).toString()) }
        server.createContext("/oauth/token") { exchange ->
            val form = parseForm(exchange.requestBody.readAllBytes().decodeToString())
            lastTokenRequest = form
            lastTokenAuthorization = exchange.requestHeaders.getFirst("Authorization")
            respond(exchange, tokenResponse(form), tokenStatus)
        }
        server.createContext("/oauth/userinfo") {
            respond(it, """{"sub":"1:7","name":"Živojin Đurić","email":"zivojin@example.rs"}""")
        }
        server.start()
    }

    fun accessToken(
        aud: Any = "k-gateway",
        sid: String = "sid-1",
        type: String = "at+jwt",
        issuer: String = this.issuer,
        expiresIn: Long = 600,
    ): String = sign(
        type,
        JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject("1:7")
            .claim("aud", aud)
            .claim("client_id", "k-gateway")
            .issueTime(Date())
            .notBeforeTime(Date())
            .expirationTime(Date.from(Instant.now().plusSeconds(expiresIn)))
            .jwtID(UUID.randomUUID().toString())
            .claim("sid", sid)
            .claim("license_id", 3)
            .claim("user_id", 7)
            .claim("role", "ADMIN")
            .build(),
    )

    fun idToken(nonce: String, sid: String = "sid-1"): String = sign(
        "JWT",
        JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject("1:7")
            .audience("k-gateway")
            .issueTime(Date())
            .expirationTime(Date.from(Instant.now().plusSeconds(600)))
            .claim("nonce", nonce)
            .claim("sid", sid)
            .build(),
    )

    fun logoutToken(sid: String = "sid-1"): String = sign(
        "logout+jwt",
        JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject("1:7")
            .audience("k-gateway")
            .issueTime(Date())
            .expirationTime(Date.from(Instant.now().plusSeconds(120)))
            .jwtID(UUID.randomUUID().toString())
            .claim("sid", sid)
            .claim("events", mapOf("http://schemas.openid.net/event/backchannel-logout" to emptyMap<String, Any>()))
            .build(),
    )

    private fun sign(type: String, claims: JWTClaimsSet): String =
        SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.keyID).type(JOSEObjectType(type)).build(), claims)
            .apply { sign(RSASSASigner(key)) }
            .serialize()

    override fun close() = server.stop(0)

    companion object {
        fun parseForm(body: String): Map<String, String> = body.split('&')
            .filter { it.isNotEmpty() }
            .associate { pair ->
                val (name, value) = pair.split('=', limit = 2).let { it[0] to it.getOrElse(1) { "" } }
                URLDecoder.decode(name, Charsets.UTF_8) to URLDecoder.decode(value, Charsets.UTF_8)
            }

        fun respond(exchange: HttpExchange, body: String, status: Int = 200) {
            val bytes = body.toByteArray()
            exchange.responseHeaders.add("Content-Type", "application/json")
            exchange.sendResponseHeaders(status, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
    }
}

/**
 * Aplikacija/servis iza gateway-a: pamti metod i zaglavlja poslednjeg zahteva.
 */
class EchoService : AutoCloseable {

    private val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)

    val url: String get() = "http://localhost:${server.address.port}"

    @Volatile
    var lastHeaders: Map<String, String?> = emptyMap()

    @Volatile
    var lastMethod: String? = null

    init {
        server.createContext("/") { exchange ->
            lastHeaders = exchange.requestHeaders.mapKeys { it.key.lowercase() }.mapValues { it.value.firstOrNull() }
            lastMethod = exchange.requestMethod
            FakeKAuth.respond(exchange, "{\"ok\":true}")
        }
        server.start()
    }

    override fun close() = server.stop(0)
}
