package rs.kancelarko.kancelarkoapigateway.security

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

/**
 * Veza sa k-auth-om (IdP): klijent gateway-a, provera tokena i lista opozvanih sesija.
 */
@ConfigurationProperties("kancelarko.auth")
data class KAuthProperties(
    // Mora tačno da se poklopi sa `iss` u tokenima, bez "/" na kraju.
    val issuer: String,
    val client: Client,
    val clockSkew: Duration = Duration.ofSeconds(60),
    val revocation: Revocation = Revocation(),
    // Koliko dugo se pamti veza sid → sesija gateway-a (za back-channel odjavu).
    val oidcSessionTtl: Duration = Duration.ofDays(30),
) {
    data class Client(
        val id: String,
        val secret: String,
    )

    /**
     * Ključevi `revoked-sid:{sid}` i `revoked-jti:{jti}` koje upisuje k-auth.
     */
    data class Revocation(
        val redisDatabase: Int = 2,
        val keyPrefix: String = "k-auth:",
        val timeout: Duration = Duration.ofMillis(300),
        // S3: kad Redis ne radi, zahtev prolazi (token je i dalje potpisan i kratko traje).
        val failOpen: Boolean = true,
    )
}
