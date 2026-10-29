package rs.kancelarko.kancelarkoapigateway.security

import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * Javne adrese gateway-a i aplikacija iza njega.
 *
 * Aplikacije su na poddomenima `parentDomain` (fakture.kancelarko.local…), a cookie sesije gateway-a
 * važi za ceo `parentDomain`, pa postoji jedna sesija i jedna adresa za povratak sa k-auth-a.
 * Na koje adrese aplikacija sme da se preusmeri odlučuje [AppUrls] (hostovi iz ruta).
 */
@ConfigurationProperties("kancelarko.gateway")
data class GatewayProperties(
    // Gde k-auth vraća korisnika posle prijave i odjave (npr. https://gateway.kancelarko.local).
    val publicUrl: String,
    val parentDomain: String,
    // Kuda posle prijave/odjave kad nije poznato sa koje aplikacije je korisnik došao.
    val homeUrl: String,
    // Preusmeravanje i na http:// adrese aplikacija (samo testovi i okruženja bez TLS-a).
    val allowInsecureUrls: Boolean = false,
    val rateLimit: RateLimit = RateLimit(),
) {
    /**
     * Ograničenje broja zahteva ka putanjama gateway-a (prijava, provera sesije, odjava), po minutu.
     * Rute aplikacija se ovde ne ograničavaju.
     */
    data class RateLimit(
        val enabled: Boolean = true,
        // Adresa klijenta: zaglavlje koje nginx postavlja iz $remote_addr. Ne X-Forwarded-For: prvu vrednost
        // u njemu bira klijent. Važi samo dok je gateway dostupan isključivo preko nginx-a.
        val clientIpHeader: String = "X-Real-IP",
        // Po adresi: /bff/login, početak prijave na k-auth-u i povratak sa njega.
        val loginPerMinute: Long = 30,
        // Po sesiji (bez sesije po adresi): /bff/session.
        val sessionPerMinute: Long = 60,
        // Po adresi: /logout.
        val logoutPerMinute: Long = 20,
    )
}
