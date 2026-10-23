package rs.kancelarko.kancelarkoapigateway.security

import org.springframework.boot.context.properties.ConfigurationProperties
import java.net.URI

/**
 * Javne adrese gateway-a i aplikacija iza njega.
 *
 * Aplikacije su na poddomenima `parentDomain` (fakture.kancelarko.local…), a cookie sesije gateway-a
 * važi za ceo `parentDomain`, pa postoji jedna sesija i jedna adresa za povratak sa k-auth-a.
 */
@ConfigurationProperties("kancelarko.gateway")
data class GatewayProperties(
    // Gde k-auth vraća korisnika posle prijave i odjave (npr. http://gateway.kancelarko.local).
    val publicUrl: String,
    val parentDomain: String,
    // Kuda posle prijave/odjave kad nije poznato sa koje aplikacije je korisnik došao.
    val homeUrl: String,
) {
    /**
     * Sme li gateway da preusmeri browser na ovu adresu: samo http(s) na poddomenu `parentDomain`.
     */
    fun isAppUrl(url: String?): Boolean {
        val uri = url?.let { runCatching { URI(it) }.getOrNull() } ?: return false
        val host = uri.host ?: return false

        return uri.scheme in setOf("http", "https") && uri.userInfo == null && host.endsWith(".$parentDomain")
    }
}
