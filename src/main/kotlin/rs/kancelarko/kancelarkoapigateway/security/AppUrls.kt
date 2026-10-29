package rs.kancelarko.kancelarkoapigateway.security

import org.springframework.cloud.gateway.route.RouteDefinitionLocator
import org.springframework.stereotype.Component
import org.springframework.util.AntPathMatcher
import java.net.URI

/**
 * Adrese na koje gateway sme da pošalje browser (`returnTo`, `state` odjave, zapamćen zahtev pre prijave):
 * samo hostovi aplikacija iz ruta (predikat `Host=`) i samo `https` (`http` uz `allow-insecure-urls`).
 *
 * Ostali poddomeni roditeljskog domena ne prolaze, i kad postoje (sajt, stari sistem, napušten poddomen):
 * inače bi gateway bio otvoreno preusmeravanje na njih.
 */
@Component
class AppUrls(
    gateway: GatewayProperties,
    routes: RouteDefinitionLocator,
) {

    private val allowInsecure = gateway.allowInsecureUrls

    private val matcher = AntPathMatcher(".")

    // Rute su iz konfiguracije (u memoriji), pa se čitaju jednom, pri pokretanju.
    private val hostPatterns: List<String> = routes.routeDefinitions
        .flatMapIterable { it.predicates }
        .filter { it.name == HOST_PREDICATE }
        .flatMapIterable { it.args.values }
        .flatMapIterable { it.split(',') }
        .map { it.trim().lowercase() }
        .filter { it.isNotEmpty() }
        .collectList()
        .block()
        .orEmpty()

    fun isAppUrl(url: String?): Boolean {
        val uri = url?.let { runCatching { URI(it) }.getOrNull() } ?: return false
        val host = uri.host?.lowercase() ?: return false
        val secure = uri.scheme == "https" || (allowInsecure && uri.scheme == "http")

        return secure && uri.userInfo == null && hostPatterns.any { matcher.match(it, host) }
    }

    private companion object {
        const val HOST_PREDICATE = "Host"
    }
}
