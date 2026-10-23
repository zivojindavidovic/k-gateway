package rs.kancelarko.kancelarkoapigateway.security

import com.nimbusds.jwt.JWTParser
import org.springframework.data.redis.core.ReactiveStringRedisTemplate
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken
import org.springframework.security.oauth2.client.oidc.server.session.ReactiveOidcSessionRegistry
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.stereotype.Component
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

/**
 * Veza sesija k-auth-a (`sid`, `sub`) i sesija gateway-a, u Redis-u, da back-channel odjava
 * nađe sesiju bez obzira na to koja instanca gateway-a ju je napravila.
 *
 *   k-gateway:oidc-session:{sessionId}   HASH  id_token + CSRF zaglavlja za internu odjavu
 *   k-gateway:oidc-sid:{sid}             SET   sessionId-jevi
 *   k-gateway:oidc-sub:{sub}             SET   sessionId-jevi (logout_token bez sid-a)
 */
@Component
class RedisOidcSessionRegistry(
    private val redis: ReactiveStringRedisTemplate,
    properties: KAuthProperties,
) : ReactiveOidcSessionRegistry {

    private val ttl = properties.oidcSessionTtl

    override fun saveSessionInformation(info: OidcSessionInformation): Mono<Void> {
        val key = sessionKey(info.sessionId)
        val fields = info.authorities.mapKeys { AUTHORITY_FIELD + it.key } + (ID_TOKEN_FIELD to info.principal.idToken.tokenValue)

        return redis.delete(key)
            .then(redis.opsForHash<String, String>().putAll(key, fields))
            .then(redis.expire(key, ttl))
            .thenMany(Flux.fromIterable(indexKeys(info.principal.idToken)))
            .concatMap { index -> redis.opsForSet().add(index, info.sessionId).then(redis.expire(index, ttl)) }
            .then()
    }

    override fun removeSessionInformation(clientSessionId: String): Mono<OidcSessionInformation> =
        load(clientSessionId).flatMap { info ->
            Flux.fromIterable(indexKeys(info.principal.idToken))
                .concatMap { index -> redis.opsForSet().remove(index, clientSessionId) }
                .then(redis.delete(sessionKey(clientSessionId)))
                .thenReturn(info)
        }

    override fun removeSessionInformation(logoutToken: OidcLogoutToken): Flux<OidcSessionInformation> {
        val sid = logoutToken.sessionId
        val sub = logoutToken.subject
        val index = when {
            sid != null -> sidKey(sid)
            sub != null -> subKey(sub)
            else -> return Flux.empty()
        }

        return redis.opsForSet().members(index)
            .concatMap { load(it) }
            .filter { matches(it.principal.idToken, logoutToken) }
            .concatMap { removeSessionInformation(it.sessionId) }
    }

    private fun load(sessionId: String): Mono<OidcSessionInformation> =
        redis.opsForHash<String, String>().entries(sessionKey(sessionId))
            .collectMap({ it.key }, { it.value })
            .mapNotNull { fields ->
                val idToken = fields[ID_TOKEN_FIELD] ?: return@mapNotNull null
                val authorities = fields
                    .filterKeys { it.startsWith(AUTHORITY_FIELD) }
                    .mapKeys { it.key.removePrefix(AUTHORITY_FIELD) }
                OidcSessionInformation(sessionId, authorities, DefaultOidcUser(emptySet(), parseIdToken(idToken)))
            }

    private fun matches(idToken: OidcIdToken, logoutToken: OidcLogoutToken): Boolean {
        val sameProvider = idToken.issuer.toString() == logoutToken.issuer.toString() &&
            idToken.audience.orEmpty().any { it in logoutToken.audience.orEmpty() }
        val sid = logoutToken.sessionId

        return sameProvider && if (sid != null) idToken.getClaimAsString(SID) == sid else idToken.subject == logoutToken.subject
    }

    private fun indexKeys(idToken: OidcIdToken): List<String> =
        listOfNotNull(idToken.getClaimAsString(SID)?.let(::sidKey), idToken.subject?.let(::subKey))

    // id_token je gateway sam dobio od k-auth-a i proverio pri prijavi; ovde se samo čitaju claim-ovi.
    private fun parseIdToken(tokenValue: String): OidcIdToken {
        val claims = JWTParser.parse(tokenValue).jwtClaimsSet
        return OidcIdToken(tokenValue, claims.issueTime?.toInstant(), claims.expirationTime?.toInstant(), claims.claims)
    }

    private fun sessionKey(sessionId: String) = "$PREFIX:oidc-session:$sessionId"

    private fun sidKey(sid: String) = "$PREFIX:oidc-sid:$sid"

    private fun subKey(sub: String) = "$PREFIX:oidc-sub:$sub"

    private companion object {
        const val PREFIX = "k-gateway"
        const val SID = "sid"
        const val ID_TOKEN_FIELD = "id_token"
        const val AUTHORITY_FIELD = "h:"
    }
}
