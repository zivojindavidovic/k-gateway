package rs.kancelarko.kancelarkoapigateway.security

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.DisposableBean
import org.springframework.boot.data.redis.autoconfigure.DataRedisProperties
import org.springframework.data.redis.connection.RedisPassword
import org.springframework.data.redis.connection.RedisStandaloneConfiguration
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory
import org.springframework.data.redis.core.ReactiveStringRedisTemplate
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

/**
 * Lista opozvanih sesija i tokena koju vodi k-auth (Redis baza auth-a, podrazumevano DB 2).
 *
 * Konekcija je namerno van Spring konteksta: kao bean bi isključila Boot-ovu podrazumevanu
 * konekciju koju koriste sesije gateway-a.
 */
@Component
class RevocationList(
    redisProperties: DataRedisProperties,
    properties: KAuthProperties,
) : DisposableBean {

    private val log = LoggerFactory.getLogger(javaClass)

    private val revocation = properties.revocation

    private val connectionFactory = LettuceConnectionFactory(
        RedisStandaloneConfiguration(redisProperties.host, redisProperties.port).apply {
            database = revocation.redisDatabase
            username = redisProperties.username
            password = RedisPassword.of(redisProperties.password)
        },
    ).apply {
        afterPropertiesSet()
        start()
    }

    private val redis = ReactiveStringRedisTemplate(connectionFactory)

    fun isRevoked(sid: String?, jti: String?): Mono<Boolean> {
        val keys = listOfNotNull(
            sid?.let { "${revocation.keyPrefix}revoked-sid:$it" },
            jti?.let { "${revocation.keyPrefix}revoked-jti:$it" },
        )
        if (keys.isEmpty()) {
            return Mono.just(false)
        }

        return redis.countExistingKeys(keys)
            .map { it > 0 }
            .timeout(revocation.timeout)
            .onErrorResume { ex ->
                log.warn("Provera opoziva nije uspela (Redis), failOpen={}: {}", revocation.failOpen, ex.toString())
                Mono.just(!revocation.failOpen)
            }
    }

    override fun destroy() {
        connectionFactory.destroy()
    }
}
