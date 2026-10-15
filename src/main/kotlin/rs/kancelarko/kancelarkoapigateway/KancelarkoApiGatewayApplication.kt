package rs.kancelarko.kancelarkoapigateway

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class KancelarkoApiGatewayApplication

fun main(args: Array<String>) {
    runApplication<KancelarkoApiGatewayApplication>(*args)
}
