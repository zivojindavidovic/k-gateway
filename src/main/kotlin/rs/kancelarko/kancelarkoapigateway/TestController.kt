package rs.kancelarko.kancelarkoapigateway

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/ping")
class TestController {
    @GetMapping
    fun ping(): String {
        return "Hello World!"
    }
}