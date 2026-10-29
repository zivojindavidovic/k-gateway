plugins {
    kotlin("jvm") version "2.3.21"
    kotlin("plugin.spring") version "2.3.21"
    id("org.springframework.boot") version "4.1.1"
    id("io.spring.dependency-management") version "1.1.7"
    id("com.github.node-gradle.node") version "7.1.0"
}

group = "rs.kancelarko"
version = "0.0.1-SNAPSHOT"
description = "kancelarko-api-gateway"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

repositories {
    mavenCentral()
}

extra["springCloudVersion"] = "2025.1.3"

dependencies {
    implementation("io.projectreactor.kotlin:reactor-kotlin-extensions")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")
    implementation("org.springframework.cloud:spring-cloud-starter-gateway-server-webflux")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-security-oauth2-client")
    implementation("org.springframework.boot:spring-boot-starter-data-redis-reactive")
    implementation("org.springframework.boot:spring-boot-starter-security-oauth2-resource-server")
    implementation("org.springframework.boot:spring-boot-starter-session-data-redis")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("io.projectreactor:reactor-test")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test")
    testImplementation("org.springframework.security:spring-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

dependencyManagement {
    imports {
        mavenBom("org.springframework.cloud:spring-cloud-dependencies:${property("springCloudVersion")}")
    }
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll("-Xjsr305=strict", "-Xannotation-default-target=param-property")
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}

// Browser klijent (src/main/frontend, TypeScript) → build/generated/frontend/bff/sdk.js → u jar, gateway ga
// servira na /bff/sdk.js. Node se preuzima u Gradle keš; na mašini ne mora da postoji.
node {
    download = true
    version = "24.11.0"
    npmInstallCommand = "ci"
    nodeProjectDir = file("src/main/frontend")
}

val frontendBuild by tasks.registering(com.github.gradle.node.npm.task.NpmTask::class) {
    dependsOn(tasks.npmInstall)
    args = listOf("run", "build")
    inputs.dir("src/main/frontend/src")
    inputs.files("src/main/frontend/package.json", "src/main/frontend/package-lock.json", "src/main/frontend/tsconfig.json")
    outputs.dir(layout.buildDirectory.dir("generated/frontend"))
}

val frontendTest by tasks.registering(com.github.gradle.node.npm.task.NpmTask::class) {
    dependsOn(tasks.npmInstall)
    args = listOf("test")
    inputs.dir("src/main/frontend/src")
    inputs.dir("src/main/frontend/test")
}

tasks.processResources {
    from(frontendBuild)
}

tasks.check {
    dependsOn(frontendTest)
}
