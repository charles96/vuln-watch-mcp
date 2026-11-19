plugins {
    java
    alias(libs.plugins.spring.boot)
    id("io.spring.dependency-management") version "1.0.11.RELEASE"
}

val nettyVersion = "4.1.68.Final"

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")   // version from Spring Boot BOM
    implementation(libs.jackson.databind)
    implementation(libs.bundles.utils)
    implementation("io.netty:netty-codec-http:$nettyVersion")
    testImplementation(libs.junit)
}
