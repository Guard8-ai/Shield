plugins {
    kotlin("jvm") version "1.9.22"
}

group = "ai.dikestra"
version = "2.2.0"

repositories {
    mavenCentral()
}

dependencies {
    // Post-quantum hybrid KEX: FIPS 203 ML-KEM-768 + X25519 via the audited Bouncy Castle provider.
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.9.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}
