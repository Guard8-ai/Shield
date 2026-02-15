plugins {
    kotlin("jvm") version "1.9.22"
}

group = "ai.guard8"
version = "1.0.0"

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.9.3")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(11)
}
