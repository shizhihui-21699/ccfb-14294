import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.4.21"
    application
}

group = "ccfb.hsm"
version = "1.0.0"

repositories { mavenCentral() }

dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.2")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.17.2")
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_21) } }

application {
    mainClass.set("ccfb.hsm.cli.MainKt")
    applicationDefaultJvmArgs = listOf("-Xmx512m")
}

tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "failed", "skipped"); showStandardStreams = true }
}

tasks.register<JavaExec>("attackDemo") {
    group = "verification"
    description = "Runs the built-in adversarial probe suite against the in-process HSM"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("ccfb.hsm.attack.AttackDemoKt")
}
