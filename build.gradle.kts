import java.time.Duration

plugins {
    id("java")
    id("application")
    id("com.gradleup.shadow") version "9.4.1"
    id("org.glavo.gradle-wrapper-neo") version "0.2.0"
}

group = "org.glavo"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

val mainClassName = "org.glavo.riscv.Main"
val unsafeModuleArgs = listOf(
    "--add-exports=java.base/jdk.internal.misc=ALL-UNNAMED",
    "--add-opens=java.base/jdk.internal.misc=ALL-UNNAMED",
)

application {
    applicationName = "jriscv"
    mainClass = "org.glavo.riscv.Main"

    applicationDefaultJvmArgs = unsafeModuleArgs + listOf(
        "--sun-misc-unsafe-memory-access=allow"
    )
}

tasks.shadowJar {
    manifest.attributes(
        "Main-Class" to mainClassName,
        "Enable-Native-Access" to "ALL-UNNAMED",
        "Add-Opens" to "java.base/jdk.internal.misc"
    )
}

dependencies {
    val kalaCompressVersion = "1.27.1-3"

    implementation("org.glavo.kala:kala-compress-archivers-tar:$kalaCompressVersion")
    implementation("net.fornwall:jelf:0.11.0")

    compileOnly("org.jetbrains:annotations:26.1.0")
    testCompileOnly("org.jetbrains:annotations:26.1.0")

    testImplementation(platform("org.junit:junit-bom:6.0.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    jvmArgs(unsafeModuleArgs)
    timeout.set(Duration.ofMinutes(10))
    systemProperty("java.io.tmpdir", layout.buildDirectory.dir("tmp/test-temp").get().asFile.absolutePath)
    doFirst {
        layout.buildDirectory.dir("tmp/test-temp").get().asFile.mkdirs()
    }
}

tasks.withType<JavaExec>().configureEach {
    jvmArgs(unsafeModuleArgs)
}

tasks.register<JavaExec>("runSwingFramebufferDemo") {
    group = "application"
    description = "Run the Swing framebuffer smoke demo."
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass = "org.glavo.riscv.gui.SwingFramebufferDemo"
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.add("--add-exports=java.base/jdk.internal.misc=ALL-UNNAMED")
}

tasks.named<org.gradle.jvm.application.tasks.CreateStartScripts>("startScripts") {
    doFirst {
        delete(outputDir)
    }
}

apply(from = "gradle/riscv-examples.gradle.kts")
apply(from = "gradle/riscv-tests.gradle.kts")
apply(from = "gradle/ubuntu-base.gradle.kts")
apply(from = "gradle/fastfetch.gradle.kts")
apply(from = "gradle/jdk25.gradle.kts")
apply(from = "gradle/ltp.gradle.kts")
apply(from = "gradle/packaging-smoke.gradle.kts")
apply(from = "gradle/native-image.gradle.kts")
