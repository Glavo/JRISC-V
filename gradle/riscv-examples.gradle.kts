import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import org.gradle.api.file.RelativePath
import org.gradle.api.file.RegularFile
import org.gradle.api.plugins.JavaApplication
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.jvm.tasks.Jar
import org.gradle.jvm.toolchain.JavaLanguageVersion
import org.gradle.jvm.toolchain.JavaToolchainService
import org.glavo.go.GoUtils
import org.glavo.go.RiscVGoBuildTask
import org.glavo.zig.AbstractRiscVZigCCTask
import org.glavo.zig.RiscVFreestandingZigCCTask
import org.glavo.zig.RiscVLinuxMuslStaticZigCCTask
import org.glavo.zig.ZigToolchainSupport

val applicationExtension = extensions.getByType<JavaApplication>()
val sourceSets = extensions.getByType<SourceSetContainer>()
val javaToolchains = extensions.getByType<JavaToolchainService>()
val zigToolchain = ZigToolchainSupport.getOrCreate(project)

val mainClassName = applicationExtension.mainClass.get()
val applicationDefaultJvmArgs = applicationExtension.applicationDefaultJvmArgs.toList()
val isWindowsHost = System.getProperty("os.name").lowercase().contains("win")
val goArchiveName = GoUtils.getGoArchiveName()
fun downloadFile(path: String) = providers.provider { layout.projectDirectory.file("downloads/$path") }
fun downloadDirectory(path: String) = providers.provider { layout.projectDirectory.dir("downloads/$path") }

val goArchiveFile = downloadFile("go/$goArchiveName")
val goInstallDirectory = layout.buildDirectory.dir("tools/go/${GoUtils.getGoDistributionName()}")
val goExecutableFile = goInstallDirectory.map {
    it.file("go/bin/${GoUtils.getGoExecutableName()}")
}
val configuredGoExecutablePath = providers.gradleProperty("jriscv.goExecutable")
    .orElse(providers.gradleProperty("graalriscv.goExecutable"))
    .orElse(providers.gradleProperty("goExecutable"))
    .orElse(providers.environmentVariable("GO_EXECUTABLE"))
val shadowJarFile = tasks.named<Jar>("shadowJar").flatMap { it.archiveFile }
val javaLauncher = javaToolchains.launcherFor {
    languageVersion = JavaLanguageVersion.of(25)
}

fun AbstractRiscVZigCCTask.configureZigExecutable() {
    zigToolchain.configureExecutable(this, zigExecutable)
}

fun RiscVGoBuildTask.configureGoExecutable() {
    val configuredPath = configuredGoExecutablePath.orNull
    if (configuredPath != null) {
        goExecutable.set(configuredPath)
    } else {
        dependsOn(extractGo)
        goExecutable.set(goExecutableFile.map { it.asFile.absolutePath })
    }
}

fun RiscVLinuxMuslStaticZigCCTask.configureLinuxStaticExample(sourceFileName: String, elfFile: Provider<RegularFile>) {
    configureZigExecutable()
    sourceFiles.from(layout.projectDirectory.file("examples/linux-static/$sourceFileName"))
    outputFile.set(elfFile)
    localCacheDirectory.set(layout.buildDirectory.dir("zig-local-cache"))
    globalCacheDirectory.set(layout.buildDirectory.dir("zig-global-cache"))
    additionalCompilerArguments.set(listOf("-O0", "-g0", "-no-pie"))
}

val downloadGo by tasks.registering(de.undercouch.gradle.tasks.download.Download::class) {
    group = "build setup"
    description = "Downloads Go ${GoUtils.GO_VERSION} for the current host platform."

    src("https://go.dev/dl/${GoUtils.getGoArchiveName()}")
    dest(goArchiveFile.get().asFile)
    overwrite(false)
    tempAndMove(true)
    retries(3)
    connectTimeout(30_000)
    readTimeout(30_000)

    doFirst {
        val archive = goArchiveFile.get().asFile
        val parent = archive.parentFile
        if (!parent.isDirectory && !parent.mkdirs()) {
            throw GradleException("Failed to create Go archive directory: $parent")
        }
        if (archive.isFile && archive.length() == 0L) {
            delete(archive)
        }
    }
}

val extractGo by tasks.registering {
    group = "build setup"
    description = "Extracts the downloaded Go toolchain."

    dependsOn(downloadGo)
    inputs.file(goArchiveFile)
    outputs.file(goExecutableFile)

    doLast {
        if (goExecutableFile.get().asFile.isFile) {
            return@doLast
        }

        val installDirectory = goInstallDirectory.get().asFile
        delete(installDirectory)
        val archive = goArchiveFile.get().asFile
        GoUtils.extractGoArchive(archive, installDirectory)
    }
}

tasks.register<Exec>("goToolchainVersion") {
    group = "build setup"
    description = "Prints the managed or configured Go toolchain version."

    val configuredPath = configuredGoExecutablePath.orNull
    if (configuredPath == null) {
        dependsOn(extractGo)
    }

    doFirst {
        val executable = configuredGoExecutablePath.orNull ?: goExecutableFile.get().asFile.absolutePath
        commandLine(executable, "version")
    }
}

// Static Go hello-world example.
val goHelloWorldExampleDirectory = layout.projectDirectory.dir("examples/go/go-hello")
val goHelloWorldExampleElf = layout.buildDirectory.file("examples/go/go-hello/hello-world")
val freeBsdGoHelloWorldExampleElf = layout.buildDirectory.file("examples/go/go-hello-freebsd/hello-world")
val goHelloWorldExpectedOutput = """
    Hello and welcome, gopher!
    i = 100
    i = 50
    i = 33
    i = 25
    i = 20
""".trimIndent() + "\n"

tasks.register<RiscVGoBuildTask>("buildGoHelloWorldExample") {
    group = "verification"
    description = "Builds examples/go/go-hello as a static linux/riscv64 Go executable."

    configureGoExecutable()
    moduleDirectory.set(goHelloWorldExampleDirectory)
    outputFile.set(goHelloWorldExampleElf)
    buildCacheDirectory.set(layout.buildDirectory.dir("go-build-cache"))
    moduleCacheDirectory.set(layout.buildDirectory.dir("go-module-cache"))
}

tasks.register<JavaExec>("testGoHelloWorldExample") {
    group = "verification"
    description = "Builds and verifies the static linux/riscv64 Go hello-world example."

    dependsOn("classes", "buildGoHelloWorldExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()
        setArgs(listOf(goHelloWorldExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (actualOutput != goHelloWorldExpectedOutput) {
            throw GradleException("Unexpected Go hello-world output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Go hello-world example wrote to stderr: $actualError")
        }
    }
}

tasks.register<JavaExec>("runGoHelloWorldExample") {
    group = "verification"
    description = "Runs the static linux/riscv64 Go hello-world example with the JRISC-V CLI."

    dependsOn("classes", "buildGoHelloWorldExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    doFirst {
        setArgs(listOf(goHelloWorldExampleElf.get().asFile.absolutePath))
    }
}

tasks.register<RiscVGoBuildTask>("buildFreeBsdGoHelloWorldExample") {
    group = "verification"
    description = "Builds examples/go/go-hello as a static freebsd/riscv64 Go executable."

    configureGoExecutable()
    goOS.set("freebsd")
    moduleDirectory.set(goHelloWorldExampleDirectory)
    outputFile.set(freeBsdGoHelloWorldExampleElf)
    buildCacheDirectory.set(layout.buildDirectory.dir("go-build-cache"))
    moduleCacheDirectory.set(layout.buildDirectory.dir("go-module-cache"))
}

tasks.register<JavaExec>("testFreeBsdGoHelloWorldExample") {
    group = "verification"
    description = "Builds and verifies the static freebsd/riscv64 Go hello-world example."

    dependsOn("classes", "buildFreeBsdGoHelloWorldExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()
        setArgs(listOf(freeBsdGoHelloWorldExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (actualOutput != goHelloWorldExpectedOutput) {
            throw GradleException("Unexpected FreeBSD Go hello-world output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("FreeBSD Go hello-world example wrote to stderr: $actualError")
        }
    }
}

tasks.register<JavaExec>("runFreeBsdGoHelloWorldExample") {
    group = "verification"
    description = "Runs the static freebsd/riscv64 Go hello-world example with the JRISC-V CLI."

    dependsOn("classes", "buildFreeBsdGoHelloWorldExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    doFirst {
        setArgs(listOf(freeBsdGoHelloWorldExampleElf.get().asFile.absolutePath))
    }
}

// Static Go showcase example.
val goShowcaseExampleDirectory = layout.projectDirectory.dir("examples/go/go-showcase")
val goShowcaseExampleElf = layout.buildDirectory.file("examples/go/go-showcase/showcase")
val freeBsdGoShowcaseExampleElf = layout.buildDirectory.file("examples/go/go-showcase-freebsd/showcase")

tasks.register<RiscVGoBuildTask>("buildGoShowcaseExample") {
    group = "verification"
    description = "Builds examples/go/go-showcase as a static linux/riscv64 Go workload."

    configureGoExecutable()
    moduleDirectory.set(goShowcaseExampleDirectory)
    outputFile.set(goShowcaseExampleElf)
    buildCacheDirectory.set(layout.buildDirectory.dir("go-build-cache"))
    moduleCacheDirectory.set(layout.buildDirectory.dir("go-module-cache"))
}

tasks.register<RiscVGoBuildTask>("buildFreeBsdGoShowcaseExample") {
    group = "verification"
    description = "Builds examples/go/go-showcase as a static freebsd/riscv64 Go workload."

    configureGoExecutable()
    goOS.set("freebsd")
    moduleDirectory.set(goShowcaseExampleDirectory)
    outputFile.set(freeBsdGoShowcaseExampleElf)
    buildCacheDirectory.set(layout.buildDirectory.dir("go-build-cache"))
    moduleCacheDirectory.set(layout.buildDirectory.dir("go-module-cache"))
}

tasks.register<JavaExec>("testGoShowcaseExample") {
    group = "verification"
    description = "Builds and verifies the static linux/riscv64 Go showcase workload."

    dependsOn("classes", "buildGoShowcaseExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()
        setArgs(listOf("--network", "host", goShowcaseExampleElf.get().asFile.absolutePath, "/showcase"))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (!actualOutput.contains("filesystem-ok\n")
            || !actualOutput.contains("network-ok\n")
            || !actualOutput.contains("process-ok\n")
            || !actualOutput.endsWith("go-showcase-ok\n")) {
            throw GradleException("Unexpected Go showcase output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Go showcase example wrote to stderr: $actualError")
        }
    }
}

tasks.register<JavaExec>("runGoShowcaseExample") {
    group = "verification"
    description = "Runs the static linux/riscv64 Go showcase workload with the JRISC-V CLI."

    dependsOn("classes", "buildGoShowcaseExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    doFirst {
        setArgs(listOf("--network", "host", goShowcaseExampleElf.get().asFile.absolutePath, "/showcase"))
    }
}

tasks.register<JavaExec>("testFreeBsdGoShowcaseExample") {
    group = "verification"
    description = "Builds and verifies the static freebsd/riscv64 Go showcase workload."

    dependsOn("classes", "buildFreeBsdGoShowcaseExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()
        setArgs(listOf("--network", "host", freeBsdGoShowcaseExampleElf.get().asFile.absolutePath, "/showcase"))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (!actualOutput.contains("filesystem-ok\n")
            || !actualOutput.contains("network-ok\n")
            || !actualOutput.contains("process-ok\n")
            || !actualOutput.endsWith("go-showcase-ok\n")) {
            throw GradleException("Unexpected FreeBSD Go showcase output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("FreeBSD Go showcase example wrote to stderr: $actualError")
        }
    }
}

tasks.register<JavaExec>("runFreeBsdGoShowcaseExample") {
    group = "verification"
    description = "Runs the static freebsd/riscv64 Go showcase workload with the JRISC-V CLI."

    dependsOn("classes", "buildFreeBsdGoShowcaseExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    doFirst {
        setArgs(listOf("--network", "host", freeBsdGoShowcaseExampleElf.get().asFile.absolutePath, "/showcase"))
    }
}

// Freestanding Hello World example.
val helloWorldExampleElf = layout.buildDirectory.file("examples/freestanding/hello.elf")

tasks.register<RiscVFreestandingZigCCTask>("buildHelloWorldExample") {
    group = "verification"
    description = "Builds examples/freestanding/HelloWorld.c for RISC-V with Zig CC."

    configureZigExecutable()
    sourceFiles.from(layout.projectDirectory.file("examples/freestanding/HelloWorld.c"))
    linkerScript.set(layout.projectDirectory.file("examples/freestanding/linker.ld"))
    outputFile.set(helloWorldExampleElf)
    localCacheDirectory.set(layout.buildDirectory.dir("zig-local-cache"))
    globalCacheDirectory.set(layout.buildDirectory.dir("zig-global-cache"))
}

tasks.register<JavaExec>("testHelloWorldExample") {
    group = "verification"
    description = "Compiles Hello World and verifies the JRISC-V CLI output."

    dependsOn("classes", "buildHelloWorldExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()
        setArgs(listOf(helloWorldExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (actualOutput != "Hello World!\n") {
            throw GradleException("Unexpected Hello World output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Hello World wrote to stderr: $actualError")
        }
    }
}

tasks.register<JavaExec>("runHelloWorldExample") {
    group = "verification"
    description = "Runs the compiled Hello World RISC-V example with the JRISC-V CLI."

    dependsOn("classes", "buildHelloWorldExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    doFirst {
        args(helloWorldExampleElf.get().asFile.absolutePath)
    }
}

tasks.register<Exec>("runHelloWorldInstalledExample") {
    group = "verification"
    description = "Runs the Hello World example through the installDist launch script."

    dependsOn("installDist", "buildHelloWorldExample")

    doFirst {
        val scriptName = if (isWindowsHost) {
            "jriscv.bat"
        } else {
            "jriscv"
        }
        val script = layout.buildDirectory.file("install/jriscv/bin/$scriptName").get().asFile
        val elf = helloWorldExampleElf.get().asFile

        if (isWindowsHost) {
            commandLine("cmd", "/c", script.absolutePath, elf.absolutePath)
        } else {
            commandLine(script.absolutePath, elf.absolutePath)
        }
    }
}

tasks.register<Exec>("runHelloWorldShadowJarExample") {
    group = "verification"
    description = "Runs the Hello World example through the packaged Shadow JAR."

    dependsOn("shadowJar", "buildHelloWorldExample")
    inputs.file(shadowJarFile)

    doFirst {
        commandLine(
            listOf(javaLauncher.get().executablePath.asFile.absolutePath) +
                    applicationDefaultJvmArgs +
                    listOf(
                        "-jar",
                        shadowJarFile.get().asFile.absolutePath,
                        helloWorldExampleElf.get().asFile.absolutePath
                    )
        )
    }
}

tasks.register("buildZigHelloWorldExample") {
    group = "verification"
    description = "Alias for buildHelloWorldExample."

    dependsOn("buildHelloWorldExample")
}

tasks.register("testZigHelloWorldExample") {
    group = "verification"
    description = "Alias for testHelloWorldExample."

    dependsOn("testHelloWorldExample")
}

// Freestanding hot-loop example.
val hotLoopExampleElf = layout.buildDirectory.file("examples/freestanding/hot-loop.elf")

tasks.register<RiscVFreestandingZigCCTask>("buildHotLoopExample") {
    group = "verification"
    description = "Builds examples/freestanding/HotLoop.c for RISC-V with Zig CC."

    configureZigExecutable()
    sourceFiles.from(layout.projectDirectory.file("examples/freestanding/HotLoop.c"))
    linkerScript.set(layout.projectDirectory.file("examples/freestanding/linker.ld"))
    outputFile.set(hotLoopExampleElf)
    localCacheDirectory.set(layout.buildDirectory.dir("zig-local-cache"))
    globalCacheDirectory.set(layout.buildDirectory.dir("zig-global-cache"))
    additionalCompilerArguments.set(listOf("-O2", "-g0", "-DHOT_LOOP_ITERATIONS=1000000UL"))
}

tasks.register<JavaExec>("testHotLoopExample") {
    group = "verification"
    description = "Runs the freestanding hot-loop example and verifies its checksum shape."

    dependsOn("classes", "buildHotLoopExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()
        setArgs(listOf(hotLoopExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (!Regex("checksum=0x[0-9a-f]{16}\\n").matches(actualOutput)) {
            throw GradleException("Unexpected hot-loop output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Hot-loop example wrote to stderr: $actualError")
        }
    }
}

tasks.register<JavaExec>("runHotLoopExample") {
    group = "verification"
    description = "Runs the freestanding hot-loop example with the JRISC-V CLI."

    dependsOn("classes", "buildHotLoopExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    doFirst {
        setArgs(listOf(hotLoopExampleElf.get().asFile.absolutePath))
    }
}

tasks.register<JavaExec>("runHotLoopCompilationTrace") {
    group = "verification"
    description = "Runs the freestanding hot-loop example with the compatibility trace-compilation option."

    dependsOn("classes", "buildHotLoopExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    doFirst {
        setArgs(listOf("--debug-trace-compilation", hotLoopExampleElf.get().asFile.absolutePath))
    }
}

// Static Linux printf example.
val linuxStaticPrintfExampleElf = layout.buildDirectory.file("examples/linux-static/printf-hello.elf")

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildLinuxStaticPrintfExample") {
    group = "verification"
    description = "Builds examples/linux-static/PrintfHelloWorld.c as a static riscv64-linux-musl executable."

    configureLinuxStaticExample("PrintfHelloWorld.c", linuxStaticPrintfExampleElf)
}

tasks.register<JavaExec>("testLinuxStaticPrintfExample") {
    group = "verification"
    description = "Compiles a static musl printf Hello World and verifies the JRISC-V CLI output."

    dependsOn("classes", "buildLinuxStaticPrintfExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()
        setArgs(listOf(linuxStaticPrintfExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (actualOutput != "Hello World!\n") {
            throw GradleException("Unexpected static printf output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Static printf Hello World wrote to stderr: $actualError")
        }
    }
}

tasks.register<JavaExec>("runLinuxStaticPrintfExample") {
    group = "verification"
    description = "Runs the static musl printf Hello World example with the JRISC-V CLI."

    dependsOn("classes", "buildLinuxStaticPrintfExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    doFirst {
        setArgs(listOf(linuxStaticPrintfExampleElf.get().asFile.absolutePath))
    }
}

// Static Linux argv example.
val linuxStaticArgvExampleElf = layout.buildDirectory.file("examples/linux-static/argv-echo.elf")

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildLinuxStaticArgvExample") {
    group = "verification"
    description = "Builds examples/linux-static/ArgvEcho.c as a static riscv64-linux-musl executable."

    configureLinuxStaticExample("ArgvEcho.c", linuxStaticArgvExampleElf)
}

tasks.register<JavaExec>("testLinuxStaticArgvExample") {
    group = "verification"
    description = "Compiles a static musl argv example and verifies the JRISC-V CLI output."

    dependsOn("classes", "buildLinuxStaticArgvExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()
        setArgs(listOf(linuxStaticArgvExampleElf.get().asFile.absolutePath, "alpha", "--beta"))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        val expectedOutput = "argc=3\nargv1=alpha\nargv2=--beta\n"
        if (actualOutput != expectedOutput) {
            throw GradleException("Unexpected static argv output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Static argv example wrote to stderr: $actualError")
        }
    }
}

// Static Linux file I/O example.
val linuxStaticFileIoExampleElf = layout.buildDirectory.file("examples/linux-static/file-io.elf")
val linuxStaticFileIoRoot = layout.buildDirectory.dir("tmp/linux-static-file-io-root")

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildLinuxStaticFileIoExample") {
    group = "verification"
    description = "Builds examples/linux-static/FileIo.c as a static riscv64-linux-musl executable."

    configureLinuxStaticExample("FileIo.c", linuxStaticFileIoExampleElf)
}

tasks.register<JavaExec>("testLinuxStaticFileIoExample") {
    group = "verification"
    description = "Compiles a static musl file I/O example and verifies sandboxed root-mount output."

    dependsOn("classes", "buildLinuxStaticFileIoExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()

        val root = linuxStaticFileIoRoot.get().asFile
        delete(root)
        if (!root.mkdirs()) {
            throw GradleException("Failed to create example root mount: $root")
        }

        setArgs(listOf("--mount", "type=bind,src=${root.absolutePath},dst=/", linuxStaticFileIoExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (actualOutput != "file-data\n") {
            throw GradleException("Unexpected static file I/O output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Static file I/O example wrote to stderr: $actualError")
        }

        val outputFile = linuxStaticFileIoRoot.get().file("output.txt").asFile
        val fileOutput = outputFile.readText(StandardCharsets.UTF_8)
        if (fileOutput != "file-data\n") {
            throw GradleException("Unexpected static file I/O host output: ${fileOutput.trim()}")
        }
    }
}

// Static Linux directory listing example.
val linuxStaticDirectoryListExampleElf = layout.buildDirectory.file("examples/linux-static/directory-list.elf")
val linuxStaticDirectoryListRoot = layout.buildDirectory.dir("tmp/linux-static-directory-list-root")

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildLinuxStaticDirectoryListExample") {
    group = "verification"
    description = "Builds examples/linux-static/DirectoryList.c as a static riscv64-linux-musl executable."

    configureLinuxStaticExample("DirectoryList.c", linuxStaticDirectoryListExampleElf)
}

tasks.register<JavaExec>("testLinuxStaticDirectoryListExample") {
    group = "verification"
    description = "Compiles a static musl directory listing example and verifies getdents64-backed output."

    dependsOn("classes", "buildLinuxStaticDirectoryListExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()

        val root = linuxStaticDirectoryListRoot.get().asFile
        delete(root)
        val entries = root.resolve("entries")
        if (!entries.mkdirs()) {
            throw GradleException("Failed to create example directory: $entries")
        }
        entries.resolve("alpha.txt").writeText("alpha\n", StandardCharsets.UTF_8)
        if (!entries.resolve("nested").mkdirs()) {
            throw GradleException("Failed to create nested example directory.")
        }

        setArgs(listOf("--mount", "type=bind,src=${root.absolutePath},dst=/", linuxStaticDirectoryListExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        val expectedOutput = "alpha.txt:file\nnested:dir\n"
        if (actualOutput != expectedOutput) {
            throw GradleException("Unexpected static directory listing output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Static directory listing example wrote to stderr: $actualError")
        }
    }
}

// Static Linux file mutation example.
val linuxStaticFileMutationExampleElf = layout.buildDirectory.file("examples/linux-static/file-mutation.elf")
val linuxStaticFileMutationRoot = layout.buildDirectory.dir("tmp/linux-static-file-mutation-root")

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildLinuxStaticFileMutationExample") {
    group = "verification"
    description = "Builds examples/linux-static/FileMutation.c as a static riscv64-linux-musl executable."

    configureLinuxStaticExample("FileMutation.c", linuxStaticFileMutationExampleElf)
}

tasks.register<JavaExec>("testLinuxStaticFileMutationExample") {
    group = "verification"
    description = "Compiles a static musl file mutation example and verifies sandboxed root-mount changes."

    dependsOn("classes", "buildLinuxStaticFileMutationExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()

        val root = linuxStaticFileMutationRoot.get().asFile
        delete(root)
        if (!root.mkdirs()) {
            throw GradleException("Failed to create example root mount: $root")
        }

        setArgs(listOf("--mount", "type=bind,src=${root.absolutePath},dst=/", linuxStaticFileMutationExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (actualOutput != "mutations-ok\n") {
            throw GradleException("Unexpected static file mutation output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Static file mutation example wrote to stderr: $actualError")
        }

        val workDirectory = linuxStaticFileMutationRoot.get().file("work").asFile
        if (workDirectory.exists()) {
            throw GradleException("Static file mutation example left work directory behind: $workDirectory")
        }
    }
}

// Static Linux working-directory example.
val linuxStaticWorkingDirectoryExampleElf = layout.buildDirectory.file("examples/linux-static/working-directory.elf")
val linuxStaticWorkingDirectoryRoot = layout.buildDirectory.dir("tmp/linux-static-working-directory-root")

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildLinuxStaticWorkingDirectoryExample") {
    group = "verification"
    description = "Builds examples/linux-static/WorkingDirectory.c as a static riscv64-linux-musl executable."

    configureLinuxStaticExample("WorkingDirectory.c", linuxStaticWorkingDirectoryExampleElf)
}

tasks.register<JavaExec>("testLinuxStaticWorkingDirectoryExample") {
    group = "verification"
    description = "Compiles a static musl working-directory example and verifies chdir/fchdir behavior."

    dependsOn("classes", "buildLinuxStaticWorkingDirectoryExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()

        val root = linuxStaticWorkingDirectoryRoot.get().asFile
        delete(root)
        if (!root.mkdirs()) {
            throw GradleException("Failed to create example root mount: $root")
        }

        setArgs(listOf("--mount", "type=bind,src=${root.absolutePath},dst=/", linuxStaticWorkingDirectoryExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (actualOutput != "cwd-ok\n") {
            throw GradleException("Unexpected static working-directory output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Static working-directory example wrote to stderr: $actualError")
        }

        val outputFile = linuxStaticWorkingDirectoryRoot.get().file("work/message.txt").asFile
        val fileOutput = outputFile.readText(StandardCharsets.UTF_8)
        if (fileOutput != "cwd-data\n") {
            throw GradleException("Unexpected static working-directory host output: ${fileOutput.trim()}")
        }
    }
}

// Static Linux filesystem-status example.
val linuxStaticFilesystemStatusExampleElf = layout.buildDirectory.file("examples/linux-static/filesystem-status.elf")
val linuxStaticFilesystemStatusRoot = layout.buildDirectory.dir("tmp/linux-static-filesystem-status-root")

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildLinuxStaticFilesystemStatusExample") {
    group = "verification"
    description = "Builds examples/linux-static/FilesystemStatus.c as a static riscv64-linux-musl executable."

    configureLinuxStaticExample("FilesystemStatus.c", linuxStaticFilesystemStatusExampleElf)
}

tasks.register<JavaExec>("testLinuxStaticFilesystemStatusExample") {
    group = "verification"
    description = "Compiles a static musl statvfs example and verifies statfs/fstatfs behavior."

    dependsOn("classes", "buildLinuxStaticFilesystemStatusExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()

        val root = linuxStaticFilesystemStatusRoot.get().asFile
        delete(root)
        if (!root.mkdirs()) {
            throw GradleException("Failed to create example root mount: $root")
        }

        setArgs(listOf("--mount", "type=bind,src=${root.absolutePath},dst=/", linuxStaticFilesystemStatusExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (actualOutput != "statvfs-ok\n") {
            throw GradleException("Unexpected static filesystem status output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Static filesystem status example wrote to stderr: $actualError")
        }

        val outputFile = linuxStaticFilesystemStatusRoot.get().file("status.txt").asFile
        val fileOutput = outputFile.readText(StandardCharsets.UTF_8)
        if (fileOutput != "status\n") {
            throw GradleException("Unexpected static filesystem status host output: ${fileOutput.trim()}")
        }
    }
}

// Static Linux statx metadata example.
val linuxStaticStatxMetadataExampleElf = layout.buildDirectory.file("examples/linux-static/statx-metadata.elf")
val linuxStaticStatxMetadataRoot = layout.buildDirectory.dir("tmp/linux-static-statx-metadata-root")

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildLinuxStaticStatxMetadataExample") {
    group = "verification"
    description = "Builds examples/linux-static/StatxMetadata.c as a static riscv64-linux-musl executable."

    configureLinuxStaticExample("StatxMetadata.c", linuxStaticStatxMetadataExampleElf)
}

tasks.register<JavaExec>("testLinuxStaticStatxMetadataExample") {
    group = "verification"
    description = "Compiles a static musl statx example and verifies sandboxed metadata output."

    dependsOn("classes", "buildLinuxStaticStatxMetadataExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()

        val root = linuxStaticStatxMetadataRoot.get().asFile
        delete(root)
        if (!root.mkdirs()) {
            throw GradleException("Failed to create example root mount: $root")
        }

        setArgs(listOf("--mount", "type=bind,src=${root.absolutePath},dst=/", linuxStaticStatxMetadataExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (actualOutput != "statx-ok\n") {
            throw GradleException("Unexpected static statx output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Static statx example wrote to stderr: $actualError")
        }

        val outputFile = linuxStaticStatxMetadataRoot.get().file("statx.txt").asFile
        val fileOutput = outputFile.readText(StandardCharsets.UTF_8)
        if (fileOutput != "statx-data\n") {
            throw GradleException("Unexpected static statx host output: ${fileOutput.trim()}")
        }
    }
}

// Static Linux positioned I/O example.
val linuxStaticPositionedIoExampleElf = layout.buildDirectory.file("examples/linux-static/positioned-io.elf")
val linuxStaticPositionedIoRoot = layout.buildDirectory.dir("tmp/linux-static-positioned-io-root")

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildLinuxStaticPositionedIoExample") {
    group = "verification"
    description = "Builds examples/linux-static/PositionedIo.c as a static riscv64-linux-musl executable."

    configureLinuxStaticExample("PositionedIo.c", linuxStaticPositionedIoExampleElf)
}

tasks.register<JavaExec>("testLinuxStaticPositionedIoExample") {
    group = "verification"
    description = "Compiles a static musl positioned I/O example and verifies pread/pwrite behavior."

    dependsOn("classes", "buildLinuxStaticPositionedIoExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()

        val root = linuxStaticPositionedIoRoot.get().asFile
        delete(root)
        if (!root.mkdirs()) {
            throw GradleException("Failed to create example root mount: $root")
        }

        setArgs(listOf("--mount", "type=bind,src=${root.absolutePath},dst=/", linuxStaticPositionedIoExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (actualOutput != "positioned-io-ok\n") {
            throw GradleException("Unexpected static positioned I/O output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Static positioned I/O example wrote to stderr: $actualError")
        }

        val outputFile = linuxStaticPositionedIoRoot.get().file("positioned.txt").asFile
        val fileOutput = outputFile.readText(StandardCharsets.UTF_8)
        if (fileOutput != "0123AB6789") {
            throw GradleException("Unexpected static positioned I/O host output: ${fileOutput.trim()}")
        }
    }
}

// Static Linux event polling example.
val linuxStaticEventPollingExampleElf = layout.buildDirectory.file("examples/linux-static/event-polling.elf")

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildLinuxStaticEventPollingExample") {
    group = "verification"
    description = "Builds examples/linux-static/EventPolling.c as a static riscv64-linux-musl executable."

    configureLinuxStaticExample("EventPolling.c", linuxStaticEventPollingExampleElf)
}

tasks.register<JavaExec>("testLinuxStaticEventPollingExample") {
    group = "verification"
    description = "Compiles a static musl eventfd/epoll example and verifies readiness polling."

    dependsOn("classes", "buildLinuxStaticEventPollingExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()
        setArgs(listOf(linuxStaticEventPollingExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (actualOutput != "event-polling-ok\n") {
            throw GradleException("Unexpected static event polling output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Static event polling example wrote to stderr: $actualError")
        }
    }
}

// Static Linux thread join example.
val linuxStaticThreadJoinExampleElf = layout.buildDirectory.file("examples/linux-static/thread-join.elf")

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildLinuxStaticThreadJoinExample") {
    group = "verification"
    description = "Builds examples/linux-static/ThreadJoin.c as a static riscv64-linux-musl executable."

    configureLinuxStaticExample("ThreadJoin.c", linuxStaticThreadJoinExampleElf)
    additionalCompilerArguments.set(listOf("-O0", "-g0", "-no-pie", "-pthread"))
}

tasks.register<JavaExec>("testLinuxStaticThreadJoinExample") {
    group = "verification"
    description = "Compiles a static musl pthread example and verifies clone/futex-backed joins."

    dependsOn("classes", "buildLinuxStaticThreadJoinExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()
        setArgs(listOf(linuxStaticThreadJoinExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (actualOutput != "thread-join-ok\n") {
            throw GradleException("Unexpected static pthread output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Static pthread example wrote to stderr: $actualError")
        }
    }
}

// Static Linux runtime services example.
val linuxStaticRuntimeServicesExampleElf = layout.buildDirectory.file("examples/linux-static/runtime-services.elf")

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildLinuxStaticRuntimeServicesExample") {
    group = "verification"
    description = "Builds examples/linux-static/RuntimeServices.c as a static riscv64-linux-musl executable."

    configureLinuxStaticExample("RuntimeServices.c", linuxStaticRuntimeServicesExampleElf)
}

tasks.register<JavaExec>("testLinuxStaticRuntimeServicesExample") {
    group = "verification"
    description = "Compiles a static musl runtime-services example and verifies memory, time, random, and resource syscalls."

    dependsOn("classes", "buildLinuxStaticRuntimeServicesExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()
        setArgs(listOf(linuxStaticRuntimeServicesExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (actualOutput != "runtime-services-ok\n") {
            throw GradleException("Unexpected static runtime services output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Static runtime services example wrote to stderr: $actualError")
        }
    }
}

// Static Linux framebuffer demo.
val linuxStaticFramebufferDemoElf = layout.buildDirectory.file("examples/linux-static/framebuffer-demo.elf")

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildLinuxStaticFramebufferDemo") {
    group = "verification"
    description = "Builds examples/linux-static/FramebufferDemo.c as a static riscv64-linux-musl executable."

    configureLinuxStaticExample("FramebufferDemo.c", linuxStaticFramebufferDemoElf)
}

tasks.register<JavaExec>("runLinuxStaticFramebufferDemo") {
    group = "application"
    description = "Runs the static musl framebuffer demo through the Swing /dev/fb0 backend."

    dependsOn("classes", "buildLinuxStaticFramebufferDemo")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    doFirst {
        setArgs(listOf(
            "--framebuffer",
            "320x180",
            "--framebuffer-scale",
            "3",
            linuxStaticFramebufferDemoElf.get().asFile.absolutePath
        ))
    }
}

// Static Linux process signals example.
val linuxStaticProcessSignalsExampleElf = layout.buildDirectory.file("examples/linux-static/process-signals.elf")

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildLinuxStaticProcessSignalsExample") {
    group = "verification"
    description = "Builds examples/linux-static/ProcessSignals.c as a static riscv64-linux-musl executable."

    configureLinuxStaticExample("ProcessSignals.c", linuxStaticProcessSignalsExampleElf)
}

tasks.register<JavaExec>("testLinuxStaticProcessSignalsExample") {
    group = "verification"
    description = "Compiles a static musl process and signal setup example and verifies process, signal, and prctl syscalls."

    dependsOn("classes", "buildLinuxStaticProcessSignalsExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()
        setArgs(listOf(linuxStaticProcessSignalsExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (actualOutput != "process-signals-ok\n") {
            throw GradleException("Unexpected static process signals output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("Static process signals example wrote to stderr: $actualError")
        }
    }
}

// Downloaded static Linux SQLite showcase example.
val sqliteVersion = "3520000"
val sqliteArchiveRoot = "sqlite-autoconf-$sqliteVersion"
val sqliteArchiveFile = downloadFile("sqlite/sqlite-autoconf-$sqliteVersion.tar.gz")
val sqliteSourceDirectory = downloadDirectory("sqlite/$sqliteVersion")
val sqliteExampleElf = layout.buildDirectory.file("examples/linux-static/sqlite-showcase.elf")
val sqliteRoot = layout.buildDirectory.dir("tmp/linux-static-sqlite-root")
val sqliteSourcePaths = listOf(
    "sqlite3.c",
    "sqlite3.h"
)
val sqliteSourceFiles = sqliteSourcePaths.associateWith { sourcePath ->
    sqliteSourceDirectory.map { directory -> directory.file(sourcePath) }
}

val downloadSQLiteArchive by tasks.registering(de.undercouch.gradle.tasks.download.Download::class) {
    group = "build setup"
    description = "Downloads SQLite amalgamation source package version $sqliteVersion."

    src("https://www.sqlite.org/2026/sqlite-autoconf-$sqliteVersion.tar.gz")
    dest(sqliteArchiveFile.get().asFile)
    overwrite(false)
    tempAndMove(true)
    retries(3)
    connectTimeout(30_000)
    readTimeout(30_000)

    doFirst {
        val archive = sqliteArchiveFile.get().asFile
        val parent = archive.parentFile
        if (!parent.isDirectory && !parent.mkdirs()) {
            throw GradleException("Failed to create SQLite archive directory: $parent")
        }
        if (archive.isFile && archive.length() == 0L) {
            delete(archive)
        }
    }
}

tasks.register("extractSQLiteSources") {
    group = "build setup"
    description = "Extracts the selected SQLite amalgamation sources used by the SQLite showcase example."

    dependsOn(downloadSQLiteArchive)
    inputs.file(sqliteArchiveFile)
    outputs.files(sqliteSourceFiles.values)

    doLast {
        copy {
            from(tarTree(resources.gzip(sqliteArchiveFile.get().asFile))) {
                sqliteSourcePaths.forEach { sourcePath ->
                    include("$sqliteArchiveRoot/$sourcePath")
                }
                eachFile {
                    relativePath = RelativePath(true, *relativePath.segments.drop(1).toTypedArray())
                }
                includeEmptyDirs = false
            }
            into(sqliteSourceDirectory)
        }
        val missingFiles = sqliteSourceFiles.values
            .map { it.get().asFile }
            .filterNot { it.isFile }
        if (missingFiles.isNotEmpty()) {
            throw GradleException("SQLite archive did not contain expected files: ${missingFiles.joinToString()}")
        }
    }
}

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildSQLiteShowcaseExample") {
    group = "verification"
    description = "Downloads SQLite and builds a static riscv64-linux-musl file-database showcase executable."

    dependsOn("extractSQLiteSources")
    configureZigExecutable()
    sourceFiles.from(
        layout.projectDirectory.file("examples/linux-static/SQLiteDemo.c"),
        sqliteSourceFiles.getValue("sqlite3.c")
    )
    outputFile.set(sqliteExampleElf)
    localCacheDirectory.set(layout.buildDirectory.dir("zig-local-cache"))
    globalCacheDirectory.set(layout.buildDirectory.dir("zig-global-cache"))
    additionalCompilerArguments.set(
        listOf(
            "-O2",
            "-g0",
            "-no-pie",
            "-DSQLITE_THREADSAFE=0",
            "-DSQLITE_OMIT_LOAD_EXTENSION",
            "-DSQLITE_TEMP_STORE=3",
            "-DSQLITE_DEFAULT_MEMSTATUS=0",
            "-I${sqliteSourceDirectory.get().asFile.absolutePath}"
        )
    )
}

tasks.register<JavaExec>("testSQLiteShowcaseExample") {
    group = "verification"
    description = "Runs the downloaded SQLite showcase example and verifies the database workload output."

    dependsOn("classes", "buildSQLiteShowcaseExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()

        val root = sqliteRoot.get().asFile
        delete(root)
        if (!root.mkdirs()) {
            throw GradleException("Failed to create SQLite showcase root mount: $root")
        }

        setArgs(listOf("--mount", "type=bind,src=${root.absolutePath},dst=/", sqliteExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        val expectedOutput = """
            sqlite-version=3.52.0
            rows=64
            value-sum=89440
            fizz=21:29799
            recursive=16:1496
            sqlite-showcase-ok
        """.trimIndent() + "\n"
        if (actualOutput != expectedOutput) {
            throw GradleException("Unexpected SQLite showcase output: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("SQLite showcase example wrote to stderr: $actualError")
        }

        val databaseFile = sqliteRoot.get().file("showcase.db").asFile
        if (!databaseFile.isFile || databaseFile.length() == 0L) {
            throw GradleException("SQLite showcase did not create a non-empty database file: $databaseFile")
        }
    }
}

tasks.register<JavaExec>("runSQLiteShowcaseExample") {
    group = "verification"
    description = "Runs the downloaded SQLite showcase example with the JRISC-V CLI."

    dependsOn("classes", "buildSQLiteShowcaseExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    doFirst {
        val root = sqliteRoot.get().asFile
        delete(root)
        if (!root.mkdirs()) {
            throw GradleException("Failed to create SQLite showcase root mount: $root")
        }

        setArgs(listOf("--mount", "type=bind,src=${root.absolutePath},dst=/", sqliteExampleElf.get().asFile.absolutePath))
    }
}

// Downloaded RVV examples.
val rvvExamplesRevision = "29b4973954799cdbc32ea354df22c4bab6b82b67"
val rvvExamplesArchiveRoot = "rvv-examples-$rvvExamplesRevision"
val rvvExamplesArchiveFile = downloadFile("rvv-examples/rvv-examples-$rvvExamplesRevision.zip")
val rvvExamplesSourceDirectory = downloadDirectory("rvv-examples/$rvvExamplesRevision")
val rvvExamplesGeneratedDirectory = layout.buildDirectory.dir("generated/rvv-examples/$rvvExamplesRevision")
val rvvVectorAddExampleElf = layout.buildDirectory.file("examples/linux-static/rvv-vector-add.elf")
val rvvMatrixTransposeExampleElf = layout.buildDirectory.file("examples/linux-static/rvv-matrix-transpose.elf")
val rvvReductionExampleElf = layout.buildDirectory.file("examples/linux-static/rvv-reduction.elf")
val rvvSoftmaxExampleElf = layout.buildDirectory.file("examples/linux-static/rvv-softmax.elf")
val rvvPolynomialBasicExampleElf = layout.buildDirectory.file("examples/linux-static/rvv-polynomial-basic.elf")
val rvvUbenchExampleElf = layout.buildDirectory.file("examples/linux-static/rvv-ubench.elf")
val rvvCrcExampleElf = layout.buildDirectory.file("examples/linux-static/rvv-crc.elf")
val rvvMatrixTransposeSmokeSource = rvvExamplesGeneratedDirectory.map { it.file("matrix_transpose_smoke.c") }
val rvvReductionSmokeSource = rvvExamplesGeneratedDirectory.map { it.file("reduction_smoke.c") }
val rvvCrcSmokeSource = rvvExamplesGeneratedDirectory.map { it.file("crc_smoke.c") }
val rvvNoArgumentBenchUtilsHeader = rvvExamplesGeneratedDirectory.map { it.file("no-argument-bench-utils/bench_utils.h") }
val rvvUbenchGeneratedDataHeader = rvvExamplesGeneratedDirectory.map { it.file("ubench-generated-data/generated_data_2op_int.h") }
val rvvBaseTargetFeatures = listOf("m", "a", "f", "d", "c", "v", "zicsr", "zifencei")
val rvvZbaTargetFeatures = rvvBaseTargetFeatures + "zba"
val rvvZbaZbbTargetFeatures = rvvZbaTargetFeatures + "zbb"
val rvvZvbbZvbcTargetFeatures = rvvBaseTargetFeatures + listOf("zvbb", "zvbc")
val rvvVectorAddSourcePaths = listOf(
    "src/vector_add/bench_vector_add.c",
    "src/vector_add/vector_add_intrinsics.c"
)
val rvvVectorAddSourceFiles = rvvVectorAddSourcePaths.associateWith { sourcePath ->
    rvvExamplesSourceDirectory.map { directory -> directory.file(sourcePath) }
}
val rvvMatrixTransposeSourceFiles = listOf(
    rvvMatrixTransposeSmokeSource,
    rvvExamplesSourceDirectory.map { it.file("src/matrix_transpose/matrix_transpose_intrinsics.c") }
)
val rvvReductionSourceFiles = listOf(
    rvvReductionSmokeSource
)
val rvvSoftmaxSourceFiles = listOf(
    "src/softmax/bench_softmax.c",
    "src/softmax/softmax_baseline.c",
    "src/softmax/softmax_rvv.c"
).map { sourcePath ->
    rvvExamplesSourceDirectory.map { it.file(sourcePath) }
}
val rvvPolynomialBasicSourceFiles = listOf(
    "src/polynomial_mult/basic_poly_test.c",
    "src/polynomial_mult/poly_mult_baseline.c",
    "src/polynomial_mult/ntt_scalar.c"
).map { sourcePath ->
    rvvExamplesSourceDirectory.map { it.file(sourcePath) }
}
val rvvUbenchSourceFiles = listOf(
    rvvExamplesSourceDirectory.map { it.file("src/ubench/microbenchmarks.c") }
)
val rvvCrcSourceFiles = listOf(
    rvvCrcSmokeSource,
    rvvExamplesSourceDirectory.map { it.file("src/crc/crc32.c") },
    rvvExamplesSourceDirectory.map { it.file("src/crc/vector_crc_be.c") },
    rvvExamplesSourceDirectory.map { it.file("src/crc/vector_crc_le.c") }
)

fun registerRvvExampleRunTask(
    taskName: String,
    descriptionText: String,
    buildTaskName: String,
    elfFile: Provider<RegularFile>
) {
    tasks.register<JavaExec>(taskName) {
        group = "verification"
        description = descriptionText

        dependsOn("classes", buildTaskName)
        classpath = sourceSets.named("main").get().runtimeClasspath
        mainClass = mainClassName
        jvmArgs(applicationDefaultJvmArgs)

        doFirst {
            setArgs(listOf(elfFile.get().asFile.absolutePath))
        }
    }
}

fun registerRvvExampleTestTask(
    taskName: String,
    descriptionText: String,
    buildTaskName: String,
    elfFile: Provider<RegularFile>,
    expectedOutputSnippets: List<String>
) {
    tasks.register<JavaExec>(taskName) {
        group = "verification"
        description = descriptionText

        dependsOn("classes", buildTaskName)
        classpath = sourceSets.named("main").get().runtimeClasspath
        mainClass = mainClassName
        jvmArgs(applicationDefaultJvmArgs)

        val stdout = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()
        standardOutput = stdout
        errorOutput = stderr

        doFirst {
            stdout.reset()
            stderr.reset()
            setArgs(listOf(elfFile.get().asFile.absolutePath))
        }

        doLast {
            val actualOutput = stdout.toString(StandardCharsets.UTF_8)
            val missingSnippets = expectedOutputSnippets.filterNot { actualOutput.contains(it) }
            if (missingSnippets.isNotEmpty()) {
                throw GradleException(
                    "Unexpected RVV example output; missing ${missingSnippets.joinToString()}: ${actualOutput.trim()}"
                )
            }

            val actualError = stderr.toString(StandardCharsets.UTF_8)
            if (actualError.isNotEmpty()) {
                throw GradleException("RVV example wrote to stderr: $actualError")
            }
        }
    }
}

val downloadRvvExamplesArchive by tasks.registering(de.undercouch.gradle.tasks.download.Download::class) {
    group = "build setup"
    description = "Downloads nibrunie/rvv-examples source archive revision $rvvExamplesRevision."

    src("https://github.com/nibrunie/rvv-examples/archive/$rvvExamplesRevision.zip")
    dest(rvvExamplesArchiveFile.get().asFile)
    overwrite(false)
    tempAndMove(true)
    retries(3)
    connectTimeout(30_000)
    readTimeout(30_000)

    doFirst {
        val archive = rvvExamplesArchiveFile.get().asFile
        val parent = archive.parentFile
        if (!parent.isDirectory && !parent.mkdirs()) {
            throw GradleException("Failed to create rvv-examples archive directory: $parent")
        }
        if (archive.isFile && archive.length() == 0L) {
            delete(archive)
        }
    }
}

tasks.register("extractRvvExamplesSources") {
    group = "build setup"
    description = "Extracts the selected nibrunie/rvv-examples sources used by the RVV examples."

    dependsOn(downloadRvvExamplesArchive)
    inputs.file(rvvExamplesArchiveFile)
    outputs.dir(rvvExamplesSourceDirectory)

    doLast {
        copy {
            from(zipTree(rvvExamplesArchiveFile.get().asFile)) {
                include("$rvvExamplesArchiveRoot/src/**")
                eachFile {
                    relativePath = RelativePath(true, *relativePath.segments.drop(1).toTypedArray())
                }
                includeEmptyDirs = false
            }
            into(rvvExamplesSourceDirectory)
        }
        val expectedDirectories = listOf("src/vector_add", "src/matrix_transpose", "src/reduction", "src/softmax", "src/polynomial_mult", "src/ubench", "src/crc")
            .map { rvvExamplesSourceDirectory.get().dir(it).asFile }
            .filterNot { it.isDirectory }
        if (expectedDirectories.isNotEmpty()) {
            throw GradleException("rvv-examples archive did not contain expected directories: ${expectedDirectories.joinToString()}")
        }
    }
}

tasks.register("generateRvvExamplesSupportSources") {
    group = "build setup"
    description = "Generates small support sources used to run selected rvv-examples as standalone Linux binaries."

    outputs.files(
        rvvMatrixTransposeSmokeSource,
        rvvReductionSmokeSource,
        rvvCrcSmokeSource,
        rvvNoArgumentBenchUtilsHeader,
        rvvUbenchGeneratedDataHeader
    )

    fun writeGeneratedFile(file: File, content: String) {
        val parent = file.parentFile
        if (!parent.isDirectory && !parent.mkdirs()) {
            throw GradleException("Failed to create generated rvv-examples directory: $parent")
        }
        file.writeText(content.trimIndent() + "\n", StandardCharsets.UTF_8)
    }

    doLast {
        writeGeneratedFile(
            rvvNoArgumentBenchUtilsHeader.get().asFile,
            """
                #ifndef RVV_EXAMPLES_NO_ARGUMENT_BENCH_UTILS_H
                #define RVV_EXAMPLES_NO_ARGUMENT_BENCH_UTILS_H

                static unsigned long read_perf_counter(void) {
                  unsigned long counter_value;
                #if defined(COUNT_CYCLE)
                #define PERF_METRIC "cycle"
                  __asm__ volatile ("rdcycle %0" : "=r" (counter_value));
                #else
                #define PERF_METRIC "instruction"
                  __asm__ volatile ("rdinstret %0" : "=r" (counter_value));
                #endif
                  return counter_value;
                }

                #endif
            """
        )
        writeGeneratedFile(
            rvvUbenchGeneratedDataHeader.get().asFile,
            """
                generated_data_t data_2op_int[] = {
                  {.v={0x0000000000000100ull, 0x0000000000000003ull}, .label="small positive division"},
                  {.v={0x0000000010000000ull, 0x000000000000001full}, .label="wide positive division"},
                };
            """
        )
        writeGeneratedFile(
            rvvMatrixTransposeSmokeSource.get().asFile,
            """
                #include <assert.h>
                #include <stdio.h>
                #include <string.h>
                #include <bench_matrix_utils.h>

                void matrix_transpose(float *dst, float *src, size_t n);
                void matrix_transpose_intrinsics(float *dst, float *src, size_t n);
                void matrix_transpose_intrinsics_loads(float *dst, float *src, size_t n);
                void matrix_transpose_intrinsics_4x4(float *dst, float *src);

                static void fill(float *matrix, size_t n) {
                  for (size_t i = 0; i < n * n; i++) {
                    matrix[i] = (float) (i + 1);
                  }
                }

                static void check(float *actual, float *expected, size_t n, const char *label) {
                  if (memcmp(actual, expected, n * n * sizeof(float)) != 0) {
                    fprintf(stderr, "matrix transpose mismatch: %s\n", label);
                    assert(0);
                  }
                  printf("%s ok for %zux%zu\n", label, n, n);
                }

                int main(void) {
                  enum { N = 4 };
                  float src[N * N];
                  float expected[N * N];
                  float actual[N * N];

                  fill(src, N);
                  matrix_transpose(expected, src, N);

                  memset(actual, 0, sizeof(actual));
                  matrix_transpose_intrinsics_4x4(actual, src);
                  check(actual, expected, N, "matrix_transpose_intrinsics_4x4");

                  memset(actual, 0, sizeof(actual));
                  matrix_transpose_intrinsics(actual, src, N);
                  check(actual, expected, N, "matrix_transpose_intrinsics_nxn");

                  memset(actual, 0, sizeof(actual));
                  matrix_transpose_intrinsics_loads(actual, src, N);
                  check(actual, expected, N, "matrix_transpose_intrinsics_loads_nxn");

                  return 0;
                }
            """
        )
        writeGeneratedFile(
            rvvReductionSmokeSource.get().asFile,
            """
                #define main rvv_reduction_upstream_main
                #include "reduction_bench.c"
                #undef main

                int main(void) {
                  int error = 0;
                  error |= bench_int_reduction();
                  error |= synthetic_bench();
                  return error;
                }
            """
        )
        writeGeneratedFile(
            rvvCrcSmokeSource.get().asFile,
            """
                #include <stdint.h>
                #include <stddef.h>
                #include <stdio.h>

                uint32_t crc32_le_generic(uint32_t crc, unsigned char const *p, size_t len, uint32_t polynomial);
                uint32_t crc32_be_generic(uint32_t crc, unsigned char const *p, size_t len, uint32_t polynomial);
                void crc32init_le(const uint32_t polynomial);
                void crc32init_be(const uint32_t polynomial);

                uint32_t crcEth32_be_vector(uint32_t crc, unsigned char const *p, size_t len);
                uint32_t crcEth32_be_vector_opt(uint32_t crc, unsigned char const *p, size_t len);
                uint32_t crcEth32_le_vector(uint32_t crc, unsigned char const *p, size_t len);

                static const uint32_t ETH_CRC32_POLY = 0x04c11db7u;
                static const uint32_t ETH_CRC32_POLY_INV = 0xedb88320u;

                static uint32_t crcEth32_be_generic(uint32_t crc, unsigned char const *p, size_t len) {
                  return crc32_be_generic(crc, p, len, ETH_CRC32_POLY);
                }

                static uint32_t crcEth32_le_generic(uint32_t crc, unsigned char const *p, size_t len) {
                  return crc32_le_generic(crc, p, len, ETH_CRC32_POLY_INV);
                }

                static void fill_message(unsigned char *message, size_t length) {
                  for (size_t index = 0; index < length; index++) {
                    message[index] = (unsigned char) (index * 37u + 11u);
                  }
                }

                static int check_crc(const char *label, uint32_t actual, uint32_t expected, size_t length) {
                  if (actual != expected) {
                    fprintf(stderr, "%s mismatch for %zu bytes: actual=%08x expected=%08x\n", label, length, actual, expected);
                    return 1;
                  }
                  printf("%s ok for %zu bytes: %08x\n", label, length, actual);
                  return 0;
                }

                int main(void) {
                  static const size_t SIZES[] = {32, 64, 128, 512, 1024};
                  unsigned char message[1024];
                  int error = 0;

                  crc32init_le(ETH_CRC32_POLY_INV);
                  crc32init_be(ETH_CRC32_POLY);
                  fill_message(message, sizeof(message));

                  for (size_t index = 0; index < sizeof(SIZES) / sizeof(SIZES[0]); index++) {
                    size_t length = SIZES[index];
                    uint32_t expected_be = crcEth32_be_generic(0, message, length);
                    uint32_t expected_le = crcEth32_le_generic(0, message, length);

                    error |= check_crc("crcEth32_be_vector", crcEth32_be_vector(0, message, length), expected_be, length);
                    error |= check_crc("crcEth32_be_vector_opt", crcEth32_be_vector_opt(0, message, length), expected_be, length);
                    error |= check_crc("crcEth32_le_vector", crcEth32_le_vector(0, message, length), expected_le, length);
                  }

                  return error;
                }
            """
        )
    }
}

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildRvvVectorAddExample") {
    group = "verification"
    description = "Downloads nibrunie/rvv-examples and builds the RVV vector-add example as a static RISC-V Linux executable."

    dependsOn("extractRvvExamplesSources")
    configureZigExecutable()
    enabledTargetFeatures.set(rvvBaseTargetFeatures)
    sourceFiles.from(
        rvvVectorAddSourceFiles.getValue("src/vector_add/bench_vector_add.c"),
        rvvVectorAddSourceFiles.getValue("src/vector_add/vector_add_intrinsics.c")
    )
    outputFile.set(rvvVectorAddExampleElf)
    localCacheDirectory.set(layout.buildDirectory.dir("zig-local-cache"))
    globalCacheDirectory.set(layout.buildDirectory.dir("zig-global-cache"))
    additionalCompilerArguments.set(
        listOf(
            "-O2",
            "-g0",
            "-no-pie",
            "-DARRAY_SIZE=16",
            "-Wno-format"
        )
    )
}

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildRvvMatrixTransposeExample") {
    group = "verification"
    description = "Builds the RVV matrix-transpose smoke example as a static RISC-V Linux executable."

    dependsOn("extractRvvExamplesSources", "generateRvvExamplesSupportSources")
    configureZigExecutable()
    enabledTargetFeatures.set(rvvBaseTargetFeatures)
    sourceFiles.from(rvvMatrixTransposeSourceFiles)
    outputFile.set(rvvMatrixTransposeExampleElf)
    localCacheDirectory.set(layout.buildDirectory.dir("zig-local-cache"))
    globalCacheDirectory.set(layout.buildDirectory.dir("zig-global-cache"))
    additionalCompilerArguments.set(
        providers.provider {
            listOf(
                "-O2",
                "-g0",
                "-no-pie",
                "-DCOUNT_INSTRET",
                "-I${rvvExamplesSourceDirectory.get().dir("src/matrix_transpose").asFile.absolutePath}",
            )
        }
    )
}

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildRvvReductionExample") {
    group = "verification"
    description = "Builds the RVV reduction smoke example as a static RISC-V Linux executable."

    dependsOn("extractRvvExamplesSources", "generateRvvExamplesSupportSources")
    configureZigExecutable()
    enabledTargetFeatures.set(rvvZbaTargetFeatures)
    sourceFiles.from(rvvReductionSourceFiles)
    outputFile.set(rvvReductionExampleElf)
    localCacheDirectory.set(layout.buildDirectory.dir("zig-local-cache"))
    globalCacheDirectory.set(layout.buildDirectory.dir("zig-global-cache"))
    additionalCompilerArguments.set(
        providers.provider {
            listOf(
                "-O2",
                "-g0",
                "-no-pie",
                "-DCOUNT_INSTRET",
                "-DVECTOR_SIZE=256",
                "-I${rvvNoArgumentBenchUtilsHeader.get().asFile.parentFile.absolutePath}",
                "-I${rvvExamplesSourceDirectory.get().dir("src/reduction").asFile.absolutePath}",
            )
        }
    )
}

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildRvvSoftmaxExample") {
    group = "verification"
    description = "Builds the RVV softmax example as a static RISC-V Linux executable."

    dependsOn("extractRvvExamplesSources")
    configureZigExecutable()
    enabledTargetFeatures.set(rvvBaseTargetFeatures)
    sourceFiles.from(rvvSoftmaxSourceFiles)
    outputFile.set(rvvSoftmaxExampleElf)
    localCacheDirectory.set(layout.buildDirectory.dir("zig-local-cache"))
    globalCacheDirectory.set(layout.buildDirectory.dir("zig-global-cache"))
    additionalCompilerArguments.set(
        providers.provider {
            listOf(
                "-O2",
                "-g0",
                "-no-pie",
                "-DCOUNT_INSTRET",
                "-DNUM_TESTS=1",
                "-I${rvvExamplesSourceDirectory.get().dir("src/softmax").asFile.absolutePath}",
                "-lm"
            )
        }
    )
}

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildRvvPolynomialBasicExample") {
    group = "verification"
    description = "Builds the RVV polynomial basic example as a static RISC-V Linux executable."

    dependsOn("extractRvvExamplesSources", "generateRvvExamplesSupportSources")
    configureZigExecutable()
    enabledTargetFeatures.set(rvvBaseTargetFeatures)
    sourceFiles.from(rvvPolynomialBasicSourceFiles)
    outputFile.set(rvvPolynomialBasicExampleElf)
    localCacheDirectory.set(layout.buildDirectory.dir("zig-local-cache"))
    globalCacheDirectory.set(layout.buildDirectory.dir("zig-global-cache"))
    additionalCompilerArguments.set(
        providers.provider {
            listOf(
                "-O2",
                "-g0",
                "-no-pie",
                "-DCOUNT_INSTRET",
                "-I${rvvNoArgumentBenchUtilsHeader.get().asFile.parentFile.absolutePath}",
                "-I${rvvExamplesSourceDirectory.get().dir("src/polynomial_mult").asFile.absolutePath}",
                "-I${rvvExamplesSourceDirectory.get().dir("src/utils").asFile.absolutePath}",
                "-lm"
            )
        }
    )
}

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildRvvUbenchExample") {
    group = "verification"
    description = "Builds the RVV micro-benchmark example as a static RISC-V Linux executable."

    dependsOn("extractRvvExamplesSources", "generateRvvExamplesSupportSources")
    configureZigExecutable()
    enabledTargetFeatures.set(rvvZbaZbbTargetFeatures)
    sourceFiles.from(rvvUbenchSourceFiles)
    outputFile.set(rvvUbenchExampleElf)
    localCacheDirectory.set(layout.buildDirectory.dir("zig-local-cache"))
    globalCacheDirectory.set(layout.buildDirectory.dir("zig-global-cache"))
    additionalCompilerArguments.set(
        providers.provider {
            listOf(
                "-O2",
                "-g0",
                "-no-pie",
                "-DCOUNT_INSTRET",
                "-DNUM_TESTS=1",
                "-DTEST_SIZE=64",
                "-DNDEBUG",
                "-I${rvvUbenchGeneratedDataHeader.get().asFile.parentFile.absolutePath}",
                "-I${rvvExamplesSourceDirectory.get().dir("src/ubench").asFile.absolutePath}",
                "-I${rvvExamplesSourceDirectory.get().dir("src/utils").asFile.absolutePath}",
                "-lm"
            )
        }
    )
}

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildRvvCrcExample") {
    group = "verification"
    description = "Builds the RVV CRC smoke example as a static RISC-V Linux executable."

    dependsOn("extractRvvExamplesSources", "generateRvvExamplesSupportSources")
    configureZigExecutable()
    enabledTargetFeatures.set(rvvZvbbZvbcTargetFeatures)
    sourceFiles.from(rvvCrcSourceFiles)
    outputFile.set(rvvCrcExampleElf)
    localCacheDirectory.set(layout.buildDirectory.dir("zig-local-cache"))
    globalCacheDirectory.set(layout.buildDirectory.dir("zig-global-cache"))
    additionalCompilerArguments.set(
        providers.provider {
            listOf(
                "-O2",
                "-g0",
                "-no-pie",
                "-DHAS_ZVBB_SUPPORT=1",
                "-I${rvvExamplesSourceDirectory.get().dir("src/crc").asFile.absolutePath}"
            )
        }
    )
}

registerRvvExampleRunTask(
    "runRvvVectorAddExample",
    "Runs the downloaded RVV vector-add example with the JRISC-V CLI.",
    "buildRvvVectorAddExample",
    rvvVectorAddExampleElf
)

registerRvvExampleTestTask(
    "testRvvVectorAddExample",
    "Runs the downloaded RVV vector-add example and verifies its summary output.",
    "buildRvvVectorAddExample",
    rvvVectorAddExampleElf,
    listOf("vector_add_intrinsics used ", " to evaluate 16 element(s).")
)

registerRvvExampleRunTask(
    "runRvvMatrixTransposeExample",
    "Runs the RVV matrix-transpose smoke example with the JRISC-V CLI.",
    "buildRvvMatrixTransposeExample",
    rvvMatrixTransposeExampleElf
)

registerRvvExampleTestTask(
    "testRvvMatrixTransposeExample",
    "Runs the RVV matrix-transpose smoke example and verifies its summary output.",
    "buildRvvMatrixTransposeExample",
    rvvMatrixTransposeExampleElf,
    listOf(
        "matrix_transpose_intrinsics_4x4 ok for 4x4",
        "matrix_transpose_intrinsics_nxn ok for 4x4",
        "matrix_transpose_intrinsics_loads_nxn ok for 4x4"
    )
)

registerRvvExampleRunTask(
    "runRvvReductionExample",
    "Runs the RVV reduction smoke example with the JRISC-V CLI.",
    "buildRvvReductionExample",
    rvvReductionExampleElf
)

registerRvvExampleTestTask(
    "testRvvReductionExample",
    "Runs the RVV reduction smoke example and verifies its summary output.",
    "buildRvvReductionExample",
    rvvReductionExampleElf,
    listOf("RVV based vector min reduction", "vredmin.vs;lmul=m8")
)

registerRvvExampleRunTask(
    "runRvvSoftmaxExample",
    "Runs the RVV softmax example with the JRISC-V CLI.",
    "buildRvvSoftmaxExample",
    rvvSoftmaxExampleElf
)

registerRvvExampleTestTask(
    "testRvvSoftmaxExample",
    "Runs the RVV softmax example and verifies its summary output.",
    "buildRvvSoftmaxExample",
    rvvSoftmaxExampleElf,
    listOf("baseline n-element softmax", "rvv-based n-element stable softmax")
)

registerRvvExampleRunTask(
    "runRvvPolynomialBasicExample",
    "Runs the RVV polynomial basic example with the JRISC-V CLI.",
    "buildRvvPolynomialBasicExample",
    rvvPolynomialBasicExampleElf
)

registerRvvExampleTestTask(
    "testRvvPolynomialBasicExample",
    "Runs the RVV polynomial basic example and verifies its summary output.",
    "buildRvvPolynomialBasicExample",
    rvvPolynomialBasicExampleElf,
    listOf("NTT example:", "(pa * pb)'s inv NTT")
)

registerRvvExampleRunTask(
    "runRvvUbenchExample",
    "Runs the RVV micro-benchmark example with the JRISC-V CLI.",
    "buildRvvUbenchExample",
    rvvUbenchExampleElf
)

registerRvvExampleTestTask(
    "testRvvUbenchExample",
    "Runs the RVV micro-benchmark example and verifies its summary output.",
    "buildRvvUbenchExample",
    rvvUbenchExampleElf,
    listOf("data div benchmark #0", "wide positive division")
)

registerRvvExampleRunTask(
    "runRvvCrcExample",
    "Runs the RVV CRC smoke example with the JRISC-V CLI.",
    "buildRvvCrcExample",
    rvvCrcExampleElf
)

registerRvvExampleTestTask(
    "testRvvCrcExample",
    "Runs the RVV CRC smoke example and verifies its summary output.",
    "buildRvvCrcExample",
    rvvCrcExampleElf,
    listOf(
        "crcEth32_be_vector ok for 1024 bytes",
        "crcEth32_be_vector_opt ok for 1024 bytes",
        "crcEth32_le_vector ok for 1024 bytes"
    )
)

// Downloaded static Linux CoreMark example.
val coreMarkRevision = "1f483d5b8316753a742cbf5590caf5bd0a4e4777"
val coreMarkArchiveRoot = "coremark-$coreMarkRevision"
val coreMarkArchiveFile = downloadFile("coremark/coremark-$coreMarkRevision.zip")
val coreMarkSourceDirectory = downloadDirectory("coremark/$coreMarkRevision")
val coreMarkExampleElf = layout.buildDirectory.file("examples/linux-static/coremark.elf")
val coreMarkIterations = 12000
val coreMarkSourcePaths = listOf(
    "core_list_join.c",
    "core_main.c",
    "core_matrix.c",
    "core_state.c",
    "core_util.c",
    "coremark.h",
    "posix/core_portme.c",
    "posix/core_portme.h",
    "posix/core_portme_posix_overrides.h"
)
val coreMarkSourceFiles = coreMarkSourcePaths.associateWith { sourcePath ->
    coreMarkSourceDirectory.map { directory -> directory.file(sourcePath) }
}

val downloadCoreMarkArchive by tasks.registering(de.undercouch.gradle.tasks.download.Download::class) {
    group = "build setup"
    description = "Downloads EEMBC CoreMark source archive revision $coreMarkRevision."

    src("https://github.com/eembc/coremark/archive/$coreMarkRevision.zip")
    dest(coreMarkArchiveFile.get().asFile)
    overwrite(false)
    tempAndMove(true)
    retries(3)
    connectTimeout(30_000)
    readTimeout(30_000)

    doFirst {
        val archive = coreMarkArchiveFile.get().asFile
        val parent = archive.parentFile
        if (!parent.isDirectory && !parent.mkdirs()) {
            throw GradleException("Failed to create CoreMark archive directory: $parent")
        }
        if (archive.isFile && archive.length() == 0L) {
            delete(archive)
        }
    }
}

tasks.register("extractCoreMarkSources") {
    group = "build setup"
    description = "Extracts the selected EEMBC CoreMark sources used by the CoreMark example."

    dependsOn(downloadCoreMarkArchive)
    inputs.file(coreMarkArchiveFile)
    outputs.files(coreMarkSourceFiles.values)

    doLast {
        copy {
            from(zipTree(coreMarkArchiveFile.get().asFile)) {
                coreMarkSourcePaths.forEach { sourcePath ->
                    include("$coreMarkArchiveRoot/$sourcePath")
                }
                eachFile {
                    relativePath = RelativePath(true, *relativePath.segments.drop(1).toTypedArray())
                }
                includeEmptyDirs = false
            }
            into(coreMarkSourceDirectory)
        }
        val missingFiles = coreMarkSourceFiles.values
            .map { it.get().asFile }
            .filterNot { it.isFile }
        if (missingFiles.isNotEmpty()) {
            throw GradleException("CoreMark archive did not contain expected files: ${missingFiles.joinToString()}")
        }
    }
}

tasks.register<RiscVLinuxMuslStaticZigCCTask>("buildCoreMarkExample") {
    group = "verification"
    description = "Downloads EEMBC CoreMark and builds it as a static riscv64-linux-musl executable."

    dependsOn("extractCoreMarkSources")
    configureZigExecutable()
    sourceFiles.from(
        coreMarkSourceFiles.getValue("core_main.c"),
        coreMarkSourceFiles.getValue("core_list_join.c"),
        coreMarkSourceFiles.getValue("core_matrix.c"),
        coreMarkSourceFiles.getValue("core_state.c"),
        coreMarkSourceFiles.getValue("core_util.c"),
        coreMarkSourceFiles.getValue("posix/core_portme.c")
    )
    outputFile.set(coreMarkExampleElf)
    localCacheDirectory.set(layout.buildDirectory.dir("zig-local-cache"))
    globalCacheDirectory.set(layout.buildDirectory.dir("zig-global-cache"))
    additionalCompilerArguments.set(
        listOf(
            "-O2",
            "-g0",
            "-no-pie",
            "-DPERFORMANCE_RUN=1",
            "-DSEED_METHOD=SEED_VOLATILE",
            "-DITERATIONS=$coreMarkIterations",
            "-DFLAGS_STR=\\\"-O2 -static -DPERFORMANCE_RUN=1 -DSEED_METHOD=SEED_VOLATILE -DITERATIONS=$coreMarkIterations\\\"",
            "-I${coreMarkSourceDirectory.get().asFile.absolutePath}",
            "-I${coreMarkSourceDirectory.get().dir("posix").asFile.absolutePath}"
        )
    )
}

tasks.register<JavaExec>("runCoreMarkExample") {
    group = "verification"
    description = "Runs the downloaded static CoreMark example with the JRISC-V CLI."

    dependsOn("classes", "buildCoreMarkExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    doFirst {
        setArgs(listOf(coreMarkExampleElf.get().asFile.absolutePath))
    }
}

tasks.register<JavaExec>("testCoreMarkExample") {
    group = "verification"
    description = "Runs the downloaded static CoreMark example and verifies CoreMark validation output."

    dependsOn("classes", "buildCoreMarkExample")
    classpath = sourceSets.named("main").get().runtimeClasspath
    mainClass = mainClassName
    jvmArgs(applicationDefaultJvmArgs)

    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()
    standardOutput = stdout
    errorOutput = stderr

    doFirst {
        stdout.reset()
        stderr.reset()
        setArgs(listOf(coreMarkExampleElf.get().asFile.absolutePath))
    }

    doLast {
        val actualOutput = stdout.toString(StandardCharsets.UTF_8)
        if (!actualOutput.contains("Correct operation validated.")) {
            throw GradleException("CoreMark validation did not succeed: ${actualOutput.trim()}")
        }
        if (actualOutput.contains("Errors detected")) {
            throw GradleException("CoreMark reported errors: ${actualOutput.trim()}")
        }

        val actualError = stderr.toString(StandardCharsets.UTF_8)
        if (actualError.isNotEmpty()) {
            throw GradleException("CoreMark example wrote to stderr: $actualError")
        }
    }
}

tasks.register("checkShowcaseExamples") {
    group = "verification"
    description = "Runs the larger demonstration workloads suitable for showcase use."

    dependsOn(
        "testGoShowcaseExample",
        "testFreeBsdGoShowcaseExample",
        "testHotLoopExample",
        "testSQLiteShowcaseExample",
        "testRvvVectorAddExample",
        "testRvvMatrixTransposeExample",
        "testRvvReductionExample",
        "testRvvSoftmaxExample",
        "testRvvPolynomialBasicExample",
        "testRvvUbenchExample",
        "testRvvCrcExample",
        "testCoreMarkExample"
    )
}

// Example aggregate checks.

tasks.register("checkHelloWorldExample") {
    group = "verification"
    description = "Runs every available Hello World example smoke check."

    dependsOn(
        "testHelloWorldExample",
        "testGoHelloWorldExample",
        "testFreeBsdGoHelloWorldExample",
        "testLinuxStaticPrintfExample",
        "testLinuxStaticArgvExample",
        "testLinuxStaticFileIoExample",
        "testLinuxStaticDirectoryListExample",
        "testLinuxStaticFileMutationExample",
        "testLinuxStaticWorkingDirectoryExample",
        "testLinuxStaticFilesystemStatusExample",
        "testLinuxStaticStatxMetadataExample",
        "testLinuxStaticPositionedIoExample",
        "testLinuxStaticEventPollingExample",
        "testLinuxStaticThreadJoinExample",
        "testLinuxStaticRuntimeServicesExample",
        "testLinuxStaticProcessSignalsExample",
        "runHelloWorldExample",
        "runHelloWorldInstalledExample",
        "runHelloWorldShadowJarExample"
    )
}

tasks.named("check") {
    dependsOn("testHelloWorldExample")
    dependsOn("testLinuxStaticPrintfExample")
    dependsOn("testLinuxStaticArgvExample")
    dependsOn("testLinuxStaticFileIoExample")
    dependsOn("testLinuxStaticDirectoryListExample")
    dependsOn("testLinuxStaticFileMutationExample")
    dependsOn("testLinuxStaticWorkingDirectoryExample")
    dependsOn("testLinuxStaticFilesystemStatusExample")
    dependsOn("testLinuxStaticStatxMetadataExample")
    dependsOn("testLinuxStaticPositionedIoExample")
    dependsOn("testLinuxStaticEventPollingExample")
    dependsOn("testLinuxStaticThreadJoinExample")
    dependsOn("testLinuxStaticRuntimeServicesExample")
    dependsOn("testLinuxStaticProcessSignalsExample")
}
