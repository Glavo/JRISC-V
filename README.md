# JRISC-V

JRISC-V is a pure Java RV64 user-mode emulator.
Its long-term goal is to run every Linux and FreeBSD RISC-V 64-bit user-space program without a guest kernel.

Today it can already run real Linux RISC-V userland without a Linux kernel:
Ubuntu Base binaries, interactive Bash, fastfetch, SQLite, CoreMark, Go programs,
and RVV workloads. FreeBSD user-space support has also started, with static
FreeBSD Go programs using credentials, filesystems, local networking, descriptor
readiness, kqueue, and child process execution through the FreeBSD syscall ABI.

## Requirements

- JDK 25

## Run A RISC-V Program

During development, run an ELF directly through Gradle:

```text
./gradlew run --args="path/to/program.riscv64-musl"
```

Pass guest arguments after the ELF path:

```text
./gradlew run --args="path/to/program.riscv64-musl alpha --beta"
```

You can also package it as a Shadow JAR:

```text
./gradlew shadowJar
java -jar build/libs/riscv-1.0-SNAPSHOT-all.jar path/to/program.riscv64-musl
```

## CLI Options

```text
Usage:
jriscv [options] <program.elf> [program-args...]
jriscv [options] --guest-program <path> [program-args...]

Options:
  --guest-program <path>     Load the executable from an absolute guest path resolved through mounts.
  --memory-base <address>    Set the guest memory base address: auto, decimal, or 0x-prefixed hex.
                              Default: 0. auto derives the base from ELF load segments.
  --memory-size <bytes>      Set the guest virtual address window size.
  --page-size <bytes>        Set the guest base page size; must be a power of two >= 4096.
  --max-committed-pages <n>  Limit committed guest base pages; 0 disables the limit.
  --huge-page-size <bytes>   Set the guest HugeTLB page size.
  --huge-pages <n>           Set the number of guest HugeTLB pages.
  --vector-vlen <bits>       Set vector register length. Default: 128.
  --max-instructions <count> Stop after this many guest instructions; 0 disables the limit.
  --mount <spec>             Add a guest filesystem mount:
                              type=bind|tar,src=<path>,dst=<guest>[,readonly|rw][,memory]
                              or type=tmpfs,dst=<guest>[,readonly|rw].
  --network <none|host>      Select the host socket backend. Default: none.
  --use-host-tty             Attach guest /dev/tty to the host controlling terminal when available.
  --framebuffer <width>x<height>
                              Open a Swing framebuffer and expose it as guest /dev/fb0.
  --framebuffer-scale <n>    Set integer Swing framebuffer scale. Default: 3.
  --root                     Use root identity; equivalent to --user root --uid 0 --gid 0 --groups 0.
  --user <name>              Set the guest login name exported in the default environment.
  --uid <id>                 Set guest real, effective, and saved uid. Default: 1000.
  --gid <id>                 Set guest real, effective, and saved gid. Default: 1000.
  --groups <ids|none>        Set comma-separated supplementary guest gids, or none.
  --home <path>              Set the guest home directory used by the default environment.
  --shell <path>             Set the guest shell path used by the default environment.
  --env <name[=value]>       Set a guest environment variable; without =, copy host value.
  --debug-fixed-clock-nanos <nanos>
                              Use fixed epoch nanoseconds for deterministic guest time.
  --debug-trace-compilation  Accepted for compatibility; currently ignored.
  --trace                    Print guest instruction traces.
  -h, --help                 Print this help message.
```

`<program.elf>` is interpreted as a host path. Use `--guest-program` when the
executable must be loaded from a guest mount instead. `--mount` accepts
Docker-like key-value specs for bind mounts, tar archives, and tmpfs trees:
`type=bind,src=./root,dst=/,readonly`,
`type=tar,src=ubuntu-base.tar,dst=/`, or `type=tmpfs,dst=/tmp`. When `type` is
omitted, regular host files are inferred as tar mounts and other host paths are
inferred as bind mounts.

Tar mounts are lazy by default and read file payloads from the archive only when
opened. Add `memory` to load a tar archive into process memory; add `rw` as well
to allow guest writes that are discarded when the process exits. Tmpfs mounts
are empty writable in-memory trees by default. If no `/` mount is provided for a
host executable, the CLI mounts the executable's containing directory at `/`.
By default, guest `/dev/tty` is backed by the configured process streams; pass
`--use-host-tty` to try a real host controlling terminal when available. Pass
`--framebuffer <width>x<height>` to create a Swing-backed XRGB8888 framebuffer
that guest Linux programs can access through `/dev/fb0`. Use `--env NAME=value`
to append or override one guest environment entry; `--env NAME` copies the
current host value.

Guest host sockets are disabled by default. Pass `--network host` to map Linux
or FreeBSD IPv4 and IPv6 TCP/UDP sockets, plus filesystem-backed Unix-domain
stream sockets, to host Java NIO sockets. Linux `NETLINK_ROUTE` and
network-interface ioctl metadata remain synthetic. Swing/AWT programs running inside the guest can reach
an X11 server by bind-mounting the host socket directory, for example
`--mount type=bind,src=/tmp/.X11-unix,dst=/tmp/.X11-unix,readonly`, and passing
`--env DISPLAY`. Mount the host Xauthority file too when your X server requires
cookie authentication:

```text
java -jar build/libs/riscv-1.0-SNAPSHOT-all.jar \
  --mount src=./ubuntu-26.04-server-cloudimg-riscv64-root.tar,dst=/,memory \
  --mount type=bind,src=/tmp/.X11-unix,dst=/tmp/.X11-unix,readonly \
  --mount type=bind,src="${XAUTHORITY:-$HOME/.Xauthority}",dst=/root/.Xauthority,readonly \
  --network host \
  --root \
  --env DISPLAY \
  --env XAUTHORITY=/root/.Xauthority \
  --guest-program /path/to/java -jar /path/to/app.jar
```

## Supported ELF Inputs

The loader accepts ELF64 little-endian RISC-V `ET_EXEC` and `ET_DYN` inputs with
System V, GNU/Linux, or FreeBSD OS ABI markers. It validates segment ranges,
alignment, permissions, overlap, entry-point placement, and dynamic interpreter
metadata before execution. Dynamically linked Linux programs are supported when
their interpreter and shared libraries are available through configured guest
mounts. FreeBSD ELF support currently selects the FreeBSD RISC-V syscall ABI for
static user-mode programs and a growing syscall subset.

## Current Linux User-Mode Support

The simulator implements enough Linux RISC-V user-mode behavior to run the
bundled static musl examples, the static Go example, CoreMark, RVV examples, and
common dynamically linked Ubuntu Base shell, coreutils, and findutils commands.
File access is sandboxed under configured `--mount` entries, with built-in
`/proc` and `/dev` virtual filesystems for process metadata and basic character
devices. Guest uid, gid, supplementary groups, login name, home, and shell can be
configured with CLI options. Host passthrough networking is opt-in with
`--network host`, which enables IPv4 and IPv6 TCP client/server sockets, UDP
datagrams, and bind-mounted Unix-domain stream sockets through the host network
stack. Local Unix-domain stream `socketpair` descriptors are supported even
without host networking. Synthetic netlink and interface ioctl metadata remain
available. Process creation supports Linux clone-child selection, `wait4`,
`waitid`, and pollable pidfds created by `pidfd_open` or `CLONE_PIDFD`.

## Examples

Each `run...Example` task builds the required RISC-V program before executing
it.

The `decompressUbuntuBaseImage` task downloads Ubuntu Base 26.04 for RISC-V and
produces a `.tar` root filesystem under `downloads/ubuntu-base/26.04`
without unpacking the tar entries.

The `decompressFastfetchArchive` task downloads fastfetch for Linux RISC-V from
GitHub releases and produces a `.tar` archive under
`downloads/fastfetch`. The default version is 2.62.1; override it with
`-PfastfetchVersion=<version>`. The `runFastfetch`, `testFastfetchVersion`, and
`testFastfetch` tasks also mount Ubuntu Base because the fastfetch release
binary is dynamically linked.

Run the Ubuntu Base dynamic-linking smoke tests:

```text
./gradlew testUbuntuBaseTrue
./gradlew testUbuntuBaseBash
./gradlew testUbuntuBaseLs
./gradlew testUbuntuBaseCat
./gradlew testUbuntuBaseFind
```

The C and CoreMark examples use Zig CC. Gradle downloads the configured Zig
release when needed. To use an existing Zig executable command or path, set one
of `ZIG_EXECUTABLE`, `zigExecutable`, or `jriscv.zigExecutable`:

```text
ZIG_EXECUTABLE=zig ./gradlew runLinuxStaticPrintfExample
ZIG_EXECUTABLE=/path/to/zig ./gradlew runLinuxStaticPrintfExample
./gradlew "-PzigExecutable=/path/to/zig" runLinuxStaticPrintfExample
```

The Go example uses the Go toolchain. Gradle downloads the configured Go
release when needed. To use an existing Go executable command or path, set one
of `GO_EXECUTABLE`, `goExecutable`, or `jriscv.goExecutable`:

```text
GO_EXECUTABLE=go ./gradlew runGoHelloWorldExample
GO_EXECUTABLE=/path/to/go ./gradlew runGoHelloWorldExample
./gradlew "-PgoExecutable=/path/to/go" runGoHelloWorldExample
```

| Example | Purpose | Command |
| --- | --- | --- |
| Freestanding Hello World | Run the smallest freestanding output example. | `./gradlew runHelloWorldExample` |
| Freestanding hot loop | Run a small CPU hot-loop probe. | `./gradlew runHotLoopExample` |
| Static Linux Go hello-world | Build and run a static `linux/riscv64` Go program. | `./gradlew runGoHelloWorldExample` |
| Static FreeBSD Go hello-world | Build and run a static `freebsd/riscv64` Go program. | `./gradlew runFreeBsdGoHelloWorldExample` |
| Static Linux Go showcase | Run a larger Linux Go standard-library workload covering filesystem metadata and mutations, links, local TCP/UDP networking, `os/exec`, executable-path discovery, JSON, sorting, compression, hashing, and goroutines. | `./gradlew runGoShowcaseExample` |
| Static FreeBSD Go showcase | Run the same filesystem, networking, process, executable-path, and standard-library workload through the FreeBSD syscall ABI and kqueue. | `./gradlew runFreeBsdGoShowcaseExample` |
| Static musl printf | Run a static musl `printf` hello-world program. | `./gradlew runLinuxStaticPrintfExample` |
| Static musl framebuffer | Build and run a RISC-V Linux program that renders animation through `/dev/fb0` in a Swing window. | `./gradlew runLinuxStaticFramebufferDemo` |
| SQLite showcase | Download SQLite, build a static RISC-V file-database demo, and run transactions and queries. | `./gradlew runSQLiteShowcaseExample` |
| fastfetch | Download the Linux RISC-V fastfetch release tar and run it. | `./gradlew runFastfetch` |
| RVV vector add | Build and run the RVV vector-add example. | `./gradlew runRvvVectorAddExample` |
| RVV matrix transpose | Build and run the RVV matrix-transpose smoke example. | `./gradlew runRvvMatrixTransposeExample` |
| RVV reduction | Build and run the RVV reduction smoke example. | `./gradlew runRvvReductionExample` |
| RVV softmax | Build and run the RVV softmax example. | `./gradlew runRvvSoftmaxExample` |
| RVV polynomial basic | Build and run the RVV polynomial basic example. | `./gradlew runRvvPolynomialBasicExample` |
| RVV micro-benchmark | Build and run the RVV micro-benchmark example. | `./gradlew runRvvUbenchExample` |
| RVV CRC | Build and run the RVV CRC smoke example. | `./gradlew runRvvCrcExample` |
| CoreMark | Build and run the downloaded CoreMark benchmark. | `./gradlew runCoreMarkExample` |

Run the larger showcase workloads together:

```text
./gradlew checkShowcaseExamples
```

## RISC-V ISA Acceptance Tests

Run the RV64GC baseline `riscv-tests` ISA acceptance tests through the
JRISC-V CLI:

```text
./gradlew buildRiscVTests
./gradlew testRiscVTests
```

Run the repository-owned RVA22U64 extension acceptance tests:

```text
./gradlew testRva22Acceptance
```

Run the repository-owned RVA23U64 extension acceptance tests:

```text
./gradlew testRva23Acceptance
```

Use `jriscv.riscvTestsFilter` to run a subset by ELF filename regex, and
`jriscv.riscvTestsMaxInstructions` to override the per-ELF instruction
limit:

```text
./gradlew "-Pjriscv.riscvTestsFilter=^rv64ui-p-.*[.]elf$" testRiscVTests
./gradlew "-Pjriscv.riscvTestsMaxInstructions=20000000" testRiscVTests
```

## LTP Syscall Checks

Generate the Linux Test Project syscall coverage guide:

```text
./gradlew ltpSyscallCoverage
```

Run the LTP ABI-table driven syscall smoke test:

```text
./gradlew testLtpSyscallSmoke
```

Run both checks:

```text
./gradlew ltpSyscallCheck
```

The smoke test is generated from LTP's asm-generic 64-bit syscall table and
then built as a static `riscv64-linux-musl` ELF before running through the
JRISC-V CLI. It covers identity, process/resource, time, random, and
bind-mounted file-system syscall behavior.

## Package And CI Smoke Checks

Run package smoke tests that do not require Zig:

```text
./gradlew packageSmokeTest
```

This generates a tiny RISC-V ELF fixture under `build/fixtures/smoke`, then runs
it through both the `installDist` launcher and the packaged Shadow JAR.

Run the local CI verification task:

```text
./gradlew ciCheck
```

This compiles main and test sources, runs the unit tests, builds distribution
artifacts, builds the Shadow JAR, and runs no-toolchain package smoke checks.
When the managed Zig archive, extracted toolchain, or manual Zig executable
configuration is already present, it also runs the static Linux C example
checks and the RVA22U64/RVA23U64 acceptance suites.

Run the Zig-backed CI example checks explicitly:

```text
./gradlew ciZigExampleCheck
```

Force `ciCheck` to download/use Zig and include those checks:

```text
./gradlew -PjriscvCiIncludeZigExamples=true ciCheck
```

## Native Image Packaging

The build includes opt-in native-image packaging tasks for environments with a
GraalVM Native Image toolchain:

```text
./gradlew nativeCompile
./gradlew nativeImageSmokeTest
```

JVM mode is the primary path for current performance work.

## Performance Work

CoreMark and the freestanding hot-loop example are useful probes for dispatch
and block-cache performance. The CLI still accepts `--debug-trace-compilation`
as a compatibility option for existing scripts; it is currently a no-op until
trace compiler diagnostics are added:

```text
./gradlew runHotLoopCompilationTrace
```
