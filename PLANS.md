# Plans

## Scope

- JRISC-V is a user-mode RV64 emulator for 64-bit little-endian RISC-V ELF programs.
- Linux-like user-mode execution is the primary compatibility target; FreeBSD user-mode support is incremental.
- Privileged mode, guest page tables, interrupts, devices, and Linux kernel boot are out of scope unless a later plan explicitly adds them.

## Current Baseline

- ISA support targets RVA23U64 when the configured VLEN is profile-valid; shorter vector configurations expose the RVA22U64 capability surface.
- Linux workload coverage includes static C/musl/Go programs, SQLite, CoreMark, RVV examples, `riscv-tests`, Ubuntu Base dynamic-linking smoke tests, interactive shells, fastfetch, curl, and interpreted BellSoft JDK 25 `java -version` and `jshell --version`.
- FreeBSD support covers static Go hello-world and standard-library showcase workloads, including filesystem metadata and mutations, links, timestamp updates, local TCP/UDP networking through kqueue, and `os/exec` child processes through `fork`/`execve`/`wait4` with `kern.proc.pathname` executable-path discovery.
- Gradle-managed external downloads are cached under project-root `downloads/` so `clean` preserves them.

### Runtime Surface

- Syscall handling is split by guest ABI: `GuestSyscalls` owns shared runtime state and helpers, while `LinuxGuestSyscalls` and `FreeBsdGuestSyscalls` own ABI-specific dispatch and compatibility behavior.
- FreeBSD runtime support includes ABI-specific errno conversion, real/effective/saved credential mutation, current and compatibility supplementary-group ABIs, shared session identity and login names with constrained `setsid`, persistent clamped nice values with native negative-success returns, sticky `issetugid` state, deterministic `getrandom`, native POSIX scheduling ranges, numbered single-CPU set allocation and process assignment with cpuset affinity and single-domain memory policies, privileged memory locking, thread naming, one-shot pending `thr_suspend`/`thr_wake` coordination, targeted signal probes, traditional pipe and select/poll readiness interfaces, timer file descriptors, descriptor-range closing with close-on-exec and close-on-fork inheritance, advisory whole-file and record locking, interval and nanosecond sleeps, mapped-memory synchronization and residency calls, positioned vector I/O, regular-file range copying and zeroing, POSIX file allocation and access advice, path configuration queries, process creation and `wait4`/`wait6` observation and reaping, `execve` entry-state setup, read-only runtime sysctl queries, file and filesystem metadata layouts, native directory-entry encoding, traditional and `*at` mutation calls including the current `renameat2` entry point, link creation, path and open-descriptor timestamp updates with native sentinels, native socket structures and flags, and current and legacy kqueue event layouts.
- Linux runtime support includes process/thread state, mutable guest credentials, setuid/setgid exec credential transitions, shared session identity with constrained `setpgid`/`setsid`, persistent clamped nice values, child-exit `SIGCHLD` delivery, deterministic time, tracked `getitimer`/`setitimer` interval timer state, `clone` with normal/clone-child selection and `CLONE_PIDFD`, `wait4`, non-reaping `waitid` including `P_PIDFD`, `pidfd_open`/`pidfd_send_signal`, pollable process descriptors, resource-limit reporting and lowering through `getrlimit`/`setrlimit`/`prlimit64`, single-CPU scheduling policy/priority and affinity syscalls, positioned scalar/vector file I/O, regular-file range copying, file allocation and access advice, validated memory-sync and memory-locking no-op syscalls, descriptor close-on-exec and `close_range` handling, blocking `eventfd2` counters, Linux `timerfd_create`/`timerfd_settime`/`timerfd_gettime`, event-aware `epoll_pwait`/`epoll_pwait2`/`pselect6`/`ppoll` waits for guest-internal descriptors, Linux `#!` binary-format rewriting, terminal raw-mode behavior, and CLI environment overrides.
- LTP syscall work includes a coverage report and an ABI-table driven static smoke ELF for core identity, process/resource, time, random, and filesystem behavior.

### Filesystems And Devices

- The filesystem layer supports Docker-like bind/tar/tmpfs mounts, gzip-compressed memory tar mounts with fork-inherited writable state, virtual `/proc`, minimal virtual `/sys`, Linux-like `/dev` with a basic `/dev/ptmx` and `/dev/pts/0` pseudoterminal pair, and resolver-file fallback for rootfs images with broken `/etc/resolv.conf` symlinks.
- Filesystem metadata includes guest-visible uid, gid, chmod mode bits, process `umask`, Linux-style DAC, setgid directory inheritance, sticky-directory mutation checks, and ancestor-directory search checks.
- Filesystem namespace and mount-spec parsing live under `org.glavo.riscv.runtime.fs`; host paths use `java.nio.file.Path` directly.

### Networking

- Network backend selection lives under `org.glavo.riscv.runtime.net`.
- The opt-in host networking backend supports Linux and FreeBSD IPv4/IPv6 TCP client/server sockets, UDP datagrams, batched message syscalls, FreeBSD kqueue readiness, deterministic Linux `NETLINK_ROUTE` metadata, bind-mounted Unix-domain stream client sockets for X11/Swing workloads, and local Unix-domain stream socket pairs.

### Execution Engine

- CLI execution runs through the plain Java `RiscVEngine` and `RiscVInterpreter` loop.
- Decoded blocks and traces use `ExecutableBlock` and `ExecutableTrace`, with `TraceCompiler` reserved as the future bytecode trace compiler boundary.
- The Java interpreter includes a PC-indexed `DecodedCodeSegment` fast path for batched integer blocks, local segment caches, segment-local operand rewrites, packed register operands, segment-internal fast-slice dispatch, batched retire accounting, lazy memory-fault PC materialization, and aligned scalar memory helpers.
- `MemoryAccess` owns a non-null software TLB directly, while direct `Memory` API paths create short-lived non-null caches without `ThreadLocal` state.

### Graphics

- Graphical-device groundwork includes framebuffer geometry, packed pixel-format metadata, dirty-region tracking, immutable framebuffer snapshots, host ARGB conversion, a Swing framebuffer presentation backend, a Gradle-runnable Swing framebuffer demo, CLI-created Swing framebuffer windows, minimal Linux `/dev/fb0` access, fbdev screen-info ioctls, write-based framebuffer updates, shared framebuffer `mmap` writeback, snapshot-triggered live `mmap` refresh, and static RISC-V Linux framebuffer demos.

## Maintenance Principles

- Expand syscall, ELF, filesystem, terminal, and runtime behavior only when a direct test or real workload requires it.
- Keep profile reporting, Linux `riscv_hwprobe`, README claims, and acceptance tests aligned whenever ISA behavior changes.
- Keep filesystem simulation behind `GuestFileSystem`; avoid coupling workload-specific behavior directly to mount implementations.
- Preserve deterministic behavior for tests, especially around time, process/thread state, random data, terminal state, and child process cleanup.
- Prefer focused smoke workloads over broad host-dependent assumptions.

## Remaining Work

### ISA And Profile Correctness

- Add ISA corner-case coverage as bugs or spec ambiguities are found.
- Preserve the `Zkt`/`Zvkt` audit boundary and keep unimplemented optional extensions unreported.

### Linux Runtime Compatibility

- Continue improving signal, process, clone, exec, and dynamic-linking semantics as workloads require them.
- Add richer `/proc`, `/sys`, device, terminal, and process/thread-scoped filesystem state only when concrete programs need it.
- Extend framebuffer integration beyond the current writeback-based fbdev path when a concrete workload needs it, starting with broader pixel-format negotiation.

### FreeBSD Runtime Compatibility

- Grow FreeBSD stack, auxv, dynamic-linking, syscall, threading, and libc behavior from direct smoke workloads.

### Memory And Mapping

- Reduce syscall-side mapping duplication by moving ELF segments, stack, `brk`, anonymous mappings, `munmap`, `mprotect`, and `madvise` behavior toward one VMA and page-table implementation.
- Preserve the current page-backing shape so native or file-mapped backings can be added later.
- Broaden paged-memory tests as mapping behavior changes.

### Build And Performance

- Keep README, CI aggregation, package smoke tests, example workloads, `riscv-tests`, and RVA22U64/RVA23U64 acceptance tests aligned with behavior changes.
- Continue investigating HotSpot JIT/RVC code generation beyond the interpreted JDK 25 smoke path.
- Continue tuning the decoded segment fast path, trace executor, and micro-bytecode executor from CoreMark/HotLoop measurements before adding a JVM bytecode trace compiler.
