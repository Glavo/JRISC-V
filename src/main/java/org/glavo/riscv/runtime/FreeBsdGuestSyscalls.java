// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.riscv.runtime;

import org.glavo.riscv.exception.ProgramExitException;
import org.glavo.riscv.exception.RiscVException;
import org.glavo.riscv.memory.Memory;
import org.glavo.riscv.runtime.fs.GuestFileSystem;
import org.glavo.riscv.runtime.fs.GuestFileSystem.DirectoryEntry;
import org.glavo.riscv.runtime.fs.GuestFileSystem.VirtualMount;
import org.glavo.riscv.runtime.net.GuestNetworkBackend;
import org.glavo.riscv.runtime.net.GuestNetworkMode;
import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Unmodifiable;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.net.UnixDomainSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

/// Handles the FreeBSD RISC-V syscall ABI exposed by the simulator.
@NotNullByDefault
public final class FreeBsdGuestSyscalls extends LinuxGuestSyscalls {
    /// Whether a successful FreeBSD credential mutation has marked this process as set-id.
    private boolean credentialStateChanged;

    /// Creates a FreeBSD syscall handler backed by streams, lazy filesystem mounts, time source, credentials,
    /// terminal option, and guest thread runner.
    public FreeBsdGuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String @Unmodifiable [] filesystemMountSpecs,
            TimeSource timeSource,
            boolean useHostTty,
            GuestCredentials credentials,
            GuestThreadRunner guestThreadRunner) {
        this(
                memory,
                in,
                out,
                err,
                initialProgramBreak,
                filesystemMountSpecs,
                timeSource,
                useHostTty,
                credentials,
                guestThreadRunner,
                null);
    }

    /// Creates a FreeBSD syscall handler backed by streams, lazy filesystem mounts, time source, credentials,
    /// terminal option, guest thread runner, and framebuffer device.
    public FreeBsdGuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String @Unmodifiable [] filesystemMountSpecs,
            TimeSource timeSource,
            boolean useHostTty,
            GuestCredentials credentials,
            GuestThreadRunner guestThreadRunner,
            @Nullable FramebufferDevice framebufferDevice) {
        this(
                memory,
                in,
                out,
                err,
                initialProgramBreak,
                filesystemMountSpecs,
                timeSource,
                useHostTty,
                credentials,
                guestThreadRunner,
                framebufferDevice,
                GuestNetworkMode.NONE.backend());
    }

    /// Creates a FreeBSD syscall handler backed by streams, lazy filesystem mounts, time source, credentials,
    /// terminal option, guest thread runner, framebuffer device, and networking backend.
    public FreeBsdGuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String @Unmodifiable [] filesystemMountSpecs,
            TimeSource timeSource,
            boolean useHostTty,
            GuestCredentials credentials,
            GuestThreadRunner guestThreadRunner,
            @Nullable FramebufferDevice framebufferDevice,
            GuestNetworkBackend networkBackend) {
        super(
                memory,
                in,
                out,
                err,
                initialProgramBreak,
                filesystemMountSpecs,
                timeSource,
                useHostTty,
                credentials,
                guestThreadRunner,
                framebufferDevice,
                networkBackend);
        initializeFreeBsdLoginName(credentials.userName());
    }

    /// Creates a child-process FreeBSD syscall handler by copying fork-inherited parent state.
    private FreeBsdGuestSyscalls(FreeBsdGuestSyscalls parent, Memory memory, GuestProcess process) {
        super(parent, memory, process);
        this.credentialStateChanged = parent.credentialStateChanged;
    }

    /// The FreeBSD RISC-V syscall number for the `syscall` indirection entry.
    private static final int FREEBSD_SYS_SYSCALL = 0;

    /// The FreeBSD RISC-V syscall number for `exit`.
    private static final int FREEBSD_SYS_EXIT = 1;

    /// The FreeBSD RISC-V syscall number for `fork`.
    private static final int FREEBSD_SYS_FORK = 2;

    /// The FreeBSD RISC-V syscall number for `read`.
    private static final int FREEBSD_SYS_READ = 3;

    /// The FreeBSD RISC-V syscall number for `write`.
    private static final int FREEBSD_SYS_WRITE = 4;

    /// The FreeBSD RISC-V syscall number for `open`.
    private static final int FREEBSD_SYS_OPEN = 5;

    /// The FreeBSD RISC-V syscall number for `close`.
    private static final int FREEBSD_SYS_CLOSE = 6;

    /// The FreeBSD RISC-V syscall number for `wait4`.
    private static final int FREEBSD_SYS_WAIT4 = 7;

    /// The FreeBSD RISC-V syscall number for `link`.
    private static final int FREEBSD_SYS_LINK = 9;

    /// The FreeBSD RISC-V syscall number for `unlink`.
    private static final int FREEBSD_SYS_UNLINK = 10;

    /// The FreeBSD RISC-V syscall number for `chdir`.
    private static final int FREEBSD_SYS_CHDIR = 12;

    /// The FreeBSD RISC-V syscall number for `fchdir`.
    private static final int FREEBSD_SYS_FCHDIR = 13;

    /// The FreeBSD RISC-V syscall number for `chmod`.
    private static final int FREEBSD_SYS_CHMOD = 15;

    /// The FreeBSD RISC-V syscall number for `chown`.
    private static final int FREEBSD_SYS_CHOWN = 16;

    /// The FreeBSD RISC-V syscall number for `getpid`.
    private static final int FREEBSD_SYS_GETPID = 20;

    /// The FreeBSD RISC-V syscall number for `setuid`.
    private static final int FREEBSD_SYS_SETUID = 23;

    /// The FreeBSD RISC-V syscall number for `getuid`.
    private static final int FREEBSD_SYS_GETUID = 24;

    /// The FreeBSD RISC-V syscall number for `geteuid`.
    private static final int FREEBSD_SYS_GETEUID = 25;

    /// The FreeBSD RISC-V syscall number for `recvmsg`.
    private static final int FREEBSD_SYS_RECVMSG = 27;

    /// The FreeBSD RISC-V syscall number for `sendmsg`.
    private static final int FREEBSD_SYS_SENDMSG = 28;

    /// The FreeBSD RISC-V syscall number for `recvfrom`.
    private static final int FREEBSD_SYS_RECVFROM = 29;

    /// The FreeBSD RISC-V syscall number for `accept`.
    private static final int FREEBSD_SYS_ACCEPT = 30;

    /// The FreeBSD RISC-V syscall number for `getpeername`.
    private static final int FREEBSD_SYS_GETPEERNAME = 31;

    /// The FreeBSD RISC-V syscall number for `getsockname`.
    private static final int FREEBSD_SYS_GETSOCKNAME = 32;

    /// The FreeBSD RISC-V syscall number for `access`.
    private static final int FREEBSD_SYS_ACCESS = 33;

    /// The FreeBSD RISC-V syscall number for `sync`.
    private static final int FREEBSD_SYS_SYNC = 36;

    /// The FreeBSD RISC-V syscall number for `kill`.
    private static final int FREEBSD_SYS_KILL = 37;

    /// The FreeBSD RISC-V syscall number for `sigaltstack`.
    private static final int FREEBSD_SYS_SIGALTSTACK = 53;

    /// The FreeBSD RISC-V syscall number for `getppid`.
    private static final int FREEBSD_SYS_GETPPID = 39;

    /// The FreeBSD RISC-V syscall number for `dup`.
    private static final int FREEBSD_SYS_DUP = 41;

    /// The FreeBSD RISC-V syscall number for legacy `pipe`.
    private static final int FREEBSD_SYS_PIPE = 42;

    /// The FreeBSD RISC-V syscall number for `getegid`.
    private static final int FREEBSD_SYS_GETEGID = 43;

    /// The FreeBSD RISC-V syscall number for `getgid`.
    private static final int FREEBSD_SYS_GETGID = 47;

    /// The FreeBSD RISC-V syscall number for `getlogin`.
    private static final int FREEBSD_SYS_GETLOGIN = 49;

    /// The FreeBSD RISC-V syscall number for `setlogin`.
    private static final int FREEBSD_SYS_SETLOGIN = 50;

    /// The FreeBSD RISC-V syscall number for `ioctl`.
    private static final int FREEBSD_SYS_IOCTL = 54;

    /// The FreeBSD RISC-V syscall number for `symlink`.
    private static final int FREEBSD_SYS_SYMLINK = 57;

    /// The FreeBSD RISC-V syscall number for `readlink`.
    private static final int FREEBSD_SYS_READLINK = 58;

    /// The FreeBSD RISC-V syscall number for `execve`.
    private static final int FREEBSD_SYS_EXECVE = 59;

    /// The FreeBSD RISC-V syscall number for `umask`.
    private static final int FREEBSD_SYS_UMASK = 60;

    /// The FreeBSD RISC-V syscall number for `msync`.
    private static final int FREEBSD_SYS_MSYNC = 65;

    /// The FreeBSD RISC-V syscall number for `munmap`.
    private static final int FREEBSD_SYS_MUNMAP = 73;

    /// The FreeBSD RISC-V syscall number for `mprotect`.
    private static final int FREEBSD_SYS_MPROTECT = 74;

    /// The FreeBSD RISC-V syscall number for `madvise`.
    private static final int FREEBSD_SYS_MADVISE = 75;

    /// The FreeBSD RISC-V syscall number for `mincore`.
    private static final int FREEBSD_SYS_MINCORE = 78;

    /// The FreeBSD RISC-V syscall number for `getgroups`.
    private static final int FREEBSD_SYS_GETGROUPS = 79;

    /// The FreeBSD RISC-V syscall number for `setgroups`.
    private static final int FREEBSD_SYS_SETGROUPS = 80;

    /// The FreeBSD RISC-V syscall number for `getpgrp`.
    private static final int FREEBSD_SYS_GETPGRP = 81;

    /// The FreeBSD RISC-V syscall number for `setpgid`.
    private static final int FREEBSD_SYS_SETPGID = 82;

    /// The FreeBSD RISC-V syscall number for `setitimer`.
    private static final int FREEBSD_SYS_SETITIMER = 83;

    /// The FreeBSD RISC-V syscall number for `getitimer`.
    private static final int FREEBSD_SYS_GETITIMER = 86;

    /// The FreeBSD RISC-V syscall number for `getdtablesize`.
    private static final int FREEBSD_SYS_GETDTABLESIZE = 89;

    /// The FreeBSD RISC-V syscall number for `dup2`.
    private static final int FREEBSD_SYS_DUP2 = 90;

    /// The FreeBSD RISC-V syscall number for `fcntl`.
    private static final int FREEBSD_SYS_FCNTL = 92;

    /// The FreeBSD RISC-V syscall number for `select`.
    private static final int FREEBSD_SYS_SELECT = 93;

    /// The FreeBSD RISC-V syscall number for `fsync`.
    private static final int FREEBSD_SYS_FSYNC = 95;

    /// The FreeBSD RISC-V syscall number for `setpriority`.
    private static final int FREEBSD_SYS_SETPRIORITY = 96;

    /// The FreeBSD RISC-V syscall number for `socket`.
    private static final int FREEBSD_SYS_SOCKET = 97;

    /// The FreeBSD RISC-V syscall number for `connect`.
    private static final int FREEBSD_SYS_CONNECT = 98;

    /// The FreeBSD RISC-V syscall number for `getpriority`.
    private static final int FREEBSD_SYS_GETPRIORITY = 100;

    /// The FreeBSD RISC-V syscall number for `bind`.
    private static final int FREEBSD_SYS_BIND = 104;

    /// The FreeBSD RISC-V syscall number for `setsockopt`.
    private static final int FREEBSD_SYS_SETSOCKOPT = 105;

    /// The FreeBSD RISC-V syscall number for `listen`.
    private static final int FREEBSD_SYS_LISTEN = 106;

    /// The FreeBSD RISC-V syscall number for `gettimeofday`.
    private static final int FREEBSD_SYS_GETTIMEOFDAY = 116;

    /// The FreeBSD RISC-V syscall number for `getrusage`.
    private static final int FREEBSD_SYS_GETRUSAGE = 117;

    /// The FreeBSD RISC-V syscall number for `getsockopt`.
    private static final int FREEBSD_SYS_GETSOCKOPT = 118;

    /// The FreeBSD RISC-V syscall number for `fchown`.
    private static final int FREEBSD_SYS_FCHOWN = 123;

    /// The FreeBSD RISC-V syscall number for `fchmod`.
    private static final int FREEBSD_SYS_FCHMOD = 124;

    /// The FreeBSD RISC-V syscall number for `flock`.
    private static final int FREEBSD_SYS_FLOCK = 131;

    /// The FreeBSD RISC-V syscall number for `setreuid`.
    private static final int FREEBSD_SYS_SETREUID = 126;

    /// The FreeBSD RISC-V syscall number for `setregid`.
    private static final int FREEBSD_SYS_SETREGID = 127;

    /// The FreeBSD RISC-V syscall number for `rename`.
    private static final int FREEBSD_SYS_RENAME = 128;

    /// The FreeBSD RISC-V syscall number for `sendto`.
    private static final int FREEBSD_SYS_SENDTO = 133;

    /// The FreeBSD RISC-V syscall number for `shutdown`.
    private static final int FREEBSD_SYS_SHUTDOWN = 134;

    /// The FreeBSD RISC-V syscall number for `socketpair`.
    private static final int FREEBSD_SYS_SOCKETPAIR = 135;

    /// The FreeBSD RISC-V syscall number for `mkdir`.
    private static final int FREEBSD_SYS_MKDIR = 136;

    /// The FreeBSD RISC-V syscall number for `rmdir`.
    private static final int FREEBSD_SYS_RMDIR = 137;

    /// The FreeBSD RISC-V syscall number for `readv`.
    private static final int FREEBSD_SYS_READV = 120;

    /// The FreeBSD RISC-V syscall number for `writev`.
    private static final int FREEBSD_SYS_WRITEV = 121;

    /// The FreeBSD RISC-V syscall number for `setsid`.
    private static final int FREEBSD_SYS_SETSID = 147;

    /// The FreeBSD RISC-V syscall number for `setgid`.
    private static final int FREEBSD_SYS_SETGID = 181;

    /// The FreeBSD RISC-V syscall number for `setegid`.
    private static final int FREEBSD_SYS_SETEGID = 182;

    /// The FreeBSD RISC-V syscall number for `seteuid`.
    private static final int FREEBSD_SYS_SETEUID = 183;

    /// The FreeBSD RISC-V syscall number for `pathconf`.
    private static final int FREEBSD_SYS_PATHCONF = 191;

    /// The FreeBSD RISC-V syscall number for `fpathconf`.
    private static final int FREEBSD_SYS_FPATHCONF = 192;

    /// The FreeBSD RISC-V syscall number for `__syscall`.
    private static final int FREEBSD_SYS___SYSCALL = 198;

    /// The FreeBSD RISC-V syscall number for `getrlimit`.
    private static final int FREEBSD_SYS_GETRLIMIT = 194;

    /// The FreeBSD RISC-V syscall number for `setrlimit`.
    private static final int FREEBSD_SYS_SETRLIMIT = 195;

    /// The FreeBSD RISC-V syscall number for `__sysctl`.
    private static final int FREEBSD_SYS___SYSCTL = 202;

    /// The FreeBSD RISC-V syscall number for `mlock`.
    private static final int FREEBSD_SYS_MLOCK = 203;

    /// The FreeBSD RISC-V syscall number for `munlock`.
    private static final int FREEBSD_SYS_MUNLOCK = 204;

    /// The FreeBSD RISC-V syscall number for `getpgid`.
    private static final int FREEBSD_SYS_GETPGID = 207;

    /// The FreeBSD RISC-V syscall number for `poll`.
    private static final int FREEBSD_SYS_POLL = 209;

    /// The FreeBSD RISC-V syscall number for `clock_gettime`.
    private static final int FREEBSD_SYS_CLOCK_GETTIME = 232;

    /// The FreeBSD RISC-V syscall number for `clock_getres`.
    private static final int FREEBSD_SYS_CLOCK_GETRES = 234;

    /// The FreeBSD RISC-V syscall number for `nanosleep`.
    private static final int FREEBSD_SYS_NANOSLEEP = 240;

    /// The FreeBSD RISC-V syscall number for `clock_nanosleep`.
    private static final int FREEBSD_SYS_CLOCK_NANOSLEEP = 244;

    /// The FreeBSD RISC-V syscall number for `issetugid`.
    private static final int FREEBSD_SYS_ISSETUGID = 253;

    /// The FreeBSD RISC-V syscall number for `preadv`.
    private static final int FREEBSD_SYS_PREADV = 289;

    /// The FreeBSD RISC-V syscall number for `pwritev`.
    private static final int FREEBSD_SYS_PWRITEV = 290;

    /// The FreeBSD RISC-V syscall number for `getsid`.
    private static final int FREEBSD_SYS_GETSID = 310;

    /// The FreeBSD RISC-V syscall number for `setresuid`.
    private static final int FREEBSD_SYS_SETRESUID = 311;

    /// The FreeBSD RISC-V syscall number for `setresgid`.
    private static final int FREEBSD_SYS_SETRESGID = 312;

    /// The FreeBSD RISC-V syscall number for the legacy `yield` entry point.
    private static final int FREEBSD_SYS_YIELD = 321;

    /// The FreeBSD RISC-V syscall number for `mlockall`.
    private static final int FREEBSD_SYS_MLOCKALL = 324;

    /// The FreeBSD RISC-V syscall number for `munlockall`.
    private static final int FREEBSD_SYS_MUNLOCKALL = 325;

    /// The FreeBSD RISC-V syscall number for `__getcwd`.
    private static final int FREEBSD_SYS___GETCWD = 326;

    /// The FreeBSD RISC-V syscall number for `sched_setparam`.
    private static final int FREEBSD_SYS_SCHED_SETPARAM = 327;

    /// The FreeBSD RISC-V syscall number for `sched_getparam`.
    private static final int FREEBSD_SYS_SCHED_GETPARAM = 328;

    /// The FreeBSD RISC-V syscall number for `sched_setscheduler`.
    private static final int FREEBSD_SYS_SCHED_SETSCHEDULER = 329;

    /// The FreeBSD RISC-V syscall number for `sched_getscheduler`.
    private static final int FREEBSD_SYS_SCHED_GETSCHEDULER = 330;

    /// The FreeBSD RISC-V syscall number for `sched_yield`.
    private static final int FREEBSD_SYS_SCHED_YIELD = 331;

    /// The FreeBSD RISC-V syscall number for `sched_get_priority_max`.
    private static final int FREEBSD_SYS_SCHED_GET_PRIORITY_MAX = 332;

    /// The FreeBSD RISC-V syscall number for `sched_get_priority_min`.
    private static final int FREEBSD_SYS_SCHED_GET_PRIORITY_MIN = 333;

    /// The FreeBSD RISC-V syscall number for `sched_rr_get_interval`.
    private static final int FREEBSD_SYS_SCHED_RR_GET_INTERVAL = 334;

    /// The FreeBSD RISC-V syscall number for `sigprocmask`.
    private static final int FREEBSD_SYS_SIGPROCMASK = 340;

    /// The FreeBSD RISC-V syscall number for `getresuid`.
    private static final int FREEBSD_SYS_GETRESUID = 360;

    /// The FreeBSD RISC-V syscall number for `getresgid`.
    private static final int FREEBSD_SYS_GETRESGID = 361;

    /// The FreeBSD RISC-V syscall number for `kqueue`.
    private static final int FREEBSD_SYS_KQUEUE = 362;

    /// The FreeBSD RISC-V syscall number for the legacy 32-byte `kevent` ABI.
    private static final int FREEBSD_SYS_FREEBSD11_KEVENT = 363;

    /// The FreeBSD RISC-V syscall number for `sigaction`.
    private static final int FREEBSD_SYS_SIGACTION = 416;

    /// The FreeBSD RISC-V syscall number for `thr_exit`.
    private static final int FREEBSD_SYS_THR_EXIT = 431;

    /// The FreeBSD RISC-V syscall number for `thr_self`.
    private static final int FREEBSD_SYS_THR_SELF = 432;

    /// The FreeBSD RISC-V syscall number for `thr_kill`.
    private static final int FREEBSD_SYS_THR_KILL = 433;

    /// The FreeBSD RISC-V syscall number for `thr_suspend`.
    private static final int FREEBSD_SYS_THR_SUSPEND = 442;

    /// The FreeBSD RISC-V syscall number for `thr_wake`.
    private static final int FREEBSD_SYS_THR_WAKE = 443;

    /// The FreeBSD RISC-V syscall number for `_umtx_op`.
    private static final int FREEBSD_SYS_UMTX_OP = 454;

    /// The FreeBSD RISC-V syscall number for `thr_new`.
    private static final int FREEBSD_SYS_THR_NEW = 455;

    /// The FreeBSD RISC-V syscall number for `thr_set_name`.
    private static final int FREEBSD_SYS_THR_SET_NAME = 464;

    /// The FreeBSD RISC-V syscall number for `pread`.
    private static final int FREEBSD_SYS_PREAD = 475;

    /// The FreeBSD RISC-V syscall number for `pwrite`.
    private static final int FREEBSD_SYS_PWRITE = 476;

    /// The FreeBSD RISC-V syscall number for `mmap`.
    private static final int FREEBSD_SYS_MMAP = 477;

    /// The FreeBSD RISC-V syscall number for `lseek`.
    private static final int FREEBSD_SYS_LSEEK = 478;

    /// The FreeBSD RISC-V syscall number for `truncate`.
    private static final int FREEBSD_SYS_TRUNCATE = 479;

    /// The FreeBSD RISC-V syscall number for `ftruncate`.
    private static final int FREEBSD_SYS_FTRUNCATE = 480;

    /// The FreeBSD RISC-V syscall number for `thr_kill2`.
    private static final int FREEBSD_SYS_THR_KILL2 = 481;

    /// The FreeBSD RISC-V syscall number for `cpuset`.
    private static final int FREEBSD_SYS_CPUSET = 484;

    /// The FreeBSD RISC-V syscall number for `cpuset_setid`.
    private static final int FREEBSD_SYS_CPUSET_SETID = 485;

    /// The FreeBSD RISC-V syscall number for `cpuset_getid`.
    private static final int FREEBSD_SYS_CPUSET_GETID = 486;

    /// The FreeBSD RISC-V syscall number for `faccessat`.
    private static final int FREEBSD_SYS_FACCESSAT = 489;

    /// The FreeBSD RISC-V syscall number for `fchmodat`.
    private static final int FREEBSD_SYS_FCHMODAT = 490;

    /// The FreeBSD RISC-V syscall number for `cpuset_getaffinity`.
    private static final int FREEBSD_SYS_CPUSET_GETAFFINITY = 487;

    /// The FreeBSD RISC-V syscall number for `cpuset_setaffinity`.
    private static final int FREEBSD_SYS_CPUSET_SETAFFINITY = 488;

    /// The FreeBSD RISC-V syscall number for `fchownat`.
    private static final int FREEBSD_SYS_FCHOWNAT = 491;

    /// The FreeBSD RISC-V syscall number for `linkat`.
    private static final int FREEBSD_SYS_LINKAT = 495;

    /// The FreeBSD RISC-V syscall number for `mkdirat`.
    private static final int FREEBSD_SYS_MKDIRAT = 496;

    /// The FreeBSD RISC-V syscall number for `openat`.
    private static final int FREEBSD_SYS_OPENAT = 499;

    /// The FreeBSD RISC-V syscall number for `readlinkat`.
    private static final int FREEBSD_SYS_READLINKAT = 500;

    /// The FreeBSD RISC-V syscall number for `renameat`.
    private static final int FREEBSD_SYS_RENAMEAT = 501;

    /// The FreeBSD RISC-V syscall number for `symlinkat`.
    private static final int FREEBSD_SYS_SYMLINKAT = 502;

    /// The FreeBSD RISC-V syscall number for `unlinkat`.
    private static final int FREEBSD_SYS_UNLINKAT = 503;

    /// The FreeBSD RISC-V syscall number for `closefrom`.
    private static final int FREEBSD_SYS_CLOSEFROM = 509;

    /// The FreeBSD RISC-V syscall number for `lpathconf`.
    private static final int FREEBSD_SYS_LPATHCONF = 513;

    /// The FreeBSD RISC-V syscall number for `pselect`.
    private static final int FREEBSD_SYS_PSELECT = 522;

    /// The FreeBSD RISC-V syscall number for `posix_fallocate`.
    private static final int FREEBSD_SYS_POSIX_FALLOCATE = 530;

    /// The FreeBSD RISC-V syscall number for `posix_fadvise`.
    private static final int FREEBSD_SYS_POSIX_FADVISE = 531;

    /// The FreeBSD RISC-V syscall number for `wait6`.
    private static final int FREEBSD_SYS_WAIT6 = 532;

    /// FreeBSD `P_PID`.
    private static final int FREEBSD_WAIT_ID_PROCESS = 0;

    /// FreeBSD `P_PPID`.
    private static final int FREEBSD_WAIT_ID_PARENT_PROCESS = 1;

    /// FreeBSD `P_PGID`.
    private static final int FREEBSD_WAIT_ID_PROCESS_GROUP = 2;

    /// FreeBSD `P_ALL`.
    private static final int FREEBSD_WAIT_ID_ALL = 7;

    /// FreeBSD `WNOHANG`.
    private static final long FREEBSD_WAIT_NO_HANG = 0x0000_0001L;

    /// FreeBSD `WUNTRACED` and `WSTOPPED`.
    private static final long FREEBSD_WAIT_UNTRACED = 0x0000_0002L;

    /// FreeBSD `WCONTINUED`.
    private static final long FREEBSD_WAIT_CONTINUED = 0x0000_0004L;

    /// FreeBSD `WNOWAIT`.
    private static final long FREEBSD_WAIT_NO_WAIT = 0x0000_0008L;

    /// FreeBSD `WEXITED`.
    private static final long FREEBSD_WAIT_EXITED = 0x0000_0010L;

    /// FreeBSD `WTRAPPED`.
    private static final long FREEBSD_WAIT_TRAPPED = 0x0000_0020L;

    /// FreeBSD `WLINUXCLONE`.
    private static final long FREEBSD_WAIT_LINUX_CLONE = 0x8000_0000L;

    /// FreeBSD `wait6` option bits accepted by the simulator.
    private static final long FREEBSD_SUPPORTED_WAIT6_OPTIONS = FREEBSD_WAIT_NO_HANG
            | FREEBSD_WAIT_UNTRACED
            | FREEBSD_WAIT_CONTINUED
            | FREEBSD_WAIT_NO_WAIT
            | FREEBSD_WAIT_EXITED
            | FREEBSD_WAIT_TRAPPED
            | FREEBSD_WAIT_LINUX_CLONE;

    /// FreeBSD `wait6` option bits that select reportable child events.
    private static final long FREEBSD_WAIT6_EVENT_OPTIONS = FREEBSD_WAIT_UNTRACED
            | FREEBSD_WAIT_CONTINUED
            | FREEBSD_WAIT_EXITED
            | FREEBSD_WAIT_TRAPPED;

    /// FreeBSD `SIGCHLD`.
    private static final int FREEBSD_SIGNAL_CHILD = 20;

    /// FreeBSD `CLD_EXITED`.
    private static final int FREEBSD_CHILD_EXITED = 1;

    /// The byte size of FreeBSD RISC-V `siginfo_t`.
    private static final long FREEBSD_SIGNAL_INFO_SIZE = 80;

    /// The byte offset of `si_signo` inside FreeBSD RISC-V `siginfo_t`.
    private static final long FREEBSD_SIGNAL_INFO_NUMBER_OFFSET = 0;

    /// The byte offset of `si_errno` inside FreeBSD RISC-V `siginfo_t`.
    private static final long FREEBSD_SIGNAL_INFO_ERRNO_OFFSET = Integer.BYTES;

    /// The byte offset of `si_code` inside FreeBSD RISC-V `siginfo_t`.
    private static final long FREEBSD_SIGNAL_INFO_CODE_OFFSET = 2L * Integer.BYTES;

    /// The byte offset of `si_pid` inside FreeBSD RISC-V `siginfo_t`.
    private static final long FREEBSD_SIGNAL_INFO_PROCESS_ID_OFFSET = 3L * Integer.BYTES;

    /// The byte offset of `si_uid` inside FreeBSD RISC-V `siginfo_t`.
    private static final long FREEBSD_SIGNAL_INFO_USER_ID_OFFSET = 4L * Integer.BYTES;

    /// The byte offset of `si_status` inside FreeBSD RISC-V `siginfo_t`.
    private static final long FREEBSD_SIGNAL_INFO_STATUS_OFFSET = 5L * Integer.BYTES;

    /// The byte size of FreeBSD RISC-V `struct __wrusage`.
    private static final long FREEBSD_WRUSAGE_SIZE = 2L * RUSAGE_SIZE;

    /// The FreeBSD RISC-V syscall number for `accept4`.
    private static final int FREEBSD_SYS_ACCEPT4 = 541;

    /// The FreeBSD RISC-V syscall number for `pipe2`.
    private static final int FREEBSD_SYS_PIPE2 = 542;

    /// The FreeBSD RISC-V syscall number for `ppoll`.
    private static final int FREEBSD_SYS_PPOLL = 545;

    /// The FreeBSD RISC-V syscall number for `futimens`.
    private static final int FREEBSD_SYS_FUTIMENS = 546;

    /// The FreeBSD RISC-V syscall number for `utimensat`.
    private static final int FREEBSD_SYS_UTIMENSAT = 547;

    /// The FreeBSD RISC-V syscall number for `fdatasync`.
    private static final int FREEBSD_SYS_FDATASYNC = 550;

    /// The FreeBSD RISC-V syscall number for `fstat`.
    private static final int FREEBSD_SYS_FSTAT = 551;

    /// The FreeBSD RISC-V syscall number for `fstatat`.
    private static final int FREEBSD_SYS_FSTATAT = 552;

    /// The FreeBSD RISC-V syscall number for `getdirentries`.
    private static final int FREEBSD_SYS_GETDIRENTRIES = 554;

    /// The FreeBSD RISC-V syscall number for `statfs`.
    private static final int FREEBSD_SYS_STATFS = 555;

    /// The FreeBSD RISC-V syscall number for `fstatfs`.
    private static final int FREEBSD_SYS_FSTATFS = 556;

    /// The FreeBSD RISC-V syscall number for the current 64-byte `kevent` ABI.
    private static final int FREEBSD_SYS_KEVENT = 560;

    /// The FreeBSD RISC-V syscall number for `cpuset_getdomain`.
    private static final int FREEBSD_SYS_CPUSET_GETDOMAIN = 561;

    /// The FreeBSD RISC-V syscall number for `cpuset_setdomain`.
    private static final int FREEBSD_SYS_CPUSET_SETDOMAIN = 562;

    /// The FreeBSD RISC-V syscall number for `getrandom`.
    private static final int FREEBSD_SYS_GETRANDOM = 563;

    /// The FreeBSD RISC-V syscall number for `copy_file_range`.
    private static final int FREEBSD_SYS_COPY_FILE_RANGE = 569;

    /// The FreeBSD RISC-V syscall number for `close_range`.
    private static final int FREEBSD_SYS_CLOSE_RANGE = 575;

    /// The FreeBSD RISC-V syscall number for `fspacectl`.
    private static final int FREEBSD_SYS_FSPACECTL = 580;

    /// The FreeBSD RISC-V syscall number for `sched_getcpu`.
    private static final int FREEBSD_SYS_SCHED_GETCPU = 581;

    /// The FreeBSD RISC-V syscall number for `kqueuex`.
    private static final int FREEBSD_SYS_KQUEUEX = 583;

    /// The FreeBSD RISC-V syscall number for `membarrier`.
    private static final int FREEBSD_SYS_MEMBARRIER = 584;

    /// The FreeBSD RISC-V syscall number for `timerfd_create`.
    private static final int FREEBSD_SYS_TIMERFD_CREATE = 585;

    /// The FreeBSD RISC-V syscall number for `timerfd_gettime`.
    private static final int FREEBSD_SYS_TIMERFD_GETTIME = 586;

    /// The FreeBSD RISC-V syscall number for `timerfd_settime`.
    private static final int FREEBSD_SYS_TIMERFD_SETTIME = 587;

    /// The current FreeBSD RISC-V syscall number for `getgroups`.
    private static final int FREEBSD_SYS_GETGROUPS_CURRENT = 595;

    /// The current FreeBSD RISC-V syscall number for `setgroups`.
    private static final int FREEBSD_SYS_SETGROUPS_CURRENT = 596;

    /// The FreeBSD RISC-V syscall number for `renameat2`.
    private static final int FREEBSD_SYS_RENAMEAT2 = 602;

    /// FreeBSD `SPACECTL_DEALLOC`.
    private static final long FREEBSD_SPACECTL_DEALLOC = 1;

    /// FreeBSD `MEMBARRIER_CMD_QUERY`.
    private static final long FREEBSD_MEMBARRIER_CMD_QUERY = 0;

    /// FreeBSD `MCL_CURRENT`.
    private static final long FREEBSD_MCL_CURRENT = 1;

    /// FreeBSD `MCL_FUTURE`.
    private static final long FREEBSD_MCL_FUTURE = 2;

    /// FreeBSD `SCHED_FIFO`.
    private static final int FREEBSD_SCHED_FIFO = 1;

    /// FreeBSD `SCHED_OTHER`.
    private static final int FREEBSD_SCHED_OTHER = 2;

    /// FreeBSD `SCHED_RR`.
    private static final int FREEBSD_SCHED_RR = 3;

    /// FreeBSD `CPU_LEVEL_ROOT`.
    private static final int FREEBSD_CPU_LEVEL_ROOT = 1;

    /// FreeBSD `CPU_LEVEL_CPUSET`.
    private static final int FREEBSD_CPU_LEVEL_CPUSET = 2;

    /// FreeBSD `CPU_LEVEL_WHICH`.
    private static final int FREEBSD_CPU_LEVEL_WHICH = 3;

    /// FreeBSD `CPU_WHICH_TID`.
    private static final int FREEBSD_CPU_WHICH_TID = 1;

    /// FreeBSD `CPU_WHICH_PID`.
    private static final int FREEBSD_CPU_WHICH_PID = 2;

    /// FreeBSD `CPU_WHICH_CPUSET`.
    private static final int FREEBSD_CPU_WHICH_CPUSET = 3;

    /// FreeBSD `CPU_WHICH_TIDPID`.
    private static final int FREEBSD_CPU_WHICH_TIDPID = 9;

    /// FreeBSD `DOMAINSET_POLICY_ROUNDROBIN`.
    private static final int FREEBSD_DOMAINSET_POLICY_ROUNDROBIN = 1;

    /// FreeBSD `DOMAINSET_POLICY_FIRSTTOUCH`.
    private static final int FREEBSD_DOMAINSET_POLICY_FIRSTTOUCH = 2;

    /// FreeBSD `DOMAINSET_POLICY_PREFER`.
    private static final int FREEBSD_DOMAINSET_POLICY_PREFER = 3;

    /// FreeBSD `DOMAINSET_POLICY_INTERLEAVE`.
    private static final int FREEBSD_DOMAINSET_POLICY_INTERLEAVE = 4;

    /// The native RISC-V kernel byte size of FreeBSD `domainset_t` for one memory domain.
    private static final long FREEBSD_DOMAINSET_KERNEL_SIZE = Long.BYTES;

    /// The largest user ABI memory-domain mask accepted by FreeBSD.
    private static final long FREEBSD_DOMAINSET_MAXIMUM_SIZE = 32;

    /// The reserved internal result used to report FreeBSD `EDEADLK` without colliding with Linux `EAGAIN`.
    private static final long FREEBSD_EDEADLK_RESULT = Long.MIN_VALUE + 11;

    /// The reserved base used to encode successful negative 32-bit FreeBSD syscall results.
    private static final long FREEBSD_NEGATIVE_INT_SUCCESS_BASE = Long.MIN_VALUE + 4096;

    /// The highest internal encoding of a successful negative 32-bit FreeBSD syscall result.
    private static final long FREEBSD_NEGATIVE_INT_SUCCESS_MAXIMUM =
            FREEBSD_NEGATIVE_INT_SUCCESS_BASE - (long) Integer.MIN_VALUE;

    /// The maximum number of non-NUL bytes stored in a FreeBSD thread name.
    private static final int FREEBSD_MAXCOMLEN = 19;

    /// FreeBSD `MAXLOGNAME`, including the terminating NUL byte.
    private static final int FREEBSD_MAXLOGNAME = 33;

    /// The minimum FreeBSD POSIX realtime scheduler priority.
    private static final int FREEBSD_SCHED_REALTIME_PRIORITY_MINIMUM = 0;

    /// The maximum FreeBSD POSIX realtime scheduler priority.
    private static final int FREEBSD_SCHED_REALTIME_PRIORITY_MAXIMUM = 31;

    /// The minimum FreeBSD time-sharing scheduler priority.
    private static final int FREEBSD_SCHED_OTHER_PRIORITY_MINIMUM = 0;

    /// The maximum FreeBSD time-sharing scheduler priority.
    private static final int FREEBSD_SCHED_OTHER_PRIORITY_MAXIMUM = 167;

    /// The byte size of FreeBSD RISC-V `struct spacectl_range`.
    private static final long FREEBSD_SPACECTL_RANGE_SIZE = 2L * Long.BYTES;

    /// The byte offset of `r_offset` inside FreeBSD RISC-V `struct spacectl_range`.
    private static final long FREEBSD_SPACECTL_RANGE_OFFSET_OFFSET = 0;

    /// The byte offset of `r_len` inside FreeBSD RISC-V `struct spacectl_range`.
    private static final long FREEBSD_SPACECTL_RANGE_LENGTH_OFFSET = Long.BYTES;

    /// FreeBSD `CLOCK_REALTIME`.
    private static final long FREEBSD_CLOCK_REALTIME = 0;

    /// FreeBSD `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME`.
    private static final long FREEBSD_CLOCK_MONOTONIC = 4;

    /// FreeBSD `CLOCK_UPTIME`.
    private static final long FREEBSD_CLOCK_UPTIME = 5;

    /// FreeBSD `CLOCK_VIRTUAL`.
    private static final long FREEBSD_CLOCK_VIRTUAL = 1;

    /// FreeBSD `CLOCK_PROF`.
    private static final long FREEBSD_CLOCK_PROF = 2;

    /// FreeBSD `CLOCK_UPTIME_PRECISE`.
    private static final long FREEBSD_CLOCK_UPTIME_PRECISE = 7;

    /// FreeBSD `CLOCK_UPTIME_FAST`.
    private static final long FREEBSD_CLOCK_UPTIME_FAST = 8;

    /// FreeBSD `CLOCK_REALTIME_PRECISE`.
    private static final long FREEBSD_CLOCK_REALTIME_PRECISE = 9;

    /// FreeBSD `CLOCK_REALTIME_FAST` and `CLOCK_REALTIME_COARSE`.
    private static final long FREEBSD_CLOCK_REALTIME_FAST = 10;

    /// FreeBSD `CLOCK_MONOTONIC_PRECISE`.
    private static final long FREEBSD_CLOCK_MONOTONIC_PRECISE = 11;

    /// FreeBSD `CLOCK_MONOTONIC_FAST` and `CLOCK_MONOTONIC_COARSE`.
    private static final long FREEBSD_CLOCK_MONOTONIC_FAST = 12;

    /// FreeBSD `CLOCK_SECOND`.
    private static final long FREEBSD_CLOCK_SECOND = 13;

    /// FreeBSD `CLOCK_THREAD_CPUTIME_ID`.
    private static final long FREEBSD_CLOCK_THREAD_CPUTIME_ID = 14;

    /// FreeBSD `CLOCK_PROCESS_CPUTIME_ID`.
    private static final long FREEBSD_CLOCK_PROCESS_CPUTIME_ID = 15;

    /// FreeBSD `CLOCK_TAI`.
    private static final long FREEBSD_CLOCK_TAI = 16;

    /// FreeBSD `_PC_LINK_MAX`.
    private static final int FREEBSD_PC_LINK_MAX = 1;

    /// FreeBSD `_PC_MAX_CANON`.
    private static final int FREEBSD_PC_MAX_CANON = 2;

    /// FreeBSD `_PC_MAX_INPUT`.
    private static final int FREEBSD_PC_MAX_INPUT = 3;

    /// FreeBSD `_PC_NAME_MAX`.
    private static final int FREEBSD_PC_NAME_MAX = 4;

    /// FreeBSD `_PC_PATH_MAX`.
    private static final int FREEBSD_PC_PATH_MAX = 5;

    /// FreeBSD `_PC_PIPE_BUF`.
    private static final int FREEBSD_PC_PIPE_BUF = 6;

    /// FreeBSD `_PC_CHOWN_RESTRICTED`.
    private static final int FREEBSD_PC_CHOWN_RESTRICTED = 7;

    /// FreeBSD `_PC_NO_TRUNC`.
    private static final int FREEBSD_PC_NO_TRUNC = 8;

    /// FreeBSD `_PC_VDISABLE`.
    private static final int FREEBSD_PC_VDISABLE = 9;

    /// FreeBSD `_PC_ALLOC_SIZE_MIN`.
    private static final int FREEBSD_PC_ALLOC_SIZE_MIN = 10;

    /// FreeBSD `_PC_FILESIZEBITS`.
    private static final int FREEBSD_PC_FILESIZEBITS = 12;

    /// FreeBSD `_PC_REC_INCR_XFER_SIZE`.
    private static final int FREEBSD_PC_REC_INCR_XFER_SIZE = 14;

    /// FreeBSD `_PC_REC_MAX_XFER_SIZE`.
    private static final int FREEBSD_PC_REC_MAX_XFER_SIZE = 15;

    /// FreeBSD `_PC_REC_MIN_XFER_SIZE`.
    private static final int FREEBSD_PC_REC_MIN_XFER_SIZE = 16;

    /// FreeBSD `_PC_REC_XFER_ALIGN`.
    private static final int FREEBSD_PC_REC_XFER_ALIGN = 17;

    /// FreeBSD `_PC_SYMLINK_MAX`.
    private static final int FREEBSD_PC_SYMLINK_MAX = 18;

    /// FreeBSD `_PC_MIN_HOLE_SIZE`.
    private static final int FREEBSD_PC_MIN_HOLE_SIZE = 21;

    /// FreeBSD `_PC_ASYNC_IO`.
    private static final int FREEBSD_PC_ASYNC_IO = 53;

    /// FreeBSD `_PC_PRIO_IO`.
    private static final int FREEBSD_PC_PRIO_IO = 54;

    /// FreeBSD `_PC_SYNC_IO`.
    private static final int FREEBSD_PC_SYNC_IO = 55;

    /// The first FreeBSD filesystem-capability path configuration name.
    private static final int FREEBSD_PC_CAPABILITY_FIRST = 59;

    /// The last FreeBSD filesystem-capability path configuration name.
    private static final int FREEBSD_PC_CAPABILITY_LAST = 70;

    /// FreeBSD `MAX_CANON` and `MAX_INPUT`.
    private static final int FREEBSD_TERMINAL_INPUT_MAX = 255;

    /// FreeBSD `NAME_MAX`.
    private static final int FREEBSD_NAME_MAX = 255;

    /// FreeBSD `PATH_MAX` and `MAXPATHLEN`.
    private static final int FREEBSD_PATH_MAX = 1024;

    /// FreeBSD `PIPE_BUF`.
    private static final int FREEBSD_PIPE_BUF = 512;

    /// FreeBSD `_POSIX_VDISABLE`.
    private static final int FREEBSD_POSIX_VDISABLE = 0xff;

    /// The default FreeBSD maximum number of supplementary groups.
    private static final int FREEBSD_MAX_SUPPLEMENTARY_GROUP_COUNT = 1023;

    /// The byte size of FreeBSD RISC-V `struct stat`.
    private static final long FREEBSD_STAT_SIZE = 224;

    /// The byte offset of `st_ino` inside FreeBSD RISC-V `struct stat`.
    private static final long FREEBSD_STAT_INODE_OFFSET = 8;

    /// The byte offset of `st_nlink` inside FreeBSD RISC-V `struct stat`.
    private static final long FREEBSD_STAT_LINK_COUNT_OFFSET = 16;

    /// The byte offset of `st_mode` inside FreeBSD RISC-V `struct stat`.
    private static final long FREEBSD_STAT_MODE_OFFSET = 24;

    /// The byte offset of `st_uid` inside FreeBSD RISC-V `struct stat`.
    private static final long FREEBSD_STAT_USER_ID_OFFSET = 28;

    /// The byte offset of `st_gid` inside FreeBSD RISC-V `struct stat`.
    private static final long FREEBSD_STAT_GROUP_ID_OFFSET = 32;

    /// The byte offset of `st_size` inside FreeBSD RISC-V `struct stat`.
    private static final long FREEBSD_STAT_FILE_SIZE_OFFSET = 112;

    /// The byte offset of `st_atim` inside FreeBSD RISC-V `struct stat`.
    private static final long FREEBSD_STAT_ACCESS_TIME_OFFSET = 48;

    /// The byte offset of `st_mtim` inside FreeBSD RISC-V `struct stat`.
    private static final long FREEBSD_STAT_MODIFICATION_TIME_OFFSET = 64;

    /// The byte offset of `st_ctim` inside FreeBSD RISC-V `struct stat`.
    private static final long FREEBSD_STAT_CHANGE_TIME_OFFSET = 80;

    /// The byte offset of `st_birthtim` inside FreeBSD RISC-V `struct stat`.
    private static final long FREEBSD_STAT_BIRTH_TIME_OFFSET = 96;

    /// The byte offset of `st_blocks` inside FreeBSD RISC-V `struct stat`.
    private static final long FREEBSD_STAT_BLOCK_COUNT_OFFSET = 120;

    /// The byte offset of `st_blksize` inside FreeBSD RISC-V `struct stat`.
    private static final long FREEBSD_STAT_BLOCK_SIZE_OFFSET = 128;

    /// The byte size of FreeBSD RISC-V `struct statfs`.
    private static final long FREEBSD_STATFS_SIZE = 2344;

    /// The current FreeBSD `struct statfs` layout version.
    private static final int FREEBSD_STATFS_VERSION = 0x2014_0518;

    /// The byte offset of `f_bsize` inside FreeBSD RISC-V `struct statfs`.
    private static final long FREEBSD_STATFS_BLOCK_SIZE_OFFSET = 16;

    /// The byte offset of `f_iosize` inside FreeBSD RISC-V `struct statfs`.
    private static final long FREEBSD_STATFS_IO_SIZE_OFFSET = 24;

    /// The byte offset of `f_blocks` inside FreeBSD RISC-V `struct statfs`.
    private static final long FREEBSD_STATFS_BLOCK_COUNT_OFFSET = 32;

    /// The byte offset of `f_bfree` inside FreeBSD RISC-V `struct statfs`.
    private static final long FREEBSD_STATFS_FREE_BLOCK_COUNT_OFFSET = 40;

    /// The byte offset of `f_bavail` inside FreeBSD RISC-V `struct statfs`.
    private static final long FREEBSD_STATFS_AVAILABLE_BLOCK_COUNT_OFFSET = 48;

    /// The byte offset of `f_files` inside FreeBSD RISC-V `struct statfs`.
    private static final long FREEBSD_STATFS_FILE_COUNT_OFFSET = 56;

    /// The byte offset of `f_ffree` inside FreeBSD RISC-V `struct statfs`.
    private static final long FREEBSD_STATFS_FREE_FILE_COUNT_OFFSET = 64;

    /// The byte offset of `f_namemax` inside FreeBSD RISC-V `struct statfs`.
    private static final long FREEBSD_STATFS_NAME_MAX_OFFSET = 184;

    /// The byte offset of `f_owner` inside FreeBSD RISC-V `struct statfs`.
    private static final long FREEBSD_STATFS_OWNER_OFFSET = 188;

    /// The byte offset of `f_fsid` inside FreeBSD RISC-V `struct statfs`.
    private static final long FREEBSD_STATFS_FILE_SYSTEM_ID_OFFSET = 192;

    /// The byte offset of `f_fstypename` inside FreeBSD RISC-V `struct statfs`.
    private static final long FREEBSD_STATFS_TYPE_NAME_OFFSET = 280;

    /// The byte offset of `f_mntfromname` inside FreeBSD RISC-V `struct statfs`.
    private static final long FREEBSD_STATFS_MOUNT_SOURCE_OFFSET = 296;

    /// The byte offset of `f_mntonname` inside FreeBSD RISC-V `struct statfs`.
    private static final long FREEBSD_STATFS_MOUNT_POINT_OFFSET = 1320;

    /// The byte capacity of `f_fstypename` inside FreeBSD `struct statfs`.
    private static final int FREEBSD_STATFS_TYPE_NAME_SIZE = 16;

    /// The byte capacity of each FreeBSD `struct statfs` mount-name field.
    private static final int FREEBSD_STATFS_MOUNT_NAME_SIZE = 1024;

    /// The byte offset of `d_fileno` inside FreeBSD RISC-V `struct dirent`.
    private static final long FREEBSD_DIRENT_INODE_OFFSET = 0;

    /// The byte offset of `d_off` inside FreeBSD RISC-V `struct dirent`.
    private static final long FREEBSD_DIRENT_NEXT_OFFSET = 8;

    /// The byte offset of `d_reclen` inside FreeBSD RISC-V `struct dirent`.
    private static final long FREEBSD_DIRENT_RECORD_LENGTH_OFFSET = 16;

    /// The byte offset of `d_type` inside FreeBSD RISC-V `struct dirent`.
    private static final long FREEBSD_DIRENT_TYPE_OFFSET = 18;

    /// The byte offset of `d_namlen` inside FreeBSD RISC-V `struct dirent`.
    private static final long FREEBSD_DIRENT_NAME_LENGTH_OFFSET = 20;

    /// The byte offset of `d_name` inside FreeBSD RISC-V `struct dirent`.
    private static final long FREEBSD_DIRENT_NAME_OFFSET = 24;

    /// The alignment of variable-length FreeBSD `struct dirent` records.
    private static final long FREEBSD_DIRENT_ALIGNMENT = Long.BYTES;

    /// FreeBSD `CTL_QUERY`.
    private static final int FREEBSD_CTL_QUERY = 0;

    /// FreeBSD `CTL_QUERY_MIB`.
    private static final int FREEBSD_CTL_QUERY_MIB = 3;

    /// FreeBSD `CTL_HW`.
    private static final int FREEBSD_CTL_HW = 6;

    /// FreeBSD `HW_PAGESIZE`.
    private static final int FREEBSD_HW_PAGESIZE = 7;

    /// FreeBSD `CTL_KERN`.
    private static final int FREEBSD_CTL_KERN = 1;

    /// FreeBSD `KERN_PROC`.
    private static final int FREEBSD_KERN_PROC = 14;

    /// FreeBSD `KERN_PROC_PATHNAME`.
    private static final int FREEBSD_KERN_PROC_PATHNAME = 12;

    /// Synthetic FreeBSD sysctl MIB component for `kern.smp`.
    private static final int FREEBSD_KERN_SMP = 1000;

    /// Synthetic FreeBSD sysctl MIB component for `kern.smp.maxcpus`.
    private static final int FREEBSD_KERN_SMP_MAXCPUS = 1;

    /// Synthetic FreeBSD `kern.smp.maxcpus` MIB exposed to Go runtime startup.
    private static final int @Unmodifiable [] FREEBSD_SYSCTL_KERN_SMP_MAXCPUS = {
            FREEBSD_CTL_KERN,
            FREEBSD_KERN_SMP,
            FREEBSD_KERN_SMP_MAXCPUS
    };

    /// FreeBSD `kern.proc.pathname` MIB used to query the current executable path.
    private static final int @Unmodifiable [] FREEBSD_SYSCTL_KERN_PROC_PATHNAME = {
            FREEBSD_CTL_KERN,
            FREEBSD_KERN_PROC,
            FREEBSD_KERN_PROC_PATHNAME,
            -1
    };

    /// FreeBSD sysctl name used by Go to discover the cpuset mask size.
    private static final String FREEBSD_SYSCTL_KERN_SMP_MAXCPUS_NAME = "kern.smp.maxcpus";

    /// FreeBSD address family number for Unix-domain sockets.
    private static final long FREEBSD_AF_UNIX = 1;

    /// FreeBSD address family number for IPv4 sockets.
    private static final long FREEBSD_AF_INET = 2;

    /// FreeBSD address family number for IPv6 sockets.
    private static final long FREEBSD_AF_INET6 = 28;

    /// FreeBSD socket type mask excluding creation flags.
    private static final long FREEBSD_SOCK_TYPE_MASK = 0xf;

    /// FreeBSD `SOCK_CLOEXEC`.
    private static final long FREEBSD_SOCK_CLOEXEC = 0x1000_0000L;

    /// FreeBSD `SOCK_NONBLOCK`.
    private static final long FREEBSD_SOCK_NONBLOCK = 0x2000_0000L;

    /// FreeBSD socket creation flags implemented by the simulator.
    private static final long FREEBSD_SUPPORTED_SOCKET_TYPE_FLAGS =
            FREEBSD_SOCK_CLOEXEC | FREEBSD_SOCK_NONBLOCK;

    /// FreeBSD `MSG_DONTWAIT`.
    private static final long FREEBSD_MSG_DONTWAIT = 0x80L;

    /// FreeBSD `MSG_NOSIGNAL`.
    private static final long FREEBSD_MSG_NOSIGNAL = 0x2_0000L;

    /// FreeBSD message flags implemented by the simulator.
    private static final long FREEBSD_SUPPORTED_SOCKET_MESSAGE_FLAGS =
            FREEBSD_MSG_DONTWAIT | FREEBSD_MSG_NOSIGNAL;

    /// FreeBSD generic socket option level.
    private static final long FREEBSD_SOL_SOCKET = 0xffffL;

    /// FreeBSD `SO_REUSEADDR`.
    private static final long FREEBSD_SO_REUSEADDR = 0x4L;

    /// FreeBSD `SO_KEEPALIVE`.
    private static final long FREEBSD_SO_KEEPALIVE = 0x8L;

    /// FreeBSD `SO_BROADCAST`.
    private static final long FREEBSD_SO_BROADCAST = 0x20L;

    /// FreeBSD `SO_SNDBUF`.
    private static final long FREEBSD_SO_SNDBUF = 0x1001L;

    /// FreeBSD `SO_RCVBUF`.
    private static final long FREEBSD_SO_RCVBUF = 0x1002L;

    /// FreeBSD `SO_ERROR`.
    private static final long FREEBSD_SO_ERROR = 0x1007L;

    /// FreeBSD `SO_REUSEPORT`.
    private static final long FREEBSD_SO_REUSEPORT = 0x200L;

    /// FreeBSD `IPV6_V6ONLY`.
    private static final long FREEBSD_IPV6_V6ONLY = 0x1bL;

    /// Byte size of FreeBSD RISC-V `struct sockaddr_in`.
    private static final long FREEBSD_SOCKADDR_IN_SIZE = 16;

    /// Byte size of FreeBSD RISC-V `struct sockaddr_in6`.
    private static final long FREEBSD_SOCKADDR_IN6_SIZE = 28;

    /// Byte size of FreeBSD RISC-V `struct sockaddr_un`.
    private static final long FREEBSD_SOCKADDR_UN_SIZE = 106;

    /// Byte offset of the length field inside a FreeBSD socket address.
    private static final long FREEBSD_SOCKADDR_LENGTH_OFFSET = 0;

    /// Byte offset of the family field inside a FreeBSD socket address.
    private static final long FREEBSD_SOCKADDR_FAMILY_OFFSET = 1;

    /// Byte offset of the network-endian port field inside a FreeBSD Internet socket address.
    private static final long FREEBSD_SOCKADDR_PORT_OFFSET = 2;

    /// Byte offset of the IPv4 address inside FreeBSD `struct sockaddr_in`.
    private static final long FREEBSD_SOCKADDR_IN_ADDRESS_OFFSET = 4;

    /// Byte offset of the IPv6 address inside FreeBSD `struct sockaddr_in6`.
    private static final long FREEBSD_SOCKADDR_IN6_ADDRESS_OFFSET = 8;

    /// Byte offset of the IPv6 scope identifier inside FreeBSD `struct sockaddr_in6`.
    private static final long FREEBSD_SOCKADDR_IN6_SCOPE_ID_OFFSET = 24;

    /// Byte offset of `sun_path` inside FreeBSD `struct sockaddr_un`.
    private static final long FREEBSD_SOCKADDR_UN_PATH_OFFSET = 2;

    /// Byte capacity of `sun_path` inside FreeBSD `struct sockaddr_un`.
    private static final int FREEBSD_SOCKADDR_UN_PATH_SIZE = 104;

    /// Byte offset of `msg_iovlen` inside FreeBSD RISC-V `struct msghdr`.
    private static final long FREEBSD_MSGHDR_IOV_LENGTH_OFFSET = 3L * Long.BYTES;

    /// Byte offset of `msg_flags` inside FreeBSD RISC-V `struct msghdr`.
    private static final long FREEBSD_MSGHDR_FLAGS_OFFSET = 5L * Long.BYTES + Integer.BYTES;

    /// Byte size of the current FreeBSD RISC-V `struct kevent`.
    private static final long FREEBSD_KEVENT_SIZE = 64;

    /// Byte size of the legacy FreeBSD 11 `struct kevent`.
    private static final long FREEBSD11_KEVENT_SIZE = 32;

    /// Byte offset of `ident` inside FreeBSD `struct kevent`.
    private static final long FREEBSD_KEVENT_IDENT_OFFSET = 0;

    /// Byte offset of `filter` inside FreeBSD `struct kevent`.
    private static final long FREEBSD_KEVENT_FILTER_OFFSET = Long.BYTES;

    /// Byte offset of `flags` inside FreeBSD `struct kevent`.
    private static final long FREEBSD_KEVENT_FLAGS_OFFSET = Long.BYTES + Short.BYTES;

    /// Byte offset of `fflags` inside FreeBSD `struct kevent`.
    private static final long FREEBSD_KEVENT_FILTER_FLAGS_OFFSET = Long.BYTES + 2L * Short.BYTES;

    /// Byte offset of `data` inside FreeBSD `struct kevent`.
    private static final long FREEBSD_KEVENT_DATA_OFFSET = 2L * Long.BYTES;

    /// Byte offset of `udata` inside FreeBSD `struct kevent`.
    private static final long FREEBSD_KEVENT_USER_DATA_OFFSET = 3L * Long.BYTES;

    /// FreeBSD read descriptor filter.
    private static final short FREEBSD_EVFILT_READ = -1;

    /// FreeBSD write descriptor filter.
    private static final short FREEBSD_EVFILT_WRITE = -2;

    /// FreeBSD user-triggered event filter.
    private static final short FREEBSD_EVFILT_USER = -11;

    /// FreeBSD `EV_ADD`.
    private static final int FREEBSD_EV_ADD = 0x0001;

    /// FreeBSD `EV_DELETE`.
    private static final int FREEBSD_EV_DELETE = 0x0002;

    /// FreeBSD `EV_ENABLE`.
    private static final int FREEBSD_EV_ENABLE = 0x0004;

    /// FreeBSD `EV_DISABLE`.
    private static final int FREEBSD_EV_DISABLE = 0x0008;

    /// FreeBSD `EV_CLEAR`.
    private static final int FREEBSD_EV_CLEAR = 0x0020;

    /// FreeBSD `EV_EOF` result flag.
    private static final int FREEBSD_EV_EOF = 0x8000;

    /// FreeBSD `NOTE_TRIGGER` user-event operation.
    private static final long FREEBSD_NOTE_TRIGGER = 0x0100_0000L;

    /// FreeBSD change flags implemented by the in-memory kqueue.
    private static final int FREEBSD_SUPPORTED_KEVENT_CHANGE_FLAGS =
            FREEBSD_EV_ADD | FREEBSD_EV_DELETE | FREEBSD_EV_ENABLE | FREEBSD_EV_DISABLE | FREEBSD_EV_CLEAR;

    /// Maximum number of changes or returned events accepted by one `kevent` call.
    private static final long FREEBSD_KEVENT_MAX_COUNT = 65_536;

    /// FreeBSD `F_DUP2FD`.
    private static final long FREEBSD_F_DUP2FD = 10;

    /// FreeBSD `F_GETLK`.
    private static final long FREEBSD_F_GETLK = 11;

    /// FreeBSD `F_SETLK`.
    private static final long FREEBSD_F_SETLK = 12;

    /// FreeBSD `F_SETLKW`.
    private static final long FREEBSD_F_SETLKW = 13;

    /// FreeBSD `F_DUPFD_CLOEXEC`.
    private static final long FREEBSD_F_DUPFD_CLOEXEC = 17;

    /// FreeBSD `F_DUP2FD_CLOEXEC`.
    private static final long FREEBSD_F_DUP2FD_CLOEXEC = 18;

    /// FreeBSD `FD_CLOFORK`.
    private static final long FREEBSD_FD_CLOFORK = 4;

    /// FreeBSD `F_RDLCK`.
    private static final int FREEBSD_F_RDLCK = 1;

    /// FreeBSD `F_UNLCK`.
    private static final int FREEBSD_F_UNLCK = 2;

    /// FreeBSD `F_WRLCK`.
    private static final int FREEBSD_F_WRLCK = 3;

    /// The byte size of FreeBSD RISC-V `struct flock`.
    private static final long FREEBSD_FLOCK_SIZE = 32;

    /// The byte offset of `l_type` inside FreeBSD RISC-V `struct flock`.
    private static final long FREEBSD_FLOCK_TYPE_OFFSET = 20;

    /// FreeBSD `LOCK_SH`.
    private static final long FREEBSD_LOCK_SH = 0x01;

    /// FreeBSD `LOCK_EX`.
    private static final long FREEBSD_LOCK_EX = 0x02;

    /// FreeBSD `LOCK_UN`.
    private static final long FREEBSD_LOCK_UN = 0x08;

    /// FreeBSD `O_ACCMODE`.
    private static final long FREEBSD_O_ACCMODE = 0x0003;

    /// FreeBSD `O_NONBLOCK`.
    private static final long FREEBSD_O_NONBLOCK = 0x0004;

    /// FreeBSD `O_APPEND`.
    private static final long FREEBSD_O_APPEND = 0x0008;

    /// FreeBSD `O_CREAT`.
    private static final long FREEBSD_O_CREAT = 0x0200;

    /// FreeBSD `O_TRUNC`.
    private static final long FREEBSD_O_TRUNC = 0x0400;

    /// FreeBSD `O_EXCL`.
    private static final long FREEBSD_O_EXCL = 0x0800;

    /// FreeBSD `O_DIRECTORY`.
    private static final long FREEBSD_O_DIRECTORY = 0x0002_0000;

    /// FreeBSD `O_CLOEXEC`.
    private static final long FREEBSD_O_CLOEXEC = 0x0010_0000;

    /// FreeBSD `CLOSE_RANGE_CLOEXEC`.
    private static final long FREEBSD_CLOSE_RANGE_CLOEXEC = 1L << 2;

    /// FreeBSD `CLOSE_RANGE_CLOFORK`.
    private static final long FREEBSD_CLOSE_RANGE_CLOFORK = 1L << 3;

    /// Flags accepted by FreeBSD `close_range`.
    private static final long FREEBSD_SUPPORTED_CLOSE_RANGE_FLAGS =
            FREEBSD_CLOSE_RANGE_CLOEXEC | FREEBSD_CLOSE_RANGE_CLOFORK;

    /// FreeBSD `COPY_FILE_RANGE_CLONE`.
    private static final long FREEBSD_COPY_FILE_RANGE_CLONE = 0x0080_0000L;

    /// FreeBSD flags accepted by `pipe2`.
    private static final long FREEBSD_SUPPORTED_PIPE2_FLAGS = FREEBSD_O_NONBLOCK | FREEBSD_O_CLOEXEC;

    /// FreeBSD flags accepted by `timerfd_create`.
    private static final long FREEBSD_SUPPORTED_TIMERFD_CREATE_FLAGS = FREEBSD_O_NONBLOCK | FREEBSD_O_CLOEXEC;

    /// FreeBSD `KQUEUE_CLOEXEC`.
    private static final long FREEBSD_KQUEUE_CLOEXEC = 0x0000_0001L;

    /// FreeBSD `AT_EACCESS`.
    private static final long FREEBSD_AT_EACCESS = 0x0100;

    /// FreeBSD `AT_SYMLINK_NOFOLLOW`.
    private static final long FREEBSD_AT_SYMLINK_NOFOLLOW = 0x0200;

    /// FreeBSD `AT_SYMLINK_FOLLOW`.
    private static final long FREEBSD_AT_SYMLINK_FOLLOW = 0x0400;

    /// FreeBSD `AT_REMOVEDIR`.
    private static final long FREEBSD_AT_REMOVEDIR = 0x0800;

    /// FreeBSD `AT_EMPTY_PATH`.
    private static final long FREEBSD_AT_EMPTY_PATH = 0x4000;

    /// The FreeBSD `fstatat` flags implemented by the simulator.
    private static final long FREEBSD_SUPPORTED_FSTATAT_FLAGS =
            FREEBSD_AT_SYMLINK_NOFOLLOW | FREEBSD_AT_EMPTY_PATH;


    /// FreeBSD `RLIMIT_NOFILE`.
    private static final int FREEBSD_RLIMIT_NOFILE = 8;


    /// FreeBSD `MAP_ANON`.
    private static final long FREEBSD_MAP_ANON = 0x1000;

    /// FreeBSD `MAP_EXCL`, used with `MAP_FIXED`.
    private static final long FREEBSD_MAP_EXCL = 0x4000;

    /// FreeBSD `MS_ASYNC`.
    private static final long FREEBSD_MS_ASYNC = 0x0001;

    /// FreeBSD `MS_INVALIDATE`.
    private static final long FREEBSD_MS_INVALIDATE = 0x0002;

    /// FreeBSD `MADV_FREE`.
    private static final long FREEBSD_MADV_FREE = 5;

    /// FreeBSD `MADV_NOSYNC`, the first accepted advisory no-op distinct from Linux values.
    private static final long FREEBSD_MADV_NOSYNC = 6;

    /// FreeBSD `MADV_PROTECT`, the last accepted advisory no-op distinct from Linux values.
    private static final long FREEBSD_MADV_PROTECT = 10;

    /// FreeBSD `UTIME_NOW`.
    private static final long FREEBSD_UTIME_NOW = -1;

    /// FreeBSD `UTIME_OMIT`.
    private static final long FREEBSD_UTIME_OMIT = -2;


    /// FreeBSD `SIG_BLOCK` signal-mask operation.
    private static final long FREEBSD_SIG_BLOCK = 1;

    /// FreeBSD `SIG_UNBLOCK` signal-mask operation.
    private static final long FREEBSD_SIG_UNBLOCK = 2;

    /// FreeBSD `SIG_SETMASK` signal-mask operation.
    private static final long FREEBSD_SIG_SETMASK = 3;

    /// The byte size of FreeBSD RISC-V `sigset_t`.
    private static final long FREEBSD_SIGNAL_SET_SIZE = 4L * Integer.BYTES;

    /// The byte size of FreeBSD RISC-V `struct sigaction` used by Go.
    private static final long FREEBSD_SIGACTION_SIZE = Long.BYTES + Integer.BYTES + 4L * Integer.BYTES;

    /// The byte offset of `ss_sp` inside FreeBSD RISC-V `stack_t`.
    private static final long FREEBSD_SIGNAL_STACK_POINTER_OFFSET = 0;

    /// The byte offset of `ss_size` inside FreeBSD RISC-V `stack_t`.
    private static final long FREEBSD_SIGNAL_STACK_SIZE_OFFSET = Long.BYTES;

    /// The byte offset of `ss_flags` inside FreeBSD RISC-V `stack_t`.
    private static final long FREEBSD_SIGNAL_STACK_FLAGS_OFFSET = 2L * Long.BYTES;

    /// FreeBSD `SS_DISABLE`.
    private static final long FREEBSD_SS_DISABLE = 4;

    /// FreeBSD `_UMTX_OP_WAIT_UINT`.
    private static final long FREEBSD_UMTX_OP_WAIT_UINT = 0x0b;

    /// FreeBSD `_UMTX_OP_WAIT_UINT_PRIVATE`.
    private static final long FREEBSD_UMTX_OP_WAIT_UINT_PRIVATE = 0x0f;

    /// FreeBSD `_UMTX_OP_WAKE`.
    private static final long FREEBSD_UMTX_OP_WAKE = 0x03;

    /// FreeBSD `_UMTX_OP_WAKE_PRIVATE`.
    private static final long FREEBSD_UMTX_OP_WAKE_PRIVATE = 0x10;

    /// The byte size of a FreeBSD RISC-V `struct _umtx_time`.
    private static final long FREEBSD_UMTX_TIME_SIZE = 3L * Long.BYTES;

    /// The byte offset of `_flags` inside FreeBSD RISC-V `struct _umtx_time`.
    private static final long FREEBSD_UMTX_TIME_FLAGS_OFFSET = TIMESPEC_SIZE;

    /// The byte offset of `_clockid` inside FreeBSD RISC-V `struct _umtx_time`.
    private static final long FREEBSD_UMTX_TIME_CLOCK_ID_OFFSET = TIMESPEC_SIZE + Integer.BYTES;

    /// FreeBSD `UMTX_ABSTIME`.
    private static final long FREEBSD_UMTX_ABSTIME = 0x01;

    /// The byte offset of `start_func` inside FreeBSD `struct thr_param`.
    private static final long FREEBSD_THR_PARAM_START_FUNC_OFFSET = 0;

    /// The byte offset of `arg` inside FreeBSD `struct thr_param`.
    private static final long FREEBSD_THR_PARAM_ARG_OFFSET = Long.BYTES;

    /// The byte offset of `stack_base` inside FreeBSD `struct thr_param`.
    private static final long FREEBSD_THR_PARAM_STACK_BASE_OFFSET = 2L * Long.BYTES;

    /// The byte offset of `stack_size` inside FreeBSD `struct thr_param`.
    private static final long FREEBSD_THR_PARAM_STACK_SIZE_OFFSET = 3L * Long.BYTES;

    /// The byte offset of `tls_base` inside FreeBSD `struct thr_param`.
    private static final long FREEBSD_THR_PARAM_TLS_BASE_OFFSET = 4L * Long.BYTES;

    /// The byte offset of `child_tid` inside FreeBSD `struct thr_param`.
    private static final long FREEBSD_THR_PARAM_CHILD_TID_OFFSET = 6L * Long.BYTES;

    /// The byte offset of `parent_tid` inside FreeBSD `struct thr_param`.
    private static final long FREEBSD_THR_PARAM_PARENT_TID_OFFSET = 7L * Long.BYTES;

    /// The minimum FreeBSD `struct thr_param` byte size needed by the simulator.
    private static final long FREEBSD_THR_PARAM_MINIMUM_SIZE = 8L * Long.BYTES;


    /// Executes the FreeBSD syscall described by the guest argument registers at the supplied program counter.
    @Override
    public void handle(RiscVThreadState state, long pc) {
        long callNumber = state.register(5);
        boolean indirect = callNumber == FREEBSD_SYS_SYSCALL || callNumber == FREEBSD_SYS___SYSCALL;
        int argumentBaseRegister = indirect ? 11 : 10;
        if (indirect) {
            callNumber = state.register(10);
        }
        if (callNumber != (int) callNumber) {
            throw new RiscVException(unsupportedEcallMessage(state, pc, callNumber));
        }

        long previousMask = state.enterSyscallPointerMask();
        try {
            long result;
            try {
                switch ((int) callNumber) {
                case FREEBSD_SYS_EXIT -> {
                    long exitCode = freeBsdArgument(state, argumentBaseRegister, 0);
                    requestProcessExit(exitCode);
                    throw new ProgramExitException(exitCode);
                }
                case FREEBSD_SYS_FORK -> result = forkProcess(state, pc);
                case FREEBSD_SYS_READ -> result = read(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_WRITE -> result = write(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_RECVMSG -> result = freeBsdRecvmsg(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_SENDMSG -> result = freeBsdSendmsg(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_RECVFROM -> result = freeBsdRecvfrom(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4),
                        freeBsdArgument(state, argumentBaseRegister, 5));
                case FREEBSD_SYS_ACCEPT -> result = freeBsdAccept(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        0);
                case FREEBSD_SYS_GETPEERNAME -> result = getpeername(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_GETSOCKNAME -> result = getsockname(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_OPEN -> result = openat(
                        AT_FDCWD,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdOpenFlagsToLinux(freeBsdArgument(state, argumentBaseRegister, 1)),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_OPENAT -> result = openat(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdOpenFlagsToLinux(freeBsdArgument(state, argumentBaseRegister, 2)),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_UNLINK -> result = unlinkat(
                        AT_FDCWD,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        0);
                case FREEBSD_SYS_LINK -> result = linkat(
                        AT_FDCWD,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        AT_FDCWD,
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        0);
                case FREEBSD_SYS_CLOSE -> result = close((int) freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_WAIT4 -> result = freeBsdWait4(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_CHDIR -> result = chdir(freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_FCHDIR -> result = fchdir((int) freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_CHMOD -> result = fchmodat(
                        AT_FDCWD,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        0);
                case FREEBSD_SYS_CHOWN -> result = fchownat(
                        AT_FDCWD,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        0);
                case FREEBSD_SYS_GETPID -> result = process.id();
                case FREEBSD_SYS_GETPPID -> result = process.parentId();
                case FREEBSD_SYS_SETUID -> result = freeBsdSetuid(
                        freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_GETUID -> result = credentials.realUserId();
                case FREEBSD_SYS_GETEUID -> result = credentials.effectiveUserId();
                case FREEBSD_SYS_GETGID -> result = credentials.realGroupId();
                case FREEBSD_SYS_GETEGID -> result = credentials.effectiveGroupId();
                case FREEBSD_SYS_GETLOGIN -> result = freeBsdGetlogin(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_SETLOGIN -> result = freeBsdSetlogin(
                        freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_ACCESS -> result = faccessat(
                        AT_FDCWD,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        0);
                case FREEBSD_SYS_FACCESSAT -> result = faccessat(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdAtFlagsToLinux(freeBsdArgument(state, argumentBaseRegister, 3)));
                case FREEBSD_SYS_SYNC -> result = sync();
                case FREEBSD_SYS_KILL -> result = kill(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_SIGALTSTACK -> result = freeBsdSigaltstack(
                        state,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_DUP -> result = dup((int) freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_PIPE -> result = freeBsdPipe(state);
                case FREEBSD_SYS_DUP2 -> result = freeBsdDup2(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_IOCTL -> result = ioctl(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_SYMLINK -> result = symlinkat(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        AT_FDCWD,
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_READLINK -> result = readlinkat(
                        AT_FDCWD,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_READLINKAT -> result = readlinkat(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_EXECVE -> result = execve(
                        state,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_UMASK -> result = umask(freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_MSYNC -> result = freeBsdMsync(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_MUNMAP -> result = munmap(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_MPROTECT -> result = mprotect(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_MADVISE -> result = freeBsdMadvise(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_MINCORE -> result = mincore(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_GETGROUPS -> result = freeBsd14Getgroups(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_SETGROUPS -> result = freeBsd14Setgroups(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_GETPGRP -> result = process.processGroupId();
                case FREEBSD_SYS_SETPGID -> result = setpgid(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_SETITIMER -> result = setitimer(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_GETITIMER -> result = getitimer(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_GETDTABLESIZE -> result = DEFAULT_OPEN_FILE_LIMIT;
                case FREEBSD_SYS_FCNTL -> result = freeBsdFcntl(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_SELECT -> result = freeBsdSelect(
                        state,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4));
                case FREEBSD_SYS_FSYNC -> result = fsync((int) freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_SETPRIORITY -> result = setFreeBsdProcessPriority(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_SOCKET -> result = freeBsdSocket(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_CONNECT -> result = connect(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_GETPRIORITY -> result = freeBsdGetpriority(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_BIND -> result = bind(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_SETSOCKOPT -> result = freeBsdSetsockopt(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4));
                case FREEBSD_SYS_LISTEN -> result = listen(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_FDATASYNC -> result = fdatasync((int) freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_FSTAT -> result = fstat(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_FSTATAT -> result = freeBsdFstatat(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_GETDIRENTRIES -> result = freeBsdGetdirentries(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_STATFS -> result = statfs(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_FSTATFS -> result = fstatfs(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_GETTIMEOFDAY -> result = gettimeofday(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_GETRUSAGE -> result = getrusage(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_GETSOCKOPT -> result = freeBsdGetsockopt(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4));
                case FREEBSD_SYS_READV -> result = readv(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_WRITEV -> result = writev(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_FCHOWN -> result = fchown(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_FCHMOD -> result = fchmod(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_FLOCK -> result = freeBsdFlock(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_SETREUID -> result = freeBsdSetreuid(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_SETREGID -> result = freeBsdSetregid(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_RENAME -> result = renameat(
                        AT_FDCWD,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        AT_FDCWD,
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_SENDTO -> result = freeBsdSendto(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4),
                        freeBsdArgument(state, argumentBaseRegister, 5));
                case FREEBSD_SYS_SHUTDOWN -> result = shutdown(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_SOCKETPAIR -> result = freeBsdSocketpair(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_MKDIR -> result = mkdirat(
                        AT_FDCWD,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_RMDIR -> result = unlinkat(
                        AT_FDCWD,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        AT_REMOVEDIR);
                case FREEBSD_SYS_SETSID -> result = setsid();
                case FREEBSD_SYS_SETGID -> result = freeBsdSetgid(
                        freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_SETEGID -> result = freeBsdSetegid(
                        freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_SETEUID -> result = freeBsdSeteuid(
                        freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_PATHCONF -> result = freeBsdPathconf(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        true);
                case FREEBSD_SYS_FPATHCONF -> result = freeBsdFpathconf(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_GETRLIMIT -> result = freeBsdGetrlimit(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_SETRLIMIT -> result = freeBsdSetrlimit(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS___SYSCTL -> result = freeBsdSysctl(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4),
                        freeBsdArgument(state, argumentBaseRegister, 5));
                case FREEBSD_SYS_MLOCK -> result = freeBsdMlock(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_MUNLOCK -> result = freeBsdMunlock(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_GETPGID -> result = getpgid(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_POLL -> result = poll(
                        state,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        Integer.toUnsignedLong((int) freeBsdArgument(state, argumentBaseRegister, 1)),
                        (int) freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_CLOCK_GETTIME -> result = freeBsdClockGettime(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_CLOCK_GETRES -> result = freeBsdClockGetres(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_NANOSLEEP -> result = freeBsdNanosleep(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_CLOCK_NANOSLEEP -> result = freeBsdClockNanosleep(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_ISSETUGID -> result = credentialStateChanged ? 1 : 0;
                case FREEBSD_SYS_PREADV -> result = preadv(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        Integer.toUnsignedLong((int) freeBsdArgument(state, argumentBaseRegister, 2)),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_PWRITEV -> result = pwritev(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        Integer.toUnsignedLong((int) freeBsdArgument(state, argumentBaseRegister, 2)),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_GETSID -> result = getsid(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_SETRESUID -> result = freeBsdSetresuid(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_SETRESGID -> result = freeBsdSetresgid(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_MLOCKALL -> result = freeBsdMlockall(
                        freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_MUNLOCKALL -> result = freeBsdMunlockall();
                case FREEBSD_SYS___GETCWD -> result = getcwd(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_YIELD -> result = schedYield();
                case FREEBSD_SYS_SCHED_SETPARAM -> result = freeBsdSchedSetparam(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_SCHED_GETPARAM -> result = freeBsdSchedGetparam(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_SCHED_SETSCHEDULER -> result = freeBsdSchedSetscheduler(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_SCHED_GETSCHEDULER -> result = freeBsdSchedGetscheduler(
                        freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_SCHED_YIELD -> result = schedYield();
                case FREEBSD_SYS_SCHED_GET_PRIORITY_MAX -> result = freeBsdSchedGetPriorityMax(
                        freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_SCHED_GET_PRIORITY_MIN -> result = freeBsdSchedGetPriorityMin(
                        freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_SCHED_RR_GET_INTERVAL -> result = freeBsdSchedRrGetInterval(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_SIGPROCMASK -> result = freeBsdSigprocmask(
                        state,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_GETRESUID -> result = getresid(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        credentials.realUserId(),
                        credentials.effectiveUserId(),
                        credentials.savedUserId());
                case FREEBSD_SYS_GETRESGID -> result = getresid(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        credentials.realGroupId(),
                        credentials.effectiveGroupId(),
                        credentials.savedGroupId());
                case FREEBSD_SYS_KQUEUE -> result = freeBsdKqueue();
                case FREEBSD_SYS_GETRANDOM -> result = getrandom(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        Integer.toUnsignedLong((int) freeBsdArgument(state, argumentBaseRegister, 2)));
                case FREEBSD_SYS_FREEBSD11_KEVENT -> result = freeBsdKevent(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4),
                        freeBsdArgument(state, argumentBaseRegister, 5),
                        FREEBSD11_KEVENT_SIZE);
                case FREEBSD_SYS_SIGACTION -> result = freeBsdSigaction(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_THR_EXIT -> {
                    freeBsdThrExit(state, freeBsdArgument(state, argumentBaseRegister, 0));
                    result = 0;
                }
                case FREEBSD_SYS_THR_SELF -> result = freeBsdThrSelf(
                        state,
                        freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_THR_KILL -> result = freeBsdThrKill(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_THR_SUSPEND -> result = freeBsdThrSuspend(
                        state,
                        freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_THR_WAKE -> result = freeBsdThrWake(
                        freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_UMTX_OP -> result = freeBsdUmtxOp(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4));
                case FREEBSD_SYS_THR_NEW -> result = freeBsdThrNew(
                        state,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_THR_SET_NAME -> result = freeBsdThrSetName(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_PREAD -> result = pread64(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_PWRITE -> result = pwrite64(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_MMAP -> {
                    result = mmap(
                            freeBsdArgument(state, argumentBaseRegister, 0),
                            freeBsdArgument(state, argumentBaseRegister, 1),
                            freeBsdArgument(state, argumentBaseRegister, 2),
                            freeBsdMmapFlagsToLinux(freeBsdArgument(state, argumentBaseRegister, 3)),
                            freeBsdArgument(state, argumentBaseRegister, 4),
                            freeBsdArgument(state, argumentBaseRegister, 5));
                }
                case FREEBSD_SYS_CPUSET_GETAFFINITY -> result = freeBsdCpusetGetaffinity(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4));
                case FREEBSD_SYS_CPUSET_SETAFFINITY -> result = freeBsdCpusetSetaffinity(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4));
                case FREEBSD_SYS_LSEEK -> result = lseek(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        (int) freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_TRUNCATE -> result = truncate(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_FTRUNCATE -> result = ftruncate(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_THR_KILL2 -> result = freeBsdThrKill2(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_CPUSET -> result = freeBsdCpuset(
                        freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_CPUSET_SETID -> result = freeBsdCpusetSetid(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_CPUSET_GETID -> result = freeBsdCpusetGetid(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_FCHOWNAT -> result = fchownat(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdAtFlagsToLinux(freeBsdArgument(state, argumentBaseRegister, 4)));
                case FREEBSD_SYS_LINKAT -> result = linkat(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdAtFlagsToLinux(freeBsdArgument(state, argumentBaseRegister, 4)));
                case FREEBSD_SYS_FCHMODAT -> result = fchmodat(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdAtFlagsToLinux(freeBsdArgument(state, argumentBaseRegister, 3)));
                case FREEBSD_SYS_MKDIRAT -> result = mkdirat(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_RENAMEAT -> result = renameat(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_SYMLINKAT -> result = symlinkat(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2));
                case FREEBSD_SYS_UNLINKAT -> result = unlinkat(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdAtFlagsToLinux(freeBsdArgument(state, argumentBaseRegister, 2)));
                case FREEBSD_SYS_CLOSEFROM -> result = freeBsdClosefrom(
                        freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_LPATHCONF -> result = freeBsdPathconf(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        false);
                case FREEBSD_SYS_PSELECT -> result = freeBsdPselect(
                        state,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4),
                        freeBsdArgument(state, argumentBaseRegister, 5));
                case FREEBSD_SYS_ACCEPT4 -> result = freeBsdAccept(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_PIPE2 -> result = freeBsdPipe2(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_POSIX_FALLOCATE -> result = freeBsdPosixError(posixFallocate(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2)));
                case FREEBSD_SYS_POSIX_FADVISE -> result = freeBsdPosixError(posixFadvise(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3)));
                case FREEBSD_SYS_WAIT6 -> result = freeBsdWait6(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4),
                        freeBsdArgument(state, argumentBaseRegister, 5));
                case FREEBSD_SYS_PPOLL -> result = freeBsdPpoll(
                        state,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        Integer.toUnsignedLong((int) freeBsdArgument(state, argumentBaseRegister, 1)),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_FUTIMENS -> result = futimens(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        FREEBSD_UTIME_NOW,
                        FREEBSD_UTIME_OMIT);
                case FREEBSD_SYS_UTIMENSAT -> result = utimensat(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdAtFlagsToLinux(freeBsdArgument(state, argumentBaseRegister, 3)),
                        FREEBSD_UTIME_NOW,
                        FREEBSD_UTIME_OMIT);
                case FREEBSD_SYS_KEVENT -> result = freeBsdKevent(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4),
                        freeBsdArgument(state, argumentBaseRegister, 5),
                        FREEBSD_KEVENT_SIZE);
                case FREEBSD_SYS_CPUSET_GETDOMAIN -> result = freeBsdCpusetGetdomain(
                        state,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4),
                        freeBsdArgument(state, argumentBaseRegister, 5));
                case FREEBSD_SYS_CPUSET_SETDOMAIN -> result = freeBsdCpusetSetdomain(
                        state,
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4),
                        freeBsdArgument(state, argumentBaseRegister, 5));
                case FREEBSD_SYS_COPY_FILE_RANGE -> result = freeBsdCopyFileRange(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        (int) freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4),
                        freeBsdArgument(state, argumentBaseRegister, 5));
                case FREEBSD_SYS_CLOSE_RANGE -> result = closeRange(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        FREEBSD_SUPPORTED_CLOSE_RANGE_FLAGS);
                case FREEBSD_SYS_FSPACECTL -> result = freeBsdFspacectl(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4));
                case FREEBSD_SYS_SCHED_GETCPU -> result = 0;
                case FREEBSD_SYS_KQUEUEX -> result = freeBsdKqueuex(
                        freeBsdArgument(state, argumentBaseRegister, 0));
                case FREEBSD_SYS_MEMBARRIER -> result = freeBsdMembarrier(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_TIMERFD_CREATE -> result = freeBsdTimerfdCreate(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_TIMERFD_GETTIME -> result = timerfdGettime(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_TIMERFD_SETTIME -> result = timerfdSettime(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3));
                case FREEBSD_SYS_GETGROUPS_CURRENT -> result = getgroups(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_SETGROUPS_CURRENT -> result = freeBsdSetgroups(
                        (int) freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1));
                case FREEBSD_SYS_RENAMEAT2 -> result = renameat2(
                        freeBsdArgument(state, argumentBaseRegister, 0),
                        freeBsdArgument(state, argumentBaseRegister, 1),
                        freeBsdArgument(state, argumentBaseRegister, 2),
                        freeBsdArgument(state, argumentBaseRegister, 3),
                        freeBsdArgument(state, argumentBaseRegister, 4));
                default -> throw new RiscVException(unsupportedEcallMessage(state, pc, callNumber));
                }
            } catch (RiscVException exception) {
                throw new RiscVException(freeBsdSyscallFailureMessage(state, pc, callNumber, argumentBaseRegister, exception), exception);
            }
            setFreeBsdSyscallResult(state, result);
        } finally {
            state.restorePointerMask(previousMask);
        }
    }

    /// Reads one FreeBSD syscall argument register after optional syscall-number indirection.
    private static long freeBsdArgument(RiscVThreadState state, int baseRegister, int index) {
        int register = baseRegister + index;
        return register <= 17 ? state.register(register) : 0;
    }

    /// Converts a FreeBSD `uid_t` or `gid_t` syscall argument to its unsigned 32-bit value.
    private static long freeBsdIdArgument(long value) {
        return Integer.toUnsignedLong((int) value);
    }

    /// Seeds the initial FreeBSD session login name from configured credentials when present.
    private void initializeFreeBsdLoginName(@Nullable String loginName) {
        if (loginName == null) {
            return;
        }
        byte[] bytes = loginName.getBytes(StandardCharsets.UTF_8);
        process.session().setLoginName(Arrays.copyOf(bytes, Math.min(bytes.length, FREEBSD_MAXLOGNAME - 1)));
    }

    /// Copies the current FreeBSD session login name to guest memory.
    private long freeBsdGetlogin(long nameAddress, long requestedLength) {
        int nameLength = (int) Math.min(Integer.toUnsignedLong((int) requestedLength), FREEBSD_MAXLOGNAME);
        byte[] loginName = process.session().loginName();
        int requiredLength = loginName.length + 1;
        if (requiredLength > nameLength) {
            return ERANGE;
        }
        if (!memory.isBacked(nameAddress, requiredLength)) {
            return EFAULT;
        }

        memory.writeBytes(nameAddress, loginName, 0, loginName.length);
        memory.writeByte(nameAddress + loginName.length, (byte) 0);
        return 0;
    }

    /// Replaces the FreeBSD session login name after privilege and bounded-string checks.
    private long freeBsdSetlogin(long nameAddress) {
        if (credentials.effectiveUserId() != 0) {
            return EPERM;
        }

        byte[] loginName = new byte[FREEBSD_MAXLOGNAME - 1];
        for (int index = 0; index < FREEBSD_MAXLOGNAME; index++) {
            long address = nameAddress + index;
            if (!memory.isBacked(address, 1)) {
                return EFAULT;
            }
            int value = memory.readUnsignedByte(address);
            if (value == 0) {
                process.session().setLoginName(Arrays.copyOf(loginName, index));
                return 0;
            }
            if (index < loginName.length) {
                loginName[index] = (byte) value;
            }
        }
        return EINVAL;
    }

    /// Returns a FreeBSD nice value or a raw shared errno for `getpriority`.
    private long freeBsdGetpriority(long which, long who) {
        PriorityResult result = freeBsdProcessPriority(which, who);
        return result.error() != 0
                ? result.error()
                : encodeFreeBsdSuccessfulIntResult(result.niceValue());
    }

    /// Applies FreeBSD `setuid` permission checks and updates all three user ids.
    private long freeBsdSetuid(long requestedUserId) {
        long userId = freeBsdIdArgument(requestedUserId);
        if (credentials.effectiveUserId() != 0
                && userId != credentials.realUserId()
                && userId != credentials.effectiveUserId()
                && userId != credentials.savedUserId()) {
            return EPERM;
        }
        updateFreeBsdUserIds(userId, userId, userId);
        return 0;
    }

    /// Applies FreeBSD `seteuid` permission checks and updates only the effective user id.
    private long freeBsdSeteuid(long requestedEffectiveUserId) {
        long effectiveUserId = freeBsdIdArgument(requestedEffectiveUserId);
        if (credentials.effectiveUserId() != 0
                && effectiveUserId != credentials.realUserId()
                && effectiveUserId != credentials.savedUserId()) {
            return EPERM;
        }
        updateFreeBsdUserIds(
                credentials.realUserId(),
                effectiveUserId,
                credentials.savedUserId());
        return 0;
    }

    /// Applies FreeBSD `setgid` permission checks and updates all three group ids.
    private long freeBsdSetgid(long requestedGroupId) {
        long groupId = freeBsdIdArgument(requestedGroupId);
        if (credentials.effectiveUserId() != 0
                && groupId != credentials.realGroupId()
                && groupId != credentials.effectiveGroupId()
                && groupId != credentials.savedGroupId()) {
            return EPERM;
        }
        updateFreeBsdGroupIds(groupId, groupId, groupId);
        return 0;
    }

    /// Applies FreeBSD `setegid` permission checks and updates only the effective group id.
    private long freeBsdSetegid(long requestedEffectiveGroupId) {
        long effectiveGroupId = freeBsdIdArgument(requestedEffectiveGroupId);
        if (credentials.effectiveUserId() != 0
                && effectiveGroupId != credentials.realGroupId()
                && effectiveGroupId != credentials.savedGroupId()) {
            return EPERM;
        }
        updateFreeBsdGroupIds(
                credentials.realGroupId(),
                effectiveGroupId,
                credentials.savedGroupId());
        return 0;
    }

    /// Applies FreeBSD `setreuid` permission and saved-id transition rules.
    private long freeBsdSetreuid(long requestedRealUserId, long requestedEffectiveUserId) {
        long realUserIdArgument = freeBsdIdArgument(requestedRealUserId);
        long effectiveUserIdArgument = freeBsdIdArgument(requestedEffectiveUserId);
        long currentRealUserId = credentials.realUserId();
        long currentEffectiveUserId = credentials.effectiveUserId();
        long currentSavedUserId = credentials.savedUserId();
        if (currentEffectiveUserId != 0
                && ((!isSetresidUnchanged(realUserIdArgument)
                && realUserIdArgument != currentRealUserId
                && realUserIdArgument != currentSavedUserId)
                || (!isSetresidUnchanged(effectiveUserIdArgument)
                && effectiveUserIdArgument != currentEffectiveUserId
                && effectiveUserIdArgument != currentRealUserId
                && effectiveUserIdArgument != currentSavedUserId))) {
            return EPERM;
        }

        long realUserId = setresidValue(realUserIdArgument, currentRealUserId);
        long effectiveUserId = setresidValue(effectiveUserIdArgument, currentEffectiveUserId);
        long savedUserId = !isSetresidUnchanged(realUserIdArgument) || effectiveUserId != realUserId
                ? effectiveUserId
                : currentSavedUserId;
        updateFreeBsdUserIds(realUserId, effectiveUserId, savedUserId);
        return 0;
    }

    /// Applies FreeBSD `setregid` permission and saved-id transition rules.
    private long freeBsdSetregid(long requestedRealGroupId, long requestedEffectiveGroupId) {
        long realGroupIdArgument = freeBsdIdArgument(requestedRealGroupId);
        long effectiveGroupIdArgument = freeBsdIdArgument(requestedEffectiveGroupId);
        long currentRealGroupId = credentials.realGroupId();
        long currentEffectiveGroupId = credentials.effectiveGroupId();
        long currentSavedGroupId = credentials.savedGroupId();
        if (credentials.effectiveUserId() != 0
                && ((!isSetresidUnchanged(realGroupIdArgument)
                && realGroupIdArgument != currentRealGroupId
                && realGroupIdArgument != currentSavedGroupId)
                || (!isSetresidUnchanged(effectiveGroupIdArgument)
                && effectiveGroupIdArgument != currentEffectiveGroupId
                && effectiveGroupIdArgument != currentRealGroupId
                && effectiveGroupIdArgument != currentSavedGroupId))) {
            return EPERM;
        }

        long realGroupId = setresidValue(realGroupIdArgument, currentRealGroupId);
        long effectiveGroupId = setresidValue(effectiveGroupIdArgument, currentEffectiveGroupId);
        long savedGroupId = !isSetresidUnchanged(realGroupIdArgument) || effectiveGroupId != realGroupId
                ? effectiveGroupId
                : currentSavedGroupId;
        updateFreeBsdGroupIds(realGroupId, effectiveGroupId, savedGroupId);
        return 0;
    }

    /// Updates real, effective, and saved user ids using FreeBSD unsigned id arguments.
    private long freeBsdSetresuid(
            long requestedRealUserId,
            long requestedEffectiveUserId,
            long requestedSavedUserId) {
        long previousRealUserId = credentials.realUserId();
        long previousEffectiveUserId = credentials.effectiveUserId();
        long previousSavedUserId = credentials.savedUserId();
        long result = setresuid(
                freeBsdIdArgument(requestedRealUserId),
                freeBsdIdArgument(requestedEffectiveUserId),
                freeBsdIdArgument(requestedSavedUserId));
        if (result == 0
                && (credentials.realUserId() != previousRealUserId
                || credentials.effectiveUserId() != previousEffectiveUserId
                || credentials.savedUserId() != previousSavedUserId)) {
            credentialStateChanged = true;
        }
        return result;
    }

    /// Updates real, effective, and saved group ids using FreeBSD unsigned id arguments.
    private long freeBsdSetresgid(
            long requestedRealGroupId,
            long requestedEffectiveGroupId,
            long requestedSavedGroupId) {
        long previousRealGroupId = credentials.realGroupId();
        long previousEffectiveGroupId = credentials.effectiveGroupId();
        long previousSavedGroupId = credentials.savedGroupId();
        long result = setresgid(
                freeBsdIdArgument(requestedRealGroupId),
                freeBsdIdArgument(requestedEffectiveGroupId),
                freeBsdIdArgument(requestedSavedGroupId));
        if (result == 0
                && (credentials.realGroupId() != previousRealGroupId
                || credentials.effectiveGroupId() != previousEffectiveGroupId
                || credentials.savedGroupId() != previousSavedGroupId)) {
            credentialStateChanged = true;
        }
        return result;
    }

    /// Writes the FreeBSD 14 group vector, including the effective gid as its first element.
    private long freeBsd14Getgroups(long size, long listAddress) {
        if (size < 0 || size > Integer.MAX_VALUE) {
            return EINVAL;
        }

        int supplementaryGroupCount = credentials.supplementaryGroupCount();
        int groupCount = supplementaryGroupCount + 1;
        if (size == 0) {
            return groupCount;
        }
        if (size < groupCount) {
            return EINVAL;
        }

        long byteCount = (long) groupCount * Integer.BYTES;
        if (!memory.isBacked(listAddress, byteCount)) {
            return EFAULT;
        }
        memory.writeInt(listAddress, GuestCredentials.idToInt(credentials.effectiveGroupId()));
        for (int index = 0; index < supplementaryGroupCount; index++) {
            memory.writeInt(
                    listAddress + (long) (index + 1) * Integer.BYTES,
                    GuestCredentials.idToInt(credentials.supplementaryGroupAt(index)));
        }
        return groupCount;
    }

    /// Replaces the FreeBSD 14 effective and supplementary group vector.
    private long freeBsd14Setgroups(long size, long listAddress) {
        if (size < 0 || size > FREEBSD_MAX_SUPPLEMENTARY_GROUP_COUNT + 1L) {
            return EINVAL;
        }
        int groupCount = (int) size;
        long byteCount = size * Integer.BYTES;
        if (groupCount != 0 && !memory.isBacked(listAddress, byteCount)) {
            return EFAULT;
        }

        long[] groups = new long[groupCount];
        for (int index = 0; index < groupCount; index++) {
            groups[index] = memory.readUnsignedInt(listAddress + (long) index * Integer.BYTES);
        }
        if (credentials.effectiveUserId() != 0) {
            return EPERM;
        }

        if (groupCount == 0) {
            credentials = credentials.withSupplementaryGroups(new long[0]);
        } else {
            long effectiveGroupId = groups[0];
            Arrays.sort(groups, 1, groups.length);
            int uniqueEnd = Math.min(2, groups.length);
            for (int index = 2; index < groups.length; index++) {
                if (groups[index] != groups[uniqueEnd - 1]) {
                    groups[uniqueEnd++] = groups[index];
                }
            }
            long[] supplementaryGroups = Arrays.copyOfRange(groups, 1, uniqueEnd);
            credentials = credentials
                    .withGroupIds(credentials.realGroupId(), effectiveGroupId, credentials.savedGroupId())
                    .withSupplementaryGroups(supplementaryGroups);
        }
        credentialStateChanged = true;
        return 0;
    }

    /// Replaces current FreeBSD supplementary groups after sorting and duplicate removal.
    private long freeBsdSetgroups(long size, long listAddress) {
        if (size < 0 || size > FREEBSD_MAX_SUPPLEMENTARY_GROUP_COUNT) {
            return EINVAL;
        }
        int groupCount = (int) size;
        long byteCount = size * Integer.BYTES;
        if (groupCount != 0 && !memory.isBacked(listAddress, byteCount)) {
            return EFAULT;
        }

        long[] groups = new long[groupCount];
        for (int index = 0; index < groupCount; index++) {
            groups[index] = memory.readUnsignedInt(listAddress + (long) index * Integer.BYTES);
        }
        Arrays.sort(groups);
        int uniqueCount = 0;
        for (long group : groups) {
            if (uniqueCount == 0 || groups[uniqueCount - 1] != group) {
                groups[uniqueCount++] = group;
            }
        }
        if (credentials.effectiveUserId() != 0) {
            return EPERM;
        }

        credentials = credentials.withSupplementaryGroups(
                uniqueCount == groups.length ? groups : Arrays.copyOf(groups, uniqueCount));
        credentialStateChanged = true;
        return 0;
    }

    /// Replaces user ids and records a sticky FreeBSD set-id state when any value changes.
    private void updateFreeBsdUserIds(long realUserId, long effectiveUserId, long savedUserId) {
        if (realUserId != credentials.realUserId()
                || effectiveUserId != credentials.effectiveUserId()
                || savedUserId != credentials.savedUserId()) {
            credentialStateChanged = true;
        }
        credentials = credentials.withUserIds(realUserId, effectiveUserId, savedUserId);
    }

    /// Replaces group ids and records a sticky FreeBSD set-id state when any value changes.
    private void updateFreeBsdGroupIds(long realGroupId, long effectiveGroupId, long savedGroupId) {
        if (realGroupId != credentials.realGroupId()
                || effectiveGroupId != credentials.effectiveGroupId()
                || savedGroupId != credentials.savedGroupId()) {
            credentialStateChanged = true;
        }
        credentials = credentials.withGroupIds(realGroupId, effectiveGroupId, savedGroupId);
    }

    /// Stores a FreeBSD syscall result and error indicator in guest registers.
    private static void setFreeBsdSyscallResult(RiscVThreadState state, long result) {
        if (isEncodedFreeBsdSuccessfulNegativeIntResult(result)) {
            state.setRegister(10, -(result - FREEBSD_NEGATIVE_INT_SUCCESS_BASE));
            state.setRegister(5, 0);
            return;
        }

        long freeBsdResult = freeBsdErrno(result);
        if (freeBsdResult < 0) {
            state.setRegister(10, -freeBsdResult);
            state.setRegister(5, 1);
            return;
        }
        state.setRegister(10, freeBsdResult);
        state.setRegister(5, 0);
    }

    /// Encodes a successful signed 32-bit result that the shared negative-errno convention cannot represent.
    private static long encodeFreeBsdSuccessfulIntResult(int result) {
        return result < 0 ? FREEBSD_NEGATIVE_INT_SUCCESS_BASE - (long) result : result;
    }

    /// Returns true when a dispatch result encodes a successful negative FreeBSD integer.
    private static boolean isEncodedFreeBsdSuccessfulNegativeIntResult(long result) {
        return result > FREEBSD_NEGATIVE_INT_SUCCESS_BASE
                && result <= FREEBSD_NEGATIVE_INT_SUCCESS_MAXIMUM;
    }

    /// Builds a diagnostic message for a FreeBSD syscall handler failure.
    private static String freeBsdSyscallFailureMessage(
            RiscVThreadState state,
            long pc,
            long callNumber,
            int argumentBaseRegister,
            RiscVException exception) {
        return "FreeBSD syscall failed: pc=0x"
                + Long.toUnsignedString(pc, 16)
                + ", call="
                + callNumber
                + ", a0=0x"
                + Long.toUnsignedString(freeBsdArgument(state, argumentBaseRegister, 0), 16)
                + ", a1=0x"
                + Long.toUnsignedString(freeBsdArgument(state, argumentBaseRegister, 1), 16)
                + ", a2=0x"
                + Long.toUnsignedString(freeBsdArgument(state, argumentBaseRegister, 2), 16)
                + ", a3=0x"
                + Long.toUnsignedString(freeBsdArgument(state, argumentBaseRegister, 3), 16)
                + ", a4=0x"
                + Long.toUnsignedString(freeBsdArgument(state, argumentBaseRegister, 4), 16)
                + ", a5=0x"
                + Long.toUnsignedString(freeBsdArgument(state, argumentBaseRegister, 5), 16)
                + ": "
                + exception.getMessage();
    }

    /// Handles the small read-only FreeBSD `__sysctl` surface required by Go programs.
    private long freeBsdSysctl(
            long mibAddress,
            long mibLength,
            long outputAddress,
            long outputLengthAddress,
            long newValueAddress,
            long newValueLength) {
        if (mibAddress == 0 || mibLength <= 0 || mibLength > 24) {
            return EINVAL;
        }

        int[] mib = new int[(int) mibLength];
        for (int index = 0; index < mib.length; index++) {
            mib[index] = memory.readInt(mibAddress + (long) index * Integer.BYTES);
        }

        if (mib.length == 2 && mib[0] == FREEBSD_CTL_QUERY && mib[1] == FREEBSD_CTL_QUERY_MIB) {
            @Nullable String name = readFreeBsdSysctlName(newValueAddress, newValueLength);
            if (FREEBSD_SYSCTL_KERN_SMP_MAXCPUS_NAME.equals(name)) {
                return writeFreeBsdSysctlIntArray(outputAddress, outputLengthAddress, FREEBSD_SYSCTL_KERN_SMP_MAXCPUS);
            }
            return ENOENT;
        }

        if (mib.length == 2 && mib[0] == FREEBSD_CTL_HW && mib[1] == FREEBSD_HW_PAGESIZE) {
            return writeFreeBsdSysctlInt(outputAddress, outputLengthAddress, memory.pageSize());
        }

        if (Arrays.equals(mib, FREEBSD_SYSCTL_KERN_SMP_MAXCPUS)) {
            return writeFreeBsdSysctlInt(outputAddress, outputLengthAddress, 1);
        }

        if (Arrays.equals(mib, FREEBSD_SYSCTL_KERN_PROC_PATHNAME)) {
            byte[] pathBytes = procExecutablePath.getBytes(StandardCharsets.UTF_8);
            return writeFreeBsdSysctlBytes(
                    outputAddress,
                    outputLengthAddress,
                    Arrays.copyOf(pathBytes, pathBytes.length + 1));
        }

        return ENOENT;
    }

    /// Reads the sysctl query name supplied to `CTL_QUERY_MIB`.
    private @Nullable String readFreeBsdSysctlName(long address, long length) {
        if (address == 0 || length < 0 || length > Integer.MAX_VALUE) {
            return null;
        }
        byte[] bytes = memory.readBytes(address, length);
        int end = 0;
        while (end < bytes.length && bytes[end] != 0) {
            end++;
        }
        return new String(bytes, 0, end, StandardCharsets.US_ASCII);
    }

    /// Writes a 32-bit sysctl value and updates `oldlenp`.
    private long writeFreeBsdSysctlInt(long outputAddress, long outputLengthAddress, long value) {
        return writeFreeBsdSysctlBytes(outputAddress, outputLengthAddress, intBytes(value));
    }

    /// Writes a 32-bit sysctl MIB array and updates `oldlenp`.
    private long writeFreeBsdSysctlIntArray(
            long outputAddress,
            long outputLengthAddress,
            int @Unmodifiable [] values) {
        byte[] bytes = new byte[values.length * Integer.BYTES];
        for (int index = 0; index < values.length; index++) {
            writeLittleEndianInt(bytes, index * Integer.BYTES, values[index]);
        }
        return writeFreeBsdSysctlBytes(outputAddress, outputLengthAddress, bytes);
    }

    /// Writes a sysctl byte result while honoring the guest output length pointer.
    private long writeFreeBsdSysctlBytes(long outputAddress, long outputLengthAddress, byte @Unmodifiable [] bytes) {
        if (outputLengthAddress == 0) {
            return outputAddress == 0 ? 0 : EFAULT;
        }

        long availableLength = memory.readLong(outputLengthAddress);
        memory.writeLong(outputLengthAddress, bytes.length);
        if (outputAddress == 0) {
            return 0;
        }
        if (availableLength < bytes.length) {
            return ENOMEM;
        }

        memory.writeBytes(outputAddress, bytes, 0, bytes.length);
        return 0;
    }

    /// Returns a little-endian byte representation of a 32-bit integer.
    private static byte[] intBytes(long value) {
        byte[] bytes = new byte[Integer.BYTES];
        writeLittleEndianInt(bytes, 0, (int) value);
        return bytes;
    }

    /// Writes a little-endian 32-bit integer into a byte array.
    private static void writeLittleEndianInt(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) value;
        bytes[offset + 1] = (byte) (value >>> Byte.SIZE);
        bytes[offset + 2] = (byte) (value >>> (2 * Byte.SIZE));
        bytes[offset + 3] = (byte) (value >>> (3 * Byte.SIZE));
    }

    /// Creates a numbered single-CPU FreeBSD set and assigns the calling process to it.
    private long freeBsdCpuset(long setIdAddress) {
        if (setIdAddress == 0 || !memory.isBacked(setIdAddress, Integer.BYTES)) {
            return EFAULT;
        }

        @Nullable Integer setId = processRegistry.createFreeBsdCpuSet();
        if (setId == null) {
            return ENFILE;
        }
        process.setFreeBsdCpuSetId(setId);
        memory.writeInt(setIdAddress, setId);
        return 0;
    }

    /// Assigns a selected FreeBSD process to an existing numbered CPU set.
    private long freeBsdCpusetSetid(long which, long id, long setId) {
        if (which != FREEBSD_CPU_WHICH_PID) {
            return EINVAL;
        }
        if (!processRegistry.isKnownFreeBsdCpuSetId(setId)) {
            return ESRCH;
        }

        @Nullable GuestProcess targetProcess = freeBsdCpusetProcess(id);
        if (targetProcess == null) {
            return ESRCH;
        }
        targetProcess.setFreeBsdCpuSetId((int) setId);
        return 0;
    }

    /// Writes the numbered root or assigned FreeBSD CPU set selected by level and object id.
    private long freeBsdCpusetGetid(long level, long which, long id, long setIdAddress) {
        if (level < FREEBSD_CPU_LEVEL_ROOT || level > FREEBSD_CPU_LEVEL_WHICH
                || level == FREEBSD_CPU_LEVEL_WHICH && which != FREEBSD_CPU_WHICH_CPUSET) {
            return EINVAL;
        }

        int selectedSetId;
        switch ((int) which) {
            case FREEBSD_CPU_WHICH_TID -> {
                if (id != -1 && !isKnownGuestThreadId(id)) {
                    return ESRCH;
                }
                selectedSetId = process.freeBsdCpuSetId();
            }
            case FREEBSD_CPU_WHICH_PID -> {
                @Nullable GuestProcess targetProcess = freeBsdCpusetProcess(id);
                if (targetProcess == null) {
                    return ESRCH;
                }
                selectedSetId = targetProcess.freeBsdCpuSetId();
            }
            case FREEBSD_CPU_WHICH_TIDPID -> {
                if (id == -1 || isKnownGuestThreadId(id)) {
                    selectedSetId = process.freeBsdCpuSetId();
                } else {
                    @Nullable GuestProcess targetProcess = freeBsdCpusetProcess(id);
                    if (targetProcess == null) {
                        return ESRCH;
                    }
                    selectedSetId = targetProcess.freeBsdCpuSetId();
                }
            }
            case FREEBSD_CPU_WHICH_CPUSET -> {
                long requestedSetId = id == -1 ? process.freeBsdCpuSetId() : id;
                if (!processRegistry.isKnownFreeBsdCpuSetId(requestedSetId)) {
                    return ESRCH;
                }
                selectedSetId = (int) requestedSetId;
            }
            default -> {
                return EINVAL;
            }
        }

        if (setIdAddress == 0 || !memory.isBacked(setIdAddress, Integer.BYTES)) {
            return EFAULT;
        }
        memory.writeInt(
                setIdAddress,
                level == FREEBSD_CPU_LEVEL_ROOT ? 0 : selectedSetId);
        return 0;
    }

    /// Returns the current or live direct-child process selected by a FreeBSD CPU-set process id.
    private @Nullable GuestProcess freeBsdCpusetProcess(long processId) {
        if (processId == -1 || processId == process.id()) {
            return process;
        }
        if (processId != (int) processId) {
            return null;
        }

        synchronized (childProcessLock) {
            @Nullable ChildProcess child = childProcess((int) processId);
            return child == null || child.exited() ? null : child.syscalls().process;
        }
    }

    /// Writes a single-CPU FreeBSD affinity mask after validating the requested target and buffer.
    private long freeBsdCpusetGetaffinity(
            long level,
            long which,
            long id,
            long setSize,
            long maskAddress) {
        long targetError = freeBsdCpusetTargetError(level, which, id);
        if (targetError != 0) {
            return targetError;
        }
        if (setSize == 0) {
            return ERANGE;
        }
        if (setSize < 0 || maskAddress == 0 || !memory.isBacked(maskAddress, setSize)) {
            return EFAULT;
        }

        memory.clear(maskAddress, setSize);
        memory.writeByte(maskAddress, (byte) 1);
        return 0;
    }

    /// Accepts a single-CPU FreeBSD affinity mask for a supported guest target.
    private long freeBsdCpusetSetaffinity(
            long level,
            long which,
            long id,
            long setSize,
            long maskAddress) {
        if (setSize < 0
                || setSize > Integer.MAX_VALUE
                || setSize != 0 && (maskAddress == 0 || !memory.isBacked(maskAddress, setSize))) {
            return EFAULT;
        }

        long targetError = freeBsdCpusetTargetError(level, which, id);
        if (targetError != 0) {
            return targetError;
        }

        boolean anyCpu = false;
        boolean onlyCpuZero = false;
        for (long index = 0; index < setSize; index++) {
            int value = memory.readUnsignedByte(maskAddress + index);
            if (value != 0) {
                anyCpu = true;
            }
            if (index == 0) {
                onlyCpuZero = (value & 1) != 0;
                if ((value & ~1) != 0) {
                    return EINVAL;
                }
            } else if (value != 0) {
                return EINVAL;
            }
        }
        if (!anyCpu) {
            return FREEBSD_EDEADLK_RESULT;
        }
        if (!onlyCpuZero) {
            return EINVAL;
        }

        int normalizedLevel = (int) level;
        int normalizedWhich = (int) which;
        if ((normalizedLevel != FREEBSD_CPU_LEVEL_WHICH
                || normalizedWhich == FREEBSD_CPU_WHICH_CPUSET)
                && credentials.effectiveUserId() != 0) {
            return EPERM;
        }
        return 0;
    }

    /// Writes the single available FreeBSD memory domain and the selected target's policy.
    private long freeBsdCpusetGetdomain(
            RiscVThreadState state,
            long level,
            long which,
            long id,
            long domainSetSize,
            long maskAddress,
            long policyAddress) {
        if (domainSetSize < FREEBSD_DOMAINSET_KERNEL_SIZE
                || domainSetSize > FREEBSD_DOMAINSET_MAXIMUM_SIZE) {
            return ERANGE;
        }

        long policy;
        if (level == FREEBSD_CPU_LEVEL_ROOT) {
            long selectedSetId = freeBsdCpusetBaseSetId(state, which, id);
            if (selectedSetId < 0) {
                return selectedSetId;
            }
            policy = freeBsdNumberedCpuSetDomainPolicy(0);
        } else if (level == FREEBSD_CPU_LEVEL_CPUSET) {
            long selectedSetId = freeBsdCpusetBaseSetId(state, which, id);
            if (selectedSetId < 0) {
                return selectedSetId;
            }
            policy = freeBsdNumberedCpuSetDomainPolicy(selectedSetId);
        } else if (level == FREEBSD_CPU_LEVEL_WHICH) {
            policy = freeBsdCpusetWhichDomainPolicy(state, which, id);
        } else {
            long targetError = freeBsdCpusetBaseSetId(state, which, id);
            return targetError < 0 ? targetError : EINVAL;
        }
        if (policy < 0) {
            return policy;
        }

        if (maskAddress == 0 || !memory.isBacked(maskAddress, domainSetSize)) {
            return EFAULT;
        }
        memory.clear(maskAddress, domainSetSize);
        memory.writeByte(maskAddress, (byte) 1);
        if (policyAddress == 0 || !memory.isBacked(policyAddress, Integer.BYTES)) {
            return EFAULT;
        }
        memory.writeInt(policyAddress, (int) policy);
        return 0;
    }

    /// Applies a valid single-domain FreeBSD memory policy to a thread, process, or numbered CPU set.
    private long freeBsdCpusetSetdomain(
            RiscVThreadState state,
            long level,
            long which,
            long id,
            long domainSetSize,
            long maskAddress,
            long policy) {
        if (domainSetSize < FREEBSD_DOMAINSET_KERNEL_SIZE
                || domainSetSize > FREEBSD_DOMAINSET_MAXIMUM_SIZE) {
            return ERANGE;
        }
        if (maskAddress == 0 || !memory.isBacked(maskAddress, domainSetSize)) {
            return EFAULT;
        }
        if (policy < FREEBSD_DOMAINSET_POLICY_ROUNDROBIN
                || policy > FREEBSD_DOMAINSET_POLICY_INTERLEAVE) {
            return EINVAL;
        }

        boolean domainZeroSelected = false;
        for (long index = 0; index < domainSetSize; index++) {
            int value = memory.readUnsignedByte(maskAddress + index);
            if (index == 0) {
                domainZeroSelected = (value & 1) != 0;
                if ((value & ~1) != 0) {
                    return EINVAL;
                }
            } else if (value != 0) {
                return EINVAL;
            }
        }
        if (!domainZeroSelected) {
            return FREEBSD_EDEADLK_RESULT;
        }

        if (level == FREEBSD_CPU_LEVEL_ROOT) {
            long selectedSetId = freeBsdCpusetBaseSetId(state, which, id);
            return selectedSetId < 0 ? selectedSetId : EPERM;
        }
        if (level == FREEBSD_CPU_LEVEL_CPUSET) {
            long selectedSetId = freeBsdCpusetBaseSetId(state, which, id);
            if (selectedSetId < 0) {
                return selectedSetId;
            }
            if (credentials.effectiveUserId() != 0 || selectedSetId == 0) {
                return EPERM;
            }
            return processRegistry.setFreeBsdCpuSetDomainPolicy(selectedSetId, (int) policy) ? 0 : ESRCH;
        }
        if (level == FREEBSD_CPU_LEVEL_WHICH) {
            return freeBsdCpusetSetWhichDomainPolicy(state, which, id, (int) policy);
        }
        return EINVAL;
    }

    /// Returns the numbered base CPU set selected by a FreeBSD object kind and id.
    private long freeBsdCpusetBaseSetId(RiscVThreadState state, long which, long id) {
        if (which != (int) which) {
            return EINVAL;
        }
        return switch ((int) which) {
            case FREEBSD_CPU_WHICH_TID ->
                    freeBsdCpusetThread(state, id) == null ? ESRCH : process.freeBsdCpuSetId();
            case FREEBSD_CPU_WHICH_PID -> {
                @Nullable GuestProcess targetProcess = freeBsdCpusetProcess(id);
                yield targetProcess == null ? ESRCH : targetProcess.freeBsdCpuSetId();
            }
            case FREEBSD_CPU_WHICH_TIDPID -> {
                if (id == -1 || guestThread(id) != null) {
                    yield process.freeBsdCpuSetId();
                }
                @Nullable GuestProcess targetProcess = freeBsdCpusetProcess(id);
                yield targetProcess == null ? ESRCH : targetProcess.freeBsdCpuSetId();
            }
            case FREEBSD_CPU_WHICH_CPUSET -> {
                long selectedSetId = id == -1 ? process.freeBsdCpuSetId() : id;
                yield processRegistry.isKnownFreeBsdCpuSetId(selectedSetId) ? selectedSetId : ESRCH;
            }
            default -> EINVAL;
        };
    }

    /// Returns the effective anonymous or numbered memory-domain policy selected at `CPU_LEVEL_WHICH`.
    private long freeBsdCpusetWhichDomainPolicy(RiscVThreadState state, long which, long id) {
        if (which != (int) which) {
            return EINVAL;
        }
        return switch ((int) which) {
            case FREEBSD_CPU_WHICH_TID -> {
                @Nullable GuestThread targetThread = freeBsdCpusetThread(state, id);
                yield targetThread == null ? ESRCH : freeBsdThreadDomainPolicy(targetThread);
            }
            case FREEBSD_CPU_WHICH_PID -> {
                @Nullable GuestProcess targetProcess = freeBsdCpusetProcess(id);
                yield targetProcess == null ? ESRCH : freeBsdProcessDomainPolicy(targetProcess);
            }
            case FREEBSD_CPU_WHICH_TIDPID -> {
                @Nullable GuestThread targetThread = id == -1 ? state.guestThread() : guestThread(id);
                if (targetThread != null) {
                    yield freeBsdThreadDomainPolicy(targetThread);
                }
                @Nullable GuestProcess targetProcess = freeBsdCpusetProcess(id);
                yield targetProcess == null ? ESRCH : freeBsdProcessDomainPolicy(targetProcess);
            }
            case FREEBSD_CPU_WHICH_CPUSET -> {
                long selectedSetId = id == -1 ? process.freeBsdCpuSetId() : id;
                yield freeBsdNumberedCpuSetDomainPolicy(selectedSetId);
            }
            default -> EINVAL;
        };
    }

    /// Replaces the anonymous or numbered memory-domain policy selected at `CPU_LEVEL_WHICH`.
    private long freeBsdCpusetSetWhichDomainPolicy(
            RiscVThreadState state,
            long which,
            long id,
            int policy) {
        if (which != (int) which) {
            return EINVAL;
        }
        switch ((int) which) {
            case FREEBSD_CPU_WHICH_TID -> {
                @Nullable GuestThread targetThread = freeBsdCpusetThread(state, id);
                if (targetThread == null) {
                    return ESRCH;
                }
                targetThread.setFreeBsdDomainPolicy(policy);
                return 0;
            }
            case FREEBSD_CPU_WHICH_PID -> {
                @Nullable GuestProcess targetProcess = freeBsdCpusetProcess(id);
                if (targetProcess == null) {
                    return ESRCH;
                }
                targetProcess.setFreeBsdDomainPolicy(policy);
                return 0;
            }
            case FREEBSD_CPU_WHICH_TIDPID -> {
                @Nullable GuestThread targetThread = id == -1 ? state.guestThread() : guestThread(id);
                if (targetThread != null) {
                    targetThread.setFreeBsdDomainPolicy(policy);
                    return 0;
                }
                @Nullable GuestProcess targetProcess = freeBsdCpusetProcess(id);
                if (targetProcess == null) {
                    return ESRCH;
                }
                targetProcess.setFreeBsdDomainPolicy(policy);
                return 0;
            }
            case FREEBSD_CPU_WHICH_CPUSET -> {
                long selectedSetId = id == -1 ? process.freeBsdCpuSetId() : id;
                if (!processRegistry.isKnownFreeBsdCpuSetId(selectedSetId)) {
                    return ESRCH;
                }
                if (credentials.effectiveUserId() != 0 || selectedSetId == 0) {
                    return EPERM;
                }
                return processRegistry.setFreeBsdCpuSetDomainPolicy(selectedSetId, policy) ? 0 : ESRCH;
            }
            default -> {
                return EINVAL;
            }
        }
    }

    /// Returns the current FreeBSD thread for id `-1` or a live thread with the requested id.
    private @Nullable GuestThread freeBsdCpusetThread(RiscVThreadState state, long threadId) {
        return threadId == -1 ? state.guestThread() : guestThread(threadId);
    }

    /// Returns one live thread's effective memory-domain policy using the current process base set.
    private long freeBsdThreadDomainPolicy(GuestThread thread) {
        long basePolicy = freeBsdNumberedCpuSetDomainPolicy(process.freeBsdCpuSetId());
        return basePolicy < 0 ? basePolicy : thread.freeBsdDomainPolicy((int) basePolicy);
    }

    /// Returns a process's effective memory-domain policy using its assigned numbered CPU set.
    private long freeBsdProcessDomainPolicy(GuestProcess targetProcess) {
        long basePolicy = freeBsdNumberedCpuSetDomainPolicy(targetProcess.freeBsdCpuSetId());
        return basePolicy < 0 ? basePolicy : targetProcess.freeBsdDomainPolicy((int) basePolicy);
    }

    /// Returns a numbered FreeBSD CPU set's memory-domain policy or `ESRCH` when it is unknown.
    private long freeBsdNumberedCpuSetDomainPolicy(long setId) {
        @Nullable Integer policy = processRegistry.freeBsdCpuSetDomainPolicy(setId);
        return policy == null ? ESRCH : policy;
    }

    /// Returns zero for a supported FreeBSD cpuset target or the corresponding lookup error.
    private long freeBsdCpusetTargetError(long level, long which, long id) {
        int normalizedLevel = (int) level;
        if (normalizedLevel < FREEBSD_CPU_LEVEL_ROOT || normalizedLevel > FREEBSD_CPU_LEVEL_WHICH) {
            return EINVAL;
        }

        return switch ((int) which) {
            case FREEBSD_CPU_WHICH_TID ->
                    id == -1 || isKnownGuestThreadId(id) ? 0 : ESRCH;
            case FREEBSD_CPU_WHICH_PID ->
                    id == -1 || id == process.id() || isKnownChildProcessId(id) ? 0 : ESRCH;
            case FREEBSD_CPU_WHICH_TIDPID ->
                    id == -1 || id == process.id() || isKnownGuestThreadId(id) || isKnownChildProcessId(id)
                            ? 0
                            : ESRCH;
            case FREEBSD_CPU_WHICH_CPUSET ->
                    id == -1 || processRegistry.isKnownFreeBsdCpuSetId(id) ? 0 : ESRCH;
            default -> EINVAL;
        };
    }

    /// Reports descriptor readiness through the FreeBSD `select` ABI.
    private long freeBsdSelect(
            RiscVThreadState state,
            long fileDescriptorLimit,
            long readFileDescriptorsAddress,
            long writeFileDescriptorsAddress,
            long exceptionFileDescriptorsAddress,
            long timeoutAddress) {
        if (fileDescriptorLimit < 0 || fileDescriptorLimit > DEFAULT_OPEN_FILE_LIMIT) {
            return EINVAL;
        }

        int descriptorLimit = (int) fileDescriptorLimit;
        long fileDescriptorSetSize = fdSetByteSize(descriptorLimit);
        if (!isBackedFdSet(readFileDescriptorsAddress, fileDescriptorSetSize)
                || !isBackedFdSet(writeFileDescriptorsAddress, fileDescriptorSetSize)
                || !isBackedFdSet(exceptionFileDescriptorsAddress, fileDescriptorSetSize)) {
            return EFAULT;
        }

        boolean immediateTimeout = false;
        long timeoutNanoseconds = -1;
        if (timeoutAddress != 0) {
            if (!memory.isBacked(timeoutAddress, TIMEVAL_SIZE)) {
                return EFAULT;
            }
            long seconds = memory.readLong(timeoutAddress + TIMEVAL_SECONDS_OFFSET);
            long microseconds = memory.readLong(timeoutAddress + TIMEVAL_MICROSECONDS_OFFSET);
            if (seconds < 0 || microseconds < 0 || microseconds >= 1_000_000L) {
                return EINVAL;
            }
            timeoutNanoseconds = timespecToSaturatedNanoseconds(seconds, microseconds * 1_000L);
            immediateTimeout = timeoutNanoseconds == 0;
        }

        return selectWithTimeout(
                state,
                descriptorLimit,
                fileDescriptorSetSize,
                readFileDescriptorsAddress,
                writeFileDescriptorsAddress,
                exceptionFileDescriptorsAddress,
                timeoutNanoseconds,
                immediateTimeout,
                0);
    }

    /// Reports descriptor readiness through the FreeBSD `pselect` ABI.
    private long freeBsdPselect(
            RiscVThreadState state,
            long fileDescriptorLimit,
            long readFileDescriptorsAddress,
            long writeFileDescriptorsAddress,
            long exceptionFileDescriptorsAddress,
            long timeoutAddress,
            long signalMaskAddress) {
        if (fileDescriptorLimit < 0 || fileDescriptorLimit > DEFAULT_OPEN_FILE_LIMIT) {
            return EINVAL;
        }

        int descriptorLimit = (int) fileDescriptorLimit;
        long fileDescriptorSetSize = fdSetByteSize(descriptorLimit);
        if (!isBackedFdSet(readFileDescriptorsAddress, fileDescriptorSetSize)
                || !isBackedFdSet(writeFileDescriptorsAddress, fileDescriptorSetSize)
                || !isBackedFdSet(exceptionFileDescriptorsAddress, fileDescriptorSetSize)) {
            return EFAULT;
        }

        boolean immediateTimeout = false;
        long timeoutNanoseconds = -1;
        if (timeoutAddress != 0) {
            if (!memory.isBacked(timeoutAddress, TIMESPEC_SIZE)) {
                return EFAULT;
            }
            long seconds = memory.readLong(timeoutAddress + TIMESPEC_SECONDS_OFFSET);
            long nanoseconds = memory.readLong(timeoutAddress + TIMESPEC_NANOSECONDS_OFFSET);
            if (seconds < 0 || nanoseconds < 0 || nanoseconds >= NANOSECONDS_PER_SECOND) {
                return EINVAL;
            }
            timeoutNanoseconds = timespecToSaturatedNanoseconds(seconds, nanoseconds);
            immediateTimeout = timeoutNanoseconds == 0;
        }
        if (signalMaskAddress != 0 && !memory.isBacked(signalMaskAddress, FREEBSD_SIGNAL_SET_SIZE)) {
            return EFAULT;
        }

        return selectWithTimeout(
                state,
                descriptorLimit,
                fileDescriptorSetSize,
                readFileDescriptorsAddress,
                writeFileDescriptorsAddress,
                exceptionFileDescriptorsAddress,
                timeoutNanoseconds,
                immediateTimeout,
                signalMaskAddress);
    }

    /// Reports descriptor readiness through the FreeBSD `ppoll` ABI and 16-byte signal-set layout.
    private long freeBsdPpoll(
            RiscVThreadState state,
            long fileDescriptorsAddress,
            long fileDescriptorCount,
            long timeoutAddress,
            long signalMaskAddress) {
        if (signalMaskAddress != 0 && !memory.isBacked(signalMaskAddress, FREEBSD_SIGNAL_SET_SIZE)) {
            return EFAULT;
        }
        return ppoll(
                state,
                fileDescriptorsAddress,
                fileDescriptorCount,
                timeoutAddress,
                signalMaskAddress,
                KERNEL_SIGSET_SIZE);
    }

    /// Writes a FreeBSD clock value after translating its native clock identifier.
    private long freeBsdClockGettime(long clockId, long timespecAddress) {
        if (!memory.isBacked(timespecAddress, TIMESPEC_SIZE)) {
            return EFAULT;
        }
        if (clockId == FREEBSD_CLOCK_SECOND) {
            memory.writeLong(timespecAddress + TIMESPEC_SECONDS_OFFSET, timeSource.realtimeInstant().getEpochSecond());
            memory.writeLong(timespecAddress + TIMESPEC_NANOSECONDS_OFFSET, 0);
            return 0;
        }

        long linuxClockId = freeBsdClockIdToLinux(clockId);
        return linuxClockId < 0 ? EINVAL : clockGettime(linuxClockId, timespecAddress);
    }

    /// Writes the simulated resolution of a FreeBSD clock identifier.
    private long freeBsdClockGetres(long clockId, long timespecAddress) {
        if (timespecAddress != 0 && !memory.isBacked(timespecAddress, TIMESPEC_SIZE)) {
            return EFAULT;
        }
        if (clockId == FREEBSD_CLOCK_SECOND) {
            if (timespecAddress != 0) {
                memory.writeLong(timespecAddress + TIMESPEC_SECONDS_OFFSET, 1);
                memory.writeLong(timespecAddress + TIMESPEC_NANOSECONDS_OFFSET, 0);
            }
            return 0;
        }

        long linuxClockId = freeBsdClockIdToLinux(clockId);
        return linuxClockId < 0 ? EINVAL : clockGetres(linuxClockId, timespecAddress);
    }

    /// Maps a supported FreeBSD clock identifier to the shared Linux-style clock model.
    private static long freeBsdClockIdToLinux(long clockId) {
        if (clockId == FREEBSD_CLOCK_REALTIME
                || clockId == FREEBSD_CLOCK_REALTIME_PRECISE
                || clockId == FREEBSD_CLOCK_REALTIME_FAST
                || clockId == FREEBSD_CLOCK_TAI) {
            return CLOCK_REALTIME;
        }
        if (clockId == FREEBSD_CLOCK_MONOTONIC
                || clockId == FREEBSD_CLOCK_UPTIME
                || clockId == FREEBSD_CLOCK_UPTIME_PRECISE
                || clockId == FREEBSD_CLOCK_UPTIME_FAST
                || clockId == FREEBSD_CLOCK_MONOTONIC_PRECISE
                || clockId == FREEBSD_CLOCK_MONOTONIC_FAST) {
            return CLOCK_MONOTONIC;
        }
        if (clockId == FREEBSD_CLOCK_VIRTUAL
                || clockId == FREEBSD_CLOCK_PROF
                || clockId == FREEBSD_CLOCK_PROCESS_CPUTIME_ID) {
            return CLOCK_PROCESS_CPUTIME_ID;
        }
        return clockId == FREEBSD_CLOCK_THREAD_CPUTIME_ID ? CLOCK_THREAD_CPUTIME_ID : -1;
    }

    /// Returns whether a FreeBSD clock is approximated by the simulator's wall-clock source.
    private static boolean isFreeBsdRealtimeClock(long clockId) {
        return clockId == FREEBSD_CLOCK_REALTIME
                || clockId == FREEBSD_CLOCK_REALTIME_PRECISE
                || clockId == FREEBSD_CLOCK_REALTIME_FAST
                || clockId == FREEBSD_CLOCK_SECOND
                || clockId == FREEBSD_CLOCK_TAI;
    }

    /// Validates FreeBSD timespec pointers and performs a relative `nanosleep`.
    private long freeBsdNanosleep(long requestAddress, long remainingAddress) {
        if (requestAddress == 0 || !memory.isBacked(requestAddress, TIMESPEC_SIZE)) {
            return EFAULT;
        }
        if (remainingAddress != 0 && !memory.isBacked(remainingAddress, TIMESPEC_SIZE)) {
            return EFAULT;
        }
        return nanosleep(requestAddress, remainingAddress);
    }

    /// Validates FreeBSD timespec pointers and performs a `clock_nanosleep` request.
    private long freeBsdClockNanosleep(
            long clockId,
            long flags,
            long requestAddress,
            long remainingAddress) {
        if (requestAddress == 0 || !memory.isBacked(requestAddress, TIMESPEC_SIZE)) {
            return EFAULT;
        }
        if (remainingAddress != 0 && !memory.isBacked(remainingAddress, TIMESPEC_SIZE)) {
            return EFAULT;
        }
        long linuxClockId = freeBsdClockIdToLinux(clockId);
        return linuxClockId < 0
                ? EINVAL
                : clockNanosleep(linuxClockId, flags, requestAddress, remainingAddress);
    }

    /// Reads and updates the calling guest thread's FreeBSD signal mask.
    private long freeBsdSigprocmask(RiscVThreadState state, long how, long setAddress, long oldSetAddress) {
        if (oldSetAddress != 0 && !memory.isBacked(oldSetAddress, FREEBSD_SIGNAL_SET_SIZE)) {
            return EFAULT;
        }
        if (setAddress != 0 && !memory.isBacked(setAddress, FREEBSD_SIGNAL_SET_SIZE)) {
            return EFAULT;
        }

        GuestThread thread = state.guestThread();
        long oldMask = thread.signalMask();
        if (oldSetAddress != 0) {
            memory.writeLong(oldSetAddress, oldMask);
            memory.writeLong(oldSetAddress + Long.BYTES, 0);
        }
        if (setAddress == 0) {
            return 0;
        }
        if (how != FREEBSD_SIG_BLOCK && how != FREEBSD_SIG_UNBLOCK && how != FREEBSD_SIG_SETMASK) {
            return EINVAL;
        }

        long requestedMask = memory.readLong(setAddress) & ~UNBLOCKABLE_SIGNAL_MASK;
        long updatedMask = oldMask;
        if (how == FREEBSD_SIG_BLOCK) {
            updatedMask |= requestedMask;
        } else if (how == FREEBSD_SIG_UNBLOCK) {
            updatedMask &= ~requestedMask;
        } else {
            updatedMask = requestedMask;
        }
        thread.setSignalMask(updatedMask);
        return 0;
    }

    /// Accepts FreeBSD signal action setup for a guest that never receives host signals.
    private long freeBsdSigaction(long signalNumber, long actionAddress, long oldActionAddress) {
        if (signalNumber < MIN_SIGNAL_NUMBER || signalNumber > MAX_SIGNAL_NUMBER) {
            return EINVAL;
        }
        if (oldActionAddress != 0) {
            memory.clear(oldActionAddress, FREEBSD_SIGACTION_SIZE);
        }
        return 0;
    }

    /// Writes the current FreeBSD thread id to the guest pointer.
    private long freeBsdThrSelf(RiscVThreadState state, long threadIdAddress) {
        if (threadIdAddress == 0 || !memory.isBacked(threadIdAddress, Long.BYTES)) {
            return EFAULT;
        }
        memory.writeLong(threadIdAddress, state.threadId());
        return 0;
    }

    /// Exits the current FreeBSD guest thread.
    private void freeBsdThrExit(RiscVThreadState state, long threadIdAddress) {
        if (threadIdAddress != 0 && memory.isBacked(threadIdAddress, Long.BYTES)) {
            synchronized (threadLock) {
                memory.writeLong(threadIdAddress, 0);
                futexWakeLocked(threadIdAddress, 1, FUTEX_BITSET_MATCH_ANY);
            }
        }
        exitThread(state, 0);
    }

    /// Accepts FreeBSD thread-directed signal requests for live guest threads.
    private long freeBsdThrKill(long threadId, long signalNumber) {
        if (threadId == -1) {
            if (!isValidSignalNumber(signalNumber)) {
                return EINVAL;
            }
            return process.threadCount() > 1 ? 0 : ESRCH;
        }
        if (!isKnownGuestThreadId(threadId)) {
            return ESRCH;
        }
        if (!isValidSignalNumber(signalNumber)) {
            return EINVAL;
        }
        return 0;
    }

    /// Suspends the current FreeBSD guest thread until a wake request, timeout, or process interruption.
    private long freeBsdThrSuspend(RiscVThreadState state, long timeoutAddress) {
        long timeoutNanoseconds = -1;
        if (timeoutAddress != 0) {
            if (!memory.isBacked(timeoutAddress, TIMESPEC_SIZE)) {
                return EFAULT;
            }

            long seconds = memory.readLong(timeoutAddress + TIMESPEC_SECONDS_OFFSET);
            long nanoseconds = memory.readLong(timeoutAddress + TIMESPEC_NANOSECONDS_OFFSET);
            if (!isValidTimespec(seconds, nanoseconds)) {
                return EINVAL;
            }
            timeoutNanoseconds = timespecToSaturatedNanoseconds(seconds, nanoseconds);
        }

        GuestThread currentThread = state.guestThread();
        synchronized (threadLock) {
            if (currentThread.consumeFreeBsdSuspendWake()) {
                return 0;
            }
            if (timeoutNanoseconds == 0) {
                return ETIMEDOUT;
            }

            long remainingNanoseconds = timeoutNanoseconds;
            long lastNanoseconds = timeoutNanoseconds >= 0 ? timeSource.monotonicNanoseconds() : 0;
            try {
                while (!processExitRequested && threadFailure == null) {
                    if (currentThread.consumeFreeBsdSuspendWake()) {
                        return 0;
                    }
                    if (remainingNanoseconds == 0) {
                        return ETIMEDOUT;
                    }

                    if (remainingNanoseconds > 0) {
                        waitNanos(remainingNanoseconds);
                        long nowNanoseconds = timeSource.monotonicNanoseconds();
                        long elapsedNanoseconds = Math.max(0, nowNanoseconds - lastNanoseconds);
                        remainingNanoseconds = elapsedNanoseconds >= remainingNanoseconds
                                ? 0
                                : remainingNanoseconds - elapsedNanoseconds;
                        lastNanoseconds = nowNanoseconds;
                    } else {
                        threadLock.wait();
                    }
                }

                return currentThread.consumeFreeBsdSuspendWake() ? 0 : EINTR;
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                return EINTR;
            }
        }
    }

    /// Records one pending wake request for a live thread in the current FreeBSD process.
    private long freeBsdThrWake(long threadId) {
        synchronized (threadLock) {
            @Nullable GuestThread targetThread = process.thread(threadId);
            if (targetThread == null) {
                return ESRCH;
            }
            targetThread.requestFreeBsdSuspendWake();
            threadLock.notifyAll();
            return 0;
        }
    }

    /// Accepts a FreeBSD thread-directed signal request scoped to a selected process.
    private long freeBsdThrKill2(long processId, long threadId, long signalNumber) {
        int targetProcessId = (int) processId;
        boolean currentProcess = targetProcessId == process.id();
        boolean childProcess = isKnownChildProcessId(targetProcessId);
        if (!currentProcess && !childProcess) {
            return ESRCH;
        }

        if (threadId == -1) {
            if (!isValidSignalNumber(signalNumber)) {
                return EINVAL;
            }
            if (currentProcess) {
                return process.threadCount() > 1 ? 0 : ESRCH;
            }
            return 0;
        }

        boolean knownThread = currentProcess
                ? isKnownGuestThreadId(threadId)
                : threadId == targetProcessId;
        if (!knownThread) {
            return ESRCH;
        }
        return isValidSignalNumber(signalNumber) ? 0 : EINVAL;
    }

    /// Sets a FreeBSD thread name after applying `MAXCOMLEN` byte truncation.
    private long freeBsdThrSetName(long threadId, long nameAddress) {
        @Nullable String name = nameAddress == 0 ? "" : readFreeBsdThreadName(nameAddress);
        if (name == null) {
            return EFAULT;
        }

        @Nullable GuestThread target = process.thread(threadId);
        if (target == null) {
            return ESRCH;
        }
        target.setName(name);
        return 0;
    }

    /// Reads a FreeBSD thread name, returning null when any required guest byte is inaccessible.
    private @Nullable String readFreeBsdThreadName(long address) {
        byte[] name = new byte[FREEBSD_MAXCOMLEN];
        for (int index = 0; index <= FREEBSD_MAXCOMLEN; index++) {
            long byteAddress = address + index;
            if (byteAddress < address || !memory.isBacked(byteAddress, 1)) {
                return null;
            }
            int value = memory.readUnsignedByte(byteAddress);
            if (value == 0) {
                return new String(name, 0, Math.min(index, name.length), StandardCharsets.UTF_8);
            }
            if (index < name.length) {
                name[index] = (byte) value;
            }
        }
        return new String(name, StandardCharsets.UTF_8);
    }

    /// Handles FreeBSD `_umtx_op` wait and wake operations needed by Go runtime locks.
    private long freeBsdUmtxOp(long address, long operation, long value, long value2, long timeoutAddress) {
        return switch ((int) operation) {
            case (int) FREEBSD_UMTX_OP_WAIT_UINT, (int) FREEBSD_UMTX_OP_WAIT_UINT_PRIVATE ->
                    freeBsdUmtxWait(address, value, value2, timeoutAddress);
            case (int) FREEBSD_UMTX_OP_WAKE, (int) FREEBSD_UMTX_OP_WAKE_PRIVATE ->
                    futexWake(address, value, FUTEX_BITSET_MATCH_ANY);
            default -> ENOSYS;
        };
    }

    /// Waits on a FreeBSD unsigned umtx word using either the legacy or extended timeout structure.
    private long freeBsdUmtxWait(long address, long value, long timeoutSize, long timeoutAddress) {
        long timeoutNanoseconds = -1;
        if (timeoutAddress != 0) {
            boolean extendedTimeout = Long.compareUnsigned(timeoutSize, TIMESPEC_SIZE) > 0;
            long copiedSize = extendedTimeout ? FREEBSD_UMTX_TIME_SIZE : TIMESPEC_SIZE;
            if (!memory.isBacked(timeoutAddress, copiedSize)) {
                return EFAULT;
            }

            long seconds = memory.readLong(timeoutAddress + TIMESPEC_SECONDS_OFFSET);
            long nanoseconds = memory.readLong(timeoutAddress + TIMESPEC_NANOSECONDS_OFFSET);
            if (!isValidTimespec(seconds, nanoseconds)) {
                return EINVAL;
            }

            long flags = extendedTimeout
                    ? memory.readUnsignedInt(timeoutAddress + FREEBSD_UMTX_TIME_FLAGS_OFFSET)
                    : 0;
            long clockId = extendedTimeout
                    ? memory.readUnsignedInt(timeoutAddress + FREEBSD_UMTX_TIME_CLOCK_ID_OFFSET)
                    : FREEBSD_CLOCK_REALTIME;
            if (clockId != FREEBSD_CLOCK_SECOND && freeBsdClockIdToLinux(clockId) < 0) {
                return EINVAL;
            }
            timeoutNanoseconds = freeBsdUmtxTimeoutNanoseconds(seconds, nanoseconds, flags, clockId);
        }

        long result = futexWaitWithTimeoutNanos(
                address,
                value,
                FUTEX_BITSET_MATCH_ANY,
                timeoutNanoseconds);
        return result == EAGAIN ? 0 : result;
    }

    /// Converts a validated FreeBSD umtx timeout to a relative nanosecond count.
    private long freeBsdUmtxTimeoutNanoseconds(long seconds, long nanoseconds, long flags, long clockId) {
        if ((flags & FREEBSD_UMTX_ABSTIME) == 0) {
            return timespecToSaturatedNanoseconds(seconds, nanoseconds);
        }

        if (isFreeBsdRealtimeClock(clockId)) {
            Instant current = timeSource.realtimeInstant();
            int currentNanoseconds = clockId == FREEBSD_CLOCK_SECOND ? 0 : current.getNano();
            return relativeNanosecondsUntil(
                    seconds,
                    nanoseconds,
                    current.getEpochSecond(),
                    currentNanoseconds);
        }

        Duration current = elapsedDuration();
        return relativeNanosecondsUntil(seconds, nanoseconds, current.getSeconds(), current.getNano());
    }

    /// Converts Linux errno values returned by shared syscall helpers to FreeBSD errno values when they differ.
    private static long freeBsdErrno(long result) {
        if (result == FREEBSD_EDEADLK_RESULT) {
            return -11;
        }
        if (result >= 0) {
            return result;
        }
        return switch ((int) result) {
            case (int) EAGAIN -> -35;
            case (int) EINPROGRESS -> -36;
            case (int) EALREADY -> -37;
            case (int) ENOTSOCK -> -38;
            case (int) EDESTADDRREQ -> -39;
            case (int) EMSGSIZE -> -40;
            case (int) ENOPROTOOPT -> -42;
            case (int) EPROTONOSUPPORT -> -43;
            case (int) ENOTSUP -> -45;
            case (int) EAFNOSUPPORT -> -47;
            case (int) EADDRINUSE -> -48;
            case (int) EADDRNOTAVAIL -> -49;
            case (int) ENETUNREACH -> -51;
            case (int) ECONNRESET -> -54;
            case (int) EISCONN -> -56;
            case (int) ENOTCONN -> -57;
            case (int) ETIMEDOUT -> -60;
            case (int) ECONNREFUSED -> -61;
            case (int) ELOOP -> -62;
            case (int) ENAMETOOLONG -> -63;
            case (int) ENOTEMPTY -> -66;
            case (int) ENOSYS -> -78;
            case (int) EOVERFLOW -> -84;
            case (int) ENODATA -> -87;
            default -> result;
        };
    }

    /// Converts a raw shared errno to the positive-error convention used by FreeBSD POSIX syscalls.
    private static long freeBsdPosixError(long result) {
        return result < 0 ? -freeBsdErrno(result) : result;
    }

    /// Creates an in-memory FreeBSD kernel event queue descriptor.
    private long freeBsdKqueue() {
        return freeBsdKqueuex(0);
    }

    /// Creates an in-memory FreeBSD kernel event queue with supported `kqueuex` descriptor flags.
    private long freeBsdKqueuex(long flags) {
        if ((flags & ~FREEBSD_KQUEUE_CLOEXEC) != 0) {
            return EINVAL;
        }
        return addOpenFile(
                OpenFile.socket(new FreeBsdKqueue(), false),
                (flags & FREEBSD_KQUEUE_CLOEXEC) != 0);
    }

    /// Reports the safely modeled FreeBSD memory-barrier command set while ignoring `cpu_id` as required by the ABI.
    private static long freeBsdMembarrier(long command, long flags) {
        if (flags != 0) {
            return EINVAL;
        }
        return command == FREEBSD_MEMBARRIER_CMD_QUERY ? 0 : EINVAL;
    }

    /// Accepts a FreeBSD page-lock request after applying its privilege check.
    private long freeBsdMlock(long address, long length) {
        if (credentials.effectiveUserId() != 0) {
            return EPERM;
        }
        return mlock(address, length);
    }

    /// Accepts a FreeBSD page-unlock request after applying its privilege check.
    private long freeBsdMunlock(long address, long length) {
        if (credentials.effectiveUserId() != 0) {
            return EPERM;
        }
        return munlock(address, length);
    }

    /// Accepts a privileged FreeBSD process-wide memory-lock request as a deterministic no-op.
    private long freeBsdMlockall(long flags) {
        if (credentials.effectiveUserId() != 0) {
            return EPERM;
        }

        int lockFlags = (int) flags;
        if (lockFlags == 0 || (lockFlags & ~(FREEBSD_MCL_CURRENT | FREEBSD_MCL_FUTURE)) != 0) {
            return EINVAL;
        }
        return 0;
    }

    /// Accepts a privileged FreeBSD process-wide memory-unlock request as a deterministic no-op.
    private long freeBsdMunlockall() {
        return credentials.effectiveUserId() == 0 ? 0 : EPERM;
    }

    /// Updates the current FreeBSD scheduler priority while preserving its active policy.
    private long freeBsdSchedSetparam(long processId, long parameterAddress) {
        if (!memory.isBacked(parameterAddress, Integer.BYTES)) {
            return EFAULT;
        }
        if (!isKnownSchedulerTarget(processId)) {
            return ESRCH;
        }

        int freeBsdPolicy = internalSchedulerPolicyToFreeBsd(schedulerPolicy);
        int priority = memory.readInt(parameterAddress + SCHED_PARAM_PRIORITY_OFFSET);
        if (freeBsdPolicy < 0 || !isValidFreeBsdSchedulerPriority(freeBsdPolicy, priority)) {
            return EINVAL;
        }

        schedulerPriority = priority;
        return 0;
    }

    /// Writes the current FreeBSD scheduler priority for the selected guest target.
    private long freeBsdSchedGetparam(long processId, long parameterAddress) {
        if (!isKnownSchedulerTarget(processId)) {
            return ESRCH;
        }
        if (!memory.isBacked(parameterAddress, Integer.BYTES)) {
            return EFAULT;
        }

        memory.writeInt(parameterAddress + SCHED_PARAM_PRIORITY_OFFSET, schedulerPriority);
        return 0;
    }

    /// Applies a privileged FreeBSD scheduler policy and priority change.
    private long freeBsdSchedSetscheduler(long processId, long policy, long parameterAddress) {
        if (!memory.isBacked(parameterAddress, Integer.BYTES)) {
            return EFAULT;
        }
        if (!isKnownSchedulerTarget(processId)) {
            return ESRCH;
        }
        if (credentials.effectiveUserId() != 0) {
            return EPERM;
        }

        int freeBsdPolicy = (int) policy;
        int internalPolicy = freeBsdSchedulerPolicyToInternal(freeBsdPolicy);
        int priority = memory.readInt(parameterAddress + SCHED_PARAM_PRIORITY_OFFSET);
        if (internalPolicy < 0 || !isValidFreeBsdSchedulerPriority(freeBsdPolicy, priority)) {
            return EINVAL;
        }

        schedulerPolicy = internalPolicy;
        schedulerPriority = priority;
        return 0;
    }

    /// Returns the current FreeBSD scheduler policy for the selected guest target.
    private long freeBsdSchedGetscheduler(long processId) {
        if (!isKnownSchedulerTarget(processId)) {
            return ESRCH;
        }

        int policy = internalSchedulerPolicyToFreeBsd(schedulerPolicy);
        return policy >= 0 ? policy : EINVAL;
    }

    /// Returns the maximum priority accepted for a FreeBSD scheduler policy.
    private static long freeBsdSchedGetPriorityMax(long policy) {
        return switch ((int) policy) {
            case FREEBSD_SCHED_FIFO, FREEBSD_SCHED_RR -> FREEBSD_SCHED_REALTIME_PRIORITY_MAXIMUM;
            case FREEBSD_SCHED_OTHER -> FREEBSD_SCHED_OTHER_PRIORITY_MAXIMUM;
            default -> EINVAL;
        };
    }

    /// Returns the minimum priority accepted for a FreeBSD scheduler policy.
    private static long freeBsdSchedGetPriorityMin(long policy) {
        return switch ((int) policy) {
            case FREEBSD_SCHED_FIFO, FREEBSD_SCHED_RR -> FREEBSD_SCHED_REALTIME_PRIORITY_MINIMUM;
            case FREEBSD_SCHED_OTHER -> FREEBSD_SCHED_OTHER_PRIORITY_MINIMUM;
            default -> EINVAL;
        };
    }

    /// Writes the deterministic round-robin interval for a selected FreeBSD guest target.
    private long freeBsdSchedRrGetInterval(long processId, long intervalAddress) {
        if (!isKnownSchedulerTarget(processId)) {
            return ESRCH;
        }
        if (!memory.isBacked(intervalAddress, TIMESPEC_SIZE)) {
            return EFAULT;
        }

        writeTimespecFromNanoseconds(intervalAddress, SCHED_RR_INTERVAL_NANOSECONDS);
        return 0;
    }

    /// Translates a FreeBSD scheduler policy to the shared internal Linux policy numbering.
    private static int freeBsdSchedulerPolicyToInternal(int policy) {
        return switch (policy) {
            case FREEBSD_SCHED_FIFO -> SCHED_FIFO;
            case FREEBSD_SCHED_OTHER -> SCHED_OTHER;
            case FREEBSD_SCHED_RR -> SCHED_RR;
            default -> -1;
        };
    }

    /// Translates a shared internal Linux scheduler policy to FreeBSD numbering.
    private static int internalSchedulerPolicyToFreeBsd(int policy) {
        return switch (policy) {
            case SCHED_FIFO -> FREEBSD_SCHED_FIFO;
            case SCHED_OTHER -> FREEBSD_SCHED_OTHER;
            case SCHED_RR -> FREEBSD_SCHED_RR;
            default -> -1;
        };
    }

    /// Returns whether a priority belongs to the supplied FreeBSD scheduler policy range.
    private static boolean isValidFreeBsdSchedulerPriority(int policy, int priority) {
        return switch (policy) {
            case FREEBSD_SCHED_FIFO, FREEBSD_SCHED_RR ->
                    priority >= FREEBSD_SCHED_REALTIME_PRIORITY_MINIMUM
                            && priority <= FREEBSD_SCHED_REALTIME_PRIORITY_MAXIMUM;
            case FREEBSD_SCHED_OTHER -> priority >= FREEBSD_SCHED_OTHER_PRIORITY_MINIMUM
                    && priority <= FREEBSD_SCHED_OTHER_PRIORITY_MAXIMUM;
            default -> false;
        };
    }

    /// Applies FreeBSD event changes and reports ready events using the selected native structure size.
    private long freeBsdKevent(
            int kqueueFileDescriptor,
            long changeListAddress,
            long changeCount,
            long eventListAddress,
            long eventCount,
            long timeoutAddress,
            long eventSize) {
        if (changeCount < 0
                || changeCount > FREEBSD_KEVENT_MAX_COUNT
                || eventCount < 0
                || eventCount > FREEBSD_KEVENT_MAX_COUNT) {
            return EINVAL;
        }
        long changeListSize = changeCount * eventSize;
        long eventListSize = eventCount * eventSize;
        if ((changeCount != 0 && !memory.isBacked(changeListAddress, changeListSize))
                || (eventCount != 0 && !memory.isBacked(eventListAddress, eventListSize))) {
            return EFAULT;
        }

        long timeoutNanoseconds = -1;
        boolean immediateTimeout = false;
        if (timeoutAddress != 0) {
            if (!memory.isBacked(timeoutAddress, 2L * Long.BYTES)) {
                return EFAULT;
            }
            long seconds = memory.readLong(timeoutAddress);
            long nanoseconds = memory.readLong(timeoutAddress + Long.BYTES);
            if (!isValidTimespec(seconds, nanoseconds)) {
                return EINVAL;
            }
            timeoutNanoseconds = timespecToSaturatedNanoseconds(seconds, nanoseconds);
            immediateTimeout = timeoutNanoseconds == 0;
        }

        @Nullable FreeBsdKqueue kqueue = freeBsdKqueueFor(kqueueFileDescriptor);
        if (kqueue == null) {
            return EBADF;
        }
        for (long index = 0; index < changeCount; index++) {
            long result = kqueue.applyChange(changeListAddress + index * eventSize);
            if (result != 0) {
                return result;
            }
        }
        if (eventCount == 0) {
            return 0;
        }

        long deadlineNanoseconds = pollDeadlineNanoseconds(timeoutNanoseconds);
        while (true) {
            long observedPollGeneration = pollGeneration;
            int count = kqueue.reportEvents(eventListAddress, (int) eventCount, eventSize);
            if (count != 0 || immediateTimeout) {
                return count;
            }
            long remainingNanoseconds = remainingPollNanoseconds(deadlineNanoseconds);
            if (remainingNanoseconds == 0) {
                return 0;
            }
            long waitResult = waitForPollChange(observedPollGeneration, remainingNanoseconds);
            if (waitResult != 0) {
                return waitResult;
            }
        }
    }

    /// Returns the in-memory event queue stored in a descriptor, or null for invalid and non-kqueue descriptors.
    private @Nullable FreeBsdKqueue freeBsdKqueueFor(int fileDescriptor) {
        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null || !openFile.isSocket()) {
            return null;
        }
        return openFile.socket() instanceof FreeBsdKqueue kqueue ? kqueue : null;
    }

    /// Writes one ready FreeBSD event with the ABI-selected structure size.
    private void writeFreeBsdKevent(
            long address,
            long eventSize,
            FreeBsdKqueueInterest interest,
            int resultFlags) {
        memory.clear(address, eventSize);
        memory.writeLong(address + FREEBSD_KEVENT_IDENT_OFFSET, interest.ident());
        memory.writeShort(address + FREEBSD_KEVENT_FILTER_OFFSET, interest.filter());
        memory.writeShort(address + FREEBSD_KEVENT_FLAGS_OFFSET, (short) resultFlags);
        memory.writeInt(address + FREEBSD_KEVENT_FILTER_FLAGS_OFFSET, 0);
        memory.writeLong(address + FREEBSD_KEVENT_DATA_OFFSET, 0);
        memory.writeLong(address + FREEBSD_KEVENT_USER_DATA_OFFSET, interest.userData());
    }

    /// Stores one FreeBSD kqueue registration and its edge-trigger state.
    @NotNullByDefault
    private final class FreeBsdKqueueInterest {
        /// The descriptor or user identifier selected by the registration.
        private final long ident;

        /// The FreeBSD event filter.
        private final short filter;

        /// Opaque guest data copied to reported events.
        private long userData;

        /// Whether the registration uses clear-after-delivery edge semantics.
        private boolean clear;

        /// Whether event delivery is enabled.
        private boolean enabled;

        /// Whether a user event has been triggered but not cleared.
        private boolean triggered;

        /// Whether a clear-mode descriptor event was ready during the previous scan.
        private boolean previouslyReady;

        /// Creates one event registration.
        private FreeBsdKqueueInterest(long ident, short filter) {
            this.ident = ident;
            this.filter = filter;
        }

        /// Returns the registered descriptor or user identifier.
        private long ident() {
            return ident;
        }

        /// Returns the registered FreeBSD event filter.
        private short filter() {
            return filter;
        }

        /// Returns the opaque guest data associated with the registration.
        private long userData() {
            return userData;
        }
    }

    /// Stores registrations and readiness state for one in-memory FreeBSD kqueue descriptor.
    @NotNullByDefault
    private final class FreeBsdKqueue implements org.glavo.riscv.runtime.net.GuestSocket {
        /// Ordered event registrations in this queue.
        private final ArrayList<FreeBsdKqueueInterest> interests = new ArrayList<>();

        /// Applies one native `struct kevent` change.
        private synchronized long applyChange(long changeAddress) {
            long ident = memory.readLong(changeAddress + FREEBSD_KEVENT_IDENT_OFFSET);
            short filter = memory.readShort(changeAddress + FREEBSD_KEVENT_FILTER_OFFSET);
            int flags = memory.readUnsignedShort(changeAddress + FREEBSD_KEVENT_FLAGS_OFFSET);
            long filterFlags = memory.readUnsignedInt(changeAddress + FREEBSD_KEVENT_FILTER_FLAGS_OFFSET);
            long userData = memory.readLong(changeAddress + FREEBSD_KEVENT_USER_DATA_OFFSET);
            if ((flags & ~FREEBSD_SUPPORTED_KEVENT_CHANGE_FLAGS) != 0
                    || (flags & FREEBSD_EV_ADD) != 0 && (flags & FREEBSD_EV_DELETE) != 0
                    || (flags & FREEBSD_EV_ENABLE) != 0 && (flags & FREEBSD_EV_DISABLE) != 0) {
                return EINVAL;
            }
            if (filter != FREEBSD_EVFILT_READ
                    && filter != FREEBSD_EVFILT_WRITE
                    && filter != FREEBSD_EVFILT_USER) {
                return EINVAL;
            }
            if (filter != FREEBSD_EVFILT_USER && filterFlags != 0) {
                return EINVAL;
            }
            if (filter == FREEBSD_EVFILT_USER && (filterFlags & ~FREEBSD_NOTE_TRIGGER) != 0) {
                return EINVAL;
            }
            if (filter != FREEBSD_EVFILT_USER
                    && (ident < 0 || ident > Integer.MAX_VALUE || !isOpenFileDescriptor((int) ident))) {
                return EBADF;
            }

            int index = findIndex(ident, filter);
            if ((flags & FREEBSD_EV_DELETE) != 0) {
                if (index < 0) {
                    return ENOENT;
                }
                interests.remove(index);
                notifyPollWaiters();
                return 0;
            }

            FreeBsdKqueueInterest interest;
            if ((flags & FREEBSD_EV_ADD) != 0) {
                if (index < 0) {
                    interest = new FreeBsdKqueueInterest(ident, filter);
                    interests.add(interest);
                } else {
                    interest = interests.get(index);
                }
                interest.userData = userData;
                interest.clear = (flags & FREEBSD_EV_CLEAR) != 0;
                interest.enabled = (flags & FREEBSD_EV_DISABLE) == 0;
                interest.previouslyReady = false;
            } else {
                if (index < 0) {
                    return ENOENT;
                }
                interest = interests.get(index);
                if ((flags & FREEBSD_EV_ENABLE) != 0) {
                    interest.enabled = true;
                    interest.previouslyReady = false;
                }
                if ((flags & FREEBSD_EV_DISABLE) != 0) {
                    interest.enabled = false;
                }
            }
            if (filter == FREEBSD_EVFILT_USER && (filterFlags & FREEBSD_NOTE_TRIGGER) != 0) {
                interest.triggered = true;
            }
            notifyPollWaiters();
            return 0;
        }

        /// Reports currently ready registrations using FreeBSD edge-trigger behavior.
        private synchronized int reportEvents(long eventListAddress, int maximumEvents, long eventSize) {
            HashMap<Integer, Integer> readyEventsByDescriptor = new HashMap<>();
            int count = 0;
            for (int index = 0; index < interests.size() && count < maximumEvents; ) {
                FreeBsdKqueueInterest interest = interests.get(index);
                if (interest.filter != FREEBSD_EVFILT_USER
                        && !isOpenFileDescriptor((int) interest.ident)) {
                    interests.remove(index);
                    continue;
                }
                index++;
                if (!interest.enabled) {
                    continue;
                }

                boolean ready;
                boolean endOfFile = false;
                int events = 0;
                if (interest.filter == FREEBSD_EVFILT_USER) {
                    ready = interest.triggered;
                } else {
                    int fileDescriptor = (int) interest.ident;
                    // A host selector probe may consume a connection-completion notification. Reuse its result
                    // for every filter on the same descriptor during this native kqueue scan.
                    events = readyEventsByDescriptor.computeIfAbsent(
                            fileDescriptor,
                            ignored -> readyEventsFor(fileDescriptor));
                    int requestedEvent = interest.filter == FREEBSD_EVFILT_READ ? EPOLLIN : EPOLLOUT;
                    ready = (events & (requestedEvent | EPOLLERR | EPOLLHUP)) != 0;
                    endOfFile = (events & EPOLLHUP) != 0;
                }
                if (!ready) {
                    interest.previouslyReady = false;
                    continue;
                }
                if (interest.clear && interest.previouslyReady) {
                    continue;
                }

                int resultFlags = interest.clear ? FREEBSD_EV_CLEAR : 0;
                if (endOfFile) {
                    resultFlags |= FREEBSD_EV_EOF;
                }
                writeFreeBsdKevent(
                        eventListAddress + (long) count * eventSize,
                        eventSize,
                        interest,
                        resultFlags);
                count++;
                if (interest.filter == FREEBSD_EVFILT_USER && interest.clear) {
                    interest.triggered = false;
                }
                interest.previouslyReady = interest.clear;
            }
            return count;
        }

        /// Returns the index of a registration key, or `-1` when absent.
        private int findIndex(long ident, short filter) {
            for (int index = 0; index < interests.size(); index++) {
                FreeBsdKqueueInterest interest = interests.get(index);
                if (interest.ident == ident && interest.filter == filter) {
                    return index;
                }
            }
            return -1;
        }

        /// Clears registrations and wakes any thread blocked in `kevent`.
        @Override
        public synchronized void close() {
            interests.clear();
            notifyPollWaiters();
        }
    }

    /// Creates an Internet or Unix-domain socket after translating FreeBSD creation flags and address families.
    private long freeBsdSocket(long domain, long type, long protocol) {
        long linuxDomain = freeBsdSocketDomainToLinux(domain);
        if (linuxDomain < 0) {
            return EAFNOSUPPORT;
        }
        long linuxType = freeBsdSocketTypeToLinux(type);
        return linuxType < 0 ? EINVAL : super.socket(linuxDomain, linuxType, protocol);
    }

    /// Creates a connected Unix-domain socket pair after translating FreeBSD creation flags.
    private long freeBsdSocketpair(long domain, long type, long protocol, long pairAddress) {
        long linuxDomain = freeBsdSocketDomainToLinux(domain);
        if (linuxDomain < 0) {
            return EAFNOSUPPORT;
        }
        long linuxType = freeBsdSocketTypeToLinux(type);
        return linuxType < 0 ? EINVAL : super.socketpair(linuxDomain, linuxType, protocol, pairAddress);
    }

    /// Accepts a connection after translating FreeBSD `accept4` descriptor flags.
    private long freeBsdAccept(int fileDescriptor, long address, long lengthAddress, long flags) {
        if ((flags & ~FREEBSD_SUPPORTED_SOCKET_TYPE_FLAGS) != 0) {
            return EINVAL;
        }
        long linuxFlags = 0;
        if ((flags & FREEBSD_SOCK_NONBLOCK) != 0) {
            linuxFlags |= O_NONBLOCK;
        }
        if ((flags & FREEBSD_SOCK_CLOEXEC) != 0) {
            linuxFlags |= O_CLOEXEC;
        }
        return super.accept(fileDescriptor, address, lengthAddress, linuxFlags);
    }

    /// Sends bytes after translating FreeBSD message flags.
    private long freeBsdSendto(
            int fileDescriptor,
            long bufferAddress,
            long length,
            long flags,
            long destinationAddress,
            long destinationLength) {
        long linuxFlags = freeBsdSocketMessageFlagsToLinux(flags);
        if (linuxFlags < 0) {
            return EINVAL;
        }
        return super.sendto(
                fileDescriptor,
                bufferAddress,
                length,
                linuxFlags,
                destinationAddress,
                destinationLength);
    }

    /// Receives bytes after translating FreeBSD message flags.
    private long freeBsdRecvfrom(
            int fileDescriptor,
            long bufferAddress,
            long length,
            long flags,
            long sourceAddress,
            long sourceLengthAddress) {
        long linuxFlags = freeBsdSocketMessageFlagsToLinux(flags);
        if (linuxFlags < 0) {
            return EINVAL;
        }
        return super.recvfrom(
                fileDescriptor,
                bufferAddress,
                length,
                linuxFlags,
                sourceAddress,
                sourceLengthAddress);
    }

    /// Sends a FreeBSD socket message after translating message flags and using the native header layout.
    private long freeBsdSendmsg(int fileDescriptor, long messageAddress, long flags) {
        long linuxFlags = freeBsdSocketMessageFlagsToLinux(flags);
        return linuxFlags < 0 ? EINVAL : super.sendmsg(fileDescriptor, messageAddress, linuxFlags);
    }

    /// Receives a FreeBSD socket message after translating message flags and using the native header layout.
    private long freeBsdRecvmsg(int fileDescriptor, long messageAddress, long flags) {
        long linuxFlags = freeBsdSocketMessageFlagsToLinux(flags);
        return linuxFlags < 0 ? EINVAL : super.recvmsg(fileDescriptor, messageAddress, linuxFlags);
    }

    /// Returns the native FreeBSD `msg_flags` field offset.
    @Override
    protected long socketMessageFlagsOffset() {
        return FREEBSD_MSGHDR_FLAGS_OFFSET;
    }

    /// Reads the signed 32-bit FreeBSD `msg_iovlen` field.
    @Override
    protected long socketMessageIovecCount(long messageAddress) {
        return memory.readInt(messageAddress + FREEBSD_MSGHDR_IOV_LENGTH_OFFSET);
    }

    /// Sets one supported socket option after mapping FreeBSD option numbers to the normalized backend model.
    private long freeBsdSetsockopt(
            int fileDescriptor,
            long level,
            long option,
            long valueAddress,
            long valueLength) {
        @Nullable SocketOptionMapping mapping = freeBsdSocketOptionMapping(level, option);
        return mapping == null
                ? ENOPROTOOPT
                : super.setsockopt(
                        fileDescriptor,
                        mapping.level(),
                        mapping.option(),
                        valueAddress,
                        valueLength);
    }

    /// Gets one supported socket option and converts a pending `SO_ERROR` value to FreeBSD errno numbering.
    private long freeBsdGetsockopt(
            int fileDescriptor,
            long level,
            long option,
            long valueAddress,
            long lengthAddress) {
        @Nullable SocketOptionMapping mapping = freeBsdSocketOptionMapping(level, option);
        if (mapping == null) {
            return ENOPROTOOPT;
        }
        long result = super.getsockopt(
                fileDescriptor,
                mapping.level(),
                mapping.option(),
                valueAddress,
                lengthAddress);
        if (result == 0
                && mapping.level() == SOL_SOCKET
                && mapping.option() == SO_ERROR
                && memory.isBacked(valueAddress, Integer.BYTES)) {
            int linuxErrno = memory.readInt(valueAddress);
            if (linuxErrno > 0) {
                memory.writeInt(valueAddress, (int) -freeBsdErrno(-linuxErrno));
            }
        }
        return result;
    }

    /// Converts one FreeBSD socket address family to the normalized Linux-numbered backend family.
    private static long freeBsdSocketDomainToLinux(long domain) {
        return switch ((int) domain) {
            case (int) FREEBSD_AF_UNIX -> AF_UNIX;
            case (int) FREEBSD_AF_INET -> AF_INET;
            case (int) FREEBSD_AF_INET6 -> AF_INET6;
            default -> -1;
        };
    }

    /// Converts one FreeBSD socket type and creation flags to normalized Linux-numbered values.
    private static long freeBsdSocketTypeToLinux(long type) {
        long typeFlags = type & ~FREEBSD_SOCK_TYPE_MASK;
        if ((typeFlags & ~FREEBSD_SUPPORTED_SOCKET_TYPE_FLAGS) != 0) {
            return -1;
        }
        long linuxType = type & FREEBSD_SOCK_TYPE_MASK;
        if ((typeFlags & FREEBSD_SOCK_NONBLOCK) != 0) {
            linuxType |= O_NONBLOCK;
        }
        if ((typeFlags & FREEBSD_SOCK_CLOEXEC) != 0) {
            linuxType |= O_CLOEXEC;
        }
        return linuxType;
    }

    /// Converts supported FreeBSD message flags to normalized Linux-numbered values.
    private static long freeBsdSocketMessageFlagsToLinux(long flags) {
        if ((flags & ~FREEBSD_SUPPORTED_SOCKET_MESSAGE_FLAGS) != 0) {
            return -1;
        }
        long linuxFlags = 0;
        if ((flags & FREEBSD_MSG_DONTWAIT) != 0) {
            linuxFlags |= MSG_DONTWAIT;
        }
        if ((flags & FREEBSD_MSG_NOSIGNAL) != 0) {
            linuxFlags |= MSG_NOSIGNAL;
        }
        return linuxFlags;
    }

    /// Maps a FreeBSD socket option to the normalized option numbering used by the shared host backend.
    private static @Nullable SocketOptionMapping freeBsdSocketOptionMapping(long level, long option) {
        if (level == FREEBSD_SOL_SOCKET) {
            long linuxOption = switch ((int) option) {
                case (int) FREEBSD_SO_REUSEADDR -> SO_REUSEADDR;
                case (int) FREEBSD_SO_KEEPALIVE -> SO_KEEPALIVE;
                case (int) FREEBSD_SO_BROADCAST -> SO_BROADCAST;
                case (int) FREEBSD_SO_SNDBUF -> SO_SNDBUF;
                case (int) FREEBSD_SO_RCVBUF -> SO_RCVBUF;
                case (int) FREEBSD_SO_ERROR -> SO_ERROR;
                case (int) FREEBSD_SO_REUSEPORT -> SO_REUSEPORT;
                default -> -1;
            };
            return linuxOption < 0 ? null : new SocketOptionMapping(SOL_SOCKET, linuxOption);
        }
        if (level == IPPROTO_TCP && option == TCP_NODELAY) {
            return new SocketOptionMapping(IPPROTO_TCP, TCP_NODELAY);
        }
        if (level == IPPROTO_IPV6 && option == FREEBSD_IPV6_V6ONLY) {
            return new SocketOptionMapping(IPPROTO_IPV6, IPV6_V6ONLY);
        }
        return null;
    }

    /// Reads a FreeBSD IPv4 or IPv6 socket address.
    @Override
    protected AddressResult readInetSocketAddress(long address, long length) {
        if (address == 0 || length < Short.BYTES || !memory.isBacked(address, Short.BYTES)) {
            return AddressResult.error(EFAULT);
        }

        int family = memory.readUnsignedByte(address + FREEBSD_SOCKADDR_FAMILY_OFFSET);
        try {
            if (family == FREEBSD_AF_INET) {
                if (length < FREEBSD_SOCKADDR_IN_SIZE || !memory.isBacked(address, FREEBSD_SOCKADDR_IN_SIZE)) {
                    return AddressResult.error(EFAULT);
                }
                if (memory.readUnsignedByte(address + FREEBSD_SOCKADDR_LENGTH_OFFSET) < FREEBSD_SOCKADDR_IN_SIZE) {
                    return AddressResult.error(EINVAL);
                }
                byte[] bytes = memory.readBytes(address + FREEBSD_SOCKADDR_IN_ADDRESS_OFFSET, Integer.BYTES);
                return AddressResult.address(new InetSocketAddress(
                        Inet4Address.getByAddress(bytes),
                        readNetworkPort(address + FREEBSD_SOCKADDR_PORT_OFFSET)));
            }
            if (family == FREEBSD_AF_INET6) {
                if (length < FREEBSD_SOCKADDR_IN6_SIZE || !memory.isBacked(address, FREEBSD_SOCKADDR_IN6_SIZE)) {
                    return AddressResult.error(EFAULT);
                }
                if (memory.readUnsignedByte(address + FREEBSD_SOCKADDR_LENGTH_OFFSET) < FREEBSD_SOCKADDR_IN6_SIZE) {
                    return AddressResult.error(EINVAL);
                }
                byte[] bytes = memory.readBytes(address + FREEBSD_SOCKADDR_IN6_ADDRESS_OFFSET, 16);
                int scopeId = memory.readInt(address + FREEBSD_SOCKADDR_IN6_SCOPE_ID_OFFSET);
                return AddressResult.address(new InetSocketAddress(
                        Inet6Address.getByAddress(null, bytes, scopeId),
                        readNetworkPort(address + FREEBSD_SOCKADDR_PORT_OFFSET)));
            }
            return AddressResult.error(EAFNOSUPPORT);
        } catch (UnknownHostException exception) {
            return AddressResult.error(EINVAL);
        }
    }

    /// Reads a FreeBSD Unix-domain socket address and maps it through the guest filesystem namespace.
    @Override
    protected UnixAddressResult readUnixSocketAddress(long address, long length) {
        if (address == 0 || length < Short.BYTES || !memory.isBacked(address, Short.BYTES)) {
            return UnixAddressResult.error(EFAULT);
        }
        if (memory.readUnsignedByte(address + FREEBSD_SOCKADDR_FAMILY_OFFSET) != FREEBSD_AF_UNIX) {
            return UnixAddressResult.error(EAFNOSUPPORT);
        }

        int declaredLength = memory.readUnsignedByte(address + FREEBSD_SOCKADDR_LENGTH_OFFSET);
        long suppliedPathLength = Math.min(length, declaredLength) - FREEBSD_SOCKADDR_UN_PATH_OFFSET;
        if (suppliedPathLength <= 0) {
            return UnixAddressResult.error(EINVAL);
        }
        int pathLength = (int) Math.min(suppliedPathLength, FREEBSD_SOCKADDR_UN_PATH_SIZE);
        if (!memory.isBacked(address + FREEBSD_SOCKADDR_UN_PATH_OFFSET, pathLength)) {
            return UnixAddressResult.error(EFAULT);
        }

        byte[] pathBytes = memory.readBytes(address + FREEBSD_SOCKADDR_UN_PATH_OFFSET, pathLength);
        if (pathBytes.length == 0 || pathBytes[0] == 0) {
            return UnixAddressResult.error(EAFNOSUPPORT);
        }
        int terminator = 0;
        while (terminator < pathBytes.length && pathBytes[terminator] != 0) {
            terminator++;
        }
        if (terminator == 0) {
            return UnixAddressResult.error(EINVAL);
        }

        String guestPath = new String(pathBytes, 0, terminator, StandardCharsets.UTF_8);
        String absoluteGuestPath = GuestFileSystem.isAbsoluteGuestPath(guestPath)
                ? guestPath
                : GuestFileSystem.appendGuestPath(guestWorkingDirectory, guestPath);
        @Nullable String normalizedGuestPath = GuestFileSystem.normalizeAbsoluteGuestPath(absoluteGuestPath);
        if (normalizedGuestPath == null) {
            return UnixAddressResult.error(EINVAL);
        }
        @Nullable Path hostPath = fileSystem.resolveHostFile(normalizedGuestPath);
        if (hostPath == null) {
            return UnixAddressResult.error(EACCES);
        }
        return UnixAddressResult.address(new UnixSocketAddress(
                normalizedGuestPath,
                UnixDomainSocketAddress.of(hostPath)));
    }

    /// Writes a host Internet socket address using the FreeBSD RISC-V socket address layout.
    @Override
    protected long writeInetSocketAddress(
            InetSocketAddress socketAddress,
            int domain,
            long address,
            long lengthAddress) {
        if (lengthAddress != 0 && !memory.isBacked(lengthAddress, Integer.BYTES)) {
            return EFAULT;
        }
        long size = domain == AF_INET6 ? FREEBSD_SOCKADDR_IN6_SIZE : FREEBSD_SOCKADDR_IN_SIZE;
        int freeBsdFamily = domain == AF_INET6 ? (int) FREEBSD_AF_INET6 : (int) FREEBSD_AF_INET;
        if (address != 0) {
            if (!memory.isBacked(address, size)) {
                return EFAULT;
            }
            memory.clear(address, size);
            memory.writeByte(address + FREEBSD_SOCKADDR_LENGTH_OFFSET, (byte) size);
            memory.writeByte(address + FREEBSD_SOCKADDR_FAMILY_OFFSET, (byte) freeBsdFamily);
            writeNetworkPort(address + FREEBSD_SOCKADDR_PORT_OFFSET, socketAddress.getPort());
            byte[] bytes = socketAddress.getAddress().getAddress();
            if (domain == AF_INET && bytes.length == Integer.BYTES) {
                memory.writeBytes(address + FREEBSD_SOCKADDR_IN_ADDRESS_OFFSET, bytes, 0, bytes.length);
            } else if (domain == AF_INET6 && bytes.length == 16) {
                memory.writeBytes(address + FREEBSD_SOCKADDR_IN6_ADDRESS_OFFSET, bytes, 0, bytes.length);
                if (socketAddress.getAddress() instanceof Inet6Address inet6Address) {
                    memory.writeInt(address + FREEBSD_SOCKADDR_IN6_SCOPE_ID_OFFSET, inet6Address.getScopeId());
                }
            } else {
                return EAFNOSUPPORT;
            }
        }
        if (lengthAddress != 0) {
            memory.writeInt(lengthAddress, (int) size);
        }
        return 0;
    }

    /// Writes a guest Unix-domain socket address using the FreeBSD RISC-V layout.
    @Override
    protected long writeUnixSocketAddress(@Nullable String guestPath, long address, long lengthAddress) {
        if (lengthAddress != 0 && !memory.isBacked(lengthAddress, Integer.BYTES)) {
            return EFAULT;
        }
        byte @Nullable [] pathBytes = guestPath == null ? null : guestPath.getBytes(StandardCharsets.UTF_8);
        if (pathBytes != null && pathBytes.length >= FREEBSD_SOCKADDR_UN_PATH_SIZE) {
            return EINVAL;
        }
        long size = pathBytes == null || pathBytes.length == 0
                ? FREEBSD_SOCKADDR_UN_PATH_OFFSET
                : FREEBSD_SOCKADDR_UN_PATH_OFFSET + pathBytes.length + 1L;
        if (address != 0) {
            if (!memory.isBacked(address, size)) {
                return EFAULT;
            }
            memory.clear(address, size);
            memory.writeByte(address + FREEBSD_SOCKADDR_LENGTH_OFFSET, (byte) size);
            memory.writeByte(address + FREEBSD_SOCKADDR_FAMILY_OFFSET, (byte) FREEBSD_AF_UNIX);
            if (pathBytes != null && pathBytes.length > 0) {
                memory.writeBytes(address + FREEBSD_SOCKADDR_UN_PATH_OFFSET, pathBytes, 0, pathBytes.length);
                memory.writeByte(address + FREEBSD_SOCKADDR_UN_PATH_OFFSET + pathBytes.length, (byte) 0);
            }
        }
        if (lengthAddress != 0) {
            memory.writeInt(lengthAddress, (int) size);
        }
        return 0;
    }

    /// Stores one normalized socket option mapping.
    ///
    /// @param level the normalized option level
    /// @param option the normalized option number
    @NotNullByDefault
    private record SocketOptionMapping(long level, long option) {
    }

    /// Writes FreeBSD `struct stat` metadata for a path relative to a directory descriptor.
    private long freeBsdFstatat(long directoryFileDescriptor, long pathAddress, long statAddress, long flags) {
        if ((flags & ~FREEBSD_SUPPORTED_FSTATAT_FLAGS) != 0) {
            return EINVAL;
        }
        return newfstatat(
                directoryFileDescriptor,
                pathAddress,
                statAddress,
                freeBsdAtFlagsToLinux(flags));
    }

    /// Reads FreeBSD `struct dirent` records from one open directory and returns its starting offset.
    private long freeBsdGetdirentries(
            int fileDescriptor,
            long bufferAddress,
            long byteCount,
            long baseAddress) {
        if (byteCount <= 0) {
            return EINVAL;
        }
        if (bufferAddress == 0) {
            return EFAULT;
        }
        if (!memory.isBacked(bufferAddress, byteCount)
                || (baseAddress != 0 && !memory.isBacked(baseAddress, Long.BYTES))) {
            return EFAULT;
        }
        if (isStandardFileDescriptor(fileDescriptor)) {
            return EINVAL;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }
        if (!openFile.isDirectory()) {
            return EINVAL;
        }

        try {
            DirectoryEntry[] entries = directoryEntries(openFile);
            int index = openFile.directoryEntryIndex();
            if (baseAddress != 0) {
                memory.writeLong(baseAddress, index);
            }
            long written = 0;
            while (index < entries.length) {
                DirectoryEntry entry = entries[index];
                byte[] name = entry.name().getBytes(StandardCharsets.UTF_8);
                int recordLength = freeBsdDirectoryEntryRecordLength(name.length);
                if (recordLength > byteCount - written) {
                    if (written > 0) {
                        openFile.setDirectoryEntryIndex(index);
                    }
                    return written == 0 ? EINVAL : written;
                }

                writeFreeBsdDirectoryEntry(bufferAddress + written, entry, index + 1L, name, recordLength);
                written += recordLength;
                index++;
            }

            openFile.setDirectoryEntryIndex(index);
            return written;
        } catch (java.io.IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Computes the aligned byte size needed for one variable-length FreeBSD `struct dirent` record.
    private static int freeBsdDirectoryEntryRecordLength(int nameLength) {
        return (int) alignUp(FREEBSD_DIRENT_NAME_OFFSET + nameLength + 1L, FREEBSD_DIRENT_ALIGNMENT);
    }

    /// Waits for a child using FreeBSD `wait4` options and resource-usage layout.
    private long freeBsdWait4(long processId, long statusAddress, long options, long rusageAddress) {
        long normalizedOptions = Integer.toUnsignedLong((int) options);
        if ((normalizedOptions & ~FREEBSD_SUPPORTED_WAIT6_OPTIONS) != 0) {
            return EINVAL;
        }
        if (statusAddress != 0 && !memory.isBacked(statusAddress, Integer.BYTES)) {
            return EFAULT;
        }
        if (rusageAddress != 0 && !memory.isBacked(rusageAddress, RUSAGE_SIZE)) {
            return EFAULT;
        }
        boolean waitForCloneChildren = (normalizedOptions & FREEBSD_WAIT_LINUX_CLONE) != 0;
        ChildWaitResult waitResult = waitForExitedChild(
                (int) processId,
                true,
                (normalizedOptions & FREEBSD_WAIT_NO_HANG) != 0,
                (normalizedOptions & FREEBSD_WAIT_NO_WAIT) != 0,
                !waitForCloneChildren,
                waitForCloneChildren,
                0);
        if (waitResult.result() <= 0) {
            return waitResult.result();
        }

        @Nullable ChildProcess child = waitResult.child();
        if (child == null) {
            throw new AssertionError("Successful FreeBSD wait4 did not return a child process");
        }
        if (statusAddress != 0) {
            memory.writeInt(statusAddress, child.waitStatus());
        }
        if (rusageAddress != 0) {
            memory.clear(rusageAddress, RUSAGE_SIZE);
        }
        return child.processId();
    }

    /// Waits for a child event using FreeBSD `wait6` selectors and output layouts.
    private long freeBsdWait6(
            long idType,
            long id,
            long statusAddress,
            long options,
            long waitRusageAddress,
            long signalInfoAddress) {
        long normalizedOptions = Integer.toUnsignedLong((int) options);
        if ((normalizedOptions & ~FREEBSD_SUPPORTED_WAIT6_OPTIONS) != 0
                || (normalizedOptions & FREEBSD_WAIT6_EVENT_OPTIONS) == 0) {
            return EINVAL;
        }
        if (statusAddress != 0 && !memory.isBacked(statusAddress, Integer.BYTES)) {
            return EFAULT;
        }
        if (waitRusageAddress != 0 && !memory.isBacked(waitRusageAddress, FREEBSD_WRUSAGE_SIZE)) {
            return EFAULT;
        }
        if (signalInfoAddress != 0 && !memory.isBacked(signalInfoAddress, FREEBSD_SIGNAL_INFO_SIZE)) {
            return EFAULT;
        }

        int selectorType = (int) idType;
        int identifier = (int) id;
        long processSelector;
        switch (selectorType) {
            case FREEBSD_WAIT_ID_PROCESS -> {
                if (identifier < 0) {
                    return EINVAL;
                }
                processSelector = identifier == 0 ? 0 : identifier;
            }
            case FREEBSD_WAIT_ID_PROCESS_GROUP -> {
                if (identifier < 0) {
                    return EINVAL;
                }
                processSelector = identifier == 0 ? 0 : -(long) identifier;
            }
            case FREEBSD_WAIT_ID_ALL -> processSelector = -1;
            case FREEBSD_WAIT_ID_PARENT_PROCESS -> {
                if (id != process.id()) {
                    return ECHILD;
                }
                processSelector = -1;
            }
            default -> {
                return EINVAL;
            }
        }

        ChildWaitResult waitResult = waitForExitedChild(
                processSelector,
                (normalizedOptions & FREEBSD_WAIT_EXITED) != 0,
                (normalizedOptions & FREEBSD_WAIT_NO_HANG) != 0,
                (normalizedOptions & FREEBSD_WAIT_NO_WAIT) != 0,
                (normalizedOptions & FREEBSD_WAIT_LINUX_CLONE) == 0,
                (normalizedOptions & FREEBSD_WAIT_LINUX_CLONE) != 0,
                0);
        if (waitResult.result() <= 0) {
            return waitResult.result();
        }

        @Nullable ChildProcess child = waitResult.child();
        if (child == null) {
            throw new AssertionError("Successful wait6 did not return a child process");
        }
        if (statusAddress != 0) {
            memory.writeInt(statusAddress, child.waitStatus());
        }
        if (waitRusageAddress != 0) {
            memory.clear(waitRusageAddress, FREEBSD_WRUSAGE_SIZE);
        }
        writeFreeBsdWaitSignalInfo(signalInfoAddress, child);
        return child.processId();
    }

    /// Writes FreeBSD `wait6` signal information for one normally exited child.
    private void writeFreeBsdWaitSignalInfo(long address, ChildProcess child) {
        if (address == 0) {
            return;
        }
        memory.clear(address, FREEBSD_SIGNAL_INFO_SIZE);
        memory.writeInt(address + FREEBSD_SIGNAL_INFO_NUMBER_OFFSET, FREEBSD_SIGNAL_CHILD);
        memory.writeInt(address + FREEBSD_SIGNAL_INFO_ERRNO_OFFSET, 0);
        memory.writeInt(address + FREEBSD_SIGNAL_INFO_CODE_OFFSET, FREEBSD_CHILD_EXITED);
        memory.writeInt(address + FREEBSD_SIGNAL_INFO_PROCESS_ID_OFFSET, child.processId());
        memory.writeInt(address + FREEBSD_SIGNAL_INFO_USER_ID_OFFSET, GuestCredentials.idToInt(child.userId()));
        memory.writeInt(address + FREEBSD_SIGNAL_INFO_STATUS_OFFSET, child.exitCode());
    }

    /// Writes one variable-length FreeBSD RISC-V `struct dirent` record.
    private void writeFreeBsdDirectoryEntry(
            long address,
            DirectoryEntry entry,
            long nextOffset,
            byte[] name,
            int recordLength) {
        memory.clear(address, recordLength);
        memory.writeLong(address + FREEBSD_DIRENT_INODE_OFFSET, entry.inode());
        memory.writeLong(address + FREEBSD_DIRENT_NEXT_OFFSET, nextOffset);
        memory.writeShort(address + FREEBSD_DIRENT_RECORD_LENGTH_OFFSET, (short) recordLength);
        memory.writeByte(address + FREEBSD_DIRENT_TYPE_OFFSET, entry.type());
        memory.writeShort(address + FREEBSD_DIRENT_NAME_LENGTH_OFFSET, (short) name.length);
        memory.writeBytes(address + FREEBSD_DIRENT_NAME_OFFSET, name, 0, name.length);
    }

    /// Writes the current FreeBSD resource limit for the guest process.
    private long freeBsdGetrlimit(long resource, long limitAddress) {
        if (limitAddress == 0) {
            return EFAULT;
        }
        int index = freeBsdResourceLimitIndex(resource);
        if (index < 0) {
            return EINVAL;
        }

        writeResourceLimit(limitAddress, resourceLimitCurrent[index], resourceLimitMaximum[index]);
        return 0;
    }

    /// Lowers one FreeBSD resource limit using the shared process limit table.
    private long freeBsdSetrlimit(long resource, long limitAddress) {
        if (limitAddress == 0) {
            return EFAULT;
        }
        int index = freeBsdResourceLimitIndex(resource);
        return index < 0 ? EINVAL : setrlimit(index, limitAddress);
    }

    /// Maps a FreeBSD resource id to the shared resource-limit table index.
    private static int freeBsdResourceLimitIndex(long resource) {
        if (resource == FREEBSD_RLIMIT_NOFILE) {
            return RLIMIT_NOFILE;
        }
        return resource >= 0 && resource < RESOURCE_LIMIT_COUNT ? (int) resource : -1;
    }

    /// Starts a FreeBSD guest thread from `struct thr_param`.
    private long freeBsdThrNew(RiscVThreadState state, long parameterAddress, long size) {
        if (parameterAddress == 0 || size < FREEBSD_THR_PARAM_MINIMUM_SIZE) {
            return EINVAL;
        }
        if (!memory.isBacked(parameterAddress, FREEBSD_THR_PARAM_MINIMUM_SIZE)) {
            return EFAULT;
        }
        if (!guestThreadingEnabled()) {
            return EAGAIN;
        }

        long startFunction = memory.readLong(parameterAddress + FREEBSD_THR_PARAM_START_FUNC_OFFSET);
        long argument = memory.readLong(parameterAddress + FREEBSD_THR_PARAM_ARG_OFFSET);
        long stackBase = memory.readLong(parameterAddress + FREEBSD_THR_PARAM_STACK_BASE_OFFSET);
        long stackSize = memory.readLong(parameterAddress + FREEBSD_THR_PARAM_STACK_SIZE_OFFSET);
        long tlsBase = memory.readLong(parameterAddress + FREEBSD_THR_PARAM_TLS_BASE_OFFSET);
        long childTidAddress = memory.readLong(parameterAddress + FREEBSD_THR_PARAM_CHILD_TID_OFFSET);
        long parentTidAddress = memory.readLong(parameterAddress + FREEBSD_THR_PARAM_PARENT_TID_OFFSET);
        if (startFunction == 0 || stackBase == 0 || stackSize <= 0 || stackBase > Long.MAX_VALUE - stackSize) {
            return EINVAL;
        }

        GuestThread childThread;
        synchronized (threadLock) {
            if (processExitRequested || threadFailure != null) {
                return EAGAIN;
            }
            childThread = processRegistry.createChildThread(process);
            if (childThread == null) {
                return ENOMEM;
            }
            childThread.setSignalMask(state.guestThread().signalMask());
            childThread.inheritExecutionControlsFrom(state.guestThread());
        }
        long threadId = childThread.id();

        RiscVThreadState child = state.forkForClone(childThread, startFunction, stackBase + stackSize, tlsBase, true);
        child.setRegister(10, argument);
        if (childTidAddress != 0) {
            childThread.setClearChildTidAddress(childTidAddress);
        }

        GuestThreadRunner currentRunner = guestThreadRunner;
        if (currentRunner == null) {
            return EAGAIN;
        }
        Thread thread;
        try {
            thread = new Thread(
                    () -> currentRunner.runGuestThread(memory, child),
                    "riscv-guest-thread-" + threadId);
        } catch (RuntimeException exception) {
            return EAGAIN;
        }
        thread.setUncaughtExceptionHandler((failedThread, throwable) -> recordThreadFailure(throwable));

        if (parentTidAddress != 0) {
            memory.writeLong(parentTidAddress, threadId);
        }
        if (childTidAddress != 0) {
            memory.writeLong(childTidAddress, threadId);
        }

        synchronized (threadLock) {
            if (processExitRequested || threadFailure != null) {
                return EAGAIN;
            }
            liveThreadCount++;
            guestThreads.add(thread);
            process.registerThread(childThread);
            processStatusPollingRequired = true;
        }

        try {
            thread.start();
        } catch (RuntimeException exception) {
            unregisterUnstartedGuestThread(thread, childThread);
            return EAGAIN;
        }
        return 0;
    }

    /// Registers or reports the FreeBSD alternate signal stack for the current guest thread.
    private long freeBsdSigaltstack(RiscVThreadState state, long stackAddress, long oldStackAddress) {
        long newStackPointer = 0;
        long newStackSize = 0;
        long newStackFlags = 0;
        if (stackAddress != 0) {
            newStackPointer = memory.readLong(stackAddress + FREEBSD_SIGNAL_STACK_POINTER_OFFSET);
            newStackSize = memory.readLong(stackAddress + FREEBSD_SIGNAL_STACK_SIZE_OFFSET);
            newStackFlags = Integer.toUnsignedLong(memory.readInt(stackAddress + FREEBSD_SIGNAL_STACK_FLAGS_OFFSET));
            if ((newStackFlags & ~FREEBSD_SS_DISABLE) != 0 || newStackSize < 0) {
                return EINVAL;
            }
            if ((newStackFlags & FREEBSD_SS_DISABLE) == 0 && newStackSize < MINIMUM_SIGNAL_STACK_SIZE) {
                return ENOMEM;
            }
        }

        if (oldStackAddress != 0) {
            writeFreeBsdSignalStack(state.guestThread(), oldStackAddress);
        }
        if (stackAddress != 0) {
            if ((newStackFlags & FREEBSD_SS_DISABLE) != 0) {
                state.guestThread().disableAlternateSignalStack();
            } else {
                state.guestThread().setAlternateSignalStack(newStackPointer, newStackSize, 0);
            }
        }
        return 0;
    }

    /// Writes the current FreeBSD RISC-V `stack_t` alternate signal stack.
    private void writeFreeBsdSignalStack(GuestThread thread, long stackAddress) {
        memory.writeLong(stackAddress + FREEBSD_SIGNAL_STACK_POINTER_OFFSET, thread.alternateSignalStackPointer());
        memory.writeLong(stackAddress + FREEBSD_SIGNAL_STACK_SIZE_OFFSET, thread.alternateSignalStackSize());
        memory.writeInt(
                stackAddress + FREEBSD_SIGNAL_STACK_FLAGS_OFFSET,
                thread.alternateSignalStackSize() == 0 ? (int) FREEBSD_SS_DISABLE : 0);
    }

    /// Translates FreeBSD open flags to the Linux-style internal flag set.
    private static long freeBsdOpenFlagsToLinux(long freeBsdFlags) {
        long flags = freeBsdFlags & FREEBSD_O_ACCMODE;
        if ((freeBsdFlags & FREEBSD_O_NONBLOCK) != 0) {
            flags |= O_NONBLOCK;
        }
        if ((freeBsdFlags & FREEBSD_O_APPEND) != 0) {
            flags |= O_APPEND;
        }
        if ((freeBsdFlags & FREEBSD_O_CREAT) != 0) {
            flags |= O_CREAT;
        }
        if ((freeBsdFlags & FREEBSD_O_TRUNC) != 0) {
            flags |= O_TRUNC;
        }
        if ((freeBsdFlags & FREEBSD_O_EXCL) != 0) {
            flags |= O_EXCL;
        }
        if ((freeBsdFlags & FREEBSD_O_DIRECTORY) != 0) {
            flags |= O_DIRECTORY;
        }
        if ((freeBsdFlags & FREEBSD_O_CLOEXEC) != 0) {
            flags |= O_CLOEXEC;
        }
        return flags;
    }

    /// Translates Linux-style internal open-file status flags to FreeBSD values.
    private static long linuxOpenStatusFlagsToFreeBsd(long linuxFlags) {
        long flags = linuxFlags & O_ACCMODE;
        if ((linuxFlags & O_NONBLOCK) != 0) {
            flags |= FREEBSD_O_NONBLOCK;
        }
        if ((linuxFlags & O_APPEND) != 0) {
            flags |= FREEBSD_O_APPEND;
        }
        if ((linuxFlags & O_DIRECTORY) != 0) {
            flags |= FREEBSD_O_DIRECTORY;
        }
        return flags;
    }

    /// Translates FreeBSD `*at` flags to the Linux-style internal flag set.
    private static long freeBsdAtFlagsToLinux(long freeBsdFlags) {
        long flags = 0;
        if ((freeBsdFlags & FREEBSD_AT_EACCESS) != 0) {
            flags |= AT_EACCESS;
        }
        if ((freeBsdFlags & FREEBSD_AT_SYMLINK_NOFOLLOW) != 0) {
            flags |= AT_SYMLINK_NOFOLLOW;
        }
        if ((freeBsdFlags & FREEBSD_AT_SYMLINK_FOLLOW) != 0) {
            flags |= AT_SYMLINK_FOLLOW;
        }
        if ((freeBsdFlags & FREEBSD_AT_REMOVEDIR) != 0) {
            flags |= AT_REMOVEDIR;
        }
        if ((freeBsdFlags & FREEBSD_AT_EMPTY_PATH) != 0) {
            flags |= AT_EMPTY_PATH;
        }
        return flags;
    }

    /// Translates FreeBSD `mmap` flags to the Linux-style internal flag set.
    private static long freeBsdMmapFlagsToLinux(long freeBsdFlags) {
        long flags = freeBsdFlags & (MAP_SHARED | MAP_PRIVATE | MAP_FIXED);
        if ((freeBsdFlags & FREEBSD_MAP_ANON) != 0) {
            flags |= MAP_ANONYMOUS;
        }
        if ((freeBsdFlags & FREEBSD_MAP_EXCL) != 0) {
            flags |= MAP_FIXED_NOREPLACE;
        }
        return flags;
    }

    /// Validates FreeBSD `msync` flags before using the shared mapped-range implementation.
    private long freeBsdMsync(long address, long length, long flags) {
        if ((flags & ~(FREEBSD_MS_ASYNC | FREEBSD_MS_INVALIDATE)) != 0) {
            return EINVAL;
        }
        return msync(address, length, flags);
    }

    /// Translates FreeBSD memory-advice values without confusing `MADV_NOCORE` with Linux `MADV_FREE`.
    private long freeBsdMadvise(long address, long length, long advice) {
        if (advice >= MADV_NORMAL && advice <= MADV_DONTNEED) {
            return madvise(address, length, advice);
        }
        if (advice == FREEBSD_MADV_FREE) {
            return madvise(address, length, MADV_FREE);
        }
        if (advice >= FREEBSD_MADV_NOSYNC && advice <= FREEBSD_MADV_PROTECT) {
            return madvise(address, length, MADV_NORMAL);
        }
        return EINVAL;
    }

    /// Translates FreeBSD `fcntl` commands to the Linux-style internal command set.
    private static long freeBsdFcntlCommandToLinux(long command) {
        if (command == FREEBSD_F_DUPFD_CLOEXEC) {
            return F_DUPFD_CLOEXEC;
        }
        return command >= F_DUPFD && command <= F_SETFL ? command : -1;
    }

    /// Applies FreeBSD command and status-flag translations around the shared `fcntl` implementation.
    private long freeBsdFcntl(int fileDescriptor, long command, long argument) {
        if (command == FREEBSD_F_DUP2FD || command == FREEBSD_F_DUP2FD_CLOEXEC) {
            return freeBsdFcntlDuplicateExact(
                    fileDescriptor,
                    argument,
                    command == FREEBSD_F_DUP2FD_CLOEXEC);
        }
        if (command == F_GETFD) {
            if (!isOpenFileDescriptor(fileDescriptor)) {
                return EBADF;
            }
            return (fileDescriptorCloseOnExec(fileDescriptor) ? FD_CLOEXEC : 0)
                    | (fileDescriptorCloseOnFork(fileDescriptor) ? FREEBSD_FD_CLOFORK : 0);
        }
        if (command == F_SETFD) {
            if (!isOpenFileDescriptor(fileDescriptor)) {
                return EBADF;
            }
            setFileDescriptorCloseOnExec(fileDescriptor, (argument & FD_CLOEXEC) != 0);
            setFileDescriptorCloseOnFork(fileDescriptor, (argument & FREEBSD_FD_CLOFORK) != 0);
            return 0;
        }
        if (command == FREEBSD_F_GETLK || command == FREEBSD_F_SETLK || command == FREEBSD_F_SETLKW) {
            return freeBsdFcntlRecordLock(fileDescriptor, command, argument);
        }
        long linuxCommand = freeBsdFcntlCommandToLinux(command);
        long linuxArgument = command == F_SETFL ? freeBsdOpenFlagsToLinux(argument) : argument;
        long result = fcntl(fileDescriptor, linuxCommand, linuxArgument);
        return result >= 0 && command == F_GETFL ? linuxOpenStatusFlagsToFreeBsd(result) : result;
    }

    /// Handles advisory record-lock commands using the native FreeBSD `struct flock` layout.
    private long freeBsdFcntlRecordLock(int fileDescriptor, long command, long flockAddress) {
        if (!isOpenFileDescriptor(fileDescriptor)) {
            return EBADF;
        }
        if (!memory.isBacked(flockAddress, FREEBSD_FLOCK_SIZE)) {
            return EFAULT;
        }
        if (command == FREEBSD_F_GETLK) {
            memory.writeShort(flockAddress + FREEBSD_FLOCK_TYPE_OFFSET, (short) FREEBSD_F_UNLCK);
            return 0;
        }

        int type = memory.readUnsignedShort(flockAddress + FREEBSD_FLOCK_TYPE_OFFSET);
        if (type != FREEBSD_F_RDLCK && type != FREEBSD_F_UNLCK && type != FREEBSD_F_WRLCK) {
            return EINVAL;
        }
        long accessMode = statusFlagsFor(fileDescriptor) & O_ACCMODE;
        if (type == FREEBSD_F_RDLCK && accessMode == O_WRONLY
                || type == FREEBSD_F_WRLCK && accessMode == O_RDONLY) {
            return EBADF;
        }
        return 0;
    }

    /// Applies or removes a whole-file advisory lock for a file-like descriptor.
    private long freeBsdFlock(int fileDescriptor, long operation) {
        if (!isOpenFileDescriptor(fileDescriptor)) {
            return EBADF;
        }
        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null
                || !(openFile.isHostFile() || openFile.isDirectory() || openFile.isPipe())) {
            return ENOTSUP;
        }
        if ((operation & FREEBSD_LOCK_UN) != 0
                || (operation & FREEBSD_LOCK_EX) != 0
                || (operation & FREEBSD_LOCK_SH) != 0) {
            return 0;
        }
        return EBADF;
    }

    /// Copies a regular-file range while handling the FreeBSD-only clone request flag.
    private long freeBsdCopyFileRange(
            int inputFileDescriptor,
            long inputOffsetAddress,
            int outputFileDescriptor,
            long outputOffsetAddress,
            long length,
            long flags) {
        if (flags == FREEBSD_COPY_FILE_RANGE_CLONE) {
            return ENOTSUP;
        }
        return copyFileRange(
                inputFileDescriptor,
                inputOffsetAddress,
                outputFileDescriptor,
                outputOffsetAddress,
                length,
                flags);
    }

    /// Zeroes a FreeBSD file range and reports that no requested bytes remain unprocessed.
    private long freeBsdFspacectl(
            int fileDescriptor,
            long command,
            long requestedRangeAddress,
            long flags,
            long remainingRangeAddress) {
        if (command != FREEBSD_SPACECTL_DEALLOC || flags != 0) {
            return EINVAL;
        }
        if (!memory.isBacked(requestedRangeAddress, FREEBSD_SPACECTL_RANGE_SIZE)
                || remainingRangeAddress != 0
                && !memory.isBacked(remainingRangeAddress, FREEBSD_SPACECTL_RANGE_SIZE)) {
            return EFAULT;
        }

        long offset = memory.readLong(requestedRangeAddress + FREEBSD_SPACECTL_RANGE_OFFSET_OFFSET);
        long length = memory.readLong(requestedRangeAddress + FREEBSD_SPACECTL_RANGE_LENGTH_OFFSET);
        if (offset < 0 || length <= 0 || offset > Long.MAX_VALUE - length) {
            return EINVAL;
        }

        long zeroed = zeroFileRange(fileDescriptor, offset, length);
        if (zeroed < 0) {
            return zeroed;
        }
        if (remainingRangeAddress != 0) {
            memory.writeLong(remainingRangeAddress + FREEBSD_SPACECTL_RANGE_OFFSET_OFFSET, offset + zeroed);
            memory.writeLong(remainingRangeAddress + FREEBSD_SPACECTL_RANGE_LENGTH_OFFSET, 0);
        }
        return 0;
    }

    /// Creates a timer descriptor after translating FreeBSD clock and descriptor flags.
    private long freeBsdTimerfdCreate(long clockId, long flags) {
        if ((flags & ~FREEBSD_SUPPORTED_TIMERFD_CREATE_FLAGS) != 0) {
            return EINVAL;
        }

        long linuxClockId;
        if (clockId == FREEBSD_CLOCK_REALTIME) {
            linuxClockId = CLOCK_REALTIME;
        } else if (clockId == FREEBSD_CLOCK_MONOTONIC || clockId == FREEBSD_CLOCK_UPTIME) {
            linuxClockId = CLOCK_MONOTONIC;
        } else {
            return EINVAL;
        }

        long linuxFlags = 0;
        if ((flags & FREEBSD_O_NONBLOCK) != 0) {
            linuxFlags |= O_NONBLOCK;
        }
        if ((flags & FREEBSD_O_CLOEXEC) != 0) {
            linuxFlags |= O_CLOEXEC;
        }
        return timerfdCreate(linuxClockId, linuxFlags);
    }

    /// Returns one FreeBSD path configuration value after validating a mounted guest path.
    private long freeBsdPathconf(long pathAddress, long name, boolean followFinalSymbolicLink) {
        long access = validateXattrPath(pathAddress, followFinalSymbolicLink);
        if (access != 0) {
            return access;
        }

        @Nullable String guestPath;
        try {
            guestPath = readGuestPath(pathAddress);
        } catch (RiscVException exception) {
            return EFAULT;
        }
        if (guestPath == null) {
            return ENAMETOOLONG;
        }

        @Nullable GuestFileSystem.TarPath tarPath = resolveTarPath(
                AT_FDCWD,
                guestPath,
                followFinalSymbolicLink);
        if (tarPath != null) {
            @Nullable GuestFileSystem.TarNode node = tarPath.node();
            return node == null
                    ? ENOENT
                    : freeBsdPathconfValue(name, node.isDirectory(), false);
        }

        @Nullable GuestFileSystem.VirtualPath virtualPath = resolveVirtualPath(
                AT_FDCWD,
                guestPath,
                followFinalSymbolicLink);
        if (virtualPath != null) {
            @Nullable GuestFileSystem.VirtualNode node = virtualPath.node();
            return node == null
                    ? ENOENT
                    : freeBsdPathconfValue(name, node.isDirectory(), node.isCharacterDevice());
        }

        @Nullable Path hostFile = resolveHostFile(AT_FDCWD, guestPath);
        if (hostFile == null) {
            return EACCES;
        }
        boolean finalSymbolicLink = !followFinalSymbolicLink && Files.isSymbolicLink(hostFile);
        return freeBsdPathconfValue(name, !finalSymbolicLink && Files.isDirectory(hostFile), false);
    }

    /// Returns one FreeBSD path configuration value for an open descriptor.
    private long freeBsdFpathconf(int fileDescriptor, long name) {
        if (!isOpenFileDescriptor(fileDescriptor)) {
            return EBADF;
        }
        @Nullable OpenFile openFile = openFile(fileDescriptor);
        boolean directoryOrPipe = openFile != null && (openFile.isDirectory() || openFile.isPipe());
        return freeBsdPathconfValue(name, directoryOrPipe, terminalDeviceFor(fileDescriptor) != null);
    }

    /// Returns a deterministic FreeBSD path configuration value for the simulated filesystem.
    private long freeBsdPathconfValue(long name, boolean directoryOrPipe, boolean terminal) {
        if (name < Integer.MIN_VALUE || name > Integer.MAX_VALUE) {
            return EINVAL;
        }
        int configurationName = (int) name;
        if (configurationName >= FREEBSD_PC_CAPABILITY_FIRST
                && configurationName <= FREEBSD_PC_CAPABILITY_LAST) {
            return 0;
        }
        return switch (configurationName) {
            case FREEBSD_PC_LINK_MAX -> Integer.MAX_VALUE;
            case FREEBSD_PC_MAX_CANON, FREEBSD_PC_MAX_INPUT ->
                    terminal ? FREEBSD_TERMINAL_INPUT_MAX : EINVAL;
            case FREEBSD_PC_NAME_MAX -> FREEBSD_NAME_MAX;
            case FREEBSD_PC_PATH_MAX, FREEBSD_PC_SYMLINK_MAX -> FREEBSD_PATH_MAX;
            case FREEBSD_PC_PIPE_BUF -> directoryOrPipe ? FREEBSD_PIPE_BUF : EINVAL;
            case FREEBSD_PC_CHOWN_RESTRICTED, FREEBSD_PC_NO_TRUNC, FREEBSD_PC_SYNC_IO -> 1;
            case FREEBSD_PC_VDISABLE -> terminal ? FREEBSD_POSIX_VDISABLE : EINVAL;
            case FREEBSD_PC_ALLOC_SIZE_MIN,
                 FREEBSD_PC_REC_INCR_XFER_SIZE,
                 FREEBSD_PC_REC_MIN_XFER_SIZE,
                 FREEBSD_PC_REC_XFER_ALIGN,
                 FREEBSD_PC_MIN_HOLE_SIZE -> pageSize;
            case FREEBSD_PC_FILESIZEBITS -> Long.SIZE;
            case FREEBSD_PC_REC_MAX_XFER_SIZE -> Integer.MAX_VALUE;
            case FREEBSD_PC_ASYNC_IO, FREEBSD_PC_PRIO_IO -> 0;
            default -> EINVAL;
        };
    }

    /// Implements FreeBSD `F_DUP2FD` and `F_DUP2FD_CLOEXEC` exact-target duplication.
    private long freeBsdFcntlDuplicateExact(int fileDescriptor, long targetFileDescriptor, boolean closeOnExec) {
        if (targetFileDescriptor < 0 || targetFileDescriptor > Integer.MAX_VALUE) {
            return EINVAL;
        }
        int target = (int) targetFileDescriptor;
        if (fileDescriptor == target) {
            if (!isOpenFileDescriptor(fileDescriptor)) {
                return EBADF;
            }
            if (closeOnExec) {
                setFileDescriptorCloseOnExec(fileDescriptor, true);
            }
            return target;
        }
        return dup3(fileDescriptor, target, closeOnExec ? O_CLOEXEC : 0);
    }

    /// Implements FreeBSD `dup2`, including its valid same-descriptor no-op case.
    private long freeBsdDup2(int fileDescriptor, long targetFileDescriptor) {
        if (targetFileDescriptor < 0 || targetFileDescriptor > Integer.MAX_VALUE) {
            return EBADF;
        }
        int target = (int) targetFileDescriptor;
        if (fileDescriptor == target) {
            return isOpenFileDescriptor(fileDescriptor) ? target : EBADF;
        }
        return dup3(fileDescriptor, target, 0);
    }

    /// Closes every descriptor at or above the FreeBSD lower bound, clamping negative values to zero.
    private long freeBsdClosefrom(long lowFileDescriptor) {
        return closeRange(Math.max(0, (int) lowFileDescriptor), 0xffff_ffffL, 0);
    }

    /// Creates a legacy FreeBSD pipe and returns its descriptors in `a0` and `a1`.
    private long freeBsdPipe(RiscVThreadState state) {
        PipeBuffer pipe = new PipeBuffer(this::notifyPollWaiters);
        long readFileDescriptor = addOpenFile(OpenFile.pipeReader(pipe, false), false);
        long writeFileDescriptor = addOpenFile(OpenFile.pipeWriter(pipe, false), false);
        state.setRegister(11, writeFileDescriptor);
        return readFileDescriptor;
    }

    /// Creates a pipe after translating FreeBSD descriptor flags to the shared internal values.
    private long freeBsdPipe2(long pipeAddress, long flags) {
        if ((flags & ~FREEBSD_SUPPORTED_PIPE2_FLAGS) != 0) {
            return EINVAL;
        }
        long linuxFlags = 0;
        if ((flags & FREEBSD_O_NONBLOCK) != 0) {
            linuxFlags |= O_NONBLOCK;
        }
        if ((flags & FREEBSD_O_CLOEXEC) != 0) {
            linuxFlags |= O_CLOEXEC;
        }
        return pipe2(pipeAddress, linuxFlags);
    }

    /// Writes the shared file metadata subset using the FreeBSD RISC-V `struct stat` layout.
    @Override
    protected void writeStat(long statAddress, long inode, int mode, long size) {
        writeFreeBsdStat(
                statAddress,
                inode,
                mode,
                size,
                credentials.effectiveUserId(),
                credentials.effectiveGroupId());
    }

    /// Writes explicitly owned file metadata using the FreeBSD RISC-V `struct stat` layout.
    @Override
    protected void writeStat(long statAddress, long inode, int mode, long size, long userId, long groupId) {
        writeFreeBsdStat(statAddress, inode, mode, size, userId, groupId);
    }

    /// Writes host timestamps using the FreeBSD RISC-V `struct stat` timespec offsets.
    @Override
    protected void writeStatTimestamps(
            long statAddress,
            FileTime accessTime,
            FileTime modificationTime,
            @Nullable FileTime changeTime,
            @Nullable FileTime birthTime) {
        writeFileTime(statAddress + FREEBSD_STAT_ACCESS_TIME_OFFSET, accessTime);
        writeFileTime(statAddress + FREEBSD_STAT_MODIFICATION_TIME_OFFSET, modificationTime);
        if (changeTime != null) {
            writeFileTime(statAddress + FREEBSD_STAT_CHANGE_TIME_OFFSET, changeTime);
        }
        if (birthTime != null) {
            writeFileTime(statAddress + FREEBSD_STAT_BIRTH_TIME_OFFSET, birthTime);
        }
    }

    /// Writes one zero-initialized FreeBSD RISC-V `struct stat` with deterministic device ids.
    private void writeFreeBsdStat(
            long statAddress,
            long inode,
            int mode,
            long size,
            long userId,
            long groupId) {
        memory.clear(statAddress, FREEBSD_STAT_SIZE);
        memory.writeLong(statAddress + FREEBSD_STAT_INODE_OFFSET, inode);
        memory.writeLong(statAddress + FREEBSD_STAT_LINK_COUNT_OFFSET, 1);
        memory.writeShort(statAddress + FREEBSD_STAT_MODE_OFFSET, (short) mode);
        memory.writeInt(statAddress + FREEBSD_STAT_USER_ID_OFFSET, GuestCredentials.idToInt(userId));
        memory.writeInt(statAddress + FREEBSD_STAT_GROUP_ID_OFFSET, GuestCredentials.idToInt(groupId));
        memory.writeLong(statAddress + FREEBSD_STAT_FILE_SIZE_OFFSET, size);
        memory.writeLong(statAddress + FREEBSD_STAT_BLOCK_COUNT_OFFSET, (size + 511L) / 512L);
        memory.writeInt(statAddress + FREEBSD_STAT_BLOCK_SIZE_OFFSET, STANDARD_STREAM_BLOCK_SIZE);
    }

    /// Writes deterministic root-filesystem metadata using the FreeBSD RISC-V `struct statfs` layout.
    @Override
    protected void writeStatfs(long statfsAddress) {
        writeFreeBsdStatfs(statfsAddress, STATFS_BLOCK_COUNT, "jriscvfs", "jriscv", "/");
    }

    /// Writes deterministic virtual-mount metadata using the FreeBSD RISC-V `struct statfs` layout.
    @Override
    protected void writeVirtualStatfs(VirtualMount mount, long statfsAddress) {
        switch (mount.guestPath()) {
            case PROC_MOUNT_PATH -> writeFreeBsdStatfs(statfsAddress, 0, "procfs", "procfs", PROC_MOUNT_PATH);
            case SYS_MOUNT_PATH -> writeFreeBsdStatfs(statfsAddress, 0, "sysfs", "sysfs", SYS_MOUNT_PATH);
            case DEV_MOUNT_PATH -> writeFreeBsdStatfs(statfsAddress, 0, "devfs", "devfs", DEV_MOUNT_PATH);
            default -> writeFreeBsdStatfs(statfsAddress, 0, "jriscvfs", "jriscv", mount.guestPath());
        }
    }

    /// Writes one zero-initialized FreeBSD RISC-V `struct statfs` for a synthetic mount.
    private void writeFreeBsdStatfs(
            long statfsAddress,
            long blockCount,
            String fileSystemType,
            String mountSource,
            String mountPoint) {
        memory.clear(statfsAddress, FREEBSD_STATFS_SIZE);
        memory.writeInt(statfsAddress, FREEBSD_STATFS_VERSION);
        memory.writeLong(statfsAddress + FREEBSD_STATFS_BLOCK_SIZE_OFFSET, STATFS_BLOCK_SIZE);
        memory.writeLong(statfsAddress + FREEBSD_STATFS_IO_SIZE_OFFSET, STATFS_BLOCK_SIZE);
        memory.writeLong(statfsAddress + FREEBSD_STATFS_BLOCK_COUNT_OFFSET, blockCount);
        memory.writeLong(statfsAddress + FREEBSD_STATFS_FREE_BLOCK_COUNT_OFFSET, blockCount);
        memory.writeLong(statfsAddress + FREEBSD_STATFS_AVAILABLE_BLOCK_COUNT_OFFSET, blockCount);
        memory.writeLong(statfsAddress + FREEBSD_STATFS_FILE_COUNT_OFFSET, STATFS_FILE_COUNT);
        memory.writeLong(statfsAddress + FREEBSD_STATFS_FREE_FILE_COUNT_OFFSET, STATFS_FILE_COUNT);
        memory.writeInt(statfsAddress + FREEBSD_STATFS_NAME_MAX_OFFSET, (int) STATFS_NAME_MAX);
        memory.writeInt(
                statfsAddress + FREEBSD_STATFS_OWNER_OFFSET,
                GuestCredentials.idToInt(credentials.effectiveUserId()));
        memory.writeInt(statfsAddress + FREEBSD_STATFS_FILE_SYSTEM_ID_OFFSET, 1);
        writeFreeBsdStatfsString(
                statfsAddress + FREEBSD_STATFS_TYPE_NAME_OFFSET,
                FREEBSD_STATFS_TYPE_NAME_SIZE,
                fileSystemType);
        writeFreeBsdStatfsString(
                statfsAddress + FREEBSD_STATFS_MOUNT_SOURCE_OFFSET,
                FREEBSD_STATFS_MOUNT_NAME_SIZE,
                mountSource);
        writeFreeBsdStatfsString(
                statfsAddress + FREEBSD_STATFS_MOUNT_POINT_OFFSET,
                FREEBSD_STATFS_MOUNT_NAME_SIZE,
                mountPoint);
    }

    /// Writes a null-terminated UTF-8 string into one fixed-size FreeBSD `struct statfs` character field.
    private void writeFreeBsdStatfsString(long address, int capacity, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        int length = Math.min(bytes.length, capacity - 1);
        memory.writeBytes(address, bytes, 0, length);
        memory.writeByte(address + length, (byte) 0);
    }

    /// Clears the FreeBSD RISC-V syscall error indicator in a successful `fork` child.
    @Override
    protected void initializeProcessChildSyscallResult(RiscVThreadState child) {
        child.setRegister(5, 0);
    }

    /// Passes the initial stack pointer in `a0` as required by the FreeBSD RISC-V process ABI.
    @Override
    protected void initializeExecEntryState(RiscVThreadState state, long stackPointer) {
        state.setRegister(10, stackPointer);
    }

    /// Creates a child-process FreeBSD syscall handler.
    @Override
    protected GuestSyscalls createChildSyscalls(Memory childMemory, GuestProcess childProcess) {
        return new FreeBsdGuestSyscalls(this, childMemory, childProcess);
    }
}
