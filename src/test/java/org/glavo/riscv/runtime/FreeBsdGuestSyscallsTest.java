// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.riscv.runtime;

import org.glavo.riscv.memory.Memory;
import org.glavo.riscv.parser.ElfImage;
import org.glavo.riscv.runtime.net.GuestNetworkMode;
import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/// Tests FreeBSD RISC-V syscall ABI layouts, error reporting, and filesystem compatibility entry points.
@NotNullByDefault
public final class FreeBsdGuestSyscallsTest {
    /// A temporary bind-mounted root for filesystem syscall tests.
    @TempDir
    private Path tempDirectory;

    /// The guest program counter supplied to direct syscall tests.
    private static final long TEST_PC = Memory.DEFAULT_BASE_ADDRESS;

    /// The FreeBSD syscall number for `read`.
    private static final long FREEBSD_SYS_READ = 3;

    /// The FreeBSD syscall number for `write`.
    private static final long FREEBSD_SYS_WRITE = 4;

    /// The FreeBSD syscall number for `fork`.
    private static final long FREEBSD_SYS_FORK = 2;

    /// The FreeBSD syscall number for `open`.
    private static final long FREEBSD_SYS_OPEN = 5;

    /// The FreeBSD syscall number for `close`.
    private static final long FREEBSD_SYS_CLOSE = 6;

    /// The FreeBSD syscall number for `wait4`.
    private static final long FREEBSD_SYS_WAIT4 = 7;

    /// The FreeBSD syscall number for legacy `pipe`.
    private static final long FREEBSD_SYS_PIPE = 42;

    /// The FreeBSD syscall number for `link`.
    private static final long FREEBSD_SYS_LINK = 9;

    /// The FreeBSD syscall number for `unlink`.
    private static final long FREEBSD_SYS_UNLINK = 10;

    /// The FreeBSD syscall number for `chmod`.
    private static final long FREEBSD_SYS_CHMOD = 15;

    /// The FreeBSD syscall number for `chown`.
    private static final long FREEBSD_SYS_CHOWN = 16;

    /// The FreeBSD syscall number for `setuid`.
    private static final long FREEBSD_SYS_SETUID = 23;

    /// The FreeBSD syscall number for `recvmsg`.
    private static final long FREEBSD_SYS_RECVMSG = 27;

    /// The FreeBSD syscall number for `sendmsg`.
    private static final long FREEBSD_SYS_SENDMSG = 28;

    /// The FreeBSD syscall number for `recvfrom`.
    private static final long FREEBSD_SYS_RECVFROM = 29;

    /// The FreeBSD syscall number for `getpeername`.
    private static final long FREEBSD_SYS_GETPEERNAME = 31;

    /// The FreeBSD syscall number for `getsockname`.
    private static final long FREEBSD_SYS_GETSOCKNAME = 32;

    /// The FreeBSD syscall number for `symlink`.
    private static final long FREEBSD_SYS_SYMLINK = 57;

    /// The FreeBSD syscall number for `readlink`.
    private static final long FREEBSD_SYS_READLINK = 58;

    /// The FreeBSD syscall number for `msync`.
    private static final long FREEBSD_SYS_MSYNC = 65;

    /// The FreeBSD syscall number for `madvise`.
    private static final long FREEBSD_SYS_MADVISE = 75;

    /// The FreeBSD syscall number for `mincore`.
    private static final long FREEBSD_SYS_MINCORE = 78;

    /// The FreeBSD syscall number for `getgroups`.
    private static final long FREEBSD_SYS_GETGROUPS = 79;

    /// The FreeBSD syscall number for `setgroups`.
    private static final long FREEBSD_SYS_SETGROUPS = 80;

    /// The FreeBSD syscall number for `getpgrp`.
    private static final long FREEBSD_SYS_GETPGRP = 81;

    /// The FreeBSD syscall number for `setpgid`.
    private static final long FREEBSD_SYS_SETPGID = 82;

    /// The FreeBSD syscall number for `getlogin`.
    private static final long FREEBSD_SYS_GETLOGIN = 49;

    /// The FreeBSD syscall number for `setlogin`.
    private static final long FREEBSD_SYS_SETLOGIN = 50;

    /// The FreeBSD syscall number for `setitimer`.
    private static final long FREEBSD_SYS_SETITIMER = 83;

    /// The FreeBSD syscall number for `getitimer`.
    private static final long FREEBSD_SYS_GETITIMER = 86;

    /// The FreeBSD syscall number for `getdtablesize`.
    private static final long FREEBSD_SYS_GETDTABLESIZE = 89;

    /// The FreeBSD syscall number for `fcntl`.
    private static final long FREEBSD_SYS_FCNTL = 92;

    /// The FreeBSD syscall number for `select`.
    private static final long FREEBSD_SYS_SELECT = 93;

    /// The FreeBSD syscall number for `setpriority`.
    private static final long FREEBSD_SYS_SETPRIORITY = 96;

    /// The FreeBSD syscall number for `socket`.
    private static final long FREEBSD_SYS_SOCKET = 97;

    /// The FreeBSD syscall number for `connect`.
    private static final long FREEBSD_SYS_CONNECT = 98;

    /// The FreeBSD syscall number for `getpriority`.
    private static final long FREEBSD_SYS_GETPRIORITY = 100;

    /// The FreeBSD syscall number for `bind`.
    private static final long FREEBSD_SYS_BIND = 104;

    /// The FreeBSD syscall number for `setsockopt`.
    private static final long FREEBSD_SYS_SETSOCKOPT = 105;

    /// The FreeBSD syscall number for `listen`.
    private static final long FREEBSD_SYS_LISTEN = 106;

    /// The FreeBSD syscall number for `getrusage`.
    private static final long FREEBSD_SYS_GETRUSAGE = 117;

    /// The FreeBSD syscall number for `getsockopt`.
    private static final long FREEBSD_SYS_GETSOCKOPT = 118;

    /// The FreeBSD syscall number for `fchown`.
    private static final long FREEBSD_SYS_FCHOWN = 123;

    /// The FreeBSD syscall number for `fchmod`.
    private static final long FREEBSD_SYS_FCHMOD = 124;

    /// The FreeBSD syscall number for `flock`.
    private static final long FREEBSD_SYS_FLOCK = 131;

    /// The FreeBSD syscall number for `setreuid`.
    private static final long FREEBSD_SYS_SETREUID = 126;

    /// The FreeBSD syscall number for `setregid`.
    private static final long FREEBSD_SYS_SETREGID = 127;

    /// The FreeBSD syscall number for `rename`.
    private static final long FREEBSD_SYS_RENAME = 128;

    /// The FreeBSD syscall number for `socketpair`.
    private static final long FREEBSD_SYS_SOCKETPAIR = 135;

    /// The FreeBSD syscall number for `setsid`.
    private static final long FREEBSD_SYS_SETSID = 147;

    /// The FreeBSD syscall number for `pathconf`.
    private static final long FREEBSD_SYS_PATHCONF = 191;

    /// The FreeBSD syscall number for `fpathconf`.
    private static final long FREEBSD_SYS_FPATHCONF = 192;

    /// The FreeBSD syscall number for `mkdir`.
    private static final long FREEBSD_SYS_MKDIR = 136;

    /// The FreeBSD syscall number for `rmdir`.
    private static final long FREEBSD_SYS_RMDIR = 137;

    /// The FreeBSD syscall number for `setgid`.
    private static final long FREEBSD_SYS_SETGID = 181;

    /// The FreeBSD syscall number for `setegid`.
    private static final long FREEBSD_SYS_SETEGID = 182;

    /// The FreeBSD syscall number for `seteuid`.
    private static final long FREEBSD_SYS_SETEUID = 183;

    /// The FreeBSD syscall number for `__sysctl`.
    private static final long FREEBSD_SYS___SYSCTL = 202;

    /// The FreeBSD syscall number for `mlock`.
    private static final long FREEBSD_SYS_MLOCK = 203;

    /// The FreeBSD syscall number for `munlock`.
    private static final long FREEBSD_SYS_MUNLOCK = 204;

    /// The FreeBSD syscall number for `getpgid`.
    private static final long FREEBSD_SYS_GETPGID = 207;

    /// The FreeBSD syscall number for `poll`.
    private static final long FREEBSD_SYS_POLL = 209;

    /// The FreeBSD syscall number for `clock_gettime`.
    private static final long FREEBSD_SYS_CLOCK_GETTIME = 232;

    /// The FreeBSD syscall number for `clock_getres`.
    private static final long FREEBSD_SYS_CLOCK_GETRES = 234;

    /// The FreeBSD syscall number for `nanosleep`.
    private static final long FREEBSD_SYS_NANOSLEEP = 240;

    /// The FreeBSD syscall number for `clock_nanosleep`.
    private static final long FREEBSD_SYS_CLOCK_NANOSLEEP = 244;

    /// The FreeBSD syscall number for `issetugid`.
    private static final long FREEBSD_SYS_ISSETUGID = 253;

    /// The FreeBSD syscall number for `preadv`.
    private static final long FREEBSD_SYS_PREADV = 289;

    /// The FreeBSD syscall number for `pwritev`.
    private static final long FREEBSD_SYS_PWRITEV = 290;

    /// The FreeBSD syscall number for `getsid`.
    private static final long FREEBSD_SYS_GETSID = 310;

    /// The FreeBSD syscall number for `setresuid`.
    private static final long FREEBSD_SYS_SETRESUID = 311;

    /// The FreeBSD syscall number for `setresgid`.
    private static final long FREEBSD_SYS_SETRESGID = 312;

    /// The FreeBSD syscall number for the legacy `yield` entry point.
    private static final long FREEBSD_SYS_YIELD = 321;

    /// The FreeBSD syscall number for `mlockall`.
    private static final long FREEBSD_SYS_MLOCKALL = 324;

    /// The FreeBSD syscall number for `munlockall`.
    private static final long FREEBSD_SYS_MUNLOCKALL = 325;

    /// The FreeBSD syscall number for `sched_setparam`.
    private static final long FREEBSD_SYS_SCHED_SETPARAM = 327;

    /// The FreeBSD syscall number for `sched_getparam`.
    private static final long FREEBSD_SYS_SCHED_GETPARAM = 328;

    /// The FreeBSD syscall number for `sched_setscheduler`.
    private static final long FREEBSD_SYS_SCHED_SETSCHEDULER = 329;

    /// The FreeBSD syscall number for `sched_getscheduler`.
    private static final long FREEBSD_SYS_SCHED_GETSCHEDULER = 330;

    /// The FreeBSD syscall number for `sched_yield`.
    private static final long FREEBSD_SYS_SCHED_YIELD = 331;

    /// The FreeBSD syscall number for `sched_get_priority_max`.
    private static final long FREEBSD_SYS_SCHED_GET_PRIORITY_MAX = 332;

    /// The FreeBSD syscall number for `sched_get_priority_min`.
    private static final long FREEBSD_SYS_SCHED_GET_PRIORITY_MIN = 333;

    /// The FreeBSD syscall number for `sched_rr_get_interval`.
    private static final long FREEBSD_SYS_SCHED_RR_GET_INTERVAL = 334;

    /// The FreeBSD syscall number for `getresuid`.
    private static final long FREEBSD_SYS_GETRESUID = 360;

    /// The FreeBSD syscall number for `getresgid`.
    private static final long FREEBSD_SYS_GETRESGID = 361;

    /// The FreeBSD syscall number for `fchmodat`.
    private static final long FREEBSD_SYS_FCHMODAT = 490;

    /// The FreeBSD syscall number for `kqueue`.
    private static final long FREEBSD_SYS_KQUEUE = 362;

    /// The FreeBSD syscall number for `pselect`.
    private static final long FREEBSD_SYS_PSELECT = 522;

    /// The FreeBSD syscall number for `mmap`.
    private static final long FREEBSD_SYS_MMAP = 477;

    /// The FreeBSD syscall number for `lseek`.
    private static final long FREEBSD_SYS_LSEEK = 478;

    /// The FreeBSD syscall number for `closefrom`.
    private static final long FREEBSD_SYS_CLOSEFROM = 509;

    /// The FreeBSD syscall number for `lpathconf`.
    private static final long FREEBSD_SYS_LPATHCONF = 513;

    /// The FreeBSD syscall number for `posix_fallocate`.
    private static final long FREEBSD_SYS_POSIX_FALLOCATE = 530;

    /// The FreeBSD syscall number for `posix_fadvise`.
    private static final long FREEBSD_SYS_POSIX_FADVISE = 531;

    /// The FreeBSD syscall number for `wait6`.
    private static final long FREEBSD_SYS_WAIT6 = 532;

    /// The FreeBSD syscall number for `pipe2`.
    private static final long FREEBSD_SYS_PIPE2 = 542;

    /// The FreeBSD syscall number for `ppoll`.
    private static final long FREEBSD_SYS_PPOLL = 545;

    /// The FreeBSD syscall number for `futimens`.
    private static final long FREEBSD_SYS_FUTIMENS = 546;

    /// The FreeBSD syscall number for `utimensat`.
    private static final long FREEBSD_SYS_UTIMENSAT = 547;

    /// The FreeBSD syscall number for `fstat`.
    private static final long FREEBSD_SYS_FSTAT = 551;

    /// The FreeBSD syscall number for `fstatat`.
    private static final long FREEBSD_SYS_FSTATAT = 552;

    /// The FreeBSD syscall number for `getdirentries`.
    private static final long FREEBSD_SYS_GETDIRENTRIES = 554;

    /// The FreeBSD syscall number for `statfs`.
    private static final long FREEBSD_SYS_STATFS = 555;

    /// The FreeBSD syscall number for `fstatfs`.
    private static final long FREEBSD_SYS_FSTATFS = 556;

    /// The FreeBSD syscall number for the current `kevent` ABI.
    private static final long FREEBSD_SYS_KEVENT = 560;

    /// The FreeBSD syscall number for `cpuset_getdomain`.
    private static final long FREEBSD_SYS_CPUSET_GETDOMAIN = 561;

    /// The FreeBSD syscall number for `cpuset_setdomain`.
    private static final long FREEBSD_SYS_CPUSET_SETDOMAIN = 562;

    /// The FreeBSD syscall number for `getrandom`.
    private static final long FREEBSD_SYS_GETRANDOM = 563;

    /// The FreeBSD syscall number for `_umtx_op`.
    private static final long FREEBSD_SYS_UMTX_OP = 454;

    /// The FreeBSD syscall number for `thr_self`.
    private static final long FREEBSD_SYS_THR_SELF = 432;

    /// The FreeBSD syscall number for `thr_kill`.
    private static final long FREEBSD_SYS_THR_KILL = 433;

    /// The FreeBSD syscall number for `thr_suspend`.
    private static final long FREEBSD_SYS_THR_SUSPEND = 442;

    /// The FreeBSD syscall number for `thr_wake`.
    private static final long FREEBSD_SYS_THR_WAKE = 443;

    /// The FreeBSD syscall number for `thr_set_name`.
    private static final long FREEBSD_SYS_THR_SET_NAME = 464;

    /// The FreeBSD syscall number for `thr_kill2`.
    private static final long FREEBSD_SYS_THR_KILL2 = 481;

    /// The FreeBSD syscall number for `cpuset`.
    private static final long FREEBSD_SYS_CPUSET = 484;

    /// The FreeBSD syscall number for `cpuset_setid`.
    private static final long FREEBSD_SYS_CPUSET_SETID = 485;

    /// The FreeBSD syscall number for `cpuset_getid`.
    private static final long FREEBSD_SYS_CPUSET_GETID = 486;

    /// The FreeBSD syscall number for `cpuset_getaffinity`.
    private static final long FREEBSD_SYS_CPUSET_GETAFFINITY = 487;

    /// The FreeBSD syscall number for `cpuset_setaffinity`.
    private static final long FREEBSD_SYS_CPUSET_SETAFFINITY = 488;

    /// The FreeBSD syscall number for `copy_file_range`.
    private static final long FREEBSD_SYS_COPY_FILE_RANGE = 569;

    /// The FreeBSD syscall number for `close_range`.
    private static final long FREEBSD_SYS_CLOSE_RANGE = 575;

    /// The FreeBSD syscall number for `fspacectl`.
    private static final long FREEBSD_SYS_FSPACECTL = 580;

    /// The FreeBSD syscall number for `sched_getcpu`.
    private static final long FREEBSD_SYS_SCHED_GETCPU = 581;

    /// The FreeBSD syscall number for `kqueuex`.
    private static final long FREEBSD_SYS_KQUEUEX = 583;

    /// The FreeBSD syscall number for `membarrier`.
    private static final long FREEBSD_SYS_MEMBARRIER = 584;

    /// The FreeBSD syscall number for `timerfd_create`.
    private static final long FREEBSD_SYS_TIMERFD_CREATE = 585;

    /// The FreeBSD syscall number for `timerfd_gettime`.
    private static final long FREEBSD_SYS_TIMERFD_GETTIME = 586;

    /// The FreeBSD syscall number for `timerfd_settime`.
    private static final long FREEBSD_SYS_TIMERFD_SETTIME = 587;

    /// The current FreeBSD syscall number for `getgroups`.
    private static final long FREEBSD_SYS_GETGROUPS_CURRENT = 595;

    /// The current FreeBSD syscall number for `setgroups`.
    private static final long FREEBSD_SYS_SETGROUPS_CURRENT = 596;

    /// The FreeBSD syscall number for `renameat2`.
    private static final long FREEBSD_SYS_RENAMEAT2 = 602;

    /// FreeBSD `AT_FDCWD`.
    private static final long FREEBSD_AT_FDCWD = -100;

    /// FreeBSD `O_DIRECTORY`.
    private static final long FREEBSD_O_DIRECTORY = 0x0002_0000;

    /// FreeBSD `O_RDWR`.
    private static final long FREEBSD_O_RDWR = 2;

    /// FreeBSD `O_NONBLOCK`.
    private static final long FREEBSD_O_NONBLOCK = 0x4;

    /// FreeBSD `O_APPEND`.
    private static final long FREEBSD_O_APPEND = 0x8;

    /// FreeBSD `O_CLOEXEC`.
    private static final long FREEBSD_O_CLOEXEC = 0x0010_0000;

    /// FreeBSD `COPY_FILE_RANGE_CLONE`.
    private static final long FREEBSD_COPY_FILE_RANGE_CLONE = 0x0080_0000L;

    /// FreeBSD `SPACECTL_DEALLOC`.
    private static final long FREEBSD_SPACECTL_DEALLOC = 1;

    /// The byte offset of `r_len` inside FreeBSD RISC-V `struct spacectl_range`.
    private static final long FREEBSD_SPACECTL_RANGE_LENGTH_OFFSET = Long.BYTES;

    /// FreeBSD `_PC_NAME_MAX`.
    private static final long FREEBSD_PC_NAME_MAX = 4;

    /// FreeBSD `_PC_PATH_MAX`.
    private static final long FREEBSD_PC_PATH_MAX = 5;

    /// FreeBSD `_PC_PIPE_BUF`.
    private static final long FREEBSD_PC_PIPE_BUF = 6;

    /// FreeBSD `_PC_FILESIZEBITS`.
    private static final long FREEBSD_PC_FILESIZEBITS = 12;

    /// FreeBSD `PROT_READ`.
    private static final long FREEBSD_PROT_READ = 0x1;

    /// FreeBSD `PROT_WRITE`.
    private static final long FREEBSD_PROT_WRITE = 0x2;

    /// FreeBSD `MAP_PRIVATE`.
    private static final long FREEBSD_MAP_PRIVATE = 0x2;

    /// FreeBSD `MAP_ANON`.
    private static final long FREEBSD_MAP_ANON = 0x1000;

    /// FreeBSD `MS_ASYNC`.
    private static final long FREEBSD_MS_ASYNC = 0x1;

    /// FreeBSD `MS_INVALIDATE`.
    private static final long FREEBSD_MS_INVALIDATE = 0x2;

    /// FreeBSD `MADV_FREE`.
    private static final long FREEBSD_MADV_FREE = 5;

    /// FreeBSD `MADV_NOCORE`.
    private static final long FREEBSD_MADV_NOCORE = 8;

    /// FreeBSD `MCL_CURRENT`.
    private static final long FREEBSD_MCL_CURRENT = 1;

    /// FreeBSD `MCL_FUTURE`.
    private static final long FREEBSD_MCL_FUTURE = 2;

    /// FreeBSD `SCHED_FIFO`.
    private static final long FREEBSD_SCHED_FIFO = 1;

    /// FreeBSD `SCHED_OTHER`.
    private static final long FREEBSD_SCHED_OTHER = 2;

    /// FreeBSD `SCHED_RR`.
    private static final long FREEBSD_SCHED_RR = 3;

    /// FreeBSD `CPU_LEVEL_ROOT`.
    private static final long FREEBSD_CPU_LEVEL_ROOT = 1;

    /// FreeBSD `CPU_LEVEL_CPUSET`.
    private static final long FREEBSD_CPU_LEVEL_CPUSET = 2;

    /// FreeBSD `CPU_LEVEL_WHICH`.
    private static final long FREEBSD_CPU_LEVEL_WHICH = 3;

    /// FreeBSD `CPU_WHICH_TID`.
    private static final long FREEBSD_CPU_WHICH_TID = 1;

    /// FreeBSD `CPU_WHICH_PID`.
    private static final long FREEBSD_CPU_WHICH_PID = 2;

    /// FreeBSD `CPU_WHICH_CPUSET`.
    private static final long FREEBSD_CPU_WHICH_CPUSET = 3;

    /// FreeBSD `DOMAINSET_POLICY_ROUNDROBIN`.
    private static final long FREEBSD_DOMAINSET_POLICY_ROUNDROBIN = 1;

    /// FreeBSD `DOMAINSET_POLICY_FIRSTTOUCH`.
    private static final long FREEBSD_DOMAINSET_POLICY_FIRSTTOUCH = 2;

    /// FreeBSD `DOMAINSET_POLICY_PREFER`.
    private static final long FREEBSD_DOMAINSET_POLICY_PREFER = 3;

    /// FreeBSD `DOMAINSET_POLICY_INTERLEAVE`.
    private static final long FREEBSD_DOMAINSET_POLICY_INTERLEAVE = 4;

    /// FreeBSD `ITIMER_REAL`.
    private static final long FREEBSD_ITIMER_REAL = 0;

    /// FreeBSD `ITIMER_PROF`.
    private static final long FREEBSD_ITIMER_PROF = 2;

    /// The guest page size used by direct virtual-memory syscall tests.
    private static final long GUEST_PAGE_SIZE = 4096;

    /// The FreeBSD `(uid_t) -1` and `(gid_t) -1` no-change sentinel.
    private static final long FREEBSD_ID_UNCHANGED = 0xffff_ffffL;

    /// FreeBSD `UTIME_NOW`.
    private static final long FREEBSD_UTIME_NOW = -1;

    /// FreeBSD `UTIME_OMIT`.
    private static final long FREEBSD_UTIME_OMIT = -2;

    /// FreeBSD `F_GETFD`.
    private static final long FREEBSD_F_GETFD = 1;

    /// FreeBSD `F_SETFD`.
    private static final long FREEBSD_F_SETFD = 2;

    /// FreeBSD `F_GETFL`.
    private static final long FREEBSD_F_GETFL = 3;

    /// FreeBSD `F_GETOWN`.
    private static final long FREEBSD_F_GETOWN = 5;

    /// FreeBSD `F_GETLK`.
    private static final long FREEBSD_F_GETLK = 11;

    /// FreeBSD `F_SETLK`.
    private static final long FREEBSD_F_SETLK = 12;

    /// FreeBSD `F_SETLKW`.
    private static final long FREEBSD_F_SETLKW = 13;

    /// FreeBSD `F_SETFL`.
    private static final long FREEBSD_F_SETFL = 4;

    /// FreeBSD `F_DUP2FD_CLOEXEC`.
    private static final long FREEBSD_F_DUP2FD_CLOEXEC = 18;

    /// FreeBSD `FD_CLOFORK`.
    private static final long FREEBSD_FD_CLOFORK = 4;

    /// FreeBSD `FD_CLOEXEC`.
    private static final long FREEBSD_FD_CLOEXEC = 1;

    /// FreeBSD `KQUEUE_CLOEXEC`.
    private static final long FREEBSD_KQUEUE_CLOEXEC = 1;

    /// FreeBSD `_UMTX_OP_WAIT_UINT_PRIVATE`.
    private static final long FREEBSD_UMTX_OP_WAIT_UINT_PRIVATE = 0x0f;

    /// The byte size of FreeBSD RISC-V `struct _umtx_time`.
    private static final long FREEBSD_UMTX_TIME_SIZE = 3L * Long.BYTES;

    /// The byte offset of `_flags` inside FreeBSD RISC-V `struct _umtx_time`.
    private static final long FREEBSD_UMTX_TIME_FLAGS_OFFSET = 2L * Long.BYTES;

    /// The byte offset of `_clockid` inside FreeBSD RISC-V `struct _umtx_time`.
    private static final long FREEBSD_UMTX_TIME_CLOCK_ID_OFFSET = 2L * Long.BYTES + Integer.BYTES;

    /// FreeBSD `UMTX_ABSTIME`.
    private static final long FREEBSD_UMTX_ABSTIME = 0x01;

    /// FreeBSD `CLOSE_RANGE_CLOEXEC`.
    private static final long FREEBSD_CLOSE_RANGE_CLOEXEC = 1L << 2;

    /// FreeBSD `CLOSE_RANGE_CLOFORK`.
    private static final long FREEBSD_CLOSE_RANGE_CLOFORK = 1L << 3;

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

    /// FreeBSD `LOCK_NB`.
    private static final long FREEBSD_LOCK_NB = 0x04;

    /// FreeBSD `LOCK_UN`.
    private static final long FREEBSD_LOCK_UN = 0x08;

    /// FreeBSD `POLLIN`.
    private static final int FREEBSD_POLLIN = 0x0001;

    /// FreeBSD `POLLNVAL`.
    private static final int FREEBSD_POLLNVAL = 0x0020;

    /// FreeBSD `CLOCK_REALTIME`.
    private static final long FREEBSD_CLOCK_REALTIME = 0;

    /// FreeBSD `CLOCK_MONOTONIC`.
    private static final long FREEBSD_CLOCK_MONOTONIC = 4;

    /// FreeBSD `CLOCK_UPTIME`.
    private static final long FREEBSD_CLOCK_UPTIME = 5;

    /// FreeBSD `CLOCK_REALTIME_FAST` and `CLOCK_REALTIME_COARSE`.
    private static final long FREEBSD_CLOCK_REALTIME_FAST = 10;

    /// FreeBSD `CLOCK_SECOND`.
    private static final long FREEBSD_CLOCK_SECOND = 13;

    /// FreeBSD `CLOCK_PROCESS_CPUTIME_ID`.
    private static final long FREEBSD_CLOCK_PROCESS_CPUTIME_ID = 15;

    /// FreeBSD `CLOCK_TAI`.
    private static final long FREEBSD_CLOCK_TAI = 16;

    /// FreeBSD `TIMER_ABSTIME`.
    private static final long FREEBSD_TIMER_ABSTIME = 1;

    /// The byte offset of `it_value` inside FreeBSD RISC-V `struct itimerspec`.
    private static final long FREEBSD_ITIMERSPEC_VALUE_OFFSET = 2L * Long.BYTES;

    /// The byte offset of `tv_nsec` inside FreeBSD RISC-V `struct timespec`.
    private static final long FREEBSD_TIMESPEC_NANOSECONDS_OFFSET = Long.BYTES;

    /// FreeBSD `P_PID`.
    private static final long FREEBSD_WAIT_ID_PROCESS = 0;

    /// FreeBSD `WNOWAIT`.
    private static final long FREEBSD_WAIT_NO_WAIT = 0x8;

    /// FreeBSD `WEXITED`.
    private static final long FREEBSD_WAIT_EXITED = 0x10;

    /// FreeBSD `SIGCHLD`.
    private static final int FREEBSD_SIGCHLD = 20;

    /// FreeBSD `CLD_EXITED`.
    private static final int FREEBSD_CLD_EXITED = 1;

    /// The byte offset of `si_code` inside FreeBSD RISC-V `siginfo_t`.
    private static final long FREEBSD_SIGNAL_INFO_CODE_OFFSET = 2L * Integer.BYTES;

    /// The byte offset of `si_pid` inside FreeBSD RISC-V `siginfo_t`.
    private static final long FREEBSD_SIGNAL_INFO_PROCESS_ID_OFFSET = 3L * Integer.BYTES;

    /// The byte offset of `si_uid` inside FreeBSD RISC-V `siginfo_t`.
    private static final long FREEBSD_SIGNAL_INFO_USER_ID_OFFSET = 4L * Integer.BYTES;

    /// The byte offset of `si_status` inside FreeBSD RISC-V `siginfo_t`.
    private static final long FREEBSD_SIGNAL_INFO_STATUS_OFFSET = 5L * Integer.BYTES;

    /// The byte size of FreeBSD RISC-V `struct __wrusage`.
    private static final long FREEBSD_WRUSAGE_SIZE = 288;

    /// FreeBSD address family number for Unix-domain sockets.
    private static final long FREEBSD_AF_UNIX = 1;

    /// FreeBSD address family number for IPv4 sockets.
    private static final long FREEBSD_AF_INET = 2;

    /// FreeBSD stream socket type.
    private static final long FREEBSD_SOCK_STREAM = 1;

    /// FreeBSD datagram socket type.
    private static final long FREEBSD_SOCK_DGRAM = 2;

    /// FreeBSD `SOCK_CLOEXEC`.
    private static final long FREEBSD_SOCK_CLOEXEC = 0x1000_0000L;

    /// FreeBSD `SOCK_NONBLOCK`.
    private static final long FREEBSD_SOCK_NONBLOCK = 0x2000_0000L;

    /// FreeBSD TCP protocol number.
    private static final long FREEBSD_IPPROTO_TCP = 6;

    /// FreeBSD UDP protocol number.
    private static final long FREEBSD_IPPROTO_UDP = 17;

    /// FreeBSD generic socket option level.
    private static final long FREEBSD_SOL_SOCKET = 0xffff;

    /// FreeBSD `SO_KEEPALIVE`.
    private static final long FREEBSD_SO_KEEPALIVE = 0x8;

    /// FreeBSD `SO_ERROR`.
    private static final long FREEBSD_SO_ERROR = 0x1007;

    /// FreeBSD `MSG_NOSIGNAL`.
    private static final long FREEBSD_MSG_NOSIGNAL = 0x2_0000;

    /// Byte size of FreeBSD `struct sockaddr_in`.
    private static final int FREEBSD_SOCKADDR_IN_SIZE = 16;

    /// Byte size of FreeBSD `struct sockaddr_un`.
    private static final int FREEBSD_SOCKADDR_UN_SIZE = 106;

    /// Byte offset of the family field inside a FreeBSD socket address.
    private static final long FREEBSD_SOCKADDR_FAMILY_OFFSET = 1;

    /// Byte offset of the network-endian port inside a FreeBSD Internet socket address.
    private static final long FREEBSD_SOCKADDR_PORT_OFFSET = 2;

    /// Byte offset of the IPv4 address inside FreeBSD `struct sockaddr_in`.
    private static final long FREEBSD_SOCKADDR_IN_ADDRESS_OFFSET = 4;

    /// Byte offset of `sun_path` inside FreeBSD `struct sockaddr_un`.
    private static final long FREEBSD_SOCKADDR_UN_PATH_OFFSET = 2;

    /// Byte offset of `msg_name` inside FreeBSD RISC-V `struct msghdr`.
    private static final long FREEBSD_MSGHDR_NAME_OFFSET = 0;

    /// Byte offset of `msg_namelen` inside FreeBSD RISC-V `struct msghdr`.
    private static final long FREEBSD_MSGHDR_NAME_LENGTH_OFFSET = Long.BYTES;

    /// Byte offset of `msg_iov` inside FreeBSD RISC-V `struct msghdr`.
    private static final long FREEBSD_MSGHDR_IOV_OFFSET = 2L * Long.BYTES;

    /// Byte offset of `msg_iovlen` inside FreeBSD RISC-V `struct msghdr`.
    private static final long FREEBSD_MSGHDR_IOV_LENGTH_OFFSET = 3L * Long.BYTES;

    /// Byte offset of `msg_flags` inside FreeBSD RISC-V `struct msghdr`.
    private static final long FREEBSD_MSGHDR_FLAGS_OFFSET = 5L * Long.BYTES + Integer.BYTES;

    /// Byte size of FreeBSD RISC-V `struct msghdr`.
    private static final long FREEBSD_MSGHDR_SIZE = 6L * Long.BYTES;

    /// Byte size of one FreeBSD RISC-V `struct iovec`.
    private static final long FREEBSD_IOVEC_SIZE = 2L * Long.BYTES;

    /// Byte offset of `iov_base` inside FreeBSD RISC-V `struct iovec`.
    private static final long FREEBSD_IOVEC_BASE_OFFSET = 0;

    /// Byte offset of `iov_len` inside FreeBSD RISC-V `struct iovec`.
    private static final long FREEBSD_IOVEC_LENGTH_OFFSET = Long.BYTES;

    /// Byte size of current FreeBSD RISC-V `struct kevent`.
    private static final long FREEBSD_KEVENT_SIZE = 64;

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

    /// FreeBSD user event filter.
    private static final short FREEBSD_EVFILT_USER = -11;

    /// FreeBSD `EV_ADD`.
    private static final int FREEBSD_EV_ADD = 0x0001;

    /// FreeBSD `EV_CLEAR`.
    private static final int FREEBSD_EV_CLEAR = 0x0020;

    /// FreeBSD `NOTE_TRIGGER`.
    private static final int FREEBSD_NOTE_TRIGGER = 0x0100_0000;

    /// FreeBSD `AT_SYMLINK_NOFOLLOW`.
    private static final long FREEBSD_AT_SYMLINK_NOFOLLOW = 0x0200;

    /// FreeBSD `AT_REMOVEDIR`, which is invalid for `fstatat`.
    private static final long FREEBSD_AT_REMOVEDIR = 0x0800;

    /// The FreeBSD errno value for `EBADF`.
    private static final long FREEBSD_EBADF = 9;

    /// The FreeBSD errno value for `EPERM`.
    private static final long FREEBSD_EPERM = 1;

    /// The FreeBSD errno value for `ENOENT`.
    private static final long FREEBSD_ENOENT = 2;

    /// The FreeBSD errno value for `ESRCH`.
    private static final long FREEBSD_ESRCH = 3;

    /// The FreeBSD errno value for `EFAULT`.
    private static final long FREEBSD_EFAULT = 14;

    /// The FreeBSD errno value for `EACCES`.
    private static final long FREEBSD_EACCES = 13;

    /// The FreeBSD errno value for `EDEADLK`.
    private static final long FREEBSD_EDEADLK = 11;

    /// The FreeBSD errno value for `EINVAL`.
    private static final long FREEBSD_EINVAL = 22;

    /// The FreeBSD errno value for `ERANGE`.
    private static final long FREEBSD_ERANGE = 34;

    /// The FreeBSD errno value for `ESPIPE`.
    private static final long FREEBSD_ESPIPE = 29;

    /// The FreeBSD errno value for `ENOTSUP`.
    private static final long FREEBSD_ENOTSUP = 45;

    /// The FreeBSD errno value for `EAGAIN`.
    private static final long FREEBSD_EAGAIN = 35;

    /// The FreeBSD errno value for `EINPROGRESS`.
    private static final long FREEBSD_EINPROGRESS = 36;

    /// The FreeBSD errno value for `ECHILD`.
    private static final long FREEBSD_ECHILD = 10;

    /// FreeBSD `PRIO_PROCESS`.
    private static final long FREEBSD_PRIO_PROCESS = 0;

    /// FreeBSD `MAXLOGNAME`, including the terminating NUL byte.
    private static final int FREEBSD_MAXLOGNAME = 33;

    /// The FreeBSD errno value for `ENAMETOOLONG`.
    private static final long FREEBSD_ENAMETOOLONG = 63;

    /// The FreeBSD errno value for `ETIMEDOUT`.
    private static final long FREEBSD_ETIMEDOUT = 60;

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

    /// The byte offset of `st_blocks` inside FreeBSD RISC-V `struct stat`.
    private static final long FREEBSD_STAT_BLOCK_COUNT_OFFSET = 120;

    /// The byte offset of `st_blksize` inside FreeBSD RISC-V `struct stat`.
    private static final long FREEBSD_STAT_BLOCK_SIZE_OFFSET = 128;

    /// FreeBSD `S_IFMT`.
    private static final int FREEBSD_STAT_FILE_TYPE_MASK = 0170000;

    /// FreeBSD `S_IFREG`.
    private static final int FREEBSD_STAT_REGULAR_FILE = 0100000;

    /// FreeBSD `S_IFLNK`.
    private static final int FREEBSD_STAT_SYMBOLIC_LINK = 0120000;

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

    /// FreeBSD `DT_DIR`.
    private static final int FREEBSD_DIRECTORY_ENTRY_DIRECTORY = 4;

    /// FreeBSD `DT_REG`.
    private static final int FREEBSD_DIRECTORY_ENTRY_REGULAR_FILE = 8;

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

    /// The synthetic filesystem block size exposed by the simulator.
    private static final long STATFS_BLOCK_SIZE = 4096;

    /// The synthetic filesystem block and inode count exposed by the simulator.
    private static final long STATFS_CAPACITY = 1_048_576;

    /// Verifies FreeBSD group, process-session, and random-source syscall behavior.
    @Test
    public void identityGroupSessionAndRandomSyscallsUseFreeBsdAbi() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long groupAddress = memory.baseAddress() + 0x100;
            long randomAddress = memory.baseAddress() + 0x200;

            invoke(state, FREEBSD_SYS_GETGROUPS, 0, 0);
            assertSuccess(state, 2);
            invoke(state, FREEBSD_SYS_GETGROUPS, 1, groupAddress);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_GETGROUPS, 2, groupAddress);
            assertSuccess(state, 2);
            assertEquals(GuestCredentials.DEFAULT_GROUP_ID, memory.readUnsignedInt(groupAddress));
            assertEquals(
                    GuestCredentials.DEFAULT_GROUP_ID,
                    memory.readUnsignedInt(groupAddress + Integer.BYTES));
            invoke(state, FREEBSD_SYS_GETGROUPS_CURRENT, 1, groupAddress);
            assertSuccess(state, 1);
            assertEquals(GuestCredentials.DEFAULT_GROUP_ID, memory.readUnsignedInt(groupAddress));
            invoke(state, FREEBSD_SYS_GETGROUPS, -1, groupAddress);
            assertError(state, FREEBSD_EINVAL);

            invoke(state, FREEBSD_SYS_SETGROUPS, 1025, groupAddress);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_SETGROUPS_CURRENT, 1024, groupAddress);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_SETGROUPS, 0, 0);
            assertError(state, FREEBSD_EPERM);

            invoke(state, FREEBSD_SYS_GETPGRP);
            assertSuccess(state, GuestProcess.PROCESS_GROUP_ID);
            invoke(state, FREEBSD_SYS_GETPGID, 0);
            assertSuccess(state, GuestProcess.PROCESS_GROUP_ID);
            invoke(state, FREEBSD_SYS_GETSID, 0);
            assertSuccess(state, GuestProcess.PROCESS_GROUP_ID);
            invoke(state, FREEBSD_SYS_SETPGID, 0, 0);
            assertError(state, FREEBSD_EPERM);
            invoke(state, FREEBSD_SYS_SETSID);
            assertError(state, FREEBSD_EPERM);
            invoke(state, FREEBSD_SYS_GETPGID, 999);
            assertError(state, FREEBSD_ESRCH);
            invoke(state, FREEBSD_SYS_GETSID, 999);
            assertError(state, FREEBSD_ESRCH);

            invoke(state, FREEBSD_SYS_GETRANDOM, randomAddress, 32, 3);
            assertSuccess(state, 32);
            assertTrue(!Arrays.equals(new byte[32], memory.readBytes(randomAddress, 32)));
            invoke(state, FREEBSD_SYS_GETRANDOM, randomAddress, 32, 4);
            assertError(state, FREEBSD_EINVAL);
        }
    }

    /// Verifies FreeBSD login-name bounds, privilege ordering, session sharing, and `setsid` isolation.
    @Test
    public void loginAndSessionSyscallsShareAndSplitState() {
        long loginAddress = Memory.DEFAULT_BASE_ADDRESS + 0x100;
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);

            invoke(state, FREEBSD_SYS_GETLOGIN, loginAddress, 1);
            assertSuccess(state, 0);
            assertEquals(0, memory.readUnsignedByte(loginAddress));
            invoke(state, FREEBSD_SYS_GETLOGIN, memory.endAddress(), 0);
            assertError(state, FREEBSD_ERANGE);
            invoke(state, FREEBSD_SYS_SETLOGIN, memory.endAddress());
            assertError(state, FREEBSD_EPERM);
        }

        GuestCredentials rootCredentials = GuestCredentials.of("root", 0, 0, "0", "/root", "/bin/sh");
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory, rootCredentials);

            invoke(state, FREEBSD_SYS_GETLOGIN, loginAddress, FREEBSD_MAXLOGNAME);
            assertSuccess(state, 0);
            assertEquals("root", readGuestString(memory, loginAddress, FREEBSD_MAXLOGNAME));

            writeGuestString(memory, loginAddress, "shared");
            invoke(state, FREEBSD_SYS_SETLOGIN, loginAddress);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_GETLOGIN, loginAddress, "shared".length());
            assertError(state, FREEBSD_ERANGE);
            invoke(state, FREEBSD_SYS_GETLOGIN, loginAddress, FREEBSD_MAXLOGNAME);
            assertSuccess(state, 0);
            assertEquals("shared", readGuestString(memory, loginAddress, FREEBSD_MAXLOGNAME));

            byte[] overlongLogin = new byte[FREEBSD_MAXLOGNAME];
            Arrays.fill(overlongLogin, (byte) 'x');
            memory.writeBytes(loginAddress, overlongLogin, 0, overlongLogin.length);
            invoke(state, FREEBSD_SYS_SETLOGIN, loginAddress);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_SETLOGIN, memory.endAddress());
            assertError(state, FREEBSD_EFAULT);

            GuestSyscalls parentSyscalls = state.syscalls();
            @Nullable GuestProcess childProcess = parentSyscalls.processRegistry.createChildProcess(parentSyscalls.process);
            assertTrue(childProcess != null);
            try (Memory childMemory = memory.fork();
                 GuestSyscalls childSyscalls = parentSyscalls.createChildSyscalls(childMemory, childProcess)) {
                RiscVThreadState childState = new RiscVThreadState(
                        childMemory,
                        0,
                        false,
                        ElfImage.ABSENT_ADDRESS,
                        ElfImage.ABSENT_ADDRESS,
                        childSyscalls);

                invoke(childState, FREEBSD_SYS_GETLOGIN, loginAddress, FREEBSD_MAXLOGNAME);
                assertSuccess(childState, 0);
                assertEquals("shared", readGuestString(childMemory, loginAddress, FREEBSD_MAXLOGNAME));

                writeGuestString(childMemory, loginAddress, "inherited");
                invoke(childState, FREEBSD_SYS_SETLOGIN, loginAddress);
                assertSuccess(childState, 0);
                invoke(state, FREEBSD_SYS_GETLOGIN, loginAddress, FREEBSD_MAXLOGNAME);
                assertSuccess(state, 0);
                assertEquals("inherited", readGuestString(memory, loginAddress, FREEBSD_MAXLOGNAME));

                assertEquals(0, childSyscalls.setpgid(0, GuestProcess.PROCESS_GROUP_ID));
                assertEquals(childProcess.id(), childSyscalls.setsid());
                assertEquals(GuestSyscalls.EPERM, childSyscalls.setsid());
                assertEquals(GuestSyscalls.EPERM, childSyscalls.setpgid(0, 0));
                invoke(childState, FREEBSD_SYS_GETSID, 0);
                assertSuccess(childState, childProcess.id());

                writeGuestString(childMemory, loginAddress, "child");
                invoke(childState, FREEBSD_SYS_SETLOGIN, loginAddress);
                assertSuccess(childState, 0);
                invoke(state, FREEBSD_SYS_GETLOGIN, loginAddress, FREEBSD_MAXLOGNAME);
                assertSuccess(state, 0);
                assertEquals("inherited", readGuestString(memory, loginAddress, FREEBSD_MAXLOGNAME));
            }
        }
    }

    /// Verifies persistent FreeBSD nice values, clamping, permissions, and negative successful returns.
    @Test
    public void prioritySyscallsPreserveFreeBsdResultSemantics() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);

            invoke(state, FREEBSD_SYS_GETPRIORITY, FREEBSD_PRIO_PROCESS, 0);
            assertSuccess(state, 0);

            invoke(state, FREEBSD_SYS_SETPRIORITY, FREEBSD_PRIO_PROCESS, 0, 5);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_GETPRIORITY, FREEBSD_PRIO_PROCESS, 0);
            assertSuccess(state, 5);

            invoke(state, FREEBSD_SYS_SETPRIORITY, FREEBSD_PRIO_PROCESS, 0, -1);
            assertError(state, FREEBSD_EACCES);
            invoke(state, FREEBSD_SYS_GETPRIORITY, FREEBSD_PRIO_PROCESS, 0);
            assertSuccess(state, 5);

            invoke(state, FREEBSD_SYS_SETPRIORITY, FREEBSD_PRIO_PROCESS, 0, 99);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_GETPRIORITY, FREEBSD_PRIO_PROCESS, 0);
            assertSuccess(state, 19);

            invoke(state, FREEBSD_SYS_GETPRIORITY, 3, 0);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_GETPRIORITY, FREEBSD_PRIO_PROCESS, 999);
            assertError(state, FREEBSD_ESRCH);
        }

        GuestCredentials rootCredentials = GuestCredentials.of("root", 0, 0, "0", "/root", "/bin/sh");
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory, rootCredentials);

            invoke(state, FREEBSD_SYS_SETPRIORITY, FREEBSD_PRIO_PROCESS, 0, -99);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_GETPRIORITY, FREEBSD_PRIO_PROCESS, 0);
            assertSuccess(state, -20);
        }

        GuestProcess parent = GuestProcess.initial();
        parent.setNiceValue(7);
        @Nullable GuestProcess child = new GuestProcessRegistry().createChildProcess(parent);
        assertTrue(child != null);
        assertEquals(7, child.niceValue());
    }

    /// Verifies FreeBSD credential mutations, saved-id transitions, and sticky set-id state.
    @Test
    public void credentialMutationSyscallsFollowFreeBsdSavedIdRules() {
        GuestCredentials rootCredentials = GuestCredentials.of("root", 0, 0, "0", "/root", "/bin/sh");
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory, rootCredentials);
            long groupAddress = memory.baseAddress() + 0x100;
            long idAddress = memory.baseAddress() + 0x200;

            invoke(state, FREEBSD_SYS_ISSETUGID);
            assertSuccess(state, 0);

            memory.writeInt(groupAddress, 42);
            memory.writeInt(groupAddress + Integer.BYTES, 0);
            memory.writeInt(groupAddress + 2L * Integer.BYTES, 42);
            invoke(state, FREEBSD_SYS_SETGROUPS, 3, groupAddress);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_GETGROUPS, 3, groupAddress);
            assertSuccess(state, 3);
            assertEquals(42, memory.readUnsignedInt(groupAddress));
            assertEquals(0, memory.readUnsignedInt(groupAddress + Integer.BYTES));
            assertEquals(42, memory.readUnsignedInt(groupAddress + 2L * Integer.BYTES));
            invoke(state, FREEBSD_SYS_GETGROUPS_CURRENT, 2, groupAddress);
            assertSuccess(state, 2);
            assertEquals(0, memory.readUnsignedInt(groupAddress));
            assertEquals(42, memory.readUnsignedInt(groupAddress + Integer.BYTES));

            memory.writeInt(groupAddress, 7);
            memory.writeInt(groupAddress + Integer.BYTES, 7);
            memory.writeInt(groupAddress + 2L * Integer.BYTES, 3);
            invoke(state, FREEBSD_SYS_SETGROUPS_CURRENT, 3, groupAddress);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_GETGROUPS_CURRENT, 3, groupAddress);
            assertSuccess(state, 2);
            assertEquals(3, memory.readUnsignedInt(groupAddress));
            assertEquals(7, memory.readUnsignedInt(groupAddress + Integer.BYTES));
            invoke(state, FREEBSD_SYS_GETGROUPS, 3, groupAddress);
            assertSuccess(state, 3);
            assertEquals(42, memory.readUnsignedInt(groupAddress));
            assertEquals(3, memory.readUnsignedInt(groupAddress + Integer.BYTES));
            assertEquals(7, memory.readUnsignedInt(groupAddress + 2L * Integer.BYTES));
            invoke(state, FREEBSD_SYS_ISSETUGID);
            assertSuccess(state, 1);

            invoke(state, FREEBSD_SYS_SETRESGID, FREEBSD_ID_UNCHANGED, 1234, FREEBSD_ID_UNCHANGED);
            assertSuccess(state, 0);
            assertFreeBsdIds(state, FREEBSD_SYS_GETRESGID, idAddress, 0, 1234, 0);
            invoke(state, FREEBSD_SYS_SETEGID, 0);
            assertSuccess(state, 0);
            assertFreeBsdIds(state, FREEBSD_SYS_GETRESGID, idAddress, 0, 0, 0);
            invoke(state, FREEBSD_SYS_SETREGID, 2345, 1234);
            assertSuccess(state, 0);
            assertFreeBsdIds(state, FREEBSD_SYS_GETRESGID, idAddress, 2345, 1234, 1234);
            invoke(state, FREEBSD_SYS_SETGID, 77);
            assertSuccess(state, 0);
            assertFreeBsdIds(state, FREEBSD_SYS_GETRESGID, idAddress, 77, 77, 77);

            invoke(state, FREEBSD_SYS_SETRESUID, FREEBSD_ID_UNCHANGED, 1234, FREEBSD_ID_UNCHANGED);
            assertSuccess(state, 0);
            assertFreeBsdIds(state, FREEBSD_SYS_GETRESUID, idAddress, 0, 1234, 0);
            invoke(state, FREEBSD_SYS_SETEUID, 0);
            assertSuccess(state, 0);
            assertFreeBsdIds(state, FREEBSD_SYS_GETRESUID, idAddress, 0, 0, 0);
            invoke(state, FREEBSD_SYS_SETREUID, 2345, 1234);
            assertSuccess(state, 0);
            assertFreeBsdIds(state, FREEBSD_SYS_GETRESUID, idAddress, 2345, 1234, 1234);
            invoke(state, FREEBSD_SYS_SETUID, 2345);
            assertSuccess(state, 0);
            assertFreeBsdIds(state, FREEBSD_SYS_GETRESUID, idAddress, 2345, 2345, 2345);

            invoke(state, FREEBSD_SYS_SETEUID, 9999);
            assertError(state, FREEBSD_EPERM);
            invoke(state, FREEBSD_SYS_SETEGID, 9999);
            assertError(state, FREEBSD_EPERM);
            invoke(state, FREEBSD_SYS_ISSETUGID);
            assertSuccess(state, 1);
        }
    }

    /// Verifies `fstat` and `fstatat` write the native FreeBSD RISC-V layout and report ABI errno values.
    @Test
    public void statSyscallsWriteFreeBsdLayoutAndErrno() throws Exception {
        Files.writeString(tempDirectory.resolve("message.txt"), "hello", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 16 * 1024)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long pathAddress = memory.baseAddress();
            long statAddress = memory.baseAddress() + 512;
            long statAtAddress = memory.baseAddress() + 1024;
            writeGuestString(memory, pathAddress, "/message.txt");

            int fileDescriptor = openReadOnly(state, pathAddress);
            memory.writeByte(statAddress + FREEBSD_STAT_SIZE - 1, (byte) 0x7f);
            invoke(state, FREEBSD_SYS_FSTAT, fileDescriptor, statAddress);
            assertSuccess(state, 0);
            assertRegularFileStat(memory, statAddress, 5);

            memory.writeByte(statAtAddress + FREEBSD_STAT_SIZE - 1, (byte) 0x7f);
            invoke(state, FREEBSD_SYS_FSTATAT, FREEBSD_AT_FDCWD, pathAddress, statAtAddress, 0);
            assertSuccess(state, 0);
            assertRegularFileStat(memory, statAtAddress, 5);
            assertEquals(
                    memory.readLong(statAddress + FREEBSD_STAT_INODE_OFFSET),
                    memory.readLong(statAtAddress + FREEBSD_STAT_INODE_OFFSET));

            invoke(state, FREEBSD_SYS_FSTAT, 99, statAddress);
            assertError(state, FREEBSD_EBADF);

            invoke(
                    state,
                    FREEBSD_SYS_FSTATAT,
                    FREEBSD_AT_FDCWD,
                    pathAddress,
                    statAtAddress,
                    FREEBSD_AT_REMOVEDIR);
            assertError(state, FREEBSD_EINVAL);

            byte[] unterminatedPath = new byte[4096];
            java.util.Arrays.fill(unterminatedPath, (byte) 'a');
            long longPathAddress = memory.baseAddress() + 4096;
            memory.writeBytes(longPathAddress, unterminatedPath, 0, unterminatedPath.length);
            invoke(state, FREEBSD_SYS_FSTATAT, FREEBSD_AT_FDCWD, longPathAddress, statAtAddress, 0);
            assertError(state, FREEBSD_ENAMETOOLONG);
        }
    }

    /// Verifies `fstatat(AT_SYMLINK_NOFOLLOW)` reports a symbolic link rather than its target.
    @Test
    public void fstatatReportsSymbolicLinkMetadata() throws Exception {
        Files.writeString(tempDirectory.resolve("target.txt"), "target-data", StandardCharsets.UTF_8);
        try {
            Files.createSymbolicLink(tempDirectory.resolve("link.txt"), Path.of("target.txt"));
        } catch (java.io.IOException | SecurityException | UnsupportedOperationException exception) {
            assumeTrue(false, "Host filesystem does not allow symbolic link creation");
        }

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long pathAddress = memory.baseAddress();
            long statAddress = memory.baseAddress() + 512;
            writeGuestString(memory, pathAddress, "/link.txt");

            invoke(
                    state,
                    FREEBSD_SYS_FSTATAT,
                    FREEBSD_AT_FDCWD,
                    pathAddress,
                    statAddress,
                    FREEBSD_AT_SYMLINK_NOFOLLOW);
            assertSuccess(state, 0);
            assertEquals(
                    FREEBSD_STAT_SYMBOLIC_LINK,
                    memory.readUnsignedShort(statAddress + FREEBSD_STAT_MODE_OFFSET) & FREEBSD_STAT_FILE_TYPE_MASK);
            assertEquals("target.txt".length(), memory.readLong(statAddress + FREEBSD_STAT_FILE_SIZE_OFFSET));

            invoke(state, FREEBSD_SYS_FSTATAT, FREEBSD_AT_FDCWD, pathAddress, statAddress, 0);
            assertSuccess(state, 0);
            assertRegularFileStat(memory, statAddress, "target-data".length());
        }
    }

    /// Verifies traditional FreeBSD filesystem calls reuse the shared sandboxed mutation behavior.
    @Test
    public void traditionalFilesystemSyscallsMutateSandboxedPaths() throws Exception {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long firstPathAddress = memory.baseAddress();
            long secondPathAddress = memory.baseAddress() + 128;
            long statAddress = memory.baseAddress() + 512;

            writeGuestString(memory, firstPathAddress, "/work");
            invoke(state, FREEBSD_SYS_MKDIR, firstPathAddress, 0755);
            assertSuccess(state, 0);
            assertTrue(Files.isDirectory(tempDirectory.resolve("work")));

            invoke(state, FREEBSD_SYS_CHMOD, firstPathAddress, 0700);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_FCHMODAT, FREEBSD_AT_FDCWD, firstPathAddress, 0710, 0);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_FSTATAT, FREEBSD_AT_FDCWD, firstPathAddress, statAddress, 0);
            assertSuccess(state, 0);
            assertEquals(0710, memory.readUnsignedShort(statAddress + FREEBSD_STAT_MODE_OFFSET) & 0777);

            Files.writeString(tempDirectory.resolve("work").resolve("original.txt"), "data", StandardCharsets.UTF_8);
            writeGuestString(memory, firstPathAddress, "/work/original.txt");
            invoke(
                    state,
                    FREEBSD_SYS_CHOWN,
                    firstPathAddress,
                    GuestCredentials.DEFAULT_USER_ID,
                    GuestCredentials.DEFAULT_GROUP_ID);
            assertSuccess(state, 0);

            invoke(state, FREEBSD_SYS_OPEN, firstPathAddress, FREEBSD_O_RDWR, 0);
            assertSuccess(state, 3);
            invoke(
                    state,
                    FREEBSD_SYS_FCHOWN,
                    3,
                    GuestCredentials.DEFAULT_USER_ID,
                    GuestCredentials.DEFAULT_GROUP_ID);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_FCHMOD, 3, 0600);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_FSTAT, 3, statAddress);
            assertSuccess(state, 0);
            assertEquals(0600, memory.readUnsignedShort(statAddress + FREEBSD_STAT_MODE_OFFSET) & 0777);
            invoke(state, FREEBSD_SYS_CLOSE, 3);
            assertSuccess(state, 0);

            writeGuestString(memory, secondPathAddress, "/work/renamed.txt");
            invoke(state, FREEBSD_SYS_RENAME, firstPathAddress, secondPathAddress);
            assertSuccess(state, 0);
            assertTrue(Files.isRegularFile(tempDirectory.resolve("work").resolve("renamed.txt")));

            long hardLinkPathAddress = memory.baseAddress() + 256;
            long symbolicTargetAddress = memory.baseAddress() + 384;
            long symbolicLinkPathAddress = memory.baseAddress() + 512;
            long linkBufferAddress = memory.baseAddress() + 768;
            writeGuestString(memory, hardLinkPathAddress, "/work/hard-link.txt");
            invoke(state, FREEBSD_SYS_LINK, secondPathAddress, hardLinkPathAddress);
            assertSuccess(state, 0);
            assertTrue(Files.isSameFile(
                    tempDirectory.resolve("work").resolve("renamed.txt"),
                    tempDirectory.resolve("work").resolve("hard-link.txt")));

            writeGuestString(memory, symbolicTargetAddress, "renamed.txt");
            writeGuestString(memory, symbolicLinkPathAddress, "/work/symbolic-link.txt");
            invoke(state, FREEBSD_SYS_SYMLINK, symbolicTargetAddress, symbolicLinkPathAddress);
            assertSuccess(state, 0);
            assertTrue(Files.isSymbolicLink(tempDirectory.resolve("work").resolve("symbolic-link.txt")));
            invoke(state, FREEBSD_SYS_READLINK, symbolicLinkPathAddress, linkBufferAddress, 64);
            assertSuccess(state, "renamed.txt".length());
            assertEquals(
                    "renamed.txt",
                    new String(
                            memory.readBytes(linkBufferAddress, "renamed.txt".length()),
                            StandardCharsets.UTF_8));

            invoke(state, FREEBSD_SYS_UNLINK, symbolicLinkPathAddress);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_UNLINK, hardLinkPathAddress);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_UNLINK, secondPathAddress);
            assertSuccess(state, 0);
            writeGuestString(memory, firstPathAddress, "/work");
            invoke(state, FREEBSD_SYS_RMDIR, firstPathAddress);
            assertSuccess(state, 0);
            assertTrue(Files.notExists(tempDirectory.resolve("work")));
        }
    }

    /// Verifies the current FreeBSD `renameat2` entry point handles zero flags through sandboxed rename logic.
    @Test
    public void renameat2UsesCurrentFreeBsdEntryPoint() throws Exception {
        Files.writeString(tempDirectory.resolve("rename-source.txt"), "data", StandardCharsets.UTF_8);
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long sourceAddress = memory.baseAddress();
            long targetAddress = memory.baseAddress() + 128;
            writeGuestString(memory, sourceAddress, "/rename-source.txt");
            writeGuestString(memory, targetAddress, "/rename-target.txt");

            invoke(
                    state,
                    FREEBSD_SYS_RENAMEAT2,
                    FREEBSD_AT_FDCWD,
                    sourceAddress,
                    FREEBSD_AT_FDCWD,
                    targetAddress,
                    0);
            assertSuccess(state, 0);
            assertTrue(Files.notExists(tempDirectory.resolve("rename-source.txt")));
            assertEquals("data", Files.readString(tempDirectory.resolve("rename-target.txt")));

            invoke(
                    state,
                    FREEBSD_SYS_RENAMEAT2,
                    FREEBSD_AT_FDCWD,
                    memory.endAddress(),
                    FREEBSD_AT_FDCWD,
                    memory.endAddress(),
                    1);
            assertError(state, FREEBSD_EINVAL);
        }
    }

    /// Verifies FreeBSD timestamp syscalls use native sentinels and expose native stat offsets.
    @Test
    public void timestampSyscallsUseFreeBsdSentinelsAndLayouts() throws Exception {
        Files.writeString(tempDirectory.resolve("timestamp.txt"), "data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    tempDirectory,
                    GuestCredentials.defaultUser(),
                    TimeSource.fixed(Instant.ofEpochSecond(1_700_000_100L, 555_555_500L)),
                    memory.baseAddress());
            long pathAddress = memory.baseAddress();
            long timesAddress = memory.baseAddress() + 512;
            long statAddress = memory.baseAddress() + 1024;
            writeGuestString(memory, pathAddress, "/timestamp.txt");
            memory.writeLong(timesAddress, 1_699_999_999L);
            memory.writeLong(timesAddress + Long.BYTES, 123_456_700L);
            memory.writeLong(timesAddress + 2L * Long.BYTES, 1_700_000_000L);
            memory.writeLong(timesAddress + 3L * Long.BYTES, 987_654_300L);

            invoke(state, FREEBSD_SYS_UTIMENSAT, FREEBSD_AT_FDCWD, pathAddress, timesAddress, 0);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_FSTATAT, FREEBSD_AT_FDCWD, pathAddress, statAddress, 0);
            assertSuccess(state, 0);
            assertEquals(1_699_999_999L, memory.readLong(statAddress + FREEBSD_STAT_ACCESS_TIME_OFFSET));
            assertEquals(
                    123_456_700L,
                    memory.readLong(statAddress + FREEBSD_STAT_ACCESS_TIME_OFFSET + Long.BYTES));
            assertEquals(1_700_000_000L, memory.readLong(statAddress + FREEBSD_STAT_MODIFICATION_TIME_OFFSET));
            assertEquals(
                    987_654_300L,
                    memory.readLong(statAddress + FREEBSD_STAT_MODIFICATION_TIME_OFFSET + Long.BYTES));

            memory.writeLong(timesAddress, 0);
            memory.writeLong(timesAddress + Long.BYTES, FREEBSD_UTIME_OMIT);
            memory.writeLong(timesAddress + 2L * Long.BYTES, 0);
            memory.writeLong(timesAddress + 3L * Long.BYTES, FREEBSD_UTIME_NOW);
            invoke(state, FREEBSD_SYS_UTIMENSAT, FREEBSD_AT_FDCWD, pathAddress, timesAddress, 0);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_FSTATAT, FREEBSD_AT_FDCWD, pathAddress, statAddress, 0);
            assertSuccess(state, 0);
            assertEquals(1_699_999_999L, memory.readLong(statAddress + FREEBSD_STAT_ACCESS_TIME_OFFSET));
            assertEquals(
                    123_456_700L,
                    memory.readLong(statAddress + FREEBSD_STAT_ACCESS_TIME_OFFSET + Long.BYTES));
            assertEquals(1_700_000_100L, memory.readLong(statAddress + FREEBSD_STAT_MODIFICATION_TIME_OFFSET));
            assertEquals(
                    555_555_500L,
                    memory.readLong(statAddress + FREEBSD_STAT_MODIFICATION_TIME_OFFSET + Long.BYTES));

            int fileDescriptor = openReadOnly(state, pathAddress);
            memory.writeLong(timesAddress, 1_600_000_001L);
            memory.writeLong(timesAddress + Long.BYTES, 111_111_100L);
            memory.writeLong(timesAddress + 2L * Long.BYTES, 1_600_000_002L);
            memory.writeLong(timesAddress + 3L * Long.BYTES, 222_222_200L);
            invoke(state, FREEBSD_SYS_FUTIMENS, fileDescriptor, timesAddress);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_FSTAT, fileDescriptor, statAddress);
            assertSuccess(state, 0);
            assertEquals(1_600_000_001L, memory.readLong(statAddress + FREEBSD_STAT_ACCESS_TIME_OFFSET));
            assertEquals(
                    111_111_100L,
                    memory.readLong(statAddress + FREEBSD_STAT_ACCESS_TIME_OFFSET + Long.BYTES));
            assertEquals(1_600_000_002L, memory.readLong(statAddress + FREEBSD_STAT_MODIFICATION_TIME_OFFSET));
            assertEquals(
                    222_222_200L,
                    memory.readLong(statAddress + FREEBSD_STAT_MODIFICATION_TIME_OFFSET + Long.BYTES));

            invoke(state, FREEBSD_SYS_FUTIMENS, fileDescriptor, memory.endAddress());
            assertError(state, FREEBSD_EFAULT);
            memory.writeLong(timesAddress + 3L * Long.BYTES, 1_000_000_000L);
            invoke(state, FREEBSD_SYS_UTIMENSAT, FREEBSD_AT_FDCWD, pathAddress, timesAddress, 0);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_CLOSE, fileDescriptor);
            assertSuccess(state, 0);
        }
    }

    /// Verifies `getrusage` accepts FreeBSD selectors and clears the complete native structure.
    @Test
    public void getrusageWritesFreeBsdLayout() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long rusageAddress = memory.baseAddress() + 512;
            memory.writeByte(rusageAddress + 143, (byte) 0x7f);

            invoke(state, FREEBSD_SYS_GETRUSAGE, 0, rusageAddress);
            assertSuccess(state, 0);
            assertTrue(memory.readLong(rusageAddress) >= 0);
            assertEquals(0, memory.readUnsignedByte(rusageAddress + 143));

            invoke(state, FREEBSD_SYS_GETRUSAGE, 2, rusageAddress);
            assertError(state, FREEBSD_EINVAL);
        }
    }

    /// Verifies FreeBSD socket creation flags, errno translation, and unnamed Unix socket address layout.
    @Test
    public void unixSocketpairUsesFreeBsdFlagsAndAddressLayout() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long pairAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 64;
            long sockaddrAddress = memory.baseAddress() + 128;
            long lengthAddress = memory.baseAddress() + 256;

            invoke(
                    state,
                    FREEBSD_SYS_SOCKETPAIR,
                    FREEBSD_AF_UNIX,
                    FREEBSD_SOCK_STREAM | FREEBSD_SOCK_NONBLOCK | FREEBSD_SOCK_CLOEXEC,
                    0,
                    pairAddress);
            assertSuccess(state, 0);
            int firstFileDescriptor = memory.readInt(pairAddress);
            int secondFileDescriptor = memory.readInt(pairAddress + Integer.BYTES);
            assertEquals(3, firstFileDescriptor);
            assertEquals(4, secondFileDescriptor);

            invoke(state, FREEBSD_SYS_RECVFROM, firstFileDescriptor, bufferAddress, 1, 0, 0, 0);
            assertError(state, FREEBSD_EAGAIN);

            byte[] message = "ping".getBytes(StandardCharsets.UTF_8);
            memory.writeBytes(bufferAddress, message, 0, message.length);
            invoke(state, FREEBSD_SYS_WRITE, firstFileDescriptor, bufferAddress, message.length);
            assertSuccess(state, message.length);
            invoke(state, FREEBSD_SYS_READ, secondFileDescriptor, bufferAddress, message.length);
            assertSuccess(state, message.length);
            assertArrayEquals(message, memory.readBytes(bufferAddress, message.length));

            memory.writeInt(lengthAddress, FREEBSD_SOCKADDR_UN_SIZE);
            invoke(state, FREEBSD_SYS_GETPEERNAME, firstFileDescriptor, sockaddrAddress, lengthAddress);
            assertSuccess(state, 0);
            assertEquals(FREEBSD_SOCKADDR_UN_PATH_OFFSET, memory.readUnsignedByte(sockaddrAddress));
            assertEquals(FREEBSD_AF_UNIX, memory.readUnsignedByte(sockaddrAddress + FREEBSD_SOCKADDR_FAMILY_OFFSET));
            assertEquals(FREEBSD_SOCKADDR_UN_PATH_OFFSET, memory.readInt(lengthAddress));

            invoke(state, FREEBSD_SYS_CLOSE, firstFileDescriptor);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, secondFileDescriptor);
            assertSuccess(state, 0);
        }
    }

    /// Verifies `fcntl` translates FreeBSD open-file status flags in both directions.
    @Test
    public void fcntlUsesFreeBsdStatusFlagValues() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long pairAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 128;

            invoke(
                    state,
                    FREEBSD_SYS_SOCKETPAIR,
                    FREEBSD_AF_UNIX,
                    FREEBSD_SOCK_STREAM,
                    0,
                    pairAddress);
            assertSuccess(state, 0);
            int firstFileDescriptor = memory.readInt(pairAddress);
            int secondFileDescriptor = memory.readInt(pairAddress + Integer.BYTES);

            invoke(state, FREEBSD_SYS_FCNTL, firstFileDescriptor, FREEBSD_F_GETFL, 0);
            assertSuccess(state, FREEBSD_O_RDWR);
            invoke(state, FREEBSD_SYS_FCNTL, firstFileDescriptor, FREEBSD_F_SETFL, FREEBSD_O_NONBLOCK);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_FCNTL, firstFileDescriptor, FREEBSD_F_GETFL, 0);
            assertSuccess(state, FREEBSD_O_RDWR | FREEBSD_O_NONBLOCK);
            invoke(state, FREEBSD_SYS_READ, firstFileDescriptor, bufferAddress, 1);
            assertError(state, FREEBSD_EAGAIN);

            invoke(state, FREEBSD_SYS_CLOSE, firstFileDescriptor);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, secondFileDescriptor);
            assertSuccess(state, 0);
        }
    }

    /// Verifies traditional FreeBSD pipe and readiness syscalls use native argument layouts.
    @Test
    public void traditionalReadinessSyscallsUseFreeBsdLayouts() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long fileDescriptorSetAddress = memory.baseAddress() + 0x100;
            long timevalAddress = memory.baseAddress() + 0x180;
            long timespecAddress = memory.baseAddress() + 0x1a0;
            long signalSetAddress = memory.baseAddress() + 0x1c0;
            long pollFileDescriptorAddress = memory.baseAddress() + 0x200;
            long bufferAddress = memory.baseAddress() + 0x300;

            invoke(state, FREEBSD_SYS_PIPE);
            assertSuccess(state, 3);
            int readFileDescriptor = (int) state.register(10);
            int writeFileDescriptor = (int) state.register(11);
            assertEquals(4, writeFileDescriptor);

            memory.writeLong(fileDescriptorSetAddress, 1L << readFileDescriptor);
            memory.clear(timevalAddress, 2L * Long.BYTES);
            invoke(
                    state,
                    FREEBSD_SYS_SELECT,
                    readFileDescriptor + 1L,
                    fileDescriptorSetAddress,
                    0,
                    0,
                    timevalAddress);
            assertSuccess(state, 0);
            assertEquals(0, memory.readLong(fileDescriptorSetAddress));

            memory.writeByte(bufferAddress, (byte) 0x5a);
            invoke(state, FREEBSD_SYS_WRITE, writeFileDescriptor, bufferAddress, 1);
            assertSuccess(state, 1);
            memory.writeLong(fileDescriptorSetAddress, 1L << readFileDescriptor);
            invoke(
                    state,
                    FREEBSD_SYS_SELECT,
                    readFileDescriptor + 1L,
                    fileDescriptorSetAddress,
                    0,
                    0,
                    timevalAddress);
            assertSuccess(state, 1);
            assertEquals(1L << readFileDescriptor, memory.readLong(fileDescriptorSetAddress));

            memory.writeInt(pollFileDescriptorAddress, readFileDescriptor);
            memory.writeShort(pollFileDescriptorAddress + Integer.BYTES, (short) FREEBSD_POLLIN);
            memory.writeShort(pollFileDescriptorAddress + Integer.BYTES + Short.BYTES, (short) 0);
            invoke(state, FREEBSD_SYS_POLL, pollFileDescriptorAddress, 1, 0);
            assertSuccess(state, 1);
            assertEquals(
                    FREEBSD_POLLIN,
                    memory.readUnsignedShort(pollFileDescriptorAddress + Integer.BYTES + Short.BYTES));

            memory.writeInt(pollFileDescriptorAddress, 99);
            invoke(state, FREEBSD_SYS_POLL, pollFileDescriptorAddress, 1, 0);
            assertSuccess(state, 1);
            assertEquals(
                    FREEBSD_POLLNVAL,
                    memory.readUnsignedShort(pollFileDescriptorAddress + Integer.BYTES + Short.BYTES));

            memory.clear(timespecAddress, 2L * Long.BYTES);
            memory.clear(signalSetAddress, 4L * Integer.BYTES);
            memory.writeLong(signalSetAddress, 1);
            memory.writeLong(fileDescriptorSetAddress, 1L << readFileDescriptor);
            invoke(
                    state,
                    FREEBSD_SYS_PSELECT,
                    readFileDescriptor + 1L,
                    fileDescriptorSetAddress,
                    0,
                    0,
                    timespecAddress,
                    signalSetAddress);
            assertSuccess(state, 1);
            assertEquals(1L << readFileDescriptor, memory.readLong(fileDescriptorSetAddress));

            memory.writeInt(pollFileDescriptorAddress, readFileDescriptor);
            memory.writeShort(pollFileDescriptorAddress + Integer.BYTES, (short) FREEBSD_POLLIN);
            memory.writeShort(pollFileDescriptorAddress + Integer.BYTES + Short.BYTES, (short) 0);
            invoke(
                    state,
                    FREEBSD_SYS_PPOLL,
                    pollFileDescriptorAddress,
                    1,
                    timespecAddress,
                    signalSetAddress);
            assertSuccess(state, 1);
            assertEquals(
                    FREEBSD_POLLIN,
                    memory.readUnsignedShort(pollFileDescriptorAddress + Integer.BYTES + Short.BYTES));

            invoke(state, FREEBSD_SYS_GETDTABLESIZE);
            assertSuccess(state, 1024);

            memory.writeLong(timevalAddress + Long.BYTES, 1_000_000);
            invoke(state, FREEBSD_SYS_SELECT, 0, 0, 0, 0, timevalAddress);
            assertError(state, FREEBSD_EINVAL);
            long partialSignalSetAddress = memory.baseAddress() + 4096 - Long.BYTES;
            invoke(state, FREEBSD_SYS_PSELECT, 0, 0, 0, 0, timespecAddress, partialSignalSetAddress);
            assertError(state, FREEBSD_EFAULT);
            invoke(state, FREEBSD_SYS_PPOLL, 0, 0, timespecAddress, partialSignalSetAddress);
            assertError(state, FREEBSD_EFAULT);

            invoke(state, FREEBSD_SYS_CLOSE, readFileDescriptor);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, writeFileDescriptor);
            assertSuccess(state, 0);
        }
    }

    /// Verifies FreeBSD clock identifiers are translated independently from Linux clock numbering.
    @Test
    public void clockSyscallsUseFreeBsdClockIdentifiers() {
        long epochSeconds = 1_700_000_000L;
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    tempDirectory,
                    GuestCredentials.defaultUser(),
                    TimeSource.fixed(Instant.ofEpochSecond(epochSeconds)),
                    memory.baseAddress());
            long timespecAddress = memory.baseAddress() + 0x100;

            invoke(state, FREEBSD_SYS_CLOCK_GETTIME, FREEBSD_CLOCK_REALTIME, timespecAddress);
            assertSuccess(state, 0);
            assertEquals(epochSeconds, memory.readLong(timespecAddress));
            assertEquals(0, memory.readLong(timespecAddress + FREEBSD_TIMESPEC_NANOSECONDS_OFFSET));

            invoke(state, FREEBSD_SYS_CLOCK_GETTIME, FREEBSD_CLOCK_UPTIME, timespecAddress);
            assertSuccess(state, 0);
            assertEquals(0, memory.readLong(timespecAddress));
            assertEquals(0, memory.readLong(timespecAddress + FREEBSD_TIMESPEC_NANOSECONDS_OFFSET));

            invoke(state, FREEBSD_SYS_CLOCK_GETTIME, FREEBSD_CLOCK_REALTIME_FAST, timespecAddress);
            assertSuccess(state, 0);
            assertEquals(epochSeconds, memory.readLong(timespecAddress));
            invoke(state, FREEBSD_SYS_CLOCK_GETTIME, FREEBSD_CLOCK_TAI, timespecAddress);
            assertSuccess(state, 0);
            assertEquals(epochSeconds, memory.readLong(timespecAddress));
            invoke(state, FREEBSD_SYS_CLOCK_GETTIME, FREEBSD_CLOCK_PROCESS_CPUTIME_ID, timespecAddress);
            assertSuccess(state, 0);
            assertEquals(0, memory.readLong(timespecAddress));
            invoke(state, FREEBSD_SYS_CLOCK_GETTIME, 3, timespecAddress);
            assertError(state, FREEBSD_EINVAL);

            invoke(state, FREEBSD_SYS_CLOCK_GETTIME, FREEBSD_CLOCK_SECOND, timespecAddress);
            assertSuccess(state, 0);
            assertEquals(epochSeconds, memory.readLong(timespecAddress));
            assertEquals(0, memory.readLong(timespecAddress + FREEBSD_TIMESPEC_NANOSECONDS_OFFSET));
            invoke(state, FREEBSD_SYS_CLOCK_GETRES, FREEBSD_CLOCK_SECOND, timespecAddress);
            assertSuccess(state, 0);
            assertEquals(1, memory.readLong(timespecAddress));
            assertEquals(0, memory.readLong(timespecAddress + FREEBSD_TIMESPEC_NANOSECONDS_OFFSET));
            invoke(state, FREEBSD_SYS_CLOCK_GETRES, FREEBSD_CLOCK_UPTIME, timespecAddress);
            assertSuccess(state, 0);
            assertEquals(0, memory.readLong(timespecAddress));
            assertEquals(1, memory.readLong(timespecAddress + FREEBSD_TIMESPEC_NANOSECONDS_OFFSET));
            invoke(state, FREEBSD_SYS_CLOCK_GETRES, FREEBSD_CLOCK_REALTIME, 0);
            assertSuccess(state, 0);

            invoke(state, FREEBSD_SYS_CLOCK_GETTIME, FREEBSD_CLOCK_REALTIME, memory.endAddress());
            assertError(state, FREEBSD_EFAULT);
            invoke(state, FREEBSD_SYS_CLOCK_GETRES, FREEBSD_CLOCK_REALTIME, memory.endAddress());
            assertError(state, FREEBSD_EFAULT);
        }
    }

    /// Verifies FreeBSD sleep syscalls validate native timespec pointers before reading or writing them.
    @Test
    public void clockNanosleepValidatesFreeBsdTimespecPointers() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long requestAddress = memory.baseAddress() + 0x100;
            long remainingAddress = memory.baseAddress() + 0x120;
            long partialTimespecAddress = memory.baseAddress() + 4096 - Long.BYTES;

            memory.clear(requestAddress, 2L * Long.BYTES);
            memory.clear(remainingAddress, 2L * Long.BYTES);
            invoke(state, FREEBSD_SYS_NANOSLEEP, requestAddress, remainingAddress);
            assertSuccess(state, 0);
            invoke(
                    state,
                    FREEBSD_SYS_CLOCK_NANOSLEEP,
                    FREEBSD_CLOCK_REALTIME,
                    0,
                    requestAddress,
                    remainingAddress);
            assertSuccess(state, 0);
            invoke(
                    state,
                    FREEBSD_SYS_CLOCK_NANOSLEEP,
                    FREEBSD_CLOCK_MONOTONIC,
                    FREEBSD_TIMER_ABSTIME,
                    requestAddress,
                    remainingAddress);
            assertSuccess(state, 0);
            invoke(
                    state,
                    FREEBSD_SYS_CLOCK_NANOSLEEP,
                    FREEBSD_CLOCK_UPTIME,
                    0,
                    requestAddress,
                    remainingAddress);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOCK_NANOSLEEP, 3, 0, requestAddress, remainingAddress);
            assertError(state, FREEBSD_EINVAL);

            memory.writeLong(requestAddress + Long.BYTES, 1_000_000_000L);
            invoke(state, FREEBSD_SYS_NANOSLEEP, requestAddress, remainingAddress);
            assertError(state, FREEBSD_EINVAL);
            invoke(
                    state,
                    FREEBSD_SYS_CLOCK_NANOSLEEP,
                    FREEBSD_CLOCK_REALTIME,
                    0,
                    requestAddress,
                    remainingAddress);
            assertError(state, FREEBSD_EINVAL);

            memory.writeLong(requestAddress + Long.BYTES, 0);
            invoke(state, FREEBSD_SYS_NANOSLEEP, partialTimespecAddress, 0);
            assertError(state, FREEBSD_EFAULT);
            invoke(
                    state,
                    FREEBSD_SYS_CLOCK_NANOSLEEP,
                    FREEBSD_CLOCK_REALTIME,
                    0,
                    partialTimespecAddress,
                    0);
            assertError(state, FREEBSD_EFAULT);
            invoke(
                    state,
                    FREEBSD_SYS_CLOCK_NANOSLEEP,
                    FREEBSD_CLOCK_REALTIME,
                    0,
                    requestAddress,
                    partialTimespecAddress);
            assertError(state, FREEBSD_EFAULT);
        }
    }

    /// Verifies FreeBSD interval timers use the native timeval layout and tracked timer state.
    @Test
    public void intervalTimerSyscallsUseFreeBsdTimevalLayout() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    tempDirectory,
                    GuestCredentials.defaultUser(),
                    TimeSource.fixed(Instant.ofEpochSecond(1_700_000_000L)),
                    memory.baseAddress());
            long currentValueAddress = memory.baseAddress() + 0x100;
            long newValueAddress = memory.baseAddress() + 0x140;
            long oldValueAddress = memory.baseAddress() + 0x180;

            invoke(state, FREEBSD_SYS_GETITIMER, FREEBSD_ITIMER_REAL, currentValueAddress);
            assertSuccess(state, 0);
            assertFreeBsdItimerval(memory, currentValueAddress, 0, 0, 0, 0);

            writeFreeBsdItimerval(memory, newValueAddress, 2, 30, 5, 40);
            invoke(
                    state,
                    FREEBSD_SYS_SETITIMER,
                    FREEBSD_ITIMER_REAL,
                    newValueAddress,
                    oldValueAddress);
            assertSuccess(state, 0);
            assertFreeBsdItimerval(memory, oldValueAddress, 0, 0, 0, 0);

            invoke(state, FREEBSD_SYS_GETITIMER, FREEBSD_ITIMER_REAL, currentValueAddress);
            assertSuccess(state, 0);
            assertFreeBsdItimerval(memory, currentValueAddress, 2, 30, 5, 40);

            invoke(state, FREEBSD_SYS_GETITIMER, FREEBSD_ITIMER_PROF + 1, currentValueAddress);
            assertError(state, FREEBSD_EINVAL);
            writeFreeBsdItimerval(memory, newValueAddress, 0, 1_000_000, 1, 0);
            invoke(state, FREEBSD_SYS_SETITIMER, FREEBSD_ITIMER_REAL, newValueAddress, 0);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_GETITIMER, FREEBSD_ITIMER_REAL, memory.endAddress());
            assertError(state, FREEBSD_EFAULT);
        }
    }

    /// Verifies FreeBSD mapped-memory probes, locks, synchronization flags, and advice translation.
    @Test
    public void mappedMemorySyscallsUseFreeBsdFlags() {
        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 8L * GUEST_PAGE_SIZE)) {
            long baseAddress = memory.baseAddress();
            assertTrue(memory.map(baseAddress, GUEST_PAGE_SIZE));
            RiscVThreadState state = state(
                    memory,
                    tempDirectory,
                    GuestCredentials.of("root", 0, 0, "0", "/root", "/bin/sh"),
                    TimeSource.system(),
                    baseAddress + GUEST_PAGE_SIZE);
            long vectorAddress = baseAddress + 0x100;

            invoke(
                    state,
                    FREEBSD_SYS_MMAP,
                    0,
                    2L * GUEST_PAGE_SIZE,
                    FREEBSD_PROT_READ | FREEBSD_PROT_WRITE,
                    FREEBSD_MAP_PRIVATE | FREEBSD_MAP_ANON,
                    -1,
                    0);
            assertEquals(0, state.register(5));
            long mappedAddress = state.register(10);
            assertTrue(mappedAddress >= baseAddress + GUEST_PAGE_SIZE);

            memory.writeByte(mappedAddress, (byte) 0x5a);
            invoke(state, FREEBSD_SYS_MADVISE, mappedAddress, GUEST_PAGE_SIZE, FREEBSD_MADV_NOCORE);
            assertSuccess(state, 0);
            assertEquals(0x5a, memory.readUnsignedByte(mappedAddress));
            invoke(state, FREEBSD_SYS_MADVISE, mappedAddress, GUEST_PAGE_SIZE, FREEBSD_MADV_FREE);
            assertSuccess(state, 0);
            assertEquals(0, memory.readUnsignedByte(mappedAddress));

            invoke(state, FREEBSD_SYS_MSYNC, mappedAddress, GUEST_PAGE_SIZE, 0);
            assertSuccess(state, 0);
            invoke(
                    state,
                    FREEBSD_SYS_MSYNC,
                    mappedAddress,
                    GUEST_PAGE_SIZE,
                    FREEBSD_MS_ASYNC | FREEBSD_MS_INVALIDATE);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_MSYNC, mappedAddress, GUEST_PAGE_SIZE, 4);
            assertError(state, FREEBSD_EINVAL);

            invoke(state, FREEBSD_SYS_MINCORE, mappedAddress, GUEST_PAGE_SIZE + 1, vectorAddress);
            assertSuccess(state, 0);
            assertArrayEquals(new byte[]{1, 1}, memory.readBytes(vectorAddress, 2));
            invoke(state, FREEBSD_SYS_MLOCK, mappedAddress + 1, GUEST_PAGE_SIZE - 2);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_MUNLOCK, mappedAddress + 1, GUEST_PAGE_SIZE - 2);
            assertSuccess(state, 0);

            invoke(state, FREEBSD_SYS_MINCORE, mappedAddress + 1, GUEST_PAGE_SIZE, vectorAddress);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_MINCORE, mappedAddress, GUEST_PAGE_SIZE, memory.endAddress());
            assertError(state, FREEBSD_EFAULT);
        }
    }

    /// Verifies FreeBSD memory locking requires privilege and rejects Linux-only process-wide flags.
    @Test
    public void memoryLockSyscallsUseFreeBsdPrivilegeAndFlags() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            long address = memory.baseAddress();
            RiscVThreadState unprivilegedState = state(memory, tempDirectory);

            invoke(unprivilegedState, FREEBSD_SYS_MLOCK, address, 1);
            assertError(unprivilegedState, FREEBSD_EPERM);
            invoke(unprivilegedState, FREEBSD_SYS_MUNLOCK, address, 1);
            assertError(unprivilegedState, FREEBSD_EPERM);
            invoke(unprivilegedState, FREEBSD_SYS_MLOCKALL, FREEBSD_MCL_CURRENT);
            assertError(unprivilegedState, FREEBSD_EPERM);
            invoke(unprivilegedState, FREEBSD_SYS_MUNLOCKALL);
            assertError(unprivilegedState, FREEBSD_EPERM);

            RiscVThreadState privilegedState = state(
                    memory,
                    tempDirectory,
                    GuestCredentials.of("root", 0, 0, "0", "/root", "/bin/sh"));
            invoke(privilegedState, FREEBSD_SYS_MLOCK, address + 1, 1);
            assertSuccess(privilegedState, 0);
            invoke(privilegedState, FREEBSD_SYS_MUNLOCK, address + 1, 1);
            assertSuccess(privilegedState, 0);
            invoke(privilegedState, FREEBSD_SYS_MLOCKALL, FREEBSD_MCL_CURRENT);
            assertSuccess(privilegedState, 0);
            invoke(privilegedState, FREEBSD_SYS_MLOCKALL, FREEBSD_MCL_FUTURE);
            assertSuccess(privilegedState, 0);
            invoke(
                    privilegedState,
                    FREEBSD_SYS_MLOCKALL,
                    FREEBSD_MCL_CURRENT | FREEBSD_MCL_FUTURE);
            assertSuccess(privilegedState, 0);
            invoke(privilegedState, FREEBSD_SYS_MLOCKALL, 0);
            assertError(privilegedState, FREEBSD_EINVAL);
            invoke(privilegedState, FREEBSD_SYS_MLOCKALL, 4);
            assertError(privilegedState, FREEBSD_EINVAL);
            invoke(privilegedState, FREEBSD_SYS_MUNLOCKALL);
            assertSuccess(privilegedState, 0);
        }
    }

    /// Verifies FreeBSD positioned vector I/O preserves file position and native iovec layout.
    @Test
    public void positionedVectorIoUsesFreeBsdAbi() throws Exception {
        Files.writeString(tempDirectory.resolve("vector.txt"), "abcdefghij", StandardCharsets.UTF_8);
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long pathAddress = memory.baseAddress();
            long iovecAddress = memory.baseAddress() + 0x100;
            long firstBufferAddress = memory.baseAddress() + 0x200;
            long secondBufferAddress = memory.baseAddress() + 0x240;
            writeGuestString(memory, pathAddress, "/vector.txt");

            invoke(state, FREEBSD_SYS_OPEN, pathAddress, FREEBSD_O_RDWR, 0);
            assertSuccess(state, 3);
            int fileDescriptor = (int) state.register(10);

            byte[] firstWrite = "XY".getBytes(StandardCharsets.UTF_8);
            byte[] secondWrite = "Z12".getBytes(StandardCharsets.UTF_8);
            memory.writeBytes(firstBufferAddress, firstWrite, 0, firstWrite.length);
            memory.writeBytes(secondBufferAddress, secondWrite, 0, secondWrite.length);
            writeFreeBsdIovec(memory, iovecAddress, firstBufferAddress, firstWrite.length);
            writeFreeBsdIovec(
                    memory,
                    iovecAddress + FREEBSD_IOVEC_SIZE,
                    secondBufferAddress,
                    secondWrite.length);
            invoke(state, FREEBSD_SYS_PWRITEV, fileDescriptor, iovecAddress, 2, 2);
            assertSuccess(state, firstWrite.length + secondWrite.length);

            memory.clear(firstBufferAddress, 3);
            memory.clear(secondBufferAddress, 2);
            writeFreeBsdIovec(memory, iovecAddress, firstBufferAddress, 3);
            writeFreeBsdIovec(memory, iovecAddress + FREEBSD_IOVEC_SIZE, secondBufferAddress, 2);
            invoke(state, FREEBSD_SYS_PREADV, fileDescriptor, iovecAddress, 2, 1);
            assertSuccess(state, 5);
            assertArrayEquals("bXY".getBytes(StandardCharsets.UTF_8), memory.readBytes(firstBufferAddress, 3));
            assertArrayEquals("Z1".getBytes(StandardCharsets.UTF_8), memory.readBytes(secondBufferAddress, 2));

            invoke(state, FREEBSD_SYS_PREADV, fileDescriptor, iovecAddress, 2, -1);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_PWRITEV, fileDescriptor, memory.endAddress(), 1, 0);
            assertError(state, FREEBSD_EFAULT);
            invoke(state, FREEBSD_SYS_CLOSE, fileDescriptor);
            assertSuccess(state, 0);
        }
        assertEquals("abXYZ12hij", Files.readString(tempDirectory.resolve("vector.txt"), StandardCharsets.UTF_8));
    }

    /// Verifies POSIX allocation and advice syscalls preserve offsets and return errors as positive values.
    @Test
    public void posixFileRangeSyscallsUseFreeBsdReturnConvention() throws Exception {
        Files.writeString(tempDirectory.resolve("range.txt"), "abc", StandardCharsets.UTF_8);
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 0x100;
            writeGuestString(memory, pathAddress, "/range.txt");

            invoke(state, FREEBSD_SYS_OPEN, pathAddress, FREEBSD_O_RDWR, 0);
            assertSuccess(state, 3);
            int fileDescriptor = (int) state.register(10);
            invoke(state, FREEBSD_SYS_POSIX_FALLOCATE, fileDescriptor, 8, 4);
            assertSuccess(state, 0);
            memory.writeByte(bufferAddress, (byte) 'Z');
            invoke(state, FREEBSD_SYS_WRITE, fileDescriptor, bufferAddress, 1);
            assertSuccess(state, 1);

            invoke(state, FREEBSD_SYS_POSIX_FADVISE, fileDescriptor, 0, 0, 0);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_POSIX_FADVISE, fileDescriptor, -1, 0, 0);
            assertSuccess(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_POSIX_FADVISE, fileDescriptor, 0, 0, 6);
            assertSuccess(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_POSIX_FALLOCATE, fileDescriptor, 0, 0);
            assertSuccess(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_CLOSE, fileDescriptor);
            assertSuccess(state, 0);

            fileDescriptor = openReadOnly(state, pathAddress);
            invoke(state, FREEBSD_SYS_POSIX_FALLOCATE, fileDescriptor, 0, 1);
            assertSuccess(state, FREEBSD_EBADF);
            invoke(state, FREEBSD_SYS_POSIX_FADVISE, fileDescriptor, 0, 1, 5);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, fileDescriptor);
            assertSuccess(state, 0);

            invoke(state, FREEBSD_SYS_PIPE);
            assertSuccess(state, 3);
            int readFileDescriptor = (int) state.register(10);
            int writeFileDescriptor = (int) state.register(11);
            invoke(state, FREEBSD_SYS_POSIX_FADVISE, readFileDescriptor, 0, 0, 0);
            assertSuccess(state, FREEBSD_ESPIPE);
            invoke(state, FREEBSD_SYS_POSIX_FALLOCATE, writeFileDescriptor, 0, 1);
            assertSuccess(state, FREEBSD_ESPIPE);
            invoke(state, FREEBSD_SYS_CLOSE, readFileDescriptor);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, writeFileDescriptor);
            assertSuccess(state, 0);
        }

        byte[] bytes = Files.readAllBytes(tempDirectory.resolve("range.txt"));
        assertEquals(12, bytes.length);
        assertArrayEquals("Zbc".getBytes(StandardCharsets.UTF_8), Arrays.copyOf(bytes, 3));
        assertArrayEquals(new byte[9], Arrays.copyOfRange(bytes, 3, bytes.length));
    }

    /// Verifies FreeBSD regular-file range copies and clone-flag handling.
    @Test
    public void copyFileRangeUsesFreeBsdOffsetSemantics() throws Exception {
        Files.writeString(tempDirectory.resolve("copy-source.txt"), "0123456789", StandardCharsets.UTF_8);
        Files.writeString(tempDirectory.resolve("copy-target.txt"), "..........", StandardCharsets.UTF_8);
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long sourcePathAddress = memory.baseAddress();
            long targetPathAddress = memory.baseAddress() + 0x40;
            long inputOffsetAddress = memory.baseAddress() + 0x100;
            long outputOffsetAddress = memory.baseAddress() + 0x108;
            writeGuestString(memory, sourcePathAddress, "/copy-source.txt");
            writeGuestString(memory, targetPathAddress, "/copy-target.txt");

            int sourceFileDescriptor = openReadOnly(state, sourcePathAddress);
            invoke(state, FREEBSD_SYS_OPEN, targetPathAddress, FREEBSD_O_RDWR, 0);
            assertSuccess(state, 4);
            int targetFileDescriptor = (int) state.register(10);

            invoke(state, FREEBSD_SYS_LSEEK, sourceFileDescriptor, 1, 0);
            assertSuccess(state, 1);
            invoke(state, FREEBSD_SYS_LSEEK, targetFileDescriptor, 2, 0);
            assertSuccess(state, 2);

            memory.writeLong(inputOffsetAddress, 3);
            memory.writeLong(outputOffsetAddress, 5);
            invoke(
                    state,
                    FREEBSD_SYS_COPY_FILE_RANGE,
                    sourceFileDescriptor,
                    inputOffsetAddress,
                    targetFileDescriptor,
                    outputOffsetAddress,
                    4,
                    0);
            assertSuccess(state, 4);
            assertEquals(7, memory.readLong(inputOffsetAddress));
            assertEquals(9, memory.readLong(outputOffsetAddress));

            invoke(state, FREEBSD_SYS_LSEEK, sourceFileDescriptor, 0, 1);
            assertSuccess(state, 1);
            invoke(state, FREEBSD_SYS_LSEEK, targetFileDescriptor, 0, 1);
            assertSuccess(state, 2);
            invoke(
                    state,
                    FREEBSD_SYS_COPY_FILE_RANGE,
                    sourceFileDescriptor,
                    0,
                    targetFileDescriptor,
                    0,
                    2,
                    0);
            assertSuccess(state, 2);
            invoke(state, FREEBSD_SYS_LSEEK, sourceFileDescriptor, 0, 1);
            assertSuccess(state, 3);
            invoke(state, FREEBSD_SYS_LSEEK, targetFileDescriptor, 0, 1);
            assertSuccess(state, 4);

            invoke(
                    state,
                    FREEBSD_SYS_COPY_FILE_RANGE,
                    sourceFileDescriptor,
                    0,
                    targetFileDescriptor,
                    0,
                    1,
                    FREEBSD_COPY_FILE_RANGE_CLONE);
            assertError(state, FREEBSD_ENOTSUP);
            memory.writeLong(inputOffsetAddress, 0);
            memory.writeLong(outputOffsetAddress, 1);
            invoke(
                    state,
                    FREEBSD_SYS_COPY_FILE_RANGE,
                    targetFileDescriptor,
                    inputOffsetAddress,
                    targetFileDescriptor,
                    outputOffsetAddress,
                    4,
                    0);
            assertError(state, FREEBSD_EINVAL);
            invoke(
                    state,
                    FREEBSD_SYS_COPY_FILE_RANGE,
                    sourceFileDescriptor,
                    memory.endAddress(),
                    targetFileDescriptor,
                    outputOffsetAddress,
                    1,
                    0);
            assertError(state, FREEBSD_EFAULT);

            invoke(state, FREEBSD_SYS_CLOSE, targetFileDescriptor);
            assertSuccess(state, 0);
            invoke(
                    state,
                    FREEBSD_SYS_OPEN,
                    targetPathAddress,
                    1 | FREEBSD_O_APPEND,
                    0);
            assertSuccess(state, 4);
            targetFileDescriptor = (int) state.register(10);
            invoke(
                    state,
                    FREEBSD_SYS_COPY_FILE_RANGE,
                    sourceFileDescriptor,
                    0,
                    targetFileDescriptor,
                    0,
                    1,
                    0);
            assertError(state, FREEBSD_EBADF);
            invoke(state, FREEBSD_SYS_CLOSE, sourceFileDescriptor);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, targetFileDescriptor);
            assertSuccess(state, 0);
        }

        assertEquals(
                "..12.3456.",
                Files.readString(tempDirectory.resolve("copy-target.txt"), StandardCharsets.UTF_8));
    }

    /// Verifies `fspacectl` zeroes only the in-file range and preserves the descriptor offset and file size.
    @Test
    public void fspacectlDeallocatesFreeBsdFileRanges() throws Exception {
        Files.writeString(tempDirectory.resolve("space.txt"), "abcdefghij", StandardCharsets.UTF_8);
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long pathAddress = memory.baseAddress();
            long requestedRangeAddress = memory.baseAddress() + 0x100;
            long remainingRangeAddress = memory.baseAddress() + 0x120;
            long pipeAddress = memory.baseAddress() + 0x200;
            writeGuestString(memory, pathAddress, "/space.txt");

            invoke(state, FREEBSD_SYS_OPEN, pathAddress, FREEBSD_O_RDWR, 0);
            assertSuccess(state, 3);
            int fileDescriptor = (int) state.register(10);
            invoke(state, FREEBSD_SYS_LSEEK, fileDescriptor, 3, 0);
            assertSuccess(state, 3);

            memory.writeLong(requestedRangeAddress, 2);
            memory.writeLong(requestedRangeAddress + FREEBSD_SPACECTL_RANGE_LENGTH_OFFSET, 4);
            invoke(
                    state,
                    FREEBSD_SYS_FSPACECTL,
                    fileDescriptor,
                    FREEBSD_SPACECTL_DEALLOC,
                    requestedRangeAddress,
                    0,
                    remainingRangeAddress);
            assertSuccess(state, 0);
            assertEquals(6, memory.readLong(remainingRangeAddress));
            assertEquals(0, memory.readLong(remainingRangeAddress + FREEBSD_SPACECTL_RANGE_LENGTH_OFFSET));
            invoke(state, FREEBSD_SYS_LSEEK, fileDescriptor, 0, 1);
            assertSuccess(state, 3);

            memory.writeLong(requestedRangeAddress, 20);
            memory.writeLong(requestedRangeAddress + FREEBSD_SPACECTL_RANGE_LENGTH_OFFSET, 5);
            invoke(
                    state,
                    FREEBSD_SYS_FSPACECTL,
                    fileDescriptor,
                    FREEBSD_SPACECTL_DEALLOC,
                    requestedRangeAddress,
                    0,
                    requestedRangeAddress);
            assertSuccess(state, 0);
            assertEquals(20, memory.readLong(requestedRangeAddress));
            assertEquals(0, memory.readLong(requestedRangeAddress + FREEBSD_SPACECTL_RANGE_LENGTH_OFFSET));

            memory.writeLong(requestedRangeAddress, 0);
            memory.writeLong(requestedRangeAddress + FREEBSD_SPACECTL_RANGE_LENGTH_OFFSET, 1);
            invoke(
                    state,
                    FREEBSD_SYS_FSPACECTL,
                    fileDescriptor,
                    FREEBSD_SPACECTL_DEALLOC,
                    requestedRangeAddress,
                    1,
                    0);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_FSPACECTL, fileDescriptor, 2, requestedRangeAddress, 0, 0);
            assertError(state, FREEBSD_EINVAL);
            memory.writeLong(requestedRangeAddress, -1);
            invoke(
                    state,
                    FREEBSD_SYS_FSPACECTL,
                    fileDescriptor,
                    FREEBSD_SPACECTL_DEALLOC,
                    requestedRangeAddress,
                    0,
                    0);
            assertError(state, FREEBSD_EINVAL);
            invoke(
                    state,
                    FREEBSD_SYS_FSPACECTL,
                    fileDescriptor,
                    FREEBSD_SPACECTL_DEALLOC,
                    memory.endAddress(),
                    0,
                    0);
            assertError(state, FREEBSD_EFAULT);
            invoke(state, FREEBSD_SYS_CLOSE, fileDescriptor);
            assertSuccess(state, 0);

            fileDescriptor = openReadOnly(state, pathAddress);
            memory.writeLong(requestedRangeAddress, 0);
            memory.writeLong(requestedRangeAddress + FREEBSD_SPACECTL_RANGE_LENGTH_OFFSET, 1);
            invoke(
                    state,
                    FREEBSD_SYS_FSPACECTL,
                    fileDescriptor,
                    FREEBSD_SPACECTL_DEALLOC,
                    requestedRangeAddress,
                    0,
                    0);
            assertError(state, FREEBSD_EBADF);
            invoke(state, FREEBSD_SYS_CLOSE, fileDescriptor);
            assertSuccess(state, 0);

            invoke(state, FREEBSD_SYS_PIPE, pipeAddress);
            assertSuccess(state, 3);
            int pipeReader = (int) state.register(10);
            int pipeWriter = (int) state.register(11);
            invoke(
                    state,
                    FREEBSD_SYS_FSPACECTL,
                    pipeWriter,
                    FREEBSD_SPACECTL_DEALLOC,
                    requestedRangeAddress,
                    0,
                    0);
            assertError(state, FREEBSD_ESPIPE);
            invoke(state, FREEBSD_SYS_CLOSE, pipeReader);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, pipeWriter);
            assertSuccess(state, 0);
        }

        byte[] bytes = Files.readAllBytes(tempDirectory.resolve("space.txt"));
        assertEquals(10, bytes.length);
        assertArrayEquals(
                new byte[]{'a', 'b', 0, 0, 0, 0, 'g', 'h', 'i', 'j'},
                bytes);
    }

    /// Verifies native FreeBSD timerfd clocks, descriptor flags, timer state, reads, and validation.
    @Test
    public void timerfdSyscallsUseFreeBsdClocksAndFlags() throws Exception {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long timerAddress = memory.baseAddress();
            long currentAddress = memory.baseAddress() + 0x80;
            long bufferAddress = memory.baseAddress() + 0x100;

            invoke(
                    state,
                    FREEBSD_SYS_TIMERFD_CREATE,
                    FREEBSD_CLOCK_MONOTONIC,
                    FREEBSD_O_NONBLOCK | FREEBSD_O_CLOEXEC);
            assertSuccess(state, 3);
            int timerFileDescriptor = (int) state.register(10);
            invoke(state, FREEBSD_SYS_FCNTL, timerFileDescriptor, FREEBSD_F_GETFD, 0);
            assertSuccess(state, FREEBSD_FD_CLOEXEC);
            invoke(state, FREEBSD_SYS_FCNTL, timerFileDescriptor, FREEBSD_F_GETFL, 0);
            assertSuccess(state, FREEBSD_O_RDWR | FREEBSD_O_NONBLOCK);

            invoke(state, FREEBSD_SYS_READ, timerFileDescriptor, bufferAddress, Long.BYTES);
            assertError(state, FREEBSD_EAGAIN);

            memory.clear(timerAddress, 4L * Long.BYTES);
            memory.writeLong(
                    timerAddress + FREEBSD_ITIMERSPEC_VALUE_OFFSET + FREEBSD_TIMESPEC_NANOSECONDS_OFFSET,
                    20_000_000);
            invoke(state, FREEBSD_SYS_TIMERFD_SETTIME, timerFileDescriptor, 0, timerAddress, 0);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_TIMERFD_GETTIME, timerFileDescriptor, currentAddress);
            assertSuccess(state, 0);
            assertEquals(0, memory.readLong(currentAddress));
            assertEquals(0, memory.readLong(currentAddress + FREEBSD_TIMESPEC_NANOSECONDS_OFFSET));
            long remainingSeconds = memory.readLong(currentAddress + FREEBSD_ITIMERSPEC_VALUE_OFFSET);
            long remainingNanoseconds = memory.readLong(
                    currentAddress + FREEBSD_ITIMERSPEC_VALUE_OFFSET + FREEBSD_TIMESPEC_NANOSECONDS_OFFSET);
            assertEquals(0, remainingSeconds);
            assertTrue(remainingNanoseconds >= 0 && remainingNanoseconds <= 20_000_000);

            for (int attempt = 0; attempt < 100; attempt++) {
                invoke(state, FREEBSD_SYS_READ, timerFileDescriptor, bufferAddress, Long.BYTES);
                if (state.register(5) == 0) {
                    break;
                }
                assertError(state, FREEBSD_EAGAIN);
                Thread.sleep(10);
            }
            assertSuccess(state, Long.BYTES);
            assertTrue(memory.readLong(bufferAddress) >= 1);

            memory.writeLong(
                    timerAddress + FREEBSD_ITIMERSPEC_VALUE_OFFSET + FREEBSD_TIMESPEC_NANOSECONDS_OFFSET,
                    1_000_000_000L);
            invoke(state, FREEBSD_SYS_TIMERFD_SETTIME, timerFileDescriptor, 0, timerAddress, 0);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_TIMERFD_GETTIME, timerFileDescriptor, memory.endAddress());
            assertError(state, FREEBSD_EFAULT);
            invoke(state, FREEBSD_SYS_CLOSE, timerFileDescriptor);
            assertSuccess(state, 0);

            invoke(state, FREEBSD_SYS_TIMERFD_CREATE, FREEBSD_CLOCK_UPTIME, 0);
            assertSuccess(state, 3);
            invoke(state, FREEBSD_SYS_CLOSE, 3);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_TIMERFD_CREATE, 1, 0);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_TIMERFD_CREATE, FREEBSD_CLOCK_REALTIME, FREEBSD_O_APPEND);
            assertError(state, FREEBSD_EINVAL);
        }
    }

    /// Verifies FreeBSD path configuration calls validate paths, descriptors, and file kinds.
    @Test
    public void pathconfSyscallsReportFreeBsdLimits() throws Exception {
        Files.writeString(tempDirectory.resolve("config.txt"), "data", StandardCharsets.UTF_8);
        Files.createDirectory(tempDirectory.resolve("config-directory"));
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long filePathAddress = memory.baseAddress();
            long directoryPathAddress = memory.baseAddress() + 0x40;
            long missingPathAddress = memory.baseAddress() + 0x80;
            writeGuestString(memory, filePathAddress, "/config.txt");
            writeGuestString(memory, directoryPathAddress, "/config-directory");
            writeGuestString(memory, missingPathAddress, "/missing");

            invoke(state, FREEBSD_SYS_PATHCONF, filePathAddress, FREEBSD_PC_NAME_MAX);
            assertSuccess(state, 255);
            invoke(state, FREEBSD_SYS_PATHCONF, filePathAddress, FREEBSD_PC_PATH_MAX);
            assertSuccess(state, 1024);
            invoke(state, FREEBSD_SYS_PATHCONF, filePathAddress, FREEBSD_PC_FILESIZEBITS);
            assertSuccess(state, 64);
            invoke(state, FREEBSD_SYS_PATHCONF, filePathAddress, FREEBSD_PC_PIPE_BUF);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_PATHCONF, directoryPathAddress, FREEBSD_PC_PIPE_BUF);
            assertSuccess(state, 512);
            invoke(state, FREEBSD_SYS_LPATHCONF, filePathAddress, FREEBSD_PC_NAME_MAX);
            assertSuccess(state, 255);
            invoke(state, FREEBSD_SYS_PATHCONF, filePathAddress, 999);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_PATHCONF, missingPathAddress, FREEBSD_PC_NAME_MAX);
            assertError(state, FREEBSD_ENOENT);
            invoke(state, FREEBSD_SYS_PATHCONF, memory.endAddress(), FREEBSD_PC_NAME_MAX);
            assertError(state, FREEBSD_EFAULT);

            int fileDescriptor = openReadOnly(state, filePathAddress);
            invoke(state, FREEBSD_SYS_FPATHCONF, fileDescriptor, FREEBSD_PC_NAME_MAX);
            assertSuccess(state, 255);
            invoke(state, FREEBSD_SYS_FPATHCONF, 99, FREEBSD_PC_NAME_MAX);
            assertError(state, FREEBSD_EBADF);
            invoke(state, FREEBSD_SYS_CLOSE, fileDescriptor);
            assertSuccess(state, 0);

            invoke(state, FREEBSD_SYS_PIPE);
            assertSuccess(state, 3);
            int pipeReader = (int) state.register(10);
            int pipeWriter = (int) state.register(11);
            invoke(state, FREEBSD_SYS_FPATHCONF, pipeReader, FREEBSD_PC_PIPE_BUF);
            assertSuccess(state, 512);
            invoke(state, FREEBSD_SYS_CLOSE, pipeReader);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, pipeWriter);
            assertSuccess(state, 0);
        }
    }

    /// Verifies advisory locking uses FreeBSD command numbers and `struct flock` layout.
    @Test
    public void advisoryLockSyscallsUseFreeBsdCommandsAndLayout() throws Exception {
        Files.writeString(tempDirectory.resolve("lock.txt"), "data", StandardCharsets.UTF_8);
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long pathAddress = memory.baseAddress();
            long flockAddress = memory.baseAddress() + 0x100;
            long pairAddress = memory.baseAddress() + 0x200;
            writeGuestString(memory, pathAddress, "/lock.txt");

            invoke(state, FREEBSD_SYS_OPEN, pathAddress, FREEBSD_O_RDWR, 0);
            assertSuccess(state, 3);
            int fileDescriptor = (int) state.register(10);

            memory.clear(flockAddress, FREEBSD_FLOCK_SIZE);
            memory.writeShort(
                    flockAddress + FREEBSD_FLOCK_TYPE_OFFSET,
                    (short) FREEBSD_F_WRLCK);
            invoke(state, FREEBSD_SYS_FCNTL, fileDescriptor, FREEBSD_F_GETLK, flockAddress);
            assertSuccess(state, 0);
            assertEquals(
                    FREEBSD_F_UNLCK,
                    memory.readUnsignedShort(flockAddress + FREEBSD_FLOCK_TYPE_OFFSET));

            memory.writeShort(
                    flockAddress + FREEBSD_FLOCK_TYPE_OFFSET,
                    (short) FREEBSD_F_RDLCK);
            invoke(state, FREEBSD_SYS_FCNTL, fileDescriptor, FREEBSD_F_SETLK, flockAddress);
            assertSuccess(state, 0);
            memory.writeShort(
                    flockAddress + FREEBSD_FLOCK_TYPE_OFFSET,
                    (short) FREEBSD_F_WRLCK);
            invoke(state, FREEBSD_SYS_FCNTL, fileDescriptor, FREEBSD_F_SETLKW, flockAddress);
            assertSuccess(state, 0);

            memory.writeShort(flockAddress + FREEBSD_FLOCK_TYPE_OFFSET, (short) 99);
            invoke(state, FREEBSD_SYS_FCNTL, fileDescriptor, FREEBSD_F_SETLK, flockAddress);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_FCNTL, fileDescriptor, FREEBSD_F_GETLK, memory.endAddress());
            assertError(state, FREEBSD_EFAULT);
            invoke(state, FREEBSD_SYS_FCNTL, fileDescriptor, FREEBSD_F_GETOWN, flockAddress);
            assertError(state, FREEBSD_EINVAL);

            invoke(state, FREEBSD_SYS_FLOCK, fileDescriptor, FREEBSD_LOCK_EX | FREEBSD_LOCK_NB);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_FLOCK, fileDescriptor, FREEBSD_LOCK_UN);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_FLOCK, fileDescriptor, 0);
            assertError(state, FREEBSD_EBADF);
            invoke(state, FREEBSD_SYS_CLOSE, fileDescriptor);
            assertSuccess(state, 0);

            fileDescriptor = openReadOnly(state, pathAddress);
            memory.writeShort(
                    flockAddress + FREEBSD_FLOCK_TYPE_OFFSET,
                    (short) FREEBSD_F_WRLCK);
            invoke(state, FREEBSD_SYS_FCNTL, fileDescriptor, FREEBSD_F_SETLK, flockAddress);
            assertError(state, FREEBSD_EBADF);
            invoke(state, FREEBSD_SYS_CLOSE, fileDescriptor);
            assertSuccess(state, 0);

            invoke(
                    state,
                    FREEBSD_SYS_SOCKETPAIR,
                    FREEBSD_AF_UNIX,
                    FREEBSD_SOCK_STREAM,
                    0,
                    pairAddress);
            assertSuccess(state, 0);
            int firstSocket = memory.readInt(pairAddress);
            int secondSocket = memory.readInt(pairAddress + Integer.BYTES);
            invoke(state, FREEBSD_SYS_FLOCK, firstSocket, FREEBSD_LOCK_SH);
            assertError(state, FREEBSD_ENOTSUP);
            invoke(state, FREEBSD_SYS_CLOSE, firstSocket);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, secondSocket);
            assertSuccess(state, 0);
        }
    }

    /// Verifies `pipe2` flags and FreeBSD exact-target descriptor duplication semantics.
    @Test
    public void pipe2AndFcntlDuplicateUseFreeBsdFlags() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long pairAddress = memory.baseAddress();

            invoke(
                    state,
                    FREEBSD_SYS_PIPE2,
                    pairAddress,
                    FREEBSD_O_NONBLOCK | FREEBSD_O_CLOEXEC);
            assertSuccess(state, 0);
            int readFileDescriptor = memory.readInt(pairAddress);
            int writeFileDescriptor = memory.readInt(pairAddress + Integer.BYTES);

            invoke(state, FREEBSD_SYS_FCNTL, readFileDescriptor, FREEBSD_F_GETFL, 0);
            assertSuccess(state, FREEBSD_O_NONBLOCK);
            invoke(state, FREEBSD_SYS_FCNTL, writeFileDescriptor, FREEBSD_F_GETFL, 0);
            assertSuccess(state, 1 | FREEBSD_O_NONBLOCK);
            invoke(state, FREEBSD_SYS_FCNTL, readFileDescriptor, FREEBSD_F_GETFD, 0);
            assertSuccess(state, 1);

            invoke(state, FREEBSD_SYS_FCNTL, readFileDescriptor, FREEBSD_F_DUP2FD_CLOEXEC, 10);
            assertSuccess(state, 10);
            invoke(state, FREEBSD_SYS_FCNTL, 10, FREEBSD_F_GETFD, 0);
            assertSuccess(state, 1);

            invoke(state, FREEBSD_SYS_CLOSE, readFileDescriptor);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, writeFileDescriptor);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, 10);
            assertSuccess(state, 0);
        }
    }

    /// Verifies `closefrom` closes descriptors at or above its lower bound and clamps negatives to zero.
    @Test
    public void closefromClosesDescriptorsAtOrAboveLimit() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);

            invoke(state, FREEBSD_SYS_PIPE);
            assertSuccess(state, 3);
            int firstReadFileDescriptor = (int) state.register(10);
            int firstWriteFileDescriptor = (int) state.register(11);
            invoke(state, FREEBSD_SYS_PIPE);
            assertSuccess(state, 5);
            int secondReadFileDescriptor = (int) state.register(10);
            int secondWriteFileDescriptor = (int) state.register(11);

            invoke(state, FREEBSD_SYS_CLOSEFROM, secondReadFileDescriptor);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_FCNTL, firstReadFileDescriptor, FREEBSD_F_GETFD, 0);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_FCNTL, firstWriteFileDescriptor, FREEBSD_F_GETFD, 0);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, secondReadFileDescriptor);
            assertError(state, FREEBSD_EBADF);
            invoke(state, FREEBSD_SYS_CLOSE, secondWriteFileDescriptor);
            assertError(state, FREEBSD_EBADF);

            invoke(state, FREEBSD_SYS_CLOSEFROM, firstReadFileDescriptor);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, firstReadFileDescriptor);
            assertError(state, FREEBSD_EBADF);
            invoke(state, FREEBSD_SYS_CLOSE, firstWriteFileDescriptor);
            assertError(state, FREEBSD_EBADF);

            invoke(state, FREEBSD_SYS_PIPE);
            assertSuccess(state, 3);
            int finalReadFileDescriptor = (int) state.register(10);
            int finalWriteFileDescriptor = (int) state.register(11);
            invoke(state, FREEBSD_SYS_CLOSEFROM, -1);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, finalReadFileDescriptor);
            assertError(state, FREEBSD_EBADF);
            invoke(state, FREEBSD_SYS_CLOSE, finalWriteFileDescriptor);
            assertError(state, FREEBSD_EBADF);

            invoke(state, FREEBSD_SYS_PIPE);
            assertSuccess(state, 0);
            assertEquals(1, state.register(11));
            invoke(state, FREEBSD_SYS_CLOSE, 0);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, 1);
            assertSuccess(state, 0);
        }
    }

    /// Verifies FreeBSD range flags affect exec and fork inheritance independently.
    @Test
    public void closeRangeTracksFreeBsdDescriptorFlags() throws Exception {
        CompletableFuture<long[]> childDescriptorFlags = new CompletableFuture<>();
        GuestThreadRunner runner = (childMemory, childState) -> {
            try {
                invoke(childState, FREEBSD_SYS_FCNTL, 3, FREEBSD_F_GETFD, 0);
                long closeOnExecResult = childState.register(10);
                long closeOnExecError = childState.register(5);
                invoke(childState, FREEBSD_SYS_FCNTL, 4, FREEBSD_F_GETFD, 0);
                childDescriptorFlags.complete(new long[]{
                        closeOnExecResult,
                        closeOnExecError,
                        childState.register(10),
                        childState.register(5)
                });
                childState.syscalls().recordThreadExit(childState, 0);
            } catch (Throwable throwable) {
                childDescriptorFlags.completeExceptionally(throwable);
                childState.syscalls().recordThreadFailure(throwable);
            }
        };

        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 65_536)) {
            assertTrue(memory.map(memory.baseAddress(), 16_384));
            RiscVThreadState state = state(
                    memory,
                    tempDirectory,
                    runner,
                    memory.baseAddress() + 16_384);

            invoke(state, FREEBSD_SYS_PIPE);
            assertSuccess(state, 3);
            invoke(state, FREEBSD_SYS_CLOSE_RANGE, 3, 3, FREEBSD_CLOSE_RANGE_CLOEXEC);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE_RANGE, 4, 4, FREEBSD_CLOSE_RANGE_CLOFORK);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_FCNTL, 3, FREEBSD_F_GETFD, 0);
            assertSuccess(state, 1);
            invoke(state, FREEBSD_SYS_FCNTL, 4, FREEBSD_F_GETFD, 0);
            assertSuccess(state, FREEBSD_FD_CLOFORK);

            invoke(state, FREEBSD_SYS_FCNTL, 3, FREEBSD_F_SETFD, FREEBSD_FD_CLOFORK | 1);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_FCNTL, 3, FREEBSD_F_SETFD, 1);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_FORK);
            assertTrue(state.register(10) > 0);
            assertEquals(0, state.register(5));
            assertArrayEquals(
                    new long[]{1, 0, FREEBSD_EBADF, 1},
                    childDescriptorFlags.get(5, TimeUnit.SECONDS));

            invoke(state, FREEBSD_SYS_CLOSE_RANGE, 4, 3, 0);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_CLOSE_RANGE, 3, 4, 1);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_CLOSE_RANGE, 3, 4, 0);
            assertSuccess(state, 0);
        }
    }

    /// Verifies FreeBSD `fork`, non-reaping `wait6`, and final `wait4` process semantics.
    @Test
    public void forkAndWait4UseFreeBsdProcessSemantics() throws Exception {
        CompletableFuture<long[]> childStateSnapshot = new CompletableFuture<>();
        GuestThreadRunner runner = (childMemory, childState) -> {
            try {
                childStateSnapshot.complete(new long[]{
                        childState.register(10),
                        childState.register(5),
                        childState.pc()
                });
                childState.syscalls().recordThreadExit(childState, 7);
            } catch (Throwable throwable) {
                childStateSnapshot.completeExceptionally(throwable);
                childState.syscalls().recordThreadFailure(throwable);
            }
        };

        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 65_536)) {
            long baseAddress = memory.baseAddress();
            assertTrue(memory.map(baseAddress, 16_384));
            RiscVThreadState state = state(memory, tempDirectory, runner, baseAddress + 16_384);
            long statusAddress = baseAddress + 64;
            long rusageAddress = baseAddress + 128;
            long signalInfoAddress = baseAddress + 512;

            invoke(state, FREEBSD_SYS_FORK);
            long childProcessId = state.register(10);
            assertTrue(childProcessId > 0);
            assertEquals(0, state.register(5));

            long[] childRegisters = childStateSnapshot.get(5, TimeUnit.SECONDS);
            assertArrayEquals(new long[]{0, 0, TEST_PC + Integer.BYTES}, childRegisters);

            memory.clear(statusAddress, Integer.BYTES);
            memory.clear(rusageAddress, FREEBSD_WRUSAGE_SIZE);
            memory.clear(signalInfoAddress, 80);
            invoke(
                    state,
                    FREEBSD_SYS_WAIT6,
                    FREEBSD_WAIT_ID_PROCESS,
                    childProcessId,
                    statusAddress,
                    FREEBSD_WAIT_EXITED | FREEBSD_WAIT_NO_WAIT,
                    rusageAddress,
                    signalInfoAddress);
            assertSuccess(state, childProcessId);
            assertEquals(7 << Byte.SIZE, memory.readInt(statusAddress));
            assertArrayEquals(new byte[(int) FREEBSD_WRUSAGE_SIZE], memory.readBytes(rusageAddress, FREEBSD_WRUSAGE_SIZE));
            assertEquals(FREEBSD_SIGCHLD, memory.readInt(signalInfoAddress));
            assertEquals(FREEBSD_CLD_EXITED, memory.readInt(signalInfoAddress + FREEBSD_SIGNAL_INFO_CODE_OFFSET));
            assertEquals(childProcessId, memory.readInt(signalInfoAddress + FREEBSD_SIGNAL_INFO_PROCESS_ID_OFFSET));
            assertEquals(
                    GuestCredentials.DEFAULT_USER_ID,
                    memory.readUnsignedInt(signalInfoAddress + FREEBSD_SIGNAL_INFO_USER_ID_OFFSET));
            assertEquals(7, memory.readInt(signalInfoAddress + FREEBSD_SIGNAL_INFO_STATUS_OFFSET));

            memory.clear(rusageAddress, 144);
            invoke(state, FREEBSD_SYS_WAIT4, childProcessId, statusAddress, 0, rusageAddress);
            assertSuccess(state, childProcessId);
            assertEquals(7 << Byte.SIZE, memory.readInt(statusAddress));
            assertArrayEquals(new byte[144], memory.readBytes(rusageAddress, 144));

            invoke(state, FREEBSD_SYS_WAIT4, -1, statusAddress, 0, rusageAddress);
            assertError(state, FREEBSD_ECHILD);
        }
    }

    /// Verifies a newly executed FreeBSD image receives its initial stack pointer in `a0`.
    @Test
    public void execEntryStatePassesStackPointerInA0() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long stackPointer = memory.baseAddress() + 2048;

            state.setRegister(10, 0);
            state.syscalls().initializeExecEntryState(state, stackPointer);

            assertEquals(stackPointer, state.register(10));
        }
    }

    /// Verifies `kern.proc.pathname` size discovery and trailing-NUL executable path output.
    @Test
    public void sysctlReturnsCurrentExecutablePathname() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long mibAddress = memory.baseAddress();
            long outputLengthAddress = memory.baseAddress() + 64;
            long outputAddress = memory.baseAddress() + 128;
            byte[] expected = "/showcase\0".getBytes(StandardCharsets.UTF_8);

            memory.writeInt(mibAddress, 1);
            memory.writeInt(mibAddress + Integer.BYTES, 14);
            memory.writeInt(mibAddress + 2L * Integer.BYTES, 12);
            memory.writeInt(mibAddress + 3L * Integer.BYTES, -1);
            state.syscalls().procExecutablePath = "/showcase";

            memory.writeLong(outputLengthAddress, 0);
            invoke(state, FREEBSD_SYS___SYSCTL, mibAddress, 4, 0, outputLengthAddress, 0, 0);
            assertSuccess(state, 0);
            assertEquals(expected.length, memory.readLong(outputLengthAddress));

            memory.writeLong(outputLengthAddress, 64);
            invoke(state, FREEBSD_SYS___SYSCTL, mibAddress, 4, outputAddress, outputLengthAddress, 0, 0);
            assertSuccess(state, 0);
            assertEquals(expected.length, memory.readLong(outputLengthAddress));
            assertArrayEquals(expected, memory.readBytes(outputAddress, expected.length));
        }
    }

    /// Verifies FreeBSD scheduling policy numbers, priority ranges, permissions, and structure access order.
    @Test
    public void schedulingSyscallsUseFreeBsdPoliciesAndPriorities() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            long parameterAddress = memory.baseAddress() + 0x100;
            long intervalAddress = memory.baseAddress() + 0x120;
            RiscVThreadState unprivilegedState = state(memory, tempDirectory);

            invoke(unprivilegedState, FREEBSD_SYS_SCHED_GETSCHEDULER, 0);
            assertSuccess(unprivilegedState, FREEBSD_SCHED_OTHER);
            invoke(unprivilegedState, FREEBSD_SYS_SCHED_GETPARAM, 0, parameterAddress);
            assertSuccess(unprivilegedState, 0);
            assertEquals(0, memory.readInt(parameterAddress));

            invoke(unprivilegedState, FREEBSD_SYS_SCHED_GET_PRIORITY_MAX, FREEBSD_SCHED_FIFO);
            assertSuccess(unprivilegedState, 31);
            invoke(unprivilegedState, FREEBSD_SYS_SCHED_GET_PRIORITY_MIN, FREEBSD_SCHED_RR);
            assertSuccess(unprivilegedState, 0);
            invoke(unprivilegedState, FREEBSD_SYS_SCHED_GET_PRIORITY_MAX, FREEBSD_SCHED_OTHER);
            assertSuccess(unprivilegedState, 167);
            invoke(unprivilegedState, FREEBSD_SYS_SCHED_GET_PRIORITY_MIN, FREEBSD_SCHED_OTHER);
            assertSuccess(unprivilegedState, 0);
            invoke(unprivilegedState, FREEBSD_SYS_SCHED_GET_PRIORITY_MAX, 0);
            assertError(unprivilegedState, FREEBSD_EINVAL);

            memory.writeInt(parameterAddress, 167);
            invoke(unprivilegedState, FREEBSD_SYS_SCHED_SETPARAM, 0, parameterAddress);
            assertSuccess(unprivilegedState, 0);
            memory.writeInt(parameterAddress, 168);
            invoke(unprivilegedState, FREEBSD_SYS_SCHED_SETPARAM, 0, parameterAddress);
            assertError(unprivilegedState, FREEBSD_EINVAL);
            memory.writeInt(parameterAddress, 31);
            invoke(
                    unprivilegedState,
                    FREEBSD_SYS_SCHED_SETSCHEDULER,
                    0,
                    FREEBSD_SCHED_RR,
                    parameterAddress);
            assertError(unprivilegedState, FREEBSD_EPERM);
            invoke(
                    unprivilegedState,
                    FREEBSD_SYS_SCHED_SETSCHEDULER,
                    9999,
                    FREEBSD_SCHED_RR,
                    parameterAddress);
            assertError(unprivilegedState, FREEBSD_ESRCH);
            invoke(
                    unprivilegedState,
                    FREEBSD_SYS_SCHED_SETSCHEDULER,
                    9999,
                    FREEBSD_SCHED_RR,
                    memory.endAddress());
            assertError(unprivilegedState, FREEBSD_EFAULT);
            invoke(unprivilegedState, FREEBSD_SYS_SCHED_GETPARAM, 9999, memory.endAddress());
            assertError(unprivilegedState, FREEBSD_ESRCH);

            RiscVThreadState privilegedState = state(
                    memory,
                    tempDirectory,
                    GuestCredentials.of("root", 0, 0, "0", "/root", "/bin/sh"));
            memory.writeInt(parameterAddress, 31);
            invoke(
                    privilegedState,
                    FREEBSD_SYS_SCHED_SETSCHEDULER,
                    0,
                    FREEBSD_SCHED_RR,
                    parameterAddress);
            assertSuccess(privilegedState, 0);
            invoke(privilegedState, FREEBSD_SYS_SCHED_GETSCHEDULER, 0);
            assertSuccess(privilegedState, FREEBSD_SCHED_RR);
            memory.clear(parameterAddress, Integer.BYTES);
            invoke(privilegedState, FREEBSD_SYS_SCHED_GETPARAM, 0, parameterAddress);
            assertSuccess(privilegedState, 0);
            assertEquals(31, memory.readInt(parameterAddress));

            memory.writeInt(parameterAddress, 32);
            invoke(privilegedState, FREEBSD_SYS_SCHED_SETPARAM, 0, parameterAddress);
            assertError(privilegedState, FREEBSD_EINVAL);
            memory.writeInt(parameterAddress, 0);
            invoke(
                    privilegedState,
                    FREEBSD_SYS_SCHED_SETSCHEDULER,
                    0,
                    FREEBSD_SCHED_FIFO,
                    parameterAddress);
            assertSuccess(privilegedState, 0);
            invoke(privilegedState, FREEBSD_SYS_SCHED_GETSCHEDULER, 0);
            assertSuccess(privilegedState, FREEBSD_SCHED_FIFO);
            memory.writeInt(parameterAddress, 168);
            invoke(
                    privilegedState,
                    FREEBSD_SYS_SCHED_SETSCHEDULER,
                    0,
                    FREEBSD_SCHED_OTHER,
                    parameterAddress);
            assertError(privilegedState, FREEBSD_EINVAL);
            memory.writeInt(parameterAddress, 167);
            invoke(
                    privilegedState,
                    FREEBSD_SYS_SCHED_SETSCHEDULER,
                    0,
                    FREEBSD_SCHED_OTHER,
                    parameterAddress);
            assertSuccess(privilegedState, 0);
            invoke(privilegedState, FREEBSD_SYS_SCHED_SETSCHEDULER, 0, 0, parameterAddress);
            assertError(privilegedState, FREEBSD_EINVAL);

            invoke(privilegedState, FREEBSD_SYS_SCHED_RR_GET_INTERVAL, 0, intervalAddress);
            assertSuccess(privilegedState, 0);
            assertEquals(0, memory.readLong(intervalAddress));
            assertEquals(100_000_000L, memory.readLong(intervalAddress + Long.BYTES));
            invoke(privilegedState, FREEBSD_SYS_SCHED_RR_GET_INTERVAL, 9999, memory.endAddress());
            assertError(privilegedState, FREEBSD_ESRCH);
            invoke(privilegedState, FREEBSD_SYS_SCHED_RR_GET_INTERVAL, 0, memory.endAddress());
            assertError(privilegedState, FREEBSD_EFAULT);
            invoke(privilegedState, FREEBSD_SYS_SCHED_YIELD);
            assertSuccess(privilegedState, 0);
        }
    }

    /// Verifies FreeBSD thread lookup, signal validation order, name truncation, and cross-process targeting.
    @Test
    public void threadAdministrationUsesFreeBsdRules() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long threadIdAddress = memory.baseAddress() + 0x80;
            long nameAddress = memory.baseAddress() + 0x100;
            long threadId = state.threadId();

            invoke(state, FREEBSD_SYS_THR_SELF, threadIdAddress);
            assertSuccess(state, 0);
            assertEquals(threadId, memory.readLong(threadIdAddress));
            invoke(state, FREEBSD_SYS_THR_SELF, memory.endAddress());
            assertError(state, FREEBSD_EFAULT);

            writeGuestString(memory, nameAddress, "123456789012345678901234");
            invoke(state, FREEBSD_SYS_THR_SET_NAME, threadId, nameAddress);
            assertSuccess(state, 0);
            assertEquals(
                    "1234567890123456789",
                    state.syscalls().process.thread(threadId).name());
            invoke(state, FREEBSD_SYS_THR_SET_NAME, threadId, 0);
            assertSuccess(state, 0);
            assertEquals("", state.syscalls().process.thread(threadId).name());
            invoke(state, FREEBSD_SYS_THR_SET_NAME, 9999, memory.endAddress());
            assertError(state, FREEBSD_EFAULT);
            invoke(state, FREEBSD_SYS_THR_SET_NAME, 9999, nameAddress);
            assertError(state, FREEBSD_ESRCH);

            invoke(state, FREEBSD_SYS_THR_KILL, threadId, 0);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_THR_KILL, 9999, 9999);
            assertError(state, FREEBSD_ESRCH);
            invoke(state, FREEBSD_SYS_THR_KILL, -1, 9999);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_THR_KILL, -1, 0);
            assertError(state, FREEBSD_ESRCH);

            invoke(state, FREEBSD_SYS_THR_KILL2, GuestProcess.PROCESS_ID, threadId, 0);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_THR_KILL2, GuestProcess.PROCESS_ID, threadId, 9999);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_THR_KILL2, 9999, threadId, 9999);
            assertError(state, FREEBSD_ESRCH);
            invoke(state, FREEBSD_SYS_THR_KILL2, GuestProcess.PROCESS_ID, -1, 0);
            assertError(state, FREEBSD_ESRCH);
        }
    }

    /// Verifies FreeBSD thread suspension consumes coalesced pending wakes and validates relative timeouts.
    @Test
    public void threadSuspendAndWakePreservePendingWakeState() throws Exception {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            GuestSyscalls syscalls = state.syscalls();
            long timeoutAddress = memory.baseAddress() + 0x100;
            long threadId = state.threadId();

            invoke(state, FREEBSD_SYS_THR_WAKE, threadId);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_THR_WAKE, threadId);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_THR_SUSPEND, memory.endAddress());
            assertError(state, FREEBSD_EFAULT);
            invoke(state, FREEBSD_SYS_THR_SUSPEND, 0);
            assertSuccess(state, 0);

            memory.writeLong(timeoutAddress, -1);
            memory.writeLong(timeoutAddress + Long.BYTES, 0);
            invoke(state, FREEBSD_SYS_THR_SUSPEND, timeoutAddress);
            assertError(state, FREEBSD_EINVAL);
            memory.writeLong(timeoutAddress, 0);
            memory.writeLong(timeoutAddress + Long.BYTES, 1_000_000_000L);
            invoke(state, FREEBSD_SYS_THR_SUSPEND, timeoutAddress);
            assertError(state, FREEBSD_EINVAL);
            memory.writeLong(timeoutAddress + Long.BYTES, 0);
            invoke(state, FREEBSD_SYS_THR_SUSPEND, timeoutAddress);
            assertError(state, FREEBSD_ETIMEDOUT);

            invoke(state, FREEBSD_SYS_THR_WAKE, 0);
            assertError(state, FREEBSD_ESRCH);
            invoke(state, FREEBSD_SYS_THR_WAKE, 9999);
            assertError(state, FREEBSD_ESRCH);

            @Nullable GuestThread childThread = syscalls.processRegistry.createChildThread(syscalls.process);
            assertTrue(childThread != null);
            synchronized (syscalls.threadLock) {
                syscalls.process.registerThread(childThread);
            }
            RiscVThreadState childState = state.forkForClone(childThread, TEST_PC, 0, 0, false);
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<long[]> suspendResult = executor.submit(() -> {
                    invoke(childState, FREEBSD_SYS_THR_SUSPEND, 0);
                    return new long[]{childState.register(10), childState.register(5)};
                });
                invoke(state, FREEBSD_SYS_THR_WAKE, childThread.id());
                assertSuccess(state, 0);
                assertArrayEquals(new long[]{0, 0}, suspendResult.get(5, TimeUnit.SECONDS));

                invoke(childState, FREEBSD_SYS_THR_SUSPEND, timeoutAddress);
                assertError(childState, FREEBSD_ETIMEDOUT);
            } finally {
                executor.shutdownNow();
                synchronized (syscalls.threadLock) {
                    syscalls.process.unregisterThread(childThread);
                }
            }
        }
    }

    /// Verifies FreeBSD cpuset calls expose and accept only CPU zero with native size and privilege rules.
    @Test
    public void cpusetAffinityUsesSingleCpuFreeBsdAbi() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long maskAddress = memory.baseAddress() + 0x100;

            memory.writeByte(maskAddress, (byte) 0x7f);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETAFFINITY,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_TID,
                    -1,
                    1,
                    maskAddress);
            assertSuccess(state, 0);
            assertEquals(1, memory.readUnsignedByte(maskAddress));

            byte[] dirtyMask = new byte[16];
            Arrays.fill(dirtyMask, (byte) 0x7f);
            memory.writeBytes(maskAddress, dirtyMask, 0, dirtyMask.length);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETAFFINITY,
                    FREEBSD_CPU_LEVEL_CPUSET,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    16,
                    maskAddress);
            assertSuccess(state, 0);
            assertEquals(1, memory.readUnsignedByte(maskAddress));
            assertArrayEquals(new byte[15], memory.readBytes(maskAddress + 1, 15));
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETAFFINITY,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_TID,
                    -1,
                    0,
                    maskAddress);
            assertError(state, FREEBSD_ERANGE);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETAFFINITY,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_TID,
                    9999,
                    1,
                    memory.endAddress());
            assertError(state, FREEBSD_ESRCH);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETAFFINITY,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_TID,
                    -1,
                    1,
                    memory.endAddress());
            assertError(state, FREEBSD_EFAULT);

            memory.writeByte(maskAddress, (byte) 1);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_SETAFFINITY,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_TID,
                    -1,
                    1,
                    maskAddress);
            assertSuccess(state, 0);
            memory.writeByte(maskAddress, (byte) 0);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_SETAFFINITY,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_TID,
                    -1,
                    1,
                    maskAddress);
            assertError(state, FREEBSD_EDEADLK);
            memory.writeByte(maskAddress, (byte) 2);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_SETAFFINITY,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_TID,
                    -1,
                    1,
                    maskAddress);
            assertError(state, FREEBSD_EINVAL);
            memory.writeByte(maskAddress, (byte) 1);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_SETAFFINITY,
                    FREEBSD_CPU_LEVEL_ROOT,
                    FREEBSD_CPU_WHICH_TID,
                    -1,
                    1,
                    maskAddress);
            assertError(state, FREEBSD_EPERM);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_SETAFFINITY,
                    0,
                    FREEBSD_CPU_WHICH_TID,
                    -1,
                    1,
                    memory.endAddress());
            assertError(state, FREEBSD_EFAULT);

            RiscVThreadState privilegedState = state(
                    memory,
                    tempDirectory,
                    GuestCredentials.of("root", 0, 0, "0", "/root", "/bin/sh"));
            invoke(
                    privilegedState,
                    FREEBSD_SYS_CPUSET_SETAFFINITY,
                    FREEBSD_CPU_LEVEL_ROOT,
                    FREEBSD_CPU_WHICH_TID,
                    -1,
                    1,
                    maskAddress);
            assertSuccess(privilegedState, 0);
        }
    }

    /// Verifies numbered FreeBSD CPU sets are allocated, assigned, queried, and inherited by child processes.
    @Test
    public void cpusetIdsTrackProcessAssignments() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            GuestSyscalls syscalls = state.syscalls();
            long setIdAddress = memory.baseAddress() + 0x100;
            long maskAddress = memory.baseAddress() + 0x180;

            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETID,
                    FREEBSD_CPU_LEVEL_ROOT,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    setIdAddress);
            assertSuccess(state, 0);
            assertEquals(0, memory.readInt(setIdAddress));
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETID,
                    FREEBSD_CPU_LEVEL_CPUSET,
                    FREEBSD_CPU_WHICH_TID,
                    -1,
                    setIdAddress);
            assertSuccess(state, 0);
            assertEquals(1, memory.readInt(setIdAddress));
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETID,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    memory.endAddress());
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_CPUSET, memory.endAddress());
            assertError(state, FREEBSD_EFAULT);

            invoke(state, FREEBSD_SYS_CPUSET, setIdAddress);
            assertSuccess(state, 0);
            int allocatedSetId = memory.readInt(setIdAddress);
            assertTrue(allocatedSetId >= 3);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETID,
                    FREEBSD_CPU_LEVEL_CPUSET,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    setIdAddress);
            assertSuccess(state, 0);
            assertEquals(allocatedSetId, memory.readInt(setIdAddress));
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETID,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_CPUSET,
                    allocatedSetId,
                    setIdAddress);
            assertSuccess(state, 0);
            assertEquals(allocatedSetId, memory.readInt(setIdAddress));

            memory.writeByte(maskAddress, (byte) 0x7f);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETAFFINITY,
                    FREEBSD_CPU_LEVEL_CPUSET,
                    FREEBSD_CPU_WHICH_CPUSET,
                    allocatedSetId,
                    1,
                    maskAddress);
            assertSuccess(state, 0);
            assertEquals(1, memory.readUnsignedByte(maskAddress));

            invoke(state, FREEBSD_SYS_CPUSET_SETID, FREEBSD_CPU_WHICH_TID, -1, allocatedSetId);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_CPUSET_SETID, FREEBSD_CPU_WHICH_PID, -1, 9999);
            assertError(state, FREEBSD_ESRCH);
            invoke(state, FREEBSD_SYS_CPUSET_SETID, FREEBSD_CPU_WHICH_PID, -1, 1);
            assertSuccess(state, 0);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETID,
                    FREEBSD_CPU_LEVEL_CPUSET,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    setIdAddress);
            assertSuccess(state, 0);
            assertEquals(1, memory.readInt(setIdAddress));

            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETID,
                    FREEBSD_CPU_LEVEL_CPUSET,
                    FREEBSD_CPU_WHICH_PID,
                    9999,
                    memory.endAddress());
            assertError(state, FREEBSD_ESRCH);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETID,
                    FREEBSD_CPU_LEVEL_CPUSET,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    memory.endAddress());
            assertError(state, FREEBSD_EFAULT);

            invoke(state, FREEBSD_SYS_CPUSET_SETID, FREEBSD_CPU_WHICH_PID, -1, allocatedSetId);
            assertSuccess(state, 0);
            @Nullable GuestProcess childProcess = syscalls.processRegistry.createChildProcess(syscalls.process);
            assertTrue(childProcess != null);
            assertEquals(allocatedSetId, childProcess.freeBsdCpuSetId());
        }
    }

    /// Verifies FreeBSD memory-domain masks, policy persistence, permissions, and ABI error ordering.
    @Test
    public void cpusetDomainsExposeTheSingleRiscVMemoryDomain() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long maskAddress = memory.baseAddress() + 0x100;
            long policyAddress = memory.baseAddress() + 0x140;
            long setIdAddress = memory.baseAddress() + 0x180;

            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETDOMAIN,
                    FREEBSD_CPU_LEVEL_CPUSET,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    7,
                    memory.endAddress(),
                    memory.endAddress());
            assertError(state, FREEBSD_ERANGE);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETDOMAIN,
                    FREEBSD_CPU_LEVEL_CPUSET,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    33,
                    memory.endAddress(),
                    memory.endAddress());
            assertError(state, FREEBSD_ERANGE);

            byte[] dirtyMask = new byte[32];
            Arrays.fill(dirtyMask, (byte) 0x7f);
            memory.writeBytes(maskAddress, dirtyMask, 0, dirtyMask.length);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETDOMAIN,
                    FREEBSD_CPU_LEVEL_CPUSET,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    32,
                    maskAddress,
                    policyAddress);
            assertSuccess(state, 0);
            assertEquals(1, memory.readUnsignedByte(maskAddress));
            assertArrayEquals(new byte[31], memory.readBytes(maskAddress + 1, 31));
            assertEquals(FREEBSD_DOMAINSET_POLICY_FIRSTTOUCH, memory.readInt(policyAddress));

            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETDOMAIN,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_CPUSET,
                    2,
                    8,
                    maskAddress,
                    policyAddress);
            assertSuccess(state, 0);
            assertEquals(FREEBSD_DOMAINSET_POLICY_INTERLEAVE, memory.readInt(policyAddress));
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETDOMAIN,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_PID,
                    9999,
                    8,
                    memory.endAddress(),
                    memory.endAddress());
            assertError(state, FREEBSD_ESRCH);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETDOMAIN,
                    0,
                    FREEBSD_CPU_WHICH_PID,
                    9999,
                    8,
                    memory.endAddress(),
                    memory.endAddress());
            assertError(state, FREEBSD_ESRCH);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETDOMAIN,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    8,
                    memory.endAddress(),
                    policyAddress);
            assertError(state, FREEBSD_EFAULT);

            Arrays.fill(dirtyMask, (byte) 0x7f);
            memory.writeBytes(maskAddress, dirtyMask, 0, Long.BYTES);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETDOMAIN,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    8,
                    maskAddress,
                    memory.endAddress());
            assertError(state, FREEBSD_EFAULT);
            assertEquals(1, memory.readUnsignedByte(maskAddress));
            assertArrayEquals(new byte[7], memory.readBytes(maskAddress + 1, 7));

            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_SETDOMAIN,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    7,
                    memory.endAddress(),
                    0);
            assertError(state, FREEBSD_ERANGE);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_SETDOMAIN,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    8,
                    memory.endAddress(),
                    0);
            assertError(state, FREEBSD_EFAULT);

            memory.clear(maskAddress, 32);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_SETDOMAIN,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    8,
                    maskAddress,
                    0);
            assertError(state, FREEBSD_EINVAL);
            memory.writeByte(maskAddress, (byte) 2);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_SETDOMAIN,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    8,
                    maskAddress,
                    FREEBSD_DOMAINSET_POLICY_FIRSTTOUCH);
            assertError(state, FREEBSD_EINVAL);
            memory.writeByte(maskAddress, (byte) 0);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_SETDOMAIN,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    8,
                    maskAddress,
                    FREEBSD_DOMAINSET_POLICY_FIRSTTOUCH);
            assertError(state, FREEBSD_EDEADLK);
            memory.writeByte(maskAddress, (byte) 1);
            memory.writeByte(maskAddress + Long.BYTES, (byte) 1);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_SETDOMAIN,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    32,
                    maskAddress,
                    FREEBSD_DOMAINSET_POLICY_FIRSTTOUCH);
            assertError(state, FREEBSD_EINVAL);

            memory.clear(maskAddress, 32);
            memory.writeByte(maskAddress, (byte) 1);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_SETDOMAIN,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    8,
                    maskAddress,
                    FREEBSD_DOMAINSET_POLICY_PREFER);
            assertSuccess(state, 0);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETDOMAIN,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    8,
                    maskAddress,
                    policyAddress);
            assertSuccess(state, 0);
            assertEquals(FREEBSD_DOMAINSET_POLICY_PREFER, memory.readInt(policyAddress));
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_GETDOMAIN,
                    FREEBSD_CPU_LEVEL_CPUSET,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    8,
                    maskAddress,
                    policyAddress);
            assertSuccess(state, 0);
            assertEquals(FREEBSD_DOMAINSET_POLICY_FIRSTTOUCH, memory.readInt(policyAddress));
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_SETDOMAIN,
                    FREEBSD_CPU_LEVEL_CPUSET,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    8,
                    maskAddress,
                    FREEBSD_DOMAINSET_POLICY_ROUNDROBIN);
            assertError(state, FREEBSD_EPERM);
            invoke(
                    state,
                    FREEBSD_SYS_CPUSET_SETDOMAIN,
                    FREEBSD_CPU_LEVEL_ROOT,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    8,
                    maskAddress,
                    FREEBSD_DOMAINSET_POLICY_ROUNDROBIN);
            assertError(state, FREEBSD_EPERM);

            RiscVThreadState privilegedState = state(
                    memory,
                    tempDirectory,
                    GuestCredentials.of("root", 0, 0, "0", "/root", "/bin/sh"));
            memory.clear(maskAddress, 32);
            memory.writeByte(maskAddress, (byte) 1);
            invoke(
                    privilegedState,
                    FREEBSD_SYS_CPUSET_SETDOMAIN,
                    FREEBSD_CPU_LEVEL_CPUSET,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    8,
                    maskAddress,
                    FREEBSD_DOMAINSET_POLICY_ROUNDROBIN);
            assertSuccess(privilegedState, 0);
            invoke(
                    privilegedState,
                    FREEBSD_SYS_CPUSET_GETDOMAIN,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    8,
                    maskAddress,
                    policyAddress);
            assertSuccess(privilegedState, 0);
            assertEquals(FREEBSD_DOMAINSET_POLICY_ROUNDROBIN, memory.readInt(policyAddress));

            invoke(privilegedState, FREEBSD_SYS_CPUSET, setIdAddress);
            assertSuccess(privilegedState, 0);
            int allocatedSetId = memory.readInt(setIdAddress);
            invoke(
                    privilegedState,
                    FREEBSD_SYS_CPUSET_GETDOMAIN,
                    FREEBSD_CPU_LEVEL_CPUSET,
                    FREEBSD_CPU_WHICH_CPUSET,
                    allocatedSetId,
                    8,
                    maskAddress,
                    policyAddress);
            assertSuccess(privilegedState, 0);
            assertEquals(FREEBSD_DOMAINSET_POLICY_FIRSTTOUCH, memory.readInt(policyAddress));
            invoke(
                    privilegedState,
                    FREEBSD_SYS_CPUSET_SETDOMAIN,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_CPUSET,
                    allocatedSetId,
                    8,
                    maskAddress,
                    FREEBSD_DOMAINSET_POLICY_PREFER);
            assertSuccess(privilegedState, 0);
            invoke(
                    privilegedState,
                    FREEBSD_SYS_CPUSET_GETDOMAIN,
                    FREEBSD_CPU_LEVEL_WHICH,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    8,
                    maskAddress,
                    policyAddress);
            assertSuccess(privilegedState, 0);
            assertEquals(FREEBSD_DOMAINSET_POLICY_PREFER, memory.readInt(policyAddress));
            invoke(
                    privilegedState,
                    FREEBSD_SYS_CPUSET_SETDOMAIN,
                    FREEBSD_CPU_LEVEL_ROOT,
                    FREEBSD_CPU_WHICH_PID,
                    -1,
                    8,
                    maskAddress,
                    FREEBSD_DOMAINSET_POLICY_INTERLEAVE);
            assertError(privilegedState, FREEBSD_EPERM);
        }
    }

    /// Verifies scheduler yielding, memory-barrier probing, CPU queries, and modern kqueue flags.
    @Test
    public void schedGetcpuAndKqueuexUseFreeBsdAbi() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);

            invoke(state, FREEBSD_SYS_YIELD);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_MEMBARRIER, 0, 0, 123);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_MEMBARRIER, 1, 0, 0);
            assertError(state, FREEBSD_EINVAL);
            invoke(state, FREEBSD_SYS_MEMBARRIER, 0, 1, 0);
            assertError(state, FREEBSD_EINVAL);

            invoke(state, FREEBSD_SYS_SCHED_GETCPU);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_KQUEUEX, FREEBSD_KQUEUE_CLOEXEC);
            assertSuccess(state, 3);
            invoke(state, FREEBSD_SYS_FCNTL, 3, FREEBSD_F_GETFD, 0);
            assertSuccess(state, FREEBSD_FD_CLOEXEC);
            invoke(state, FREEBSD_SYS_CLOSE, 3);
            assertSuccess(state, 0);

            invoke(state, FREEBSD_SYS_KQUEUEX, 0);
            assertSuccess(state, 3);
            invoke(state, FREEBSD_SYS_FCNTL, 3, FREEBSD_F_GETFD, 0);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, 3);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_KQUEUEX, 4);
            assertError(state, FREEBSD_EINVAL);
        }
    }

    /// Verifies a changed unsigned umtx word returns success instead of Linux-style `EAGAIN`.
    @Test
    public void umtxWaitTreatsChangedValueAsSuccess() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long umtxAddress = memory.baseAddress();
            memory.writeInt(umtxAddress, 7);

            invoke(
                    state,
                    FREEBSD_SYS_UMTX_OP,
                    umtxAddress,
                    FREEBSD_UMTX_OP_WAIT_UINT_PRIVATE,
                    9,
                    0,
                    0);
            assertSuccess(state, 0);

            invoke(
                    state,
                    FREEBSD_SYS_UMTX_OP,
                    umtxAddress,
                    FREEBSD_UMTX_OP_WAIT_UINT_PRIVATE,
                    7,
                    0,
                    0);
            assertError(state, FREEBSD_ETIMEDOUT);
        }
    }

    /// Verifies FreeBSD umtx waits distinguish legacy timespec and extended clock-aware timeout layouts.
    @Test
    public void umtxWaitParsesFreeBsdTimeoutLayouts() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    tempDirectory,
                    GuestCredentials.defaultUser(),
                    TimeSource.fixed(Instant.ofEpochSecond(1_700_000_000L, 500_000_000L)),
                    memory.baseAddress());
            long umtxAddress = memory.baseAddress();
            long timeoutAddress = memory.baseAddress() + 0x100;
            long legacyTimeoutAddress = memory.endAddress() - 2L * Long.BYTES;
            memory.writeInt(umtxAddress, 7);
            memory.writeLong(legacyTimeoutAddress, 0);
            memory.writeLong(legacyTimeoutAddress + Long.BYTES, 1);

            invoke(
                    state,
                    FREEBSD_SYS_UMTX_OP,
                    umtxAddress,
                    FREEBSD_UMTX_OP_WAIT_UINT_PRIVATE,
                    9,
                    2L * Long.BYTES,
                    legacyTimeoutAddress);
            assertSuccess(state, 0);
            invoke(
                    state,
                    FREEBSD_SYS_UMTX_OP,
                    umtxAddress,
                    FREEBSD_UMTX_OP_WAIT_UINT_PRIVATE,
                    9,
                    2L * Long.BYTES + 1,
                    legacyTimeoutAddress);
            assertError(state, FREEBSD_EFAULT);

            memory.clear(timeoutAddress, FREEBSD_UMTX_TIME_SIZE);
            memory.writeLong(timeoutAddress, 1_699_999_999L);
            memory.writeInt(timeoutAddress + FREEBSD_UMTX_TIME_FLAGS_OFFSET, (int) FREEBSD_UMTX_ABSTIME);
            memory.writeInt(timeoutAddress + FREEBSD_UMTX_TIME_CLOCK_ID_OFFSET, (int) FREEBSD_CLOCK_REALTIME);
            invoke(
                    state,
                    FREEBSD_SYS_UMTX_OP,
                    umtxAddress,
                    FREEBSD_UMTX_OP_WAIT_UINT_PRIVATE,
                    7,
                    FREEBSD_UMTX_TIME_SIZE,
                    timeoutAddress);
            assertError(state, FREEBSD_ETIMEDOUT);

            memory.writeInt(timeoutAddress + FREEBSD_UMTX_TIME_CLOCK_ID_OFFSET, 999);
            invoke(
                    state,
                    FREEBSD_SYS_UMTX_OP,
                    umtxAddress,
                    FREEBSD_UMTX_OP_WAIT_UINT_PRIVATE,
                    9,
                    FREEBSD_UMTX_TIME_SIZE,
                    timeoutAddress);
            assertError(state, FREEBSD_EINVAL);
            memory.writeInt(timeoutAddress + FREEBSD_UMTX_TIME_CLOCK_ID_OFFSET, (int) FREEBSD_CLOCK_MONOTONIC);
            memory.writeLong(timeoutAddress + Long.BYTES, 1_000_000_000L);
            invoke(
                    state,
                    FREEBSD_SYS_UMTX_OP,
                    umtxAddress,
                    FREEBSD_UMTX_OP_WAIT_UINT_PRIVATE,
                    9,
                    FREEBSD_UMTX_TIME_SIZE,
                    timeoutAddress);
            assertError(state, FREEBSD_EINVAL);
        }
    }

    /// Verifies current FreeBSD kqueue registration, edge clearing, and user-triggered event layouts.
    @Test
    public void kqueueReportsDescriptorAndUserEvents() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long pairAddress = memory.baseAddress();
            long changeAddress = memory.baseAddress() + 128;
            long eventAddress = memory.baseAddress() + 256;
            long timeoutAddress = memory.baseAddress() + 512;
            long bufferAddress = memory.baseAddress() + 768;

            invoke(state, FREEBSD_SYS_KQUEUE);
            assertSuccess(state, 3);
            int kqueueFileDescriptor = 3;
            invoke(
                    state,
                    FREEBSD_SYS_SOCKETPAIR,
                    FREEBSD_AF_UNIX,
                    FREEBSD_SOCK_STREAM | FREEBSD_SOCK_NONBLOCK,
                    0,
                    pairAddress);
            assertSuccess(state, 0);
            int writerFileDescriptor = memory.readInt(pairAddress);
            int readerFileDescriptor = memory.readInt(pairAddress + Integer.BYTES);

            writeFreeBsdKevent(
                    memory,
                    changeAddress,
                    readerFileDescriptor,
                    FREEBSD_EVFILT_READ,
                    FREEBSD_EV_ADD | FREEBSD_EV_CLEAR,
                    0,
                    0x1122_3344_5566_7788L);
            invoke(
                    state,
                    FREEBSD_SYS_KEVENT,
                    kqueueFileDescriptor,
                    changeAddress,
                    1,
                    0,
                    0,
                    0);
            assertSuccess(state, 0);

            memory.writeByte(bufferAddress, (byte) 0x5a);
            invoke(state, FREEBSD_SYS_WRITE, writerFileDescriptor, bufferAddress, 1);
            assertSuccess(state, 1);
            memory.writeLong(timeoutAddress, 0);
            memory.writeLong(timeoutAddress + Long.BYTES, 0);
            invoke(
                    state,
                    FREEBSD_SYS_KEVENT,
                    kqueueFileDescriptor,
                    0,
                    0,
                    eventAddress,
                    1,
                    timeoutAddress);
            assertSuccess(state, 1);
            assertEquals(readerFileDescriptor, memory.readLong(eventAddress));
            assertEquals(FREEBSD_EVFILT_READ, memory.readShort(eventAddress + FREEBSD_KEVENT_FILTER_OFFSET));
            assertEquals(
                    FREEBSD_EV_CLEAR,
                    memory.readUnsignedShort(eventAddress + FREEBSD_KEVENT_FLAGS_OFFSET));
            assertEquals(0, memory.readUnsignedInt(eventAddress + FREEBSD_KEVENT_FILTER_FLAGS_OFFSET));
            assertEquals(0, memory.readLong(eventAddress + FREEBSD_KEVENT_DATA_OFFSET));
            assertEquals(0x1122_3344_5566_7788L, memory.readLong(eventAddress + FREEBSD_KEVENT_USER_DATA_OFFSET));
            assertEquals(0, memory.readLong(eventAddress + FREEBSD_KEVENT_SIZE - Long.BYTES));

            invoke(
                    state,
                    FREEBSD_SYS_KEVENT,
                    kqueueFileDescriptor,
                    0,
                    0,
                    eventAddress,
                    1,
                    timeoutAddress);
            assertSuccess(state, 0);

            writeFreeBsdKevent(
                    memory,
                    changeAddress,
                    0xee1e_b9f4L,
                    FREEBSD_EVFILT_USER,
                    FREEBSD_EV_ADD | FREEBSD_EV_CLEAR,
                    0,
                    0x7abcL);
            invoke(state, FREEBSD_SYS_KEVENT, kqueueFileDescriptor, changeAddress, 1, 0, 0, 0);
            assertSuccess(state, 0);
            writeFreeBsdKevent(
                    memory,
                    changeAddress,
                    0xee1e_b9f4L,
                    FREEBSD_EVFILT_USER,
                    0,
                    FREEBSD_NOTE_TRIGGER,
                    0);
            invoke(state, FREEBSD_SYS_KEVENT, kqueueFileDescriptor, changeAddress, 1, 0, 0, 0);
            assertSuccess(state, 0);
            invoke(
                    state,
                    FREEBSD_SYS_KEVENT,
                    kqueueFileDescriptor,
                    0,
                    0,
                    eventAddress,
                    1,
                    timeoutAddress);
            assertSuccess(state, 1);
            assertEquals(0xee1e_b9f4L, memory.readLong(eventAddress));
            assertEquals(FREEBSD_EVFILT_USER, memory.readShort(eventAddress + FREEBSD_KEVENT_FILTER_OFFSET));
            assertEquals(0x7abcL, memory.readLong(eventAddress + FREEBSD_KEVENT_USER_DATA_OFFSET));

            invoke(state, FREEBSD_SYS_CLOSE, writerFileDescriptor);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, readerFileDescriptor);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, kqueueFileDescriptor);
            assertSuccess(state, 0);
        }
    }

    /// Verifies one kqueue scan preserves TCP connection readiness across read and write filters.
    @Test
    public void kqueueReportsNonblockingTcpConnectionReadiness() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = hostNetworkState(memory, tempDirectory);
            long sockaddrAddress = memory.baseAddress();
            long lengthAddress = memory.baseAddress() + 64;
            long changeAddress = memory.baseAddress() + 128;
            long eventAddress = memory.baseAddress() + 384;
            long timeoutAddress = memory.baseAddress() + 512;

            invoke(state, FREEBSD_SYS_KQUEUE);
            assertSuccess(state, 3);
            int kqueueFileDescriptor = 3;
            invoke(
                    state,
                    FREEBSD_SYS_SOCKET,
                    FREEBSD_AF_INET,
                    FREEBSD_SOCK_STREAM | FREEBSD_SOCK_NONBLOCK,
                    FREEBSD_IPPROTO_TCP);
            assertSuccess(state, 4);
            int serverFileDescriptor = 4;
            writeFreeBsdInetSockaddr(memory, sockaddrAddress, loopback, 0);
            invoke(
                    state,
                    FREEBSD_SYS_BIND,
                    serverFileDescriptor,
                    sockaddrAddress,
                    FREEBSD_SOCKADDR_IN_SIZE);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_LISTEN, serverFileDescriptor, 1);
            assertSuccess(state, 0);
            memory.writeInt(lengthAddress, FREEBSD_SOCKADDR_IN_SIZE);
            invoke(
                    state,
                    FREEBSD_SYS_GETSOCKNAME,
                    serverFileDescriptor,
                    sockaddrAddress,
                    lengthAddress);
            assertSuccess(state, 0);
            int serverPort = (memory.readUnsignedByte(sockaddrAddress + FREEBSD_SOCKADDR_PORT_OFFSET) << Byte.SIZE)
                    | memory.readUnsignedByte(sockaddrAddress + FREEBSD_SOCKADDR_PORT_OFFSET + 1);

            invoke(
                    state,
                    FREEBSD_SYS_SOCKET,
                    FREEBSD_AF_INET,
                    FREEBSD_SOCK_STREAM | FREEBSD_SOCK_NONBLOCK,
                    FREEBSD_IPPROTO_TCP);
            assertSuccess(state, 5);
            int socketFileDescriptor = 5;

            writeFreeBsdKevent(
                    memory,
                    changeAddress,
                    socketFileDescriptor,
                    FREEBSD_EVFILT_READ,
                    FREEBSD_EV_ADD | FREEBSD_EV_CLEAR,
                    0,
                    0x1111L);
            writeFreeBsdKevent(
                    memory,
                    changeAddress + FREEBSD_KEVENT_SIZE,
                    socketFileDescriptor,
                    FREEBSD_EVFILT_WRITE,
                    FREEBSD_EV_ADD | FREEBSD_EV_CLEAR,
                    0,
                    0x2222L);
            invoke(
                    state,
                    FREEBSD_SYS_KEVENT,
                    kqueueFileDescriptor,
                    changeAddress,
                    2,
                    0,
                    0,
                    0);
            assertSuccess(state, 0);

            writeFreeBsdInetSockaddr(memory, sockaddrAddress, loopback, serverPort);
            invoke(
                    state,
                    FREEBSD_SYS_CONNECT,
                    socketFileDescriptor,
                    sockaddrAddress,
                    FREEBSD_SOCKADDR_IN_SIZE);
            if (state.register(5) == 0) {
                assertSuccess(state, 0);
            } else {
                assertError(state, FREEBSD_EINPROGRESS);
            }

            memory.writeLong(timeoutAddress, 5);
            memory.writeLong(timeoutAddress + Long.BYTES, 0);
            invoke(
                    state,
                    FREEBSD_SYS_KEVENT,
                    kqueueFileDescriptor,
                    0,
                    0,
                    eventAddress,
                    1,
                    timeoutAddress);
            assertSuccess(state, 1);
            assertEquals(socketFileDescriptor, memory.readLong(eventAddress));
            assertEquals(FREEBSD_EVFILT_WRITE, memory.readShort(eventAddress + FREEBSD_KEVENT_FILTER_OFFSET));
            assertEquals(0x2222L, memory.readLong(eventAddress + FREEBSD_KEVENT_USER_DATA_OFFSET));

            invoke(state, FREEBSD_SYS_CLOSE, socketFileDescriptor);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, serverFileDescriptor);
            assertSuccess(state, 0);
            invoke(state, FREEBSD_SYS_CLOSE, kqueueFileDescriptor);
            assertSuccess(state, 0);
        }
    }

    /// Verifies a FreeBSD IPv4 TCP client exchanges bytes and exposes native socket addresses and options.
    @Test
    public void hostNetworkTcpClientUsesFreeBsdAbi() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (ServerSocket server = new ServerSocket(0, 1, loopback);
             Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = hostNetworkState(memory, tempDirectory);
            long sockaddrAddress = memory.baseAddress();
            long lengthAddress = memory.baseAddress() + 64;
            long bufferAddress = memory.baseAddress() + 128;
            long optionAddress = memory.baseAddress() + 256;
            long optionLengthAddress = memory.baseAddress() + 264;
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> serverTask = executor.submit(() -> {
                    try (Socket socket = server.accept()) {
                        assertArrayEquals(
                                "ping".getBytes(StandardCharsets.UTF_8),
                                socket.getInputStream().readNBytes(4));
                        socket.getOutputStream().write("pong".getBytes(StandardCharsets.UTF_8));
                    }
                    return null;
                });

                invoke(
                        state,
                        FREEBSD_SYS_SOCKET,
                        FREEBSD_AF_INET,
                        FREEBSD_SOCK_STREAM,
                        FREEBSD_IPPROTO_TCP);
                assertSuccess(state, 3);
                int fileDescriptor = 3;

                memory.writeInt(optionAddress, 1);
                invoke(
                        state,
                        FREEBSD_SYS_SETSOCKOPT,
                        fileDescriptor,
                        FREEBSD_SOL_SOCKET,
                        FREEBSD_SO_KEEPALIVE,
                        optionAddress,
                        Integer.BYTES);
                assertSuccess(state, 0);
                memory.writeInt(optionLengthAddress, Integer.BYTES);
                invoke(
                        state,
                        FREEBSD_SYS_GETSOCKOPT,
                        fileDescriptor,
                        FREEBSD_SOL_SOCKET,
                        FREEBSD_SO_KEEPALIVE,
                        optionAddress,
                        optionLengthAddress);
                assertSuccess(state, 0);
                assertEquals(1, memory.readInt(optionAddress));

                writeFreeBsdInetSockaddr(memory, sockaddrAddress, loopback, server.getLocalPort());
                invoke(state, FREEBSD_SYS_CONNECT, fileDescriptor, sockaddrAddress, FREEBSD_SOCKADDR_IN_SIZE);
                assertSuccess(state, 0);

                memory.writeInt(lengthAddress, FREEBSD_SOCKADDR_IN_SIZE);
                invoke(state, FREEBSD_SYS_GETSOCKNAME, fileDescriptor, sockaddrAddress, lengthAddress);
                assertSuccess(state, 0);
                assertFreeBsdIpv4Sockaddr(memory, sockaddrAddress, lengthAddress, loopback, -1);

                memory.writeInt(lengthAddress, FREEBSD_SOCKADDR_IN_SIZE);
                invoke(state, FREEBSD_SYS_GETPEERNAME, fileDescriptor, sockaddrAddress, lengthAddress);
                assertSuccess(state, 0);
                assertFreeBsdIpv4Sockaddr(
                        memory,
                        sockaddrAddress,
                        lengthAddress,
                        loopback,
                        server.getLocalPort());

                memory.writeInt(optionLengthAddress, Integer.BYTES);
                invoke(
                        state,
                        FREEBSD_SYS_GETSOCKOPT,
                        fileDescriptor,
                        FREEBSD_SOL_SOCKET,
                        FREEBSD_SO_ERROR,
                        optionAddress,
                        optionLengthAddress);
                assertSuccess(state, 0);
                assertEquals(0, memory.readInt(optionAddress));

                byte[] request = "ping".getBytes(StandardCharsets.UTF_8);
                memory.writeBytes(bufferAddress, request, 0, request.length);
                invoke(state, FREEBSD_SYS_WRITE, fileDescriptor, bufferAddress, request.length);
                assertSuccess(state, request.length);
                invoke(state, FREEBSD_SYS_READ, fileDescriptor, bufferAddress, 4);
                assertSuccess(state, 4);
                assertEquals("pong", new String(memory.readBytes(bufferAddress, 4), StandardCharsets.UTF_8));

                invoke(state, FREEBSD_SYS_CLOSE, fileDescriptor);
                assertSuccess(state, 0);
                serverTask.get(5, TimeUnit.SECONDS);
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /// Verifies FreeBSD `sendmsg` and `recvmsg` use the native 48-byte message header and UDP addresses.
    @Test
    public void hostNetworkUdpMessagesUseFreeBsdMsghdrLayout() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (DatagramSocket server = new DatagramSocket(new InetSocketAddress(loopback, 0));
             Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = hostNetworkState(memory, tempDirectory);
            long messageAddress = memory.baseAddress();
            long sockaddrAddress = memory.baseAddress() + 128;
            long iovecAddress = memory.baseAddress() + 256;
            long bufferAddress = memory.baseAddress() + 512;
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> serverTask = executor.submit(() -> {
                    byte[] request = new byte[4];
                    DatagramPacket packet = new DatagramPacket(request, request.length);
                    server.receive(packet);
                    assertArrayEquals("ping".getBytes(StandardCharsets.UTF_8), packet.getData());
                    byte[] response = "pong".getBytes(StandardCharsets.UTF_8);
                    server.send(new DatagramPacket(response, response.length, packet.getSocketAddress()));
                    return null;
                });

                invoke(
                        state,
                        FREEBSD_SYS_SOCKET,
                        FREEBSD_AF_INET,
                        FREEBSD_SOCK_DGRAM,
                        FREEBSD_IPPROTO_UDP);
                assertSuccess(state, 3);
                int fileDescriptor = 3;

                writeFreeBsdInetSockaddr(memory, sockaddrAddress, loopback, server.getLocalPort());
                byte[] request = "ping".getBytes(StandardCharsets.UTF_8);
                memory.writeBytes(bufferAddress, request, 0, request.length);
                writeFreeBsdMessageHeader(
                        memory,
                        messageAddress,
                        sockaddrAddress,
                        FREEBSD_SOCKADDR_IN_SIZE,
                        iovecAddress,
                        1);
                memory.writeLong(iovecAddress + FREEBSD_IOVEC_BASE_OFFSET, bufferAddress);
                memory.writeLong(iovecAddress + FREEBSD_IOVEC_LENGTH_OFFSET, request.length);
                invoke(state, FREEBSD_SYS_SENDMSG, fileDescriptor, messageAddress, FREEBSD_MSG_NOSIGNAL);
                assertSuccess(state, request.length);

                memory.clear(bufferAddress, 4);
                memory.writeInt(messageAddress + FREEBSD_MSGHDR_NAME_LENGTH_OFFSET, FREEBSD_SOCKADDR_IN_SIZE);
                memory.writeInt(messageAddress + FREEBSD_MSGHDR_FLAGS_OFFSET, 0x7f);
                memory.writeInt(messageAddress + FREEBSD_MSGHDR_FLAGS_OFFSET + Integer.BYTES, 0x1234_5678);
                invoke(state, FREEBSD_SYS_RECVMSG, fileDescriptor, messageAddress, 0);
                assertSuccess(state, 4);
                assertEquals("pong", new String(memory.readBytes(bufferAddress, 4), StandardCharsets.UTF_8));
                assertEquals(0, memory.readInt(messageAddress + FREEBSD_MSGHDR_FLAGS_OFFSET));
                assertEquals(0x1234_5678, memory.readInt(messageAddress + FREEBSD_MSGHDR_FLAGS_OFFSET + Integer.BYTES));
                assertFreeBsdIpv4Sockaddr(
                        memory,
                        sockaddrAddress,
                        messageAddress + FREEBSD_MSGHDR_NAME_LENGTH_OFFSET,
                        loopback,
                        server.getLocalPort());

                invoke(state, FREEBSD_SYS_CLOSE, fileDescriptor);
                assertSuccess(state, 0);
                serverTask.get(5, TimeUnit.SECONDS);
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /// Verifies `getdirentries` writes variable-length FreeBSD directory records and advances its cursor.
    @Test
    public void getdirentriesWritesFreeBsdLayoutAndCursor() throws Exception {
        Files.createDirectory(tempDirectory.resolve("directory"));
        Files.writeString(tempDirectory.resolve("message.txt"), "hello", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 512;
            long baseAddress = memory.baseAddress() + 2048;
            writeGuestString(memory, pathAddress, "/");
            invoke(state, FREEBSD_SYS_OPEN, pathAddress, 0, 0);
            assertSuccess(state, 3);

            invoke(state, FREEBSD_SYS_GETDIRENTRIES, 3, bufferAddress, 31, baseAddress);
            assertError(state, FREEBSD_EINVAL);

            invoke(state, FREEBSD_SYS_GETDIRENTRIES, 3, bufferAddress, 512, baseAddress);
            long byteCount = state.register(10);
            assertEquals(0, state.register(5));
            assertTrue(byteCount > 0);
            assertEquals(0, memory.readLong(baseAddress));

            long address = assertDirectoryEntry(
                    memory,
                    bufferAddress,
                    ".",
                    FREEBSD_DIRECTORY_ENTRY_DIRECTORY,
                    1);
            address = assertDirectoryEntry(
                    memory,
                    address,
                    "..",
                    FREEBSD_DIRECTORY_ENTRY_DIRECTORY,
                    2);
            address = assertDirectoryEntry(
                    memory,
                    address,
                    "directory",
                    FREEBSD_DIRECTORY_ENTRY_DIRECTORY,
                    3);
            address = assertDirectoryEntry(
                    memory,
                    address,
                    "message.txt",
                    FREEBSD_DIRECTORY_ENTRY_REGULAR_FILE,
                    4);
            assertEquals(bufferAddress + byteCount, address);

            invoke(state, FREEBSD_SYS_GETDIRENTRIES, 3, bufferAddress, 512, baseAddress);
            assertSuccess(state, 0);
            assertEquals(4, memory.readLong(baseAddress));

            invoke(state, FREEBSD_SYS_GETDIRENTRIES, 3, bufferAddress, 512, 0);
            assertSuccess(state, 0);

            invoke(state, FREEBSD_SYS_OPEN, pathAddress, FREEBSD_O_DIRECTORY, 0);
            assertSuccess(state, 4);
            int fileDescriptor = 4;
            invoke(state, FREEBSD_SYS_GETDIRENTRIES, fileDescriptor, bufferAddress, 512, baseAddress);
            assertEquals(0, state.register(5));
            assertTrue(state.register(10) > 0);

            writeGuestString(memory, pathAddress, "/message.txt");
            fileDescriptor = openReadOnly(state, pathAddress);
            invoke(state, FREEBSD_SYS_GETDIRENTRIES, fileDescriptor, bufferAddress, 512, baseAddress);
            assertError(state, FREEBSD_EINVAL);

            invoke(state, FREEBSD_SYS_GETDIRENTRIES, 99, bufferAddress, 512, baseAddress);
            assertError(state, FREEBSD_EBADF);
        }
    }

    /// Verifies `statfs` and `fstatfs` write full FreeBSD mount metadata for host and virtual filesystems.
    @Test
    public void statfsSyscallsWriteFreeBsdLayout() throws Exception {
        Files.writeString(tempDirectory.resolve("message.txt"), "hello", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 16 * 1024)) {
            RiscVThreadState state = state(memory, tempDirectory);
            long pathAddress = memory.baseAddress();
            long statfsAddress = memory.baseAddress() + 512;
            long procPathAddress = memory.baseAddress() + 3072;
            long procStatfsAddress = memory.baseAddress() + 4096;
            long descriptorStatfsAddress = memory.baseAddress() + 7000;
            writeGuestString(memory, pathAddress, "/message.txt");

            int fileDescriptor = openReadOnly(state, pathAddress);
            memory.writeByte(statfsAddress + FREEBSD_STATFS_SIZE - 1, (byte) 0x7f);
            invoke(state, FREEBSD_SYS_STATFS, pathAddress, statfsAddress);
            assertSuccess(state, 0);
            assertStatfs(memory, statfsAddress, STATFS_CAPACITY, "jriscvfs", "jriscv", "/");

            invoke(state, FREEBSD_SYS_FSTATFS, fileDescriptor, descriptorStatfsAddress);
            assertSuccess(state, 0);
            assertStatfs(
                    memory,
                    descriptorStatfsAddress,
                    STATFS_CAPACITY,
                    "jriscvfs",
                    "jriscv",
                    "/");

            writeGuestString(memory, procPathAddress, "/proc");
            invoke(state, FREEBSD_SYS_STATFS, procPathAddress, procStatfsAddress);
            assertSuccess(state, 0);
            assertStatfs(memory, procStatfsAddress, 0, "procfs", "procfs", "/proc");

            invoke(state, FREEBSD_SYS_FSTATFS, 99, descriptorStatfsAddress);
            assertError(state, FREEBSD_EBADF);
        }
    }

    /// Creates architectural state with a FreeBSD syscall handler and one writable root bind mount.
    private static RiscVThreadState state(Memory memory, Path hostRoot) {
        return state(memory, hostRoot, GuestCredentials.defaultUser());
    }

    /// Creates architectural state with a FreeBSD syscall handler and explicit guest credentials.
    private static RiscVThreadState state(Memory memory, Path hostRoot, GuestCredentials credentials) {
        return state(memory, hostRoot, credentials, TimeSource.system(), memory.baseAddress());
    }

    /// Creates architectural state with explicit credentials, time source, and initial program break.
    private static RiscVThreadState state(
            Memory memory,
            Path hostRoot,
            GuestCredentials credentials,
            TimeSource timeSource,
            long initialProgramBreak) {
        GuestSyscalls syscalls = new FreeBsdGuestSyscalls(
                memory,
                new ByteArrayInputStream(new byte[0]),
                new ByteArrayOutputStream(),
                new ByteArrayOutputStream(),
                initialProgramBreak,
                new String[]{"type=bind,src=" + hostRoot.toAbsolutePath() + ",dst=/"},
                timeSource,
                false,
                credentials,
                null);
        return new RiscVThreadState(
                memory,
                0,
                false,
                ElfImage.ABSENT_ADDRESS,
                ElfImage.ABSENT_ADDRESS,
                syscalls);
    }

    /// Writes one FreeBSD RISC-V `struct itimerval`.
    private static void writeFreeBsdItimerval(
            Memory memory,
            long address,
            long intervalSeconds,
            long intervalMicroseconds,
            long valueSeconds,
            long valueMicroseconds) {
        memory.writeLong(address, intervalSeconds);
        memory.writeLong(address + Long.BYTES, intervalMicroseconds);
        memory.writeLong(address + 2L * Long.BYTES, valueSeconds);
        memory.writeLong(address + 3L * Long.BYTES, valueMicroseconds);
    }

    /// Verifies one FreeBSD RISC-V `struct itimerval`.
    private static void assertFreeBsdItimerval(
            Memory memory,
            long address,
            long intervalSeconds,
            long intervalMicroseconds,
            long valueSeconds,
            long valueMicroseconds) {
        assertEquals(intervalSeconds, memory.readLong(address));
        assertEquals(intervalMicroseconds, memory.readLong(address + Long.BYTES));
        assertEquals(valueSeconds, memory.readLong(address + 2L * Long.BYTES));
        assertEquals(valueMicroseconds, memory.readLong(address + 3L * Long.BYTES));
    }

    /// Writes one FreeBSD RISC-V `struct iovec`.
    private static void writeFreeBsdIovec(Memory memory, long address, long bufferAddress, long length) {
        memory.writeLong(address + FREEBSD_IOVEC_BASE_OFFSET, bufferAddress);
        memory.writeLong(address + FREEBSD_IOVEC_LENGTH_OFFSET, length);
    }

    /// Creates architectural state with a FreeBSD syscall handler and an active guest thread runner.
    private static RiscVThreadState state(
            Memory memory,
            Path hostRoot,
            GuestThreadRunner guestThreadRunner,
            long initialProgramBreak) {
        GuestSyscalls syscalls = new FreeBsdGuestSyscalls(
                memory,
                new ByteArrayInputStream(new byte[0]),
                new ByteArrayOutputStream(),
                new ByteArrayOutputStream(),
                initialProgramBreak,
                new String[]{"type=bind,src=" + hostRoot.toAbsolutePath() + ",dst=/"},
                TimeSource.system(),
                false,
                GuestCredentials.defaultUser(),
                guestThreadRunner);
        return new RiscVThreadState(
                memory,
                0,
                false,
                ElfImage.ABSENT_ADDRESS,
                ElfImage.ABSENT_ADDRESS,
                syscalls);
    }

    /// Creates architectural state with FreeBSD syscalls and the host network backend enabled.
    private static RiscVThreadState hostNetworkState(Memory memory, Path hostRoot) {
        GuestSyscalls syscalls = new FreeBsdGuestSyscalls(
                memory,
                new ByteArrayInputStream(new byte[0]),
                new ByteArrayOutputStream(),
                new ByteArrayOutputStream(),
                memory.baseAddress(),
                new String[]{"type=bind,src=" + hostRoot.toAbsolutePath() + ",dst=/"},
                TimeSource.system(),
                false,
                GuestCredentials.defaultUser(),
                null,
                null,
                GuestNetworkMode.HOST.backend());
        return new RiscVThreadState(
                memory,
                0,
                false,
                ElfImage.ABSENT_ADDRESS,
                ElfImage.ABSENT_ADDRESS,
                syscalls);
    }

    /// Writes one native FreeBSD IPv4 socket address.
    private static void writeFreeBsdInetSockaddr(
            Memory memory,
            long address,
            InetAddress inetAddress,
            int port) {
        byte[] addressBytes = inetAddress.getAddress();
        assertEquals(Integer.BYTES, addressBytes.length);
        memory.clear(address, FREEBSD_SOCKADDR_IN_SIZE);
        memory.writeByte(address, (byte) FREEBSD_SOCKADDR_IN_SIZE);
        memory.writeByte(address + FREEBSD_SOCKADDR_FAMILY_OFFSET, (byte) FREEBSD_AF_INET);
        memory.writeByte(address + FREEBSD_SOCKADDR_PORT_OFFSET, (byte) (port >>> Byte.SIZE));
        memory.writeByte(address + FREEBSD_SOCKADDR_PORT_OFFSET + 1, (byte) port);
        memory.writeBytes(address + FREEBSD_SOCKADDR_IN_ADDRESS_OFFSET, addressBytes, 0, addressBytes.length);
    }

    /// Verifies one native FreeBSD IPv4 socket address and its reported size.
    private static void assertFreeBsdIpv4Sockaddr(
            Memory memory,
            long address,
            long lengthAddress,
            InetAddress inetAddress,
            int expectedPort) {
        assertEquals(FREEBSD_SOCKADDR_IN_SIZE, memory.readUnsignedByte(address));
        assertEquals(FREEBSD_AF_INET, memory.readUnsignedByte(address + FREEBSD_SOCKADDR_FAMILY_OFFSET));
        assertEquals(FREEBSD_SOCKADDR_IN_SIZE, memory.readInt(lengthAddress));
        assertArrayEquals(
                inetAddress.getAddress(),
                memory.readBytes(address + FREEBSD_SOCKADDR_IN_ADDRESS_OFFSET, Integer.BYTES));
        int actualPort = (memory.readUnsignedByte(address + FREEBSD_SOCKADDR_PORT_OFFSET) << Byte.SIZE)
                | memory.readUnsignedByte(address + FREEBSD_SOCKADDR_PORT_OFFSET + 1);
        if (expectedPort < 0) {
            assertTrue(actualPort > 0);
        } else {
            assertEquals(expectedPort, actualPort);
        }
    }

    /// Writes one native FreeBSD socket message header.
    private static void writeFreeBsdMessageHeader(
            Memory memory,
            long messageAddress,
            long nameAddress,
            int nameLength,
            long iovecAddress,
            int iovecCount) {
        memory.clear(messageAddress, FREEBSD_MSGHDR_SIZE);
        memory.writeLong(messageAddress + FREEBSD_MSGHDR_NAME_OFFSET, nameAddress);
        memory.writeInt(messageAddress + FREEBSD_MSGHDR_NAME_LENGTH_OFFSET, nameLength);
        memory.writeLong(messageAddress + FREEBSD_MSGHDR_IOV_OFFSET, iovecAddress);
        memory.writeInt(messageAddress + FREEBSD_MSGHDR_IOV_LENGTH_OFFSET, iovecCount);
    }

    /// Writes one current FreeBSD `struct kevent` change record.
    private static void writeFreeBsdKevent(
            Memory memory,
            long address,
            long identifier,
            short filter,
            int flags,
            int filterFlags,
            long userData) {
        memory.clear(address, FREEBSD_KEVENT_SIZE);
        memory.writeLong(address, identifier);
        memory.writeShort(address + FREEBSD_KEVENT_FILTER_OFFSET, filter);
        memory.writeShort(address + FREEBSD_KEVENT_FLAGS_OFFSET, (short) flags);
        memory.writeInt(address + FREEBSD_KEVENT_FILTER_FLAGS_OFFSET, filterFlags);
        memory.writeLong(address + FREEBSD_KEVENT_USER_DATA_OFFSET, userData);
    }

    /// Opens one guest path for reading and returns its descriptor.
    private static int openReadOnly(RiscVThreadState state, long pathAddress) {
        invoke(state, FREEBSD_SYS_OPEN, pathAddress, 0, 0);
        assertEquals(0, state.register(5));
        assertTrue(state.register(10) >= 3);
        return (int) state.register(10);
    }

    /// Invokes one direct FreeBSD syscall with up to eight integer arguments.
    private static void invoke(RiscVThreadState state, long callNumber, long... arguments) {
        state.setRegister(5, callNumber);
        for (int index = 0; index < 8; index++) {
            state.setRegister(10 + index, index < arguments.length ? arguments[index] : 0);
        }
        state.syscalls().handle(state, TEST_PC);
    }

    /// Verifies a successful FreeBSD syscall result and cleared error indicator.
    private static void assertSuccess(RiscVThreadState state, long result) {
        assertEquals(result, state.register(10));
        assertEquals(0, state.register(5));
    }

    /// Verifies a failed FreeBSD syscall result and set error indicator.
    private static void assertError(RiscVThreadState state, long errno) {
        assertEquals(errno, state.register(10));
        assertEquals(1, state.register(5));
    }

    /// Invokes a FreeBSD `getresuid` or `getresgid` syscall and verifies all three ids.
    private static void assertFreeBsdIds(
            RiscVThreadState state,
            long callNumber,
            long address,
            long realId,
            long effectiveId,
            long savedId) {
        invoke(state, callNumber, address, address + Integer.BYTES, address + 2L * Integer.BYTES);
        assertSuccess(state, 0);
        assertEquals(realId, state.memory().readUnsignedInt(address));
        assertEquals(effectiveId, state.memory().readUnsignedInt(address + Integer.BYTES));
        assertEquals(savedId, state.memory().readUnsignedInt(address + 2L * Integer.BYTES));
    }

    /// Verifies the deterministic fields of one regular-file FreeBSD `struct stat`.
    private static void assertRegularFileStat(Memory memory, long address, long size) {
        assertTrue(memory.readLong(address + FREEBSD_STAT_INODE_OFFSET) > 0);
        assertEquals(1, memory.readLong(address + FREEBSD_STAT_LINK_COUNT_OFFSET));
        assertEquals(
                FREEBSD_STAT_REGULAR_FILE,
                memory.readUnsignedShort(address + FREEBSD_STAT_MODE_OFFSET) & FREEBSD_STAT_FILE_TYPE_MASK);
        assertEquals(GuestCredentials.DEFAULT_USER_ID, memory.readUnsignedInt(address + FREEBSD_STAT_USER_ID_OFFSET));
        assertEquals(
                GuestCredentials.DEFAULT_GROUP_ID,
                memory.readUnsignedInt(address + FREEBSD_STAT_GROUP_ID_OFFSET));
        assertEquals(size, memory.readLong(address + FREEBSD_STAT_FILE_SIZE_OFFSET));
        assertEquals((size + 511L) / 512L, memory.readLong(address + FREEBSD_STAT_BLOCK_COUNT_OFFSET));
        assertEquals(STATFS_BLOCK_SIZE, memory.readInt(address + FREEBSD_STAT_BLOCK_SIZE_OFFSET));
        assertEquals(0, memory.readUnsignedByte(address + FREEBSD_STAT_SIZE - 1));
    }

    /// Verifies the deterministic fields and names of one FreeBSD `struct statfs`.
    private static void assertStatfs(
            Memory memory,
            long address,
            long blockCount,
            String fileSystemType,
            String mountSource,
            String mountPoint) {
        assertEquals(FREEBSD_STATFS_VERSION, memory.readInt(address));
        assertEquals(0, memory.readInt(address + Integer.BYTES));
        assertEquals(0, memory.readLong(address + 2L * Integer.BYTES));
        assertEquals(STATFS_BLOCK_SIZE, memory.readLong(address + FREEBSD_STATFS_BLOCK_SIZE_OFFSET));
        assertEquals(STATFS_BLOCK_SIZE, memory.readLong(address + FREEBSD_STATFS_IO_SIZE_OFFSET));
        assertEquals(blockCount, memory.readLong(address + FREEBSD_STATFS_BLOCK_COUNT_OFFSET));
        assertEquals(blockCount, memory.readLong(address + FREEBSD_STATFS_FREE_BLOCK_COUNT_OFFSET));
        assertEquals(blockCount, memory.readLong(address + FREEBSD_STATFS_AVAILABLE_BLOCK_COUNT_OFFSET));
        assertEquals(STATFS_CAPACITY, memory.readLong(address + FREEBSD_STATFS_FILE_COUNT_OFFSET));
        assertEquals(STATFS_CAPACITY, memory.readLong(address + FREEBSD_STATFS_FREE_FILE_COUNT_OFFSET));
        assertEquals(255, memory.readInt(address + FREEBSD_STATFS_NAME_MAX_OFFSET));
        assertEquals(GuestCredentials.DEFAULT_USER_ID, memory.readUnsignedInt(address + FREEBSD_STATFS_OWNER_OFFSET));
        assertEquals(1, memory.readInt(address + FREEBSD_STATFS_FILE_SYSTEM_ID_OFFSET));
        assertEquals(0, memory.readInt(address + FREEBSD_STATFS_FILE_SYSTEM_ID_OFFSET + Integer.BYTES));
        assertEquals(fileSystemType, readGuestString(memory, address + FREEBSD_STATFS_TYPE_NAME_OFFSET, 16));
        assertEquals(mountSource, readGuestString(memory, address + FREEBSD_STATFS_MOUNT_SOURCE_OFFSET, 1024));
        assertEquals(mountPoint, readGuestString(memory, address + FREEBSD_STATFS_MOUNT_POINT_OFFSET, 1024));
        assertEquals(0, memory.readUnsignedByte(address + FREEBSD_STATFS_SIZE - 1));
    }

    /// Verifies one variable-length FreeBSD `struct dirent` and returns the following record address.
    private static long assertDirectoryEntry(
            Memory memory,
            long address,
            String name,
            int type,
            long nextOffset) {
        int recordLength = memory.readUnsignedShort(address + FREEBSD_DIRENT_RECORD_LENGTH_OFFSET);
        assertEquals(0, recordLength % Long.BYTES);
        assertTrue(recordLength >= FREEBSD_DIRENT_NAME_OFFSET + name.length() + 1);
        assertTrue(memory.readLong(address) > 0);
        assertEquals(nextOffset, memory.readLong(address + FREEBSD_DIRENT_NEXT_OFFSET));
        assertEquals(type, memory.readUnsignedByte(address + FREEBSD_DIRENT_TYPE_OFFSET));
        assertEquals(0, memory.readUnsignedByte(address + FREEBSD_DIRENT_TYPE_OFFSET + 1));
        assertEquals(name.length(), memory.readUnsignedShort(address + FREEBSD_DIRENT_NAME_LENGTH_OFFSET));
        assertEquals(0, memory.readUnsignedShort(address + FREEBSD_DIRENT_NAME_LENGTH_OFFSET + Short.BYTES));
        assertEquals(name, readGuestString(memory, address + FREEBSD_DIRENT_NAME_OFFSET, recordLength - 24));
        return address + recordLength;
    }

    /// Writes a null-terminated UTF-8 string into guest memory.
    private static void writeGuestString(Memory memory, long address, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        memory.writeBytes(address, bytes, 0, bytes.length);
        memory.writeByte(address + bytes.length, (byte) 0);
    }

    /// Reads one bounded null-terminated UTF-8 string from guest memory.
    private static String readGuestString(Memory memory, long address, int capacity) {
        int length = 0;
        while (length < capacity && memory.readUnsignedByte(address + length) != 0) {
            length++;
        }
        return new String(memory.readBytes(address, length), StandardCharsets.UTF_8);
    }
}
