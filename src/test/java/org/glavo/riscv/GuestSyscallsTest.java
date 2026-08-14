// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.riscv;

import kala.compress.archivers.tar.TarArchiveEntry;
import kala.compress.archivers.tar.TarArchiveOutputStream;
import kala.compress.archivers.tar.TarConstants;
import org.glavo.riscv.exception.*;
import org.glavo.riscv.constants.RiscVExtensions;
import org.glavo.riscv.memory.*;
import org.glavo.riscv.parser.*;
import org.glavo.riscv.runtime.*;
import org.glavo.riscv.runtime.fs.*;
import org.glavo.riscv.runtime.net.GuestNetworkMode;
import org.glavo.riscv.constants.Rva22Profile;
import org.glavo.riscv.constants.Rva23Profile;
import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Unmodifiable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/// Tests guest syscall behavior directly against architectural state.
@NotNullByDefault
public final class GuestSyscallsTest {
    /// A temporary root mount for file syscall tests.
    @TempDir
    private Path tempDirectory;

    /// The guest program counter supplied to direct syscall tests.
    private static final long TEST_PC = Memory.DEFAULT_BASE_ADDRESS;

    /// Linux `EBADF` as a raw negative syscall result.
    private static final long EBADF = -9;

    /// Linux `ECHILD` as a raw negative syscall result.
    private static final long ECHILD = -10;

    /// Linux `ENOENT` as a raw negative syscall result.
    private static final long ENOENT = -2;

    /// Linux `ESRCH` as a raw negative syscall result.
    private static final long ESRCH = -3;

    /// Linux `EACCES` as a raw negative syscall result.
    private static final long EACCES = -13;

    /// Linux `EFAULT` as a raw negative syscall result.
    private static final long EFAULT = -14;

    /// Linux `EPERM` as a raw negative syscall result.
    private static final long EPERM = -1;

    /// Linux `ENOMEM` as a raw negative syscall result.
    private static final long ENOMEM = -12;

    /// Linux `EEXIST` as a raw negative syscall result.
    private static final long EEXIST = -17;

    /// Linux `EINTR` as a raw negative syscall result.
    private static final long EINTR = -4;

    /// Linux `EAGAIN` as a raw negative syscall result.
    private static final long EAGAIN = -11;

    /// Linux `EINPROGRESS` as a raw negative syscall result.
    private static final long EINPROGRESS = -115;

    /// Linux `EBUSY` as a raw negative syscall result.
    private static final long EBUSY = -16;

    /// Linux `ENODEV` as a raw negative syscall result.
    private static final long ENODEV = -19;

    /// Linux `ENOTDIR` as a raw negative syscall result.
    private static final long ENOTDIR = -20;

    /// Linux `EISDIR` as a raw negative syscall result.
    private static final long EISDIR = -21;

    /// Linux `EINVAL` as a raw negative syscall result.
    private static final long EINVAL = -22;

    /// Linux `ENOTTY` as a raw negative syscall result.
    private static final long ENOTTY = -25;

    /// Linux `ERANGE` as a raw negative syscall result.
    private static final long ERANGE = -34;

    /// Linux `ENOSYS` as a raw negative syscall result.
    private static final long ENOSYS = -38;

    /// Linux `ENODATA` as a raw negative syscall result.
    private static final long ENODATA = -61;

    /// Linux `ENOTSUP` as a raw negative syscall result.
    private static final long ENOTSUP = -95;

    /// Linux `ENOTSOCK` as a raw negative syscall result.
    private static final long ENOTSOCK = -88;

    /// Linux `EAFNOSUPPORT` as a raw negative syscall result.
    private static final long EAFNOSUPPORT = -97;

    /// Linux `ENOTCONN` as a raw negative syscall result.
    private static final long ENOTCONN = -107;

    /// Linux `ECONNREFUSED` as a raw negative syscall result.
    private static final long ECONNREFUSED = -111;

    /// Linux `ENOTEMPTY` as a raw negative syscall result.
    private static final long ENOTEMPTY = -39;

    /// Linux `ESPIPE` as a raw negative syscall result.
    private static final long ESPIPE = -29;

    /// Linux `EROFS` as a raw negative syscall result.
    private static final long EROFS = -30;

    /// Linux `ETIMEDOUT` as a raw negative syscall result.
    private static final long ETIMEDOUT = -110;

    /// The Linux RISC-V syscall number for `getxattr`.
    private static final long SYS_GETXATTR = 8;

    /// The Linux RISC-V syscall number for `listxattr`.
    private static final long SYS_LISTXATTR = 11;

    /// The Linux RISC-V syscall number for `flistxattr`.
    private static final long SYS_FLISTXATTR = 13;

    /// The Linux RISC-V syscall number for `getcwd`.
    private static final long SYS_GETCWD = 17;

    /// The Linux RISC-V syscall number for `eventfd2`.
    private static final long SYS_EVENTFD2 = 19;

    /// The Linux RISC-V syscall number for `epoll_create1`.
    private static final long SYS_EPOLL_CREATE1 = 20;

    /// The Linux RISC-V syscall number for `epoll_ctl`.
    private static final long SYS_EPOLL_CTL = 21;

    /// The Linux RISC-V syscall number for `epoll_pwait`.
    private static final long SYS_EPOLL_PWAIT = 22;

    /// The Linux RISC-V syscall number for `dup`.
    private static final long SYS_DUP = 23;

    /// The Linux RISC-V syscall number for `dup3`.
    private static final long SYS_DUP3 = 24;

    /// The Linux RISC-V syscall number for `fcntl`.
    private static final long SYS_FCNTL = 25;

    /// The Linux RISC-V syscall number for `ioctl`.
    private static final long SYS_IOCTL = 29;

    /// The Linux RISC-V syscall number for `mkdirat`.
    private static final long SYS_MKDIRAT = 34;

    /// The Linux RISC-V syscall number for `unlinkat`.
    private static final long SYS_UNLINKAT = 35;

    /// The Linux RISC-V syscall number for `symlinkat`.
    private static final long SYS_SYMLINKAT = 36;

    /// The Linux RISC-V syscall number for `linkat`.
    private static final long SYS_LINKAT = 37;

    /// The Linux RISC-V syscall number for `renameat`.
    private static final long SYS_RENAMEAT = 38;

    /// The Linux RISC-V syscall number for `statfs`.
    private static final long SYS_STATFS = 43;

    /// The Linux RISC-V syscall number for `fstatfs`.
    private static final long SYS_FSTATFS = 44;

    /// The Linux RISC-V syscall number for `truncate`.
    private static final long SYS_TRUNCATE = 45;

    /// The Linux RISC-V syscall number for `ftruncate`.
    private static final long SYS_FTRUNCATE = 46;

    /// The Linux RISC-V syscall number for `fallocate`.
    private static final long SYS_FALLOCATE = 47;

    /// The Linux RISC-V syscall number for `faccessat`.
    private static final long SYS_FACCESSAT = 48;

    /// The Linux RISC-V syscall number for `chdir`.
    private static final long SYS_CHDIR = 49;

    /// The Linux RISC-V syscall number for `fchdir`.
    private static final long SYS_FCHDIR = 50;

    /// The Linux RISC-V syscall number for `fchmod`.
    private static final long SYS_FCHMOD = 52;

    /// The Linux RISC-V syscall number for `fchmodat`.
    private static final long SYS_FCHMODAT = 53;

    /// The Linux RISC-V syscall number for `fchownat`.
    private static final long SYS_FCHOWNAT = 54;

    /// The Linux RISC-V syscall number for `fchown`.
    private static final long SYS_FCHOWN = 55;

    /// The Linux RISC-V syscall number for `openat`.
    private static final long SYS_OPENAT = 56;

    /// The Linux RISC-V syscall number for `close`.
    private static final long SYS_CLOSE = 57;

    /// The Linux RISC-V syscall number for `pipe2`.
    private static final long SYS_PIPE2 = 59;

    /// The Linux RISC-V syscall number for `getdents64`.
    private static final long SYS_GETDENTS64 = 61;

    /// The Linux RISC-V syscall number for `lseek`.
    private static final long SYS_LSEEK = 62;

    /// The Linux RISC-V syscall number for `read`.
    private static final long SYS_READ = 63;

    /// The Linux RISC-V syscall number for `write`.
    private static final long SYS_WRITE = 64;

    /// The Linux RISC-V syscall number for `readv`.
    private static final long SYS_READV = 65;

    /// The Linux RISC-V syscall number for `writev`.
    private static final long SYS_WRITEV = 66;

    /// The Linux RISC-V syscall number for `pread64`.
    private static final long SYS_PREAD64 = 67;

    /// The Linux RISC-V syscall number for `pwrite64`.
    private static final long SYS_PWRITE64 = 68;

    /// The Linux RISC-V syscall number for `preadv`.
    private static final long SYS_PREADV = 69;

    /// The Linux RISC-V syscall number for `pwritev`.
    private static final long SYS_PWRITEV = 70;

    /// The Linux RISC-V syscall number for `pselect6`.
    private static final long SYS_PSELECT6 = 72;

    /// The Linux RISC-V syscall number for `ppoll`.
    private static final long SYS_PPOLL = 73;

    /// The Linux RISC-V syscall number for `readlinkat`.
    private static final long SYS_READLINKAT = 78;

    /// The Linux RISC-V syscall number for `newfstatat`.
    private static final long SYS_NEWFSTATAT = 79;

    /// The Linux RISC-V syscall number for `fstat`.
    private static final long SYS_FSTAT = 80;

    /// The Linux RISC-V syscall number for `sync`.
    private static final long SYS_SYNC = 81;

    /// The Linux RISC-V syscall number for `fsync`.
    private static final long SYS_FSYNC = 82;

    /// The Linux RISC-V syscall number for `fdatasync`.
    private static final long SYS_FDATASYNC = 83;

    /// The Linux RISC-V syscall number for `timerfd_create`.
    private static final long SYS_TIMERFD_CREATE = 85;

    /// The Linux RISC-V syscall number for `timerfd_settime`.
    private static final long SYS_TIMERFD_SETTIME = 86;

    /// The Linux RISC-V syscall number for `timerfd_gettime`.
    private static final long SYS_TIMERFD_GETTIME = 87;

    /// The Linux RISC-V syscall number for `utimensat`.
    private static final long SYS_UTIMENSAT = 88;

    /// The Linux RISC-V syscall number for `capget`.
    private static final long SYS_CAPGET = 90;

    /// The Linux RISC-V syscall number for `capset`.
    private static final long SYS_CAPSET = 91;

    /// The Linux RISC-V syscall number for `waitid`.
    private static final long SYS_WAITID = 95;

    /// The Linux RISC-V syscall number for `set_tid_address`.
    private static final long SYS_SET_TID_ADDRESS = 96;

    /// The Linux RISC-V syscall number for `futex`.
    private static final long SYS_FUTEX = 98;

    /// The Linux RISC-V syscall number for `set_robust_list`.
    private static final long SYS_SET_ROBUST_LIST = 99;

    /// The Linux RISC-V syscall number for `get_robust_list`.
    private static final long SYS_GET_ROBUST_LIST = 100;

    /// The Linux RISC-V syscall number for `nanosleep`.
    private static final long SYS_NANOSLEEP = 101;

    /// The Linux RISC-V syscall number for `getitimer`.
    private static final long SYS_GETITIMER = 102;

    /// The Linux RISC-V syscall number for `setitimer`.
    private static final long SYS_SETITIMER = 103;

    /// The Linux RISC-V syscall number for `clock_gettime`.
    private static final long SYS_CLOCK_GETTIME = 113;

    /// The Linux RISC-V syscall number for `clock_getres`.
    private static final long SYS_CLOCK_GETRES = 114;

    /// The Linux RISC-V syscall number for `clock_nanosleep`.
    private static final long SYS_CLOCK_NANOSLEEP = 115;

    /// The Linux RISC-V syscall number for `sched_setparam`.
    private static final long SYS_SCHED_SETPARAM = 118;

    /// The Linux RISC-V syscall number for `sched_setscheduler`.
    private static final long SYS_SCHED_SETSCHEDULER = 119;

    /// The Linux RISC-V syscall number for `sched_getscheduler`.
    private static final long SYS_SCHED_GETSCHEDULER = 120;

    /// The Linux RISC-V syscall number for `sched_getparam`.
    private static final long SYS_SCHED_GETPARAM = 121;

    /// The Linux RISC-V syscall number for `sched_setaffinity`.
    private static final long SYS_SCHED_SETAFFINITY = 122;

    /// The Linux RISC-V syscall number for `sched_getaffinity`.
    private static final long SYS_SCHED_GETAFFINITY = 123;

    /// The Linux RISC-V syscall number for `sched_yield`.
    private static final long SYS_SCHED_YIELD = 124;

    /// The Linux RISC-V syscall number for `sched_get_priority_max`.
    private static final long SYS_SCHED_GET_PRIORITY_MAX = 125;

    /// The Linux RISC-V syscall number for `sched_get_priority_min`.
    private static final long SYS_SCHED_GET_PRIORITY_MIN = 126;

    /// The Linux RISC-V syscall number for `sched_rr_get_interval`.
    private static final long SYS_SCHED_RR_GET_INTERVAL = 127;

    /// The Linux RISC-V syscall number for `kill`.
    private static final long SYS_KILL = 129;

    /// The Linux RISC-V syscall number for `tkill`.
    private static final long SYS_TKILL = 130;

    /// The Linux RISC-V syscall number for `tgkill`.
    private static final long SYS_TGKILL = 131;

    /// The Linux RISC-V syscall number for `sigaltstack`.
    private static final long SYS_SIGALTSTACK = 132;

    /// The Linux RISC-V syscall number for `rt_sigaction`.
    private static final long SYS_RT_SIGACTION = 134;

    /// The Linux RISC-V syscall number for `rt_sigprocmask`.
    private static final long SYS_RT_SIGPROCMASK = 135;

    /// The Linux RISC-V syscall number for `rt_sigreturn`.
    private static final long SYS_RT_SIGRETURN = 139;

    /// The Linux RISC-V syscall number for `setpriority`.
    private static final long SYS_SETPRIORITY = 140;

    /// The Linux RISC-V syscall number for `getpriority`.
    private static final long SYS_GETPRIORITY = 141;

    /// The Linux RISC-V syscall number for `setgid`.
    private static final long SYS_SETGID = 144;

    /// The Linux RISC-V syscall number for `setuid`.
    private static final long SYS_SETUID = 146;

    /// The Linux RISC-V syscall number for `setresuid`.
    private static final long SYS_SETRESUID = 147;

    /// The Linux RISC-V syscall number for `getresuid`.
    private static final long SYS_GETRESUID = 148;

    /// The Linux RISC-V syscall number for `setresgid`.
    private static final long SYS_SETRESGID = 149;

    /// The Linux RISC-V syscall number for `getresgid`.
    private static final long SYS_GETRESGID = 150;

    /// The Linux RISC-V syscall number for `setfsuid`.
    private static final long SYS_SETFSUID = 151;

    /// The Linux RISC-V syscall number for `setfsgid`.
    private static final long SYS_SETFSGID = 152;

    /// The Linux RISC-V syscall number for `times`.
    private static final long SYS_TIMES = 153;

    /// The Linux RISC-V syscall number for `setpgid`.
    private static final long SYS_SETPGID = 154;

    /// The Linux RISC-V syscall number for `getpgid`.
    private static final long SYS_GETPGID = 155;

    /// The Linux RISC-V syscall number for `getsid`.
    private static final long SYS_GETSID = 156;

    /// The Linux RISC-V syscall number for `setsid`.
    private static final long SYS_SETSID = 157;

    /// The Linux RISC-V syscall number for `getgroups`.
    private static final long SYS_GETGROUPS = 158;

    /// The Linux RISC-V syscall number for `setgroups`.
    private static final long SYS_SETGROUPS = 159;

    /// The Linux RISC-V syscall number for `uname`.
    private static final long SYS_UNAME = 160;

    /// The Linux RISC-V syscall number for `getrlimit`.
    private static final long SYS_GETRLIMIT = 163;

    /// The Linux RISC-V syscall number for `setrlimit`.
    private static final long SYS_SETRLIMIT = 164;

    /// The Linux RISC-V syscall number for `getrusage`.
    private static final long SYS_GETRUSAGE = 165;

    /// The Linux RISC-V syscall number for `umask`.
    private static final long SYS_UMASK = 166;

    /// The Linux RISC-V syscall number for `prctl`.
    private static final long SYS_PRCTL = 167;

    /// The Linux RISC-V syscall number for `getcpu`.
    private static final long SYS_GETCPU = 168;

    /// The Linux RISC-V syscall number for `gettimeofday`.
    private static final long SYS_GETTIMEOFDAY = 169;

    /// The Linux RISC-V syscall number for `getpid`.
    private static final long SYS_GETPID = 172;

    /// The Linux RISC-V syscall number for `getppid`.
    private static final long SYS_GETPPID = 173;

    /// The Linux RISC-V syscall number for `getuid`.
    private static final long SYS_GETUID = 174;

    /// The Linux RISC-V syscall number for `geteuid`.
    private static final long SYS_GETEUID = 175;

    /// The Linux RISC-V syscall number for `getgid`.
    private static final long SYS_GETGID = 176;

    /// The Linux RISC-V syscall number for `getegid`.
    private static final long SYS_GETEGID = 177;

    /// The Linux RISC-V syscall number for `gettid`.
    private static final long SYS_GETTID = 178;

    /// The Linux RISC-V syscall number for `sysinfo`.
    private static final long SYS_SYSINFO = 179;

    /// The Linux RISC-V syscall number for `socket`.
    private static final long SYS_SOCKET = 198;

    /// The Linux RISC-V syscall number for `socketpair`.
    private static final long SYS_SOCKETPAIR = 199;

    /// The Linux RISC-V syscall number for `bind`.
    private static final long SYS_BIND = 200;

    /// The Linux RISC-V syscall number for `listen`.
    private static final long SYS_LISTEN = 201;

    /// The Linux RISC-V syscall number for `accept`.
    private static final long SYS_ACCEPT = 202;

    /// The Linux RISC-V syscall number for `connect`.
    private static final long SYS_CONNECT = 203;

    /// The Linux RISC-V syscall number for `getsockname`.
    private static final long SYS_GETSOCKNAME = 204;

    /// The Linux RISC-V syscall number for `getpeername`.
    private static final long SYS_GETPEERNAME = 205;

    /// The Linux RISC-V syscall number for `sendto`.
    private static final long SYS_SENDTO = 206;

    /// The Linux RISC-V syscall number for `recvfrom`.
    private static final long SYS_RECVFROM = 207;

    /// The Linux RISC-V syscall number for `setsockopt`.
    private static final long SYS_SETSOCKOPT = 208;

    /// The Linux RISC-V syscall number for `getsockopt`.
    private static final long SYS_GETSOCKOPT = 209;

    /// The Linux RISC-V syscall number for `shutdown`.
    private static final long SYS_SHUTDOWN = 210;

    /// The Linux RISC-V syscall number for `sendmsg`.
    private static final long SYS_SENDMSG = 211;

    /// The Linux RISC-V syscall number for `recvmsg`.
    private static final long SYS_RECVMSG = 212;

    /// The Linux RISC-V syscall number for `brk`.
    private static final long SYS_BRK = 214;

    /// The Linux RISC-V syscall number for `munmap`.
    private static final long SYS_MUNMAP = 215;

    /// The Linux RISC-V syscall number for `mremap`.
    private static final long SYS_MREMAP = 216;

    /// The Linux RISC-V syscall number for `clone`.
    private static final long SYS_CLONE = 220;

    /// The Linux RISC-V syscall number for `fadvise64`.
    private static final long SYS_FADVISE64 = 223;

    /// The Linux RISC-V syscall number for `pidfd_send_signal`.
    private static final long SYS_PIDFD_SEND_SIGNAL = 424;

    /// The Linux RISC-V syscall number for `pidfd_open`.
    private static final long SYS_PIDFD_OPEN = 434;

    /// The Linux RISC-V syscall number for `clone3`.
    private static final long SYS_CLONE3 = 435;

    /// The Linux RISC-V syscall number for `close_range`.
    private static final long SYS_CLOSE_RANGE = 436;

    /// The Linux RISC-V syscall number for `epoll_pwait2`.
    private static final long SYS_EPOLL_PWAIT2 = 441;

    /// The Linux RISC-V syscall number for `mmap`.
    private static final long SYS_MMAP = 222;

    /// The Linux RISC-V syscall number for `mprotect`.
    private static final long SYS_MPROTECT = 226;

    /// The Linux RISC-V syscall number for `msync`.
    private static final long SYS_MSYNC = 227;

    /// The Linux RISC-V syscall number for `mlock`.
    private static final long SYS_MLOCK = 228;

    /// The Linux RISC-V syscall number for `munlock`.
    private static final long SYS_MUNLOCK = 229;

    /// The Linux RISC-V syscall number for `mlockall`.
    private static final long SYS_MLOCKALL = 230;

    /// The Linux RISC-V syscall number for `munlockall`.
    private static final long SYS_MUNLOCKALL = 231;

    /// The Linux RISC-V syscall number for `accept4`.
    private static final long SYS_ACCEPT4 = 242;

    /// The Linux RISC-V syscall number for `recvmmsg`.
    private static final long SYS_RECVMMSG = 243;

    /// The Linux RISC-V syscall number for `mincore`.
    private static final long SYS_MINCORE = 232;

    /// The Linux RISC-V syscall number for `madvise`.
    private static final long SYS_MADVISE = 233;

    /// The Linux RISC-V syscall number for `riscv_hwprobe`.
    private static final long SYS_RISCV_HWPROBE = 258;

    /// The Linux RISC-V syscall number for `riscv_flush_icache`.
    private static final long SYS_RISCV_FLUSH_ICACHE = 259;

    /// The Linux RISC-V syscall number for `wait4`.
    private static final long SYS_WAIT4 = 260;

    /// The Linux RISC-V syscall number for `prlimit64`.
    private static final long SYS_PRLIMIT64 = 261;

    /// The Linux RISC-V syscall number for `syncfs`.
    private static final long SYS_SYNCFS = 267;

    /// The Linux RISC-V syscall number for `sendmmsg`.
    private static final long SYS_SENDMMSG = 269;

    /// The Linux RISC-V syscall number for `renameat2`.
    private static final long SYS_RENAMEAT2 = 276;

    /// The Linux RISC-V syscall number for `getrandom`.
    private static final long SYS_GETRANDOM = 278;

    /// The Linux RISC-V syscall number for `membarrier`.
    private static final long SYS_MEMBARRIER = 283;

    /// The Linux RISC-V syscall number for `mlock2`.
    private static final long SYS_MLOCK2 = 284;

    /// The Linux RISC-V syscall number for `copy_file_range`.
    private static final long SYS_COPY_FILE_RANGE = 285;

    /// The Linux RISC-V syscall number for `preadv2`.
    private static final long SYS_PREADV2 = 286;

    /// The Linux RISC-V syscall number for `pwritev2`.
    private static final long SYS_PWRITEV2 = 287;

    /// The Linux RISC-V syscall number for `statx`.
    private static final long SYS_STATX = 291;

    /// The Linux RISC-V syscall number for `rseq`.
    private static final long SYS_RSEQ = 293;

    /// The Linux RISC-V syscall number for `faccessat2`.
    private static final long SYS_FACCESSAT2 = 439;

    /// The Linux RISC-V syscall number for `fchmodat2`.
    private static final long SYS_FCHMODAT2 = 452;

    /// The Linux generic tty `TCGETS` ioctl request number.
    private static final long TCGETS = 0x5401;

    /// The Linux generic tty `TCSETS` ioctl request number.
    private static final long TCSETS = 0x5402;

    /// The Linux generic tty `TCGETS2` ioctl request number.
    private static final long TCGETS2 = 0x802c542aL;

    /// The Linux generic tty `TCSETS2` ioctl request number.
    private static final long TCSETS2 = 0x402c542bL;

    /// The Linux generic tty `TIOCGPGRP` ioctl request number.
    private static final long TIOCGPGRP = 0x540F;

    /// The Linux generic tty `TIOCSPGRP` ioctl request number.
    private static final long TIOCSPGRP = 0x5410;

    /// The Linux generic tty `TIOCGWINSZ` ioctl request number.
    private static final long TIOCGWINSZ = 0x5413;

    /// The Linux generic tty `TIOCSWINSZ` ioctl request number.
    private static final long TIOCSWINSZ = 0x5414;

    /// The Linux generic tty `TIOCGPTN` ioctl request number.
    private static final long TIOCGPTN = 0x80045430L;

    /// The Linux generic tty `TIOCSPTLCK` ioctl request number.
    private static final long TIOCSPTLCK = 0x40045431L;

    /// The Linux generic tty `TIOCGPTPEER` ioctl request number.
    private static final long TIOCGPTPEER = 0x5441;

    /// The byte size of Linux generic `struct termios`.
    private static final int TERMIOS_SIZE = 36;

    /// The byte size of Linux generic `struct termios2`.
    private static final int TERMIOS2_SIZE = 44;

    /// The byte offset of `c_lflag` inside Linux generic `struct termios`.
    private static final int TERMIOS_LOCAL_FLAGS_OFFSET = 3 * Integer.BYTES;

    /// The byte offset of `c_ispeed` inside Linux generic `struct termios2`.
    private static final int TERMIOS2_INPUT_SPEED_OFFSET = TERMIOS_SIZE;

    /// The byte offset of `c_ospeed` inside Linux generic `struct termios2`.
    private static final int TERMIOS2_OUTPUT_SPEED_OFFSET = TERMIOS2_INPUT_SPEED_OFFSET + Integer.BYTES;

    /// Linux generic `ICANON`.
    private static final int TERMIOS_LOCAL_CANONICAL = 0x00002;

    /// Linux generic `ECHO`.
    private static final int TERMIOS_LOCAL_ECHO = 0x00008;

    /// The byte size of Linux generic `struct winsize`.
    private static final int WINSIZE_SIZE = 8;

    /// The `st_mode` byte offset inside Linux generic 64-bit `struct stat`.
    private static final int STAT_MODE_OFFSET = 16;

    /// The `st_nlink` byte offset inside Linux generic 64-bit `struct stat`.
    private static final int STAT_LINK_COUNT_OFFSET = 20;

    /// The `st_uid` byte offset inside Linux generic 64-bit `struct stat`.
    private static final int STAT_UID_OFFSET = 24;

    /// The `st_gid` byte offset inside Linux generic 64-bit `struct stat`.
    private static final int STAT_GID_OFFSET = 28;

    /// The `st_blksize` byte offset inside Linux generic 64-bit `struct stat`.
    private static final int STAT_BLOCK_SIZE_OFFSET = 56;

    /// The expected `st_mode` value for simulator standard streams.
    private static final int STANDARD_STREAM_STAT_MODE = 0020000 | 0666;

    /// The expected `st_mode` value for virtual character devices.
    private static final int CHARACTER_DEVICE_STAT_MODE = 0020000 | 0777;

    /// The expected `st_mode` value for pipe endpoints.
    private static final int PIPE_STAT_MODE = 0010000 | 0444;

    /// The expected `st_mode` value for guest-created regular host files with mode 0644.
    private static final int CREATED_REGULAR_FILE_STAT_MODE = 0100000 | 0644;

    /// The expected `st_mode` value for read-write regular host files.
    private static final int READ_WRITE_REGULAR_FILE_STAT_MODE = 0100000 | 0666;

    /// The expected `st_mode` value for read-write host directories.
    private static final int READ_WRITE_DIRECTORY_STAT_MODE = 0040000 | 0777;

    /// The expected `stx_mode` value for symbolic links.
    private static final int SYMBOLIC_LINK_STAT_MODE = 0120000 | 0777;

    /// The byte offset of `d_off` inside Linux `struct linux_dirent64`.
    private static final int DIRENT64_NEXT_OFFSET = 8;

    /// The byte offset of `d_reclen` inside Linux `struct linux_dirent64`.
    private static final int DIRENT64_RECORD_LENGTH_OFFSET = 16;

    /// The byte offset of `d_type` inside Linux `struct linux_dirent64`.
    private static final int DIRENT64_TYPE_OFFSET = 18;

    /// The byte offset of `d_name` inside Linux `struct linux_dirent64`.
    private static final int DIRENT64_NAME_OFFSET = 19;

    /// Linux `DT_DIR` directory entry type.
    private static final int DIRECTORY_ENTRY_DIRECTORY = 4;

    /// Linux `DT_CHR` directory entry type.
    private static final int DIRECTORY_ENTRY_CHARACTER_DEVICE = 2;

    /// Linux `DT_REG` directory entry type.
    private static final int DIRECTORY_ENTRY_REGULAR_FILE = 8;

    /// Linux `DT_LNK` directory entry type.
    private static final int DIRECTORY_ENTRY_SYMBOLIC_LINK = 10;

    /// The `st_size` byte offset inside Linux generic 64-bit `struct stat`.
    private static final int STAT_SIZE_OFFSET = 48;

    /// The byte offset of `f_type` inside Linux generic 64-bit `struct statfs`.
    private static final int STATFS_TYPE_OFFSET = 0;

    /// The byte offset of `f_bsize` inside Linux generic 64-bit `struct statfs`.
    private static final int STATFS_BLOCK_SIZE_OFFSET = 8;

    /// The byte offset of `f_blocks` inside Linux generic 64-bit `struct statfs`.
    private static final int STATFS_BLOCKS_OFFSET = 16;

    /// The byte offset of `f_bfree` inside Linux generic 64-bit `struct statfs`.
    private static final int STATFS_BLOCKS_FREE_OFFSET = 24;

    /// The byte offset of `f_bavail` inside Linux generic 64-bit `struct statfs`.
    private static final int STATFS_BLOCKS_AVAILABLE_OFFSET = 32;

    /// The byte offset of `f_files` inside Linux generic 64-bit `struct statfs`.
    private static final int STATFS_FILES_OFFSET = 40;

    /// The byte offset of `f_ffree` inside Linux generic 64-bit `struct statfs`.
    private static final int STATFS_FILES_FREE_OFFSET = 48;

    /// The byte offset of `f_namelen` inside Linux generic 64-bit `struct statfs`.
    private static final int STATFS_NAME_LENGTH_OFFSET = 64;

    /// The byte offset of `f_frsize` inside Linux generic 64-bit `struct statfs`.
    private static final int STATFS_FRAGMENT_SIZE_OFFSET = 72;

    /// The byte offset of `f_flags` inside Linux generic 64-bit `struct statfs`.
    private static final int STATFS_FLAGS_OFFSET = 80;

    /// The byte offset of `stx_mask` inside Linux generic `struct statx`.
    private static final int STATX_MASK_OFFSET = 0;

    /// The byte offset of `stx_blksize` inside Linux generic `struct statx`.
    private static final int STATX_BLOCK_SIZE_OFFSET = 4;

    /// The byte offset of `stx_attributes` inside Linux generic `struct statx`.
    private static final int STATX_ATTRIBUTES_OFFSET = 8;

    /// The byte offset of `stx_nlink` inside Linux generic `struct statx`.
    private static final int STATX_LINK_COUNT_OFFSET = 16;

    /// The byte offset of `stx_uid` inside Linux generic `struct statx`.
    private static final int STATX_UID_OFFSET = 20;

    /// The byte offset of `stx_gid` inside Linux generic `struct statx`.
    private static final int STATX_GID_OFFSET = 24;

    /// The byte offset of `stx_mode` inside Linux generic `struct statx`.
    private static final int STATX_MODE_OFFSET = 28;

    /// The byte offset of `stx_ino` inside Linux generic `struct statx`.
    private static final int STATX_INODE_OFFSET = 32;

    /// The byte offset of `stx_size` inside Linux generic `struct statx`.
    private static final int STATX_FILE_SIZE_OFFSET = 40;

    /// The byte offset of `stx_blocks` inside Linux generic `struct statx`.
    private static final int STATX_BLOCK_COUNT_OFFSET = 48;

    /// The byte offset of `stx_attributes_mask` inside Linux generic `struct statx`.
    private static final int STATX_ATTRIBUTES_MASK_OFFSET = 56;

    /// The byte offset of `stx_dev_major` inside Linux generic `struct statx`.
    private static final int STATX_DEVICE_MAJOR_OFFSET = 136;

    /// The byte offset of `stx_dev_minor` inside Linux generic `struct statx`.
    private static final int STATX_DEVICE_MINOR_OFFSET = 140;

    /// The byte offset of `stx_mnt_id` inside Linux generic `struct statx`.
    private static final int STATX_MOUNT_ID_OFFSET = 144;

    /// The Linux `STATX_BASIC_STATS` bit mask.
    private static final int STATX_BASIC_STATS_MASK = 0x0000_07ff;

    /// The deterministic mount id returned by `statx`.
    private static final long STATX_SYNTHETIC_MOUNT_ID = 1;

    /// The synthetic filesystem magic returned by `statfs`.
    private static final long STATFS_MAGIC = 0x0102_1994L;

    /// Linux `PROC_SUPER_MAGIC`.
    private static final long PROC_SUPER_MAGIC = 0x9fa0L;

    /// Linux `SYSFS_MAGIC`.
    private static final long SYSFS_MAGIC = 0x6265_6572L;

    /// The synthetic filesystem block size returned by `statfs`.
    private static final long STATFS_BLOCK_SIZE = 4096;

    /// The synthetic filesystem block count returned by `statfs`.
    private static final long STATFS_BLOCK_COUNT = 1_048_576;

    /// The synthetic filesystem file count returned by `statfs`.
    private static final long STATFS_FILE_COUNT = 1_048_576;

    /// The maximum guest filename length returned by `statfs`.
    private static final long STATFS_NAME_MAX = 255;

    /// The Linux `AT_FDCWD` pseudo file descriptor for path-based syscalls.
    private static final long AT_FDCWD = -100;

    /// Linux `AT_EACCESS`.
    private static final long AT_EACCESS = 0x200;

    /// Linux `AT_REMOVEDIR`.
    private static final long AT_REMOVEDIR = 0x200;

    /// Linux `AT_NO_AUTOMOUNT`.
    private static final long AT_NO_AUTOMOUNT = 0x800;

    /// Linux `AT_EMPTY_PATH`.
    private static final long AT_EMPTY_PATH = 0x1000;

    /// Linux `AT_SYMLINK_NOFOLLOW`.
    private static final long AT_SYMLINK_NOFOLLOW = 0x100;

    /// Linux `UTIME_NOW`.
    private static final long UTIME_NOW = 0x3fff_ffffL;

    /// Linux `UTIME_OMIT`.
    private static final long UTIME_OMIT = 0x3fff_fffeL;

    /// Linux `AT_STATX_FORCE_SYNC`.
    private static final long AT_STATX_FORCE_SYNC = 0x2000;

    /// Linux `AT_STATX_DONT_SYNC`.
    private static final long AT_STATX_DONT_SYNC = 0x4000;

    /// Linux `F_OK` access mode.
    private static final long F_OK = 0;

    /// Linux `X_OK` access mode bit.
    private static final long X_OK = 1;

    /// Linux `W_OK` access mode bit.
    private static final long W_OK = 2;

    /// Linux `R_OK` access mode bit.
    private static final long R_OK = 4;

    /// The byte size of one Linux `struct utsname` field.
    private static final int UTSNAME_FIELD_SIZE = 65;

    /// The byte offset of `sysname` inside Linux `struct utsname`.
    private static final int UTSNAME_SYSNAME_OFFSET = 0;

    /// The byte offset of `release` inside Linux `struct utsname`.
    private static final int UTSNAME_RELEASE_OFFSET = 2 * UTSNAME_FIELD_SIZE;

    /// The byte offset of `machine` inside Linux `struct utsname`.
    private static final int UTSNAME_MACHINE_OFFSET = 4 * UTSNAME_FIELD_SIZE;

    /// The byte offset of `tv_sec` inside Linux RISC-V 64-bit `struct timeval`.
    private static final int TIMEVAL_SECONDS_OFFSET = 0;

    /// The byte offset of `tv_usec` inside Linux RISC-V 64-bit `struct timeval`.
    private static final int TIMEVAL_MICROSECONDS_OFFSET = Long.BYTES;

    /// The byte size of Linux RISC-V 64-bit `struct timeval`.
    private static final int TIMEVAL_SIZE = 2 * Long.BYTES;

    /// The byte offset of `it_interval` inside Linux RISC-V 64-bit `struct itimerval`.
    private static final int ITIMERVAL_INTERVAL_OFFSET = 0;

    /// The byte offset of `it_value` inside Linux RISC-V 64-bit `struct itimerval`.
    private static final int ITIMERVAL_VALUE_OFFSET = TIMEVAL_SIZE;

    /// The byte size of Linux RISC-V 64-bit `struct itimerval`.
    private static final int ITIMERVAL_SIZE = 2 * TIMEVAL_SIZE;

    /// The byte offset of `tz_minuteswest` inside Linux `struct timezone`.
    private static final int TIMEZONE_MINUTESWEST_OFFSET = 0;

    /// The byte offset of `tz_dsttime` inside Linux `struct timezone`.
    private static final int TIMEZONE_DSTTIME_OFFSET = Integer.BYTES;

    /// The byte offset of `tms_utime` inside Linux RISC-V 64-bit `struct tms`.
    private static final int TMS_USER_TIME_OFFSET = 0;

    /// The byte offset of `tms_stime` inside Linux RISC-V 64-bit `struct tms`.
    private static final int TMS_SYSTEM_TIME_OFFSET = Long.BYTES;

    /// The byte offset of `tms_cutime` inside Linux RISC-V 64-bit `struct tms`.
    private static final int TMS_CHILD_USER_TIME_OFFSET = 2 * Long.BYTES;

    /// The byte offset of `tms_cstime` inside Linux RISC-V 64-bit `struct tms`.
    private static final int TMS_CHILD_SYSTEM_TIME_OFFSET = 3 * Long.BYTES;

    /// The byte offset of `ru_utime` inside Linux RISC-V 64-bit `struct rusage`.
    private static final int RUSAGE_USER_TIME_OFFSET = 0;

    /// The byte offset of `ru_stime` inside Linux RISC-V 64-bit `struct rusage`.
    private static final int RUSAGE_SYSTEM_TIME_OFFSET = 2 * Long.BYTES;

    /// The byte offset of `uptime` inside Linux RISC-V 64-bit `struct sysinfo`.
    private static final int SYSINFO_UPTIME_OFFSET = 0;

    /// The byte offset of `loads` inside Linux RISC-V 64-bit `struct sysinfo`.
    private static final int SYSINFO_LOADS_OFFSET = Long.BYTES;

    /// The byte offset of `totalram` inside Linux RISC-V 64-bit `struct sysinfo`.
    private static final int SYSINFO_TOTAL_RAM_OFFSET = 4 * Long.BYTES;

    /// The byte offset of `freeram` inside Linux RISC-V 64-bit `struct sysinfo`.
    private static final int SYSINFO_FREE_RAM_OFFSET = 5 * Long.BYTES;

    /// The byte offset of `sharedram` inside Linux RISC-V 64-bit `struct sysinfo`.
    private static final int SYSINFO_SHARED_RAM_OFFSET = 6 * Long.BYTES;

    /// The byte offset of `bufferram` inside Linux RISC-V 64-bit `struct sysinfo`.
    private static final int SYSINFO_BUFFER_RAM_OFFSET = 7 * Long.BYTES;

    /// The byte offset of `totalswap` inside Linux RISC-V 64-bit `struct sysinfo`.
    private static final int SYSINFO_TOTAL_SWAP_OFFSET = 8 * Long.BYTES;

    /// The byte offset of `freeswap` inside Linux RISC-V 64-bit `struct sysinfo`.
    private static final int SYSINFO_FREE_SWAP_OFFSET = 9 * Long.BYTES;

    /// The byte offset of `procs` inside Linux RISC-V 64-bit `struct sysinfo`.
    private static final int SYSINFO_PROCESSES_OFFSET = 10 * Long.BYTES;

    /// The byte offset of `totalhigh` inside Linux RISC-V 64-bit `struct sysinfo`.
    private static final int SYSINFO_TOTAL_HIGH_OFFSET = 11 * Long.BYTES;

    /// The byte offset of `freehigh` inside Linux RISC-V 64-bit `struct sysinfo`.
    private static final int SYSINFO_FREE_HIGH_OFFSET = 12 * Long.BYTES;

    /// The byte offset of `mem_unit` inside Linux RISC-V 64-bit `struct sysinfo`.
    private static final int SYSINFO_MEMORY_UNIT_OFFSET = 13 * Long.BYTES;

    /// Linux `RUSAGE_CHILDREN`.
    private static final long RUSAGE_CHILDREN = -1;

    /// Linux `RUSAGE_SELF`.
    private static final long RUSAGE_SELF = 0;

    /// Linux `RUSAGE_THREAD`.
    private static final long RUSAGE_THREAD = 1;

    /// The byte offset of `rlim_cur` inside Linux RISC-V 64-bit `struct rlimit64`.
    private static final int RLIMIT_CURRENT_OFFSET = 0;

    /// The byte offset of `rlim_max` inside Linux RISC-V 64-bit `struct rlimit64`.
    private static final int RLIMIT_MAXIMUM_OFFSET = Long.BYTES;

    /// Linux `RLIM_INFINITY`.
    private static final long RLIM_INFINITY = -1L;

    /// Linux `RLIMIT_STACK`.
    private static final long RLIMIT_STACK = 3;

    /// Linux `RLIMIT_NOFILE`.
    private static final long RLIMIT_NOFILE = 7;

    /// The default stack soft limit exposed by the simulator.
    private static final long DEFAULT_STACK_LIMIT = 8L * 1024L * 1024L;

    /// The default open-file limit exposed by the simulator.
    private static final long DEFAULT_OPEN_FILE_LIMIT = 1024;

    /// Linux `O_RDONLY`.
    private static final long O_RDONLY = 0;

    /// Linux `O_WRONLY`.
    private static final long O_WRONLY = 1;

    /// Linux `O_RDWR`.
    private static final long O_RDWR = 2;

    /// Linux `O_CREAT`.
    private static final long O_CREAT = 00000100L;

    /// Linux `O_EXCL`.
    private static final long O_EXCL = 00000200L;

    /// Linux `O_NOCTTY`.
    private static final long O_NOCTTY = 00000400L;

    /// Linux `O_TRUNC`.
    private static final long O_TRUNC = 00001000L;

    /// Linux `O_APPEND`.
    private static final long O_APPEND = 00002000L;

    /// Linux `O_NONBLOCK`.
    private static final long O_NONBLOCK = 00004000L;

    /// Linux `O_DIRECTORY`.
    private static final long O_DIRECTORY = 00200000L;

    /// Linux `F_DUPFD`.
    private static final long F_DUPFD = 0;

    /// Linux `F_GETFD`.
    private static final long F_GETFD = 1;

    /// Linux `F_SETFD`.
    private static final long F_SETFD = 2;

    /// Linux `FD_CLOEXEC`.
    private static final long FD_CLOEXEC = 1;

    /// Linux `CLOSE_RANGE_CLOEXEC`.
    private static final long CLOSE_RANGE_CLOEXEC = 1L << 2;

    /// Linux capability ABI version 3.
    private static final int LINUX_CAPABILITY_VERSION_3 = 0x2008_0522;

    /// Linux `F_GETFL`.
    private static final long F_GETFL = 3;

    /// Linux `F_SETFL`.
    private static final long F_SETFL = 4;

    /// Linux `F_DUPFD_CLOEXEC`.
    private static final long F_DUPFD_CLOEXEC = 1030;

    /// Linux `O_CLOEXEC`.
    private static final long O_CLOEXEC = 02000000L;

    /// Linux address family number for netlink sockets.
    private static final long AF_NETLINK = 16;

    /// Linux address family number for Unix domain sockets.
    private static final long AF_UNIX = 1;

    /// Linux address family number for IPv4 sockets.
    private static final long AF_INET = 2;

    /// Linux address family number for IPv6 sockets.
    private static final long AF_INET6 = 10;

    /// Linux stream socket type.
    private static final long SOCK_STREAM = 1;

    /// Linux datagram socket type.
    private static final long SOCK_DGRAM = 2;

    /// Linux raw socket type.
    private static final long SOCK_RAW = 3;

    /// Linux netlink protocol number for route and interface metadata.
    private static final long NETLINK_ROUTE = 0;

    /// Linux IPv4 protocol level.
    private static final long IPPROTO_IP = 0;

    /// Linux TCP protocol number.
    private static final long IPPROTO_TCP = 6;

    /// Linux UDP protocol number.
    private static final long IPPROTO_UDP = 17;

    /// Linux IPv6 protocol level.
    private static final long IPPROTO_IPV6 = 41;

    /// Linux `IP_RECVERR`.
    private static final long IP_RECVERR = 11;

    /// Linux `IPV6_RECVERR`.
    private static final long IPV6_RECVERR = 25;

    /// Linux socket option level for generic socket options.
    private static final long SOL_SOCKET = 1;

    /// Linux `SO_REUSEADDR`.
    private static final long SO_REUSEADDR = 2;

    /// Linux `SO_ERROR`.
    private static final long SO_ERROR = 4;

    /// Linux `SO_SNDBUF`.
    private static final long SO_SNDBUF = 7;

    /// Linux `SO_RCVBUF`.
    private static final long SO_RCVBUF = 8;

    /// Linux `SO_KEEPALIVE`.
    private static final long SO_KEEPALIVE = 9;

    /// Linux `TCP_NODELAY`.
    private static final long TCP_NODELAY = 1;

    /// Linux `IPV6_V6ONLY`.
    private static final long IPV6_V6ONLY = 26;

    /// Linux `SHUT_WR`.
    private static final long SHUT_WR = 1;

    /// Linux `O_NONBLOCK` accepted in socket type flags.
    private static final long SOCK_NONBLOCK = O_NONBLOCK;

    /// Byte size of Linux `struct sockaddr_in`.
    private static final int SOCKADDR_IN_SIZE = 16;

    /// Byte size of Linux `struct sockaddr_in6`.
    private static final int SOCKADDR_IN6_SIZE = 28;

    /// Byte size of Linux `struct sockaddr_un`.
    private static final int SOCKADDR_UN_SIZE = 110;

    /// Byte offset of `sun_path` inside Linux `struct sockaddr_un`.
    private static final int SOCKADDR_UN_PATH_OFFSET = 2;

    /// Byte offset of the port field in Linux Internet socket addresses.
    private static final int SOCKADDR_PORT_OFFSET = 2;

    /// Byte offset of `sin_addr` inside Linux `struct sockaddr_in`.
    private static final int SOCKADDR_IN_ADDRESS_OFFSET = 4;

    /// Byte offset of `sin6_addr` inside Linux `struct sockaddr_in6`.
    private static final int SOCKADDR_IN6_ADDRESS_OFFSET = 8;

    /// Byte offset of `sin6_scope_id` inside Linux `struct sockaddr_in6`.
    private static final int SOCKADDR_IN6_SCOPE_ID_OFFSET = 24;

    /// Linux `SIOCGIFNAME` ioctl request number.
    private static final long SIOCGIFNAME = 0x8910L;

    /// Linux `SIOCGIFINDEX` ioctl request number.
    private static final long SIOCGIFINDEX = 0x8933L;

    /// Linux `IFNAMSIZ`.
    private static final int INTERFACE_NAME_SIZE = 16;

    /// Byte offset of `ifr_ifindex` in Linux `struct ifreq`.
    private static final long IFREQ_INTERFACE_INDEX_OFFSET = INTERFACE_NAME_SIZE;

    /// Byte size of Linux `struct sockaddr_nl`.
    private static final int SOCKADDR_NL_SIZE = 12;

    /// Byte offset of `nl_pid` inside Linux `struct sockaddr_nl`.
    private static final int SOCKADDR_NL_PID_OFFSET = 4;

    /// Byte offset of `nl_groups` inside Linux `struct sockaddr_nl`.
    private static final int SOCKADDR_NL_GROUPS_OFFSET = 8;

    /// Byte offset of `msg_namelen` inside Linux RISC-V 64-bit `struct msghdr`.
    private static final int MSGHDR_NAME_LENGTH_OFFSET = Long.BYTES;

    /// Byte offset of `msg_iov` inside Linux RISC-V 64-bit `struct msghdr`.
    private static final int MSGHDR_IOV_OFFSET = 2 * Long.BYTES;

    /// Byte offset of `msg_iovlen` inside Linux RISC-V 64-bit `struct msghdr`.
    private static final int MSGHDR_IOV_LENGTH_OFFSET = 3 * Long.BYTES;

    /// Byte offset of `msg_flags` inside Linux RISC-V 64-bit `struct msghdr`.
    private static final int MSGHDR_FLAGS_OFFSET = 6 * Long.BYTES;

    /// Byte offset of `msg_len` inside Linux RISC-V 64-bit `struct mmsghdr`.
    private static final int MMSGHDR_LENGTH_OFFSET = 7 * Long.BYTES;

    /// Byte size of Linux RISC-V 64-bit `struct mmsghdr`.
    private static final int MMSGHDR_SIZE = 8 * Long.BYTES;

    /// Byte size of one Linux RISC-V 64-bit `struct iovec`.
    private static final int IOVEC_SIZE = 2 * Long.BYTES;

    /// Byte offset of `iov_base` inside Linux RISC-V 64-bit `struct iovec`.
    private static final int IOVEC_BASE_OFFSET = 0;

    /// Byte offset of `iov_len` inside Linux RISC-V 64-bit `struct iovec`.
    private static final int IOVEC_LENGTH_OFFSET = Long.BYTES;

    /// Byte offset of `nlmsg_type` inside Linux `struct nlmsghdr`.
    private static final int NETLINK_HEADER_TYPE_OFFSET = Integer.BYTES;

    /// Byte offset of `nlmsg_seq` inside Linux `struct nlmsghdr`.
    private static final int NETLINK_HEADER_SEQUENCE_OFFSET = 2 * Integer.BYTES;

    /// Byte offset of `nlmsg_pid` inside Linux `struct nlmsghdr`.
    private static final int NETLINK_HEADER_PORT_ID_OFFSET = 3 * Integer.BYTES;

    /// Byte size of Linux `struct nlmsghdr`.
    private static final int NETLINK_HEADER_SIZE = 16;

    /// Byte offset of `ifi_index` inside Linux `struct ifinfomsg` payload.
    private static final int NETLINK_LINK_INTERFACE_INDEX_OFFSET = NETLINK_HEADER_SIZE + 4;

    /// Byte offset of `ifa_index` inside Linux `struct ifaddrmsg` payload.
    private static final int NETLINK_ADDRESS_INTERFACE_INDEX_OFFSET = NETLINK_HEADER_SIZE + 4;

    /// Linux netlink message type for end-of-dump responses.
    private static final int NETLINK_MESSAGE_DONE = 3;

    /// Linux rtnetlink message type for interface records.
    private static final int RTM_NEWLINK = 16;

    /// Linux rtnetlink message type for interface address records.
    private static final int RTM_NEWADDR = 20;

    /// Linux rtnetlink message type for route records.
    private static final int RTM_NEWROUTE = 24;

    /// Linux rtnetlink request type for interface records.
    private static final int RTM_GETLINK = 18;

    /// Linux rtnetlink request type for interface address records.
    private static final int RTM_GETADDR = 22;

    /// Linux rtnetlink request type for route records.
    private static final int RTM_GETROUTE = 26;

    /// Linux interface index used for the synthetic loopback interface.
    private static final int LOOPBACK_INTERFACE_INDEX = 1;

    /// Linux interface index used for the synthetic Ethernet interface.
    private static final int ETHERNET_INTERFACE_INDEX = 2;

    /// Linux `EFD_SEMAPHORE`.
    private static final long EFD_SEMAPHORE = 1;

    /// Linux `EPOLL_CTL_ADD`.
    private static final long EPOLL_CTL_ADD = 1;

    /// Linux `EPOLL_CTL_DEL`.
    private static final long EPOLL_CTL_DEL = 2;

    /// Linux `EPOLL_CTL_MOD`.
    private static final long EPOLL_CTL_MOD = 3;

    /// Linux `EPOLLIN`.
    private static final int EPOLLIN = 0x001;

    /// Linux `EPOLLOUT`.
    private static final int EPOLLOUT = 0x004;

    /// Linux `POLLIN`.
    private static final int POLLIN = 0x001;

    /// Linux `POLLOUT`.
    private static final int POLLOUT = 0x004;

    /// Linux `POLLHUP`.
    private static final int POLLHUP = 0x010;

    /// Linux `POLLNVAL`.
    private static final int POLLNVAL = 0x020;

    /// The byte size of Linux RISC-V 64-bit `struct pollfd`.
    private static final int POLL_FD_SIZE = 8;

    /// The byte offset of `events` inside Linux RISC-V 64-bit `struct pollfd`.
    private static final int POLL_FD_EVENTS_OFFSET = Integer.BYTES;

    /// The byte offset of `revents` inside Linux RISC-V 64-bit `struct pollfd`.
    private static final int POLL_FD_REVENTS_OFFSET = Integer.BYTES + Short.BYTES;

    /// The maximum byte width of a Linux RISC-V 64-bit `fd_set` used by tests.
    private static final int TEST_FD_SET_SIZE = 128;

    /// The byte offset of `ss` inside the Linux `pselect6` signal-mask argument.
    private static final int PSELECT6_SIGNAL_MASK_ADDRESS_OFFSET = 0;

    /// The byte offset of `ss_len` inside the Linux `pselect6` signal-mask argument.
    private static final int PSELECT6_SIGNAL_SET_SIZE_OFFSET = Long.BYTES;

    /// The byte size of Linux RISC-V 64-bit `struct epoll_event`.
    private static final int EPOLL_EVENT_SIZE = 16;

    /// The byte offset of `events` inside Linux RISC-V 64-bit `struct epoll_event`.
    private static final int EPOLL_EVENT_EVENTS_OFFSET = 0;

    /// The byte offset of `data` inside Linux RISC-V 64-bit `struct epoll_event`.
    private static final int EPOLL_EVENT_DATA_OFFSET = Long.BYTES;

    /// The Linux generic kernel `sigset_t` size accepted by signal syscalls.
    private static final long KERNEL_SIGSET_SIZE = 8;

    /// Linux `SIGILL`.
    private static final long SIGILL = 4;

    /// Linux `SIGCHLD`.
    private static final long SIGCHLD = 17;

    /// Linux `SIGKILL`.
    private static final long SIGKILL = 9;

    /// Linux `SIGUSR1`.
    private static final long SIGUSR1 = 10;

    /// Linux `SIGSTOP`.
    private static final long SIGSTOP = 19;

    /// Linux `SIG_BLOCK` signal-mask operation.
    private static final long SIG_BLOCK = 0;

    /// Linux `SIG_UNBLOCK` signal-mask operation.
    private static final long SIG_UNBLOCK = 1;

    /// Linux `SIG_SETMASK` signal-mask operation.
    private static final long SIG_SETMASK = 2;

    /// Linux `ILL_ILLOPC`.
    private static final int ILL_ILLOPC = 1;

    /// Linux `SA_SIGINFO`.
    private static final long SA_SIGINFO = 0x00000004L;

    /// Linux `P_PID`.
    private static final long WAIT_ID_PROCESS = 1;

    /// Linux `P_PIDFD`.
    private static final long WAIT_ID_PROCESS_FILE_DESCRIPTOR = 3;

    /// Linux `WEXITED`.
    private static final long WAIT_ID_EXITED = 0x0000_0004L;

    /// Linux `WNOWAIT`.
    private static final long WAIT_ID_NO_WAIT = 0x0100_0000L;

    /// Linux internal `__WCLONE`.
    private static final long WAIT_CLONE_CHILDREN = 0x8000_0000L;

    /// Linux `CLD_EXITED`.
    private static final int WAIT_ID_CHILD_EXITED = 1;

    /// The byte size of Linux generic 64-bit `siginfo_t`.
    private static final long SIGNAL_INFO_SIZE = 128;

    /// The rounded byte size of Linux RISC-V 64-bit `rt_sigframe`.
    private static final long SIGNAL_FRAME_SIZE = 1088;

    /// The byte offset of `si_code` inside Linux generic 64-bit `siginfo_t`.
    private static final long SIGNAL_INFO_CODE_OFFSET = 2L * Integer.BYTES;

    /// The byte offset of `si_pid` inside Linux RISC-V 64-bit `siginfo_t`.
    private static final long SIGNAL_INFO_PROCESS_ID_OFFSET = 4L * Integer.BYTES;

    /// The byte offset of `si_uid` inside Linux RISC-V 64-bit `siginfo_t`.
    private static final long SIGNAL_INFO_USER_ID_OFFSET = 5L * Integer.BYTES;

    /// The byte offset of `si_status` inside Linux RISC-V 64-bit `siginfo_t`.
    private static final long SIGNAL_INFO_STATUS_OFFSET = 6L * Integer.BYTES;

    /// The byte offset of `si_addr` inside the Linux generic 64-bit `siginfo_t` fault union.
    private static final long SIGNAL_INFO_FAULT_ADDRESS_OFFSET = 2L * Long.BYTES;

    /// The byte offset of `ss_sp` inside Linux RISC-V 64-bit `stack_t`.
    private static final long SIGNAL_STACK_POINTER_OFFSET = 0;

    /// The byte offset of `ss_flags` inside Linux RISC-V 64-bit `stack_t`.
    private static final long SIGNAL_STACK_FLAGS_OFFSET = Long.BYTES;

    /// The byte offset of `ss_size` inside Linux RISC-V 64-bit `stack_t`.
    private static final long SIGNAL_STACK_SIZE_OFFSET = 2L * Long.BYTES;

    /// The byte offset of `uc_mcontext` inside Linux RISC-V 64-bit `ucontext_t`.
    private static final long SIGNAL_CONTEXT_MACHINE_OFFSET = 176;

    /// Linux `MINSIGSTKSZ`.
    private static final long MINIMUM_SIGNAL_STACK_SIZE = 2048;

    /// Linux `SS_ONSTACK`.
    private static final long SS_ONSTACK = 1;

    /// Linux `SS_DISABLE`.
    private static final long SS_DISABLE = 2;

    /// Linux `SS_AUTODISARM`.
    private static final long SS_AUTODISARM = 1L << 31;

    /// The guest page size used by `mmap` and `munmap`.
    private static final long PAGE_SIZE = 4096;

    /// The byte size of Linux `struct riscv_hwprobe`.
    private static final long RISCV_HWPROBE_PAIR_SIZE = 16;

    /// The byte offset of `key` inside `struct riscv_hwprobe`.
    private static final long RISCV_HWPROBE_KEY_OFFSET = 0;

    /// The byte offset of `value` inside `struct riscv_hwprobe`.
    private static final long RISCV_HWPROBE_VALUE_OFFSET = Long.BYTES;

    /// Linux `RISCV_HWPROBE_WHICH_CPUS`.
    private static final long RISCV_HWPROBE_WHICH_CPUS = 1;

    /// Linux `RISCV_HWPROBE_KEY_MVENDORID`.
    private static final long RISCV_HWPROBE_KEY_MVENDORID = 0;

    /// Linux `RISCV_HWPROBE_KEY_BASE_BEHAVIOR`.
    private static final long RISCV_HWPROBE_KEY_BASE_BEHAVIOR = 3;

    /// Linux `RISCV_HWPROBE_BASE_BEHAVIOR_IMA`.
    private static final long RISCV_HWPROBE_BASE_BEHAVIOR_IMA = 1;

    /// Linux `RISCV_HWPROBE_KEY_IMA_EXT_0`.
    private static final long RISCV_HWPROBE_KEY_IMA_EXT_0 = 4;

    /// Linux `RISCV_HWPROBE_KEY_CPUPERF_0`.
    private static final long RISCV_HWPROBE_KEY_CPUPERF_0 = 5;

    /// Linux `RISCV_HWPROBE_MISALIGNED_EMULATED`.
    private static final long RISCV_HWPROBE_MISALIGNED_EMULATED = 1;

    /// Linux `RISCV_HWPROBE_KEY_ZICBOZ_BLOCK_SIZE`.
    private static final long RISCV_HWPROBE_KEY_ZICBOZ_BLOCK_SIZE = 6;

    /// Linux `RISCV_HWPROBE_KEY_HIGHEST_VIRT_ADDRESS`.
    private static final long RISCV_HWPROBE_KEY_HIGHEST_VIRT_ADDRESS = 7;

    /// Highest SV48-compatible Linux RISC-V user address reported by `riscv_hwprobe`.
    private static final long RISCV_HIGHEST_SV48_USER_ADDRESS = (1L << 47) - 1;

    /// Linux `RISCV_HWPROBE_KEY_TIME_CSR_FREQ`.
    private static final long RISCV_HWPROBE_KEY_TIME_CSR_FREQ = 8;

    /// Linux `RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF`.
    private static final long RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF = 9;

    /// Linux `RISCV_HWPROBE_MISALIGNED_SCALAR_EMULATED`.
    private static final long RISCV_HWPROBE_MISALIGNED_SCALAR_EMULATED = 1;

    /// Linux `RISCV_HWPROBE_KEY_MISALIGNED_VECTOR_PERF`.
    private static final long RISCV_HWPROBE_KEY_MISALIGNED_VECTOR_PERF = 10;

    /// Linux `RISCV_HWPROBE_KEY_ZICBOM_BLOCK_SIZE`.
    private static final long RISCV_HWPROBE_KEY_ZICBOM_BLOCK_SIZE = 12;

    /// Linux `RISCV_HWPROBE_KEY_ZICBOP_BLOCK_SIZE`.
    private static final long RISCV_HWPROBE_KEY_ZICBOP_BLOCK_SIZE = 15;

    /// Linux `RISCV_HWPROBE_MISALIGNED_VECTOR_SLOW`.
    private static final long RISCV_HWPROBE_MISALIGNED_VECTOR_SLOW = 2;

    /// Linux `PROT_NONE`.
    private static final long PROT_NONE = 0x0;

    /// Linux `PROT_READ`.
    private static final long PROT_READ = 0x1;

    /// Linux `PROT_WRITE`.
    private static final long PROT_WRITE = 0x2;

    /// Linux `PROT_EXEC`.
    private static final long PROT_EXEC = 0x4;

    /// Linux `MAP_PRIVATE`.
    private static final long MAP_PRIVATE = 0x02;

    /// Linux `MAP_SHARED`.
    private static final long MAP_SHARED = 0x01;

    /// Linux `MAP_SHARED_VALIDATE`.
    private static final long MAP_SHARED_VALIDATE = 0x03;

    /// Linux `MAP_FIXED`.
    private static final long MAP_FIXED = 0x10;

    /// Linux `MAP_ANONYMOUS`.
    private static final long MAP_ANONYMOUS = 0x20;

    /// Linux `MAP_HUGETLB`.
    private static final long MAP_HUGETLB = 0x40000;

    /// Linux `MAP_FIXED_NOREPLACE`.
    private static final long MAP_FIXED_NOREPLACE = 0x100000;

    /// Linux `MAP_NORESERVE`.
    private static final long MAP_NORESERVE = 0x4000;

    /// Linux `MREMAP_MAYMOVE`.
    private static final long MREMAP_MAYMOVE = 1;

    /// Linux `MREMAP_FIXED`.
    private static final long MREMAP_FIXED = 2;

    /// Linux `FUTEX_WAIT`.
    private static final long FUTEX_WAIT = 0;

    /// Linux `FUTEX_WAKE`.
    private static final long FUTEX_WAKE = 1;

    /// Linux `FUTEX_WAIT_BITSET`.
    private static final long FUTEX_WAIT_BITSET = 9;

    /// Linux `FUTEX_WAKE_BITSET`.
    private static final long FUTEX_WAKE_BITSET = 10;

    /// Linux `FUTEX_PRIVATE_FLAG`.
    private static final long FUTEX_PRIVATE_FLAG = 128;

    /// Linux `FUTEX_CLOCK_REALTIME`.
    private static final long FUTEX_CLOCK_REALTIME = 256;

    /// Linux `FUTEX_BITSET_MATCH_ANY`.
    private static final long FUTEX_BITSET_MATCH_ANY = 0xffff_ffffL;

    /// Linux `CLONE_VM`.
    private static final long CLONE_VM = 0x00000100L;

    /// Linux `CLONE_FS`.
    private static final long CLONE_FS = 0x00000200L;

    /// Linux `CLONE_FILES`.
    private static final long CLONE_FILES = 0x00000400L;

    /// Linux `CLONE_SIGHAND`.
    private static final long CLONE_SIGHAND = 0x00000800L;

    /// Linux `CLONE_PIDFD`.
    private static final long CLONE_PIDFD = 0x00001000L;

    /// Linux `CLONE_VFORK`.
    private static final long CLONE_VFORK = 0x00004000L;

    /// Linux `CLONE_THREAD`.
    private static final long CLONE_THREAD = 0x00010000L;

    /// Linux `CLONE_SYSVSEM`.
    private static final long CLONE_SYSVSEM = 0x00040000L;

    /// Linux `CLONE_SETTLS`.
    private static final long CLONE_SETTLS = 0x00080000L;

    /// Linux `CLONE_PARENT_SETTID`.
    private static final long CLONE_PARENT_SETTID = 0x00100000L;

    /// Linux `CLONE_CHILD_CLEARTID`.
    private static final long CLONE_CHILD_CLEARTID = 0x00200000L;

    /// Linux `CLONE_DETACHED`.
    private static final long CLONE_DETACHED = 0x00400000L;

    /// Linux `CLONE_CHILD_SETTID`.
    private static final long CLONE_CHILD_SETTID = 0x01000000L;

    /// Linux clone flags required by the syscall layer's thread-style path.
    private static final long REQUIRED_THREAD_CLONE_FLAGS =
            CLONE_VM | CLONE_SIGHAND | CLONE_THREAD;

    /// Linux clone flags accepted by the syscall layer's thread-style path.
    private static final long THREAD_CLONE_FLAGS =
            REQUIRED_THREAD_CLONE_FLAGS
                    | CLONE_FS
                    | CLONE_FILES
                    | CLONE_SYSVSEM
                    | CLONE_SETTLS
                    | CLONE_PARENT_SETTID
                    | CLONE_CHILD_CLEARTID
                    | CLONE_DETACHED
                    | CLONE_CHILD_SETTID;

    /// The known Linux `struct clone_args` byte size.
    private static final long CLONE_ARGS_SIZE = 88;

    /// The byte offset of `flags` inside `struct clone_args`.
    private static final long CLONE_ARGS_FLAGS_OFFSET = 0;

    /// The byte offset of `pidfd` inside `struct clone_args`.
    private static final long CLONE_ARGS_PIDFD_OFFSET = 8;

    /// The byte offset of `child_tid` inside `struct clone_args`.
    private static final long CLONE_ARGS_CHILD_TID_OFFSET = 16;

    /// The byte offset of `parent_tid` inside `struct clone_args`.
    private static final long CLONE_ARGS_PARENT_TID_OFFSET = 24;

    /// The byte offset of `exit_signal` inside `struct clone_args`.
    private static final long CLONE_ARGS_EXIT_SIGNAL_OFFSET = 32;

    /// The byte offset of `stack` inside `struct clone_args`.
    private static final long CLONE_ARGS_STACK_OFFSET = 40;

    /// The byte offset of `stack_size` inside `struct clone_args`.
    private static final long CLONE_ARGS_STACK_SIZE_OFFSET = 48;

    /// The byte offset of `tls` inside `struct clone_args`.
    private static final long CLONE_ARGS_TLS_OFFSET = 56;

    /// Linux `MADV_DONTNEED`.
    private static final long MADV_DONTNEED = 4;

    /// Linux `MADV_REMOVE`.
    private static final long MADV_REMOVE = 9;

    /// Linux `MADV_HUGEPAGE`.
    private static final long MADV_HUGEPAGE = 14;

    /// Linux `MS_ASYNC`.
    private static final long MS_ASYNC = 1;

    /// Linux `MS_INVALIDATE`.
    private static final long MS_INVALIDATE = 2;

    /// Linux `MS_SYNC`.
    private static final long MS_SYNC = 4;

    /// Linux `MCL_CURRENT`.
    private static final long MCL_CURRENT = 1;

    /// Linux `MCL_FUTURE`.
    private static final long MCL_FUTURE = 2;

    /// Linux `MCL_ONFAULT`.
    private static final long MCL_ONFAULT = 4;

    /// Linux `MLOCK_ONFAULT`.
    private static final long MLOCK_ONFAULT = 1;

    /// Linux `SCHED_OTHER`.
    private static final long SCHED_OTHER = 0;

    /// Linux `SCHED_FIFO`.
    private static final long SCHED_FIFO = 1;

    /// Linux `SCHED_RR`.
    private static final long SCHED_RR = 2;

    /// Linux `SCHED_BATCH`.
    private static final long SCHED_BATCH = 3;

    /// Linux `SCHED_RESET_ON_FORK`.
    private static final long SCHED_RESET_ON_FORK = 0x40000000;

    /// Linux `CLOCK_REALTIME`.
    private static final long CLOCK_REALTIME = 0;

    /// Linux `CLOCK_MONOTONIC`.
    private static final long CLOCK_MONOTONIC = 1;

    /// Linux `CLOCK_PROCESS_CPUTIME_ID`.
    private static final long CLOCK_PROCESS_CPUTIME_ID = 2;

    /// Linux `CLOCK_THREAD_CPUTIME_ID`.
    private static final long CLOCK_THREAD_CPUTIME_ID = 3;

    /// Linux `CLOCK_BOOTTIME`.
    private static final long CLOCK_BOOTTIME = 7;

    /// Linux `ITIMER_REAL`.
    private static final long ITIMER_REAL = 0;

    /// Linux `ITIMER_VIRTUAL`.
    private static final long ITIMER_VIRTUAL = 1;

    /// Linux `ITIMER_PROF`.
    private static final long ITIMER_PROF = 2;

    /// Linux `MEMBARRIER_CMD_QUERY`.
    private static final long MEMBARRIER_CMD_QUERY = 0;

    /// The original Linux `struct rseq` byte size including padding.
    private static final long RSEQ_ORIGINAL_SIZE = 32;

    /// Linux `RSEQ_FLAG_UNREGISTER`.
    private static final long RSEQ_FLAG_UNREGISTER = 1;

    /// The byte offset of `cpu_id_start` inside Linux `struct rseq`.
    private static final long RSEQ_CPU_ID_START_OFFSET = 0;

    /// The byte offset of `cpu_id` inside Linux `struct rseq`.
    private static final long RSEQ_CPU_ID_OFFSET = Integer.BYTES;

    /// The byte offset of `rseq_cs` inside Linux `struct rseq`.
    private static final long RSEQ_CRITICAL_SECTION_OFFSET = 2L * Integer.BYTES;

    /// The byte offset of `flags` inside Linux `struct rseq`.
    private static final long RSEQ_FLAGS_OFFSET = RSEQ_CRITICAL_SECTION_OFFSET + Long.BYTES;

    /// The byte offset of `node_id` inside Linux `struct rseq`.
    private static final long RSEQ_NODE_ID_OFFSET = RSEQ_FLAGS_OFFSET + Integer.BYTES;

    /// The byte offset of `mm_cid` inside Linux `struct rseq`.
    private static final long RSEQ_MEMORY_MAP_CONCURRENCY_ID_OFFSET = RSEQ_NODE_ID_OFFSET + Integer.BYTES;

    /// Linux `TIMER_ABSTIME`.
    private static final long TIMER_ABSTIME = 1;

    /// Linux `TFD_TIMER_ABSTIME`.
    private static final long TFD_TIMER_ABSTIME = 1;

    /// The byte offset of `it_interval` inside Linux RISC-V 64-bit `struct itimerspec`.
    private static final long ITIMERSPEC_INTERVAL_OFFSET = 0;

    /// The byte offset of `it_value` inside Linux RISC-V 64-bit `struct itimerspec`.
    private static final long ITIMERSPEC_VALUE_OFFSET = 2L * Long.BYTES;

    /// The byte size of Linux RISC-V 64-bit `struct itimerspec`.
    private static final long ITIMERSPEC_SIZE = 4L * Long.BYTES;

    /// Linux `PR_SET_PDEATHSIG`.
    private static final long PR_SET_PDEATHSIG = 1;

    /// Linux `PR_GET_PDEATHSIG`.
    private static final long PR_GET_PDEATHSIG = 2;

    /// Linux `PR_GET_DUMPABLE`.
    private static final long PR_GET_DUMPABLE = 3;

    /// Linux `PR_SET_DUMPABLE`.
    private static final long PR_SET_DUMPABLE = 4;

    /// Linux `PR_SET_NAME`.
    private static final long PR_SET_NAME = 15;

    /// Linux `PR_GET_NAME`.
    private static final long PR_GET_NAME = 16;

    /// Linux `PR_SET_TIMERSLACK`.
    private static final long PR_SET_TIMERSLACK = 29;

    /// Linux `PR_GET_TIMERSLACK`.
    private static final long PR_GET_TIMERSLACK = 30;

    /// Linux `PR_SET_CHILD_SUBREAPER`.
    private static final long PR_SET_CHILD_SUBREAPER = 36;

    /// Linux `PR_GET_CHILD_SUBREAPER`.
    private static final long PR_GET_CHILD_SUBREAPER = 37;

    /// Linux `PR_SET_NO_NEW_PRIVS`.
    private static final long PR_SET_NO_NEW_PRIVS = 38;

    /// Linux `PR_GET_NO_NEW_PRIVS`.
    private static final long PR_GET_NO_NEW_PRIVS = 39;

    /// Linux `PR_GET_TID_ADDRESS`.
    private static final long PR_GET_TID_ADDRESS = 40;

    /// Linux `PR_SET_THP_DISABLE`.
    private static final long PR_SET_THP_DISABLE = 41;

    /// Linux `PR_GET_THP_DISABLE`.
    private static final long PR_GET_THP_DISABLE = 42;

    /// Linux `PR_SET_TAGGED_ADDR_CTRL`.
    private static final long PR_SET_TAGGED_ADDR_CTRL = 55;

    /// Linux `PR_GET_TAGGED_ADDR_CTRL`.
    private static final long PR_GET_TAGGED_ADDR_CTRL = 56;

    /// Linux `PR_GET_AUXV`.
    private static final long PR_GET_AUXV = 0x4155_5856L;

    /// Linux `PR_TAGGED_ADDR_ENABLE`.
    private static final long PR_TAGGED_ADDR_ENABLE = 1;

    /// Linux `PR_PMLEN_SHIFT`.
    private static final long PR_PMLEN_SHIFT = 24;

    /// Linux `PR_PMLEN_MASK`.
    private static final long PR_PMLEN_MASK = 0x7fL << PR_PMLEN_SHIFT;

    /// Linux `PR_SET_VMA`.
    private static final long PR_SET_VMA = 0x53564d41L;

    /// Linux `PR_SET_VMA_ANON_NAME`.
    private static final long PR_SET_VMA_ANON_NAME = 0;

    /// Linux auxv terminator type.
    private static final long AT_NULL = 0;

    /// Linux auxv page-size type.
    private static final long AT_PAGESZ = 6;

    /// Linux auxv executable filename pointer type.
    private static final long AT_EXECFN = 31;

    /// Verifies that stdin EOF is reported as a zero-byte read.
    @Test
    public void readReturnsZeroAtEndOfFile() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));

            setSyscall(state, SYS_READ, 0, memory.baseAddress(), 8);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(0, state.register(10));
        }
    }

    /// Verifies that zero-length writes succeed without touching the guest address.
    @Test
    public void writeAcceptsZeroLengthInvalidAddress() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    out,
                    new ByteArrayOutputStream(),
                    memory.baseAddress());

            setSyscall(state, SYS_WRITE, 1, 0, 0);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(0, state.register(10));
            assertEquals("", out.toString(StandardCharsets.UTF_8));
        }
    }

    /// Verifies that short host reads only copy the returned byte count into guest memory.
    @Test
    public void readCopiesPartialInput() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            memory.writeByte(memory.baseAddress() + 2, (byte) 'Z');
            RiscVThreadState state = state(memory, new ByteArrayInputStream("AB".getBytes(StandardCharsets.UTF_8)));

            setSyscall(state, SYS_READ, 0, memory.baseAddress(), 8);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(2, state.register(10));
            assertArrayEquals("AB".getBytes(StandardCharsets.UTF_8), memory.readBytes(memory.baseAddress(), 2));
            assertEquals('Z', memory.readUnsignedByte(memory.baseAddress() + 2));
        }
    }

    /// Verifies that invalid file descriptors return `-EBADF` and do not touch host output streams.
    @Test
    public void invalidFileDescriptorsReturnBadFileDescriptor() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ByteArrayOutputStream err = new ByteArrayOutputStream();
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream("A".getBytes(StandardCharsets.UTF_8)),
                    out,
                    err,
                    memory.baseAddress());

            memory.writeByte(memory.baseAddress(), (byte) 'Q');
            setSyscall(state, SYS_READ, 9, memory.baseAddress(), 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
            assertEquals('Q', memory.readUnsignedByte(memory.baseAddress()));

            memory.writeByte(memory.baseAddress(), (byte) 'B');
            setSyscall(state, SYS_WRITE, 9, memory.baseAddress(), 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
            assertEquals("", out.toString(StandardCharsets.UTF_8));
            assertEquals("", err.toString(StandardCharsets.UTF_8));
        }
    }

    /// Verifies that syscall buffers still use checked guest memory bounds.
    @Test
    public void syscallBuffersMustFitGuestMemory() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream("A".getBytes(StandardCharsets.UTF_8)));

            setSyscall(state, SYS_READ, 0, memory.endAddress(), 1);
            assertThrows(RiscVException.class, () -> state.syscalls().handle(state, TEST_PC));

            setSyscall(state, SYS_WRITE, 1, memory.endAddress(), 1);
            assertThrows(RiscVException.class, () -> state.syscalls().handle(state, TEST_PC));
        }
    }

    /// Verifies that standard file descriptor `close` is a deterministic no-op.
    @Test
    public void closeSupportsStandardFileDescriptors() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));

            setSyscall(state, SYS_CLOSE, 1, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_CLOSE, 9, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
        }
    }

    /// Verifies `fcntl` descriptor duplication with a requested minimum descriptor.
    @Test
    public void fcntlDuplicatesDescriptorsAtMinimumDescriptor() throws Exception {
        Files.createDirectories(tempDirectory.resolve("directory"));
        Files.writeString(tempDirectory.resolve("directory").resolve("message.txt"), "directory-data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 512;

            writeGuestString(memory, pathAddress, "directory");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            int directoryFileDescriptor = (int) state.register(10);
            assertEquals(3, directoryFileDescriptor);

            setSyscall(state, SYS_FCNTL, directoryFileDescriptor, F_DUPFD_CLOEXEC, 10);
            state.syscalls().handle(state, TEST_PC);
            int duplicatedFileDescriptor = (int) state.register(10);
            assertEquals(10, duplicatedFileDescriptor);

            setSyscall(state, SYS_FCNTL, duplicatedFileDescriptor, F_GETFD, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(FD_CLOEXEC, state.register(10));

            setSyscall(state, SYS_FCNTL, duplicatedFileDescriptor, F_SETFD, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FCNTL, duplicatedFileDescriptor, F_GETFD, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_CLOSE, directoryFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETDENTS64, duplicatedFileDescriptor, bufferAddress, 512);
            state.syscalls().handle(state, TEST_PC);
            assertTrue(state.register(10) > 0);
            long nextEntry = assertDirectoryEntry(memory, bufferAddress, ".", DIRECTORY_ENTRY_DIRECTORY, 1);
            nextEntry = assertDirectoryEntry(memory, nextEntry, "..", DIRECTORY_ENTRY_DIRECTORY, 2);
            assertDirectoryEntry(memory, nextEntry, "message.txt", DIRECTORY_ENTRY_REGULAR_FILE, 3);

            setSyscall(state, SYS_FCNTL, duplicatedFileDescriptor, F_DUPFD, -1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies `fcntl(F_SETFL)` stores `O_NONBLOCK` for standard input descriptors.
    @Test
    public void fcntlSetsNonblockingOnStandardInput() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));

            setSyscall(state, SYS_FCNTL, 0, F_GETFL, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(O_RDONLY, state.register(10));

            setSyscall(state, SYS_FCNTL, 0, F_SETFL, O_NONBLOCK);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FCNTL, 0, F_GETFL, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(O_RDONLY | O_NONBLOCK, state.register(10));
        }
    }

    /// Verifies that standard streams report as character devices through `fstat`.
    @Test
    public void fstatReportsStandardStreamsAsCharacterDevices() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));

            setSyscall(state, SYS_FSTAT, 1, memory.baseAddress(), 0);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(0, state.register(10));
            assertEquals(STANDARD_STREAM_STAT_MODE, memory.readInt(memory.baseAddress() + STAT_MODE_OFFSET));
            assertEquals(1, memory.readInt(memory.baseAddress() + STAT_LINK_COUNT_OFFSET));
            assertEquals(4096, memory.readInt(memory.baseAddress() + STAT_BLOCK_SIZE_OFFSET));

            setSyscall(state, SYS_FSTAT, 9, memory.baseAddress(), 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
        }
    }

    /// Verifies that the guest working directory is exposed as the sandbox root.
    @Test
    public void getcwdReportsSandboxRoot() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long bufferAddress = memory.baseAddress() + 64;

            setSyscall(state, SYS_GETCWD, bufferAddress, 16, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));
            assertArrayEquals(new byte[]{'/', 0}, memory.readBytes(bufferAddress, 2));

            setSyscall(state, SYS_GETCWD, bufferAddress, 1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ERANGE, state.register(10));
        }
    }

    /// Verifies that `chdir` and `fchdir` update `AT_FDCWD` path resolution.
    @Test
    public void chdirUpdatesWorkingDirectoryAndRelativePaths() throws Exception {
        Files.createDirectories(tempDirectory.resolve("first").resolve("nested"));
        Files.writeString(tempDirectory.resolve("first").resolve("message.txt"), "cwd-data", StandardCharsets.UTF_8);
        Files.writeString(tempDirectory.resolve("root.txt"), "root-data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 128;
            long statAddress = memory.baseAddress() + 256;

            writeGuestString(memory, pathAddress, "first");
            setSyscall(state, SYS_CHDIR, pathAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETCWD, bufferAddress, 16, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(7, state.register(10));
            assertEquals("/first", readGuestCString(memory, bufferAddress, 16));

            writeGuestString(memory, pathAddress, "message.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int fileDescriptor = (int) state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_READ, fileDescriptor, bufferAddress, 8);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(8, state.register(10));
            assertArrayEquals("cwd-data".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 8));

            setSyscall(state, SYS_CLOSE, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "/root.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            fileDescriptor = (int) state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_CLOSE, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "nested");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            int directoryFileDescriptor = (int) state.register(10);
            assertEquals(3, directoryFileDescriptor);

            setSyscall(state, SYS_FCHDIR, directoryFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETCWD, bufferAddress, 32, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(14, state.register(10));
            assertEquals("/first/nested", readGuestCString(memory, bufferAddress, 32));

            writeGuestString(memory, pathAddress, "");
            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, pathAddress, statAddress, AT_EMPTY_PATH);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(READ_WRITE_DIRECTORY_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));

            writeGuestString(memory, pathAddress, "../message.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            fileDescriptor = (int) state.register(10);
            assertEquals(4, fileDescriptor);

            setSyscall(state, SYS_FCHDIR, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOTDIR, state.register(10));

            setSyscall(state, SYS_CLOSE, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "../..");
            setSyscall(state, SYS_CHDIR, pathAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETCWD, bufferAddress, 16, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));
            assertEquals("/", readGuestCString(memory, bufferAddress, 16));

            writeGuestString(memory, pathAddress, "../outside");
            setSyscall(state, SYS_CHDIR, pathAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            writeGuestString(memory, pathAddress, "root.txt");
            setSyscall(state, SYS_CHDIR, pathAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOTDIR, state.register(10));

            writeGuestString(memory, pathAddress, "missing");
            setSyscall(state, SYS_CHDIR, pathAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOENT, state.register(10));

            setSyscall(state, SYS_FCHDIR, 99, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
        }
    }

    /// Verifies that `newfstatat` reports sandboxed host files and directories.
    @Test
    public void newfstatatReportsSandboxedHostPaths() throws Exception {
        Files.writeString(tempDirectory.resolve("message.txt"), "file-data", StandardCharsets.UTF_8);
        Files.createDirectories(tempDirectory.resolve("directory"));

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long statAddress = memory.baseAddress() + 256;

            writeGuestString(memory, pathAddress, "/message.txt");
            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, pathAddress, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(READ_WRITE_REGULAR_FILE_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));
            assertEquals(9, memory.readLong(statAddress + STAT_SIZE_OFFSET));

            writeGuestString(memory, pathAddress, "directory");
            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, pathAddress, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(READ_WRITE_DIRECTORY_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));

            writeGuestString(memory, pathAddress, "");
            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, pathAddress, statAddress, AT_EMPTY_PATH);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(READ_WRITE_DIRECTORY_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));

            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, 0, statAddress, AT_EMPTY_PATH);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(READ_WRITE_DIRECTORY_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));

            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, 0, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));

            writeGuestString(memory, pathAddress, "missing.txt");
            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, pathAddress, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOENT, state.register(10));

            writeGuestString(memory, pathAddress, "../message.txt");
            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, pathAddress, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));
        }
    }

    /// Verifies that `statfs` and `fstatfs` return deterministic sandbox filesystem metadata.
    @Test
    public void statfsReportsDeterministicFilesystemMetadata() throws Exception {
        Files.createDirectories(tempDirectory.resolve("directory"));
        Files.writeString(tempDirectory.resolve("directory").resolve("message.txt"), "file-data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long statfsAddress = memory.baseAddress() + 256;
            long pipeAddress = memory.baseAddress() + 512;

            writeGuestString(memory, pathAddress, "directory/message.txt");
            setSyscall(state, SYS_STATFS, pathAddress, statfsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatfs(memory, statfsAddress);

            writeGuestString(memory, pathAddress, "missing.txt");
            setSyscall(state, SYS_STATFS, pathAddress, statfsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOENT, state.register(10));

            writeGuestString(memory, pathAddress, "../escape");
            setSyscall(state, SYS_STATFS, pathAddress, statfsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            writeGuestString(memory, pathAddress, "directory");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            int directoryFileDescriptor = (int) state.register(10);
            assertEquals(3, directoryFileDescriptor);

            setSyscall(state, SYS_FSTATFS, directoryFileDescriptor, statfsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatfs(memory, statfsAddress);

            setSyscall(state, SYS_FCHDIR, directoryFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, ".");
            setSyscall(state, SYS_STATFS, pathAddress, statfsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatfs(memory, statfsAddress);

            writeGuestString(memory, pathAddress, "message.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int fileDescriptor = (int) state.register(10);
            assertEquals(4, fileDescriptor);

            setSyscall(state, SYS_FSTATFS, fileDescriptor, statfsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatfs(memory, statfsAddress);

            setSyscall(state, SYS_PIPE2, pipeAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            int readFileDescriptor = memory.readInt(pipeAddress);
            assertEquals(5, readFileDescriptor);

            setSyscall(state, SYS_FSTATFS, readFileDescriptor, statfsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatfs(memory, statfsAddress);

            setSyscall(state, SYS_FSTATFS, 99, statfsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
        }
    }

    /// Verifies that `statx` reports sandboxed host files, descriptors, and deterministic metadata.
    @Test
    public void statxReportsSandboxedHostMetadata() throws Exception {
        Files.createDirectories(tempDirectory.resolve("directory"));
        Files.writeString(tempDirectory.resolve("directory").resolve("message.txt"), "file-data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long statxAddress = memory.baseAddress() + 512;
            long pipeAddress = memory.baseAddress() + 1024;

            writeGuestString(memory, pathAddress, "directory/message.txt");
            setSyscall(
                    state,
                    SYS_STATX,
                    AT_FDCWD,
                    pathAddress,
                    AT_NO_AUTOMOUNT | AT_STATX_DONT_SYNC,
                    STATX_BASIC_STATS_MASK,
                    statxAddress,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatx(memory, statxAddress, READ_WRITE_REGULAR_FILE_STAT_MODE, 9);

            writeGuestString(memory, pathAddress, "directory");
            setSyscall(state, SYS_STATX, AT_FDCWD, pathAddress, 0, STATX_BASIC_STATS_MASK, statxAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatx(memory, statxAddress, READ_WRITE_DIRECTORY_STAT_MODE, 0);

            writeGuestString(memory, pathAddress, "");
            setSyscall(
                    state,
                    SYS_STATX,
                    AT_FDCWD,
                    pathAddress,
                    AT_EMPTY_PATH | AT_STATX_FORCE_SYNC,
                    STATX_BASIC_STATS_MASK,
                    statxAddress,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatx(memory, statxAddress, READ_WRITE_DIRECTORY_STAT_MODE, 0);

            setSyscall(
                    state,
                    SYS_STATX,
                    AT_FDCWD,
                    0,
                    AT_EMPTY_PATH,
                    STATX_BASIC_STATS_MASK,
                    statxAddress,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatx(memory, statxAddress, READ_WRITE_DIRECTORY_STAT_MODE, 0);

            setSyscall(state, SYS_STATX, AT_FDCWD, 0, 0, STATX_BASIC_STATS_MASK, statxAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));

            setSyscall(state, SYS_STATX, 1, pathAddress, AT_EMPTY_PATH, STATX_BASIC_STATS_MASK, statxAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatx(memory, statxAddress, STANDARD_STREAM_STAT_MODE, 0);

            setSyscall(state, SYS_STATX, AT_FDCWD, pathAddress, 0, STATX_BASIC_STATS_MASK, statxAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOENT, state.register(10));

            writeGuestString(memory, pathAddress, "directory");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            int directoryFileDescriptor = (int) state.register(10);
            assertEquals(3, directoryFileDescriptor);

            writeGuestString(memory, pathAddress, "");
            setSyscall(
                    state,
                    SYS_STATX,
                    directoryFileDescriptor,
                    pathAddress,
                    AT_EMPTY_PATH,
                    STATX_BASIC_STATS_MASK,
                    statxAddress,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatx(memory, statxAddress, READ_WRITE_DIRECTORY_STAT_MODE, 0);

            writeGuestString(memory, pathAddress, "message.txt");
            setSyscall(state, SYS_OPENAT, directoryFileDescriptor, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int fileDescriptor = (int) state.register(10);
            assertEquals(4, fileDescriptor);

            writeGuestString(memory, pathAddress, "");
            setSyscall(
                    state,
                    SYS_STATX,
                    fileDescriptor,
                    pathAddress,
                    AT_EMPTY_PATH,
                    STATX_BASIC_STATS_MASK,
                    statxAddress,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatx(memory, statxAddress, READ_WRITE_REGULAR_FILE_STAT_MODE, 9);

            setSyscall(
                    state,
                    SYS_STATX,
                    fileDescriptor,
                    0,
                    AT_EMPTY_PATH,
                    STATX_BASIC_STATS_MASK,
                    statxAddress,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatx(memory, statxAddress, READ_WRITE_REGULAR_FILE_STAT_MODE, 9);

            setSyscall(state, SYS_PIPE2, pipeAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            int readFileDescriptor = memory.readInt(pipeAddress);
            assertEquals(5, readFileDescriptor);

            setSyscall(
                    state,
                    SYS_STATX,
                    readFileDescriptor,
                    pathAddress,
                    AT_EMPTY_PATH,
                    STATX_BASIC_STATS_MASK,
                    statxAddress,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatx(memory, statxAddress, PIPE_STAT_MODE, 0);

            writeGuestString(memory, pathAddress, "missing.txt");
            setSyscall(state, SYS_STATX, AT_FDCWD, pathAddress, 0, STATX_BASIC_STATS_MASK, statxAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOENT, state.register(10));

            writeGuestString(memory, pathAddress, "../escape");
            setSyscall(state, SYS_STATX, AT_FDCWD, pathAddress, 0, STATX_BASIC_STATS_MASK, statxAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            writeGuestString(memory, pathAddress, "directory/message.txt");
            setSyscall(state, SYS_STATX, AT_FDCWD, pathAddress, 0x4000_0000L, STATX_BASIC_STATS_MASK, statxAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            writeGuestString(memory, pathAddress, "message.txt");
            setSyscall(state, SYS_STATX, 99, pathAddress, 0, STATX_BASIC_STATS_MASK, statxAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
        }
    }

    /// Verifies that `statx` can report symbolic links without following them when the host supports links.
    @Test
    public void statxReportsSandboxedSymlinkMetadata() throws Exception {
        try {
            Files.createSymbolicLink(tempDirectory.resolve("link.txt"), Path.of("target.txt"));
        } catch (IOException | UnsupportedOperationException exception) {
            assumeTrue(false, "Host filesystem does not allow symbolic link creation");
        }

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long statxAddress = memory.baseAddress() + 512;

            writeGuestString(memory, pathAddress, "link.txt");
            setSyscall(
                    state,
                    SYS_STATX,
                    AT_FDCWD,
                    pathAddress,
                    AT_SYMLINK_NOFOLLOW,
                    STATX_BASIC_STATS_MASK,
                    statxAddress,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatx(memory, statxAddress, SYMBOLIC_LINK_STAT_MODE, "target.txt".length());
        }
    }

    /// Verifies access checks for sandboxed paths and open file descriptors.
    @Test
    public void faccessatChecksSandboxedPaths() throws Exception {
        Files.writeString(tempDirectory.resolve("readable.txt"), "data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            writeGuestString(memory, pathAddress, "readable.txt");

            setSyscall(state, SYS_FACCESSAT, AT_FDCWD, pathAddress, F_OK, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FACCESSAT2, AT_FDCWD, pathAddress, R_OK, AT_EACCESS, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "missing.txt");
            setSyscall(state, SYS_FACCESSAT, AT_FDCWD, pathAddress, F_OK, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOENT, state.register(10));

            writeGuestString(memory, pathAddress, "../readable.txt");
            setSyscall(state, SYS_FACCESSAT2, AT_FDCWD, pathAddress, F_OK, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            setSyscall(state, SYS_FACCESSAT2, AT_FDCWD, pathAddress, R_OK | 8, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies extended-attribute queries report an empty attribute set.
    @Test
    public void xattrQueriesReportEmptyAttributeSet() throws Exception {
        Files.writeString(tempDirectory.resolve("readable.txt"), "data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long nameAddress = memory.baseAddress() + 128;
            long bufferAddress = memory.baseAddress() + 256;

            writeGuestString(memory, pathAddress, "readable.txt");
            writeGuestString(memory, nameAddress, "system.posix_acl_access");
            setSyscall(state, SYS_LISTXATTR, pathAddress, bufferAddress, 16);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETXATTR, pathAddress, nameAddress, bufferAddress, 16);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENODATA, state.register(10));

            setSyscall(state, SYS_FLISTXATTR, -1, bufferAddress, 16);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));

            writeGuestString(memory, pathAddress, "missing.txt");
            setSyscall(state, SYS_LISTXATTR, pathAddress, bufferAddress, 16);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOENT, state.register(10));
        }
    }

    /// Verifies `faccessat2` access checks on `AT_EMPTY_PATH` file descriptors.
    @Test
    public void faccessat2ChecksEmptyPathFileDescriptors() throws Exception {
        Files.writeString(tempDirectory.resolve("output.txt"), "data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            writeGuestString(memory, pathAddress, "output.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_WRONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            long fileDescriptor = state.register(10);
            assertEquals(3, fileDescriptor);

            writeGuestString(memory, pathAddress, "");
            setSyscall(state, SYS_FACCESSAT2, fileDescriptor, pathAddress, W_OK, AT_EMPTY_PATH, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FACCESSAT2, fileDescriptor, pathAddress, R_OK, AT_EMPTY_PATH, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FACCESSAT2, fileDescriptor, pathAddress, X_OK, AT_EMPTY_PATH, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));
        }
    }

    /// Verifies that `fchownat` validates paths and applies synthetic ownership metadata.
    @Test
    public void fchownatUpdatesSandboxedPathMetadata() throws Exception {
        Files.writeString(tempDirectory.resolve("owned.txt"), "data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();

            writeGuestString(memory, pathAddress, "owned.txt");
            setSyscall(state, SYS_FCHOWNAT, AT_FDCWD, pathAddress, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EPERM, state.register(10));

            setSyscall(state, SYS_FCHOWNAT, AT_FDCWD, pathAddress, -1, -1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "missing.txt");
            setSyscall(state, SYS_FCHOWNAT, AT_FDCWD, pathAddress, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOENT, state.register(10));

            writeGuestString(memory, pathAddress, "../owned.txt");
            setSyscall(state, SYS_FCHOWNAT, AT_FDCWD, pathAddress, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            writeGuestString(memory, pathAddress, "owned.txt");
            setSyscall(state, SYS_FCHOWNAT, AT_FDCWD, pathAddress, GuestCredentials.MAX_ID + 1, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_FCHOWNAT, AT_FDCWD, pathAddress, 0, 0, AT_EACCESS);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_FCHOWNAT, AT_FDCWD, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));
        }

        GuestCredentials root = GuestCredentials.of("root", 0, 0, "", "/root", "/bin/sh");
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    GuestFileSystem.forHostRoot(tempDirectory),
                    root);
            long pathAddress = memory.baseAddress();
            long statAddress = memory.baseAddress() + 256;

            writeGuestString(memory, pathAddress, "owned.txt");
            setSyscall(state, SYS_FCHOWNAT, AT_FDCWD, pathAddress, 1234, 5678, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, pathAddress, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(1234, Integer.toUnsignedLong(memory.readInt(statAddress + STAT_UID_OFFSET)));
            assertEquals(5678, Integer.toUnsignedLong(memory.readInt(statAddress + STAT_GID_OFFSET)));
        }
    }

    /// Verifies that `fchown` and `fchownat` support file descriptor updates.
    @Test
    public void fchownUpdatesFileDescriptorMetadata() throws Exception {
        Files.writeString(tempDirectory.resolve("owned.txt"), "data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();

            writeGuestString(memory, pathAddress, "owned.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            long fileDescriptor = state.register(10);
            assertEquals(3, fileDescriptor);

            writeGuestString(memory, pathAddress, "");
            setSyscall(state, SYS_FCHOWNAT, fileDescriptor, pathAddress, 0, 0, AT_EMPTY_PATH);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EPERM, state.register(10));

            setSyscall(state, SYS_FCHOWNAT, 99, pathAddress, 0, 0, AT_EMPTY_PATH);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));

            setSyscall(state, SYS_FCHOWNAT, fileDescriptor, pathAddress, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOENT, state.register(10));
        }

        GuestCredentials root = GuestCredentials.of("root", 0, 0, "", "/root", "/bin/sh");
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    GuestFileSystem.forHostRoot(tempDirectory),
                    root);
            long pathAddress = memory.baseAddress();
            long statAddress = memory.baseAddress() + 256;

            writeGuestString(memory, pathAddress, "owned.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            long fileDescriptor = state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_FCHOWN, fileDescriptor, 2000, 3000);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FSTAT, fileDescriptor, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(2000, Integer.toUnsignedLong(memory.readInt(statAddress + STAT_UID_OFFSET)));
            assertEquals(3000, Integer.toUnsignedLong(memory.readInt(statAddress + STAT_GID_OFFSET)));
        }
    }

    /// Verifies that `fchmod`, `fchmodat`, and `fchmodat2` update host metadata and access checks.
    @Test
    public void fchmodUpdatesHostMetadataAndAccessChecks() throws Exception {
        Files.writeString(tempDirectory.resolve("mode.txt"), "data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long statAddress = memory.baseAddress() + 256;

            writeGuestString(memory, pathAddress, "mode.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDWR, 0);
            state.syscalls().handle(state, TEST_PC);
            long fileDescriptor = state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_FCHMOD, fileDescriptor, 0600, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FSTAT, fileDescriptor, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0100000 | 0600, memory.readInt(statAddress + STAT_MODE_OFFSET));

            writeGuestString(memory, pathAddress, "");
            setSyscall(state, SYS_FACCESSAT2, fileDescriptor, pathAddress, R_OK | W_OK, AT_EMPTY_PATH, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FACCESSAT2, fileDescriptor, pathAddress, X_OK, AT_EMPTY_PATH, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            writeGuestString(memory, pathAddress, "mode.txt");
            setSyscall(state, SYS_FCHMODAT, AT_FDCWD, pathAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            writeGuestString(memory, pathAddress, "");
            setSyscall(state, SYS_FCHMODAT2, fileDescriptor, pathAddress, 0644, AT_EMPTY_PATH);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "mode.txt");
            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, pathAddress, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(CREATED_REGULAR_FILE_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));

            setSyscall(state, SYS_FCHMODAT2, AT_FDCWD, pathAddress, 0600, AT_EACCESS);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_FCHMOD, 99, 0600, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
        }
    }

    /// Verifies that host child path access requires search permission on the parent directory.
    @Test
    public void hostPathAccessRequiresParentSearchPermission() throws Exception {
        Files.createDirectories(tempDirectory.resolve("private").resolve("nested"));
        Files.writeString(tempDirectory.resolve("private").resolve("nested").resolve("child.txt"), "child", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();

            writeGuestString(memory, pathAddress, "private");
            setSyscall(state, SYS_FCHMODAT, AT_FDCWD, pathAddress, 0600, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "private/nested/child.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            setSyscall(state, SYS_FACCESSAT2, AT_FDCWD, pathAddress, R_OK, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            writeGuestString(memory, pathAddress, "private");
            setSyscall(state, SYS_FCHMODAT, AT_FDCWD, pathAddress, 0700, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "private/nested/child.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(3, state.register(10));
        }
    }

    /// Verifies that tar uid, gid, and mode metadata drive DAC access checks.
    @Test
    public void tarPermissionsUseOwnerGroupAndOtherBits() throws Exception {
        Path archive = tempDirectory.resolve("permissions.tar");
        try (OutputStream output = Files.newOutputStream(archive);
             TarArchiveOutputStream tarOutput = new TarArchiveOutputStream(output)) {
            writeTarFile(tarOutput, "owner.txt", "owner".getBytes(StandardCharsets.UTF_8), 0600, 1234, 9999);
            writeTarFile(tarOutput, "group.txt", "group".getBytes(StandardCharsets.UTF_8), 0040, 2000, 42);
            writeTarFile(tarOutput, "other.txt", "other".getBytes(StandardCharsets.UTF_8), 0004, 2000, 7777);
            writeTarFile(tarOutput, "blocked.txt", "blocked".getBytes(StandardCharsets.UTF_8), 0000, 2000, 7777);
            writeTarDirectory(tarOutput, "private", 0600, 1234, 5678);
            writeTarDirectory(tarOutput, "private/nested", 0700, 1234, 5678);
            writeTarFile(tarOutput, "private/nested/child.txt", "child".getBytes(StandardCharsets.UTF_8), 0600, 1234, 5678);
            tarOutput.finish();
        }

        GuestCredentials credentials = GuestCredentials.of("alice", 1234, 5678, "42,43", "/home/alice", "/bin/bash");
        GuestFileSystem fileSystem = GuestFileSystem.forMountSpecs(new String[]{
                "type=tar,src=" + archive + ",dst=/tar"
        });
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    fileSystem,
                    credentials);
            long pathAddress = memory.baseAddress();
            long statAddress = memory.baseAddress() + 256;

            writeGuestString(memory, pathAddress, "/tar/owner.txt");
            setSyscall(state, SYS_FACCESSAT2, AT_FDCWD, pathAddress, R_OK, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, pathAddress, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0100000 | 0600, memory.readInt(statAddress + STAT_MODE_OFFSET));
            assertEquals(1234, Integer.toUnsignedLong(memory.readInt(statAddress + STAT_UID_OFFSET)));
            assertEquals(9999, Integer.toUnsignedLong(memory.readInt(statAddress + STAT_GID_OFFSET)));

            writeGuestString(memory, pathAddress, "/tar/group.txt");
            setSyscall(state, SYS_FACCESSAT2, AT_FDCWD, pathAddress, R_OK, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "/tar/other.txt");
            setSyscall(state, SYS_FACCESSAT2, AT_FDCWD, pathAddress, R_OK, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "/tar/blocked.txt");
            setSyscall(state, SYS_FACCESSAT2, AT_FDCWD, pathAddress, R_OK, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            writeGuestString(memory, pathAddress, "/tar/private/nested/child.txt");
            setSyscall(state, SYS_FACCESSAT2, AT_FDCWD, pathAddress, R_OK, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));
        }
    }

    /// Verifies that writable memory tar mounts support chmod while read-only tar mounts reject it.
    @Test
    public void fchmodatUpdatesWritableTarMetadata() throws Exception {
        Path archive = tempDirectory.resolve("chmod.tar");
        try (OutputStream output = Files.newOutputStream(archive);
             TarArchiveOutputStream tarOutput = new TarArchiveOutputStream(output)) {
            writeTarFile(tarOutput, "owned.txt", "owned".getBytes(StandardCharsets.UTF_8), 0600, 1234, 5678);
            writeTarFile(tarOutput, "other.txt", "other".getBytes(StandardCharsets.UTF_8), 0600, 2000, 5678);
            tarOutput.finish();
        }

        GuestCredentials credentials = GuestCredentials.of("alice", 1234, 5678, "42,43", "/home/alice", "/bin/bash");
        GuestFileSystem fileSystem = GuestFileSystem.forMountSpecs(new String[]{
                "type=tar,src=" + archive + ",dst=/tar,memory,rw",
                "type=tar,src=" + archive + ",dst=/ro,memory"
        });
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    fileSystem,
                    credentials);
            long pathAddress = memory.baseAddress();
            long statAddress = memory.baseAddress() + 256;

            writeGuestString(memory, pathAddress, "/tar/owned.txt");
            setSyscall(state, SYS_FCHMODAT, AT_FDCWD, pathAddress, 0644, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, pathAddress, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(CREATED_REGULAR_FILE_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));

            writeGuestString(memory, pathAddress, "/tar/other.txt");
            setSyscall(state, SYS_FCHMODAT, AT_FDCWD, pathAddress, 0644, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EPERM, state.register(10));

            writeGuestString(memory, pathAddress, "/ro/owned.txt");
            setSyscall(state, SYS_FCHMODAT, AT_FDCWD, pathAddress, 0644, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EROFS, state.register(10));
        }
    }

    /// Verifies `utimensat` updates host timestamps and accepts writable tmpfs timestamps.
    @Test
    public void utimensatUpdatesHostAndTmpfsTimestamps() throws Exception {
        Path hostFile = tempDirectory.resolve("timestamp.txt");
        Files.writeString(hostFile, "timestamp", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long timesAddress = memory.baseAddress() + 256;

            writeGuestString(memory, pathAddress, "/timestamp.txt");
            writeTimespec(memory, timesAddress, 0, UTIME_OMIT);
            writeTimespec(memory, timesAddress + 2L * Long.BYTES, 1_700_000_123L, 456_789_000L);
            setSyscall(state, SYS_UTIMENSAT, AT_FDCWD, pathAddress, timesAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            Instant modified = Files.getLastModifiedTime(hostFile).toInstant();
            assertEquals(1_700_000_123L, modified.getEpochSecond());

            writeTimespec(memory, timesAddress + 2L * Long.BYTES, 1_700_000_123L, 1_000_000_000L);
            setSyscall(state, SYS_UTIMENSAT, AT_FDCWD, pathAddress, timesAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }

        GuestFileSystem fileSystem = GuestFileSystem.forMountSpecs(new String[]{
                "type=tmpfs,dst=/tmp",
                "type=tmpfs,dst=/ro,readonly"
        });
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    fileSystem);
            long pathAddress = memory.baseAddress();

            writeGuestString(memory, pathAddress, "/tmp");
            setSyscall(state, SYS_UTIMENSAT, AT_FDCWD, pathAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "/ro");
            setSyscall(state, SYS_UTIMENSAT, AT_FDCWD, pathAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EROFS, state.register(10));
        }
    }

    /// Verifies forked child processes inherit writable memory tar changes made before `clone`.
    @Test
    public void cloneInheritsWritableMemoryTarChanges() throws Exception {
        Path archive = tempDirectory.resolve("clone-memory.tar");
        try (OutputStream output = Files.newOutputStream(archive);
             TarArchiveOutputStream tarOutput = new TarArchiveOutputStream(output)) {
            tarOutput.finish();
        }

        CompletableFuture<String> childRead = new CompletableFuture<>();
        GuestThreadRunner runner = (childMemory, childState) -> {
            try {
                long childPathAddress = childMemory.baseAddress();
                long childBufferAddress = childMemory.baseAddress() + 256;

                writeGuestString(childMemory, childPathAddress, "/tar/A.txt");
                setSyscall(childState, SYS_OPENAT, AT_FDCWD, childPathAddress, O_RDONLY, 0);
                childState.syscalls().handle(childState, TEST_PC);
                long childFileDescriptor = childState.register(10);
                if (childFileDescriptor < 0) {
                    throw new AssertionError("Child open failed: " + childFileDescriptor);
                }

                setSyscall(childState, SYS_READ, childFileDescriptor, childBufferAddress, 8);
                childState.syscalls().handle(childState, TEST_PC);
                long readCount = childState.register(10);
                if (readCount < 0) {
                    throw new AssertionError("Child read failed: " + readCount);
                }

                setSyscall(childState, SYS_CLOSE, childFileDescriptor, 0, 0);
                childState.syscalls().handle(childState, TEST_PC);
                if (childState.register(10) != 0) {
                    throw new AssertionError("Child close failed: " + childState.register(10));
                }

                childRead.complete(readGuestString(childMemory, childBufferAddress, (int) readCount));
                childState.syscalls().recordThreadExit(childState, 0);
            } catch (Throwable throwable) {
                childRead.completeExceptionally(throwable);
                childState.syscalls().recordThreadFailure(throwable);
            }
        };

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            GuestSyscalls syscalls = new LinuxGuestSyscalls(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    new String[]{"type=tar,src=" + archive + ",dst=/tar,memory,rw"},
                    TimeSource.system(),
                    runner);
            RiscVThreadState state = new RiscVThreadState(
                    memory,
                    0,
                    false,
                    ElfImage.ABSENT_ADDRESS,
                    ElfImage.ABSENT_ADDRESS,
                    syscalls);
            long pathAddress = memory.baseAddress();
            long dataAddress = memory.baseAddress() + 256;
            long statusAddress = memory.baseAddress() + 512;
            byte[] data = "A\n".getBytes(StandardCharsets.UTF_8);

            writeGuestString(memory, pathAddress, "/tar/A.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            state.syscalls().handle(state, TEST_PC);
            long fileDescriptor = state.register(10);
            assertEquals(3, fileDescriptor);

            memory.writeBytes(dataAddress, data, 0, data.length);
            setSyscall(state, SYS_WRITE, fileDescriptor, dataAddress, data.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(data.length, state.register(10));

            setSyscall(state, SYS_CLOSE, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_CLONE, SIGCHLD, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            long childProcessId = state.register(10);
            assertTrue(childProcessId > 0);

            assertEquals("A\n", childRead.get(5, TimeUnit.SECONDS));

            setSyscall(state, SYS_WAIT4, childProcessId, statusAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(childProcessId, state.register(10));
            assertEquals(0, memory.readInt(statusAddress));
        }
    }

    /// Verifies tmpfs mounts expose empty writable in-memory directories without host sources.
    @Test
    public void tmpfsMountSupportsGuestWrites() throws Exception {
        GuestFileSystem fileSystem = GuestFileSystem.forMountSpecs(new String[]{
                "type=tmpfs,dst=/tmp"
        });
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    fileSystem);
            long pathAddress = memory.baseAddress();
            long dataAddress = memory.baseAddress() + 256;
            long statAddress = memory.baseAddress() + 512;
            long statfsAddress = memory.baseAddress() + 1024;
            byte[] data = "tmpfs-data".getBytes(StandardCharsets.UTF_8);

            writeGuestString(memory, pathAddress, "/tmp");
            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, pathAddress, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0040000 | 01777, memory.readInt(statAddress + STAT_MODE_OFFSET));

            writeGuestString(memory, pathAddress, "/tmp/message.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            state.syscalls().handle(state, TEST_PC);
            long writeFileDescriptor = state.register(10);
            assertEquals(3, writeFileDescriptor);

            memory.writeBytes(dataAddress, data, 0, data.length);
            setSyscall(state, SYS_WRITE, writeFileDescriptor, dataAddress, data.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(data.length, state.register(10));

            setSyscall(state, SYS_CLOSE, writeFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            long readFileDescriptor = state.register(10);
            assertEquals(3, readFileDescriptor);

            setSyscall(state, SYS_READ, readFileDescriptor, dataAddress, data.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(data.length, state.register(10));
            assertEquals("tmpfs-data", readGuestString(memory, dataAddress, data.length));

            writeGuestString(memory, pathAddress, "/tmp");
            setSyscall(state, SYS_STATFS, pathAddress, statfsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatfs(memory, statfsAddress);

            setSyscall(state, SYS_FSTATFS, readFileDescriptor, statfsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertStatfs(memory, statfsAddress);
        }
    }

    /// Verifies that `umask` masks host file and directory creation modes.
    @Test
    public void umaskMasksHostCreatedEntryModes() throws Exception {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long statAddress = memory.baseAddress() + 256;

            setSyscall(state, SYS_UMASK, 0027, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "masked");
            setSyscall(state, SYS_MKDIRAT, AT_FDCWD, pathAddress, 0777);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, pathAddress, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0040000 | 0750, memory.readInt(statAddress + STAT_MODE_OFFSET));

            writeGuestString(memory, pathAddress, "masked/file.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            state.syscalls().handle(state, TEST_PC);
            long fileDescriptor = state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_FSTAT, fileDescriptor, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0100000 | 0640, memory.readInt(statAddress + STAT_MODE_OFFSET));

            setSyscall(state, SYS_UMASK, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0027, state.register(10));
        }
    }

    /// Verifies that `umask` masks writable tar file and directory creation modes.
    @Test
    public void umaskMasksTarCreatedEntryModes() throws Exception {
        Path archive = tempDirectory.resolve("umask.tar");
        try (OutputStream output = Files.newOutputStream(archive);
             TarArchiveOutputStream tarOutput = new TarArchiveOutputStream(output)) {
            tarOutput.finish();
        }

        GuestFileSystem fileSystem = GuestFileSystem.forMountSpecs(new String[]{
                "type=tar,src=" + archive + ",dst=/tar,memory,rw"
        });
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    fileSystem);
            long pathAddress = memory.baseAddress();
            long statAddress = memory.baseAddress() + 256;

            setSyscall(state, SYS_UMASK, 0077, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "/tar/private");
            setSyscall(state, SYS_MKDIRAT, AT_FDCWD, pathAddress, 0777);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, pathAddress, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0040000 | 0700, memory.readInt(statAddress + STAT_MODE_OFFSET));

            writeGuestString(memory, pathAddress, "/tar/private/file.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            state.syscalls().handle(state, TEST_PC);
            long fileDescriptor = state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_FSTAT, fileDescriptor, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0100000 | 0600, memory.readInt(statAddress + STAT_MODE_OFFSET));

            setSyscall(state, SYS_UMASK, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0077, state.register(10));
        }
    }

    /// Verifies that host setgid directories supply inherited groups to created children.
    @Test
    public void hostSetgidDirectoryControlsCreatedEntryGroups() throws Exception {
        GuestCredentials root = GuestCredentials.of("root", 0, 0, "", "/root", "/bin/sh");

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    GuestFileSystem.forHostRoot(tempDirectory),
                    root);
            long pathAddress = memory.baseAddress();
            long statAddress = memory.baseAddress() + 256;

            writeGuestString(memory, pathAddress, "setgid");
            setSyscall(state, SYS_MKDIRAT, AT_FDCWD, pathAddress, 0770);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FCHOWNAT, AT_FDCWD, pathAddress, 0, 4242, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FCHMODAT, AT_FDCWD, pathAddress, 02770, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "setgid/file.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_WRONLY | O_CREAT | O_TRUNC, 0660);
            state.syscalls().handle(state, TEST_PC);
            long fileDescriptor = state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_FSTAT, fileDescriptor, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0100000 | 0660, memory.readInt(statAddress + STAT_MODE_OFFSET));
            assertEquals(0, Integer.toUnsignedLong(memory.readInt(statAddress + STAT_UID_OFFSET)));
            assertEquals(4242, Integer.toUnsignedLong(memory.readInt(statAddress + STAT_GID_OFFSET)));

            writeGuestString(memory, pathAddress, "setgid/child");
            setSyscall(state, SYS_MKDIRAT, AT_FDCWD, pathAddress, 0770);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, pathAddress, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0040000 | 02770, memory.readInt(statAddress + STAT_MODE_OFFSET));
            assertEquals(0, Integer.toUnsignedLong(memory.readInt(statAddress + STAT_UID_OFFSET)));
            assertEquals(4242, Integer.toUnsignedLong(memory.readInt(statAddress + STAT_GID_OFFSET)));
        }
    }

    /// Verifies that tar setgid directories supply inherited groups to created children.
    @Test
    public void tarSetgidDirectoryControlsCreatedEntryGroups() throws Exception {
        Path archive = tempDirectory.resolve("setgid.tar");
        try (OutputStream output = Files.newOutputStream(archive);
             TarArchiveOutputStream tarOutput = new TarArchiveOutputStream(output)) {
            writeTarDirectory(tarOutput, "setgid", 02770, 1234, 4242);
            tarOutput.finish();
        }

        GuestCredentials credentials = GuestCredentials.of("alice", 1234, 5678, "", "/home/alice", "/bin/bash");
        GuestFileSystem fileSystem = GuestFileSystem.forMountSpecs(new String[]{
                "type=tar,src=" + archive + ",dst=/tar,memory,rw"
        });
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    fileSystem,
                    credentials);
            long pathAddress = memory.baseAddress();
            long statAddress = memory.baseAddress() + 256;

            writeGuestString(memory, pathAddress, "/tar/setgid/file.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_WRONLY | O_CREAT | O_TRUNC, 0660);
            state.syscalls().handle(state, TEST_PC);
            long fileDescriptor = state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_FSTAT, fileDescriptor, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0100000 | 0660, memory.readInt(statAddress + STAT_MODE_OFFSET));
            assertEquals(1234, Integer.toUnsignedLong(memory.readInt(statAddress + STAT_UID_OFFSET)));
            assertEquals(4242, Integer.toUnsignedLong(memory.readInt(statAddress + STAT_GID_OFFSET)));

            writeGuestString(memory, pathAddress, "/tar/setgid/child");
            setSyscall(state, SYS_MKDIRAT, AT_FDCWD, pathAddress, 0770);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_NEWFSTATAT, AT_FDCWD, pathAddress, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0040000 | 02770, memory.readInt(statAddress + STAT_MODE_OFFSET));
            assertEquals(1234, Integer.toUnsignedLong(memory.readInt(statAddress + STAT_UID_OFFSET)));
            assertEquals(4242, Integer.toUnsignedLong(memory.readInt(statAddress + STAT_GID_OFFSET)));
        }
    }

    /// Verifies that sticky tar directories restrict deleting and replacing entries owned by other users.
    @Test
    public void tarStickyDirectoryRestrictsEntryMutation() throws Exception {
        Path archive = tempDirectory.resolve("sticky.tar");
        try (OutputStream output = Files.newOutputStream(archive);
             TarArchiveOutputStream tarOutput = new TarArchiveOutputStream(output)) {
            writeTarDirectory(tarOutput, "sticky", 01777, 3000, 3000);
            writeTarFile(tarOutput, "sticky/owned.txt", "owned".getBytes(StandardCharsets.UTF_8), 0600, 1234, 5678);
            writeTarFile(tarOutput, "sticky/other.txt", "other".getBytes(StandardCharsets.UTF_8), 0600, 2000, 5678);
            writeTarFile(tarOutput, "sticky/source.txt", "source".getBytes(StandardCharsets.UTF_8), 0600, 1234, 5678);
            writeTarFile(tarOutput, "sticky/target.txt", "target".getBytes(StandardCharsets.UTF_8), 0600, 2000, 5678);
            writeTarFile(tarOutput, "sticky/rename.txt", "rename".getBytes(StandardCharsets.UTF_8), 0600, 1234, 5678);
            tarOutput.finish();
        }

        GuestCredentials credentials = GuestCredentials.of("alice", 1234, 5678, "", "/home/alice", "/bin/bash");
        GuestFileSystem fileSystem = GuestFileSystem.forMountSpecs(new String[]{
                "type=tar,src=" + archive + ",dst=/tar,memory,rw"
        });
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    fileSystem,
                    credentials);
            long oldPathAddress = memory.baseAddress();
            long newPathAddress = memory.baseAddress() + 256;

            writeGuestString(memory, oldPathAddress, "/tar/sticky/owned.txt");
            setSyscall(state, SYS_UNLINKAT, AT_FDCWD, oldPathAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, oldPathAddress, "/tar/sticky/other.txt");
            setSyscall(state, SYS_UNLINKAT, AT_FDCWD, oldPathAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EPERM, state.register(10));

            writeGuestString(memory, oldPathAddress, "/tar/sticky/source.txt");
            writeGuestString(memory, newPathAddress, "/tar/sticky/target.txt");
            setSyscall(state, SYS_RENAMEAT, AT_FDCWD, oldPathAddress, AT_FDCWD, newPathAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EPERM, state.register(10));

            writeGuestString(memory, oldPathAddress, "/tar/sticky/rename.txt");
            writeGuestString(memory, newPathAddress, "/tar/sticky/moved.txt");
            setSyscall(state, SYS_RENAMEAT, AT_FDCWD, oldPathAddress, AT_FDCWD, newPathAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FACCESSAT2, AT_FDCWD, newPathAddress, F_OK, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
        }

        GuestCredentials root = GuestCredentials.of("root", 0, 0, "", "/root", "/bin/sh");
        GuestFileSystem rootFileSystem = GuestFileSystem.forMountSpecs(new String[]{
                "type=tar,src=" + archive + ",dst=/tar,memory,rw"
        });
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    rootFileSystem,
                    root);
            long pathAddress = memory.baseAddress();

            writeGuestString(memory, pathAddress, "/tar/sticky/other.txt");
            setSyscall(state, SYS_UNLINKAT, AT_FDCWD, pathAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
        }
    }

    /// Verifies that `readlinkat` reads sandboxed symbolic link targets when the host supports them.
    @Test
    public void readlinkatReadsSandboxedSymlinkTargets() throws Exception {
        Files.writeString(tempDirectory.resolve("target.txt"), "target", StandardCharsets.UTF_8);
        try {
            Files.createSymbolicLink(tempDirectory.resolve("link.txt"), Path.of("target.txt"));
        } catch (IOException | SecurityException | UnsupportedOperationException exception) {
            assumeTrue(false, "Host filesystem does not allow symbolic link creation");
        }

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 256;
            writeGuestString(memory, pathAddress, "link.txt");

            setSyscall(state, SYS_READLINKAT, AT_FDCWD, pathAddress, bufferAddress, 64);
            state.syscalls().handle(state, TEST_PC);

            assertEquals("target.txt".length(), state.register(10));
            assertArrayEquals("target.txt".getBytes(StandardCharsets.UTF_8),
                    memory.readBytes(bufferAddress, "target.txt".length()));

            writeGuestString(memory, pathAddress, "target.txt");
            setSyscall(state, SYS_READLINKAT, AT_FDCWD, pathAddress, bufferAddress, 64);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies that `openat` exposes read-only host files below the configured root mount.
    @Test
    public void openatReadsHostFileBelowRoot() throws Exception {
        Files.writeString(tempDirectory.resolve("message.txt"), "file-data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 128;
            long statAddress = memory.baseAddress() + 256;
            writeGuestString(memory, pathAddress, "/message.txt");

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_CLOEXEC, 0);
            state.syscalls().handle(state, TEST_PC);
            int fileDescriptor = (int) state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_READ, fileDescriptor, bufferAddress, 4);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4, state.register(10));
            assertArrayEquals("file".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 4));

            setSyscall(state, SYS_LSEEK, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_READ, fileDescriptor, bufferAddress, 9);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(9, state.register(10));
            assertArrayEquals("file-data".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 9));

            setSyscall(state, SYS_FSTAT, fileDescriptor, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(READ_WRITE_REGULAR_FILE_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));
            assertEquals(1, memory.readInt(statAddress + STAT_LINK_COUNT_OFFSET));
            assertEquals(9, memory.readLong(statAddress + STAT_SIZE_OFFSET));
            assertEquals(4096, memory.readInt(statAddress + STAT_BLOCK_SIZE_OFFSET));

            setSyscall(state, SYS_CLOSE, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_READ, fileDescriptor, bufferAddress, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
        }
    }

    /// Verifies that `openat` supports read-only directory descriptors for relative paths.
    @Test
    public void openatSupportsDirectoryFileDescriptors() throws Exception {
        Files.createDirectories(tempDirectory.resolve("subdir"));
        Files.writeString(tempDirectory.resolve("subdir").resolve("message.txt"), "directory-data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long directoryPathAddress = memory.baseAddress();
            long filePathAddress = memory.baseAddress() + 64;
            long bufferAddress = memory.baseAddress() + 128;
            long statAddress = memory.baseAddress() + 256;

            writeGuestString(memory, directoryPathAddress, "subdir");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, directoryPathAddress, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
            state.syscalls().handle(state, TEST_PC);
            int directoryFileDescriptor = (int) state.register(10);
            assertEquals(3, directoryFileDescriptor);

            setSyscall(state, SYS_FCNTL, directoryFileDescriptor, F_GETFL, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(O_RDONLY | O_DIRECTORY, state.register(10));

            setSyscall(state, SYS_FSTAT, directoryFileDescriptor, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(READ_WRITE_DIRECTORY_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));

            setSyscall(state, SYS_READ, directoryFileDescriptor, bufferAddress, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EISDIR, state.register(10));

            writeGuestString(memory, filePathAddress, "message.txt");
            setSyscall(state, SYS_OPENAT, directoryFileDescriptor, filePathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int fileDescriptor = (int) state.register(10);
            assertEquals(4, fileDescriptor);

            setSyscall(state, SYS_READ, fileDescriptor, bufferAddress, 14);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(14, state.register(10));
            assertArrayEquals("directory-data".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 14));

            setSyscall(state, SYS_NEWFSTATAT, directoryFileDescriptor, filePathAddress, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(READ_WRITE_REGULAR_FILE_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));

            setSyscall(state, SYS_FACCESSAT2, directoryFileDescriptor, filePathAddress, R_OK, AT_EACCESS, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, filePathAddress, "../../outside.txt");
            setSyscall(state, SYS_OPENAT, directoryFileDescriptor, filePathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            writeGuestString(memory, filePathAddress, "subdir/message.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, filePathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOTDIR, state.register(10));
        }
    }

    /// Verifies that `linkat` and `symlinkat` create sandboxed host links with readable metadata and targets.
    @Test
    public void linkSyscallsCreateSandboxedHostLinks() throws Exception {
        Files.writeString(tempDirectory.resolve("target.txt"), "link-data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long targetPathAddress = memory.baseAddress();
            long hardLinkPathAddress = memory.baseAddress() + 128;
            long symbolicTargetAddress = memory.baseAddress() + 256;
            long symbolicLinkPathAddress = memory.baseAddress() + 384;
            long bufferAddress = memory.baseAddress() + 512;
            long statAddress = memory.baseAddress() + 768;
            writeGuestString(memory, targetPathAddress, "/target.txt");
            writeGuestString(memory, hardLinkPathAddress, "/hard-link.txt");
            writeGuestString(memory, symbolicTargetAddress, "target.txt");
            writeGuestString(memory, symbolicLinkPathAddress, "/symbolic-link.txt");

            setSyscall(
                    state,
                    SYS_LINKAT,
                    AT_FDCWD,
                    targetPathAddress,
                    AT_FDCWD,
                    hardLinkPathAddress,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertTrue(Files.isSameFile(tempDirectory.resolve("target.txt"), tempDirectory.resolve("hard-link.txt")));

            setSyscall(state, SYS_SYMLINKAT, symbolicTargetAddress, AT_FDCWD, symbolicLinkPathAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertTrue(Files.isSymbolicLink(tempDirectory.resolve("symbolic-link.txt")));

            setSyscall(state, SYS_READLINKAT, AT_FDCWD, symbolicLinkPathAddress, bufferAddress, 64);
            state.syscalls().handle(state, TEST_PC);
            assertEquals("target.txt".length(), state.register(10));
            assertArrayEquals(
                    "target.txt".getBytes(StandardCharsets.UTF_8),
                    memory.readBytes(bufferAddress, "target.txt".length()));

            setSyscall(
                    state,
                    SYS_NEWFSTATAT,
                    AT_FDCWD,
                    symbolicLinkPathAddress,
                    statAddress,
                    AT_SYMLINK_NOFOLLOW);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(SYMBOLIC_LINK_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));

            setSyscall(
                    state,
                    SYS_LINKAT,
                    AT_FDCWD,
                    targetPathAddress,
                    AT_FDCWD,
                    hardLinkPathAddress,
                    AT_REMOVEDIR);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies that `getdents64` reads deterministic directory records from directory descriptors.
    @Test
    public void getdents64ReadsDirectoryEntries() throws Exception {
        Files.createDirectories(tempDirectory.resolve("subdir").resolve("nested"));
        Files.writeString(tempDirectory.resolve("subdir").resolve("message.txt"), "directory-data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 128;
            writeGuestString(memory, pathAddress, "subdir");

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            int directoryFileDescriptor = (int) state.register(10);
            assertEquals(3, directoryFileDescriptor);

            setSyscall(state, SYS_GETDENTS64, directoryFileDescriptor, bufferAddress, 512);
            state.syscalls().handle(state, TEST_PC);
            long bytesRead = state.register(10);
            assertTrue(bytesRead > 0);

            long cursor = bufferAddress;
            cursor = assertDirectoryEntry(memory, cursor, ".", DIRECTORY_ENTRY_DIRECTORY, 1);
            cursor = assertDirectoryEntry(memory, cursor, "..", DIRECTORY_ENTRY_DIRECTORY, 2);
            cursor = assertDirectoryEntry(memory, cursor, "message.txt", DIRECTORY_ENTRY_REGULAR_FILE, 3);
            cursor = assertDirectoryEntry(memory, cursor, "nested", DIRECTORY_ENTRY_DIRECTORY, 4);
            assertEquals(bufferAddress + bytesRead, cursor);

            setSyscall(state, SYS_GETDENTS64, directoryFileDescriptor, bufferAddress, 512);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "subdir/message.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int fileDescriptor = (int) state.register(10);
            assertEquals(4, fileDescriptor);

            setSyscall(state, SYS_GETDENTS64, fileDescriptor, bufferAddress, 512);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOTDIR, state.register(10));

            writeGuestString(memory, pathAddress, "subdir");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            int smallBufferDirectoryFileDescriptor = (int) state.register(10);
            assertEquals(5, smallBufferDirectoryFileDescriptor);

            setSyscall(state, SYS_GETDENTS64, smallBufferDirectoryFileDescriptor, bufferAddress, 8);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            writeGuestString(memory, pathAddress, "subdir");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            int partialDirectoryFileDescriptor = (int) state.register(10);
            assertEquals(6, partialDirectoryFileDescriptor);

            setSyscall(state, SYS_GETDENTS64, partialDirectoryFileDescriptor, bufferAddress, 48);
            state.syscalls().handle(state, TEST_PC);
            bytesRead = state.register(10);
            assertEquals(48, bytesRead);
            cursor = bufferAddress;
            cursor = assertDirectoryEntry(memory, cursor, ".", DIRECTORY_ENTRY_DIRECTORY, 1);
            cursor = assertDirectoryEntry(memory, cursor, "..", DIRECTORY_ENTRY_DIRECTORY, 2);
            assertEquals(bufferAddress + bytesRead, cursor);

            setSyscall(state, SYS_GETDENTS64, partialDirectoryFileDescriptor, bufferAddress, 512);
            state.syscalls().handle(state, TEST_PC);
            bytesRead = state.register(10);
            assertTrue(bytesRead > 0);
            cursor = bufferAddress;
            cursor = assertDirectoryEntry(memory, cursor, "message.txt", DIRECTORY_ENTRY_REGULAR_FILE, 3);
            cursor = assertDirectoryEntry(memory, cursor, "nested", DIRECTORY_ENTRY_DIRECTORY, 4);
            assertEquals(bufferAddress + bytesRead, cursor);
        }
    }

    /// Verifies that `dup` shares host file offsets and keeps the file open until every descriptor is closed.
    @Test
    public void dupSharesHostFileOffsetAndLifetime() throws Exception {
        Files.writeString(tempDirectory.resolve("message.txt"), "file-data", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 128;
            writeGuestString(memory, pathAddress, "message.txt");

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int fileDescriptor = (int) state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_DUP, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            int duplicateFileDescriptor = (int) state.register(10);
            assertEquals(4, duplicateFileDescriptor);

            setSyscall(state, SYS_READ, fileDescriptor, bufferAddress, 4);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4, state.register(10));
            assertArrayEquals("file".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 4));

            setSyscall(state, SYS_READ, duplicateFileDescriptor, bufferAddress, 5);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(5, state.register(10));
            assertArrayEquals("-data".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 5));

            setSyscall(state, SYS_CLOSE, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_LSEEK, duplicateFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_READ, duplicateFileDescriptor, bufferAddress, 9);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(9, state.register(10));
            assertArrayEquals("file-data".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 9));
        }
    }

    /// Verifies that `dup` can duplicate standard streams.
    @Test
    public void dupDuplicatesStandardStreams() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream("input".getBytes(StandardCharsets.UTF_8)),
                    out,
                    new ByteArrayOutputStream(),
                    memory.baseAddress());
            long bufferAddress = memory.baseAddress();

            setSyscall(state, SYS_DUP, 1, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            int duplicateOutput = (int) state.register(10);
            assertEquals(3, duplicateOutput);

            memory.writeBytes(bufferAddress, "Hi".getBytes(StandardCharsets.UTF_8), 0, 2);
            setSyscall(state, SYS_WRITE, duplicateOutput, bufferAddress, 2);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));
            assertEquals("Hi", out.toString(StandardCharsets.UTF_8));

            setSyscall(state, SYS_DUP, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            int duplicateInput = (int) state.register(10);
            assertEquals(4, duplicateInput);

            setSyscall(state, SYS_READ, duplicateInput, bufferAddress, 5);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(5, state.register(10));
            assertArrayEquals("input".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 5));
        }
    }

    /// Verifies explicit `dup3` replacement and flag validation.
    @Test
    public void dup3ReplacesTargetDescriptor() throws Exception {
        Files.writeString(tempDirectory.resolve("first.txt"), "first", StandardCharsets.UTF_8);
        Files.writeString(tempDirectory.resolve("second.txt"), "second", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 128;

            writeGuestString(memory, pathAddress, "first.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int firstFileDescriptor = (int) state.register(10);
            assertEquals(3, firstFileDescriptor);

            writeGuestString(memory, pathAddress, "second.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int secondFileDescriptor = (int) state.register(10);
            assertEquals(4, secondFileDescriptor);

            setSyscall(state, SYS_DUP3, firstFileDescriptor, secondFileDescriptor, O_CLOEXEC);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(secondFileDescriptor, state.register(10));

            setSyscall(state, SYS_CLOSE, firstFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_READ, secondFileDescriptor, bufferAddress, 5);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(5, state.register(10));
            assertArrayEquals("first".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 5));

            setSyscall(state, SYS_DUP3, secondFileDescriptor, secondFileDescriptor, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_DUP3, secondFileDescriptor, 5, O_NONBLOCK);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_DUP3, 9, 5, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
        }
    }

    /// Verifies in-memory `pipe2` descriptors for static single-process programs.
    @Test
    public void pipe2TransfersBytesBetweenDescriptors() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long pipeAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 32;
            long statAddress = memory.baseAddress() + 128;

            setSyscall(state, SYS_PIPE2, pipeAddress, O_NONBLOCK | O_CLOEXEC, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            int readFileDescriptor = memory.readInt(pipeAddress);
            int writeFileDescriptor = memory.readInt(pipeAddress + Integer.BYTES);
            assertEquals(3, readFileDescriptor);
            assertEquals(4, writeFileDescriptor);

            setSyscall(state, SYS_FCNTL, readFileDescriptor, F_GETFD, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(FD_CLOEXEC, state.register(10));

            setSyscall(state, SYS_FCNTL, writeFileDescriptor, F_GETFD, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(FD_CLOEXEC, state.register(10));

            setSyscall(state, SYS_READ, readFileDescriptor, bufferAddress, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAGAIN, state.register(10));

            setSyscall(state, SYS_FCNTL, readFileDescriptor, F_GETFL, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(O_RDONLY | O_NONBLOCK, state.register(10));

            setSyscall(state, SYS_FSTAT, readFileDescriptor, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(PIPE_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));

            memory.writeBytes(bufferAddress, "pipe".getBytes(StandardCharsets.UTF_8), 0, 4);
            setSyscall(state, SYS_WRITE, writeFileDescriptor, bufferAddress, 4);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4, state.register(10));

            setSyscall(state, SYS_READ, readFileDescriptor, bufferAddress, 4);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4, state.register(10));
            assertArrayEquals("pipe".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 4));

            setSyscall(state, SYS_CLOSE_RANGE, writeFileDescriptor, writeFileDescriptor, CLOSE_RANGE_CLOEXEC);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FCNTL, writeFileDescriptor, F_GETFD, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(FD_CLOEXEC, state.register(10));

            setSyscall(state, SYS_CLOSE_RANGE, writeFileDescriptor, writeFileDescriptor, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_READ, readFileDescriptor, bufferAddress, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_CLOSE_RANGE, readFileDescriptor, -1L, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FCNTL, readFileDescriptor, F_GETFD, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));

            setSyscall(state, SYS_PIPE2, pipeAddress, O_APPEND, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies that `dup3` can redirect standard descriptors to pipe endpoints.
    @Test
    public void dup3CanReplaceStandardDescriptors() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream("host".getBytes(StandardCharsets.UTF_8)),
                    out,
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pipeAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 32;

            setSyscall(state, SYS_PIPE2, pipeAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            int readFileDescriptor = memory.readInt(pipeAddress);
            int writeFileDescriptor = memory.readInt(pipeAddress + Integer.BYTES);

            setSyscall(state, SYS_DUP3, writeFileDescriptor, 1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            memory.writeBytes(bufferAddress, "abc".getBytes(StandardCharsets.UTF_8), 0, 3);
            setSyscall(state, SYS_WRITE, 1, bufferAddress, 3);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(3, state.register(10));
            assertEquals("", out.toString(StandardCharsets.UTF_8));

            setSyscall(state, SYS_READ, readFileDescriptor, bufferAddress, 3);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(3, state.register(10));
            assertArrayEquals("abc".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 3));

            setSyscall(state, SYS_DUP, 1, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            int duplicateOutput = (int) state.register(10);
            assertEquals(5, duplicateOutput);

            memory.writeBytes(bufferAddress, "def".getBytes(StandardCharsets.UTF_8), 0, 3);
            setSyscall(state, SYS_WRITE, duplicateOutput, bufferAddress, 3);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(3, state.register(10));

            setSyscall(state, SYS_READ, readFileDescriptor, bufferAddress, 3);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(3, state.register(10));
            assertArrayEquals("def".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 3));

            memory.writeBytes(bufferAddress, "xy".getBytes(StandardCharsets.UTF_8), 0, 2);
            setSyscall(state, SYS_WRITE, writeFileDescriptor, bufferAddress, 2);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));

            setSyscall(state, SYS_DUP3, readFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_READ, 0, bufferAddress, 2);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));
            assertArrayEquals("xy".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 2));
        }
    }

    /// Verifies that standard descriptor redirects can target other standard descriptors.
    @Test
    public void dup3CanReplaceStandardOutputWithStandardError() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    out,
                    err,
                    memory.baseAddress(),
                    tempDirectory);
            long bufferAddress = memory.baseAddress();

            setSyscall(state, SYS_DUP3, 2, 1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            memory.writeBytes(bufferAddress, "err".getBytes(StandardCharsets.UTF_8), 0, 3);
            setSyscall(state, SYS_WRITE, 1, bufferAddress, 3);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(3, state.register(10));
            assertEquals("", out.toString(StandardCharsets.UTF_8));
            assertEquals("err", err.toString(StandardCharsets.UTF_8));

            setSyscall(state, SYS_DUP, 1, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            int duplicateOutput = (int) state.register(10);
            assertEquals(3, duplicateOutput);

            memory.writeBytes(bufferAddress, "dup".getBytes(StandardCharsets.UTF_8), 0, 3);
            setSyscall(state, SYS_WRITE, duplicateOutput, bufferAddress, 3);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(3, state.register(10));
            assertEquals("", out.toString(StandardCharsets.UTF_8));
            assertEquals("errdup", err.toString(StandardCharsets.UTF_8));
        }
    }

    /// Verifies in-memory `eventfd2` counters and basic zero-timeout `epoll` readiness.
    @Test
    public void eventfd2AndEpollReportReadiness() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 2048)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long bufferAddress = memory.baseAddress();
            long eventAddress = memory.baseAddress() + 128;
            long eventsAddress = memory.baseAddress() + 256;
            long signalSetAddress = memory.baseAddress() + 512;
            long oldSignalSetAddress = memory.baseAddress() + 520;
            long userSignalMask = signalMask(SIGUSR1);

            setSyscall(state, SYS_EVENTFD2, 0, O_NONBLOCK | O_CLOEXEC, 0);
            state.syscalls().handle(state, TEST_PC);
            int eventFileDescriptor = (int) state.register(10);
            assertEquals(3, eventFileDescriptor);

            setSyscall(state, SYS_READ, eventFileDescriptor, bufferAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAGAIN, state.register(10));

            setSyscall(state, SYS_FCNTL, eventFileDescriptor, F_GETFL, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(O_RDWR | O_NONBLOCK, state.register(10));

            setSyscall(state, SYS_EVENTFD2, 0, O_APPEND, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            memory.writeLong(bufferAddress, 3);
            setSyscall(state, SYS_WRITE, eventFileDescriptor, bufferAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(Long.BYTES, state.register(10));

            setSyscall(state, SYS_READ, eventFileDescriptor, bufferAddress, Integer.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_READ, eventFileDescriptor, bufferAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(Long.BYTES, state.register(10));
            assertEquals(3, memory.readLong(bufferAddress));

            setSyscall(state, SYS_EVENTFD2, 2, EFD_SEMAPHORE | O_NONBLOCK, 0);
            state.syscalls().handle(state, TEST_PC);
            int semaphoreFileDescriptor = (int) state.register(10);
            assertEquals(4, semaphoreFileDescriptor);

            setSyscall(state, SYS_READ, semaphoreFileDescriptor, bufferAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(Long.BYTES, state.register(10));
            assertEquals(1, memory.readLong(bufferAddress));

            setSyscall(state, SYS_READ, semaphoreFileDescriptor, bufferAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(Long.BYTES, state.register(10));
            assertEquals(1, memory.readLong(bufferAddress));

            setSyscall(state, SYS_READ, semaphoreFileDescriptor, bufferAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAGAIN, state.register(10));

            setSyscall(state, SYS_EPOLL_CREATE1, O_CLOEXEC, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            int epollFileDescriptor = (int) state.register(10);
            assertEquals(5, epollFileDescriptor);

            setSyscall(state, SYS_EPOLL_CREATE1, O_NONBLOCK, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            writeEpollEvent(memory, eventAddress, EPOLLIN, 0x1122_3344_5566_7788L);
            setSyscall(state, SYS_EPOLL_CTL, epollFileDescriptor, EPOLL_CTL_ADD, eventFileDescriptor, eventAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_EPOLL_CTL, epollFileDescriptor, EPOLL_CTL_ADD, eventFileDescriptor, eventAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EEXIST, state.register(10));

            setSyscall(state, SYS_EPOLL_PWAIT, epollFileDescriptor, eventsAddress, 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.writeLong(signalSetAddress, userSignalMask);
            setSyscall(state, SYS_RT_SIGPROCMASK, SIG_SETMASK, signalSetAddress, 0, KERNEL_SIGSET_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.writeLong(signalSetAddress, 0);
            setSyscall(
                    state,
                    SYS_EPOLL_PWAIT,
                    epollFileDescriptor,
                    eventsAddress,
                    1,
                    0,
                    signalSetAddress,
                    KERNEL_SIGSET_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.writeLong(oldSignalSetAddress, -1);
            setSyscall(state, SYS_RT_SIGPROCMASK, SIG_BLOCK, 0, oldSignalSetAddress, KERNEL_SIGSET_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(userSignalMask, memory.readLong(oldSignalSetAddress));

            setSyscall(
                    state,
                    SYS_EPOLL_PWAIT,
                    epollFileDescriptor,
                    eventsAddress,
                    1,
                    0,
                    signalSetAddress,
                    KERNEL_SIGSET_SIZE - 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            memory.writeLong(bufferAddress, 5);
            setSyscall(state, SYS_WRITE, eventFileDescriptor, bufferAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(Long.BYTES, state.register(10));

            setSyscall(state, SYS_EPOLL_PWAIT, epollFileDescriptor, eventsAddress, 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));
            assertEquals(EPOLLIN, memory.readInt(eventsAddress + EPOLL_EVENT_EVENTS_OFFSET));
            assertEquals(0x1122_3344_5566_7788L, readEpollEventData(memory, eventsAddress));

            setSyscall(state, SYS_READ, eventFileDescriptor, bufferAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(Long.BYTES, state.register(10));
            assertEquals(5, memory.readLong(bufferAddress));

            setSyscall(state, SYS_EPOLL_PWAIT, epollFileDescriptor, eventsAddress, 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeEpollEvent(memory, eventAddress, EPOLLOUT, 0x55);
            setSyscall(state, SYS_EPOLL_CTL, epollFileDescriptor, EPOLL_CTL_MOD, eventFileDescriptor, eventAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_EPOLL_PWAIT, epollFileDescriptor, eventsAddress, 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));
            assertEquals(EPOLLOUT, memory.readInt(eventsAddress + EPOLL_EVENT_EVENTS_OFFSET));
            assertEquals(0x55, readEpollEventData(memory, eventsAddress));

            setSyscall(state, SYS_EPOLL_CTL, epollFileDescriptor, EPOLL_CTL_DEL, eventFileDescriptor, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_EPOLL_CTL, epollFileDescriptor, EPOLL_CTL_DEL, eventFileDescriptor, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOENT, state.register(10));

            setSyscall(state, SYS_EPOLL_CTL, epollFileDescriptor, EPOLL_CTL_ADD, 99, eventAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
        }
    }

    /// Verifies `timerfd` creation, arming, querying, reading, and validation behavior.
    @Test
    public void timerfdCreateSettimeGettimeAndRead() throws Exception {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long timerAddress = memory.baseAddress();
            long currentAddress = memory.baseAddress() + 128;
            long oldAddress = memory.baseAddress() + 256;
            long bufferAddress = memory.baseAddress() + 384;

            setSyscall(state, SYS_TIMERFD_CREATE, CLOCK_MONOTONIC, O_NONBLOCK | O_CLOEXEC, 0);
            state.syscalls().handle(state, TEST_PC);
            int timerFileDescriptor = (int) state.register(10);
            assertEquals(3, timerFileDescriptor);

            setSyscall(state, SYS_FCNTL, timerFileDescriptor, F_GETFD, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(FD_CLOEXEC, state.register(10));

            setSyscall(state, SYS_FCNTL, timerFileDescriptor, F_GETFL, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(O_RDWR | O_NONBLOCK, state.register(10));

            setSyscall(state, SYS_READ, timerFileDescriptor, bufferAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAGAIN, state.register(10));

            setSyscall(state, SYS_TIMERFD_CREATE, CLOCK_THREAD_CPUTIME_ID, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_TIMERFD_CREATE, CLOCK_MONOTONIC, O_APPEND, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            writeItimerspec(memory, timerAddress, 0, 0, 1, 0);
            setSyscall(state, SYS_TIMERFD_SETTIME, timerFileDescriptor, 0, timerAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_TIMERFD_GETTIME, timerFileDescriptor, currentAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readLong(currentAddress + ITIMERSPEC_INTERVAL_OFFSET));
            assertEquals(0, memory.readLong(currentAddress + ITIMERSPEC_INTERVAL_OFFSET + Long.BYTES));
            long currentValueSeconds = memory.readLong(currentAddress + ITIMERSPEC_VALUE_OFFSET);
            long currentValueNanoseconds = memory.readLong(currentAddress + ITIMERSPEC_VALUE_OFFSET + Long.BYTES);
            assertTrue(currentValueSeconds >= 0 && currentValueSeconds <= 1);
            assertTrue(currentValueSeconds > 0 || currentValueNanoseconds > 0);

            writeItimerspec(memory, timerAddress, 0, 0, 0, 20_000_000);
            setSyscall(state, SYS_TIMERFD_SETTIME, timerFileDescriptor, 0, timerAddress, oldAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            long oldValueSeconds = memory.readLong(oldAddress + ITIMERSPEC_VALUE_OFFSET);
            long oldValueNanoseconds = memory.readLong(oldAddress + ITIMERSPEC_VALUE_OFFSET + Long.BYTES);
            assertTrue(oldValueSeconds >= 0 && oldValueSeconds <= 1);
            assertTrue(oldValueSeconds > 0 || oldValueNanoseconds > 0);

            writeItimerspec(memory, timerAddress, 0, 1_000_000_000L, 0, 1);
            setSyscall(state, SYS_TIMERFD_SETTIME, timerFileDescriptor, 0, timerAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            for (int attempt = 0; attempt < 100; attempt++) {
                setSyscall(state, SYS_READ, timerFileDescriptor, bufferAddress, Long.BYTES);
                state.syscalls().handle(state, TEST_PC);
                if (state.register(10) == Long.BYTES) {
                    break;
                }
                assertEquals(EAGAIN, state.register(10));
                Thread.sleep(10);
            }
            assertEquals(Long.BYTES, state.register(10));
            assertTrue(memory.readLong(bufferAddress) >= 1);

            setSyscall(state, SYS_READ, timerFileDescriptor, bufferAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAGAIN, state.register(10));

            memory.writeLong(bufferAddress, 1);
            setSyscall(state, SYS_WRITE, timerFileDescriptor, bufferAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies periodic `timerfd` expirations and `epoll` readiness.
    @Test
    public void timerfdPeriodicTimersAccumulateExpirationsAndEpollReady() throws Exception {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long timerAddress = memory.baseAddress();
            long eventAddress = memory.baseAddress() + 128;
            long eventsAddress = memory.baseAddress() + 256;
            long currentAddress = memory.baseAddress() + 384;
            long bufferAddress = memory.baseAddress() + 512;
            long fileDescriptorSetAddress = memory.baseAddress() + 640;

            setSyscall(state, SYS_TIMERFD_CREATE, CLOCK_MONOTONIC, O_NONBLOCK, 0);
            state.syscalls().handle(state, TEST_PC);
            int timerFileDescriptor = (int) state.register(10);
            assertEquals(3, timerFileDescriptor);

            setSyscall(state, SYS_EPOLL_CREATE1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            int epollFileDescriptor = (int) state.register(10);
            assertEquals(4, epollFileDescriptor);

            writeEpollEvent(memory, eventAddress, EPOLLIN, 0x88);
            setSyscall(state, SYS_EPOLL_CTL, epollFileDescriptor, EPOLL_CTL_ADD, timerFileDescriptor, eventAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_EPOLL_PWAIT, epollFileDescriptor, eventsAddress, 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeItimerspec(memory, timerAddress, 0, 5_000_000, 0, 5_000_000);
            setSyscall(state, SYS_TIMERFD_SETTIME, timerFileDescriptor, 0, timerAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            waitForEpollReady(state, epollFileDescriptor, eventsAddress);
            assertEquals(EPOLLIN, memory.readInt(eventsAddress + EPOLL_EVENT_EVENTS_OFFSET));
            assertEquals(0x88, readEpollEventData(memory, eventsAddress));
            waitForPselectReadReady(state, memory, fileDescriptorSetAddress, timerFileDescriptor);

            Thread.sleep(50);
            setSyscall(state, SYS_READ, timerFileDescriptor, bufferAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(Long.BYTES, state.register(10));
            assertTrue(memory.readLong(bufferAddress) >= 2);

            setSyscall(state, SYS_TIMERFD_GETTIME, timerFileDescriptor, currentAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readLong(currentAddress + ITIMERSPEC_INTERVAL_OFFSET));
            assertEquals(5_000_000, memory.readLong(currentAddress + ITIMERSPEC_INTERVAL_OFFSET + Long.BYTES));
            long remainingSeconds = memory.readLong(currentAddress + ITIMERSPEC_VALUE_OFFSET);
            long remainingNanoseconds = memory.readLong(currentAddress + ITIMERSPEC_VALUE_OFFSET + Long.BYTES);
            assertEquals(0, remainingSeconds);
            assertTrue(remainingNanoseconds >= 0 && remainingNanoseconds <= 5_000_000);
        }
    }

    /// Verifies blocking `eventfd2` reads and writes wait for counter transitions.
    @Test
    public void eventfd2SupportsBlockingReadAndWrite() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            RiscVThreadState readState = new RiscVThreadState(
                    memory,
                    0,
                    false,
                    ElfImage.ABSENT_ADDRESS,
                    ElfImage.ABSENT_ADDRESS,
                    state.syscalls());
            RiscVThreadState writeState = new RiscVThreadState(
                    memory,
                    0,
                    false,
                    ElfImage.ABSENT_ADDRESS,
                    ElfImage.ABSENT_ADDRESS,
                    state.syscalls());
            long incrementAddress = memory.baseAddress();
            long readValueAddress = memory.baseAddress() + 64;
            long blockedIncrementAddress = memory.baseAddress() + 128;

            setSyscall(state, SYS_EVENTFD2, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            int eventFileDescriptor = (int) state.register(10);
            assertEquals(3, eventFileDescriptor);

            Future<Long> readResult = executor.submit(() -> {
                setSyscall(readState, SYS_READ, eventFileDescriptor, readValueAddress, Long.BYTES);
                readState.syscalls().handle(readState, TEST_PC);
                return readState.register(10);
            });

            Thread.sleep(50);
            assertTrue(!readResult.isDone());

            memory.writeLong(incrementAddress, 12);
            setSyscall(state, SYS_WRITE, eventFileDescriptor, incrementAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(Long.BYTES, state.register(10));
            assertEquals(Long.BYTES, readResult.get(5, TimeUnit.SECONDS));
            assertEquals(12, memory.readLong(readValueAddress));

            memory.writeLong(incrementAddress, -2L);
            setSyscall(state, SYS_WRITE, eventFileDescriptor, incrementAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(Long.BYTES, state.register(10));

            memory.writeLong(blockedIncrementAddress, 1);
            Future<Long> writeResult = executor.submit(() -> {
                setSyscall(writeState, SYS_WRITE, eventFileDescriptor, blockedIncrementAddress, Long.BYTES);
                writeState.syscalls().handle(writeState, TEST_PC);
                return writeState.register(10);
            });

            Thread.sleep(50);
            assertTrue(!writeResult.isDone());

            setSyscall(state, SYS_READ, eventFileDescriptor, readValueAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(Long.BYTES, state.register(10));
            assertEquals(-2L, memory.readLong(readValueAddress));
            assertEquals(Long.BYTES, writeResult.get(5, TimeUnit.SECONDS));

            setSyscall(state, SYS_READ, eventFileDescriptor, readValueAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(Long.BYTES, state.register(10));
            assertEquals(1, memory.readLong(readValueAddress));
        } finally {
            executor.shutdownNow();
        }
    }

    /// Verifies `epoll_pwait` waits for guest-internal descriptor readiness changes.
    @Test
    public void epollPwaitWaitsForEventfdReadiness() throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            RiscVThreadState pollState = new RiscVThreadState(
                    memory,
                    0,
                    false,
                    ElfImage.ABSENT_ADDRESS,
                    ElfImage.ABSENT_ADDRESS,
                    state.syscalls());
            long bufferAddress = memory.baseAddress();
            long eventAddress = memory.baseAddress() + 128;
            long eventsAddress = memory.baseAddress() + 256;

            setSyscall(state, SYS_EVENTFD2, 0, O_NONBLOCK, 0);
            state.syscalls().handle(state, TEST_PC);
            int eventFileDescriptor = (int) state.register(10);
            assertEquals(3, eventFileDescriptor);

            setSyscall(state, SYS_EPOLL_CREATE1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            int epollFileDescriptor = (int) state.register(10);
            assertEquals(4, epollFileDescriptor);

            writeEpollEvent(memory, eventAddress, EPOLLIN, 0x66);
            setSyscall(state, SYS_EPOLL_CTL, epollFileDescriptor, EPOLL_CTL_ADD, eventFileDescriptor, eventAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_EPOLL_PWAIT, epollFileDescriptor, memory.endAddress(), 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));

            Future<Long> pollResult = executor.submit(() -> {
                setSyscall(pollState, SYS_EPOLL_PWAIT, epollFileDescriptor, eventsAddress, 1, -1, 0, 0);
                pollState.syscalls().handle(pollState, TEST_PC);
                return pollState.register(10);
            });

            Thread.sleep(50);
            assertTrue(!pollResult.isDone());

            memory.writeLong(bufferAddress, 9);
            setSyscall(state, SYS_WRITE, eventFileDescriptor, bufferAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(Long.BYTES, state.register(10));

            assertEquals(1, pollResult.get(5, TimeUnit.SECONDS));
            assertEquals(EPOLLIN, memory.readInt(eventsAddress + EPOLL_EVENT_EVENTS_OFFSET));
            assertEquals(0x66, readEpollEventData(memory, eventsAddress));
        } finally {
            executor.shutdownNow();
        }
    }

    /// Verifies `epoll_pwait2` uses Linux `timespec` timeout semantics.
    @Test
    public void epollPwait2UsesTimespecTimeout() throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            RiscVThreadState pollState = new RiscVThreadState(
                    memory,
                    0,
                    false,
                    ElfImage.ABSENT_ADDRESS,
                    ElfImage.ABSENT_ADDRESS,
                    state.syscalls());
            long bufferAddress = memory.baseAddress();
            long eventAddress = memory.baseAddress() + 128;
            long eventsAddress = memory.baseAddress() + 256;
            long timeoutAddress = memory.baseAddress() + 512;

            setSyscall(state, SYS_EVENTFD2, 0, O_NONBLOCK, 0);
            state.syscalls().handle(state, TEST_PC);
            int eventFileDescriptor = (int) state.register(10);
            assertEquals(3, eventFileDescriptor);

            setSyscall(state, SYS_EPOLL_CREATE1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            int epollFileDescriptor = (int) state.register(10);
            assertEquals(4, epollFileDescriptor);

            writeEpollEvent(memory, eventAddress, EPOLLIN, 0x77);
            setSyscall(state, SYS_EPOLL_CTL, epollFileDescriptor, EPOLL_CTL_ADD, eventFileDescriptor, eventAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.writeLong(timeoutAddress, 0);
            memory.writeLong(timeoutAddress + Long.BYTES, 0);
            setSyscall(state, SYS_EPOLL_PWAIT2, epollFileDescriptor, eventsAddress, 1, timeoutAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.writeLong(timeoutAddress + Long.BYTES, 1_000_000_000L);
            setSyscall(state, SYS_EPOLL_PWAIT2, epollFileDescriptor, eventsAddress, 1, timeoutAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            memory.writeLong(timeoutAddress, 5);
            memory.writeLong(timeoutAddress + Long.BYTES, 0);
            Future<Long> pollResult = executor.submit(() -> {
                setSyscall(pollState, SYS_EPOLL_PWAIT2, epollFileDescriptor, eventsAddress, 1, timeoutAddress, 0, 0);
                pollState.syscalls().handle(pollState, TEST_PC);
                return pollState.register(10);
            });

            Thread.sleep(50);
            assertTrue(!pollResult.isDone());

            memory.writeLong(bufferAddress, 11);
            setSyscall(state, SYS_WRITE, eventFileDescriptor, bufferAddress, Long.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(Long.BYTES, state.register(10));

            assertEquals(1, pollResult.get(5, TimeUnit.SECONDS));
            assertEquals(EPOLLIN, memory.readInt(eventsAddress + EPOLL_EVENT_EVENTS_OFFSET));
            assertEquals(0x77, readEpollEventData(memory, eventsAddress));
        } finally {
            executor.shutdownNow();
        }
    }

    /// Verifies deterministic `pselect6` readiness for descriptor sets.
    @Test
    public void pselect6ReportsDescriptorReadiness() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long readFileDescriptorsAddress = memory.baseAddress() + 64;
            long writeFileDescriptorsAddress = memory.baseAddress() + 256;
            long exceptionFileDescriptorsAddress = memory.baseAddress() + 448;
            long timeoutAddress = memory.baseAddress() + 640;
            long signalArgumentAddress = memory.baseAddress() + 704;
            long signalSetAddress = memory.baseAddress() + 768;

            memory.writeLong(timeoutAddress, 0);
            memory.writeLong(timeoutAddress + Long.BYTES, 0);
            setFdSetBit(memory, readFileDescriptorsAddress, 0);
            setFdSetBit(memory, readFileDescriptorsAddress, 1);
            setFdSetBit(memory, writeFileDescriptorsAddress, 0);
            setFdSetBit(memory, writeFileDescriptorsAddress, 1);
            setFdSetBit(memory, exceptionFileDescriptorsAddress, 0);

            setSyscall(
                    state,
                    SYS_PSELECT6,
                    2,
                    readFileDescriptorsAddress,
                    writeFileDescriptorsAddress,
                    exceptionFileDescriptorsAddress,
                    timeoutAddress,
                    0);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(2, state.register(10));
            assertTrue(isFdSetBitSet(memory, readFileDescriptorsAddress, 0));
            assertTrue(!isFdSetBitSet(memory, readFileDescriptorsAddress, 1));
            assertTrue(!isFdSetBitSet(memory, writeFileDescriptorsAddress, 0));
            assertTrue(isFdSetBitSet(memory, writeFileDescriptorsAddress, 1));
            assertTrue(!isFdSetBitSet(memory, exceptionFileDescriptorsAddress, 0));

            memory.clear(readFileDescriptorsAddress, TEST_FD_SET_SIZE);
            setFdSetBit(memory, readFileDescriptorsAddress, 99);
            setSyscall(state, SYS_PSELECT6, 100, readFileDescriptorsAddress, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));

            memory.writeLong(timeoutAddress + Long.BYTES, 1_000_000_000L);
            setSyscall(state, SYS_PSELECT6, 0, 0, 0, 0, timeoutAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            memory.writeLong(signalSetAddress, signalMask(SIGUSR1));
            memory.writeLong(signalArgumentAddress + PSELECT6_SIGNAL_MASK_ADDRESS_OFFSET, signalSetAddress);
            memory.writeLong(signalArgumentAddress + PSELECT6_SIGNAL_SET_SIZE_OFFSET, KERNEL_SIGSET_SIZE - 1);
            setSyscall(state, SYS_PSELECT6, 0, 0, 0, 0, 0, signalArgumentAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_PSELECT6, 1, memory.endAddress(), 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));
        }
    }

    /// Verifies `pselect6` waits for guest-internal descriptor readiness changes.
    @Test
    public void pselect6WaitsForPipeReadiness() throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            RiscVThreadState pollState = new RiscVThreadState(
                    memory,
                    0,
                    false,
                    ElfImage.ABSENT_ADDRESS,
                    ElfImage.ABSENT_ADDRESS,
                    state.syscalls());
            long pipeAddress = memory.baseAddress() + 64;
            long readFileDescriptorsAddress = memory.baseAddress() + 128;
            long dataAddress = memory.baseAddress() + 512;

            setSyscall(state, SYS_PIPE2, pipeAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            int readFileDescriptor = memory.readInt(pipeAddress);
            int writeFileDescriptor = memory.readInt(pipeAddress + Integer.BYTES);

            Future<Long> pollResult = executor.submit(() -> {
                setFdSetBit(memory, readFileDescriptorsAddress, readFileDescriptor);
                setSyscall(pollState, SYS_PSELECT6, readFileDescriptor + 1L, readFileDescriptorsAddress, 0, 0, 0, 0);
                pollState.syscalls().handle(pollState, TEST_PC);
                return pollState.register(10);
            });

            Thread.sleep(50);
            assertTrue(!pollResult.isDone());

            memory.writeByte(dataAddress, (byte) 'A');
            setSyscall(state, SYS_WRITE, writeFileDescriptor, dataAddress, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            assertEquals(1, pollResult.get(5, TimeUnit.SECONDS));
            assertTrue(isFdSetBitSet(memory, readFileDescriptorsAddress, readFileDescriptor));
        } finally {
            executor.shutdownNow();
        }
    }

    /// Verifies deterministic `ppoll` readiness for standard, invalid, and ignored descriptors.
    @Test
    public void ppollReportsDescriptorReadiness() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 2048)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long pollFileDescriptorsAddress = memory.baseAddress() + 64;
            long timeoutAddress = memory.baseAddress() + 128;

            memory.writeLong(timeoutAddress, 0);
            memory.writeLong(timeoutAddress + Long.BYTES, 0);
            writePollFileDescriptor(memory, pollFileDescriptorsAddress, 0, 1, POLLOUT);
            writePollFileDescriptor(memory, pollFileDescriptorsAddress, 1, 0, POLLIN);
            writePollFileDescriptor(memory, pollFileDescriptorsAddress, 2, 99, POLLIN);
            writePollFileDescriptor(memory, pollFileDescriptorsAddress, 3, -1, POLLIN);

            setSyscall(state, SYS_PPOLL, pollFileDescriptorsAddress, 4, timeoutAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(3, state.register(10));
            assertEquals(POLLOUT, pollRevents(memory, pollFileDescriptorsAddress, 0));
            assertEquals(POLLIN, pollRevents(memory, pollFileDescriptorsAddress, 1));
            assertEquals(POLLNVAL, pollRevents(memory, pollFileDescriptorsAddress, 2));
            assertEquals(0, pollRevents(memory, pollFileDescriptorsAddress, 3));

            memory.writeLong(timeoutAddress + Long.BYTES, 1_000_000_000L);
            setSyscall(state, SYS_PPOLL, pollFileDescriptorsAddress, 1, timeoutAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_PPOLL, pollFileDescriptorsAddress, 1, 0, memory.baseAddress(), KERNEL_SIGSET_SIZE - 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_PPOLL, 0, 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));
        }
    }

    /// Verifies `ppoll` waits for guest-internal descriptor readiness changes.
    @Test
    public void ppollWaitsForPipeReadiness() throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            RiscVThreadState pollState = new RiscVThreadState(
                    memory,
                    0,
                    false,
                    ElfImage.ABSENT_ADDRESS,
                    ElfImage.ABSENT_ADDRESS,
                    state.syscalls());
            long pipeAddress = memory.baseAddress() + 64;
            long pollFileDescriptorsAddress = memory.baseAddress() + 128;
            long dataAddress = memory.baseAddress() + 512;

            setSyscall(state, SYS_PIPE2, pipeAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            int readFileDescriptor = memory.readInt(pipeAddress);
            int writeFileDescriptor = memory.readInt(pipeAddress + Integer.BYTES);

            Future<Long> pollResult = executor.submit(() -> {
                writePollFileDescriptor(memory, pollFileDescriptorsAddress, 0, readFileDescriptor, POLLIN);
                setSyscall(pollState, SYS_PPOLL, pollFileDescriptorsAddress, 1, 0, 0, 0);
                pollState.syscalls().handle(pollState, TEST_PC);
                return pollState.register(10);
            });

            Thread.sleep(50);
            assertTrue(!pollResult.isDone());

            memory.writeByte(dataAddress, (byte) 'A');
            setSyscall(state, SYS_WRITE, writeFileDescriptor, dataAddress, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            assertEquals(1, pollResult.get(5, TimeUnit.SECONDS));
            assertEquals(POLLIN, pollRevents(memory, pollFileDescriptorsAddress, 0));
        } finally {
            executor.shutdownNow();
        }
    }

    /// Verifies immediate `ppoll` checks tty input readiness without breaking blocking waits.
    @Test
    public void ppollChecksDevTtyInputReadinessOnlyForImmediateTimeout() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress());
            long pathAddress = memory.baseAddress();
            long pollFileDescriptorsAddress = memory.baseAddress() + 128;
            long timeoutAddress = memory.baseAddress() + 256;

            writeGuestString(memory, pathAddress, "/dev/tty");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int fileDescriptor = (int) state.register(10);
            assertEquals(3, fileDescriptor);

            writePollFileDescriptor(memory, pollFileDescriptorsAddress, 0, fileDescriptor, POLLIN);
            setSyscall(state, SYS_PPOLL, pollFileDescriptorsAddress, 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));
            assertEquals(POLLIN, pollRevents(memory, pollFileDescriptorsAddress, 0));

            memory.writeLong(timeoutAddress, 0);
            memory.writeLong(timeoutAddress + Long.BYTES, 0);
            writePollFileDescriptor(memory, pollFileDescriptorsAddress, 0, fileDescriptor, POLLIN);
            setSyscall(state, SYS_PPOLL, pollFileDescriptorsAddress, 1, timeoutAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, pollRevents(memory, pollFileDescriptorsAddress, 0));
        }
    }

    /// Verifies that `openat` exposes writable host files below the configured root mount.
    @Test
    public void openatWritesHostFilesBelowRoot() throws Exception {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 128;
            long statAddress = memory.baseAddress() + 256;
            long iovecAddress = memory.baseAddress() + 384;
            long firstIovecBuffer = memory.baseAddress() + 448;
            long secondIovecBuffer = memory.baseAddress() + 456;
            writeGuestString(memory, pathAddress, "/output.txt");

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
            state.syscalls().handle(state, TEST_PC);
            int fileDescriptor = (int) state.register(10);
            assertEquals(3, fileDescriptor);

            memory.writeBytes(bufferAddress, "file".getBytes(StandardCharsets.UTF_8), 0, 4);
            setSyscall(state, SYS_WRITE, fileDescriptor, bufferAddress, 4);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4, state.register(10));

            setSyscall(state, SYS_READ, fileDescriptor, bufferAddress, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));

            setSyscall(state, SYS_FSTAT, fileDescriptor, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(CREATED_REGULAR_FILE_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));
            assertEquals(4, memory.readLong(statAddress + STAT_SIZE_OFFSET));

            setSyscall(state, SYS_CLOSE, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals("file", Files.readString(tempDirectory.resolve("output.txt"), StandardCharsets.UTF_8));

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_WRONLY | O_APPEND, 0);
            state.syscalls().handle(state, TEST_PC);
            fileDescriptor = (int) state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_FCNTL, fileDescriptor, F_GETFL, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(O_WRONLY | O_APPEND, state.register(10));

            memory.writeBytes(bufferAddress, "-".getBytes(StandardCharsets.UTF_8), 0, 1);
            setSyscall(state, SYS_WRITE, fileDescriptor, bufferAddress, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            memory.writeBytes(firstIovecBuffer, "data".getBytes(StandardCharsets.UTF_8), 0, 4);
            memory.writeBytes(secondIovecBuffer, "\n".getBytes(StandardCharsets.UTF_8), 0, 1);
            memory.writeLong(iovecAddress, firstIovecBuffer);
            memory.writeLong(iovecAddress + Long.BYTES, 4);
            memory.writeLong(iovecAddress + 2L * Long.BYTES, secondIovecBuffer);
            memory.writeLong(iovecAddress + 3L * Long.BYTES, 1);
            setSyscall(state, SYS_WRITEV, fileDescriptor, iovecAddress, 2);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(5, state.register(10));

            setSyscall(state, SYS_CLOSE, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals("file-data\n", Files.readString(tempDirectory.resolve("output.txt"), StandardCharsets.UTF_8));

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDWR, 0);
            state.syscalls().handle(state, TEST_PC);
            fileDescriptor = (int) state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_READ, fileDescriptor, bufferAddress, 10);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(10, state.register(10));
            assertArrayEquals("file-data\n".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 10));

            setSyscall(state, SYS_LSEEK, fileDescriptor, 4, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4, state.register(10));

            memory.writeBytes(bufferAddress, "!".getBytes(StandardCharsets.UTF_8), 0, 1);
            setSyscall(state, SYS_WRITE, fileDescriptor, bufferAddress, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_FSTAT, fileDescriptor, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(CREATED_REGULAR_FILE_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));

            setSyscall(state, SYS_CLOSE, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals("file!data\n", Files.readString(tempDirectory.resolve("output.txt"), StandardCharsets.UTF_8));
        }
    }

    /// Verifies positioned host file reads and writes without moving the descriptor offset.
    @Test
    public void positionedFileIoPreservesDescriptorOffset() throws Exception {
        Files.writeString(tempDirectory.resolve("positioned.txt"), "0123456789", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 128;
            long pipeAddress = memory.baseAddress() + 512;
            long iovecAddress = memory.baseAddress() + 768;
            long firstIovecBuffer = memory.baseAddress() + 832;
            long secondIovecBuffer = memory.baseAddress() + 848;
            writeGuestString(memory, pathAddress, "positioned.txt");

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDWR, 0);
            state.syscalls().handle(state, TEST_PC);
            int fileDescriptor = (int) state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_LSEEK, fileDescriptor, 2, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));

            setSyscall(state, SYS_PREAD64, fileDescriptor, bufferAddress, 4, 5);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4, state.register(10));
            assertArrayEquals("5678".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 4));

            setSyscall(state, SYS_LSEEK, fileDescriptor, 0, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));

            memory.writeBytes(bufferAddress, "AB".getBytes(StandardCharsets.UTF_8), 0, 2);
            setSyscall(state, SYS_PWRITE64, fileDescriptor, bufferAddress, 2, 4);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));

            setSyscall(state, SYS_LSEEK, fileDescriptor, 0, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));

            memory.writeLong(iovecAddress + IOVEC_BASE_OFFSET, firstIovecBuffer);
            memory.writeLong(iovecAddress + IOVEC_LENGTH_OFFSET, 2);
            memory.writeLong(iovecAddress + IOVEC_SIZE + IOVEC_BASE_OFFSET, secondIovecBuffer);
            memory.writeLong(iovecAddress + IOVEC_SIZE + IOVEC_LENGTH_OFFSET, 2);
            setSyscall(state, SYS_PREADV, fileDescriptor, iovecAddress, 2, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4, state.register(10));
            assertArrayEquals("01".getBytes(StandardCharsets.UTF_8), memory.readBytes(firstIovecBuffer, 2));
            assertArrayEquals("23".getBytes(StandardCharsets.UTF_8), memory.readBytes(secondIovecBuffer, 2));

            setSyscall(state, SYS_LSEEK, fileDescriptor, 0, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));

            memory.writeBytes(firstIovecBuffer, "XY".getBytes(StandardCharsets.UTF_8), 0, 2);
            memory.writeBytes(secondIovecBuffer, "Z".getBytes(StandardCharsets.UTF_8), 0, 1);
            memory.writeLong(iovecAddress + IOVEC_LENGTH_OFFSET, 2);
            memory.writeLong(iovecAddress + IOVEC_SIZE + IOVEC_LENGTH_OFFSET, 1);
            setSyscall(state, SYS_PWRITEV, fileDescriptor, iovecAddress, 2, 6);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(3, state.register(10));

            setSyscall(state, SYS_LSEEK, fileDescriptor, 0, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));

            setSyscall(state, SYS_PREADV2, fileDescriptor, iovecAddress, 1, 0, -1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOTSUP, state.register(10));

            memory.writeLong(iovecAddress + IOVEC_LENGTH_OFFSET, 2);
            memory.writeLong(iovecAddress + IOVEC_SIZE + IOVEC_LENGTH_OFFSET, 2);
            setSyscall(state, SYS_PREADV2, fileDescriptor, iovecAddress, 2, -1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4, state.register(10));
            assertArrayEquals("23".getBytes(StandardCharsets.UTF_8), memory.readBytes(firstIovecBuffer, 2));
            assertArrayEquals("AB".getBytes(StandardCharsets.UTF_8), memory.readBytes(secondIovecBuffer, 2));

            setSyscall(state, SYS_LSEEK, fileDescriptor, 0, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(6, state.register(10));

            memory.writeBytes(firstIovecBuffer, "cd".getBytes(StandardCharsets.UTF_8), 0, 2);
            memory.writeBytes(secondIovecBuffer, "e".getBytes(StandardCharsets.UTF_8), 0, 1);
            memory.writeLong(iovecAddress + IOVEC_LENGTH_OFFSET, 2);
            memory.writeLong(iovecAddress + IOVEC_SIZE + IOVEC_LENGTH_OFFSET, 1);
            setSyscall(state, SYS_PWRITEV2, fileDescriptor, iovecAddress, 2, -1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(3, state.register(10));

            setSyscall(state, SYS_LSEEK, fileDescriptor, 0, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(9, state.register(10));

            setSyscall(state, SYS_PWRITEV2, fileDescriptor, iovecAddress, 1, 0, -1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOTSUP, state.register(10));

            setSyscall(state, SYS_FDATASYNC, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FSYNC, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_SYNCFS, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_SYNC, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_CLOSE, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals("0123ABcde9", Files.readString(tempDirectory.resolve("positioned.txt"), StandardCharsets.UTF_8));

            writeGuestString(memory, pathAddress, "positioned.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int readOnlyFileDescriptor = (int) state.register(10);
            assertEquals(3, readOnlyFileDescriptor);

            memory.writeBytes(bufferAddress, "!".getBytes(StandardCharsets.UTF_8), 0, 1);
            setSyscall(state, SYS_PWRITE64, readOnlyFileDescriptor, bufferAddress, 1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));

            setSyscall(state, SYS_PREAD64, readOnlyFileDescriptor, bufferAddress, 1, -1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            writeGuestString(memory, pathAddress, ".");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            int directoryFileDescriptor = (int) state.register(10);
            assertEquals(4, directoryFileDescriptor);

            setSyscall(state, SYS_PREAD64, directoryFileDescriptor, bufferAddress, 1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EISDIR, state.register(10));

            setSyscall(state, SYS_FSYNC, directoryFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PIPE2, pipeAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            int readFileDescriptor = memory.readInt(pipeAddress);
            int writeFileDescriptor = memory.readInt(pipeAddress + Integer.BYTES);
            assertEquals(5, readFileDescriptor);
            assertEquals(6, writeFileDescriptor);

            setSyscall(state, SYS_PREAD64, readFileDescriptor, bufferAddress, 1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESPIPE, state.register(10));

            setSyscall(state, SYS_PWRITE64, writeFileDescriptor, bufferAddress, 1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESPIPE, state.register(10));

            setSyscall(state, SYS_FSYNC, readFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_SYNCFS, 99, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
        }
    }

    /// Verifies Linux allocation and advice syscalls use raw errno results and preserve file offsets.
    @Test
    public void fileRangeSyscallsUseLinuxAbi() throws Exception {
        Files.writeString(tempDirectory.resolve("range.txt"), "abc", StandardCharsets.UTF_8);
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 0x100;
            long pipeAddress = memory.baseAddress() + 0x200;
            writeGuestString(memory, pathAddress, "/range.txt");

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDWR, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(3, state.register(10));
            int fileDescriptor = (int) state.register(10);
            setSyscall(state, SYS_FALLOCATE, fileDescriptor, 0, 8, 4);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            memory.writeByte(bufferAddress, (byte) 'Z');
            setSyscall(state, SYS_WRITE, fileDescriptor, bufferAddress, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_FADVISE64, fileDescriptor, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            setSyscall(state, SYS_FADVISE64, fileDescriptor, -1, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
            setSyscall(state, SYS_FALLOCATE, fileDescriptor, 1, 0, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOTSUP, state.register(10));
            setSyscall(state, SYS_CLOSE, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            fileDescriptor = (int) state.register(10);
            setSyscall(state, SYS_FALLOCATE, fileDescriptor, 0, 0, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
            setSyscall(state, SYS_CLOSE, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PIPE2, pipeAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            int readFileDescriptor = memory.readInt(pipeAddress);
            int writeFileDescriptor = memory.readInt(pipeAddress + Integer.BYTES);
            setSyscall(state, SYS_FADVISE64, readFileDescriptor, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESPIPE, state.register(10));
            setSyscall(state, SYS_FALLOCATE, writeFileDescriptor, 0, 0, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESPIPE, state.register(10));
            setSyscall(state, SYS_CLOSE, readFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            setSyscall(state, SYS_CLOSE, writeFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
        }

        byte[] bytes = Files.readAllBytes(tempDirectory.resolve("range.txt"));
        assertEquals(12, bytes.length);
        assertArrayEquals("Zbc".getBytes(StandardCharsets.UTF_8), Arrays.copyOf(bytes, 3));
        assertArrayEquals(new byte[9], Arrays.copyOfRange(bytes, 3, bytes.length));
    }

    /// Verifies Linux regular-file range copies honor explicit and descriptor offsets.
    @Test
    public void copyFileRangeUsesLinuxOffsetSemantics() throws Exception {
        Files.writeString(tempDirectory.resolve("copy-source.txt"), "0123456789", StandardCharsets.UTF_8);
        Files.writeString(tempDirectory.resolve("copy-target.txt"), "..........", StandardCharsets.UTF_8);
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long sourcePathAddress = memory.baseAddress();
            long targetPathAddress = memory.baseAddress() + 0x40;
            long inputOffsetAddress = memory.baseAddress() + 0x100;
            long outputOffsetAddress = memory.baseAddress() + 0x108;
            long pipeAddress = memory.baseAddress() + 0x200;
            writeGuestString(memory, sourcePathAddress, "/copy-source.txt");
            writeGuestString(memory, targetPathAddress, "/copy-target.txt");

            setSyscall(state, SYS_OPENAT, AT_FDCWD, sourcePathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(3, state.register(10));
            int sourceFileDescriptor = (int) state.register(10);
            setSyscall(state, SYS_OPENAT, AT_FDCWD, targetPathAddress, O_RDWR, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4, state.register(10));
            int targetFileDescriptor = (int) state.register(10);

            setSyscall(state, SYS_LSEEK, sourceFileDescriptor, 1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));
            setSyscall(state, SYS_LSEEK, targetFileDescriptor, 2, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));

            memory.writeLong(inputOffsetAddress, 3);
            memory.writeLong(outputOffsetAddress, 5);
            setSyscall(
                    state,
                    SYS_COPY_FILE_RANGE,
                    sourceFileDescriptor,
                    inputOffsetAddress,
                    targetFileDescriptor,
                    outputOffsetAddress,
                    4,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4, state.register(10));
            assertEquals(7, memory.readLong(inputOffsetAddress));
            assertEquals(9, memory.readLong(outputOffsetAddress));

            setSyscall(state, SYS_LSEEK, sourceFileDescriptor, 0, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));
            setSyscall(state, SYS_LSEEK, targetFileDescriptor, 0, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));

            setSyscall(
                    state,
                    SYS_COPY_FILE_RANGE,
                    sourceFileDescriptor,
                    0,
                    targetFileDescriptor,
                    0,
                    2,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));
            setSyscall(state, SYS_LSEEK, sourceFileDescriptor, 0, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(3, state.register(10));
            setSyscall(state, SYS_LSEEK, targetFileDescriptor, 0, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4, state.register(10));

            setSyscall(
                    state,
                    SYS_COPY_FILE_RANGE,
                    sourceFileDescriptor,
                    0,
                    targetFileDescriptor,
                    0,
                    1,
                    1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            memory.writeLong(inputOffsetAddress, 0);
            memory.writeLong(outputOffsetAddress, 1);
            setSyscall(
                    state,
                    SYS_COPY_FILE_RANGE,
                    targetFileDescriptor,
                    inputOffsetAddress,
                    targetFileDescriptor,
                    outputOffsetAddress,
                    4,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
            setSyscall(
                    state,
                    SYS_COPY_FILE_RANGE,
                    sourceFileDescriptor,
                    memory.endAddress(),
                    targetFileDescriptor,
                    outputOffsetAddress,
                    1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));

            setSyscall(state, SYS_PIPE2, pipeAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            int pipeReader = memory.readInt(pipeAddress);
            int pipeWriter = memory.readInt(pipeAddress + Integer.BYTES);
            setSyscall(
                    state,
                    SYS_COPY_FILE_RANGE,
                    pipeReader,
                    0,
                    targetFileDescriptor,
                    0,
                    1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
            setSyscall(state, SYS_CLOSE, pipeReader, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            setSyscall(state, SYS_CLOSE, pipeWriter, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_CLOSE, targetFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            setSyscall(state, SYS_OPENAT, AT_FDCWD, targetPathAddress, O_WRONLY | O_APPEND, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4, state.register(10));
            targetFileDescriptor = (int) state.register(10);
            setSyscall(
                    state,
                    SYS_COPY_FILE_RANGE,
                    sourceFileDescriptor,
                    0,
                    targetFileDescriptor,
                    0,
                    1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));

            setSyscall(state, SYS_CLOSE, sourceFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            setSyscall(state, SYS_CLOSE, targetFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
        }

        assertEquals(
                "..12.3456.",
                Files.readString(tempDirectory.resolve("copy-target.txt"), StandardCharsets.UTF_8));
    }

    /// Verifies path mutation syscalls for sandboxed files and directories.
    @Test
    public void fileMutationSyscallsStaySandboxed() throws Exception {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long newPathAddress = memory.baseAddress() + 128;
            long bufferAddress = memory.baseAddress() + 256;

            writeGuestString(memory, pathAddress, "work");
            setSyscall(state, SYS_MKDIRAT, AT_FDCWD, pathAddress, 0777);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertTrue(Files.isDirectory(tempDirectory.resolve("work")));

            setSyscall(state, SYS_MKDIRAT, AT_FDCWD, pathAddress, 0777);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EEXIST, state.register(10));

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            int directoryFileDescriptor = (int) state.register(10);
            assertEquals(3, directoryFileDescriptor);

            writeGuestString(memory, pathAddress, "nested");
            setSyscall(state, SYS_MKDIRAT, directoryFileDescriptor, pathAddress, 0777);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertTrue(Files.isDirectory(tempDirectory.resolve("work").resolve("nested")));

            writeGuestString(memory, pathAddress, "../../escape");
            setSyscall(state, SYS_MKDIRAT, directoryFileDescriptor, pathAddress, 0777);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            writeGuestString(memory, pathAddress, "nested/data.txt");
            setSyscall(state, SYS_OPENAT, directoryFileDescriptor, pathAddress, O_RDWR | O_CREAT | O_TRUNC, 0644);
            state.syscalls().handle(state, TEST_PC);
            int fileDescriptor = (int) state.register(10);
            assertEquals(4, fileDescriptor);

            memory.writeBytes(bufferAddress, "abcdef".getBytes(StandardCharsets.UTF_8), 0, 6);
            setSyscall(state, SYS_WRITE, fileDescriptor, bufferAddress, 6);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(6, state.register(10));

            setSyscall(state, SYS_FTRUNCATE, fileDescriptor, 8, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_LSEEK, fileDescriptor, 6, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(6, state.register(10));

            setSyscall(state, SYS_READ, fileDescriptor, bufferAddress, 2);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));
            assertEquals(0, memory.readUnsignedByte(bufferAddress));
            assertEquals(0, memory.readUnsignedByte(bufferAddress + 1));

            setSyscall(state, SYS_FTRUNCATE, fileDescriptor, 3, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_LSEEK, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_READ, fileDescriptor, bufferAddress, 3);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(3, state.register(10));
            assertArrayEquals("abc".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 3));

            setSyscall(state, SYS_CLOSE, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "nested/data.txt");
            writeGuestString(memory, newPathAddress, "work/renamed.txt");
            setSyscall(state, SYS_RENAMEAT, directoryFileDescriptor, pathAddress, AT_FDCWD, newPathAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertTrue(Files.notExists(tempDirectory.resolve("work").resolve("nested").resolve("data.txt")));
            assertEquals("abc", Files.readString(tempDirectory.resolve("work").resolve("renamed.txt"), StandardCharsets.UTF_8));

            writeGuestString(memory, pathAddress, "work/renamed.txt");
            setSyscall(state, SYS_TRUNCATE, pathAddress, 2, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals("ab", Files.readString(tempDirectory.resolve("work").resolve("renamed.txt"), StandardCharsets.UTF_8));

            writeGuestString(memory, newPathAddress, "work/final.txt");
            setSyscall(state, SYS_RENAMEAT2, AT_FDCWD, pathAddress, AT_FDCWD, newPathAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertTrue(Files.notExists(tempDirectory.resolve("work").resolve("renamed.txt")));
            assertEquals("ab", Files.readString(tempDirectory.resolve("work").resolve("final.txt"), StandardCharsets.UTF_8));

            setSyscall(state, SYS_RENAMEAT2, AT_FDCWD, newPathAddress, AT_FDCWD, pathAddress, 1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            writeGuestString(memory, pathAddress, "work/nonempty");
            setSyscall(state, SYS_MKDIRAT, AT_FDCWD, pathAddress, 0777);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "work/nonempty/child");
            setSyscall(state, SYS_MKDIRAT, AT_FDCWD, pathAddress, 0777);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "work/nonempty");
            setSyscall(state, SYS_UNLINKAT, AT_FDCWD, pathAddress, AT_REMOVEDIR);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOTEMPTY, state.register(10));

            setSyscall(state, SYS_CLOSE, directoryFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "work/final.txt");
            setSyscall(state, SYS_UNLINKAT, AT_FDCWD, pathAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertTrue(Files.notExists(tempDirectory.resolve("work").resolve("final.txt")));

            setSyscall(state, SYS_UNLINKAT, AT_FDCWD, pathAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOENT, state.register(10));

            writeGuestString(memory, pathAddress, "work/nested");
            setSyscall(state, SYS_UNLINKAT, AT_FDCWD, pathAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EISDIR, state.register(10));

            setSyscall(state, SYS_UNLINKAT, AT_FDCWD, pathAddress, AT_REMOVEDIR);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "work/nonempty/child");
            setSyscall(state, SYS_UNLINKAT, AT_FDCWD, pathAddress, AT_REMOVEDIR);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "work/nonempty");
            setSyscall(state, SYS_UNLINKAT, AT_FDCWD, pathAddress, AT_REMOVEDIR);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "work");
            setSyscall(state, SYS_UNLINKAT, AT_FDCWD, pathAddress, AT_REMOVEDIR);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertTrue(Files.notExists(tempDirectory.resolve("work")));
        }
    }

    /// Verifies that `openat` keeps host access sandboxed and rejects unsupported modes.
    @Test
    public void openatRejectsUnsupportedHostAccess() throws Exception {
        Files.writeString(tempDirectory.resolve("message.txt"), "file-data", StandardCharsets.UTF_8);
        Files.createDirectory(tempDirectory.resolve("directory"));

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long pathAddress = memory.baseAddress();

            writeGuestString(memory, pathAddress, "../message.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            writeGuestString(memory, pathAddress, "missing.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOENT, state.register(10));

            writeGuestString(memory, pathAddress, "directory");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(3, state.register(10));

            setSyscall(state, SYS_CLOSE, 3, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "message.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_WRONLY | O_CREAT | O_EXCL, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EEXIST, state.register(10));

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_TRUNC, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_APPEND, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_WRONLY | O_RDWR, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_OPENAT, 3, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
        }
    }

    /// Verifies that `lseek` rejects standard streams as non-seekable.
    @Test
    public void lseekRejectsStandardStreamsAsPipes() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));

            setSyscall(state, SYS_LSEEK, 1, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESPIPE, state.register(10));

            setSyscall(state, SYS_LSEEK, 9, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));

            setSyscall(state, SYS_LSEEK, 1, 0, 9);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies that plain standard streams are not reported as controllable tty descriptors.
    @Test
    public void ioctlRejectsPlainStandardStreamTerminalQueries() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));

            memory.writeByte(memory.baseAddress(), (byte) 0x7f);
            setSyscall(state, SYS_IOCTL, 1, TCGETS, memory.baseAddress());
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOTTY, state.register(10));
            assertEquals(0x7f, memory.readUnsignedByte(memory.baseAddress()));

            setSyscall(state, SYS_IOCTL, 1, TIOCGWINSZ, memory.baseAddress());
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOTTY, state.register(10));

            setSyscall(state, SYS_IOCTL, 1, 0x1234, memory.baseAddress());
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOTTY, state.register(10));

            setSyscall(state, SYS_IOCTL, 9, TCGETS, memory.baseAddress());
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
        }
    }

    /// Verifies that `/dev/tty` opens as a terminal device with stream-backed I/O.
    @Test
    public void openatOpensDevTtyAsTerminalDevice() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[]{'x'}),
                    out,
                    new ByteArrayOutputStream(),
                    memory.baseAddress());
            long pathAddress = memory.baseAddress();
            long dataAddress = memory.baseAddress() + 128;
            long ioctlAddress = memory.baseAddress() + 256;
            long statAddress = memory.baseAddress() + 512;

            writeGuestString(memory, pathAddress, "/dev/tty");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDWR, 0);
            state.syscalls().handle(state, TEST_PC);
            long fileDescriptor = state.register(10);
            assertEquals(3, fileDescriptor);

            byte[] bytes = "tty".getBytes(StandardCharsets.UTF_8);
            memory.writeBytes(dataAddress, bytes, 0, bytes.length);
            setSyscall(state, SYS_WRITE, fileDescriptor, dataAddress, bytes.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(bytes.length, state.register(10));
            assertEquals("tty", out.toString(StandardCharsets.UTF_8));

            setSyscall(state, SYS_READ, fileDescriptor, dataAddress, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));
            assertEquals('x', memory.readUnsignedByte(dataAddress));

            memory.clear(ioctlAddress, TERMIOS_SIZE);
            setSyscall(state, SYS_IOCTL, fileDescriptor, TCGETS, ioctlAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readUnsignedByte(ioctlAddress));
            int localFlags = memory.readInt(ioctlAddress + TERMIOS_LOCAL_FLAGS_OFFSET);
            assertEquals(
                    TERMIOS_LOCAL_CANONICAL | TERMIOS_LOCAL_ECHO,
                    localFlags & (TERMIOS_LOCAL_CANONICAL | TERMIOS_LOCAL_ECHO));

            memory.writeInt(ioctlAddress + TERMIOS_LOCAL_FLAGS_OFFSET, localFlags & ~TERMIOS_LOCAL_ECHO);
            setSyscall(state, SYS_IOCTL, fileDescriptor, TCSETS, ioctlAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.clear(ioctlAddress, TERMIOS_SIZE);
            setSyscall(state, SYS_IOCTL, fileDescriptor, TCGETS, ioctlAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(
                    TERMIOS_LOCAL_CANONICAL,
                    memory.readInt(ioctlAddress + TERMIOS_LOCAL_FLAGS_OFFSET)
                            & (TERMIOS_LOCAL_CANONICAL | TERMIOS_LOCAL_ECHO));

            memory.clear(ioctlAddress, TERMIOS2_SIZE);
            setSyscall(state, SYS_IOCTL, fileDescriptor, TCGETS2, ioctlAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(
                    TERMIOS_LOCAL_CANONICAL,
                    memory.readInt(ioctlAddress + TERMIOS_LOCAL_FLAGS_OFFSET)
                            & (TERMIOS_LOCAL_CANONICAL | TERMIOS_LOCAL_ECHO));
            assertEquals(38_400, memory.readInt(ioctlAddress + TERMIOS2_INPUT_SPEED_OFFSET));
            assertEquals(38_400, memory.readInt(ioctlAddress + TERMIOS2_OUTPUT_SPEED_OFFSET));

            memory.writeInt(ioctlAddress + TERMIOS_LOCAL_FLAGS_OFFSET, localFlags);
            setSyscall(state, SYS_IOCTL, fileDescriptor, TCSETS2, ioctlAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            memory.clear(ioctlAddress, TERMIOS_SIZE);
            setSyscall(state, SYS_IOCTL, fileDescriptor, TCGETS, ioctlAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(
                    TERMIOS_LOCAL_CANONICAL | TERMIOS_LOCAL_ECHO,
                    memory.readInt(ioctlAddress + TERMIOS_LOCAL_FLAGS_OFFSET)
                            & (TERMIOS_LOCAL_CANONICAL | TERMIOS_LOCAL_ECHO));

            memory.writeByte(ioctlAddress, (byte) 0x5a);
            setSyscall(state, SYS_IOCTL, fileDescriptor, TCSETS, ioctlAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            memory.clear(ioctlAddress, TERMIOS_SIZE);
            setSyscall(state, SYS_IOCTL, fileDescriptor, TCGETS, ioctlAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0x5a, memory.readUnsignedByte(ioctlAddress));

            memory.writeShort(ioctlAddress, (short) 40);
            memory.writeShort(ioctlAddress + Short.BYTES, (short) 120);
            setSyscall(state, SYS_IOCTL, fileDescriptor, TIOCSWINSZ, ioctlAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            memory.clear(ioctlAddress, WINSIZE_SIZE);
            setSyscall(state, SYS_IOCTL, fileDescriptor, TIOCGWINSZ, ioctlAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(40, memory.readUnsignedShort(ioctlAddress));
            assertEquals(120, memory.readUnsignedShort(ioctlAddress + Short.BYTES));

            setSyscall(state, SYS_IOCTL, fileDescriptor, TIOCGPGRP, ioctlAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            int processGroupId = memory.readInt(ioctlAddress);
            assertTrue(processGroupId > 0);
            memory.writeInt(ioctlAddress, processGroupId);
            setSyscall(state, SYS_IOCTL, fileDescriptor, TIOCSPGRP, ioctlAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FSTAT, fileDescriptor, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(CHARACTER_DEVICE_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));
        }
    }

    /// Verifies nonblocking terminal reads return `EAGAIN` when no input is buffered.
    @Test
    public void readDevTtyReturnsEagainWhenNonblockingInputIsEmpty() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[]{'x'}),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress());
            long pathAddress = memory.baseAddress();
            long dataAddress = memory.baseAddress() + 128;

            writeGuestString(memory, pathAddress, "/dev/tty");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDWR, 0);
            state.syscalls().handle(state, TEST_PC);
            long fileDescriptor = state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_FCNTL, fileDescriptor, F_SETFL, O_NONBLOCK);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FCNTL, fileDescriptor, F_GETFL, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(O_RDWR | O_NONBLOCK, state.register(10));

            setSyscall(state, SYS_READ, fileDescriptor, dataAddress, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));
            assertEquals('x', memory.readUnsignedByte(dataAddress));

            setSyscall(state, SYS_READ, fileDescriptor, dataAddress, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAGAIN, state.register(10));
        }
    }

    /// Verifies that `/dev/ptmx` opens a pseudoterminal pair with a usable slave peer.
    @Test
    public void openatOpensPseudoterminalPair() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long pathAddress = memory.baseAddress();
            long dataAddress = memory.baseAddress() + 128;
            long ioctlAddress = memory.baseAddress() + 256;

            writeGuestString(memory, pathAddress, "/dev/ptmx");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC, 0);
            state.syscalls().handle(state, TEST_PC);
            long masterFileDescriptor = state.register(10);
            assertEquals(3, masterFileDescriptor);

            setSyscall(state, SYS_FCNTL, masterFileDescriptor, F_GETFD, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(FD_CLOEXEC, state.register(10));

            setSyscall(state, SYS_IOCTL, masterFileDescriptor, TIOCGPTN, ioctlAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readInt(ioctlAddress));

            memory.writeInt(ioctlAddress, 0);
            setSyscall(state, SYS_IOCTL, masterFileDescriptor, TIOCSPTLCK, ioctlAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "/dev/pts/0");
            setSyscall(state, SYS_FCHOWNAT, AT_FDCWD, pathAddress, 0, 1000, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FCHMODAT, AT_FDCWD, pathAddress, 0620, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_IOCTL, masterFileDescriptor, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_NONBLOCK);
            state.syscalls().handle(state, TEST_PC);
            long slaveFileDescriptor = state.register(10);
            assertEquals(4, slaveFileDescriptor);

            memory.clear(ioctlAddress, TERMIOS_SIZE);
            setSyscall(state, SYS_IOCTL, slaveFileDescriptor, TCGETS, ioctlAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            byte[] slaveBytes = "slave".getBytes(StandardCharsets.UTF_8);
            memory.writeBytes(dataAddress, slaveBytes, 0, slaveBytes.length);
            setSyscall(state, SYS_WRITE, slaveFileDescriptor, dataAddress, slaveBytes.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(slaveBytes.length, state.register(10));

            memory.clear(dataAddress, slaveBytes.length);
            setSyscall(state, SYS_READ, masterFileDescriptor, dataAddress, slaveBytes.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(slaveBytes.length, state.register(10));
            assertEquals("slave", readGuestString(memory, dataAddress, slaveBytes.length));

            byte[] masterBytes = "master".getBytes(StandardCharsets.UTF_8);
            memory.writeBytes(dataAddress, masterBytes, 0, masterBytes.length);
            setSyscall(state, SYS_WRITE, masterFileDescriptor, dataAddress, masterBytes.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(masterBytes.length, state.register(10));

            memory.clear(dataAddress, masterBytes.length);
            setSyscall(state, SYS_READ, slaveFileDescriptor, dataAddress, masterBytes.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(masterBytes.length, state.register(10));
            assertEquals("master", readGuestString(memory, dataAddress, masterBytes.length));

            writeGuestString(memory, pathAddress, "/dev/pts/0");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDWR | O_NOCTTY | O_NONBLOCK, 0);
            state.syscalls().handle(state, TEST_PC);
            long pathSlaveFileDescriptor = state.register(10);
            assertEquals(5, pathSlaveFileDescriptor);

            byte[] pathBytes = "path".getBytes(StandardCharsets.UTF_8);
            memory.writeBytes(dataAddress, pathBytes, 0, pathBytes.length);
            setSyscall(state, SYS_WRITE, pathSlaveFileDescriptor, dataAddress, pathBytes.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(pathBytes.length, state.register(10));

            memory.clear(dataAddress, pathBytes.length);
            setSyscall(state, SYS_READ, masterFileDescriptor, dataAddress, pathBytes.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(pathBytes.length, state.register(10));
            assertEquals("path", readGuestString(memory, dataAddress, pathBytes.length));
        }
    }

    /// Verifies that `/dev/null` consumes writes and returns end-of-file on reads.
    @Test
    public void openatOpensDevNullAsNullDevice() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[]{'x'}),
                    out,
                    new ByteArrayOutputStream(),
                    memory.baseAddress());
            long pathAddress = memory.baseAddress();
            long dataAddress = memory.baseAddress() + 128;
            long statAddress = memory.baseAddress() + 256;

            writeGuestString(memory, pathAddress, "/dev/null");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDWR, 0);
            state.syscalls().handle(state, TEST_PC);
            long fileDescriptor = state.register(10);
            assertEquals(3, fileDescriptor);

            byte[] bytes = "discarded".getBytes(StandardCharsets.UTF_8);
            memory.writeBytes(dataAddress, bytes, 0, bytes.length);
            setSyscall(state, SYS_WRITE, fileDescriptor, dataAddress, bytes.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(bytes.length, state.register(10));
            assertEquals("", out.toString(StandardCharsets.UTF_8));

            setSyscall(state, SYS_READ, fileDescriptor, dataAddress, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FSTAT, fileDescriptor, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(CHARACTER_DEVICE_STAT_MODE, memory.readInt(statAddress + STAT_MODE_OFFSET));
        }
    }

    /// Verifies common built-in random and zero character devices.
    @Test
    public void openatOpensDevZeroAndRandomDevices() {
        byte[] randomBytes;
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long pathAddress = memory.baseAddress();
            long dataAddress = memory.baseAddress() + 128;

            writeGuestString(memory, pathAddress, "/dev/zero");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDWR, 0);
            state.syscalls().handle(state, TEST_PC);
            long zeroFileDescriptor = state.register(10);
            assertEquals(3, zeroFileDescriptor);

            memory.writeBytes(dataAddress, "xxxxxxxx".getBytes(StandardCharsets.UTF_8), 0, 8);
            setSyscall(state, SYS_READ, zeroFileDescriptor, dataAddress, 8);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(8, state.register(10));
            assertArrayEquals(new byte[8], memory.readBytes(dataAddress, 8));

            setSyscall(state, SYS_WRITE, zeroFileDescriptor, dataAddress, 8);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(8, state.register(10));

            writeGuestString(memory, pathAddress, "/dev/urandom");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            long urandomFileDescriptor = state.register(10);
            assertEquals(4, urandomFileDescriptor);

            setSyscall(state, SYS_READ, urandomFileDescriptor, dataAddress, 8);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(8, state.register(10));
            randomBytes = memory.readBytes(dataAddress, 8);

            writeGuestString(memory, pathAddress, "/dev/random");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_WRONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            long randomFileDescriptor = state.register(10);
            assertEquals(5, randomFileDescriptor);

            setSyscall(state, SYS_WRITE, randomFileDescriptor, dataAddress, 8);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(8, state.register(10));
        }

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));

            setSyscall(state, SYS_GETRANDOM, memory.baseAddress(), 8, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(8, state.register(10));
            assertArrayEquals(randomBytes, memory.readBytes(memory.baseAddress(), 8));
        }
    }

    /// Verifies built-in `/dev` directory entries and standard descriptor aliases.
    @Test
    public void devFilesystemListsDevicesAndStandardAliases() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    out,
                    new ByteArrayOutputStream(),
                    memory.baseAddress());
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 512;

            writeGuestString(memory, pathAddress, "/dev");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            long directoryFileDescriptor = state.register(10);
            assertEquals(3, directoryFileDescriptor);

            setSyscall(state, SYS_GETDENTS64, directoryFileDescriptor, bufferAddress, 512);
            state.syscalls().handle(state, TEST_PC);
            assertTrue(state.register(10) > 0);
            long nextAddress = assertDirectoryEntry(
                    memory,
                    bufferAddress,
                    ".",
                    DIRECTORY_ENTRY_DIRECTORY,
                    1);
            nextAddress = assertDirectoryEntry(memory, nextAddress, "..", DIRECTORY_ENTRY_DIRECTORY, 2);
            nextAddress = assertDirectoryEntry(memory, nextAddress, "console", DIRECTORY_ENTRY_CHARACTER_DEVICE, 3);
            nextAddress = assertDirectoryEntry(memory, nextAddress, "fd", DIRECTORY_ENTRY_SYMBOLIC_LINK, 4);
            nextAddress = assertDirectoryEntry(memory, nextAddress, "null", DIRECTORY_ENTRY_CHARACTER_DEVICE, 5);
            nextAddress = assertDirectoryEntry(memory, nextAddress, "ptmx", DIRECTORY_ENTRY_CHARACTER_DEVICE, 6);
            nextAddress = assertDirectoryEntry(memory, nextAddress, "pts", DIRECTORY_ENTRY_DIRECTORY, 7);
            nextAddress = assertDirectoryEntry(memory, nextAddress, "random", DIRECTORY_ENTRY_CHARACTER_DEVICE, 8);
            nextAddress = assertDirectoryEntry(memory, nextAddress, "stderr", DIRECTORY_ENTRY_SYMBOLIC_LINK, 9);
            nextAddress = assertDirectoryEntry(memory, nextAddress, "stdin", DIRECTORY_ENTRY_SYMBOLIC_LINK, 10);
            nextAddress = assertDirectoryEntry(memory, nextAddress, "stdout", DIRECTORY_ENTRY_SYMBOLIC_LINK, 11);
            nextAddress = assertDirectoryEntry(memory, nextAddress, "tty", DIRECTORY_ENTRY_CHARACTER_DEVICE, 12);
            nextAddress = assertDirectoryEntry(memory, nextAddress, "urandom", DIRECTORY_ENTRY_CHARACTER_DEVICE, 13);
            assertDirectoryEntry(memory, nextAddress, "zero", DIRECTORY_ENTRY_CHARACTER_DEVICE, 14);

            writeGuestString(memory, pathAddress, "/dev/stdout");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_WRONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            long outputFileDescriptor = state.register(10);
            assertEquals(4, outputFileDescriptor);

            byte[] bytes = "stdout".getBytes(StandardCharsets.UTF_8);
            memory.writeBytes(bufferAddress, bytes, 0, bytes.length);
            setSyscall(state, SYS_WRITE, outputFileDescriptor, bufferAddress, bytes.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(bytes.length, state.register(10));
            assertEquals("stdout", out.toString(StandardCharsets.UTF_8));

            writeGuestString(memory, pathAddress, "/dev/fd");
            setSyscall(state, SYS_READLINKAT, AT_FDCWD, pathAddress, bufferAddress, 64);
            state.syscalls().handle(state, TEST_PC);
            assertEquals("/proc/self/fd".length(), state.register(10));
            assertEquals("/proc/self/fd", readGuestString(memory, bufferAddress, (int) state.register(10)));

            writeGuestString(memory, pathAddress, "/dev/stdout");
            setSyscall(state, SYS_READLINKAT, AT_FDCWD, pathAddress, bufferAddress, 64);
            state.syscalls().handle(state, TEST_PC);
            assertEquals("/proc/self/fd/1".length(), state.register(10));
            assertEquals("/proc/self/fd/1", readGuestString(memory, bufferAddress, (int) state.register(10)));

            writeGuestString(memory, pathAddress, "/proc/self/fd/1");
            setSyscall(state, SYS_READLINKAT, AT_FDCWD, pathAddress, bufferAddress, 64);
            state.syscalls().handle(state, TEST_PC);
            assertEquals("/dev/tty".length(), state.register(10));
            assertEquals("/dev/tty", readGuestString(memory, bufferAddress, (int) state.register(10)));
        }
    }

    /// Verifies that `writev` writes all guest iovec buffers to stderr.
    @Test
    public void writevWritesMultipleBuffers() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            ByteArrayOutputStream err = new ByteArrayOutputStream();
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    err,
                    memory.baseAddress());
            long iovecAddress = memory.baseAddress();
            long firstBuffer = memory.baseAddress() + 64;
            long secondBuffer = memory.baseAddress() + 72;

            memory.writeBytes(firstBuffer, "Hi".getBytes(StandardCharsets.UTF_8), 0, 2);
            memory.writeBytes(secondBuffer, "!".getBytes(StandardCharsets.UTF_8), 0, 1);
            memory.writeLong(iovecAddress, firstBuffer);
            memory.writeLong(iovecAddress + Long.BYTES, 2);
            memory.writeLong(iovecAddress + 2L * Long.BYTES, secondBuffer);
            memory.writeLong(iovecAddress + 3L * Long.BYTES, 1);

            setSyscall(state, SYS_WRITEV, 2, iovecAddress, 2);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(3, state.register(10));
            assertEquals("Hi!", err.toString(StandardCharsets.UTF_8));
        }
    }

    /// Verifies that `readv` fills guest iovec buffers from stdin in order.
    @Test
    public void readvReadsMultipleBuffers() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream("ABC".getBytes(StandardCharsets.UTF_8)),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress());
            long iovecAddress = memory.baseAddress();
            long firstBuffer = memory.baseAddress() + 64;
            long secondBuffer = memory.baseAddress() + 72;

            memory.writeByte(secondBuffer + 1, (byte) 'Z');
            memory.writeLong(iovecAddress, firstBuffer);
            memory.writeLong(iovecAddress + Long.BYTES, 2);
            memory.writeLong(iovecAddress + 2L * Long.BYTES, secondBuffer);
            memory.writeLong(iovecAddress + 3L * Long.BYTES, 2);

            setSyscall(state, SYS_READV, 0, iovecAddress, 2);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(3, state.register(10));
            assertArrayEquals("AB".getBytes(StandardCharsets.UTF_8), memory.readBytes(firstBuffer, 2));
            assertEquals('C', memory.readUnsignedByte(secondBuffer));
            assertEquals('Z', memory.readUnsignedByte(secondBuffer + 1));
        }
    }

    /// Verifies stable process identity syscalls for the single-process simulator.
    @Test
    public void processIdentitySyscallsReturnStableIds() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));

            setSyscall(state, SYS_GETPID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_GETPPID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETPGID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_GETSID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_SETPGID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EPERM, state.register(10));

            setSyscall(state, SYS_GETPGID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_SETPGID, 0, 99, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EPERM, state.register(10));

            setSyscall(state, SYS_SETPGID, -1, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESRCH, state.register(10));

            setSyscall(state, SYS_SETSID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EPERM, state.register(10));

            setSyscall(state, SYS_GETPRIORITY, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(20, state.register(10));

            setSyscall(state, SYS_SETPRIORITY, 0, 0, 5);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETPRIORITY, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(15, state.register(10));

            setSyscall(state, SYS_SETPRIORITY, 0, 0, -1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EACCES, state.register(10));

            setSyscall(state, SYS_SETPRIORITY, 0, 0, 99);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETPRIORITY, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_GETPRIORITY, 3, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_GETTID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_SET_TID_ADDRESS, memory.baseAddress() + 32, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_GETUID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1000, state.register(10));

            setSyscall(state, SYS_GETEUID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1000, state.register(10));

            setSyscall(state, SYS_GETGID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1000, state.register(10));

            setSyscall(state, SYS_GETEGID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1000, state.register(10));

            long realIdAddress = memory.baseAddress() + 64;
            long effectiveIdAddress = memory.baseAddress() + 68;
            long savedIdAddress = memory.baseAddress() + 72;
            setSyscall(state, SYS_GETRESUID, realIdAddress, effectiveIdAddress, savedIdAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(1000, memory.readInt(realIdAddress));
            assertEquals(1000, memory.readInt(effectiveIdAddress));
            assertEquals(1000, memory.readInt(savedIdAddress));

            setSyscall(state, SYS_GETRESGID, realIdAddress, effectiveIdAddress, savedIdAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(1000, memory.readInt(realIdAddress));
            assertEquals(1000, memory.readInt(effectiveIdAddress));
            assertEquals(1000, memory.readInt(savedIdAddress));

            long capabilityHeaderAddress = memory.baseAddress() + 160;
            long capabilityDataAddress = memory.baseAddress() + 192;
            memory.writeInt(capabilityHeaderAddress, LINUX_CAPABILITY_VERSION_3);
            memory.writeInt(capabilityHeaderAddress + Integer.BYTES, 0);
            setSyscall(state, SYS_CAPGET, capabilityHeaderAddress, capabilityDataAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readInt(capabilityDataAddress));
            assertEquals(0, memory.readInt(capabilityDataAddress + Integer.BYTES));
            assertEquals(0, memory.readInt(capabilityDataAddress + 2L * Integer.BYTES));

            setSyscall(state, SYS_CAPGET, capabilityHeaderAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_SETRESUID, 1000, 1000, 1000);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_SETRESUID, 0xffff_ffffL, 1000, -1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_SETRESUID, 0, 1000, 1000);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EPERM, state.register(10));

            setSyscall(state, SYS_SETRESGID, 1000, 1000, 1000);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_SETRESGID, 0xffff_ffffL, 1000, -1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_SETRESGID, 0, 1000, 1000);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EPERM, state.register(10));

            setSyscall(state, SYS_SETFSUID, 1000, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1000, state.register(10));

            setSyscall(state, SYS_SETFSUID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1000, state.register(10));

            setSyscall(state, SYS_SETFSGID, 1000, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1000, state.register(10));

            setSyscall(state, SYS_SETFSGID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1000, state.register(10));

            long groupsAddress = memory.baseAddress() + 96;
            setSyscall(state, SYS_GETGROUPS, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_GETGROUPS, 1, groupsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));
            assertEquals(1000, memory.readInt(groupsAddress));

            setSyscall(state, SYS_SETGROUPS, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EPERM, state.register(10));

            setSyscall(state, SYS_GETGROUPS, 1, memory.endAddress(), 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));

            setSyscall(state, SYS_GETRESUID, memory.endAddress(), effectiveIdAddress, savedIdAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));

            setSyscall(state, SYS_GETPGID, 99, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESRCH, state.register(10));

            setSyscall(state, SYS_GETSID, 99, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESRCH, state.register(10));

            setSyscall(state, SYS_SETPGID, 99, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESRCH, state.register(10));

            setSyscall(state, SYS_SOCKET, 1, 0x80801, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAFNOSUPPORT, state.register(10));

            setSyscall(state, SYS_GETSOCKNAME, 0, memory.baseAddress() + 96, memory.baseAddress() + 112);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOTSOCK, state.register(10));

            setSyscall(state, SYS_GETPEERNAME, 0, memory.baseAddress() + 96, memory.baseAddress() + 112);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOTSOCK, state.register(10));
        }
    }

    /// Verifies setuid-root credentials can drop and regain the saved root user id.
    @Test
    public void setuidRootCredentialsCanDropAndRegainEffectiveRoot() {
        GuestCredentials credentials = new GuestCredentials(
                "alice",
                1000,
                0,
                0,
                1000,
                1000,
                1000,
                new long[]{1000},
                "/home/alice",
                "/bin/sh");

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    GuestFileSystem.empty(),
                    credentials);
            long realIdAddress = memory.baseAddress() + 64;
            long effectiveIdAddress = memory.baseAddress() + 68;
            long savedIdAddress = memory.baseAddress() + 72;

            setSyscall(state, SYS_SETRESUID, -1, 1000, -1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETRESUID, realIdAddress, effectiveIdAddress, savedIdAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(1000, memory.readInt(realIdAddress));
            assertEquals(1000, memory.readInt(effectiveIdAddress));
            assertEquals(0, memory.readInt(savedIdAddress));

            setSyscall(state, SYS_SETRESUID, -1, 0, -1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETRESUID, realIdAddress, effectiveIdAddress, savedIdAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(1000, memory.readInt(realIdAddress));
            assertEquals(0, memory.readInt(effectiveIdAddress));
            assertEquals(0, memory.readInt(savedIdAddress));
        }
    }

    /// Verifies root credentials can update ids and supplementary groups.
    @Test
    public void rootIdentitySyscallsUpdateProcessCredentials() {
        GuestCredentials root = GuestCredentials.of("root", 0, 0, "", "/root", "/bin/sh");

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    GuestFileSystem.empty(),
                    root);
            long realIdAddress = memory.baseAddress() + 64;
            long effectiveIdAddress = memory.baseAddress() + 68;
            long savedIdAddress = memory.baseAddress() + 72;
            long groupsAddress = memory.baseAddress() + 96;
            long capabilityHeaderAddress = memory.baseAddress() + 128;
            long capabilityDataAddress = memory.baseAddress() + 160;

            memory.writeInt(groupsAddress, 0);
            memory.writeInt(groupsAddress + Integer.BYTES, 42);
            setSyscall(state, SYS_SETGROUPS, 2, groupsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETGROUPS, 2, groupsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));
            assertEquals(0, memory.readInt(groupsAddress));
            assertEquals(42, memory.readInt(groupsAddress + Integer.BYTES));

            memory.writeInt(capabilityHeaderAddress, LINUX_CAPABILITY_VERSION_3);
            memory.writeInt(capabilityHeaderAddress + Integer.BYTES, 0);
            setSyscall(state, SYS_CAPGET, capabilityHeaderAddress, capabilityDataAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertTrue(memory.readUnsignedInt(capabilityDataAddress) != 0);
            assertTrue(memory.readUnsignedInt(capabilityDataAddress + Integer.BYTES) != 0);

            setSyscall(state, SYS_CAPSET, capabilityHeaderAddress, capabilityDataAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_SETGID, 2345, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETRESGID, realIdAddress, effectiveIdAddress, savedIdAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(2345, memory.readInt(realIdAddress));
            assertEquals(2345, memory.readInt(effectiveIdAddress));
            assertEquals(2345, memory.readInt(savedIdAddress));

            setSyscall(state, SYS_SETUID, 1234, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETRESUID, realIdAddress, effectiveIdAddress, savedIdAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(1234, memory.readInt(realIdAddress));
            assertEquals(1234, memory.readInt(effectiveIdAddress));
            assertEquals(1234, memory.readInt(savedIdAddress));
        }
    }

    /// Verifies configurable guest credentials drive identity syscalls and metadata.
    @Test
    public void processIdentitySyscallsUseConfiguredCredentials() {
        GuestCredentials credentials = GuestCredentials.of("alice", 1234, 5678, "42,43", "/home/alice", "/bin/bash");

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 8192)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    GuestFileSystem.empty(),
                    credentials);
            long realIdAddress = memory.baseAddress() + 64;
            long effectiveIdAddress = memory.baseAddress() + 68;
            long savedIdAddress = memory.baseAddress() + 72;
            long groupsAddress = memory.baseAddress() + 96;
            long statAddress = memory.baseAddress() + 128;
            long pathAddress = memory.baseAddress() + 512;
            long bufferAddress = memory.baseAddress() + 1024;
            long statxAddress = memory.baseAddress() + 4096;

            setSyscall(state, SYS_GETUID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1234, state.register(10));

            setSyscall(state, SYS_GETEUID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1234, state.register(10));

            setSyscall(state, SYS_GETGID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(5678, state.register(10));

            setSyscall(state, SYS_GETEGID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(5678, state.register(10));

            setSyscall(state, SYS_GETRESUID, realIdAddress, effectiveIdAddress, savedIdAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(1234, memory.readInt(realIdAddress));
            assertEquals(1234, memory.readInt(effectiveIdAddress));
            assertEquals(1234, memory.readInt(savedIdAddress));

            setSyscall(state, SYS_GETRESGID, realIdAddress, effectiveIdAddress, savedIdAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(5678, memory.readInt(realIdAddress));
            assertEquals(5678, memory.readInt(effectiveIdAddress));
            assertEquals(5678, memory.readInt(savedIdAddress));

            setSyscall(state, SYS_GETGROUPS, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));

            setSyscall(state, SYS_GETGROUPS, 1, groupsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_GETGROUPS, 2, groupsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(2, state.register(10));
            assertEquals(42, memory.readInt(groupsAddress));
            assertEquals(43, memory.readInt(groupsAddress + Integer.BYTES));

            setSyscall(state, SYS_FSTAT, 0, statAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(1234, memory.readInt(statAddress + STAT_UID_OFFSET));
            assertEquals(5678, memory.readInt(statAddress + STAT_GID_OFFSET));

            writeGuestString(memory, pathAddress, "/proc/self/status");
            setSyscall(state, SYS_STATX, AT_FDCWD, pathAddress, 0, STATX_BASIC_STATS_MASK, statxAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(1234, memory.readInt(statxAddress + STATX_UID_OFFSET));
            assertEquals(5678, memory.readInt(statxAddress + STATX_GID_OFFSET));

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int statusFileDescriptor = (int) state.register(10);
            assertEquals(3, statusFileDescriptor);

            setSyscall(state, SYS_READ, statusFileDescriptor, bufferAddress, 512);
            state.syscalls().handle(state, TEST_PC);
            String status = new String(
                    memory.readBytes(bufferAddress, (int) state.register(10)),
                    StandardCharsets.UTF_8);
            assertTrue(status.contains("Uid:\t1234\t1234\t1234\t1234\n"));
            assertTrue(status.contains("Gid:\t5678\t5678\t5678\t5678\n"));
        }
    }

    /// Verifies `wait4` reports no children for the initial single-process state.
    @Test
    public void wait4WithoutChildrenReportsEchild() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long statusAddress = memory.baseAddress() + 64;
            long rusageAddress = memory.baseAddress() + 128;

            setSyscall(state, SYS_WAIT4, -1, statusAddress, 0, rusageAddress);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(ECHILD, state.register(10));
        }
    }

    /// Verifies Linux `waitid` reports but does not reap an exited child when `WNOWAIT` is set.
    @Test
    public void waitidObservesChildBeforeWait4ReapsIt() throws Exception {
        CompletableFuture<Void> childExited = new CompletableFuture<>();
        GuestThreadRunner runner = (childMemory, childState) -> {
            try {
                childState.syscalls().recordThreadExit(childState, 7);
                childExited.complete(null);
            } catch (Throwable throwable) {
                childExited.completeExceptionally(throwable);
                childState.syscalls().recordThreadFailure(throwable);
            }
        };

        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 65_536)) {
            long baseAddress = memory.baseAddress();
            assertTrue(memory.map(baseAddress, 16_384));
            GuestSyscalls syscalls = new LinuxGuestSyscalls(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    baseAddress + 16_384,
                    new String[0],
                    TimeSource.system(),
                    runner);
            RiscVThreadState state = new RiscVThreadState(
                    memory,
                    0,
                    false,
                    ElfImage.ABSENT_ADDRESS,
                    ElfImage.ABSENT_ADDRESS,
                    syscalls);
            long signalInfoAddress = baseAddress + 64;
            long rusageAddress = baseAddress + 256;
            long statusAddress = baseAddress + 512;

            setSyscall(state, SYS_CLONE, SIGCHLD, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            long childProcessId = state.register(10);
            assertTrue(childProcessId > 0);
            childExited.get(5, TimeUnit.SECONDS);

            memory.clear(signalInfoAddress, SIGNAL_INFO_SIZE);
            memory.clear(rusageAddress, 144);
            setSyscall(
                    state,
                    SYS_WAITID,
                    WAIT_ID_PROCESS,
                    childProcessId,
                    signalInfoAddress,
                    WAIT_ID_EXITED | WAIT_ID_NO_WAIT,
                    rusageAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(SIGCHLD, memory.readInt(signalInfoAddress));
            assertEquals(WAIT_ID_CHILD_EXITED, memory.readInt(signalInfoAddress + SIGNAL_INFO_CODE_OFFSET));
            assertEquals(childProcessId, memory.readInt(signalInfoAddress + SIGNAL_INFO_PROCESS_ID_OFFSET));
            assertEquals(
                    GuestCredentials.DEFAULT_USER_ID,
                    memory.readUnsignedInt(signalInfoAddress + SIGNAL_INFO_USER_ID_OFFSET));
            assertEquals(7, memory.readInt(signalInfoAddress + SIGNAL_INFO_STATUS_OFFSET));
            assertArrayEquals(new byte[144], memory.readBytes(rusageAddress, 144));

            setSyscall(state, SYS_WAIT4, childProcessId, statusAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(childProcessId, state.register(10));
            assertEquals(7 << Byte.SIZE, memory.readInt(statusAddress));

            setSyscall(
                    state,
                    SYS_WAITID,
                    WAIT_ID_PROCESS,
                    childProcessId,
                    signalInfoAddress,
                    WAIT_ID_EXITED | WAIT_ID_NO_WAIT,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ECHILD, state.register(10));
        }
    }

    /// Verifies `pidfd_open`, `pidfd_send_signal`, and self `P_PIDFD` wait validation.
    @Test
    public void pidfdOpenRepresentsTheCurrentProcess() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long signalInfoAddress = memory.baseAddress() + 128;

            setSyscall(state, SYS_GETPID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            long processId = state.register(10);

            setSyscall(state, SYS_PIDFD_OPEN, processId, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            int processFileDescriptor = (int) state.register(10);
            assertEquals(3, processFileDescriptor);

            setSyscall(state, SYS_FCNTL, processFileDescriptor, F_GETFD, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(FD_CLOEXEC, state.register(10));

            setSyscall(state, SYS_FCNTL, processFileDescriptor, F_GETFL, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(O_RDWR, state.register(10));

            setSyscall(state, SYS_PIDFD_OPEN, processId, O_EXCL, 0);
            state.syscalls().handle(state, TEST_PC);
            int threadFileDescriptor = (int) state.register(10);
            assertEquals(4, threadFileDescriptor);

            setSyscall(state, SYS_PIDFD_SEND_SIGNAL, threadFileDescriptor, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_CLOSE, threadFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PIDFD_SEND_SIGNAL, processFileDescriptor, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(
                    state,
                    SYS_WAITID,
                    WAIT_ID_PROCESS_FILE_DESCRIPTOR,
                    processFileDescriptor,
                    signalInfoAddress,
                    WAIT_ID_EXITED,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ECHILD, state.register(10));

            setSyscall(state, SYS_PIDFD_OPEN, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_PIDFD_OPEN, 99, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESRCH, state.register(10));

            setSyscall(state, SYS_PIDFD_OPEN, processId, 1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_PIDFD_SEND_SIGNAL, 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));

            setSyscall(state, SYS_CLOSE, processFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PIDFD_SEND_SIGNAL, processFileDescriptor, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));
        }
    }

    /// Verifies `CLONE_PIDFD` returns a pollable descriptor accepted by `waitid(P_PIDFD)`.
    @Test
    public void clonePidfdTracksAndReapsACloneChild() throws Exception {
        CountDownLatch releaseChild = new CountDownLatch(1);
        CompletableFuture<Void> childExited = new CompletableFuture<>();
        GuestThreadRunner runner = (childMemory, childState) -> {
            try {
                if (!releaseChild.await(5, TimeUnit.SECONDS)) {
                    throw new AssertionError("Timed out waiting to release pidfd child process");
                }
                childState.syscalls().recordThreadExit(childState, 5);
                childExited.complete(null);
            } catch (Throwable throwable) {
                childExited.completeExceptionally(throwable);
                childState.syscalls().recordThreadFailure(throwable);
            }
        };

        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 65_536)) {
            long baseAddress = memory.baseAddress();
            assertTrue(memory.map(baseAddress, 16_384));
            GuestSyscalls syscalls = new LinuxGuestSyscalls(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    baseAddress + 16_384,
                    new String[0],
                    TimeSource.system(),
                    runner);
            RiscVThreadState state = new RiscVThreadState(
                    memory,
                    0,
                    false,
                    ElfImage.ABSENT_ADDRESS,
                    ElfImage.ABSENT_ADDRESS,
                    syscalls);
            long processFileDescriptorAddress = baseAddress + 64;
            long signalInfoAddress = baseAddress + 128;
            long pollAddress = baseAddress + 384;
            long timeoutAddress = baseAddress + 448;

            setSyscall(
                    state,
                    SYS_CLONE,
                    CLONE_VM | CLONE_VFORK | CLONE_PIDFD,
                    0,
                    processFileDescriptorAddress,
                    0,
                    0);
            state.syscalls().handle(state, TEST_PC);
            long childProcessId = state.register(10);
            assertTrue(childProcessId > 0);
            int processFileDescriptor = memory.readInt(processFileDescriptorAddress);
            assertEquals(3, processFileDescriptor);

            setSyscall(state, SYS_FCNTL, processFileDescriptor, F_GETFD, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(FD_CLOEXEC, state.register(10));

            setSyscall(state, SYS_PIDFD_OPEN, childProcessId, O_NONBLOCK, 0);
            state.syscalls().handle(state, TEST_PC);
            int nonblockingProcessFileDescriptor = (int) state.register(10);
            assertEquals(4, nonblockingProcessFileDescriptor);

            setSyscall(
                    state,
                    SYS_WAITID,
                    WAIT_ID_PROCESS_FILE_DESCRIPTOR,
                    nonblockingProcessFileDescriptor,
                    signalInfoAddress,
                    WAIT_ID_EXITED | WAIT_CLONE_CHILDREN,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAGAIN, state.register(10));

            setSyscall(state, SYS_CLOSE, nonblockingProcessFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.writeLong(timeoutAddress, 0);
            memory.writeLong(timeoutAddress + Long.BYTES, 0);
            writePollFileDescriptor(memory, pollAddress, 0, processFileDescriptor, POLLIN);
            setSyscall(state, SYS_PPOLL, pollAddress, 1, timeoutAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            releaseChild.countDown();
            childExited.get(5, TimeUnit.SECONDS);

            writePollFileDescriptor(memory, pollAddress, 0, processFileDescriptor, POLLIN);
            setSyscall(state, SYS_PPOLL, pollAddress, 1, timeoutAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));
            assertEquals(POLLIN, pollRevents(memory, pollAddress, 0));

            setSyscall(state, SYS_PIDFD_SEND_SIGNAL, processFileDescriptor, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESRCH, state.register(10));

            memory.clear(signalInfoAddress, SIGNAL_INFO_SIZE);
            setSyscall(
                    state,
                    SYS_WAITID,
                    WAIT_ID_PROCESS_FILE_DESCRIPTOR,
                    processFileDescriptor,
                    signalInfoAddress,
                    WAIT_ID_EXITED | WAIT_CLONE_CHILDREN,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(SIGCHLD, memory.readInt(signalInfoAddress));
            assertEquals(WAIT_ID_CHILD_EXITED, memory.readInt(signalInfoAddress + SIGNAL_INFO_CODE_OFFSET));
            assertEquals(childProcessId, memory.readInt(signalInfoAddress + SIGNAL_INFO_PROCESS_ID_OFFSET));
            assertEquals(5, memory.readInt(signalInfoAddress + SIGNAL_INFO_STATUS_OFFSET));

            writePollFileDescriptor(memory, pollAddress, 0, processFileDescriptor, POLLIN);
            setSyscall(state, SYS_PPOLL, pollAddress, 1, timeoutAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));
            assertEquals(POLLIN | POLLHUP, pollRevents(memory, pollAddress, 0));

            setSyscall(
                    state,
                    SYS_WAITID,
                    WAIT_ID_PROCESS_FILE_DESCRIPTOR,
                    processFileDescriptor,
                    signalInfoAddress,
                    WAIT_ID_EXITED | WAIT_CLONE_CHILDREN,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ECHILD, state.register(10));
        }
    }

    /// Verifies Linux clone children without `SIGCHLD` require the `__WCLONE` wait option.
    @Test
    public void wait4CloneSelectionUsesChildExitSignal() throws Exception {
        CompletableFuture<Void> childExited = new CompletableFuture<>();
        GuestThreadRunner runner = (childMemory, childState) -> {
            try {
                childState.syscalls().recordThreadExit(childState, 3);
                childExited.complete(null);
            } catch (Throwable throwable) {
                childExited.completeExceptionally(throwable);
                childState.syscalls().recordThreadFailure(throwable);
            }
        };

        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 65_536)) {
            long baseAddress = memory.baseAddress();
            assertTrue(memory.map(baseAddress, 16_384));
            GuestSyscalls syscalls = new LinuxGuestSyscalls(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    baseAddress + 16_384,
                    new String[0],
                    TimeSource.system(),
                    runner);
            RiscVThreadState state = new RiscVThreadState(
                    memory,
                    0,
                    false,
                    ElfImage.ABSENT_ADDRESS,
                    ElfImage.ABSENT_ADDRESS,
                    syscalls);
            long statusAddress = baseAddress + 64;

            setSyscall(state, SYS_CLONE, 0, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            long childProcessId = state.register(10);
            assertTrue(childProcessId > 0);
            childExited.get(5, TimeUnit.SECONDS);

            setSyscall(state, SYS_WAIT4, childProcessId, statusAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ECHILD, state.register(10));

            setSyscall(state, SYS_WAIT4, childProcessId, statusAddress, WAIT_CLONE_CHILDREN, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(childProcessId, state.register(10));
            assertEquals(3 << Byte.SIZE, memory.readInt(statusAddress));
        }
    }

    /// Verifies child-process exits queue a `SIGCHLD` frame before the next syscall returns to user code.
    @Test
    public void childExitQueuesSigchldSignalFrame() throws Exception {
        CountDownLatch releaseChild = new CountDownLatch(1);
        CompletableFuture<Void> childExited = new CompletableFuture<>();
        GuestThreadRunner runner = (childMemory, childState) -> {
            try {
                if (!releaseChild.await(5, TimeUnit.SECONDS)) {
                    throw new AssertionError("Timed out waiting to release child process");
                }
                childState.syscalls().recordThreadExit(childState, 0);
                childExited.complete(null);
            } catch (Throwable throwable) {
                childExited.completeExceptionally(throwable);
                childState.syscalls().recordThreadFailure(throwable);
            }
        };

        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 65536)) {
            long base = memory.baseAddress();
            assertTrue(memory.map(base, 16384));

            GuestSyscalls syscalls = new LinuxGuestSyscalls(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    base + 16384,
                    new String[0],
                    TimeSource.system(),
                    runner);
            RiscVThreadState state = new RiscVThreadState(
                    memory,
                    0,
                    false,
                    ElfImage.ABSENT_ADDRESS,
                    ElfImage.ABSENT_ADDRESS,
                    syscalls);

            long actionAddress = base + 64;
            long handlerAddress = base + 512;
            long stackPointer = base + 8192;
            long statusAddress = base + 12288;

            memory.writeLong(actionAddress, handlerAddress);
            memory.writeLong(actionAddress + Long.BYTES, SA_SIGINFO);
            memory.writeLong(actionAddress + 2L * Long.BYTES, 0);
            setSyscall(state, SYS_RT_SIGACTION, SIGCHLD, actionAddress, 0, KERNEL_SIGSET_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            state.setRegister(2, stackPointer);
            state.setPc(TEST_PC);
            setSyscall(state, SYS_CLONE, SIGCHLD, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            long childProcessId = state.register(10);
            assertTrue(childProcessId > 0);

            releaseChild.countDown();
            childExited.get(5, TimeUnit.SECONDS);

            state.setPc(TEST_PC);
            setSyscall(state, SYS_GETPID, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            long frameAddress = state.register(2);
            long infoAddress = state.register(11);
            long contextAddress = state.register(12);
            long registersAddress = contextAddress + SIGNAL_CONTEXT_MACHINE_OFFSET;

            assertEquals(handlerAddress, state.pc());
            assertEquals(SIGCHLD, state.register(10));
            assertEquals(frameAddress, infoAddress);
            assertEquals(frameAddress + SIGNAL_INFO_SIZE, contextAddress);
            assertEquals(SIGCHLD, memory.readInt(infoAddress));
            assertEquals(TEST_PC + Integer.BYTES, memory.readLong(registersAddress));
            assertEquals(1, memory.readLong(registersAddress + 10L * Long.BYTES));

            long resumePc = base + 14000;
            memory.writeLong(registersAddress, resumePc);
            setSyscall(state, SYS_RT_SIGRETURN, 0, 0, 0);
            state.syscalls().handle(state, state.pc());
            assertEquals(resumePc, state.pc());
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_WAIT4, childProcessId, statusAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(childProcessId, state.register(10));
            assertEquals(0, memory.readInt(statusAddress));
        }
    }

    /// Verifies signal-send syscalls use deterministic single-process validation.
    @Test
    public void signalSendSyscallsValidateSingleProcessTargets() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));

            setSyscall(state, SYS_KILL, 1, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_KILL, 0, 15, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_KILL, 99, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESRCH, state.register(10));

            setSyscall(state, SYS_KILL, 1, 65, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_TKILL, 1, 10, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_TKILL, 99, 10, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESRCH, state.register(10));

            setSyscall(state, SYS_TGKILL, 1, 1, 10);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_TGKILL, 99, 1, 10);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESRCH, state.register(10));
        }
    }

    /// Verifies that thread-style `clone` requires a guest thread runner.
    @Test
    public void cloneRequiresThreadCreationContext() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long stackAddress = memory.baseAddress() + 512;
            long parentTidAddress = memory.baseAddress() + 32;
            long childTidAddress = memory.baseAddress() + 40;
            long tlsAddress = memory.baseAddress() + 96;

            setSyscall(
                    state,
                    SYS_CLONE,
                    THREAD_CLONE_FLAGS,
                    stackAddress,
                    parentTidAddress,
                    tlsAddress,
                    childTidAddress,
                    0);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(EAGAIN, state.register(10));
            assertEquals(0, memory.readInt(parentTidAddress));
            assertEquals(0, memory.readInt(childTidAddress));
        }
    }

    /// Verifies process-style `clone` requires a runner and unsupported mixed clone flags are rejected.
    @Test
    public void cloneRejectsUnsupportedProcessCreationForms() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long stackAddress = memory.baseAddress() + 512;

            setSyscall(state, SYS_CLONE, 17, stackAddress, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAGAIN, state.register(10));

            setSyscall(state, SYS_CLONE, CLONE_VM | 17, stackAddress, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_CLONE, CLONE_VM | CLONE_VFORK | 17, stackAddress, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAGAIN, state.register(10));

            setSyscall(state, SYS_CLONE, CLONE_PIDFD, stackAddress, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));

            setSyscall(
                    state,
                    SYS_CLONE,
                    CLONE_PIDFD | CLONE_PARENT_SETTID,
                    stackAddress,
                    memory.baseAddress() + 32,
                    0,
                    0,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_CLONE, REQUIRED_THREAD_CLONE_FLAGS & ~CLONE_THREAD, stackAddress, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_CLONE, REQUIRED_THREAD_CLONE_FLAGS, 0, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies `clone3` argument translation for the existing clone implementation.
    @Test
    public void clone3TranslatesCloneArguments() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 2048)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long argumentsAddress = memory.baseAddress() + 128;
            long stackBaseAddress = memory.baseAddress() + 512;
            long stackSize = 256;
            long parentTidAddress = memory.baseAddress() + 32;
            long childTidAddress = memory.baseAddress() + 40;
            long tlsAddress = memory.baseAddress() + 96;

            memory.writeLong(argumentsAddress + CLONE_ARGS_FLAGS_OFFSET, THREAD_CLONE_FLAGS);
            memory.writeLong(argumentsAddress + CLONE_ARGS_PIDFD_OFFSET, parentTidAddress);
            memory.writeLong(argumentsAddress + CLONE_ARGS_CHILD_TID_OFFSET, childTidAddress);
            memory.writeLong(argumentsAddress + CLONE_ARGS_PARENT_TID_OFFSET, parentTidAddress);
            memory.writeLong(argumentsAddress + CLONE_ARGS_EXIT_SIGNAL_OFFSET, 0);
            memory.writeLong(argumentsAddress + CLONE_ARGS_STACK_OFFSET, stackBaseAddress);
            memory.writeLong(argumentsAddress + CLONE_ARGS_STACK_SIZE_OFFSET, stackSize);
            memory.writeLong(argumentsAddress + CLONE_ARGS_TLS_OFFSET, tlsAddress);
            setSyscall(state, SYS_CLONE3, argumentsAddress, CLONE_ARGS_SIZE, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAGAIN, state.register(10));

            memory.writeLong(argumentsAddress + CLONE_ARGS_FLAGS_OFFSET, CLONE_VM | CLONE_VFORK);
            memory.writeLong(argumentsAddress + CLONE_ARGS_EXIT_SIGNAL_OFFSET, 17);
            memory.writeLong(argumentsAddress + CLONE_ARGS_STACK_OFFSET, 0);
            memory.writeLong(argumentsAddress + CLONE_ARGS_STACK_SIZE_OFFSET, 0);
            setSyscall(state, SYS_CLONE3, argumentsAddress, CLONE_ARGS_SIZE, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAGAIN, state.register(10));

            memory.writeLong(argumentsAddress + CLONE_ARGS_FLAGS_OFFSET, CLONE_PIDFD);
            memory.writeLong(argumentsAddress + CLONE_ARGS_EXIT_SIGNAL_OFFSET, 0);
            setSyscall(state, SYS_CLONE3, argumentsAddress, CLONE_ARGS_SIZE, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAGAIN, state.register(10));

            memory.writeLong(argumentsAddress + CLONE_ARGS_PIDFD_OFFSET, 0);
            setSyscall(state, SYS_CLONE3, argumentsAddress, CLONE_ARGS_SIZE, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));

            memory.writeLong(argumentsAddress + CLONE_ARGS_FLAGS_OFFSET, 0);
            setSyscall(state, SYS_CLONE3, argumentsAddress, 63, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies that robust futex list registration is accepted for single-threaded guests.
    @Test
    public void setRobustListAcceptsNonNegativeLength() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long headPointerAddress = memory.baseAddress() + 128;
            long lengthAddress = memory.baseAddress() + 136;

            setSyscall(state, SYS_SET_ROBUST_LIST, memory.baseAddress() + 64, 24, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GET_ROBUST_LIST, 0, headPointerAddress, lengthAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(memory.baseAddress() + 64, memory.readLong(headPointerAddress));
            assertEquals(24, memory.readLong(lengthAddress));

            setSyscall(state, SYS_GET_ROBUST_LIST, 99, headPointerAddress, lengthAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESRCH, state.register(10));

            setSyscall(state, SYS_SET_ROBUST_LIST, memory.baseAddress() + 64, -1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies non-blocking single-threaded futex wait results.
    @Test
    public void futexWaitComparesWordAndReturnsImmediately() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long futexAddress = memory.baseAddress() + 64;
            long timeoutAddress = memory.baseAddress() + 80;

            memory.writeInt(futexAddress, 7);
            setSyscall(state, SYS_FUTEX, futexAddress, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 9, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAGAIN, state.register(10));

            setSyscall(state, SYS_FUTEX, futexAddress, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 7, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ETIMEDOUT, state.register(10));

            memory.writeLong(timeoutAddress, 0);
            memory.writeLong(timeoutAddress + Long.BYTES, 1);
            setSyscall(state, SYS_FUTEX, futexAddress, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 7, timeoutAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ETIMEDOUT, state.register(10));

            memory.writeLong(timeoutAddress + Long.BYTES, 1_000_000_000L);
            setSyscall(state, SYS_FUTEX, futexAddress, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 7, timeoutAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies `FUTEX_WAIT_BITSET` interprets timeout values as absolute monotonic deadlines.
    @Test
    public void futexWaitBitsetUsesAbsoluteTimeout() {
        GuestThreadRunner runner = (childMemory, childState) -> {
        };

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            GuestSyscalls syscalls = new LinuxGuestSyscalls(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    ".",
                    TimeSource.system(),
                    runner);
            RiscVThreadState state = new RiscVThreadState(
                    memory,
                    0,
                    false,
                    ElfImage.ABSENT_ADDRESS,
                    ElfImage.ABSENT_ADDRESS,
                    syscalls);
            long futexAddress = memory.baseAddress() + 64;
            long timeoutAddress = memory.baseAddress() + 80;

            memory.writeInt(futexAddress, 7);
            writeTimespec(memory, timeoutAddress, 1, 0);

            long startNanos = System.nanoTime();
            setSyscall(
                    state,
                    SYS_FUTEX,
                    futexAddress,
                    FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG,
                    7,
                    timeoutAddress,
                    0,
                    FUTEX_BITSET_MATCH_ANY);
            state.syscalls().handle(state, TEST_PC);
            long elapsedNanos = System.nanoTime() - startNanos;

            assertEquals(ETIMEDOUT, state.register(10));
            assertTrue(
                    elapsedNanos < TimeUnit.MILLISECONDS.toNanos(250),
                    "`FUTEX_WAIT_BITSET` timeout was treated as a relative duration");
        }
    }

    /// Verifies futex wake operations against the empty waiter set.
    @Test
    public void futexWakeReportsNoWaiters() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long futexAddress = memory.baseAddress() + 64;

            setSyscall(state, SYS_FUTEX, futexAddress, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(
                    state,
                    SYS_FUTEX,
                    futexAddress,
                    FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG,
                    1,
                    0,
                    0,
                    FUTEX_BITSET_MATCH_ANY);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FUTEX, futexAddress, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, -1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies futex validation and unsupported operation reporting.
    @Test
    public void futexRejectsInvalidOrUnsupportedOperations() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long futexAddress = memory.baseAddress() + 64;

            setSyscall(state, SYS_FUTEX, futexAddress + 1, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(
                    state,
                    SYS_FUTEX,
                    futexAddress,
                    FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME,
                    0,
                    0,
                    0,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_FUTEX, futexAddress, FUTEX_WAKE | FUTEX_CLOCK_REALTIME, 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_FUTEX, futexAddress, 3 | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOSYS, state.register(10));
        }
    }

    /// Verifies `nanosleep` validation and successful short sleeps.
    @Test
    public void nanosleepValidatesTimespec() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long requestAddress = memory.baseAddress() + 64;
            long remainingAddress = memory.baseAddress() + 80;

            memory.writeLong(requestAddress, 0);
            memory.writeLong(requestAddress + Long.BYTES, 1_000_000L);
            memory.writeLong(remainingAddress, 123);
            memory.writeLong(remainingAddress + Long.BYTES, 456);
            setSyscall(state, SYS_NANOSLEEP, requestAddress, remainingAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(123, memory.readLong(remainingAddress));
            assertEquals(456, memory.readLong(remainingAddress + Long.BYTES));

            memory.writeLong(requestAddress, 0);
            memory.writeLong(requestAddress + Long.BYTES, 1_000_000_000L);
            setSyscall(state, SYS_NANOSLEEP, requestAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            memory.writeLong(requestAddress, -1);
            memory.writeLong(requestAddress + Long.BYTES, 0);
            setSyscall(state, SYS_NANOSLEEP, requestAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies `nanosleep` interruption handling and remaining-time reporting.
    @Test
    public void nanosleepReportsRemainingTimeOnInterrupt() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long requestAddress = memory.baseAddress() + 64;
            long remainingAddress = memory.baseAddress() + 80;

            memory.writeLong(requestAddress, 1);
            memory.writeLong(requestAddress + Long.BYTES, 0);
            Thread.currentThread().interrupt();
            try {
                setSyscall(state, SYS_NANOSLEEP, requestAddress, remainingAddress, 0);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(EINTR, state.register(10));
                assertTrue(memory.readLong(remainingAddress) >= 0);
                assertTrue(memory.readLong(remainingAddress + Long.BYTES) >= 0);
                assertTrue(memory.readLong(remainingAddress + Long.BYTES) < 1_000_000_000L);
            } finally {
                Thread.interrupted();
            }
        }
    }

    /// Verifies deterministic single-CPU affinity for static libc sysconf queries.
    @Test
    public void schedGetaffinityReportsSingleCpu() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long maskAddress = memory.baseAddress() + 64;

            memory.writeByte(maskAddress + Long.BYTES, (byte) 0x7f);
            setSyscall(state, SYS_SCHED_GETAFFINITY, 0, 16, maskAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(Long.BYTES, state.register(10));
            assertEquals(1, memory.readLong(maskAddress));
            assertEquals(0, memory.readUnsignedByte(maskAddress + Long.BYTES));

            setSyscall(state, SYS_SCHED_GETAFFINITY, 0, Long.BYTES - 1, maskAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            memory.writeLong(maskAddress, 1);
            setSyscall(state, SYS_SCHED_SETAFFINITY, 0, Long.BYTES, maskAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.writeLong(maskAddress, 0);
            setSyscall(state, SYS_SCHED_SETAFFINITY, 0, Long.BYTES, maskAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            memory.writeLong(maskAddress, 1);
            setSyscall(state, SYS_SCHED_SETAFFINITY, 9999, Long.BYTES, maskAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESRCH, state.register(10));
        }
    }

    /// Verifies deterministic single-CPU scheduling helper syscalls.
    @Test
    public void schedulingHelpersReportSingleCpu() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long cpuAddress = memory.baseAddress() + 64;
            long nodeAddress = memory.baseAddress() + 72;
            long parameterAddress = memory.baseAddress() + 80;
            long intervalAddress = memory.baseAddress() + 96;

            setSyscall(state, SYS_SCHED_YIELD, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_SCHED_GETSCHEDULER, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(SCHED_OTHER, state.register(10));

            memory.writeInt(parameterAddress, -1);
            setSyscall(state, SYS_SCHED_GETPARAM, 0, parameterAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readInt(parameterAddress));

            setSyscall(state, SYS_SCHED_GET_PRIORITY_MAX, SCHED_FIFO, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(99, state.register(10));

            setSyscall(state, SYS_SCHED_GET_PRIORITY_MIN, SCHED_RR, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_SCHED_GET_PRIORITY_MAX, SCHED_BATCH, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_SCHED_GET_PRIORITY_MIN, 999, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            memory.writeInt(parameterAddress, 7);
            setSyscall(state, SYS_SCHED_SETSCHEDULER, 0, SCHED_RR, parameterAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_SCHED_GETSCHEDULER, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(SCHED_RR, state.register(10));

            memory.writeInt(parameterAddress, -1);
            setSyscall(state, SYS_SCHED_GETPARAM, 0, parameterAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(7, memory.readInt(parameterAddress));

            memory.writeInt(parameterAddress, 8);
            setSyscall(state, SYS_SCHED_SETPARAM, 0, parameterAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.writeInt(parameterAddress, 0);
            setSyscall(state, SYS_SCHED_SETSCHEDULER, 0, SCHED_BATCH | SCHED_RESET_ON_FORK, parameterAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_SCHED_GETSCHEDULER, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(SCHED_BATCH, state.register(10));

            memory.writeInt(parameterAddress, 1);
            setSyscall(state, SYS_SCHED_SETPARAM, 0, parameterAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_SCHED_RR_GET_INTERVAL, 0, intervalAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readLong(intervalAddress));
            assertEquals(100_000_000L, memory.readLong(intervalAddress + Long.BYTES));

            setSyscall(state, SYS_SCHED_GETPARAM, 9999, parameterAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESRCH, state.register(10));

            memory.writeInt(cpuAddress, -1);
            memory.writeInt(nodeAddress, -1);
            setSyscall(state, SYS_GETCPU, cpuAddress, nodeAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readInt(cpuAddress));
            assertEquals(0, memory.readInt(nodeAddress));

            setSyscall(state, SYS_GETCPU, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
        }
    }

    /// Verifies deterministic RISC-V hardware probe values for the simulated CPU.
    @Test
    public void riscvHwprobeReportsSupportedCapabilities() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long pairsAddress = memory.baseAddress() + 64;

            writeHwprobeKey(memory, pairsAddress, 0, RISCV_HWPROBE_KEY_MVENDORID);
            writeHwprobeKey(memory, pairsAddress, 1, RISCV_HWPROBE_KEY_BASE_BEHAVIOR);
            writeHwprobeKey(memory, pairsAddress, 2, RISCV_HWPROBE_KEY_IMA_EXT_0);
            writeHwprobeKey(memory, pairsAddress, 3, RISCV_HWPROBE_KEY_CPUPERF_0);
            writeHwprobeKey(memory, pairsAddress, 4, RISCV_HWPROBE_KEY_HIGHEST_VIRT_ADDRESS);
            writeHwprobeKey(memory, pairsAddress, 5, RISCV_HWPROBE_KEY_TIME_CSR_FREQ);
            writeHwprobeKey(memory, pairsAddress, 6, RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF);
            writeHwprobeKey(memory, pairsAddress, 7, RISCV_HWPROBE_KEY_MISALIGNED_VECTOR_PERF);
            writeHwprobeKey(memory, pairsAddress, 8, RISCV_HWPROBE_KEY_ZICBOZ_BLOCK_SIZE);
            writeHwprobeKey(memory, pairsAddress, 9, RISCV_HWPROBE_KEY_ZICBOM_BLOCK_SIZE);
            writeHwprobeKey(memory, pairsAddress, 10, RISCV_HWPROBE_KEY_ZICBOP_BLOCK_SIZE);
            writeHwprobeKey(memory, pairsAddress, 11, 99);

            setSyscall(state, SYS_RISCV_HWPROBE, pairsAddress, 12, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(0, state.register(10));
            assertEquals(0, readHwprobeValue(memory, pairsAddress, 0));
            assertEquals(RISCV_HWPROBE_BASE_BEHAVIOR_IMA, readHwprobeValue(memory, pairsAddress, 1));
            long imaExtensions = readHwprobeValue(memory, pairsAddress, 2);
            assertEquals(Rva23Profile.HWPROBE_REPORTED_EXTENSIONS, imaExtensions);
            assertEquals(
                    Rva22Profile.HWPROBE_MANDATORY_EXTENSIONS,
                    imaExtensions & Rva22Profile.HWPROBE_MANDATORY_EXTENSIONS);
            assertEquals(
                    Rva22Profile.HWPROBE_COMPATIBILITY_EXTENSIONS,
                    imaExtensions & Rva22Profile.HWPROBE_COMPATIBILITY_EXTENSIONS);
            assertEquals(RiscVExtensions.HWPROBE_EXT_ZKT, imaExtensions & RiscVExtensions.HWPROBE_EXT_ZKT);
            assertEquals(RiscVExtensions.HWPROBE_EXT_ZVBC, imaExtensions & RiscVExtensions.HWPROBE_EXT_ZVBC);
            long expectedSplitAtomicAndCounterExtensions =
                    RiscVExtensions.HWPROBE_EXT_ZIHPM
                            | RiscVExtensions.HWPROBE_EXT_ZAAMO
                            | RiscVExtensions.HWPROBE_EXT_ZALRSC;
            assertEquals(expectedSplitAtomicAndCounterExtensions, imaExtensions & expectedSplitAtomicAndCounterExtensions);
            long unreportedOptionalExtensions =
                    RiscVExtensions.HWPROBE_EXT_ZFH
                            | RiscVExtensions.HWPROBE_EXT_ZACAS;
            assertEquals(0, imaExtensions & unreportedOptionalExtensions);
            assertEquals(RISCV_HWPROBE_MISALIGNED_EMULATED, readHwprobeValue(memory, pairsAddress, 3));
            assertEquals(RISCV_HIGHEST_SV48_USER_ADDRESS, readHwprobeValue(memory, pairsAddress, 4));
            assertEquals(1_000_000_000L, readHwprobeValue(memory, pairsAddress, 5));
            assertEquals(RISCV_HWPROBE_MISALIGNED_SCALAR_EMULATED, readHwprobeValue(memory, pairsAddress, 6));
            assertEquals(RISCV_HWPROBE_MISALIGNED_VECTOR_SLOW, readHwprobeValue(memory, pairsAddress, 7));
            assertEquals(RiscVExtensions.CACHE_BLOCK_SIZE, readHwprobeValue(memory, pairsAddress, 8));
            assertEquals(RiscVExtensions.CACHE_BLOCK_SIZE, readHwprobeValue(memory, pairsAddress, 9));
            assertEquals(RiscVExtensions.CACHE_BLOCK_SIZE, readHwprobeValue(memory, pairsAddress, 10));
            assertEquals(-1, readHwprobeKey(memory, pairsAddress, 11));
            assertEquals(0, readHwprobeValue(memory, pairsAddress, 11));
        }
    }

    /// Verifies `riscv_hwprobe` falls back to RVA22U64 bits when VLEN is below the RVA23U64 minimum.
    @Test
    public void riscvHwprobeReportsRva22ForShortVectorLength() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024);
             GuestSyscalls syscalls = new LinuxGuestSyscalls(
                     memory,
                     new ByteArrayInputStream(new byte[0]),
                     new ByteArrayOutputStream(),
                     new ByteArrayOutputStream(),
                     memory.baseAddress())) {
            RiscVThreadState state = new RiscVThreadState(
                    memory,
                    0,
                    false,
                    ElfImage.ABSENT_ADDRESS,
                    ElfImage.ABSENT_ADDRESS,
                    syscalls,
                    new ByteArrayOutputStream(),
                    Rva23Profile.MINIMUM_VLEN_BITS / 2);
            long pairsAddress = memory.baseAddress() + 64;

            writeHwprobeKey(memory, pairsAddress, 0, RISCV_HWPROBE_KEY_IMA_EXT_0);
            setSyscall(state, SYS_RISCV_HWPROBE, pairsAddress, 1, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(0, state.register(10));
            assertEquals(Rva22Profile.HWPROBE_REPORTED_EXTENSIONS, readHwprobeValue(memory, pairsAddress, 0));
        }
    }

    /// Verifies `riscv_hwprobe` validation and single-CPU filtering behavior.
    @Test
    public void riscvHwprobeFiltersWhichCpus() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long pairsAddress = memory.baseAddress() + 64;
            long cpuSetAddress = memory.baseAddress() + 256;

            writeHwprobePair(
                    memory,
                    pairsAddress,
                    0,
                    RISCV_HWPROBE_KEY_BASE_BEHAVIOR,
                    RISCV_HWPROBE_BASE_BEHAVIOR_IMA);
            setSyscall(state, SYS_RISCV_HWPROBE, pairsAddress, 1, Long.BYTES, cpuSetAddress, RISCV_HWPROBE_WHICH_CPUS, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(1, memory.readUnsignedByte(cpuSetAddress));

            memory.writeByte(cpuSetAddress, (byte) 1);
            writeHwprobePair(memory, pairsAddress, 0, RISCV_HWPROBE_KEY_IMA_EXT_0, RiscVExtensions.HWPROBE_EXT_ZACAS);
            setSyscall(state, SYS_RISCV_HWPROBE, pairsAddress, 1, Long.BYTES, cpuSetAddress, RISCV_HWPROBE_WHICH_CPUS, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readUnsignedByte(cpuSetAddress));

            setSyscall(state, SYS_RISCV_HWPROBE, pairsAddress, 1, 0, 0, RISCV_HWPROBE_WHICH_CPUS, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_RISCV_HWPROBE, pairsAddress, 1, 0, 0, 2, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies `riscv_flush_icache` refreshes guest instruction-fetch visibility.
    @Test
    public void riscvFlushIcacheRefreshesInstructionFetch() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long previousGeneration = state.instructionFetchGeneration();

            setSyscall(state, SYS_RISCV_FLUSH_ICACHE, memory.baseAddress(), memory.baseAddress() + 64, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertTrue(state.instructionFetchGeneration() > previousGeneration);

            setSyscall(state, SYS_RISCV_FLUSH_ICACHE, memory.baseAddress() + 64, memory.baseAddress(), 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_RISCV_FLUSH_ICACHE, memory.baseAddress(), memory.baseAddress() + 64, 2);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies the deterministic Linux machine identity reported by `uname`.
    @Test
    public void unameReportsRiscvLinuxIdentity() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long utsnameAddress = memory.baseAddress() + 64;

            setSyscall(state, SYS_UNAME, utsnameAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(0, state.register(10));
            assertEquals("Linux", readGuestCString(memory, utsnameAddress + UTSNAME_SYSNAME_OFFSET, UTSNAME_FIELD_SIZE));
            assertEquals("6.12.0", readGuestCString(memory, utsnameAddress + UTSNAME_RELEASE_OFFSET, UTSNAME_FIELD_SIZE));
            assertEquals("riscv64", readGuestCString(memory, utsnameAddress + UTSNAME_MACHINE_OFFSET, UTSNAME_FIELD_SIZE));
        }
    }

    /// Verifies that `clock_gettime` uses host clocks by default.
    @Test
    public void clockGettimeUsesHostTimeByDefault() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long timespecAddress = memory.baseAddress() + 64;

            long beforeMillis = System.currentTimeMillis();
            setSyscall(state, SYS_CLOCK_GETTIME, CLOCK_REALTIME, timespecAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            long afterMillis = System.currentTimeMillis();

            assertEquals(0, state.register(10));
            long realtimeSeconds = memory.readLong(timespecAddress);
            long realtimeNanoseconds = memory.readLong(timespecAddress + Long.BYTES);
            assertTrue(realtimeNanoseconds >= 0);
            assertTrue(realtimeNanoseconds < 1_000_000_000L);
            long realtimeMillis = realtimeSeconds * 1000L + realtimeNanoseconds / 1_000_000L;
            assertTrue(realtimeMillis >= beforeMillis - 1000L);
            assertTrue(realtimeMillis <= afterMillis + 1000L);

            memory.writeLong(timespecAddress, -1);
            memory.writeLong(timespecAddress + Long.BYTES, -1);
            setSyscall(state, SYS_CLOCK_GETTIME, CLOCK_MONOTONIC, timespecAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertTrue(memory.readLong(timespecAddress) >= 0);
            assertTrue(memory.readLong(timespecAddress + Long.BYTES) >= 0);
            assertTrue(memory.readLong(timespecAddress + Long.BYTES) < 1_000_000_000L);
        }
    }

    /// Verifies that a configured fixed time source makes `clock_gettime` deterministic.
    @Test
    public void clockGettimeUsesConfiguredTimeSource() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            TimeSource fixedTimeSource = TimeSource.fixed(Instant.ofEpochSecond(1_700_000_000L, 123_456_789L));
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]), fixedTimeSource);
            long timespecAddress = memory.baseAddress() + 64;

            setSyscall(state, SYS_CLOCK_GETTIME, CLOCK_REALTIME, timespecAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(1_700_000_000L, memory.readLong(timespecAddress));
            assertEquals(123_456_789L, memory.readLong(timespecAddress + Long.BYTES));

            setSyscall(state, SYS_CLOCK_GETTIME, CLOCK_MONOTONIC, timespecAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readLong(timespecAddress));
            assertEquals(0, memory.readLong(timespecAddress + Long.BYTES));

            setSyscall(state, SYS_CLOCK_GETTIME, CLOCK_BOOTTIME, timespecAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readLong(timespecAddress));
            assertEquals(0, memory.readLong(timespecAddress + Long.BYTES));

            memory.writeLong(timespecAddress, -1);
            setSyscall(state, SYS_CLOCK_GETTIME, 99, timespecAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
            assertEquals(-1, memory.readLong(timespecAddress));
        }
    }

    /// Verifies deterministic clock resolution reporting for supported clocks.
    @Test
    public void clockGetresReportsSupportedClockResolution() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long timespecAddress = memory.baseAddress() + 64;

            memory.writeLong(timespecAddress, -1);
            memory.writeLong(timespecAddress + Long.BYTES, -1);
            setSyscall(state, SYS_CLOCK_GETRES, CLOCK_REALTIME, timespecAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readLong(timespecAddress));
            assertEquals(1, memory.readLong(timespecAddress + Long.BYTES));

            setSyscall(state, SYS_CLOCK_GETRES, CLOCK_MONOTONIC, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.writeLong(timespecAddress, -1);
            setSyscall(state, SYS_CLOCK_GETRES, 99, timespecAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
            assertEquals(-1, memory.readLong(timespecAddress));
        }
    }

    /// Verifies that `gettimeofday` uses the configured guest time source.
    @Test
    public void gettimeofdayUsesConfiguredTimeSource() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            TimeSource fixedTimeSource = TimeSource.fixed(Instant.ofEpochSecond(1_700_000_000L, 987_654_321L));
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]), fixedTimeSource);
            long timevalAddress = memory.baseAddress() + 64;
            long timezoneAddress = memory.baseAddress() + 80;

            memory.writeInt(timezoneAddress + TIMEZONE_MINUTESWEST_OFFSET, -1);
            memory.writeInt(timezoneAddress + TIMEZONE_DSTTIME_OFFSET, -1);
            setSyscall(state, SYS_GETTIMEOFDAY, timevalAddress, timezoneAddress, 0);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(0, state.register(10));
            assertEquals(1_700_000_000L, memory.readLong(timevalAddress + TIMEVAL_SECONDS_OFFSET));
            assertEquals(987_654L, memory.readLong(timevalAddress + TIMEVAL_MICROSECONDS_OFFSET));
            assertEquals(0, memory.readInt(timezoneAddress + TIMEZONE_MINUTESWEST_OFFSET));
            assertEquals(0, memory.readInt(timezoneAddress + TIMEZONE_DSTTIME_OFFSET));

            setSyscall(state, SYS_GETTIMEOFDAY, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
        }
    }

    /// Verifies that `getitimer` and `setitimer` report tracked interval timer state.
    @Test
    public void intervalTimersReportAndUpdateState() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            TimeSource fixedTimeSource = TimeSource.fixed(Instant.ofEpochSecond(1_700_000_000L));
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]), fixedTimeSource);
            long currentValueAddress = memory.baseAddress() + 64;
            long newValueAddress = memory.baseAddress() + 128;
            long oldValueAddress = memory.baseAddress() + 192;

            setSyscall(state, SYS_GETITIMER, ITIMER_REAL, currentValueAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertItimerval(memory, currentValueAddress, 0, 0, 0, 0);

            writeItimerval(memory, newValueAddress, 2, 30, 5, 40);
            writeItimerval(memory, oldValueAddress, -1, -1, -1, -1);
            setSyscall(state, SYS_SETITIMER, ITIMER_REAL, newValueAddress, oldValueAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertItimerval(memory, oldValueAddress, 0, 0, 0, 0);

            writeItimerval(memory, currentValueAddress, -1, -1, -1, -1);
            setSyscall(state, SYS_GETITIMER, ITIMER_REAL, currentValueAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertItimerval(memory, currentValueAddress, 2, 30, 5, 40);

            writeItimerval(memory, newValueAddress, 1, 2, 3, 4);
            setSyscall(state, SYS_SETITIMER, ITIMER_VIRTUAL, newValueAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETITIMER, ITIMER_VIRTUAL, currentValueAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertItimerval(memory, currentValueAddress, 1, 2, 3, 4);
        }
    }

    /// Verifies that `getitimer` and `setitimer` validate timer selectors, pointers, and time values.
    @Test
    public void intervalTimersValidateArguments() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long currentValueAddress = memory.baseAddress() + 64;
            long newValueAddress = memory.baseAddress() + 128;
            long oldValueAddress = memory.baseAddress() + 192;
            long invalidAddress = memory.endAddress();

            writeItimerval(memory, newValueAddress, 0, 0, 1, 0);

            setSyscall(state, SYS_GETITIMER, ITIMER_PROF + 1, currentValueAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_GETITIMER, ITIMER_REAL, invalidAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));

            setSyscall(state, SYS_SETITIMER, ITIMER_PROF + 1, newValueAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_SETITIMER, ITIMER_REAL, invalidAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));

            setSyscall(state, SYS_SETITIMER, ITIMER_REAL, newValueAddress, invalidAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));

            writeItimerval(memory, newValueAddress, 0, 1_000_000L, 1, 0);
            setSyscall(state, SYS_SETITIMER, ITIMER_REAL, newValueAddress, oldValueAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            writeItimerval(memory, newValueAddress, -1, 0, 1, 0);
            setSyscall(state, SYS_SETITIMER, ITIMER_REAL, newValueAddress, oldValueAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            writeItimerval(memory, newValueAddress, 0, 0, Long.MAX_VALUE, 0);
            setSyscall(state, SYS_SETITIMER, ITIMER_REAL, newValueAddress, oldValueAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies deterministic `sysinfo` memory, load, and process metadata.
    @Test
    public void sysinfoReportsSyntheticSystemMetadata() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long sysinfoAddress = memory.baseAddress() + 128;

            setSyscall(state, SYS_SYSINFO, sysinfoAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertTrue(memory.readLong(sysinfoAddress + SYSINFO_UPTIME_OFFSET) >= 0);
            assertEquals(0, memory.readLong(sysinfoAddress + SYSINFO_LOADS_OFFSET));
            assertEquals(0, memory.readLong(sysinfoAddress + SYSINFO_LOADS_OFFSET + Long.BYTES));
            assertEquals(0, memory.readLong(sysinfoAddress + SYSINFO_LOADS_OFFSET + 2L * Long.BYTES));
            assertEquals(memory.size(), memory.readLong(sysinfoAddress + SYSINFO_TOTAL_RAM_OFFSET));
            assertTrue(memory.readLong(sysinfoAddress + SYSINFO_FREE_RAM_OFFSET) <= memory.size());
            assertEquals(0, memory.readLong(sysinfoAddress + SYSINFO_SHARED_RAM_OFFSET));
            assertEquals(0, memory.readLong(sysinfoAddress + SYSINFO_BUFFER_RAM_OFFSET));
            assertEquals(0, memory.readLong(sysinfoAddress + SYSINFO_TOTAL_SWAP_OFFSET));
            assertEquals(0, memory.readLong(sysinfoAddress + SYSINFO_FREE_SWAP_OFFSET));
            assertEquals(1, memory.readUnsignedShort(sysinfoAddress + SYSINFO_PROCESSES_OFFSET));
            assertEquals(0, memory.readLong(sysinfoAddress + SYSINFO_TOTAL_HIGH_OFFSET));
            assertEquals(0, memory.readLong(sysinfoAddress + SYSINFO_FREE_HIGH_OFFSET));
            assertEquals(1, memory.readInt(sysinfoAddress + SYSINFO_MEMORY_UNIT_OFFSET));

            setSyscall(state, SYS_SYSINFO, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));
        }
    }

    /// Verifies `clock_nanosleep` validation and deterministic elapsed clock handling.
    @Test
    public void clockNanosleepHandlesRelativeAndAbsoluteRequests() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            TimeSource fixedTimeSource = TimeSource.fixed(Instant.ofEpochSecond(1_700_000_000L, 123_456_789L));
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]), fixedTimeSource);
            long requestAddress = memory.baseAddress() + 64;
            long remainingAddress = memory.baseAddress() + 80;

            memory.writeLong(requestAddress, 0);
            memory.writeLong(requestAddress + Long.BYTES, 0);
            setSyscall(state, SYS_CLOCK_NANOSLEEP, CLOCK_MONOTONIC, 0, requestAddress, remainingAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.writeLong(requestAddress, 1_699_999_999L);
            memory.writeLong(requestAddress + Long.BYTES, 999_999_999L);
            setSyscall(state, SYS_CLOCK_NANOSLEEP, CLOCK_REALTIME, TIMER_ABSTIME, requestAddress, remainingAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.writeLong(requestAddress, 0);
            memory.writeLong(requestAddress + Long.BYTES, 1_000_000_000L);
            setSyscall(state, SYS_CLOCK_NANOSLEEP, CLOCK_MONOTONIC, 0, requestAddress, remainingAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            memory.writeLong(requestAddress + Long.BYTES, 0);
            setSyscall(state, SYS_CLOCK_NANOSLEEP, 99, 0, requestAddress, remainingAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_CLOCK_NANOSLEEP, CLOCK_MONOTONIC, 2, requestAddress, remainingAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_CLOCK_NANOSLEEP, CLOCK_THREAD_CPUTIME_ID, 0, requestAddress, remainingAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_CLOCK_NANOSLEEP, CLOCK_PROCESS_CPUTIME_ID, 0, requestAddress, remainingAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOTSUP, state.register(10));
        }
    }

    /// Verifies `times` reports deterministic process CPU ticks.
    @Test
    public void timesUsesConfiguredTimeSource() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            TimeSource fixedTimeSource = TimeSource.fixed(Instant.ofEpochSecond(1_700_000_000L));
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]), fixedTimeSource);
            long tmsAddress = memory.baseAddress() + 64;

            memory.writeLong(tmsAddress + TMS_USER_TIME_OFFSET, -1);
            memory.writeLong(tmsAddress + TMS_SYSTEM_TIME_OFFSET, -1);
            memory.writeLong(tmsAddress + TMS_CHILD_USER_TIME_OFFSET, -1);
            memory.writeLong(tmsAddress + TMS_CHILD_SYSTEM_TIME_OFFSET, -1);
            setSyscall(state, SYS_TIMES, tmsAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(0, state.register(10));
            assertEquals(0, memory.readLong(tmsAddress + TMS_USER_TIME_OFFSET));
            assertEquals(0, memory.readLong(tmsAddress + TMS_SYSTEM_TIME_OFFSET));
            assertEquals(0, memory.readLong(tmsAddress + TMS_CHILD_USER_TIME_OFFSET));
            assertEquals(0, memory.readLong(tmsAddress + TMS_CHILD_SYSTEM_TIME_OFFSET));

            setSyscall(state, SYS_TIMES, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
        }
    }

    /// Verifies `getrusage` reports deterministic zero usage for a fixed clock.
    @Test
    public void getrusageUsesConfiguredTimeSource() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            TimeSource fixedTimeSource = TimeSource.fixed(Instant.ofEpochSecond(1_700_000_000L));
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]), fixedTimeSource);
            long rusageAddress = memory.baseAddress() + 64;

            memory.writeLong(rusageAddress + RUSAGE_USER_TIME_OFFSET, -1);
            memory.writeLong(rusageAddress + RUSAGE_SYSTEM_TIME_OFFSET, -1);
            setSyscall(state, SYS_GETRUSAGE, RUSAGE_SELF, rusageAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readLong(rusageAddress + RUSAGE_USER_TIME_OFFSET + TIMEVAL_SECONDS_OFFSET));
            assertEquals(0, memory.readLong(rusageAddress + RUSAGE_USER_TIME_OFFSET + TIMEVAL_MICROSECONDS_OFFSET));
            assertEquals(0, memory.readLong(rusageAddress + RUSAGE_SYSTEM_TIME_OFFSET + TIMEVAL_SECONDS_OFFSET));
            assertEquals(0, memory.readLong(rusageAddress + RUSAGE_SYSTEM_TIME_OFFSET + TIMEVAL_MICROSECONDS_OFFSET));

            memory.writeLong(rusageAddress + RUSAGE_USER_TIME_OFFSET, -1);
            setSyscall(state, SYS_GETRUSAGE, RUSAGE_CHILDREN, rusageAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readLong(rusageAddress + RUSAGE_USER_TIME_OFFSET + TIMEVAL_SECONDS_OFFSET));

            setSyscall(state, SYS_GETRUSAGE, RUSAGE_THREAD, rusageAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETRUSAGE, 99, rusageAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies `prlimit64` reports and lowers tracked resource limits.
    @Test
    public void prlimit64ReportsAndUpdatesResourceLimits() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long newLimitAddress = memory.baseAddress() + 64;
            long oldLimitAddress = memory.baseAddress() + 80;

            setSyscall(state, SYS_PRLIMIT64, 0, RLIMIT_STACK, 0, oldLimitAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(DEFAULT_STACK_LIMIT, memory.readLong(oldLimitAddress + RLIMIT_CURRENT_OFFSET));
            assertEquals(RLIM_INFINITY, memory.readLong(oldLimitAddress + RLIMIT_MAXIMUM_OFFSET));

            memory.writeLong(newLimitAddress + RLIMIT_CURRENT_OFFSET, 512);
            memory.writeLong(newLimitAddress + RLIMIT_MAXIMUM_OFFSET, DEFAULT_OPEN_FILE_LIMIT);
            setSyscall(state, SYS_PRLIMIT64, 0, RLIMIT_NOFILE, newLimitAddress, oldLimitAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(DEFAULT_OPEN_FILE_LIMIT, memory.readLong(oldLimitAddress + RLIMIT_CURRENT_OFFSET));
            assertEquals(DEFAULT_OPEN_FILE_LIMIT, memory.readLong(oldLimitAddress + RLIMIT_MAXIMUM_OFFSET));

            setSyscall(state, SYS_PRLIMIT64, 0, RLIMIT_NOFILE, 0, oldLimitAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(512, memory.readLong(oldLimitAddress + RLIMIT_CURRENT_OFFSET));
            assertEquals(DEFAULT_OPEN_FILE_LIMIT, memory.readLong(oldLimitAddress + RLIMIT_MAXIMUM_OFFSET));

            memory.writeLong(newLimitAddress + RLIMIT_CURRENT_OFFSET, 2048);
            memory.writeLong(newLimitAddress + RLIMIT_MAXIMUM_OFFSET, 2048);
            setSyscall(state, SYS_PRLIMIT64, 0, RLIMIT_NOFILE, newLimitAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EPERM, state.register(10));

            setSyscall(state, SYS_PRLIMIT64, 99, RLIMIT_NOFILE, 0, oldLimitAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ESRCH, state.register(10));
        }
    }

    /// Verifies `getrlimit` and `setrlimit` share the tracked `prlimit64` resource limits.
    @Test
    public void getrlimitAndSetrlimitShareResourceLimits() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long limitAddress = memory.baseAddress() + 64;
            long oldLimitAddress = memory.baseAddress() + 96;

            setSyscall(state, SYS_GETRLIMIT, RLIMIT_STACK, limitAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(DEFAULT_STACK_LIMIT, memory.readLong(limitAddress + RLIMIT_CURRENT_OFFSET));
            assertEquals(RLIM_INFINITY, memory.readLong(limitAddress + RLIMIT_MAXIMUM_OFFSET));

            memory.writeLong(limitAddress + RLIMIT_CURRENT_OFFSET, 256);
            memory.writeLong(limitAddress + RLIMIT_MAXIMUM_OFFSET, 512);
            setSyscall(state, SYS_SETRLIMIT, RLIMIT_NOFILE, limitAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PRLIMIT64, 0, RLIMIT_NOFILE, 0, oldLimitAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(256, memory.readLong(oldLimitAddress + RLIMIT_CURRENT_OFFSET));
            assertEquals(512, memory.readLong(oldLimitAddress + RLIMIT_MAXIMUM_OFFSET));

            memory.writeLong(limitAddress + RLIMIT_CURRENT_OFFSET, 1024);
            memory.writeLong(limitAddress + RLIMIT_MAXIMUM_OFFSET, 1024);
            setSyscall(state, SYS_SETRLIMIT, RLIMIT_NOFILE, limitAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EPERM, state.register(10));

            setSyscall(state, SYS_GETRLIMIT, 99, limitAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies `prctl` process-name truncation and retrieval.
    @Test
    public void prctlSupportsProcessName() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long inputAddress = memory.baseAddress() + 64;
            long outputAddress = memory.baseAddress() + 128;

            writeGuestString(memory, inputAddress, "0123456789abcdefghi");
            setSyscall(state, SYS_PRCTL, PR_SET_NAME, inputAddress, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_GET_NAME, outputAddress, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertArrayEquals(
                    new byte[]{
                            '0', '1', '2', '3', '4', '5', '6', '7',
                            '8', '9', 'a', 'b', 'c', 'd', 'e', 0
                    },
                    memory.readBytes(outputAddress, 16));

            setSyscall(state, SYS_PRCTL, PR_SET_NAME, inputAddress, 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies `PR_GET_AUXV` copies the captured initial Linux auxiliary vector.
    @Test
    public void prctlReturnsInitialAuxiliaryVector() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long stackPointer = memory.baseAddress() + 64;
            long bufferAddress = memory.baseAddress() + 256;

            memory.writeLong(stackPointer, 1);
            memory.writeLong(stackPointer + Long.BYTES, memory.baseAddress() + 512);
            memory.writeLong(stackPointer + 2L * Long.BYTES, 0);
            memory.writeLong(stackPointer + 3L * Long.BYTES, 0);
            memory.writeLong(stackPointer + 4L * Long.BYTES, AT_PAGESZ);
            memory.writeLong(stackPointer + 5L * Long.BYTES, 4096);
            memory.writeLong(stackPointer + 6L * Long.BYTES, AT_NULL);
            memory.writeLong(stackPointer + 7L * Long.BYTES, 0);
            state.syscalls().recordInitialAuxiliaryVector(stackPointer);

            setSyscall(state, SYS_PRCTL, PR_GET_AUXV, bufferAddress, 512, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4L * Long.BYTES, state.register(10));
            assertEquals(AT_PAGESZ, memory.readLong(bufferAddress));
            assertEquals(4096, memory.readLong(bufferAddress + Long.BYTES));
            assertEquals(AT_NULL, memory.readLong(bufferAddress + 2L * Long.BYTES));
            assertEquals(0, memory.readLong(bufferAddress + 3L * Long.BYTES));

            setSyscall(state, SYS_PRCTL, PR_GET_AUXV, 0, Long.BYTES, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4L * Long.BYTES, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_GET_AUXV, 0, 512, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));
        }
    }

    /// Verifies the virtual proc filesystem exposes deterministic process metadata.
    @Test
    public void procfsExposesVirtualProcessMetadata() throws Exception {
        Files.writeString(tempDirectory.resolve("program"), "exe", StandardCharsets.UTF_8);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 8192)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    tempDirectory);
            long stackPointer = memory.baseAddress() + 64;
            long pathAddress = memory.baseAddress() + 1024;
            long bufferAddress = memory.baseAddress() + 2048;
            long statfsAddress = memory.baseAddress() + 4096;
            long executableAddress = memory.baseAddress() + 6144;
            long argumentAddress = memory.baseAddress() + 6208;
            long environmentAddress = memory.baseAddress() + 6272;

            writeGuestString(memory, executableAddress, "/program");
            writeGuestString(memory, argumentAddress, "--flag");
            writeGuestString(memory, environmentAddress, "KEY=value");
            memory.writeLong(stackPointer, 2);
            memory.writeLong(stackPointer + Long.BYTES, executableAddress);
            memory.writeLong(stackPointer + 2L * Long.BYTES, argumentAddress);
            memory.writeLong(stackPointer + 3L * Long.BYTES, 0);
            memory.writeLong(stackPointer + 4L * Long.BYTES, environmentAddress);
            memory.writeLong(stackPointer + 5L * Long.BYTES, 0);
            memory.writeLong(stackPointer + 6L * Long.BYTES, AT_PAGESZ);
            memory.writeLong(stackPointer + 7L * Long.BYTES, PAGE_SIZE);
            memory.writeLong(stackPointer + 8L * Long.BYTES, AT_EXECFN);
            memory.writeLong(stackPointer + 9L * Long.BYTES, executableAddress);
            memory.writeLong(stackPointer + 10L * Long.BYTES, AT_NULL);
            memory.writeLong(stackPointer + 11L * Long.BYTES, 0);
            state.syscalls().recordInitialAuxiliaryVector(stackPointer);

            writeGuestString(memory, pathAddress, "/proc/self/cmdline");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int commandLineFileDescriptor = (int) state.register(10);
            assertEquals(3, commandLineFileDescriptor);

            byte[] commandLine = "/program\0--flag\0".getBytes(StandardCharsets.UTF_8);
            setSyscall(state, SYS_READ, commandLineFileDescriptor, bufferAddress, commandLine.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(commandLine.length, state.register(10));
            assertArrayEquals(commandLine, memory.readBytes(bufferAddress, commandLine.length));

            writeGuestString(memory, pathAddress, "/proc/self/environ");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int environmentFileDescriptor = (int) state.register(10);
            assertEquals(4, environmentFileDescriptor);

            byte[] environment = "KEY=value\0".getBytes(StandardCharsets.UTF_8);
            setSyscall(state, SYS_READ, environmentFileDescriptor, bufferAddress, environment.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(environment.length, state.register(10));
            assertArrayEquals(environment, memory.readBytes(bufferAddress, environment.length));

            writeGuestString(memory, pathAddress, "/proc/self/mountinfo");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int mountinfoFileDescriptor = (int) state.register(10);
            assertEquals(5, mountinfoFileDescriptor);

            byte[] mountinfo = "1 0 0:1 / / rw,relatime - jriscv jriscv rw\n".getBytes(StandardCharsets.UTF_8);
            setSyscall(state, SYS_READ, mountinfoFileDescriptor, bufferAddress, mountinfo.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(mountinfo.length, state.register(10));
            assertArrayEquals(mountinfo, memory.readBytes(bufferAddress, mountinfo.length));

            setSyscall(state, SYS_CLOSE, mountinfoFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "/proc/mounts");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int mountsFileDescriptor = (int) state.register(10);
            assertEquals(5, mountsFileDescriptor);

            byte[] mounts = "jriscv / jriscv rw,relatime 0 0\n".getBytes(StandardCharsets.UTF_8);
            setSyscall(state, SYS_READ, mountsFileDescriptor, bufferAddress, mounts.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(mounts.length, state.register(10));
            assertArrayEquals(mounts, memory.readBytes(bufferAddress, mounts.length));

            setSyscall(state, SYS_CLOSE, mountsFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "/proc/self");
            setSyscall(state, SYS_READLINKAT, AT_FDCWD, pathAddress, bufferAddress, 64);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));
            assertArrayEquals("1".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 1));

            writeGuestString(memory, pathAddress, "/proc/self/exe");
            setSyscall(state, SYS_READLINKAT, AT_FDCWD, pathAddress, bufferAddress, 64);
            state.syscalls().handle(state, TEST_PC);
            assertEquals("/program".length(), state.register(10));
            assertArrayEquals(
                    "/program".getBytes(StandardCharsets.UTF_8),
                    memory.readBytes(bufferAddress, "/program".length()));

            writeGuestString(memory, pathAddress, "/proc/self/fd/3");
            setSyscall(state, SYS_READLINKAT, AT_FDCWD, pathAddress, bufferAddress, 64);
            state.syscalls().handle(state, TEST_PC);
            assertEquals("/proc/1/cmdline".length(), state.register(10));
            assertArrayEquals(
                    "/proc/1/cmdline".getBytes(StandardCharsets.UTF_8),
                    memory.readBytes(bufferAddress, "/proc/1/cmdline".length()));

            writeGuestString(memory, pathAddress, "/proc/self/exe");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int executableFileDescriptor = (int) state.register(10);
            assertEquals(5, executableFileDescriptor);

            setSyscall(state, SYS_READ, executableFileDescriptor, bufferAddress, 3);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(3, state.register(10));
            assertArrayEquals("exe".getBytes(StandardCharsets.UTF_8), memory.readBytes(bufferAddress, 3));

            setSyscall(state, SYS_CLOSE, executableFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "/proc");
            setSyscall(state, SYS_STATFS, pathAddress, statfsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertProcStatfs(memory, statfsAddress);

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            int procDirectoryFileDescriptor = (int) state.register(10);
            assertEquals(5, procDirectoryFileDescriptor);

            setSyscall(state, SYS_FSTATFS, procDirectoryFileDescriptor, statfsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertProcStatfs(memory, statfsAddress);

            setSyscall(state, SYS_GETDENTS64, procDirectoryFileDescriptor, bufferAddress, 512);
            state.syscalls().handle(state, TEST_PC);
            assertTrue(state.register(10) > 0);
            long nextEntry = assertDirectoryEntry(memory, bufferAddress, ".", DIRECTORY_ENTRY_DIRECTORY, 1);
            nextEntry = assertDirectoryEntry(memory, nextEntry, "..", DIRECTORY_ENTRY_DIRECTORY, 2);
            nextEntry = assertDirectoryEntry(memory, nextEntry, "1", DIRECTORY_ENTRY_DIRECTORY, 3);
            nextEntry = assertDirectoryEntry(memory, nextEntry, "cpuinfo", DIRECTORY_ENTRY_REGULAR_FILE, 4);
            nextEntry = assertDirectoryEntry(memory, nextEntry, "meminfo", DIRECTORY_ENTRY_REGULAR_FILE, 5);
            nextEntry = assertDirectoryEntry(memory, nextEntry, "mounts", DIRECTORY_ENTRY_SYMBOLIC_LINK, 6);
            assertDirectoryEntry(memory, nextEntry, "self", DIRECTORY_ENTRY_SYMBOLIC_LINK, 7);
        }
    }

    /// Verifies `/proc/cpuinfo` exposes virtual CPU metadata and host Java runtime summary fields.
    @Test
    public void procCpuinfoExposesJavaRuntimeSummary() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 1024;

            writeGuestString(memory, pathAddress, "/proc/cpuinfo");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int fileDescriptor = (int) state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_READ, fileDescriptor, bufferAddress, 2048);
            state.syscalls().handle(state, TEST_PC);
            int count = (int) state.register(10);
            assertTrue(count > 0);

            String cpuinfo = readGuestString(memory, bufferAddress, count);
            assertTrue(cpuinfo.contains("processor\t: 0\n"));
            assertTrue(cpuinfo.contains("isa\t\t: rv64imafdc_zicsr_zifencei_zba_zbb_zbs_v\n"));
            assertTrue(cpuinfo.contains("mmu\t\t: sv48\n"));
            assertTrue(cpuinfo.contains("uarch\t\t: glavo,jriscv\n"));
            assertTrue(cpuinfo.contains("java_version\t: "));
            assertTrue(cpuinfo.contains("java_vm_name\t: "));
            assertTrue(cpuinfo.contains("java_vm_version\t: "));
            assertTrue(cpuinfo.contains("java_vendor\t: "));

            setSyscall(state, SYS_CLOSE, fileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
        }
    }

    /// Verifies the built-in sysfs exposes minimal hardware identity and empty class directories.
    @Test
    public void defaultSysFilesystemExposesMinimalHardwareTree() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 8192)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 1024;
            long statfsAddress = memory.baseAddress() + 4096;

            writeGuestString(memory, pathAddress, "/sys");
            setSyscall(state, SYS_STATFS, pathAddress, statfsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertSysfsStatfs(memory, statfsAddress);

            writeGuestString(memory, pathAddress, "/sys/class");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            int classDirectoryFileDescriptor = (int) state.register(10);
            assertEquals(3, classDirectoryFileDescriptor);

            setSyscall(state, SYS_GETDENTS64, classDirectoryFileDescriptor, bufferAddress, 512);
            state.syscalls().handle(state, TEST_PC);
            assertTrue(state.register(10) > 0);
            long nextEntry = assertDirectoryEntry(memory, bufferAddress, ".", DIRECTORY_ENTRY_DIRECTORY, 1);
            nextEntry = assertDirectoryEntry(memory, nextEntry, "..", DIRECTORY_ENTRY_DIRECTORY, 2);
            nextEntry = assertDirectoryEntry(memory, nextEntry, "dmi", DIRECTORY_ENTRY_DIRECTORY, 3);
            nextEntry = assertDirectoryEntry(memory, nextEntry, "drm", DIRECTORY_ENTRY_DIRECTORY, 4);
            nextEntry = assertDirectoryEntry(memory, nextEntry, "graphics", DIRECTORY_ENTRY_DIRECTORY, 5);
            assertDirectoryEntry(memory, nextEntry, "power_supply", DIRECTORY_ENTRY_DIRECTORY, 6);

            setSyscall(state, SYS_CLOSE, classDirectoryFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "/sys/bus/pci/devices");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            int pciDevicesDirectoryFileDescriptor = (int) state.register(10);
            assertEquals(3, pciDevicesDirectoryFileDescriptor);

            setSyscall(state, SYS_FSTATFS, pciDevicesDirectoryFileDescriptor, statfsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertSysfsStatfs(memory, statfsAddress);

            setSyscall(state, SYS_GETDENTS64, pciDevicesDirectoryFileDescriptor, bufferAddress, 512);
            state.syscalls().handle(state, TEST_PC);
            assertTrue(state.register(10) > 0);
            nextEntry = assertDirectoryEntry(memory, bufferAddress, ".", DIRECTORY_ENTRY_DIRECTORY, 1);
            assertDirectoryEntry(memory, nextEntry, "..", DIRECTORY_ENTRY_DIRECTORY, 2);

            setSyscall(state, SYS_CLOSE, pciDevicesDirectoryFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "/sys/class/power_supply");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            int powerSupplyDirectoryFileDescriptor = (int) state.register(10);
            assertEquals(3, powerSupplyDirectoryFileDescriptor);

            setSyscall(state, SYS_FSTATFS, powerSupplyDirectoryFileDescriptor, statfsAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertSysfsStatfs(memory, statfsAddress);

            setSyscall(state, SYS_GETDENTS64, powerSupplyDirectoryFileDescriptor, bufferAddress, 512);
            state.syscalls().handle(state, TEST_PC);
            assertTrue(state.register(10) > 0);
            nextEntry = assertDirectoryEntry(memory, bufferAddress, ".", DIRECTORY_ENTRY_DIRECTORY, 1);
            assertDirectoryEntry(memory, nextEntry, "..", DIRECTORY_ENTRY_DIRECTORY, 2);

            setSyscall(state, SYS_CLOSE, powerSupplyDirectoryFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "/sys/devices/virtual/dmi/id/product_name");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int productNameFileDescriptor = (int) state.register(10);
            assertEquals(3, productNameFileDescriptor);

            setSyscall(state, SYS_READ, productNameFileDescriptor, bufferAddress, 64);
            state.syscalls().handle(state, TEST_PC);
            assertEquals("JRISC-V\n".length(), state.register(10));
            assertEquals("JRISC-V\n", readGuestString(memory, bufferAddress, "JRISC-V\n".length()));

            setSyscall(state, SYS_CLOSE, productNameFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            writeGuestString(memory, pathAddress, "/sys/class/dmi/id/sys_vendor");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int vendorFileDescriptor = (int) state.register(10);
            assertEquals(3, vendorFileDescriptor);

            setSyscall(state, SYS_READ, vendorFileDescriptor, bufferAddress, 64);
            state.syscalls().handle(state, TEST_PC);
            assertEquals("Glavo\n".length(), state.register(10));
            assertEquals("Glavo\n", readGuestString(memory, bufferAddress, "Glavo\n".length()));

            setSyscall(state, SYS_CLOSE, vendorFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
        }
    }

    /// Verifies minimal `NETLINK_ROUTE` sockets expose a loopback interface dump.
    @Test
    public void netlinkRouteSocketReportsLoopbackInterfaceDump() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 8192)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long sockaddrAddress = memory.baseAddress();
            long lengthAddress = memory.baseAddress() + 64;
            long requestAddress = memory.baseAddress() + 128;
            long messageAddress = memory.baseAddress() + 256;
            long iovecAddress = memory.baseAddress() + 384;
            long responseAddress = memory.baseAddress() + 512;

            setSyscall(state, SYS_SOCKET, AF_NETLINK, SOCK_RAW | O_CLOEXEC, NETLINK_ROUTE);
            state.syscalls().handle(state, TEST_PC);
            int socketFileDescriptor = (int) state.register(10);
            assertEquals(3, socketFileDescriptor);

            memory.clear(sockaddrAddress, SOCKADDR_NL_SIZE);
            memory.writeShort(sockaddrAddress, (short) AF_NETLINK);
            setSyscall(state, SYS_BIND, socketFileDescriptor, sockaddrAddress, SOCKADDR_NL_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.writeInt(lengthAddress, SOCKADDR_NL_SIZE);
            setSyscall(state, SYS_GETSOCKNAME, socketFileDescriptor, sockaddrAddress, lengthAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(SOCKADDR_NL_SIZE, memory.readInt(lengthAddress));
            long portId = Integer.toUnsignedLong(memory.readInt(sockaddrAddress + SOCKADDR_NL_PID_OFFSET));
            assertTrue(portId > 0);
            assertEquals(0, memory.readInt(sockaddrAddress + SOCKADDR_NL_GROUPS_OFFSET));

            writeNetlinkRequest(memory, requestAddress, RTM_GETLINK, 11);
            setSyscall(state, SYS_SENDTO, socketFileDescriptor, requestAddress, 16, 0, sockaddrAddress, SOCKADDR_NL_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(16, state.register(10));

            prepareRecvmsg(memory, messageAddress, sockaddrAddress, iovecAddress, responseAddress, 512);
            setSyscall(state, SYS_RECVMSG, socketFileDescriptor, messageAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertTrue(state.register(10) > 0);
            assertEquals(RTM_NEWLINK, memory.readUnsignedShort(responseAddress + NETLINK_HEADER_TYPE_OFFSET));
            assertEquals(11, memory.readInt(responseAddress + NETLINK_HEADER_SEQUENCE_OFFSET));
            assertEquals(portId, Integer.toUnsignedLong(memory.readInt(responseAddress + NETLINK_HEADER_PORT_ID_OFFSET)));
            assertEquals(LOOPBACK_INTERFACE_INDEX, memory.readInt(responseAddress + NETLINK_LINK_INTERFACE_INDEX_OFFSET));

            prepareRecvmsg(memory, messageAddress, sockaddrAddress, iovecAddress, responseAddress, 512);
            setSyscall(state, SYS_RECVMSG, socketFileDescriptor, messageAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertTrue(state.register(10) > 0);
            assertEquals(RTM_NEWLINK, memory.readUnsignedShort(responseAddress + NETLINK_HEADER_TYPE_OFFSET));
            assertEquals(11, memory.readInt(responseAddress + NETLINK_HEADER_SEQUENCE_OFFSET));
            assertEquals(portId, Integer.toUnsignedLong(memory.readInt(responseAddress + NETLINK_HEADER_PORT_ID_OFFSET)));
            assertEquals(ETHERNET_INTERFACE_INDEX, memory.readInt(responseAddress + NETLINK_LINK_INTERFACE_INDEX_OFFSET));

            prepareRecvmsg(memory, messageAddress, sockaddrAddress, iovecAddress, responseAddress, 512);
            setSyscall(state, SYS_RECVMSG, socketFileDescriptor, messageAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertTrue(state.register(10) > 0);
            assertEquals(NETLINK_MESSAGE_DONE, memory.readUnsignedShort(responseAddress + NETLINK_HEADER_TYPE_OFFSET));

            writeNetlinkRequest(memory, requestAddress, RTM_GETADDR, 12);
            setSyscall(state, SYS_SENDTO, socketFileDescriptor, requestAddress, 16, 0, sockaddrAddress, SOCKADDR_NL_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(16, state.register(10));

            prepareRecvmsg(memory, messageAddress, sockaddrAddress, iovecAddress, responseAddress, 512);
            setSyscall(state, SYS_RECVMSG, socketFileDescriptor, messageAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertTrue(state.register(10) > 0);
            assertEquals(RTM_NEWADDR, memory.readUnsignedShort(responseAddress + NETLINK_HEADER_TYPE_OFFSET));
            assertEquals(12, memory.readInt(responseAddress + NETLINK_HEADER_SEQUENCE_OFFSET));
            assertEquals(portId, Integer.toUnsignedLong(memory.readInt(responseAddress + NETLINK_HEADER_PORT_ID_OFFSET)));
            assertEquals(LOOPBACK_INTERFACE_INDEX, memory.readInt(responseAddress + NETLINK_ADDRESS_INTERFACE_INDEX_OFFSET));

            prepareRecvmsg(memory, messageAddress, sockaddrAddress, iovecAddress, responseAddress, 512);
            setSyscall(state, SYS_RECVMSG, socketFileDescriptor, messageAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertTrue(state.register(10) > 0);
            assertEquals(RTM_NEWADDR, memory.readUnsignedShort(responseAddress + NETLINK_HEADER_TYPE_OFFSET));
            assertEquals(12, memory.readInt(responseAddress + NETLINK_HEADER_SEQUENCE_OFFSET));
            assertEquals(portId, Integer.toUnsignedLong(memory.readInt(responseAddress + NETLINK_HEADER_PORT_ID_OFFSET)));
            assertEquals(ETHERNET_INTERFACE_INDEX, memory.readInt(responseAddress + NETLINK_ADDRESS_INTERFACE_INDEX_OFFSET));

            prepareRecvmsg(memory, messageAddress, sockaddrAddress, iovecAddress, responseAddress, 512);
            setSyscall(state, SYS_RECVMSG, socketFileDescriptor, messageAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertTrue(state.register(10) > 0);
            assertEquals(NETLINK_MESSAGE_DONE, memory.readUnsignedShort(responseAddress + NETLINK_HEADER_TYPE_OFFSET));

            writeNetlinkRequest(memory, requestAddress, RTM_GETROUTE, 13);
            setSyscall(state, SYS_SENDTO, socketFileDescriptor, requestAddress, 16, 0, sockaddrAddress, SOCKADDR_NL_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(16, state.register(10));

            prepareRecvmsg(memory, messageAddress, sockaddrAddress, iovecAddress, responseAddress, 512);
            setSyscall(state, SYS_RECVMSG, socketFileDescriptor, messageAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertTrue(state.register(10) > 0);
            assertEquals(RTM_NEWROUTE, memory.readUnsignedShort(responseAddress + NETLINK_HEADER_TYPE_OFFSET));
            assertEquals(13, memory.readInt(responseAddress + NETLINK_HEADER_SEQUENCE_OFFSET));
            assertEquals(portId, Integer.toUnsignedLong(memory.readInt(responseAddress + NETLINK_HEADER_PORT_ID_OFFSET)));

            prepareRecvmsg(memory, messageAddress, sockaddrAddress, iovecAddress, responseAddress, 512);
            setSyscall(state, SYS_RECVMSG, socketFileDescriptor, messageAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertTrue(state.register(10) > 0);
            assertEquals(NETLINK_MESSAGE_DONE, memory.readUnsignedShort(responseAddress + NETLINK_HEADER_TYPE_OFFSET));

            setSyscall(state, SYS_CLOSE, socketFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
        }
    }

    /// Verifies generic network-interface ioctl sockets map synthetic interface names and indexes.
    @Test
    public void networkInterfaceIoctlSocketMapsSyntheticInterfaces() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long ifreqAddress = memory.baseAddress();

            setSyscall(state, SYS_SOCKET, AF_UNIX, SOCK_DGRAM | O_CLOEXEC, 0);
            state.syscalls().handle(state, TEST_PC);
            int socketFileDescriptor = (int) state.register(10);
            assertEquals(3, socketFileDescriptor);

            memory.clear(ifreqAddress, 64);
            memory.writeInt(ifreqAddress + IFREQ_INTERFACE_INDEX_OFFSET, ETHERNET_INTERFACE_INDEX);
            setSyscall(state, SYS_IOCTL, socketFileDescriptor, SIOCGIFNAME, ifreqAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals("eth0", readGuestString(memory, ifreqAddress, "eth0".length()));

            memory.clear(ifreqAddress, 64);
            writeGuestString(memory, ifreqAddress, "lo");
            setSyscall(state, SYS_IOCTL, socketFileDescriptor, SIOCGIFINDEX, ifreqAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(LOOPBACK_INTERFACE_INDEX, memory.readInt(ifreqAddress + IFREQ_INTERFACE_INDEX_OFFSET));

            setSyscall(state, SYS_CLOSE, socketFileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
        }
    }

    /// Verifies host-backed network sockets are disabled unless the host network backend is configured.
    @Test
    public void hostBackedNetworkSocketsRequireHostNetworkBackend() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));

            setSyscall(state, SYS_SOCKET, AF_INET, SOCK_STREAM, IPPROTO_TCP);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAFNOSUPPORT, state.register(10));

            setSyscall(state, SYS_SOCKET, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAFNOSUPPORT, state.register(10));

            setSyscall(state, SYS_SOCKET, AF_UNIX, SOCK_STREAM, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAFNOSUPPORT, state.register(10));
        }
    }

    /// Verifies Unix-domain `socketpair` creates connected in-memory stream sockets.
    @Test
    public void unixStreamSocketpairExchangesBytes() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 8192)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long pairAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 64;
            long iovecAddress = memory.baseAddress() + 256;
            long sockaddrAddress = memory.baseAddress() + 384;
            long lengthAddress = memory.baseAddress() + 512;

            setSyscall(state, SYS_SOCKETPAIR, AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | O_CLOEXEC, 0, pairAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            int firstFileDescriptor = memory.readInt(pairAddress);
            int secondFileDescriptor = memory.readInt(pairAddress + Integer.BYTES);
            assertEquals(3, firstFileDescriptor);
            assertEquals(4, secondFileDescriptor);

            setSyscall(state, SYS_FCNTL, firstFileDescriptor, F_GETFL, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(O_RDWR | O_NONBLOCK, state.register(10));

            setSyscall(state, SYS_RECVFROM, firstFileDescriptor, bufferAddress, 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAGAIN, state.register(10));

            byte[] firstMessage = "ping".getBytes(StandardCharsets.UTF_8);
            memory.writeBytes(bufferAddress, firstMessage, 0, firstMessage.length);
            setSyscall(state, SYS_WRITE, firstFileDescriptor, bufferAddress, firstMessage.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(firstMessage.length, state.register(10));

            setSyscall(state, SYS_READ, secondFileDescriptor, bufferAddress, firstMessage.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(firstMessage.length, state.register(10));
            assertEquals("ping", readGuestString(memory, bufferAddress, firstMessage.length));

            byte[] secondPart1 = "po".getBytes(StandardCharsets.UTF_8);
            byte[] secondPart2 = "ng".getBytes(StandardCharsets.UTF_8);
            memory.writeBytes(bufferAddress, secondPart1, 0, secondPart1.length);
            memory.writeBytes(bufferAddress + 16, secondPart2, 0, secondPart2.length);
            memory.writeLong(iovecAddress + IOVEC_BASE_OFFSET, bufferAddress);
            memory.writeLong(iovecAddress + IOVEC_LENGTH_OFFSET, secondPart1.length);
            memory.writeLong(iovecAddress + IOVEC_SIZE + IOVEC_BASE_OFFSET, bufferAddress + 16);
            memory.writeLong(iovecAddress + IOVEC_SIZE + IOVEC_LENGTH_OFFSET, secondPart2.length);
            setSyscall(state, SYS_WRITEV, secondFileDescriptor, iovecAddress, 2);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(secondPart1.length + secondPart2.length, state.register(10));

            memory.writeInt(lengthAddress, SOCKADDR_UN_SIZE);
            setSyscall(state, SYS_GETPEERNAME, firstFileDescriptor, sockaddrAddress, lengthAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(AF_UNIX, memory.readUnsignedShort(sockaddrAddress));
            assertEquals(SOCKADDR_UN_PATH_OFFSET, memory.readInt(lengthAddress));

            setSyscall(state, SYS_READ, firstFileDescriptor, bufferAddress, 4);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(4, state.register(10));
            assertEquals("pong", readGuestString(memory, bufferAddress, 4));

            setSyscall(state, SYS_SHUTDOWN, firstFileDescriptor, SHUT_WR, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_READ, secondFileDescriptor, bufferAddress, 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
        }
    }

    /// Verifies host networking supports filesystem-backed Unix-domain stream client sockets.
    @Test
    public void hostNetworkUnixStreamClientConnectsToBoundHostSocket() throws Exception {
        Path socketDirectory = tempDirectory.resolve("x11");
        Files.createDirectories(socketDirectory);
        Path socketPath = socketDirectory.resolve("X99");

        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
             Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 8192)) {
            server.bind(UnixDomainSocketAddress.of(socketPath));
            RiscVThreadState state = hostNetworkState(memory, new String[]{
                    "type=bind,src=" + socketDirectory + ",dst=/tmp/.X11-unix,readonly"
            });
            long sockaddrAddress = memory.baseAddress();
            long lengthAddress = memory.baseAddress() + 128;
            long bufferAddress = memory.baseAddress() + 256;
            long optionAddress = memory.baseAddress() + 384;
            long optionLengthAddress = memory.baseAddress() + 392;
            long iovecAddress = memory.baseAddress() + 512;
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> serverTask = executor.submit(() -> {
                    try (SocketChannel socket = server.accept()) {
                        ByteBuffer request = ByteBuffer.allocate(4);
                        readFully(socket, request);
                        assertEquals("ping", new String(request.array(), StandardCharsets.UTF_8));
                        writeFully(socket, ByteBuffer.wrap("pong".getBytes(StandardCharsets.UTF_8)));
                    }
                    return null;
                });

                setSyscall(state, SYS_SOCKET, AF_UNIX, SOCK_STREAM, 0);
                state.syscalls().handle(state, TEST_PC);
                int socketFileDescriptor = (int) state.register(10);
                assertEquals(3, socketFileDescriptor);

                String guestSocketPath = "/tmp/.X11-unix/X99";
                int sockaddrLength = writeUnixSockaddr(memory, sockaddrAddress, guestSocketPath);
                setSyscall(state, SYS_CONNECT, socketFileDescriptor, sockaddrAddress, sockaddrLength);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));

                memory.writeInt(optionLengthAddress, Integer.BYTES);
                setSyscall(state, SYS_GETSOCKOPT, socketFileDescriptor, SOL_SOCKET, SO_ERROR, optionAddress, optionLengthAddress);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));
                assertEquals(0, memory.readInt(optionAddress));

                memory.writeInt(lengthAddress, SOCKADDR_UN_SIZE);
                setSyscall(state, SYS_GETPEERNAME, socketFileDescriptor, sockaddrAddress, lengthAddress);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));
                assertEquals(AF_UNIX, memory.readUnsignedShort(sockaddrAddress));
                assertEquals(guestSocketPath, readGuestCString(
                        memory,
                        sockaddrAddress + SOCKADDR_UN_PATH_OFFSET,
                        SOCKADDR_UN_SIZE - SOCKADDR_UN_PATH_OFFSET));

                byte[] requestPart1 = "pi".getBytes(StandardCharsets.UTF_8);
                byte[] requestPart2 = "ng".getBytes(StandardCharsets.UTF_8);
                memory.writeBytes(bufferAddress, requestPart1, 0, requestPart1.length);
                memory.writeBytes(bufferAddress + 16, requestPart2, 0, requestPart2.length);
                memory.writeLong(iovecAddress + IOVEC_BASE_OFFSET, bufferAddress);
                memory.writeLong(iovecAddress + IOVEC_LENGTH_OFFSET, requestPart1.length);
                memory.writeLong(iovecAddress + IOVEC_SIZE + IOVEC_BASE_OFFSET, bufferAddress + 16);
                memory.writeLong(iovecAddress + IOVEC_SIZE + IOVEC_LENGTH_OFFSET, requestPart2.length);
                setSyscall(state, SYS_WRITEV, socketFileDescriptor, iovecAddress, 2);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(requestPart1.length + requestPart2.length, state.register(10));

                setSyscall(state, SYS_READ, socketFileDescriptor, bufferAddress, 4);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(4, state.register(10));
                assertEquals("pong", readGuestString(memory, bufferAddress, 4));

                setSyscall(state, SYS_CLOSE, socketFileDescriptor, 0, 0);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));
                waitForNetworkTask(serverTask);
            } finally {
                executor.shutdownNow();
                Files.deleteIfExists(socketPath);
            }
        } catch (UnsupportedOperationException exception) {
            assumeTrue(false, "Unix-domain sockets are unavailable: " + exception.getMessage());
        }
    }

    /// Verifies host networking supports IPv4 TCP client sockets.
    @Test
    public void hostNetworkTcpIpv4ClientConnectsToLoopbackServer() throws Exception {
        assertGuestTcpClientEcho(InetAddress.getByName("127.0.0.1"));
    }

    /// Verifies host networking supports IPv6 TCP client sockets.
    @Test
    public void hostNetworkTcpIpv6ClientConnectsToLoopbackServer() throws Exception {
        InetAddress loopback = InetAddress.getByName("::1");
        try (ServerSocket ignored = new ServerSocket(0, 1, loopback)) {
            assertGuestTcpClientEcho(loopback);
        } catch (IOException exception) {
            assumeTrue(false, "IPv6 loopback is unavailable: " + exception.getMessage());
        }
    }

    /// Verifies a guest TCP client can bind a local address before connecting.
    @Test
    public void hostNetworkTcpClientBindBeforeConnectUsesLocalPort() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (ServerSocket server = new ServerSocket(0, 1, loopback);
             Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = hostNetworkState(memory);
            long sockaddrAddress = memory.baseAddress();
            long lengthAddress = memory.baseAddress() + 64;
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<Integer> remotePort = executor.submit(() -> {
                    try (Socket socket = server.accept()) {
                        return socket.getPort();
                    }
                });

                setSyscall(state, SYS_SOCKET, AF_INET, SOCK_STREAM, IPPROTO_TCP);
                state.syscalls().handle(state, TEST_PC);
                int socketFileDescriptor = (int) state.register(10);
                assertEquals(3, socketFileDescriptor);

                writeInetSockaddr(memory, sockaddrAddress, loopback, 0);
                setSyscall(state, SYS_BIND, socketFileDescriptor, sockaddrAddress, SOCKADDR_IN_SIZE);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));

                memory.writeInt(lengthAddress, SOCKADDR_IN_SIZE);
                setSyscall(state, SYS_GETSOCKNAME, socketFileDescriptor, sockaddrAddress, lengthAddress);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));
                int localPort = readNetworkPort(memory, sockaddrAddress + SOCKADDR_PORT_OFFSET);
                assertTrue(localPort > 0);

                writeInetSockaddr(memory, sockaddrAddress, loopback, server.getLocalPort());
                setSyscall(state, SYS_CONNECT, socketFileDescriptor, sockaddrAddress, SOCKADDR_IN_SIZE);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));
                assertEquals(localPort, remotePort.get(5, TimeUnit.SECONDS));
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /// Verifies TCP socket names, options, and duplicate descriptor lifetime.
    @Test
    public void hostNetworkTcpAddressesOptionsAndDupLifetimeWork() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (ServerSocket server = new ServerSocket(0, 1, loopback);
             Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 8192)) {
            RiscVThreadState state = hostNetworkState(memory);
            long sockaddrAddress = memory.baseAddress();
            long lengthAddress = memory.baseAddress() + 64;
            long bufferAddress = memory.baseAddress() + 128;
            long optionAddress = memory.baseAddress() + 256;
            long optionLengthAddress = memory.baseAddress() + 264;
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> serverTask = executor.submit(() -> {
                    try (Socket socket = server.accept()) {
                        byte[] request = socket.getInputStream().readNBytes(4);
                        assertEquals("ping", new String(request, StandardCharsets.UTF_8));
                        socket.getOutputStream().write("pong".getBytes(StandardCharsets.UTF_8));
                        assertEquals(-1, socket.getInputStream().read());
                    }
                    return null;
                });

                setSyscall(state, SYS_SOCKET, AF_INET, SOCK_STREAM, IPPROTO_TCP);
                state.syscalls().handle(state, TEST_PC);
                int socketFileDescriptor = (int) state.register(10);
                assertEquals(3, socketFileDescriptor);

                assertSetAndGetSocketOption(
                        state,
                        memory,
                        socketFileDescriptor,
                        SOL_SOCKET,
                        SO_KEEPALIVE,
                        1,
                        optionAddress,
                        optionLengthAddress);
                assertSetAndGetSocketOption(
                        state,
                        memory,
                        socketFileDescriptor,
                        IPPROTO_TCP,
                        TCP_NODELAY,
                        1,
                        optionAddress,
                        optionLengthAddress);
                assertSetAndGetSocketOption(
                        state,
                        memory,
                        socketFileDescriptor,
                        SOL_SOCKET,
                        SO_SNDBUF,
                        4096,
                        optionAddress,
                        optionLengthAddress);
                assertSetAndGetSocketOption(
                        state,
                        memory,
                        socketFileDescriptor,
                        SOL_SOCKET,
                        SO_RCVBUF,
                        4096,
                        optionAddress,
                        optionLengthAddress);

                writeInetSockaddr(memory, sockaddrAddress, loopback, server.getLocalPort());
                setSyscall(state, SYS_CONNECT, socketFileDescriptor, sockaddrAddress, SOCKADDR_IN_SIZE);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));

                memory.writeInt(lengthAddress, SOCKADDR_IN_SIZE);
                setSyscall(state, SYS_GETSOCKNAME, socketFileDescriptor, sockaddrAddress, lengthAddress);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));
                assertEquals(SOCKADDR_IN_SIZE, memory.readInt(lengthAddress));
                assertEquals(AF_INET, memory.readUnsignedShort(sockaddrAddress));
                assertArrayEquals(
                        loopback.getAddress(),
                        memory.readBytes(sockaddrAddress + SOCKADDR_IN_ADDRESS_OFFSET, Integer.BYTES));
                assertTrue(readNetworkPort(memory, sockaddrAddress + SOCKADDR_PORT_OFFSET) > 0);

                memory.writeInt(lengthAddress, SOCKADDR_IN_SIZE);
                setSyscall(state, SYS_GETPEERNAME, socketFileDescriptor, sockaddrAddress, lengthAddress);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));
                assertEquals(SOCKADDR_IN_SIZE, memory.readInt(lengthAddress));
                assertEquals(AF_INET, memory.readUnsignedShort(sockaddrAddress));
                assertEquals(server.getLocalPort(), readNetworkPort(memory, sockaddrAddress + SOCKADDR_PORT_OFFSET));
                assertArrayEquals(
                        loopback.getAddress(),
                        memory.readBytes(sockaddrAddress + SOCKADDR_IN_ADDRESS_OFFSET, Integer.BYTES));

                setSyscall(state, SYS_DUP, socketFileDescriptor, 0, 0);
                state.syscalls().handle(state, TEST_PC);
                int duplicateFileDescriptor = (int) state.register(10);
                assertEquals(4, duplicateFileDescriptor);

                setSyscall(state, SYS_CLOSE, socketFileDescriptor, 0, 0);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));

                byte[] request = "ping".getBytes(StandardCharsets.UTF_8);
                memory.writeBytes(bufferAddress, request, 0, request.length);
                setSyscall(state, SYS_WRITE, duplicateFileDescriptor, bufferAddress, request.length);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(request.length, state.register(10));

                setSyscall(state, SYS_READ, duplicateFileDescriptor, bufferAddress, 4);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(4, state.register(10));
                assertEquals("pong", readGuestString(memory, bufferAddress, 4));

                setSyscall(state, SYS_CLOSE, duplicateFileDescriptor, 0, 0);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));

                setSyscall(state, SYS_WRITE, duplicateFileDescriptor, bufferAddress, request.length);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(EBADF, state.register(10));
                waitForNetworkTask(serverTask);
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /// Verifies IPv6-only and nonblocking connect error socket options.
    @Test
    public void hostNetworkIpv6OnlyAndNonblockingConnectErrorAreReported() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        int closedPort;
        try (ServerSocket probe = new ServerSocket(0, 1, loopback)) {
            closedPort = probe.getLocalPort();
        }

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = hostNetworkState(memory);
            long sockaddrAddress = memory.baseAddress();
            long optionAddress = memory.baseAddress() + 128;
            long optionLengthAddress = memory.baseAddress() + 136;

            setSyscall(state, SYS_SOCKET, AF_INET6, SOCK_STREAM, IPPROTO_TCP);
            state.syscalls().handle(state, TEST_PC);
            int ipv6FileDescriptor = (int) state.register(10);
            assertEquals(3, ipv6FileDescriptor);

            assertSetAndGetSocketOption(
                    state,
                    memory,
                    ipv6FileDescriptor,
                    IPPROTO_IPV6,
                    IPV6_V6ONLY,
                    1,
                    optionAddress,
                    optionLengthAddress);

            setSyscall(state, SYS_CLOSE, ipv6FileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_SOCKET, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
            state.syscalls().handle(state, TEST_PC);
            int socketFileDescriptor = (int) state.register(10);
            assertEquals(3, socketFileDescriptor);

            writeInetSockaddr(memory, sockaddrAddress, loopback, closedPort);
            setSyscall(state, SYS_CONNECT, socketFileDescriptor, sockaddrAddress, SOCKADDR_IN_SIZE);
            state.syscalls().handle(state, TEST_PC);
            long connectResult = state.register(10);
            assumeTrue(connectResult != 0, "Loopback probe port was reused before the connect failed");
            assertTrue(connectResult == EINPROGRESS || connectResult == ECONNREFUSED);
            assertEquals((int) -ECONNREFUSED, waitForSocketError(
                    state,
                    memory,
                    socketFileDescriptor,
                    optionAddress,
                    optionLengthAddress));
        }
    }

    /// Verifies `F_SETFL` updates socket nonblocking state.
    @Test
    public void hostNetworkFcntlSetflUpdatesSocketNonblocking() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = hostNetworkState(memory);
            long bufferAddress = memory.baseAddress();

            setSyscall(state, SYS_SOCKET, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            state.syscalls().handle(state, TEST_PC);
            int socketFileDescriptor = (int) state.register(10);
            assertEquals(3, socketFileDescriptor);

            setSyscall(state, SYS_FCNTL, socketFileDescriptor, F_GETFL, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(O_RDWR, state.register(10));

            setSyscall(state, SYS_FCNTL, socketFileDescriptor, F_SETFL, O_NONBLOCK);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_FCNTL, socketFileDescriptor, F_GETFL, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(O_RDWR | O_NONBLOCK, state.register(10));

            setSyscall(state, SYS_RECVFROM, socketFileDescriptor, bufferAddress, 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EAGAIN, state.register(10));
        }
    }

    /// Verifies UDP sockets accept resolver-related extended-error options.
    @Test
    public void hostNetworkUdpReceiveErrorOptionsAreAccepted() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = hostNetworkState(memory);
            long optionAddress = memory.baseAddress();
            long optionLengthAddress = memory.baseAddress() + 64;

            setSyscall(state, SYS_SOCKET, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            state.syscalls().handle(state, TEST_PC);
            int ipv4FileDescriptor = (int) state.register(10);
            assertEquals(3, ipv4FileDescriptor);

            assertSetAndGetSocketOption(
                    state,
                    memory,
                    ipv4FileDescriptor,
                    IPPROTO_IP,
                    IP_RECVERR,
                    1,
                    optionAddress,
                    optionLengthAddress);

            setSyscall(state, SYS_CLOSE, ipv4FileDescriptor, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_SOCKET, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            state.syscalls().handle(state, TEST_PC);
            int ipv6FileDescriptor = (int) state.register(10);
            assertEquals(3, ipv6FileDescriptor);

            assertSetAndGetSocketOption(
                    state,
                    memory,
                    ipv6FileDescriptor,
                    IPPROTO_IPV6,
                    IPV6_RECVERR,
                    1,
                    optionAddress,
                    optionLengthAddress);
        }
    }

    /// Verifies a guest TCP server can accept a host loopback client.
    @Test
    public void hostNetworkTcpServerAcceptsHostClient() throws Exception {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 8192)) {
            RiscVThreadState state = hostNetworkState(memory);
            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            long sockaddrAddress = memory.baseAddress();
            long lengthAddress = memory.baseAddress() + 64;
            long bufferAddress = memory.baseAddress() + 128;
            long optionAddress = memory.baseAddress() + 256;
            long optionLengthAddress = memory.baseAddress() + 264;

            setSyscall(state, SYS_SOCKET, AF_INET, SOCK_STREAM, IPPROTO_TCP);
            state.syscalls().handle(state, TEST_PC);
            int serverFileDescriptor = (int) state.register(10);
            assertEquals(3, serverFileDescriptor);

            memory.writeInt(optionAddress, 1);
            setSyscall(state, SYS_SETSOCKOPT, serverFileDescriptor, SOL_SOCKET, SO_REUSEADDR, optionAddress, Integer.BYTES);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.writeInt(optionLengthAddress, Integer.BYTES);
            setSyscall(state, SYS_GETSOCKOPT, serverFileDescriptor, SOL_SOCKET, SO_REUSEADDR, optionAddress, optionLengthAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(1, memory.readInt(optionAddress));

            writeInetSockaddr(memory, sockaddrAddress, loopback, 0);
            setSyscall(state, SYS_BIND, serverFileDescriptor, sockaddrAddress, SOCKADDR_IN_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.writeInt(lengthAddress, SOCKADDR_IN_SIZE);
            setSyscall(state, SYS_GETSOCKNAME, serverFileDescriptor, sockaddrAddress, lengthAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            int port = readNetworkPort(memory, sockaddrAddress + SOCKADDR_PORT_OFFSET);
            assertTrue(port > 0);

            setSyscall(state, SYS_LISTEN, serverFileDescriptor, 16, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> client = executor.submit(() -> {
                    try (Socket socket = new Socket(loopback, port)) {
                        socket.getOutputStream().write("host".getBytes(StandardCharsets.UTF_8));
                        byte[] response = socket.getInputStream().readNBytes(5);
                        assertEquals("guest", new String(response, StandardCharsets.UTF_8));
                    }
                    return null;
                });

                memory.writeInt(lengthAddress, SOCKADDR_IN_SIZE);
                setSyscall(state, SYS_ACCEPT4, serverFileDescriptor, sockaddrAddress, lengthAddress, 0);
                state.syscalls().handle(state, TEST_PC);
                int acceptedFileDescriptor = (int) state.register(10);
                assertTrue(acceptedFileDescriptor >= 4);

                setSyscall(state, SYS_READ, acceptedFileDescriptor, bufferAddress, 4);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(4, state.register(10));
                assertEquals("host", readGuestString(memory, bufferAddress, 4));

                byte[] response = "guest".getBytes(StandardCharsets.UTF_8);
                memory.writeBytes(bufferAddress, response, 0, response.length);
                setSyscall(state, SYS_WRITE, acceptedFileDescriptor, bufferAddress, response.length);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(response.length, state.register(10));
                waitForNetworkTask(client);
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /// Verifies host networking supports IPv4 UDP datagrams.
    @Test
    public void hostNetworkUdpIpv4DatagramsReachLoopbackServer() throws Exception {
        assertGuestUdpEcho(InetAddress.getByName("127.0.0.1"));
    }

    /// Verifies host networking supports IPv6 UDP datagrams.
    @Test
    public void hostNetworkUdpIpv6DatagramsReachLoopbackServer() throws Exception {
        InetAddress loopback = InetAddress.getByName("::1");
        try (DatagramSocket ignored = new DatagramSocket(new InetSocketAddress(loopback, 0))) {
            assertGuestUdpEcho(loopback);
        } catch (IOException exception) {
            assumeTrue(false, "IPv6 UDP loopback is unavailable: " + exception.getMessage());
        }
    }

    /// Verifies host networking supports batched IPv4 UDP sends through `sendmmsg`.
    @Test
    public void hostNetworkSendmmsgSendsUdpDatagrams() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (DatagramSocket server = new DatagramSocket(new InetSocketAddress(loopback, 0));
             Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 8192)) {
            RiscVThreadState state = hostNetworkState(memory);
            long messageVectorAddress = memory.baseAddress();
            long firstSockaddrAddress = memory.baseAddress() + 256;
            long secondSockaddrAddress = memory.baseAddress() + 288;
            long firstIovecAddress = memory.baseAddress() + 512;
            long secondIovecAddress = memory.baseAddress() + 528;
            long firstPayloadAddress = memory.baseAddress() + 768;
            long secondPayloadAddress = memory.baseAddress() + 784;

            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> serverTask = executor.submit(() -> {
                    byte[] first = new byte[3];
                    byte[] second = new byte[3];
                    server.receive(new DatagramPacket(first, first.length));
                    server.receive(new DatagramPacket(second, second.length));
                    assertEquals("one", new String(first, StandardCharsets.UTF_8));
                    assertEquals("two", new String(second, StandardCharsets.UTF_8));
                    return null;
                });

                setSyscall(state, SYS_SOCKET, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                state.syscalls().handle(state, TEST_PC);
                int socketFileDescriptor = (int) state.register(10);
                assertEquals(3, socketFileDescriptor);

                writeMmsgUdpMessage(
                        memory,
                        messageVectorAddress,
                        firstSockaddrAddress,
                        firstIovecAddress,
                        firstPayloadAddress,
                        loopback,
                        server.getLocalPort(),
                        "one");
                writeMmsgUdpMessage(
                        memory,
                        messageVectorAddress + MMSGHDR_SIZE,
                        secondSockaddrAddress,
                        secondIovecAddress,
                        secondPayloadAddress,
                        loopback,
                        server.getLocalPort(),
                        "two");

                setSyscall(state, SYS_SENDMMSG, socketFileDescriptor, messageVectorAddress, 2, 0);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(2, state.register(10));
                assertEquals(3, memory.readInt(messageVectorAddress + MMSGHDR_LENGTH_OFFSET));
                assertEquals(3, memory.readInt(messageVectorAddress + MMSGHDR_SIZE + MMSGHDR_LENGTH_OFFSET));
                waitForNetworkTask(serverTask);
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /// Verifies host sockets report readiness through poll and epoll.
    @Test
    public void hostNetworkSocketReadinessIsReportedToPollAndEpoll() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (ServerSocket server = new ServerSocket(0, 1, loopback);
             Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 8192)) {
            RiscVThreadState state = hostNetworkState(memory);
            long sockaddrAddress = memory.baseAddress();
            long pollAddress = memory.baseAddress() + 128;
            long eventAddress = memory.baseAddress() + 256;
            long eventsAddress = memory.baseAddress() + 384;
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> serverTask = executor.submit(() -> {
                    try (Socket socket = server.accept()) {
                        socket.getOutputStream().write("ready".getBytes(StandardCharsets.UTF_8));
                        Thread.sleep(250);
                    }
                    return null;
                });

                setSyscall(state, SYS_SOCKET, AF_INET, SOCK_STREAM, IPPROTO_TCP);
                state.syscalls().handle(state, TEST_PC);
                int socketFileDescriptor = (int) state.register(10);
                assertEquals(3, socketFileDescriptor);

                writeInetSockaddr(memory, sockaddrAddress, loopback, server.getLocalPort());
                setSyscall(state, SYS_CONNECT, socketFileDescriptor, sockaddrAddress, SOCKADDR_IN_SIZE);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));

                writePollFileDescriptor(memory, pollAddress, 0, socketFileDescriptor, POLLIN);
                waitForPollReady(state, pollAddress);
                assertEquals(POLLIN, pollRevents(memory, pollAddress, 0));

                setSyscall(state, SYS_EPOLL_CREATE1, 0, 0, 0);
                state.syscalls().handle(state, TEST_PC);
                int epollFileDescriptor = (int) state.register(10);
                assertTrue(epollFileDescriptor >= 4);

                writeEpollEvent(memory, eventAddress, EPOLLIN, 0x77);
                setSyscall(state, SYS_EPOLL_CTL, epollFileDescriptor, EPOLL_CTL_ADD, socketFileDescriptor, eventAddress);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));

                waitForEpollReady(state, epollFileDescriptor, eventsAddress);
                assertEquals(EPOLLIN, memory.readInt(eventsAddress + EPOLL_EVENT_EVENTS_OFFSET));
                assertEquals(0x77, readEpollEventData(memory, eventsAddress));
                waitForNetworkTask(serverTask);
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /// Verifies listening and datagram sockets report read readiness through `pselect6`.
    @Test
    public void hostNetworkListeningAndDatagramSocketsReportPselectReadiness() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 8192)) {
            RiscVThreadState state = hostNetworkState(memory);
            long sockaddrAddress = memory.baseAddress();
            long lengthAddress = memory.baseAddress() + 64;
            long bufferAddress = memory.baseAddress() + 128;
            long fileDescriptorSetAddress = memory.baseAddress() + 512;
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                setSyscall(state, SYS_SOCKET, AF_INET, SOCK_STREAM, IPPROTO_TCP);
                state.syscalls().handle(state, TEST_PC);
                int serverFileDescriptor = (int) state.register(10);
                assertEquals(3, serverFileDescriptor);

                writeInetSockaddr(memory, sockaddrAddress, loopback, 0);
                setSyscall(state, SYS_BIND, serverFileDescriptor, sockaddrAddress, SOCKADDR_IN_SIZE);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));

                memory.writeInt(lengthAddress, SOCKADDR_IN_SIZE);
                setSyscall(state, SYS_GETSOCKNAME, serverFileDescriptor, sockaddrAddress, lengthAddress);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));
                int serverPort = readNetworkPort(memory, sockaddrAddress + SOCKADDR_PORT_OFFSET);

                setSyscall(state, SYS_LISTEN, serverFileDescriptor, 1, 0);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));

                Future<?> client = executor.submit(() -> {
                    try (Socket socket = new Socket(loopback, serverPort)) {
                        Thread.sleep(250);
                    }
                    return null;
                });

                waitForPselectReadReady(state, memory, fileDescriptorSetAddress, serverFileDescriptor);
                memory.writeInt(lengthAddress, SOCKADDR_IN_SIZE);
                setSyscall(state, SYS_ACCEPT, serverFileDescriptor, sockaddrAddress, lengthAddress);
                state.syscalls().handle(state, TEST_PC);
                int acceptedFileDescriptor = (int) state.register(10);
                assertTrue(acceptedFileDescriptor >= 4);

                setSyscall(state, SYS_CLOSE, acceptedFileDescriptor, 0, 0);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));
                setSyscall(state, SYS_CLOSE, serverFileDescriptor, 0, 0);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));
                waitForNetworkTask(client);

                setSyscall(state, SYS_SOCKET, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                state.syscalls().handle(state, TEST_PC);
                int datagramFileDescriptor = (int) state.register(10);
                assertEquals(3, datagramFileDescriptor);

                writeInetSockaddr(memory, sockaddrAddress, loopback, 0);
                setSyscall(state, SYS_BIND, datagramFileDescriptor, sockaddrAddress, SOCKADDR_IN_SIZE);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));

                memory.writeInt(lengthAddress, SOCKADDR_IN_SIZE);
                setSyscall(state, SYS_GETSOCKNAME, datagramFileDescriptor, sockaddrAddress, lengthAddress);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));
                int datagramPort = readNetworkPort(memory, sockaddrAddress + SOCKADDR_PORT_OFFSET);

                try (DatagramSocket sender = new DatagramSocket(new InetSocketAddress(loopback, 0))) {
                    byte[] payload = "udp".getBytes(StandardCharsets.UTF_8);
                    sender.send(new DatagramPacket(payload, payload.length, new InetSocketAddress(loopback, datagramPort)));
                }

                waitForPselectReadReady(state, memory, fileDescriptorSetAddress, datagramFileDescriptor);
                setSyscall(state, SYS_RECVFROM, datagramFileDescriptor, bufferAddress, 3, 0, sockaddrAddress, lengthAddress);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(3, state.register(10));
                assertEquals("udp", readGuestString(memory, bufferAddress, 3));
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /// Verifies callers can mount a custom virtual filesystem provider.
    @Test
    public void customVirtualFilesystemMountCanServeFiles() {
        GuestFileSystem.VirtualFileSystem virtualFileSystem = new GuestFileSystem.VirtualFileSystem() {
            /// Returns a small virtual tree rooted at `/virtual`.
            @Override
            public @Nullable GuestFileSystem.VirtualNode node(String absoluteGuestPath) {
                return switch (absoluteGuestPath) {
                    case "/virtual" -> GuestFileSystem.VirtualNode.directory(absoluteGuestPath);
                    case "/virtual/data.txt" -> GuestFileSystem.VirtualNode.file(absoluteGuestPath, "data");
                    case "/virtual/link.txt" -> GuestFileSystem.VirtualNode.symbolicLink(absoluteGuestPath, "data.txt");
                    default -> null;
                };
            }

            /// Returns the fixed virtual root children.
            @Override
            public GuestFileSystem.VirtualNode @Unmodifiable [] childNodes(String directoryGuestPath) {
                if (!"/virtual".equals(directoryGuestPath)) {
                    return new GuestFileSystem.VirtualNode[0];
                }
                return new GuestFileSystem.VirtualNode[]{
                        GuestFileSystem.VirtualNode.file("/virtual/data.txt", "data"),
                        GuestFileSystem.VirtualNode.symbolicLink("/virtual/link.txt", "data.txt")
                };
            }

            /// Returns bytes for the single virtual regular file.
            @Override
            public byte @Unmodifiable [] fileData(GuestFileSystem.VirtualNode node) {
                return "virtual-data".getBytes(StandardCharsets.UTF_8);
            }

            /// Returns the target stored in virtual symbolic-link nodes.
            @Override
            public String linkTarget(GuestFileSystem.VirtualNode node) {
                @Nullable String target = node.linkTarget();
                return target == null ? "" : target;
            }
        };
        GuestFileSystem fileSystem = GuestFileSystem.empty().withVirtualMount("/virtual", virtualFileSystem);

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    fileSystem);
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 512;

            writeGuestString(memory, pathAddress, "/virtual/data.txt");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int fileDescriptor = (int) state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_READ, fileDescriptor, bufferAddress, "virtual-data".length());
            state.syscalls().handle(state, TEST_PC);
            assertEquals("virtual-data".length(), state.register(10));
            assertArrayEquals(
                    "virtual-data".getBytes(StandardCharsets.UTF_8),
                    memory.readBytes(bufferAddress, "virtual-data".length()));

            writeGuestString(memory, pathAddress, "/virtual/link.txt");
            setSyscall(state, SYS_READLINKAT, AT_FDCWD, pathAddress, bufferAddress, 32);
            state.syscalls().handle(state, TEST_PC);
            assertEquals("data.txt".length(), state.register(10));
            assertArrayEquals("data.txt".getBytes(StandardCharsets.UTF_8),
                    memory.readBytes(bufferAddress, "data.txt".length()));

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int linkedFileDescriptor = (int) state.register(10);
            assertEquals(4, linkedFileDescriptor);

            setSyscall(state, SYS_READ, linkedFileDescriptor, bufferAddress, "virtual-data".length());
            state.syscalls().handle(state, TEST_PC);
            assertEquals("virtual-data".length(), state.register(10));
            assertArrayEquals(
                    "virtual-data".getBytes(StandardCharsets.UTF_8),
                    memory.readBytes(bufferAddress, "virtual-data".length()));

            writeGuestString(memory, pathAddress, "/virtual");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY | O_DIRECTORY, 0);
            state.syscalls().handle(state, TEST_PC);
            int directoryFileDescriptor = (int) state.register(10);
            assertEquals(5, directoryFileDescriptor);

            setSyscall(state, SYS_GETDENTS64, directoryFileDescriptor, bufferAddress, 256);
            state.syscalls().handle(state, TEST_PC);
            assertTrue(state.register(10) > 0);
            long nextEntry = assertDirectoryEntry(memory, bufferAddress, ".", DIRECTORY_ENTRY_DIRECTORY, 1);
            nextEntry = assertDirectoryEntry(memory, nextEntry, "..", DIRECTORY_ENTRY_DIRECTORY, 2);
            nextEntry = assertDirectoryEntry(memory, nextEntry, "data.txt", DIRECTORY_ENTRY_REGULAR_FILE, 3);
            assertDirectoryEntry(memory, nextEntry, "link.txt", DIRECTORY_ENTRY_SYMBOLIC_LINK, 4);
        }
    }

    /// Verifies a missing cloud-image resolver symlink target is replaced with host resolver configuration.
    @Test
    public void defaultResolvConfSuppliesHostResolverForBrokenRootfsLink() throws Exception {
        Path archive = tempDirectory.resolve("broken-resolv.tar");
        try (OutputStream output = Files.newOutputStream(archive);
             TarArchiveOutputStream tarOutput = new TarArchiveOutputStream(output)) {
            writeTarDirectory(tarOutput, "etc", 0755, 0, 0);
            writeTarSymbolicLink(
                    tarOutput,
                    "etc/resolv.conf",
                    "../run/systemd/resolve/stub-resolv.conf",
                    0777,
                    0,
                    0);
        }

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 8192)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    GuestFileSystem.forMountSpecs(new String[]{"type=tar,src=" + archive + ",dst=/"}));
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 512;

            writeGuestString(memory, pathAddress, "/etc/resolv.conf");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int fileDescriptor = (int) state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_READ, fileDescriptor, bufferAddress, 4096);
            state.syscalls().handle(state, TEST_PC);
            int byteCount = (int) state.register(10);
            assertTrue(byteCount > 0);
            assertTrue(readGuestString(memory, bufferAddress, byteCount).contains("nameserver"));
        }
    }

    /// Verifies a valid root filesystem resolver file is not replaced by the default virtual file.
    @Test
    public void defaultResolvConfDoesNotReplaceExistingRootfsFile() throws Exception {
        Path archive = tempDirectory.resolve("existing-resolv.tar");
        byte[] resolvConf = "nameserver 192.0.2.53\n".getBytes(StandardCharsets.UTF_8);
        try (OutputStream output = Files.newOutputStream(archive);
             TarArchiveOutputStream tarOutput = new TarArchiveOutputStream(output)) {
            writeTarDirectory(tarOutput, "etc", 0755, 0, 0);
            writeTarFile(tarOutput, "etc/resolv.conf", resolvConf, 0644, 0, 0);
        }

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 8192)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress(),
                    GuestFileSystem.forMountSpecs(new String[]{"type=tar,src=" + archive + ",dst=/"}));
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 512;

            writeGuestString(memory, pathAddress, "/etc/resolv.conf");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int fileDescriptor = (int) state.register(10);
            assertEquals(3, fileDescriptor);

            setSyscall(state, SYS_READ, fileDescriptor, bufferAddress, resolvConf.length);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(resolvConf.length, state.register(10));
            assertArrayEquals(resolvConf, memory.readBytes(bufferAddress, resolvConf.length));
        }
    }

    /// Verifies `prctl` state tracked by the single-process simulator.
    @Test
    public void prctlTracksSingleProcessState() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 2048)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long intAddress = memory.baseAddress() + 64;
            long longAddress = memory.baseAddress() + 72;
            long tidAddress = memory.baseAddress() + 256;

            setSyscall(state, SYS_PRCTL, PR_GET_DUMPABLE, 0, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_SET_DUMPABLE, 0, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_GET_DUMPABLE, 0, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_SET_DUMPABLE, 2, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_SET_PDEATHSIG, 15, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_GET_PDEATHSIG, intAddress, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(15, memory.readInt(intAddress));

            setSyscall(state, SYS_PRCTL, PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_GET_CHILD_SUBREAPER, intAddress, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(1, memory.readInt(intAddress));

            setSyscall(state, SYS_PRCTL, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_SET_THP_DISABLE, 1, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_GET_THP_DISABLE, 0, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_SET_TIMERSLACK, 1234, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_GET_TIMERSLACK, 0, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1234, state.register(10));

            setSyscall(state, SYS_SET_TID_ADDRESS, tidAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(1, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_GET_TID_ADDRESS, longAddress, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(tidAddress, memory.readLong(longAddress));
        }
    }

    /// Verifies Linux RISC-V tagged-address control state and syscall pointer masking.
    @Test
    public void prctlControlsRiscvPointerMasking() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long intAddress = memory.baseAddress() + 64;
            long taggedIntAddress = taggedAddress(intAddress);

            setSyscall(state, SYS_PRCTL, PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(
                    state,
                    SYS_PRCTL,
                    PR_SET_TAGGED_ADDR_CTRL,
                    PR_TAGGED_ADDR_ENABLE | (1L << PR_PMLEN_SHIFT),
                    0,
                    0,
                    0,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(PR_TAGGED_ADDR_ENABLE | (7L << PR_PMLEN_SHIFT), state.register(10));

            setSyscall(state, SYS_PRCTL, PR_SET_PDEATHSIG, 15, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_GET_PDEATHSIG, taggedIntAddress, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(15, memory.readInt(intAddress));

            setSyscall(state, SYS_PRCTL, PR_SET_TAGGED_ADDR_CTRL, 8L << PR_PMLEN_SHIFT, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_SET_TAGGED_ADDR_CTRL, PR_PMLEN_MASK | (1L << 8), 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies `prctl` no-op support and unsupported operation errors.
    @Test
    public void prctlAcceptsVirtualMemoryAreaNames() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long nameAddress = memory.baseAddress() + 64;

            writeGuestString(memory, nameAddress, "heap");
            setSyscall(
                    state,
                    SYS_PRCTL,
                    PR_SET_VMA,
                    PR_SET_VMA_ANON_NAME,
                    memory.baseAddress(),
                    PAGE_SIZE,
                    nameAddress,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_PRCTL, PR_SET_VMA, 1, memory.baseAddress(), PAGE_SIZE, nameAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_PRCTL, 9999, 0, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies deterministic `getrandom` bytes and flag validation.
    @Test
    public void getrandomFillsDeterministicBytes() {
        byte[] firstBytes;
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));

            setSyscall(state, SYS_GETRANDOM, memory.baseAddress(), 8, 3);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(8, state.register(10));
            firstBytes = memory.readBytes(memory.baseAddress(), 8);

            setSyscall(state, SYS_GETRANDOM, memory.endAddress() + 128, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_GETRANDOM, memory.baseAddress(), 1, 4);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }

        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));

            setSyscall(state, SYS_GETRANDOM, memory.baseAddress(), 8, 0);
            state.syscalls().handle(state, TEST_PC);

            assertArrayEquals(firstBytes, memory.readBytes(memory.baseAddress(), 8));
        }
    }

    /// Verifies optional runtime capability syscalls report deterministic fallback results.
    @Test
    public void optionalRuntimeCapabilitySyscallsReportUnavailable() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));

            setSyscall(state, SYS_MEMBARRIER, MEMBARRIER_CMD_QUERY, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_MEMBARRIER, 1, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_MEMBARRIER, MEMBARRIER_CMD_QUERY, 1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

        }
    }

    /// Verifies Linux restartable sequence registration and unregister validation.
    @Test
    public void rseqRegistersAndUnregistersThreadState() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long rseqAddress = memory.baseAddress();
            long signature = 0x5305_3053L;

            memory.writeLong(rseqAddress + RSEQ_CRITICAL_SECTION_OFFSET, 0x1234);
            setSyscall(state, SYS_RSEQ, rseqAddress, RSEQ_ORIGINAL_SIZE, 0, signature);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readInt(rseqAddress + RSEQ_CPU_ID_START_OFFSET));
            assertEquals(0, memory.readInt(rseqAddress + RSEQ_CPU_ID_OFFSET));
            assertEquals(0, memory.readLong(rseqAddress + RSEQ_CRITICAL_SECTION_OFFSET));
            assertEquals(0, memory.readInt(rseqAddress + RSEQ_FLAGS_OFFSET));
            assertEquals(0, memory.readInt(rseqAddress + RSEQ_NODE_ID_OFFSET));
            assertEquals(0, memory.readInt(rseqAddress + RSEQ_MEMORY_MAP_CONCURRENCY_ID_OFFSET));

            setSyscall(state, SYS_RSEQ, rseqAddress, RSEQ_ORIGINAL_SIZE, 0, signature);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBUSY, state.register(10));

            setSyscall(state, SYS_RSEQ, rseqAddress, RSEQ_ORIGINAL_SIZE, 0, signature + 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EPERM, state.register(10));

            setSyscall(state, SYS_RSEQ, rseqAddress + RSEQ_ORIGINAL_SIZE, RSEQ_ORIGINAL_SIZE, 0, signature);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_RSEQ, rseqAddress, RSEQ_ORIGINAL_SIZE, RSEQ_FLAG_UNREGISTER, signature + 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EPERM, state.register(10));

            setSyscall(state, SYS_RSEQ, rseqAddress, RSEQ_ORIGINAL_SIZE, RSEQ_FLAG_UNREGISTER, signature);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(-1, memory.readInt(rseqAddress + RSEQ_CPU_ID_START_OFFSET));
            assertEquals(-1, memory.readInt(rseqAddress + RSEQ_CPU_ID_OFFSET));
            assertEquals(0, memory.readLong(rseqAddress + RSEQ_CRITICAL_SECTION_OFFSET));

            setSyscall(state, SYS_RSEQ, rseqAddress, RSEQ_ORIGINAL_SIZE, RSEQ_FLAG_UNREGISTER, signature);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_RSEQ, rseqAddress + Integer.BYTES, RSEQ_ORIGINAL_SIZE, 0, signature);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_RSEQ, rseqAddress, RSEQ_ORIGINAL_SIZE - 1, 0, signature);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_RSEQ, rseqAddress, RSEQ_ORIGINAL_SIZE, 2, signature);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_RSEQ, memory.endAddress(), RSEQ_ORIGINAL_SIZE, 0, signature);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));
        }
    }

    /// Verifies that host input and output failures are surfaced as simulator exceptions.
    @Test
    public void propagatesHostIoFailures() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState readState = state(
                    memory,
                    new FailingInputStream(),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress());
            setSyscall(readState, SYS_READ, 0, memory.baseAddress(), 1);
            assertThrows(RiscVException.class, () -> readState.syscalls().handle(readState, TEST_PC));

            RiscVThreadState writeState = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new FailingOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress());
            memory.writeByte(memory.baseAddress(), (byte) 'A');
            setSyscall(writeState, SYS_WRITE, 1, memory.baseAddress(), 1);
            assertThrows(RiscVException.class, () -> writeState.syscalls().handle(writeState, TEST_PC));
        }
    }

    /// Verifies alternate signal stack registration for runtimes that install signal handlers.
    @Test
    public void sigaltstackTracksSingleThreadedSignalStack() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long stackAddress = memory.baseAddress() + 64;
            long oldStackAddress = memory.baseAddress() + 128;
            long alternateStackPointer = memory.baseAddress() + 1024;

            setSyscall(state, SYS_SIGALTSTACK, 0, oldStackAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, readSignalStackPointer(memory, oldStackAddress));
            assertEquals(SS_DISABLE, readSignalStackFlags(memory, oldStackAddress));
            assertEquals(0, readSignalStackSize(memory, oldStackAddress));

            writeSignalStack(memory, stackAddress, alternateStackPointer, SS_AUTODISARM, MINIMUM_SIGNAL_STACK_SIZE);
            setSyscall(state, SYS_SIGALTSTACK, stackAddress, oldStackAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(SS_DISABLE, readSignalStackFlags(memory, oldStackAddress));

            memory.clear(oldStackAddress, 24);
            setSyscall(state, SYS_SIGALTSTACK, 0, oldStackAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(alternateStackPointer, readSignalStackPointer(memory, oldStackAddress));
            assertEquals(SS_AUTODISARM, readSignalStackFlags(memory, oldStackAddress));
            assertEquals(MINIMUM_SIGNAL_STACK_SIZE, readSignalStackSize(memory, oldStackAddress));

            writeSignalStack(memory, stackAddress, 0, SS_DISABLE, 0);
            setSyscall(state, SYS_SIGALTSTACK, stackAddress, oldStackAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.clear(oldStackAddress, 24);
            setSyscall(state, SYS_SIGALTSTACK, 0, oldStackAddress, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(SS_DISABLE, readSignalStackFlags(memory, oldStackAddress));
        }
    }

    /// Verifies Linux-compatible `sigaltstack` validation for unsupported stack descriptions.
    @Test
    public void sigaltstackRejectsInvalidStacks() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4096)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long stackAddress = memory.baseAddress() + 64;
            long stackPointer = memory.baseAddress() + 1024;

            writeSignalStack(memory, stackAddress, stackPointer, 0, MINIMUM_SIGNAL_STACK_SIZE - 1);
            setSyscall(state, SYS_SIGALTSTACK, stackAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOMEM, state.register(10));

            writeSignalStack(memory, stackAddress, stackPointer, SS_ONSTACK, MINIMUM_SIGNAL_STACK_SIZE);
            setSyscall(state, SYS_SIGALTSTACK, stackAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            writeSignalStack(memory, stackAddress, stackPointer, 0x10, MINIMUM_SIGNAL_STACK_SIZE);
            setSyscall(state, SYS_SIGALTSTACK, stackAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies deterministic signal action handling for runtimes that initialize signal handlers.
    @Test
    public void rtSigactionAcceptsRuntimeSetup() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long actionAddress = memory.baseAddress() + 64;
            long oldActionAddress = memory.baseAddress() + 128;
            memory.writeLong(oldActionAddress, -1);

            setSyscall(state, SYS_RT_SIGACTION, 2, actionAddress, oldActionAddress, KERNEL_SIGSET_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readLong(oldActionAddress));

            setSyscall(state, SYS_RT_SIGACTION, 0, 0, 0, KERNEL_SIGSET_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_RT_SIGACTION, 2, 0, 0, KERNEL_SIGSET_SIZE - 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies synchronous signal delivery uses the glibc RISC-V `ucontext_t` register layout.
    @Test
    public void illegalInstructionSignalFrameUsesGlibcUcontextLayout() {
        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 65536)) {
            long base = memory.baseAddress();
            assertTrue(memory.map(base, 8192));

            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    base + 8192);
            long actionAddress = base + 64;
            long handlerAddress = base + 512;
            long stalePc = base + 1024;
            long faultPc = base + 1280;
            long returnPc = base + 1536;
            long stackPointer = base + 4096;
            long globalPointer = base + 6144;

            memory.writeLong(actionAddress, handlerAddress);
            memory.writeLong(actionAddress + Long.BYTES, SA_SIGINFO);
            memory.writeLong(actionAddress + 2L * Long.BYTES, 0);
            setSyscall(state, SYS_RT_SIGACTION, SIGILL, actionAddress, 0, KERNEL_SIGSET_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            state.setPc(stalePc);
            state.setRegister(1, returnPc);
            state.setRegister(2, stackPointer);
            state.setRegister(3, globalPointer);

            assertTrue(state.syscalls().handleIllegalInstruction(state, new IllegalInstructionException(faultPc, -1)));
            long frameAddress = state.register(2);
            long infoAddress = state.register(11);
            long contextAddress = state.register(12);
            long registersAddress = contextAddress + SIGNAL_CONTEXT_MACHINE_OFFSET;

            assertEquals(handlerAddress, state.pc());
            assertEquals(stackPointer - SIGNAL_FRAME_SIZE, frameAddress);
            assertEquals(frameAddress, infoAddress);
            assertEquals(frameAddress + SIGNAL_INFO_SIZE, contextAddress);
            assertEquals(SIGILL, memory.readInt(infoAddress));
            assertEquals(ILL_ILLOPC, memory.readInt(infoAddress + SIGNAL_INFO_CODE_OFFSET));
            assertEquals(faultPc, memory.readLong(infoAddress + SIGNAL_INFO_FAULT_ADDRESS_OFFSET));
            assertEquals(0, memory.readLong(registersAddress - Long.BYTES));
            assertEquals(faultPc, memory.readLong(registersAddress));
            assertEquals(returnPc, memory.readLong(registersAddress + Long.BYTES));
            assertEquals(stackPointer, memory.readLong(registersAddress + 2L * Long.BYTES));
            assertEquals(globalPointer, memory.readLong(registersAddress + 3L * Long.BYTES));

            long resumePc = base + 2048;
            memory.writeLong(registersAddress, resumePc);
            setSyscall(state, SYS_RT_SIGRETURN, 0, 0, 0);
            state.syscalls().handle(state, state.pc());
            assertEquals(resumePc, state.pc());
            assertEquals(returnPc, state.register(1));
            assertEquals(stackPointer, state.register(2));
            assertEquals(globalPointer, state.register(3));
        }
    }

    /// Verifies deterministic signal-mask handling for single-threaded guests.
    @Test
    public void rtSigprocmaskTracksThreadSignalMask() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            RiscVThreadState state = state(memory, new ByteArrayInputStream(new byte[0]));
            long newSetAddress = memory.baseAddress() + 64;
            long oldSetAddress = memory.baseAddress() + 128;
            long userSignalMask = signalMask(SIGUSR1);
            long unblockableSignalMask = signalMask(SIGKILL) | signalMask(SIGSTOP);
            memory.writeLong(newSetAddress, userSignalMask | unblockableSignalMask);
            memory.writeLong(oldSetAddress, -1);

            setSyscall(state, SYS_RT_SIGPROCMASK, SIG_BLOCK, newSetAddress, oldSetAddress, KERNEL_SIGSET_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readLong(oldSetAddress));

            memory.writeLong(oldSetAddress, -1);
            setSyscall(state, SYS_RT_SIGPROCMASK, SIG_BLOCK, 0, oldSetAddress, KERNEL_SIGSET_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(userSignalMask, memory.readLong(oldSetAddress));

            memory.writeLong(newSetAddress, userSignalMask);
            memory.writeLong(oldSetAddress, -1);
            setSyscall(state, SYS_RT_SIGPROCMASK, SIG_UNBLOCK, newSetAddress, oldSetAddress, KERNEL_SIGSET_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(userSignalMask, memory.readLong(oldSetAddress));

            memory.writeLong(oldSetAddress, -1);
            setSyscall(state, SYS_RT_SIGPROCMASK, SIG_BLOCK, 0, oldSetAddress, KERNEL_SIGSET_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readLong(oldSetAddress));

            memory.writeLong(newSetAddress, -1);
            setSyscall(state, SYS_RT_SIGPROCMASK, SIG_SETMASK, newSetAddress, 0, KERNEL_SIGSET_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            memory.writeLong(oldSetAddress, 0);
            setSyscall(state, SYS_RT_SIGPROCMASK, SIG_BLOCK, 0, oldSetAddress, KERNEL_SIGSET_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(-1L & ~unblockableSignalMask, memory.readLong(oldSetAddress));

            setSyscall(state, SYS_RT_SIGPROCMASK, 9, newSetAddress, 0, KERNEL_SIGSET_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_RT_SIGPROCMASK, 0, 0, 0, KERNEL_SIGSET_SIZE - 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies that anonymous `mmap` returns zero-filled page-aligned guest memory.
    @Test
    public void mmapAllocatesAnonymousGuestPages() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);
            long expectedAddress = memory.baseAddress() + PAGE_SIZE;
            memory.writeByte(expectedAddress, (byte) 0x7f);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    128,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(expectedAddress, state.register(10));
            assertEquals(0, memory.readUnsignedByte(expectedAddress));
            memory.writeLong(expectedAddress, 0x1020_3040_5060_7080L);
            assertEquals(0x1020_3040_5060_7080L, memory.readLong(expectedAddress));
        }
    }

    /// Verifies that private file-backed `mmap` copies regular-file data into guest memory.
    @Test
    public void mmapMapsPrivateRegularFilePages() throws Exception {
        Files.writeString(tempDirectory.resolve("mapped.txt"), "mapped-file-data", StandardCharsets.UTF_8);
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak,
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            writeGuestString(memory, pathAddress, "mapped.txt");

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            long fileDescriptor = state.register(10);
            assertTrue(fileDescriptor >= 3);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    PAGE_SIZE,
                    PROT_READ,
                    MAP_PRIVATE,
                    fileDescriptor,
                    0);
            state.syscalls().handle(state, TEST_PC);

            long mappedAddress = state.register(10);
            assertEquals(initialBreak, mappedAddress);
            assertEquals("mapped-file-data", readGuestString(memory, mappedAddress, "mapped-file-data".length()));
            assertEquals(0, memory.readUnsignedByte(mappedAddress + "mapped-file-data".length()));
        }
    }

    /// Verifies that framebuffer snapshots can observe live shared `/dev/fb0` mmap writes before `munmap`.
    @Test
    public void framebufferSnapshotsRefreshSharedMmapWrites() {
        FramebufferDevice framebuffer = new FramebufferDevice(FramebufferGeometry.packed(
                2,
                1,
                FramebufferPixelFormat.XRGB8888));
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = framebufferState(memory, initialBreak, framebuffer);
            try {
                long pathAddress = memory.baseAddress();
                writeGuestString(memory, pathAddress, "/dev/fb0");

                setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDWR, 0);
                state.syscalls().handle(state, TEST_PC);
                long fileDescriptor = state.register(10);
                assertTrue(fileDescriptor >= 3);

                setSyscall(
                        state,
                        SYS_MMAP,
                        0,
                        PAGE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        fileDescriptor,
                        0);
                state.syscalls().handle(state, TEST_PC);
                long mappedAddress = state.register(10);
                assertEquals(initialBreak, mappedAddress);

                memory.writeInt(mappedAddress + 4, 0x0011_2233);
                byte[] deviceBytes = new byte[8];
                assertEquals(8, framebuffer.read(0, deviceBytes, 0, deviceBytes.length));
                assertArrayEquals(new byte[8], deviceBytes);

                assertArrayEquals(
                        new byte[]{0, 0, 0, 0, 0x33, 0x22, 0x11, 0},
                        framebuffer.snapshot().pixels());
            } finally {
                state.syscalls().close();
            }
        }
    }

    /// Verifies that shared read-only file-backed `mmap` copies data and appears in `/proc/self/maps`.
    @Test
    public void mmapMapsSharedReadOnlyRegularFilePages() throws Exception {
        Files.writeString(tempDirectory.resolve("shared.txt"), "shared-file-data", StandardCharsets.UTF_8);
        try (Memory memory = new Memory(0, 128 * PAGE_SIZE)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    PAGE_SIZE,
                    tempDirectory);
            long pathAddress = memory.baseAddress();
            long bufferAddress = memory.baseAddress() + 8 * PAGE_SIZE;
            long fixedAddress = 0x10000;
            writeGuestString(memory, pathAddress, "shared.txt");

            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            long fileDescriptor = state.register(10);
            assertTrue(fileDescriptor >= 3);

            setSyscall(
                    state,
                    SYS_MMAP,
                    fixedAddress,
                    PAGE_SIZE,
                    PROT_READ,
                    MAP_SHARED_VALIDATE | MAP_FIXED,
                    fileDescriptor,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(fixedAddress, state.register(10));
            assertEquals("shared-file-data", readGuestString(memory, fixedAddress, "shared-file-data".length()));

            writeGuestString(memory, pathAddress, "/proc/self/maps");
            setSyscall(state, SYS_OPENAT, AT_FDCWD, pathAddress, O_RDONLY, 0);
            state.syscalls().handle(state, TEST_PC);
            int mapsFileDescriptor = (int) state.register(10);
            assertTrue(mapsFileDescriptor > fileDescriptor);

            setSyscall(state, SYS_READ, mapsFileDescriptor, bufferAddress, PAGE_SIZE);
            state.syscalls().handle(state, TEST_PC);
            int mapsLength = (int) state.register(10);
            assertTrue(mapsLength > 0);
            String maps = readGuestString(memory, bufferAddress, mapsLength);
            assertTrue(maps.contains("10000-11000 r--s 00000000 00:00 0    /shared.txt\n"));
        }
    }

    /// Verifies that `MAP_HUGETLB` consumes the configured guest huge-page pool.
    @Test
    public void mmapHugeTlbConsumesHugePagePool() {
        try (Memory memory = Memory.sparse(
                Memory.DEFAULT_BASE_ADDRESS,
                3L * Memory.DEFAULT_HUGE_PAGE_SIZE,
                Memory.DEFAULT_PAGE_SIZE,
                0,
                Memory.DEFAULT_HUGE_PAGE_SIZE,
                1)) {
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    memory.baseAddress() + PAGE_SIZE);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(memory.baseAddress() + Memory.DEFAULT_HUGE_PAGE_SIZE, state.register(10));
            assertEquals(1, memory.reservedHugePages());

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOMEM, state.register(10));
        }
    }

    /// Verifies that released anonymous mappings can be reused by later `mmap` calls.
    @Test
    public void munmapReleasesAnonymousGuestPages() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 5 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            long firstAddress = state.register(10);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(firstAddress + PAGE_SIZE, state.register(10));

            memory.writeByte(firstAddress, (byte) 0x7f);
            setSyscall(state, SYS_MUNMAP, firstAddress, PAGE_SIZE, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readUnsignedByte(firstAddress));

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(firstAddress, state.register(10));
        }
    }

    /// Verifies that `mremap` shrinks and grows tracked anonymous mappings in place.
    @Test
    public void mremapShrinksAndGrowsAnonymousMappings() {
        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 8 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    2 * PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            long mappedAddress = state.register(10);
            assertEquals(initialBreak, mappedAddress);
            memory.writeLong(mappedAddress, 0x0102_0304_0506_0708L);
            memory.writeLong(mappedAddress + PAGE_SIZE, 0x1122_3344_5566_7788L);

            setSyscall(state, SYS_MREMAP, mappedAddress, 2 * PAGE_SIZE, PAGE_SIZE, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(mappedAddress, state.register(10));
            assertEquals(0x0102_0304_0506_0708L, memory.readLong(mappedAddress));
            assertThrows(RiscVException.class, () -> memory.readLong(mappedAddress + PAGE_SIZE));

            setSyscall(state, SYS_MREMAP, mappedAddress, PAGE_SIZE, 2 * PAGE_SIZE, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(mappedAddress, state.register(10));
            memory.writeLong(mappedAddress + PAGE_SIZE, 0x2211_4433_6655_8877L);
            assertEquals(0x2211_4433_6655_8877L, memory.readLong(mappedAddress + PAGE_SIZE));
        }
    }

    /// Verifies that `mremap` can move anonymous mappings when in-place growth is blocked.
    @Test
    public void mremapMovesAnonymousMappingWhenGrowthIsBlocked() {
        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 8 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            long mappedAddress = state.register(10);
            memory.writeLong(mappedAddress, 0x1020_3040_5060_7080L);

            long blockingAddress = mappedAddress + PAGE_SIZE;
            setSyscall(
                    state,
                    SYS_MMAP,
                    blockingAddress,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(blockingAddress, state.register(10));

            setSyscall(state, SYS_MREMAP, mappedAddress, PAGE_SIZE, 2 * PAGE_SIZE, MREMAP_MAYMOVE, 0);
            state.syscalls().handle(state, TEST_PC);
            long movedAddress = state.register(10);
            assertEquals(blockingAddress + PAGE_SIZE, movedAddress);
            assertEquals(0x1020_3040_5060_7080L, memory.readLong(movedAddress));
            assertThrows(RiscVException.class, () -> memory.readLong(mappedAddress));

            memory.writeLong(blockingAddress, 0x0101_0202_0303_0404L);
            assertEquals(0x0101_0202_0303_0404L, memory.readLong(blockingAddress));
        }
    }

    /// Verifies that `MREMAP_FIXED` moves an anonymous mapping to the requested address.
    @Test
    public void mremapMovesAnonymousMappingToFixedAddress() {
        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 8 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            long mappedAddress = state.register(10);
            memory.writeLong(mappedAddress, 0x1122_3344_5566_7788L);

            long targetAddress = mappedAddress + 3 * PAGE_SIZE;
            setSyscall(
                    state,
                    SYS_MMAP,
                    targetAddress,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(targetAddress, state.register(10));
            memory.writeLong(targetAddress, 0x0101_0202_0303_0404L);

            setSyscall(
                    state,
                    SYS_MREMAP,
                    mappedAddress,
                    PAGE_SIZE,
                    PAGE_SIZE,
                    MREMAP_MAYMOVE | MREMAP_FIXED,
                    targetAddress);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(targetAddress, state.register(10));
            assertEquals(0x1122_3344_5566_7788L, memory.readLong(targetAddress));
            assertThrows(RiscVException.class, () -> memory.readLong(mappedAddress));
        }
    }

    /// Verifies validation for unsupported `mremap` requests.
    @Test
    public void mremapRejectsUnsupportedRequests() {
        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 4 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            long mappedAddress = state.register(10);

            setSyscall(state, SYS_MREMAP, mappedAddress + 1, PAGE_SIZE, PAGE_SIZE, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_MREMAP, mappedAddress, PAGE_SIZE, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(
                    state,
                    SYS_MREMAP,
                    mappedAddress,
                    PAGE_SIZE,
                    2 * PAGE_SIZE,
                    MREMAP_FIXED,
                    mappedAddress + 2 * PAGE_SIZE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies validation and collision behavior for unsupported `mmap` requests.
    @Test
    public void mmapRejectsUnsupportedRequests() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 3 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    0,
                    PROT_READ,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_MMAP, 0, PAGE_SIZE, PROT_READ, MAP_PRIVATE, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EBADF, state.register(10));

            setSyscall(
                    state,
                    SYS_MMAP,
                    initialBreak + 1,
                    PAGE_SIZE,
                    PROT_READ,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOMEM, state.register(10));

            setSyscall(
                    state,
                    SYS_MMAP,
                    initialBreak,
                    PAGE_SIZE,
                    PROT_READ,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(initialBreak, state.register(10));

            setSyscall(
                    state,
                    SYS_MMAP,
                    initialBreak,
                    PAGE_SIZE,
                    PROT_READ,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EEXIST, state.register(10));
        }
    }

    /// Verifies that `PROT_NONE` reservations can be activated by fixed `mmap` calls.
    @Test
    public void mmapReservesProtNoneAndMapsFixedSparsePages() {
        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 16 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    8 * PAGE_SIZE,
                    PROT_NONE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            long reservedAddress = state.register(10);
            assertEquals(initialBreak, reservedAddress);
            assertThrows(RiscVException.class, () -> memory.readByte(reservedAddress));

            long mappedAddress = reservedAddress + PAGE_SIZE;
            setSyscall(
                    state,
                    SYS_MMAP,
                    mappedAddress,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);

            assertEquals(mappedAddress, state.register(10));
            memory.writeLong(mappedAddress, 0x1020_3040_5060_7080L);
            assertEquals(0x1020_3040_5060_7080L, memory.readLong(mappedAddress));
        }
    }

    /// Verifies that `mprotect` can activate and deactivate reserved sparse mappings.
    @Test
    public void mprotectUpdatesReservedSparseMappings() {
        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 16 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    8 * PAGE_SIZE,
                    PROT_NONE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            long reservedAddress = state.register(10);

            setSyscall(state, SYS_MPROTECT, reservedAddress, PAGE_SIZE, PROT_READ | PROT_WRITE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            memory.writeLong(reservedAddress, 0x0102_0304_0506_0708L);
            assertEquals(0x0102_0304_0506_0708L, memory.readLong(reservedAddress));

            setSyscall(state, SYS_MPROTECT, reservedAddress, PAGE_SIZE, PROT_NONE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertThrows(RiscVException.class, () -> memory.readLong(reservedAddress));

            setSyscall(state, SYS_MPROTECT, reservedAddress + 16 * PAGE_SIZE, PAGE_SIZE, PROT_READ);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOMEM, state.register(10));

            setSyscall(state, SYS_MPROTECT, reservedAddress, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC | 0x8);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies that `mprotect` updates the underlying guest memory access permissions.
    @Test
    public void mprotectEnforcesSparseMappingPermissions() {
        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 16 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            long mappedAddress = state.register(10);
            memory.writeLong(mappedAddress, 0x0102_0304_0506_0708L);

            setSyscall(state, SYS_MPROTECT, mappedAddress, PAGE_SIZE, PROT_READ);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0x0102_0304_0506_0708L, memory.readLong(mappedAddress));
            assertThrows(RiscVException.class, () -> memory.writeByte(mappedAddress, (byte) 0x7f));

            setSyscall(state, SYS_MPROTECT, mappedAddress, PAGE_SIZE, PROT_READ | PROT_WRITE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            memory.writeByte(mappedAddress, (byte) 0x7f);
            assertEquals(0x7f, memory.readUnsignedByte(mappedAddress));
        }
    }

    /// Verifies that `madvise` accepts common hints and discards backed anonymous pages.
    @Test
    public void madviseClearsDiscardedAnonymousPages() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            long mappedAddress = state.register(10);
            memory.writeByte(mappedAddress, (byte) 0x7f);

            setSyscall(state, SYS_MADVISE, mappedAddress, PAGE_SIZE, MADV_DONTNEED);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0, memory.readUnsignedByte(mappedAddress));

            memory.writeByte(mappedAddress, (byte) 0x45);
            setSyscall(state, SYS_MADVISE, mappedAddress, PAGE_SIZE, MADV_HUGEPAGE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertEquals(0x45, memory.readUnsignedByte(mappedAddress));

            setSyscall(state, SYS_MADVISE, mappedAddress, PAGE_SIZE, MADV_REMOVE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));
        }
    }

    /// Verifies `msync` validates mapped ranges and accepted flags without host sync side effects.
    @Test
    public void msyncValidatesMappedRangesAndFlags() {
        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 4 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            long mappedAddress = state.register(10);

            setSyscall(state, SYS_MSYNC, mappedAddress, PAGE_SIZE, MS_SYNC);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_MSYNC, mappedAddress, PAGE_SIZE, MS_ASYNC | MS_INVALIDATE);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_MSYNC, mappedAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_MSYNC, mappedAddress + 1, PAGE_SIZE, MS_SYNC);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_MSYNC, mappedAddress, -1, MS_SYNC);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_MSYNC, mappedAddress, PAGE_SIZE, MS_ASYNC | MS_SYNC);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_MSYNC, mappedAddress, PAGE_SIZE, 8);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_MSYNC, mappedAddress, PAGE_SIZE + 1, MS_SYNC);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOMEM, state.register(10));

            setSyscall(state, SYS_MSYNC, mappedAddress + 2 * PAGE_SIZE, PAGE_SIZE, MS_SYNC);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOMEM, state.register(10));
        }
    }

    /// Verifies memory-locking syscalls validate mapped ranges and accepted flags.
    @Test
    public void memoryLockingSyscallsValidateMappedRanges() {
        try (Memory memory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, 4 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            long mappedAddress = state.register(10);

            setSyscall(state, SYS_MLOCK, mappedAddress + 1, PAGE_SIZE - 1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_MLOCK, mappedAddress, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_MLOCK2, mappedAddress, PAGE_SIZE, MLOCK_ONFAULT);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_MLOCK2, mappedAddress, PAGE_SIZE, MLOCK_ONFAULT << 1);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_MUNLOCK, mappedAddress, PAGE_SIZE, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_MLOCK, mappedAddress, -1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_MLOCK, mappedAddress, PAGE_SIZE + 1, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOMEM, state.register(10));

            setSyscall(state, SYS_MLOCK, mappedAddress + 2 * PAGE_SIZE, PAGE_SIZE, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(ENOMEM, state.register(10));

            setSyscall(state, SYS_MLOCKALL, MCL_CURRENT | MCL_ONFAULT, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_MLOCKALL, MCL_FUTURE, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));

            setSyscall(state, SYS_MLOCKALL, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_MLOCKALL, MCL_ONFAULT, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_MLOCKALL, 8, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_MUNLOCKALL, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
        }
    }

    /// Verifies that `mincore` reports mapped pages as resident.
    @Test
    public void mincoreReportsMappedPagesResident() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    2L * PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            long mappedAddress = state.register(10);
            long vectorAddress = memory.baseAddress() + 128;

            setSyscall(state, SYS_MINCORE, mappedAddress, PAGE_SIZE + 1, vectorAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            assertArrayEquals(new byte[]{1, 1}, memory.readBytes(vectorAddress, 2));

            setSyscall(state, SYS_MINCORE, mappedAddress + 1, PAGE_SIZE, vectorAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EINVAL, state.register(10));

            setSyscall(state, SYS_MINCORE, mappedAddress, PAGE_SIZE, memory.endAddress());
            state.syscalls().handle(state, TEST_PC);
            assertEquals(EFAULT, state.register(10));
        }
    }

    /// Verifies that `brk` does not grow into active anonymous mappings.
    @Test
    public void brkDoesNotOverlapAnonymousMappings() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 4 * PAGE_SIZE)) {
            long initialBreak = memory.baseAddress() + PAGE_SIZE;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);

            setSyscall(
                    state,
                    SYS_MMAP,
                    0,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(initialBreak, state.register(10));

            setSyscall(state, SYS_BRK, initialBreak + PAGE_SIZE, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(initialBreak, state.register(10));
        }
    }

    /// Verifies that `brk` reports and updates the program break inside guest memory.
    @Test
    public void brkTracksProgramBreakWithinGuestMemory() {
        try (Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 1024)) {
            long initialBreak = memory.baseAddress() + 128;
            long requestedBreak = initialBreak + 64;
            RiscVThreadState state = state(
                    memory,
                    new ByteArrayInputStream(new byte[0]),
                    new ByteArrayOutputStream(),
                    new ByteArrayOutputStream(),
                    initialBreak);

            setSyscall(state, SYS_BRK, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(initialBreak, state.register(10));

            setSyscall(state, SYS_BRK, requestedBreak, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(requestedBreak, state.register(10));

            setSyscall(state, SYS_BRK, initialBreak - 1, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(requestedBreak, state.register(10));

            setSyscall(state, SYS_BRK, memory.endAddress() + 1, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(requestedBreak, state.register(10));
        }
    }

    /// Verifies decoded-block generations are unique across independent address spaces.
    @Test
    public void instructionFetchGenerationsAreGloballyUnique() {
        try (Memory firstMemory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, Memory.DEFAULT_PAGE_SIZE);
             Memory secondMemory = Memory.sparse(Memory.DEFAULT_BASE_ADDRESS, Memory.DEFAULT_PAGE_SIZE)) {
            RiscVThreadState first = state(firstMemory, new ByteArrayInputStream(new byte[0]));
            RiscVThreadState second = state(secondMemory, new ByteArrayInputStream(new byte[0]));

            long firstInitialGeneration = first.instructionFetchGeneration();
            long secondInitialGeneration = second.instructionFetchGeneration();
            assertTrue(firstInitialGeneration != secondInitialGeneration);

            first.fenceInstructionFetch();
            long firstAfterFenceGeneration = first.instructionFetchGeneration();
            assertTrue(firstAfterFenceGeneration != firstInitialGeneration);
            assertTrue(firstAfterFenceGeneration != secondInitialGeneration);

            second.fenceInstructionFetch();
            assertTrue(second.instructionFetchGeneration() != firstAfterFenceGeneration);
        }
    }

    /// Creates test machine state with empty output streams.
    private static RiscVThreadState state(Memory memory, ByteArrayInputStream in) {
        return state(memory, in, new ByteArrayOutputStream(), new ByteArrayOutputStream(), memory.baseAddress());
    }

    /// Creates test machine state with a configured guest time source.
    private static RiscVThreadState state(Memory memory, ByteArrayInputStream in, TimeSource timeSource) {
        return state(
                memory,
                in,
                new ByteArrayOutputStream(),
                new ByteArrayOutputStream(),
                memory.baseAddress(),
                Path.of("."),
                timeSource);
    }

    /// Creates test machine state with a syscall handler.
    private static RiscVThreadState state(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak) {
        return state(memory, in, out, err, initialProgramBreak, Path.of("."));
    }

    /// Creates test machine state with a syscall handler and root mount.
    private static RiscVThreadState state(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            Path hostRoot) {
        return state(memory, in, out, err, initialProgramBreak, hostRoot, TimeSource.system());
    }

    /// Creates test machine state with a syscall handler and custom filesystem namespace.
    private static RiscVThreadState state(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            GuestFileSystem fileSystem) {
        return state(memory, in, out, err, initialProgramBreak, fileSystem, GuestCredentials.defaultUser());
    }

    /// Creates test machine state with a syscall handler, custom filesystem namespace, and credentials.
    private static RiscVThreadState state(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            GuestFileSystem fileSystem,
            GuestCredentials credentials) {
        GuestSyscalls syscalls = new LinuxGuestSyscalls(
                memory,
                in,
                out,
                err,
                initialProgramBreak,
                fileSystem,
                TimeSource.system(),
                credentials);
        return new RiscVThreadState(
                memory,
                0,
                false,
                ElfImage.ABSENT_ADDRESS,
                ElfImage.ABSENT_ADDRESS,
                syscalls);
    }

    /// Creates test machine state with an attached framebuffer device.
    private static RiscVThreadState framebufferState(
            Memory memory,
            long initialProgramBreak,
            FramebufferDevice framebufferDevice) {
        GuestSyscalls syscalls = new LinuxGuestSyscalls(
                memory,
                new ByteArrayInputStream(new byte[0]),
                new ByteArrayOutputStream(),
                new ByteArrayOutputStream(),
                initialProgramBreak,
                new String[0],
                TimeSource.system(),
                false,
                GuestCredentials.defaultUser(),
                null,
                framebufferDevice);
        return new RiscVThreadState(
                memory,
                0,
                false,
                ElfImage.ABSENT_ADDRESS,
                ElfImage.ABSENT_ADDRESS,
                syscalls);
    }

    /// Verifies a guest TCP client can exchange bytes with a host loopback server.
    private static void assertGuestTcpClientEcho(InetAddress loopback) throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, loopback);
             Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 8192)) {
            RiscVThreadState state = hostNetworkState(memory);
            long sockaddrAddress = memory.baseAddress();
            long lengthAddress = memory.baseAddress() + 64;
            long bufferAddress = memory.baseAddress() + 128;
            long optionAddress = memory.baseAddress() + 256;
            long optionLengthAddress = memory.baseAddress() + 264;
            int sockaddrSize = loopback.getAddress().length == Integer.BYTES ? SOCKADDR_IN_SIZE : SOCKADDR_IN6_SIZE;
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> serverTask = executor.submit(() -> {
                    try (Socket socket = server.accept()) {
                        byte[] request = socket.getInputStream().readNBytes(4);
                        assertEquals("ping", new String(request, StandardCharsets.UTF_8));
                        socket.getOutputStream().write("pong".getBytes(StandardCharsets.UTF_8));
                    }
                    return null;
                });

                setSyscall(
                        state,
                        SYS_SOCKET,
                        sockaddrSize == SOCKADDR_IN_SIZE ? AF_INET : AF_INET6,
                        SOCK_STREAM,
                        IPPROTO_TCP);
                state.syscalls().handle(state, TEST_PC);
                int socketFileDescriptor = (int) state.register(10);
                assertEquals(3, socketFileDescriptor);

                writeInetSockaddr(memory, sockaddrAddress, loopback, server.getLocalPort());
                setSyscall(state, SYS_CONNECT, socketFileDescriptor, sockaddrAddress, sockaddrSize);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));

                memory.writeInt(optionLengthAddress, Integer.BYTES);
                setSyscall(state, SYS_GETSOCKOPT, socketFileDescriptor, SOL_SOCKET, SO_ERROR, optionAddress, optionLengthAddress);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(0, state.register(10));
                assertEquals(0, memory.readInt(optionAddress));

                byte[] request = "ping".getBytes(StandardCharsets.UTF_8);
                memory.writeBytes(bufferAddress, request, 0, request.length);
                setSyscall(state, SYS_WRITE, socketFileDescriptor, bufferAddress, request.length);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(request.length, state.register(10));

                setSyscall(state, SYS_READ, socketFileDescriptor, bufferAddress, 4);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(4, state.register(10));
                assertEquals("pong", readGuestString(memory, bufferAddress, 4));
                waitForNetworkTask(serverTask);
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /// Verifies a guest UDP socket can exchange datagrams with a host loopback server.
    private static void assertGuestUdpEcho(InetAddress loopback) throws Exception {
        try (DatagramSocket server = new DatagramSocket(new InetSocketAddress(loopback, 0));
             Memory memory = new Memory(Memory.DEFAULT_BASE_ADDRESS, 8192)) {
            RiscVThreadState state = hostNetworkState(memory);
            long sockaddrAddress = memory.baseAddress();
            long lengthAddress = memory.baseAddress() + 64;
            long bufferAddress = memory.baseAddress() + 128;
            int sockaddrSize = loopback.getAddress().length == Integer.BYTES ? SOCKADDR_IN_SIZE : SOCKADDR_IN6_SIZE;
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> serverTask = executor.submit(() -> {
                    byte[] request = new byte[4];
                    DatagramPacket packet = new DatagramPacket(request, request.length);
                    server.receive(packet);
                    assertEquals("ping", new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8));
                    byte[] response = "pong".getBytes(StandardCharsets.UTF_8);
                    server.send(new DatagramPacket(response, response.length, packet.getSocketAddress()));
                    return null;
                });

                setSyscall(
                        state,
                        SYS_SOCKET,
                        sockaddrSize == SOCKADDR_IN_SIZE ? AF_INET : AF_INET6,
                        SOCK_DGRAM,
                        IPPROTO_UDP);
                state.syscalls().handle(state, TEST_PC);
                int socketFileDescriptor = (int) state.register(10);
                assertEquals(3, socketFileDescriptor);

                byte[] request = "ping".getBytes(StandardCharsets.UTF_8);
                memory.writeBytes(bufferAddress, request, 0, request.length);
                writeInetSockaddr(memory, sockaddrAddress, loopback, server.getLocalPort());
                setSyscall(state, SYS_SENDTO, socketFileDescriptor, bufferAddress, request.length, 0, sockaddrAddress, sockaddrSize);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(request.length, state.register(10));

                memory.writeInt(lengthAddress, sockaddrSize);
                setSyscall(state, SYS_RECVFROM, socketFileDescriptor, bufferAddress, 4, 0, sockaddrAddress, lengthAddress);
                state.syscalls().handle(state, TEST_PC);
                assertEquals(4, state.register(10));
                assertEquals("pong", readGuestString(memory, bufferAddress, 4));
                waitForNetworkTask(serverTask);
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /// Creates test machine state with host guest networking enabled.
    private static RiscVThreadState hostNetworkState(Memory memory) {
        return hostNetworkState(memory, new String[0]);
    }

    /// Creates test machine state with host guest networking and filesystem mounts enabled.
    private static RiscVThreadState hostNetworkState(Memory memory, String @Unmodifiable [] filesystemMounts) {
        GuestSyscalls syscalls = new LinuxGuestSyscalls(
                memory,
                new ByteArrayInputStream(new byte[0]),
                new ByteArrayOutputStream(),
                new ByteArrayOutputStream(),
                memory.baseAddress(),
                filesystemMounts,
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

    /// Creates test machine state with a syscall handler, root mount, and guest time source.
    private static RiscVThreadState state(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            Path hostRoot,
            TimeSource timeSource) {
        GuestSyscalls syscalls = new LinuxGuestSyscalls(
                memory,
                in,
                out,
                err,
                initialProgramBreak,
                hostRoot,
                timeSource);
        return new RiscVThreadState(
                memory,
                0,
                false,
                ElfImage.ABSENT_ADDRESS,
                ElfImage.ABSENT_ADDRESS,
                syscalls);
    }

    /// Writes a null-terminated UTF-8 string into guest memory.
    private static void writeGuestString(Memory memory, long address, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        memory.writeBytes(address, bytes, 0, bytes.length);
        memory.writeByte(address + bytes.length, (byte) 0);
    }

    /// Writes one Linux RISC-V 64-bit `struct timespec` into guest memory.
    private static void writeTimespec(Memory memory, long address, long seconds, long nanoseconds) {
        memory.writeLong(address, seconds);
        memory.writeLong(address + Long.BYTES, nanoseconds);
    }

    /// Writes one Linux RISC-V 64-bit `struct itimerval` into guest memory.
    private static void writeItimerval(
            Memory memory,
            long address,
            long intervalSeconds,
            long intervalMicroseconds,
            long valueSeconds,
            long valueMicroseconds) {
        memory.writeLong(address + ITIMERVAL_INTERVAL_OFFSET + TIMEVAL_SECONDS_OFFSET, intervalSeconds);
        memory.writeLong(address + ITIMERVAL_INTERVAL_OFFSET + TIMEVAL_MICROSECONDS_OFFSET, intervalMicroseconds);
        memory.writeLong(address + ITIMERVAL_VALUE_OFFSET + TIMEVAL_SECONDS_OFFSET, valueSeconds);
        memory.writeLong(address + ITIMERVAL_VALUE_OFFSET + TIMEVAL_MICROSECONDS_OFFSET, valueMicroseconds);
    }

    /// Asserts one Linux RISC-V 64-bit `struct itimerval` in guest memory.
    private static void assertItimerval(
            Memory memory,
            long address,
            long intervalSeconds,
            long intervalMicroseconds,
            long valueSeconds,
            long valueMicroseconds) {
        assertEquals(intervalSeconds, memory.readLong(address + ITIMERVAL_INTERVAL_OFFSET + TIMEVAL_SECONDS_OFFSET));
        assertEquals(
                intervalMicroseconds,
                memory.readLong(address + ITIMERVAL_INTERVAL_OFFSET + TIMEVAL_MICROSECONDS_OFFSET));
        assertEquals(valueSeconds, memory.readLong(address + ITIMERVAL_VALUE_OFFSET + TIMEVAL_SECONDS_OFFSET));
        assertEquals(valueMicroseconds, memory.readLong(address + ITIMERVAL_VALUE_OFFSET + TIMEVAL_MICROSECONDS_OFFSET));
    }

    /// Writes one Linux RISC-V 64-bit `struct itimerspec` into guest memory.
    private static void writeItimerspec(
            Memory memory,
            long address,
            long intervalSeconds,
            long intervalNanoseconds,
            long valueSeconds,
            long valueNanoseconds) {
        writeTimespec(memory, address + ITIMERSPEC_INTERVAL_OFFSET, intervalSeconds, intervalNanoseconds);
        writeTimespec(memory, address + ITIMERSPEC_VALUE_OFFSET, valueSeconds, valueNanoseconds);
    }

    /// Writes one regular tar entry with explicit Linux metadata to an open archive.
    private static void writeTarFile(
            TarArchiveOutputStream tarOutput,
            String name,
            byte[] data,
            int mode,
            long userId,
            long groupId) throws IOException {
        TarArchiveEntry entry = new TarArchiveEntry(name);
        entry.setMode(mode);
        entry.setUserId(userId);
        entry.setGroupId(groupId);
        entry.setSize(data.length);
        tarOutput.putArchiveEntry(entry);
        tarOutput.write(data, 0, data.length);
        tarOutput.closeArchiveEntry();
    }

    /// Writes one directory tar entry with explicit Linux metadata to an open archive.
    private static void writeTarDirectory(
            TarArchiveOutputStream tarOutput,
            String name,
            int mode,
            long userId,
            long groupId) throws IOException {
        TarArchiveEntry entry = new TarArchiveEntry(name.endsWith("/") ? name : name + "/", true);
        entry.setMode(mode);
        entry.setUserId(userId);
        entry.setGroupId(groupId);
        entry.setSize(0);
        tarOutput.putArchiveEntry(entry);
        tarOutput.closeArchiveEntry();
    }

    /// Writes one symbolic-link tar entry with explicit Linux metadata to an open archive.
    private static void writeTarSymbolicLink(
            TarArchiveOutputStream tarOutput,
            String name,
            String target,
            int mode,
            long userId,
            long groupId) throws IOException {
        TarArchiveEntry entry = new TarArchiveEntry(name, TarConstants.LF_SYMLINK);
        entry.setLinkName(target);
        entry.setMode(mode);
        entry.setUserId(userId);
        entry.setGroupId(groupId);
        entry.setSize(0);
        tarOutput.putArchiveEntry(entry);
        tarOutput.closeArchiveEntry();
    }

    /// Reads a fixed-length UTF-8 string from guest memory.
    private static String readGuestString(Memory memory, long address, int length) {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.length; index++) {
            bytes[index] = (byte) memory.readUnsignedByte(address + index);
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /// Writes one IPv4 or IPv6 socket address into guest memory.
    private static void writeInetSockaddr(Memory memory, long address, InetAddress hostAddress, int port) {
        byte[] bytes = hostAddress.getAddress();
        memory.clear(address, bytes.length == Integer.BYTES ? SOCKADDR_IN_SIZE : SOCKADDR_IN6_SIZE);
        if (bytes.length == Integer.BYTES) {
            memory.writeShort(address, (short) AF_INET);
            writeNetworkPort(memory, address + SOCKADDR_PORT_OFFSET, port);
            memory.writeBytes(address + SOCKADDR_IN_ADDRESS_OFFSET, bytes, 0, bytes.length);
        } else {
            memory.writeShort(address, (short) AF_INET6);
            writeNetworkPort(memory, address + SOCKADDR_PORT_OFFSET, port);
            memory.writeBytes(address + SOCKADDR_IN6_ADDRESS_OFFSET, bytes, 0, bytes.length);
            memory.writeInt(address + SOCKADDR_IN6_SCOPE_ID_OFFSET, 0);
        }
    }

    /// Writes one Unix-domain socket address into guest memory and returns its byte length.
    private static int writeUnixSockaddr(Memory memory, long address, String guestPath) {
        byte[] bytes = guestPath.getBytes(StandardCharsets.UTF_8);
        memory.clear(address, SOCKADDR_UN_SIZE);
        memory.writeShort(address, (short) AF_UNIX);
        memory.writeBytes(address + SOCKADDR_UN_PATH_OFFSET, bytes, 0, bytes.length);
        memory.writeByte(address + SOCKADDR_UN_PATH_OFFSET + bytes.length, (byte) 0);
        return SOCKADDR_UN_PATH_OFFSET + bytes.length + 1;
    }

    /// Reads one network-endian port from guest memory.
    private static int readNetworkPort(Memory memory, long address) {
        return (memory.readUnsignedByte(address) << Byte.SIZE) | memory.readUnsignedByte(address + 1);
    }

    /// Writes one network-endian port to guest memory.
    private static void writeNetworkPort(Memory memory, long address, int port) {
        memory.writeByte(address, (byte) (port >>> Byte.SIZE));
        memory.writeByte(address + 1, (byte) port);
    }

    /// Waits for a background host networking task.
    private static void waitForNetworkTask(Future<?> task) throws Exception {
        task.get(5, TimeUnit.SECONDS);
    }

    /// Reads until the target buffer is full or the peer closes unexpectedly.
    private static void readFully(SocketChannel socket, ByteBuffer target) throws IOException {
        while (target.hasRemaining()) {
            if (socket.read(target) < 0) {
                throw new IOException("Socket closed before reading expected bytes");
            }
        }
    }

    /// Writes until the source buffer is empty.
    private static void writeFully(SocketChannel socket, ByteBuffer source) throws IOException {
        while (source.hasRemaining()) {
            socket.write(source);
        }
    }

    /// Sets an integer socket option and verifies the returned value.
    private static void assertSetAndGetSocketOption(
            RiscVThreadState state,
            Memory memory,
            int fileDescriptor,
            long level,
            long option,
            int value,
            long optionAddress,
            long optionLengthAddress) {
        memory.writeInt(optionAddress, value);
        setSyscall(state, SYS_SETSOCKOPT, fileDescriptor, level, option, optionAddress, Integer.BYTES);
        state.syscalls().handle(state, TEST_PC);
        assertEquals(0, state.register(10));

        memory.writeInt(optionAddress, 0);
        memory.writeInt(optionLengthAddress, Integer.BYTES);
        setSyscall(state, SYS_GETSOCKOPT, fileDescriptor, level, option, optionAddress, optionLengthAddress);
        state.syscalls().handle(state, TEST_PC);
        assertEquals(0, state.register(10));
        assertEquals(Integer.BYTES, memory.readInt(optionLengthAddress));
        assertEquals(value, memory.readInt(optionAddress));
    }

    /// Waits until `SO_ERROR` reports a pending socket error.
    private static int waitForSocketError(
            RiscVThreadState state,
            Memory memory,
            int fileDescriptor,
            long optionAddress,
            long optionLengthAddress) throws Exception {
        for (int attempt = 0; attempt < 100; attempt++) {
            memory.writeInt(optionAddress, 0);
            memory.writeInt(optionLengthAddress, Integer.BYTES);
            setSyscall(state, SYS_GETSOCKOPT, fileDescriptor, SOL_SOCKET, SO_ERROR, optionAddress, optionLengthAddress);
            state.syscalls().handle(state, TEST_PC);
            assertEquals(0, state.register(10));
            int error = memory.readInt(optionAddress);
            if (error != 0) {
                return error;
            }
            Thread.sleep(10);
        }
        return 0;
    }

    /// Waits until `pselect6` reports read readiness for one descriptor.
    private static void waitForPselectReadReady(
            RiscVThreadState state,
            Memory memory,
            long fileDescriptorSetAddress,
            int fileDescriptor) throws Exception {
        for (int attempt = 0; attempt < 50; attempt++) {
            memory.clear(fileDescriptorSetAddress, TEST_FD_SET_SIZE);
            setFdSetBit(memory, fileDescriptorSetAddress, fileDescriptor);
            setSyscall(state, SYS_PSELECT6, fileDescriptor + 1L, fileDescriptorSetAddress, 0, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            if (state.register(10) == 1 && isFdSetBitSet(memory, fileDescriptorSetAddress, fileDescriptor)) {
                return;
            }
            Thread.sleep(10);
        }
        assertEquals(1, state.register(10));
        assertTrue(isFdSetBitSet(memory, fileDescriptorSetAddress, fileDescriptor));
    }

    /// Waits until one poll descriptor reports readiness.
    private static void waitForPollReady(RiscVThreadState state, long pollAddress) throws Exception {
        for (int attempt = 0; attempt < 50; attempt++) {
            setSyscall(state, SYS_PPOLL, pollAddress, 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            if (state.register(10) == 1) {
                return;
            }
            Thread.sleep(10);
        }
        assertEquals(1, state.register(10));
    }

    /// Waits until one epoll interest reports readiness.
    private static void waitForEpollReady(
            RiscVThreadState state,
            int epollFileDescriptor,
            long eventsAddress) throws Exception {
        for (int attempt = 0; attempt < 50; attempt++) {
            setSyscall(state, SYS_EPOLL_PWAIT, epollFileDescriptor, eventsAddress, 1, 0, 0, 0);
            state.syscalls().handle(state, TEST_PC);
            if (state.register(10) == 1) {
                return;
            }
            Thread.sleep(10);
        }
        assertEquals(1, state.register(10));
    }

    /// Reads a null-terminated UTF-8 string from guest memory.
    private static String readGuestCString(Memory memory, long address, int maximumLength) {
        byte[] bytes = new byte[maximumLength];
        for (int index = 0; index < bytes.length; index++) {
            int value = memory.readUnsignedByte(address + index);
            if (value == 0) {
                return new String(bytes, 0, index, StandardCharsets.UTF_8);
            }
            bytes[index] = (byte) value;
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /// Writes a minimal Linux `struct nlmsghdr` request.
    private static void writeNetlinkRequest(Memory memory, long address, int type, int sequence) {
        memory.clear(address, 16);
        memory.writeInt(address, 16);
        memory.writeShort(address + NETLINK_HEADER_TYPE_OFFSET, (short) type);
        memory.writeInt(address + NETLINK_HEADER_SEQUENCE_OFFSET, sequence);
    }

    /// Prepares a guest `struct msghdr` with one receive iovec.
    private static void prepareRecvmsg(
            Memory memory,
            long messageAddress,
            long nameAddress,
            long iovecAddress,
            long responseAddress,
            long responseLength) {
        memory.clear(messageAddress, 64);
        memory.clear(nameAddress, SOCKADDR_NL_SIZE);
        memory.writeLong(messageAddress, nameAddress);
        memory.writeInt(messageAddress + MSGHDR_NAME_LENGTH_OFFSET, SOCKADDR_NL_SIZE);
        memory.writeLong(messageAddress + MSGHDR_IOV_OFFSET, iovecAddress);
        memory.writeLong(messageAddress + MSGHDR_IOV_LENGTH_OFFSET, 1);
        memory.writeLong(iovecAddress + IOVEC_BASE_OFFSET, responseAddress);
        memory.writeLong(iovecAddress + IOVEC_LENGTH_OFFSET, responseLength);
        memory.clear(responseAddress, responseLength);
    }

    /// Prepares one guest `struct mmsghdr` with one UDP send iovec.
    private static void writeMmsgUdpMessage(
            Memory memory,
            long messageAddress,
            long sockaddrAddress,
            long iovecAddress,
            long payloadAddress,
            InetAddress address,
            int port,
            String payload) {
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        memory.clear(messageAddress, MMSGHDR_SIZE);
        writeInetSockaddr(memory, sockaddrAddress, address, port);
        memory.writeBytes(payloadAddress, payloadBytes, 0, payloadBytes.length);
        memory.writeLong(messageAddress, sockaddrAddress);
        memory.writeInt(messageAddress + MSGHDR_NAME_LENGTH_OFFSET, SOCKADDR_IN_SIZE);
        memory.writeLong(messageAddress + MSGHDR_IOV_OFFSET, iovecAddress);
        memory.writeLong(messageAddress + MSGHDR_IOV_LENGTH_OFFSET, 1);
        memory.writeLong(iovecAddress + IOVEC_BASE_OFFSET, payloadAddress);
        memory.writeLong(iovecAddress + IOVEC_LENGTH_OFFSET, payloadBytes.length);
    }

    /// Verifies one `struct linux_dirent64` record and returns the next record address.
    private static long assertDirectoryEntry(Memory memory, long address, String name, int type, long nextOffset) {
        int recordLength = memory.readUnsignedShort(address + DIRENT64_RECORD_LENGTH_OFFSET);
        assertTrue(recordLength >= DIRENT64_NAME_OFFSET + name.length() + 1);
        assertEquals(nextOffset, memory.readLong(address + DIRENT64_NEXT_OFFSET));
        assertEquals(type, memory.readUnsignedByte(address + DIRENT64_TYPE_OFFSET));
        assertEquals(name, readGuestCString(memory, address + DIRENT64_NAME_OFFSET, recordLength - DIRENT64_NAME_OFFSET));
        return address + recordLength;
    }

    /// Verifies the deterministic `struct statfs` values exposed by the simulator.
    private static void assertStatfs(Memory memory, long address) {
        assertEquals(STATFS_MAGIC, memory.readLong(address + STATFS_TYPE_OFFSET));
        assertEquals(STATFS_BLOCK_SIZE, memory.readLong(address + STATFS_BLOCK_SIZE_OFFSET));
        assertEquals(STATFS_BLOCK_COUNT, memory.readLong(address + STATFS_BLOCKS_OFFSET));
        assertEquals(STATFS_BLOCK_COUNT, memory.readLong(address + STATFS_BLOCKS_FREE_OFFSET));
        assertEquals(STATFS_BLOCK_COUNT, memory.readLong(address + STATFS_BLOCKS_AVAILABLE_OFFSET));
        assertEquals(STATFS_FILE_COUNT, memory.readLong(address + STATFS_FILES_OFFSET));
        assertEquals(STATFS_FILE_COUNT, memory.readLong(address + STATFS_FILES_FREE_OFFSET));
        assertEquals(STATFS_NAME_MAX, memory.readLong(address + STATFS_NAME_LENGTH_OFFSET));
        assertEquals(STATFS_BLOCK_SIZE, memory.readLong(address + STATFS_FRAGMENT_SIZE_OFFSET));
        assertEquals(0, memory.readLong(address + STATFS_FLAGS_OFFSET));
    }

    /// Verifies the deterministic `struct statfs` values exposed by the virtual proc filesystem.
    private static void assertProcStatfs(Memory memory, long address) {
        assertEquals(PROC_SUPER_MAGIC, memory.readLong(address + STATFS_TYPE_OFFSET));
        assertEquals(STATFS_BLOCK_SIZE, memory.readLong(address + STATFS_BLOCK_SIZE_OFFSET));
        assertEquals(0, memory.readLong(address + STATFS_BLOCKS_OFFSET));
        assertEquals(0, memory.readLong(address + STATFS_BLOCKS_FREE_OFFSET));
        assertEquals(0, memory.readLong(address + STATFS_BLOCKS_AVAILABLE_OFFSET));
        assertEquals(STATFS_FILE_COUNT, memory.readLong(address + STATFS_FILES_OFFSET));
        assertEquals(STATFS_FILE_COUNT, memory.readLong(address + STATFS_FILES_FREE_OFFSET));
        assertEquals(STATFS_NAME_MAX, memory.readLong(address + STATFS_NAME_LENGTH_OFFSET));
        assertEquals(STATFS_BLOCK_SIZE, memory.readLong(address + STATFS_FRAGMENT_SIZE_OFFSET));
        assertEquals(0, memory.readLong(address + STATFS_FLAGS_OFFSET));
    }

    /// Verifies the deterministic `struct statfs` values exposed by the virtual sys filesystem.
    private static void assertSysfsStatfs(Memory memory, long address) {
        assertEquals(SYSFS_MAGIC, memory.readLong(address + STATFS_TYPE_OFFSET));
        assertEquals(STATFS_BLOCK_SIZE, memory.readLong(address + STATFS_BLOCK_SIZE_OFFSET));
        assertEquals(0, memory.readLong(address + STATFS_BLOCKS_OFFSET));
        assertEquals(0, memory.readLong(address + STATFS_BLOCKS_FREE_OFFSET));
        assertEquals(0, memory.readLong(address + STATFS_BLOCKS_AVAILABLE_OFFSET));
        assertEquals(STATFS_FILE_COUNT, memory.readLong(address + STATFS_FILES_OFFSET));
        assertEquals(STATFS_FILE_COUNT, memory.readLong(address + STATFS_FILES_FREE_OFFSET));
        assertEquals(STATFS_NAME_MAX, memory.readLong(address + STATFS_NAME_LENGTH_OFFSET));
        assertEquals(STATFS_BLOCK_SIZE, memory.readLong(address + STATFS_FRAGMENT_SIZE_OFFSET));
        assertEquals(0, memory.readLong(address + STATFS_FLAGS_OFFSET));
    }

    /// Verifies the deterministic `struct statx` values exposed by the simulator.
    private static void assertStatx(Memory memory, long address, int mode, long size) {
        assertEquals(STATX_BASIC_STATS_MASK, memory.readInt(address + STATX_MASK_OFFSET));
        assertEquals(STATFS_BLOCK_SIZE, memory.readInt(address + STATX_BLOCK_SIZE_OFFSET));
        assertEquals(0, memory.readLong(address + STATX_ATTRIBUTES_OFFSET));
        assertEquals(1, memory.readInt(address + STATX_LINK_COUNT_OFFSET));
        assertEquals(1000, memory.readInt(address + STATX_UID_OFFSET));
        assertEquals(1000, memory.readInt(address + STATX_GID_OFFSET));
        assertEquals(mode, memory.readUnsignedShort(address + STATX_MODE_OFFSET));
        assertTrue(memory.readLong(address + STATX_INODE_OFFSET) > 0);
        assertEquals(size, memory.readLong(address + STATX_FILE_SIZE_OFFSET));
        assertEquals((size + 511L) / 512L, memory.readLong(address + STATX_BLOCK_COUNT_OFFSET));
        assertEquals(0, memory.readLong(address + STATX_ATTRIBUTES_MASK_OFFSET));
        assertEquals(0, memory.readInt(address + STATX_DEVICE_MAJOR_OFFSET));
        assertEquals(0, memory.readInt(address + STATX_DEVICE_MINOR_OFFSET));
        assertEquals(STATX_SYNTHETIC_MOUNT_ID, memory.readLong(address + STATX_MOUNT_ID_OFFSET));
    }

    /// Writes a Linux RISC-V 64-bit `stack_t` into guest memory.
    private static void writeSignalStack(Memory memory, long address, long stackPointer, long flags, long size) {
        memory.writeLong(address + SIGNAL_STACK_POINTER_OFFSET, stackPointer);
        memory.writeInt(address + SIGNAL_STACK_FLAGS_OFFSET, (int) flags);
        memory.writeInt(address + SIGNAL_STACK_FLAGS_OFFSET + Integer.BYTES, 0);
        memory.writeLong(address + SIGNAL_STACK_SIZE_OFFSET, size);
    }

    /// Reads `ss_sp` from a Linux RISC-V 64-bit `stack_t`.
    private static long readSignalStackPointer(Memory memory, long address) {
        return memory.readLong(address + SIGNAL_STACK_POINTER_OFFSET);
    }

    /// Reads `ss_flags` from a Linux RISC-V 64-bit `stack_t`.
    private static long readSignalStackFlags(Memory memory, long address) {
        return Integer.toUnsignedLong(memory.readInt(address + SIGNAL_STACK_FLAGS_OFFSET));
    }

    /// Reads `ss_size` from a Linux RISC-V 64-bit `stack_t`.
    private static long readSignalStackSize(Memory memory, long address) {
        return memory.readLong(address + SIGNAL_STACK_SIZE_OFFSET);
    }

    /// Returns the Linux `sigset_t` bit for a signal number.
    private static long signalMask(long signalNumber) {
        return 1L << (signalNumber - 1L);
    }

    /// Writes a `struct riscv_hwprobe` key with a zero value.
    private static void writeHwprobeKey(Memory memory, long pairsAddress, int index, long key) {
        writeHwprobePair(memory, pairsAddress, index, key, 0);
    }

    /// Writes one `struct riscv_hwprobe` pair into guest memory.
    private static void writeHwprobePair(Memory memory, long pairsAddress, int index, long key, long value) {
        long pairAddress = pairsAddress + index * RISCV_HWPROBE_PAIR_SIZE;
        memory.writeLong(pairAddress + RISCV_HWPROBE_KEY_OFFSET, key);
        memory.writeLong(pairAddress + RISCV_HWPROBE_VALUE_OFFSET, value);
    }

    /// Reads a `struct riscv_hwprobe` key from guest memory.
    private static long readHwprobeKey(Memory memory, long pairsAddress, int index) {
        return memory.readLong(pairsAddress + index * RISCV_HWPROBE_PAIR_SIZE + RISCV_HWPROBE_KEY_OFFSET);
    }

    /// Reads a `struct riscv_hwprobe` value from guest memory.
    private static long readHwprobeValue(Memory memory, long pairsAddress, int index) {
        return memory.readLong(pairsAddress + index * RISCV_HWPROBE_PAIR_SIZE + RISCV_HWPROBE_VALUE_OFFSET);
    }

    /// Adds a high pointer tag that is removed when PMLEN is 7.
    private static long taggedAddress(long address) {
        return address | (1L << (Long.SIZE - 7));
    }

    /// Writes a packed Linux generic `struct epoll_event` into guest memory.
    private static void writeEpollEvent(Memory memory, long eventAddress, int events, long data) {
        memory.writeInt(eventAddress + EPOLL_EVENT_EVENTS_OFFSET, events);
        writeLongUnaligned(memory, eventAddress + EPOLL_EVENT_DATA_OFFSET, data);
    }

    /// Writes one Linux `struct pollfd` entry.
    private static void writePollFileDescriptor(
            Memory memory,
            long pollFileDescriptorsAddress,
            int index,
            int fileDescriptor,
            int events) {
        long address = pollFileDescriptorsAddress + (long) index * POLL_FD_SIZE;
        memory.writeInt(address, fileDescriptor);
        memory.writeShort(address + POLL_FD_EVENTS_OFFSET, (short) events);
        memory.writeShort(address + POLL_FD_REVENTS_OFFSET, (short) -1);
    }

    /// Reads the `revents` field from one Linux `struct pollfd` entry.
    private static int pollRevents(Memory memory, long pollFileDescriptorsAddress, int index) {
        return memory.readUnsignedShort(
                pollFileDescriptorsAddress + (long) index * POLL_FD_SIZE + POLL_FD_REVENTS_OFFSET);
    }

    /// Sets one descriptor bit in a Linux `fd_set`.
    private static void setFdSetBit(Memory memory, long fileDescriptorSetAddress, int fileDescriptor) {
        long wordAddress = fdSetWordAddress(fileDescriptorSetAddress, fileDescriptor);
        memory.writeLong(wordAddress, memory.readLong(wordAddress) | fdSetBit(fileDescriptor));
    }

    /// Returns true when one descriptor bit is set in a Linux `fd_set`.
    private static boolean isFdSetBitSet(Memory memory, long fileDescriptorSetAddress, int fileDescriptor) {
        return (memory.readLong(fdSetWordAddress(fileDescriptorSetAddress, fileDescriptor))
                & fdSetBit(fileDescriptor)) != 0;
    }

    /// Returns the word address containing one descriptor bit in a Linux `fd_set`.
    private static long fdSetWordAddress(long fileDescriptorSetAddress, int fileDescriptor) {
        return fileDescriptorSetAddress + (long) (fileDescriptor / Long.SIZE) * Long.BYTES;
    }

    /// Returns the word-local bit mask for one descriptor in a Linux `fd_set`.
    private static long fdSetBit(int fileDescriptor) {
        return 1L << (fileDescriptor % Long.SIZE);
    }

    /// Reads the `data` field from a packed Linux generic `struct epoll_event`.
    private static long readEpollEventData(Memory memory, long eventAddress) {
        return readLongUnaligned(memory, eventAddress + EPOLL_EVENT_DATA_OFFSET);
    }

    /// Reads a little-endian 64-bit value without requiring guest alignment.
    private static long readLongUnaligned(Memory memory, long address) {
        long value = 0;
        for (int index = 0; index < Long.BYTES; index++) {
            value |= (long) memory.readUnsignedByte(address + index) << (index * Byte.SIZE);
        }
        return value;
    }

    /// Writes a little-endian 64-bit value without requiring guest alignment.
    private static void writeLongUnaligned(Memory memory, long address, long value) {
        byte[] bytes = new byte[Long.BYTES];
        for (int index = 0; index < bytes.length; index++) {
            bytes[index] = (byte) (value >>> (index * Byte.SIZE));
        }
        memory.writeBytes(address, bytes, 0, bytes.length);
    }

    /// Populates the syscall number and the first three argument registers.
    private static void setSyscall(RiscVThreadState state, long callNumber, long a0, long a1, long a2) {
        setSyscall(state, callNumber, a0, a1, a2, 0);
    }

    /// Populates the syscall number and the first four argument registers.
    private static void setSyscall(RiscVThreadState state, long callNumber, long a0, long a1, long a2, long a3) {
        setSyscall(state, callNumber, a0, a1, a2, a3, 0, 0);
    }

    /// Populates the syscall number and the first five argument registers.
    private static void setSyscall(RiscVThreadState state, long callNumber, long a0, long a1, long a2, long a3, long a4) {
        setSyscall(state, callNumber, a0, a1, a2, a3, a4, 0);
    }

    /// Populates the syscall number and the first six argument registers.
    private static void setSyscall(
            RiscVThreadState state,
            long callNumber,
            long a0,
            long a1,
            long a2,
            long a3,
            long a4,
            long a5) {
        state.setRegister(10, a0);
        state.setRegister(11, a1);
        state.setRegister(12, a2);
        state.setRegister(13, a3);
        state.setRegister(14, a4);
        state.setRegister(15, a5);
        state.setRegister(17, callNumber);
    }

    /// Input stream that always fails reads.
    private static final class FailingInputStream extends InputStream {
        /// Always throws an I/O failure.
        @Override
        public int read() throws IOException {
            throw new IOException("read failure");
        }

        /// Always throws an I/O failure.
        @Override
        public int read(byte[] bytes) throws IOException {
            throw new IOException("read failure");
        }
    }

    /// Output stream that always fails writes.
    private static final class FailingOutputStream extends OutputStream {
        /// Always throws an I/O failure.
        @Override
        public void write(int value) throws IOException {
            throw new IOException("write failure");
        }

        /// Always throws an I/O failure.
        @Override
        public void write(byte[] bytes) throws IOException {
            throw new IOException("write failure");
        }
    }
}
