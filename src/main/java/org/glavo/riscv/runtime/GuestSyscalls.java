// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.riscv.runtime;

import org.glavo.riscv.RiscVContext;
import org.glavo.riscv.exception.IllegalInstructionException;
import org.glavo.riscv.exception.MemoryAccessException;
import org.glavo.riscv.exception.ProgramExitException;
import org.glavo.riscv.exception.ProcessImageReplacedException;
import org.glavo.riscv.exception.RiscVException;
import org.glavo.riscv.exception.ThreadExitException;
import org.glavo.riscv.memory.Memory;
import org.glavo.riscv.parser.ElfImage;
import org.glavo.riscv.runtime.fs.FilesystemMountSpec;
import org.glavo.riscv.runtime.fs.GuestFileSystem;
import org.glavo.riscv.runtime.fs.GuestFileSystem.ByteArraySeekableByteChannel;
import org.glavo.riscv.runtime.fs.GuestFileSystem.DirectoryEntry;
import org.glavo.riscv.runtime.fs.GuestFileSystem.HostMount;
import org.glavo.riscv.runtime.fs.GuestFileSystem.Mount;
import org.glavo.riscv.runtime.fs.GuestFileSystem.TarMount;
import org.glavo.riscv.runtime.fs.GuestFileSystem.TarNode;
import org.glavo.riscv.runtime.fs.GuestFileSystem.TarPath;
import org.glavo.riscv.runtime.fs.GuestFileSystem.VirtualMount;
import org.glavo.riscv.runtime.fs.GuestFileSystem.VirtualNode;
import org.glavo.riscv.runtime.fs.GuestFileSystem.VirtualPath;
import org.glavo.riscv.runtime.net.GuestSocket;
import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Unmodifiable;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.LongUnaryOperator;

/// Provides shared state and helpers for guest syscall ABI implementations.
@SuppressWarnings("OctalInteger")
@NotNullByDefault
public sealed abstract class GuestSyscalls implements AutoCloseable
        permits LinuxGuestSyscalls {
    /// Linux `EBADF` as a raw negative syscall result.
    protected static final long EBADF = -9;

    /// Linux `ECHILD` as a raw negative syscall result.
    protected static final long ECHILD = -10;

    /// Linux `ENOENT` as a raw negative syscall result.
    protected static final long ENOENT = -2;

    /// Linux `E2BIG` as a raw negative syscall result.
    protected static final long E2BIG = -7;

    /// Linux `ENOEXEC` as a raw negative syscall result.
    protected static final long ENOEXEC = -8;

    /// Linux `ESRCH` as a raw negative syscall result.
    protected static final long ESRCH = -3;

    /// Linux `EACCES` as a raw negative syscall result.
    protected static final long EACCES = -13;

    /// Linux `EFAULT` as a raw negative syscall result.
    protected static final long EFAULT = -14;

    /// Linux `EPERM` as a raw negative syscall result.
    protected static final long EPERM = -1;

    /// Linux `ENOMEM` as a raw negative syscall result.
    protected static final long ENOMEM = -12;

    /// Linux `EEXIST` as a raw negative syscall result.
    protected static final long EEXIST = -17;

    /// Linux `EXDEV` as a raw negative syscall result.
    protected static final long EXDEV = -18;

    /// Linux `EINTR` as a raw negative syscall result.
    protected static final long EINTR = -4;

    /// Linux `EAGAIN` as a raw negative syscall result.
    protected static final long EAGAIN = -11;

    /// Linux `EBUSY` as a raw negative syscall result.
    protected static final long EBUSY = -16;

    /// Linux `ENODEV` as a raw negative syscall result.
    protected static final long ENODEV = -19;

    /// Linux `ENOTDIR` as a raw negative syscall result.
    protected static final long ENOTDIR = -20;

    /// Linux `EISDIR` as a raw negative syscall result.
    protected static final long EISDIR = -21;

    /// Linux `ENFILE` as a raw negative syscall result.
    protected static final long ENFILE = -23;

    /// Linux `EINVAL` as a raw negative syscall result.
    protected static final long EINVAL = -22;

    /// Linux `ENOTTY` as a raw negative syscall result.
    protected static final long ENOTTY = -25;

    /// Linux `EFBIG` as a raw negative syscall result.
    protected static final long EFBIG = -27;

    /// Linux `ERANGE` as a raw negative syscall result.
    protected static final long ERANGE = -34;

    /// Linux `ELOOP` as a raw negative syscall result.
    protected static final long ELOOP = -40;

    /// Linux `ENAMETOOLONG` as a raw negative syscall result.
    protected static final long ENAMETOOLONG = -36;

    /// Linux `ENOSYS` as a raw negative syscall result.
    protected static final long ENOSYS = -38;

    /// Linux `ENODATA` as a raw negative syscall result.
    protected static final long ENODATA = -61;

    /// Linux `EOVERFLOW` as a raw negative syscall result.
    protected static final long EOVERFLOW = -75;

    /// Linux `ENOTSUP` as a raw negative syscall result.
    protected static final long ENOTSUP = -95;

    /// Linux `ENOTSOCK` as a raw negative syscall result.
    protected static final long ENOTSOCK = -88;

    /// Linux `EAFNOSUPPORT` as a raw negative syscall result.
    protected static final long EAFNOSUPPORT = -97;

    /// Linux `ENOTEMPTY` as a raw negative syscall result.
    protected static final long ENOTEMPTY = -39;

    /// Linux `ESPIPE` as a raw negative syscall result.
    protected static final long ESPIPE = -29;

    /// Linux `EROFS` as a raw negative syscall result.
    protected static final long EROFS = -30;

    /// Linux `EPIPE` as a raw negative syscall result.
    protected static final long EPIPE = -32;

    /// Linux `EDESTADDRREQ` as a raw negative syscall result.
    protected static final long EDESTADDRREQ = -89;

    /// Linux `EMSGSIZE` as a raw negative syscall result.
    protected static final long EMSGSIZE = -90;

    /// Linux `ENOPROTOOPT` as a raw negative syscall result.
    protected static final long ENOPROTOOPT = -92;

    /// Linux `EPROTONOSUPPORT` as a raw negative syscall result.
    protected static final long EPROTONOSUPPORT = -93;

    /// Linux `EADDRINUSE` as a raw negative syscall result.
    protected static final long EADDRINUSE = -98;

    /// Linux `EADDRNOTAVAIL` as a raw negative syscall result.
    protected static final long EADDRNOTAVAIL = -99;

    /// Linux `ENETUNREACH` as a raw negative syscall result.
    protected static final long ENETUNREACH = -101;

    /// Linux `ECONNRESET` as a raw negative syscall result.
    protected static final long ECONNRESET = -104;

    /// Linux `EISCONN` as a raw negative syscall result.
    protected static final long EISCONN = -106;

    /// Linux `ENOTCONN` as a raw negative syscall result.
    protected static final long ENOTCONN = -107;

    /// Linux `ETIMEDOUT` as a raw negative syscall result.
    protected static final long ETIMEDOUT = -110;

    /// Linux `ECONNREFUSED` as a raw negative syscall result.
    protected static final long ECONNREFUSED = -111;

    /// Linux `EALREADY` as a raw negative syscall result.
    protected static final long EALREADY = -114;

    /// Linux `EINPROGRESS` as a raw negative syscall result.
    protected static final long EINPROGRESS = -115;

    /// The maximum Linux `iovcnt` accepted by `readv` and `writev`.
    protected static final long IOV_MAX = 1024;

    /// The byte size of one Linux RISC-V 64-bit `struct iovec`.
    protected static final int IOVEC_SIZE = 16;

    /// The byte offset of `d_ino` inside Linux `struct linux_dirent64`.
    protected static final int DIRENT64_INODE_OFFSET = 0;

    /// The byte offset of `d_off` inside Linux `struct linux_dirent64`.
    protected static final int DIRENT64_NEXT_OFFSET = 8;

    /// The byte offset of `d_reclen` inside Linux `struct linux_dirent64`.
    protected static final int DIRENT64_RECORD_LENGTH_OFFSET = 16;

    /// The byte offset of `d_type` inside Linux `struct linux_dirent64`.
    protected static final int DIRENT64_TYPE_OFFSET = 18;

    /// The byte offset of `d_name` inside Linux `struct linux_dirent64`.
    protected static final int DIRENT64_NAME_OFFSET = 19;

    /// The record alignment used by Linux `struct linux_dirent64`.
    protected static final int DIRENT64_RECORD_ALIGNMENT = Long.BYTES;

    /// Linux `DT_UNKNOWN` directory entry type.
    protected static final byte DIRECTORY_ENTRY_UNKNOWN = 0;

    /// Linux `DT_DIR` directory entry type.
    protected static final byte DIRECTORY_ENTRY_DIRECTORY = 4;

    /// Linux `DT_REG` directory entry type.
    protected static final byte DIRECTORY_ENTRY_REGULAR_FILE = 8;

    /// Linux `DT_LNK` directory entry type.
    protected static final byte DIRECTORY_ENTRY_SYMBOLIC_LINK = 10;

    /// The byte offset of `iov_base` inside `struct iovec`.
    protected static final int IOVEC_BASE_OFFSET = 0;

    /// The byte offset of `iov_len` inside `struct iovec`.
    protected static final int IOVEC_LENGTH_OFFSET = 8;

    /// The maximum transient buffer size used by one `splice` copy step.
    protected static final int SPLICE_BUFFER_SIZE = 64 * 1024;

    /// The maximum transient buffer size used by one regular-file range copy step.
    protected static final int FILE_COPY_BUFFER_SIZE = 64 * 1024;

    /// Linux `SPLICE_F_MOVE`.
    protected static final long SPLICE_F_MOVE = 1;

    /// Linux `SPLICE_F_NONBLOCK`.
    protected static final long SPLICE_F_NONBLOCK = 2;

    /// Linux `SPLICE_F_MORE`.
    protected static final long SPLICE_F_MORE = 4;

    /// Linux `SPLICE_F_GIFT`.
    protected static final long SPLICE_F_GIFT = 8;

    /// Linux `splice` flags accepted by this simulator.
    protected static final long SUPPORTED_SPLICE_FLAGS =
            SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;

    /// Linux `F_OK` access mode.
    protected static final long F_OK = 0;

    /// Linux `X_OK` access mode bit.
    protected static final long X_OK = 1;

    /// Linux `W_OK` access mode bit.
    protected static final long W_OK = 2;

    /// Linux `R_OK` access mode bit.
    protected static final long R_OK = 4;

    /// Linux access mode bit mask accepted by `faccessat`.
    protected static final long ACCESS_MODE_MASK = R_OK | W_OK | X_OK;

    /// The Linux `AT_FDCWD` pseudo file descriptor for path-based syscalls.
    protected static final long AT_FDCWD = -100;

    /// Linux `AT_SYMLINK_NOFOLLOW`.
    protected static final long AT_SYMLINK_NOFOLLOW = 0x100;

    /// Linux `AT_SYMLINK_FOLLOW`.
    protected static final long AT_SYMLINK_FOLLOW = 0x400;

    /// Linux `AT_EACCESS`.
    protected static final long AT_EACCESS = 0x200;

    /// Linux `AT_REMOVEDIR`.
    protected static final long AT_REMOVEDIR = 0x200;

    /// Linux `AT_NO_AUTOMOUNT`.
    protected static final long AT_NO_AUTOMOUNT = 0x800;

    /// Linux `AT_EMPTY_PATH`.
    protected static final long AT_EMPTY_PATH = 0x1000;

    /// Linux `AT_STATX_FORCE_SYNC`.
    protected static final long AT_STATX_FORCE_SYNC = 0x2000;

    /// Linux `AT_STATX_DONT_SYNC`.
    protected static final long AT_STATX_DONT_SYNC = 0x4000;

    /// Linux `newfstatat` flags accepted by this simulator.
    protected static final long SUPPORTED_NEWFSTATAT_FLAGS = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

    /// Linux `statx` flags accepted by this simulator.
    protected static final long SUPPORTED_STATX_FLAGS =
            AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC;

    /// Linux `faccessat2` flags accepted by this simulator.
    protected static final long SUPPORTED_FACCESSAT2_FLAGS = AT_SYMLINK_NOFOLLOW | AT_EACCESS | AT_EMPTY_PATH;

    /// Linux `fchownat` flags accepted by this simulator.
    protected static final long SUPPORTED_FCHOWNAT_FLAGS = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

    /// Linux `fchmodat2` flags accepted by this simulator.
    protected static final long SUPPORTED_FCHMODAT2_FLAGS = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

    /// Linux `utimensat` flags accepted by this simulator.
    protected static final long SUPPORTED_UTIMENSAT_FLAGS = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

    /// Linux `UTIME_NOW`.
    protected static final long UTIME_NOW = 0x3fff_ffffL;

    /// Linux `UTIME_OMIT`.
    protected static final long UTIME_OMIT = 0x3fff_fffeL;

    /// Linux `O_ACCMODE`.
    protected static final long O_ACCMODE = 0x3;

    /// Linux `O_RDONLY`.
    protected static final long O_RDONLY = 0;

    /// Linux `O_WRONLY`.
    protected static final long O_WRONLY = 1;

    /// Linux `O_RDWR`.
    protected static final long O_RDWR = 2;

    /// Linux `O_CREAT`.
    protected static final long O_CREAT = 00000100L;

    /// Linux `O_EXCL`.
    protected static final long O_EXCL = 00000200L;

    /// Linux `O_NOCTTY`.
    protected static final long O_NOCTTY = 00000400L;

    /// Linux `O_TRUNC`.
    protected static final long O_TRUNC = 00001000L;

    /// Linux `O_APPEND`.
    protected static final long O_APPEND = 00002000L;

    /// Linux `O_NONBLOCK`.
    protected static final long O_NONBLOCK = 00004000L;

    /// Linux `O_DIRECTORY`.
    protected static final long O_DIRECTORY = 00200000L;

    /// Linux `O_CLOEXEC`.
    protected static final long O_CLOEXEC = 02000000L;

    /// Linux flags accepted by `TIOCGPTPEER`.
    protected static final long SUPPORTED_TIOCGPTPEER_FLAGS =
            O_ACCMODE | O_NOCTTY | O_NONBLOCK | O_CLOEXEC;

    /// Linux `EFD_SEMAPHORE`.
    protected static final long EFD_SEMAPHORE = 1;

    /// Linux flags accepted by `eventfd2`.
    protected static final long SUPPORTED_EVENTFD2_FLAGS = EFD_SEMAPHORE | O_NONBLOCK | O_CLOEXEC;

    /// Linux flags accepted by `epoll_create1`.
    protected static final long SUPPORTED_EPOLL_CREATE1_FLAGS = O_CLOEXEC;

    /// Linux `EPOLL_CTL_ADD`.
    protected static final int EPOLL_CTL_ADD = 1;

    /// Linux `EPOLL_CTL_DEL`.
    protected static final int EPOLL_CTL_DEL = 2;

    /// Linux `EPOLL_CTL_MOD`.
    protected static final int EPOLL_CTL_MOD = 3;

    /// Linux `EPOLLIN`.
    protected static final int EPOLLIN = 0x001;

    /// Linux `EPOLLOUT`.
    protected static final int EPOLLOUT = 0x004;

    /// Linux `EPOLLERR`.
    protected static final int EPOLLERR = 0x008;

    /// Linux `EPOLLHUP`.
    protected static final int EPOLLHUP = 0x010;

    /// The byte size of Linux RISC-V 64-bit `struct epoll_event`.
    protected static final int EPOLL_EVENT_SIZE = 16;

    /// The byte offset of `events` inside Linux RISC-V 64-bit `struct epoll_event`.
    protected static final int EPOLL_EVENT_EVENTS_OFFSET = 0;

    /// The byte offset of `data` inside Linux RISC-V 64-bit `struct epoll_event`.
    protected static final int EPOLL_EVENT_DATA_OFFSET = Long.BYTES;

    /// Linux `POLLIN`.
    protected static final int POLLIN = 0x001;

    /// Linux `POLLOUT`.
    protected static final int POLLOUT = 0x004;

    /// Linux `POLLERR`.
    protected static final int POLLERR = 0x008;

    /// Linux `POLLHUP`.
    protected static final int POLLHUP = 0x010;

    /// Linux `POLLNVAL`.
    protected static final int POLLNVAL = 0x020;

    /// The byte size of Linux RISC-V 64-bit `struct pollfd`.
    protected static final int POLL_FD_SIZE = 8;

    /// The byte offset of `fd` inside Linux RISC-V 64-bit `struct pollfd`.
    protected static final int POLL_FD_FILE_DESCRIPTOR_OFFSET = 0;

    /// The byte offset of `events` inside Linux RISC-V 64-bit `struct pollfd`.
    protected static final int POLL_FD_EVENTS_OFFSET = Integer.BYTES;

    /// The byte offset of `revents` inside Linux RISC-V 64-bit `struct pollfd`.
    protected static final int POLL_FD_REVENTS_OFFSET = Integer.BYTES + Short.BYTES;

    /// The number of descriptor bits stored in one Linux RISC-V 64-bit `fd_set` word.
    protected static final int FD_SET_BITS_PER_WORD = Long.SIZE;

    /// The byte offset of `ss` inside the Linux `pselect6` signal-mask argument.
    protected static final int PSELECT6_SIGNAL_MASK_ADDRESS_OFFSET = 0;

    /// The byte offset of `ss_len` inside the Linux `pselect6` signal-mask argument.
    protected static final int PSELECT6_SIGNAL_SET_SIZE_OFFSET = Long.BYTES;

    /// The byte size of the Linux `pselect6` signal-mask argument on RISC-V 64-bit.
    protected static final int PSELECT6_SIGNAL_ARGUMENT_SIZE = 2 * Long.BYTES;

    /// Linux flags accepted by `pipe2`.
    protected static final long SUPPORTED_PIPE2_FLAGS = O_NONBLOCK | O_CLOEXEC;

    /// Linux flags accepted by `dup3`.
    protected static final long SUPPORTED_DUP3_FLAGS = O_CLOEXEC;

    /// Linux `F_DUPFD`.
    protected static final long F_DUPFD = 0;

    /// Linux `F_GETFD`.
    protected static final long F_GETFD = 1;

    /// Linux `F_SETFD`.
    protected static final long F_SETFD = 2;

    /// Linux `FD_CLOEXEC`.
    protected static final long FD_CLOEXEC = 1;

    /// Linux `CLOSE_RANGE_UNSHARE`.
    protected static final long CLOSE_RANGE_UNSHARE = 1L << 1;

    /// Linux `CLOSE_RANGE_CLOEXEC`.
    protected static final long CLOSE_RANGE_CLOEXEC = 1L << 2;

    /// FreeBSD `CLOSE_RANGE_CLOFORK`.
    protected static final long CLOSE_RANGE_CLOFORK = 1L << 3;

    /// Flags supported by `close_range`.
    protected static final long SUPPORTED_CLOSE_RANGE_FLAGS = CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC;

    /// Linux `F_GETFL`.
    protected static final long F_GETFL = 3;

    /// Linux `F_SETFL`.
    protected static final long F_SETFL = 4;

    /// Linux `F_GETLK`.
    protected static final long F_GETLK = 5;

    /// Linux `F_SETLK`.
    protected static final long F_SETLK = 6;

    /// Linux `F_SETLKW`.
    protected static final long F_SETLKW = 7;

    /// Linux `F_DUPFD_CLOEXEC`.
    protected static final long F_DUPFD_CLOEXEC = 1030;

    /// Linux `F_UNLCK`.
    protected static final short F_UNLCK = 2;

    /// The byte offset of `l_type` inside Linux RISC-V 64-bit `struct flock`.
    protected static final int FLOCK_TYPE_OFFSET = 0;

    /// The maximum guest path length accepted by `openat`, including the terminator.
    protected static final int PATH_MAX = 4096;

    /// The maximum number of argument or environment pointers accepted by `execve`.
    protected static final int EXECVE_MAX_VECTOR_ENTRIES = 131_072;

    /// The maximum bytes accepted for one `execve` argument or environment string, including the terminator.
    protected static final int EXECVE_MAX_STRING_BYTES = 128 * 1024;

    /// The maximum aggregate bytes accepted for `execve` argument and environment strings.
    protected static final int EXECVE_MAX_TOTAL_STRING_BYTES = 2 * 1024 * 1024;

    /// The maximum number of symbolic links followed while resolving one guest path.
    protected static final int SYMBOLIC_LINK_LIMIT = 40;

    /// The Linux generic tty `TCGETS` ioctl request number.
    protected static final long TCGETS = 0x5401;

    /// The Linux generic tty `TCSETS` ioctl request number.
    protected static final long TCSETS = 0x5402;

    /// The Linux generic tty `TCSETSW` ioctl request number.
    protected static final long TCSETSW = 0x5403;

    /// The Linux generic tty `TCSETSF` ioctl request number.
    protected static final long TCSETSF = 0x5404;

    /// The Linux generic tty `TCGETS2` ioctl request number.
    protected static final long TCGETS2 = 0x802c542aL;

    /// The Linux generic tty `TCSETS2` ioctl request number.
    protected static final long TCSETS2 = 0x402c542bL;

    /// The Linux generic tty `TCSETSW2` ioctl request number.
    protected static final long TCSETSW2 = 0x402c542cL;

    /// The Linux generic tty `TCSETSF2` ioctl request number.
    protected static final long TCSETSF2 = 0x402c542dL;

    /// The Linux generic tty `TIOCSCTTY` ioctl request number.
    protected static final long TIOCSCTTY = 0x540E;

    /// The Linux generic tty `TIOCGPGRP` ioctl request number.
    protected static final long TIOCGPGRP = 0x540F;

    /// The Linux generic tty `TIOCSPGRP` ioctl request number.
    protected static final long TIOCSPGRP = 0x5410;

    /// The Linux generic tty `TIOCGWINSZ` ioctl request number.
    protected static final long TIOCGWINSZ = 0x5413;

    /// The Linux generic tty `TIOCSWINSZ` ioctl request number.
    protected static final long TIOCSWINSZ = 0x5414;

    /// The Linux generic tty `TIOCGSID` ioctl request number.
    protected static final long TIOCGSID = 0x5429;

    /// The Linux generic tty `TIOCGPTN` ioctl request number.
    protected static final long TIOCGPTN = 0x80045430L;

    /// The Linux generic tty `TIOCSPTLCK` ioctl request number.
    protected static final long TIOCSPTLCK = 0x40045431L;

    /// The Linux generic tty `TIOCGPTPEER` ioctl request number.
    protected static final long TIOCGPTPEER = 0x5441;

    /// The Linux framebuffer `FBIOGET_VSCREENINFO` ioctl request number.
    protected static final long FBIOGET_VSCREENINFO = 0x4600;

    /// The Linux framebuffer `FBIOGET_FSCREENINFO` ioctl request number.
    protected static final long FBIOGET_FSCREENINFO = 0x4602;

    /// The byte size of Linux generic `struct termios`.
    protected static final int TERMIOS_SIZE = 36;

    /// The byte size of Linux generic `struct termios2`.
    protected static final int TERMIOS2_SIZE = 44;

    /// The byte size of Linux generic `struct winsize`.
    protected static final int WINSIZE_SIZE = 8;

    /// The byte size of Linux generic 64-bit `struct stat`.
    protected static final int STAT_SIZE = 128;

    /// The byte size of Linux generic 64-bit `struct statfs`.
    protected static final int STATFS_SIZE = 120;

    /// The byte size of Linux generic `struct statx`.
    protected static final int STATX_SIZE = 256;

    /// The byte size of one Linux `struct utsname` field.
    protected static final int UTSNAME_FIELD_SIZE = 65;

    /// The byte size of Linux `struct utsname`.
    protected static final int UTSNAME_SIZE = 6 * UTSNAME_FIELD_SIZE;

    /// The byte offset of `sysname` inside Linux `struct utsname`.
    protected static final int UTSNAME_SYSNAME_OFFSET = 0;

    /// The byte offset of `nodename` inside Linux `struct utsname`.
    protected static final int UTSNAME_NODENAME_OFFSET = UTSNAME_FIELD_SIZE;

    /// The byte offset of `release` inside Linux `struct utsname`.
    protected static final int UTSNAME_RELEASE_OFFSET = 2 * UTSNAME_FIELD_SIZE;

    /// The byte offset of `version` inside Linux `struct utsname`.
    protected static final int UTSNAME_VERSION_OFFSET = 3 * UTSNAME_FIELD_SIZE;

    /// The byte offset of `machine` inside Linux `struct utsname`.
    protected static final int UTSNAME_MACHINE_OFFSET = 4 * UTSNAME_FIELD_SIZE;

    /// The byte offset of `domainname` inside Linux `struct utsname`.
    protected static final int UTSNAME_DOMAINNAME_OFFSET = 5 * UTSNAME_FIELD_SIZE;

    /// The byte offset of `tv_sec` inside Linux RISC-V 64-bit `struct timeval`.
    protected static final int TIMEVAL_SECONDS_OFFSET = 0;

    /// The byte offset of `tv_usec` inside Linux RISC-V 64-bit `struct timeval`.
    protected static final int TIMEVAL_MICROSECONDS_OFFSET = Long.BYTES;

    /// The byte size of Linux RISC-V 64-bit `struct timeval`.
    protected static final int TIMEVAL_SIZE = 2 * Long.BYTES;

    /// The byte offset of `it_interval` inside Linux RISC-V 64-bit `struct itimerval`.
    protected static final int ITIMERVAL_INTERVAL_OFFSET = 0;

    /// The byte offset of `it_value` inside Linux RISC-V 64-bit `struct itimerval`.
    protected static final int ITIMERVAL_VALUE_OFFSET = TIMEVAL_SIZE;

    /// The byte size of Linux RISC-V 64-bit `struct itimerval`.
    protected static final int ITIMERVAL_SIZE = 2 * TIMEVAL_SIZE;

    /// The byte offset of `tz_minuteswest` inside Linux `struct timezone`.
    protected static final int TIMEZONE_MINUTESWEST_OFFSET = 0;

    /// The byte offset of `tz_dsttime` inside Linux `struct timezone`.
    protected static final int TIMEZONE_DSTTIME_OFFSET = Integer.BYTES;

    /// The byte size of Linux RISC-V 64-bit `struct tms`.
    protected static final int TMS_SIZE = 4 * Long.BYTES;

    /// The byte offset of `tms_utime` inside Linux RISC-V 64-bit `struct tms`.
    protected static final int TMS_USER_TIME_OFFSET = 0;

    /// The byte offset of `tms_stime` inside Linux RISC-V 64-bit `struct tms`.
    protected static final int TMS_SYSTEM_TIME_OFFSET = Long.BYTES;

    /// The byte offset of `tms_cutime` inside Linux RISC-V 64-bit `struct tms`.
    protected static final int TMS_CHILD_USER_TIME_OFFSET = 2 * Long.BYTES;

    /// The byte offset of `tms_cstime` inside Linux RISC-V 64-bit `struct tms`.
    protected static final int TMS_CHILD_SYSTEM_TIME_OFFSET = 3 * Long.BYTES;

    /// The byte size of Linux RISC-V 64-bit `struct rusage`.
    protected static final int RUSAGE_SIZE = 144;

    /// The byte offset of `ru_utime` inside Linux RISC-V 64-bit `struct rusage`.
    protected static final int RUSAGE_USER_TIME_OFFSET = 0;

    /// The byte offset of `ru_stime` inside Linux RISC-V 64-bit `struct rusage`.
    protected static final int RUSAGE_SYSTEM_TIME_OFFSET = 2 * Long.BYTES;

    /// The byte size of Linux RISC-V 64-bit `struct sysinfo`.
    protected static final int SYSINFO_SIZE = 112;

    /// The byte offset of `uptime` inside Linux RISC-V 64-bit `struct sysinfo`.
    protected static final int SYSINFO_UPTIME_OFFSET = 0;

    /// The byte offset of `loads` inside Linux RISC-V 64-bit `struct sysinfo`.
    protected static final int SYSINFO_LOADS_OFFSET = Long.BYTES;

    /// The byte offset of `totalram` inside Linux RISC-V 64-bit `struct sysinfo`.
    protected static final int SYSINFO_TOTAL_RAM_OFFSET = 4 * Long.BYTES;

    /// The byte offset of `freeram` inside Linux RISC-V 64-bit `struct sysinfo`.
    protected static final int SYSINFO_FREE_RAM_OFFSET = 5 * Long.BYTES;

    /// The byte offset of `sharedram` inside Linux RISC-V 64-bit `struct sysinfo`.
    protected static final int SYSINFO_SHARED_RAM_OFFSET = 6 * Long.BYTES;

    /// The byte offset of `bufferram` inside Linux RISC-V 64-bit `struct sysinfo`.
    protected static final int SYSINFO_BUFFER_RAM_OFFSET = 7 * Long.BYTES;

    /// The byte offset of `totalswap` inside Linux RISC-V 64-bit `struct sysinfo`.
    protected static final int SYSINFO_TOTAL_SWAP_OFFSET = 8 * Long.BYTES;

    /// The byte offset of `freeswap` inside Linux RISC-V 64-bit `struct sysinfo`.
    protected static final int SYSINFO_FREE_SWAP_OFFSET = 9 * Long.BYTES;

    /// The byte offset of `procs` inside Linux RISC-V 64-bit `struct sysinfo`.
    protected static final int SYSINFO_PROCESSES_OFFSET = 10 * Long.BYTES;

    /// The byte offset of `totalhigh` inside Linux RISC-V 64-bit `struct sysinfo`.
    protected static final int SYSINFO_TOTAL_HIGH_OFFSET = 11 * Long.BYTES;

    /// The byte offset of `freehigh` inside Linux RISC-V 64-bit `struct sysinfo`.
    protected static final int SYSINFO_FREE_HIGH_OFFSET = 12 * Long.BYTES;

    /// The byte offset of `mem_unit` inside Linux RISC-V 64-bit `struct sysinfo`.
    protected static final int SYSINFO_MEMORY_UNIT_OFFSET = 13 * Long.BYTES;

    /// Linux `RUSAGE_CHILDREN`.
    protected static final long RUSAGE_CHILDREN = -1;

    /// Linux `RUSAGE_SELF`.
    protected static final long RUSAGE_SELF = 0;

    /// Linux `RUSAGE_THREAD`.
    protected static final long RUSAGE_THREAD = 1;

    /// The byte offset of `rlim_cur` inside Linux RISC-V 64-bit `struct rlimit64`.
    protected static final int RLIMIT_CURRENT_OFFSET = 0;

    /// The byte offset of `rlim_max` inside Linux RISC-V 64-bit `struct rlimit64`.
    protected static final int RLIMIT_MAXIMUM_OFFSET = Long.BYTES;

    /// Linux `RLIM_INFINITY`.
    protected static final long RLIM_INFINITY = -1L;

    /// The number of Linux resource limits tracked by this simulator.
    protected static final int RESOURCE_LIMIT_COUNT = 16;

    /// Linux `RLIMIT_STACK`.
    protected static final int RLIMIT_STACK = 3;

    /// Linux `RLIMIT_NOFILE`.
    protected static final int RLIMIT_NOFILE = 7;

    /// The default stack soft limit exposed through `prlimit64`.
    protected static final long DEFAULT_STACK_LIMIT = 8L * 1024L * 1024L;

    /// The default open-file soft and hard limit exposed through `prlimit64`.
    protected static final long DEFAULT_OPEN_FILE_LIMIT = 1024;

    /// Default Linux resource-limit soft values.
    protected static final long @Unmodifiable [] DEFAULT_RESOURCE_LIMIT_CURRENT = initialResourceLimitCurrent();

    /// Default Linux resource-limit hard values.
    protected static final long @Unmodifiable [] DEFAULT_RESOURCE_LIMIT_MAXIMUM = initialResourceLimitMaximum();

    /// The bit mask for Linux `mmap` protection values accepted by this simulator.
    protected static final long SUPPORTED_MMAP_PROTECTION_MASK = 0x7;

    /// Linux `PROT_NONE`.
    protected static final long PROT_NONE = 0x0;

    /// Linux `MAP_SHARED`.
    protected static final long MAP_SHARED = 0x01;

    /// Linux `MAP_PRIVATE`.
    protected static final long MAP_PRIVATE = 0x02;

    /// Linux `MAP_SHARED_VALIDATE`.
    protected static final long MAP_SHARED_VALIDATE = 0x03;

    /// Linux `MAP_TYPE`.
    protected static final long MAP_TYPE = 0x0f;

    /// Linux `MAP_FIXED`.
    protected static final long MAP_FIXED = 0x10;

    /// Linux `MAP_ANONYMOUS`.
    protected static final long MAP_ANONYMOUS = 0x20;

    /// Linux `MAP_HUGETLB`.
    protected static final long MAP_HUGETLB = 0x40000;

    /// Linux `MAP_FIXED_NOREPLACE`.
    protected static final long MAP_FIXED_NOREPLACE = 0x100000;

    /// Linux `MADV_NORMAL`.
    protected static final long MADV_NORMAL = 0;

    /// Linux `MADV_RANDOM`.
    protected static final long MADV_RANDOM = 1;

    /// Linux `MADV_SEQUENTIAL`.
    protected static final long MADV_SEQUENTIAL = 2;

    /// Linux `MADV_WILLNEED`.
    protected static final long MADV_WILLNEED = 3;

    /// Linux `MADV_DONTNEED`.
    protected static final long MADV_DONTNEED = 4;

    /// Linux `MADV_FREE`.
    protected static final long MADV_FREE = 8;

    /// The lowest valid POSIX file-advice value.
    protected static final long POSIX_FADV_NORMAL = 0;

    /// The highest valid POSIX file-advice value.
    protected static final long POSIX_FADV_NOREUSE = 5;

    /// Linux `MADV_DONTFORK`.
    protected static final long MADV_DONTFORK = 10;

    /// Linux `MADV_DOFORK`.
    protected static final long MADV_DOFORK = 11;

    /// Linux `MADV_MERGEABLE`.
    protected static final long MADV_MERGEABLE = 12;

    /// Linux `MADV_UNMERGEABLE`.
    protected static final long MADV_UNMERGEABLE = 13;

    /// Linux `MADV_HUGEPAGE`.
    protected static final long MADV_HUGEPAGE = 14;

    /// Linux `MADV_NOHUGEPAGE`.
    protected static final long MADV_NOHUGEPAGE = 15;

    /// Linux `MADV_DONTDUMP`.
    protected static final long MADV_DONTDUMP = 16;

    /// Linux `MADV_DODUMP`.
    protected static final long MADV_DODUMP = 17;

    /// Linux `MADV_WIPEONFORK`.
    protected static final long MADV_WIPEONFORK = 18;

    /// Linux `MADV_KEEPONFORK`.
    protected static final long MADV_KEEPONFORK = 19;

    /// Linux `MADV_COLD`.
    protected static final long MADV_COLD = 20;

    /// Linux `MADV_PAGEOUT`.
    protected static final long MADV_PAGEOUT = 21;

    /// Linux `MADV_POPULATE_READ`.
    protected static final long MADV_POPULATE_READ = 22;

    /// Linux `MADV_POPULATE_WRITE`.
    protected static final long MADV_POPULATE_WRITE = 23;

    /// Linux `MADV_DONTNEED_LOCKED`.
    protected static final long MADV_DONTNEED_LOCKED = 24;

    /// Linux `MADV_COLLAPSE`.
    protected static final long MADV_COLLAPSE = 25;

    /// Linux `MS_ASYNC`.
    protected static final long MS_ASYNC = 1;

    /// Linux `MS_INVALIDATE`.
    protected static final long MS_INVALIDATE = 2;

    /// Linux `MS_SYNC`.
    protected static final long MS_SYNC = 4;

    /// Linux `MCL_CURRENT`.
    protected static final long MCL_CURRENT = 1;

    /// Linux `MCL_FUTURE`.
    protected static final long MCL_FUTURE = 2;

    /// Linux `MCL_ONFAULT`.
    protected static final long MCL_ONFAULT = 4;

    /// Linux `MLOCK_ONFAULT`.
    protected static final long MLOCK_ONFAULT = 1;

    /// Linux `MREMAP_MAYMOVE`.
    protected static final long MREMAP_MAYMOVE = 1;

    /// Linux `MREMAP_FIXED`.
    protected static final long MREMAP_FIXED = 2;

    /// Linux `mremap` flags accepted by this simulator.
    protected static final long SUPPORTED_MREMAP_FLAGS = MREMAP_MAYMOVE | MREMAP_FIXED;

    /// Linux `FUTEX_WAIT`.
    protected static final long FUTEX_WAIT = 0;

    /// Linux `FUTEX_WAKE`.
    protected static final long FUTEX_WAKE = 1;

    /// Linux `FUTEX_WAIT_BITSET`.
    protected static final long FUTEX_WAIT_BITSET = 9;

    /// Linux `FUTEX_WAKE_BITSET`.
    protected static final long FUTEX_WAKE_BITSET = 10;

    /// Linux futex command mask.
    protected static final long FUTEX_COMMAND_MASK = 0x7f;

    /// Linux `FUTEX_PRIVATE_FLAG`.
    protected static final long FUTEX_PRIVATE_FLAG = 128;

    /// Linux `FUTEX_CLOCK_REALTIME`.
    protected static final long FUTEX_CLOCK_REALTIME = 256;

    /// Linux futex flags accepted by this simulator.
    protected static final long SUPPORTED_FUTEX_FLAGS = FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME;

    /// Linux `FUTEX_BITSET_MATCH_ANY`.
    protected static final long FUTEX_BITSET_MATCH_ANY = 0xffff_ffffL;

    /// Linux `WNOHANG`.
    protected static final long WAIT_NO_HANG = 0x00000001L;

    /// Linux `WUNTRACED`.
    protected static final long WAIT_UNTRACED = 0x00000002L;

    /// Linux `WCONTINUED`.
    protected static final long WAIT_CONTINUED = 0x00000008L;

    /// Linux internal `__WNOTHREAD`.
    protected static final long WAIT_NOT_THREAD = 0x20000000L;

    /// Linux internal `__WALL`.
    protected static final long WAIT_ALL_CHILDREN = 0x40000000L;

    /// Linux internal `__WCLONE`.
    protected static final long WAIT_CLONE_CHILDREN = 0x80000000L;

    /// Wait options accepted by the simulator.
    protected static final long SUPPORTED_WAIT_OPTIONS = WAIT_NO_HANG
            | WAIT_UNTRACED
            | WAIT_CONTINUED
            | WAIT_NOT_THREAD
            | WAIT_ALL_CHILDREN
            | WAIT_CLONE_CHILDREN;

    /// The byte size of Linux generic 64-bit kernel `sigset_t`.
    protected static final long KERNEL_SIGSET_SIZE = 8;

    /// The byte size of Linux RISC-V 64-bit kernel `struct sigaction`.
    protected static final long KERNEL_SIGACTION_SIZE = 24;

    /// The byte offset of `ss_sp` inside Linux RISC-V 64-bit `stack_t`.
    protected static final long SIGNAL_STACK_POINTER_OFFSET = 0;

    /// The byte offset of `ss_flags` inside Linux RISC-V 64-bit `stack_t`.
    protected static final long SIGNAL_STACK_FLAGS_OFFSET = Long.BYTES;

    /// The padding byte offset after `ss_flags` inside Linux RISC-V 64-bit `stack_t`.
    protected static final long SIGNAL_STACK_FLAGS_PADDING_OFFSET = SIGNAL_STACK_FLAGS_OFFSET + Integer.BYTES;

    /// The byte offset of `ss_size` inside Linux RISC-V 64-bit `stack_t`.
    protected static final long SIGNAL_STACK_SIZE_OFFSET = 2L * Long.BYTES;

    /// Linux `MINSIGSTKSZ`.
    protected static final long MINIMUM_SIGNAL_STACK_SIZE = 2048;

    /// Linux `SS_ONSTACK`.
    protected static final long SS_ONSTACK = 1;

    /// Linux `SS_DISABLE`.
    protected static final long SS_DISABLE = 2;

    /// Linux `SS_AUTODISARM`.
    protected static final long SS_AUTODISARM = 1L << 31;

    /// Linux flags accepted when registering an alternate signal stack.
    protected static final long SUPPORTED_SIGNAL_STACK_FLAGS = SS_DISABLE | SS_AUTODISARM;

    /// The byte size of the minimal CPU affinity mask exposed to the guest.
    protected static final long MINIMUM_CPU_AFFINITY_MASK_SIZE = Long.BYTES;

    /// POSIX `PRIO_PROCESS` priority target selector.
    protected static final int PRIO_PROCESS = 0;

    /// POSIX `PRIO_PGRP` priority target selector.
    protected static final int PRIO_PROCESS_GROUP = 1;

    /// POSIX `PRIO_USER` priority target selector.
    protected static final int PRIO_USER = 2;

    /// The highest scheduling priority represented by a portable nice value.
    protected static final int NICE_MINIMUM = -20;

    /// The lowest scheduling priority represented by a portable nice value.
    protected static final int NICE_MAXIMUM = 19;

    /// The raw Linux syscall value corresponding to nice level zero.
    protected static final int LINUX_DEFAULT_RAW_PRIORITY = 20;

    /// Linux `SCHED_OTHER`.
    protected static final int SCHED_OTHER = 0;

    /// Linux `SCHED_FIFO`.
    protected static final int SCHED_FIFO = 1;

    /// Linux `SCHED_RR`.
    protected static final int SCHED_RR = 2;

    /// Linux `SCHED_BATCH`.
    protected static final int SCHED_BATCH = 3;

    /// Linux `SCHED_IDLE`.
    protected static final int SCHED_IDLE = 5;

    /// Linux `SCHED_RESET_ON_FORK`.
    protected static final int SCHED_RESET_ON_FORK = 0x40000000;

    /// The byte offset of `sched_priority` inside Linux RISC-V 64-bit `struct sched_param`.
    protected static final int SCHED_PARAM_PRIORITY_OFFSET = 0;

    /// The Linux real-time scheduling minimum priority.
    protected static final int SCHED_REALTIME_PRIORITY_MINIMUM = 1;

    /// The Linux real-time scheduling maximum priority.
    protected static final int SCHED_REALTIME_PRIORITY_MAXIMUM = 99;

    /// The deterministic round-robin interval reported for the simulated scheduler.
    protected static final long SCHED_RR_INTERVAL_NANOSECONDS = 100_000_000L;

    /// Linux `CLOCK_REALTIME`.
    protected static final long CLOCK_REALTIME = 0;

    /// Linux `CLOCK_MONOTONIC`.
    protected static final long CLOCK_MONOTONIC = 1;

    /// Linux `CLOCK_PROCESS_CPUTIME_ID`.
    protected static final long CLOCK_PROCESS_CPUTIME_ID = 2;

    /// Linux `CLOCK_THREAD_CPUTIME_ID`.
    protected static final long CLOCK_THREAD_CPUTIME_ID = 3;

    /// Linux `CLOCK_MONOTONIC_RAW`.
    protected static final long CLOCK_MONOTONIC_RAW = 4;

    /// Linux `CLOCK_REALTIME_COARSE`.
    protected static final long CLOCK_REALTIME_COARSE = 5;

    /// Linux `CLOCK_MONOTONIC_COARSE`.
    protected static final long CLOCK_MONOTONIC_COARSE = 6;

    /// Linux `CLOCK_BOOTTIME`.
    protected static final long CLOCK_BOOTTIME = 7;

    /// Linux `TIMER_ABSTIME`.
    protected static final long TIMER_ABSTIME = 1;

    /// Linux `TFD_TIMER_ABSTIME`.
    protected static final long TFD_TIMER_ABSTIME = 1;

    /// Linux flags accepted by `timerfd_create`.
    protected static final long SUPPORTED_TIMERFD_CREATE_FLAGS = O_NONBLOCK | O_CLOEXEC;

    /// Linux flags accepted by `timerfd_settime`.
    protected static final long SUPPORTED_TIMERFD_SETTIME_FLAGS = TFD_TIMER_ABSTIME;

    /// Linux flags accepted by `clock_nanosleep`.
    protected static final long SUPPORTED_CLOCK_NANOSLEEP_FLAGS = TIMER_ABSTIME;

    /// Linux `ITIMER_REAL`.
    protected static final int ITIMER_REAL = 0;

    /// Linux `ITIMER_VIRTUAL`.
    protected static final int ITIMER_VIRTUAL = 1;

    /// Linux `ITIMER_PROF`.
    protected static final int ITIMER_PROF = 2;

    /// The number of Linux interval timers tracked by this simulator.
    protected static final int ITIMER_COUNT = 3;

    /// The `tv_sec` byte offset inside Linux RISC-V 64-bit `struct timespec`.
    protected static final int TIMESPEC_SECONDS_OFFSET = 0;

    /// The `tv_nsec` byte offset inside Linux RISC-V 64-bit `struct timespec`.
    protected static final int TIMESPEC_NANOSECONDS_OFFSET = Long.BYTES;

    /// The byte size of Linux RISC-V 64-bit `struct timespec`.
    protected static final int TIMESPEC_SIZE = Long.BYTES * 2;

    /// The byte offset of `it_interval` inside Linux RISC-V 64-bit `struct itimerspec`.
    protected static final int ITIMERSPEC_INTERVAL_OFFSET = 0;

    /// The byte offset of `it_value` inside Linux RISC-V 64-bit `struct itimerspec`.
    protected static final int ITIMERSPEC_VALUE_OFFSET = TIMESPEC_SIZE;

    /// The byte size of Linux RISC-V 64-bit `struct itimerspec`.
    protected static final int ITIMERSPEC_SIZE = TIMESPEC_SIZE * 2;

    /// The number of nanoseconds in one second.
    protected static final long NANOSECONDS_PER_SECOND = 1_000_000_000L;

    /// The Linux user-space clock ticks per second value used by `times`.
    protected static final long CLOCK_TICKS_PER_SECOND = 100L;

    /// The number of nanoseconds in one millisecond.
    protected static final long NANOSECONDS_PER_MILLISECOND = 1_000_000L;

    /// Linux auxv executable filename pointer type.
    protected static final long AT_EXECFN = 31;

    /// The Linux task command string size used by `PR_SET_NAME` and `PR_GET_NAME`.
    protected static final int TASK_COMMAND_LENGTH = 16;

    /// The default timer slack value exposed by `PR_GET_TIMERSLACK`.
    protected static final long DEFAULT_TIMER_SLACK_NANOSECONDS = 50_000L;

    /// The lowest regular Linux signal number accepted by signal syscalls.
    protected static final long MIN_SIGNAL_NUMBER = 1;

    /// The highest regular Linux signal number accepted by signal syscalls.
    protected static final long MAX_SIGNAL_NUMBER = 64;

    /// Linux `SIGKILL`.
    protected static final long SIGKILL = 9;

    /// Linux `SIGSTOP`.
    protected static final long SIGSTOP = 19;

    /// Linux `SIG_BLOCK` signal-mask operation.
    protected static final long SIG_BLOCK = 0;

    /// Linux `SIG_UNBLOCK` signal-mask operation.
    protected static final long SIG_UNBLOCK = 1;

    /// Linux `SIG_SETMASK` signal-mask operation.
    protected static final long SIG_SETMASK = 2;

    /// Signal bits that Linux silently excludes from process signal masks.
    protected static final long UNBLOCKABLE_SIGNAL_MASK = signalMask(SIGKILL) | signalMask(SIGSTOP);

    /// The `st_ino` byte offset inside Linux generic 64-bit `struct stat`.
    protected static final int STAT_INODE_OFFSET = 8;

    /// The `st_mode` byte offset inside Linux generic 64-bit `struct stat`.
    protected static final int STAT_MODE_OFFSET = 16;

    /// The `st_nlink` byte offset inside Linux generic 64-bit `struct stat`.
    protected static final int STAT_LINK_COUNT_OFFSET = 20;

    /// The `st_uid` byte offset inside Linux generic 64-bit `struct stat`.
    protected static final int STAT_UID_OFFSET = 24;

    /// The `st_gid` byte offset inside Linux generic 64-bit `struct stat`.
    protected static final int STAT_GID_OFFSET = 28;

    /// The `st_size` byte offset inside Linux generic 64-bit `struct stat`.
    protected static final int STAT_SIZE_OFFSET = 48;

    /// The `st_blksize` byte offset inside Linux generic 64-bit `struct stat`.
    protected static final int STAT_BLOCK_SIZE_OFFSET = 56;

    /// The `st_blocks` byte offset inside Linux generic 64-bit `struct stat`.
    protected static final int STAT_BLOCK_COUNT_OFFSET = 64;

    /// The `st_atim` byte offset inside Linux generic 64-bit `struct stat`.
    protected static final int STAT_ACCESS_TIME_OFFSET = 72;

    /// The `st_mtim` byte offset inside Linux generic 64-bit `struct stat`.
    protected static final int STAT_MODIFICATION_TIME_OFFSET = 88;

    /// The `st_ctim` byte offset inside Linux generic 64-bit `struct stat`.
    protected static final int STAT_CHANGE_TIME_OFFSET = 104;

    /// The byte offset of `f_type` inside Linux generic 64-bit `struct statfs`.
    protected static final int STATFS_TYPE_OFFSET = 0;

    /// The byte offset of `f_bsize` inside Linux generic 64-bit `struct statfs`.
    protected static final int STATFS_BLOCK_SIZE_OFFSET = 8;

    /// The byte offset of `f_blocks` inside Linux generic 64-bit `struct statfs`.
    protected static final int STATFS_BLOCKS_OFFSET = 16;

    /// The byte offset of `f_bfree` inside Linux generic 64-bit `struct statfs`.
    protected static final int STATFS_BLOCKS_FREE_OFFSET = 24;

    /// The byte offset of `f_bavail` inside Linux generic 64-bit `struct statfs`.
    protected static final int STATFS_BLOCKS_AVAILABLE_OFFSET = 32;

    /// The byte offset of `f_files` inside Linux generic 64-bit `struct statfs`.
    protected static final int STATFS_FILES_OFFSET = 40;

    /// The byte offset of `f_ffree` inside Linux generic 64-bit `struct statfs`.
    protected static final int STATFS_FILES_FREE_OFFSET = 48;

    /// The byte offset of `f_namelen` inside Linux generic 64-bit `struct statfs`.
    protected static final int STATFS_NAME_LENGTH_OFFSET = 64;

    /// The byte offset of `f_frsize` inside Linux generic 64-bit `struct statfs`.
    protected static final int STATFS_FRAGMENT_SIZE_OFFSET = 72;

    /// The byte offset of `f_flags` inside Linux generic 64-bit `struct statfs`.
    protected static final int STATFS_FLAGS_OFFSET = 80;

    /// The byte offset of `stx_mask` inside Linux generic `struct statx`.
    protected static final int STATX_MASK_OFFSET = 0;

    /// The byte offset of `stx_blksize` inside Linux generic `struct statx`.
    protected static final int STATX_BLOCK_SIZE_OFFSET = 4;

    /// The byte offset of `stx_attributes` inside Linux generic `struct statx`.
    protected static final int STATX_ATTRIBUTES_OFFSET = 8;

    /// The byte offset of `stx_nlink` inside Linux generic `struct statx`.
    protected static final int STATX_LINK_COUNT_OFFSET = 16;

    /// The byte offset of `stx_uid` inside Linux generic `struct statx`.
    protected static final int STATX_UID_OFFSET = 20;

    /// The byte offset of `stx_gid` inside Linux generic `struct statx`.
    protected static final int STATX_GID_OFFSET = 24;

    /// The byte offset of `stx_mode` inside Linux generic `struct statx`.
    protected static final int STATX_MODE_OFFSET = 28;

    /// The byte offset of `stx_ino` inside Linux generic `struct statx`.
    protected static final int STATX_INODE_OFFSET = 32;

    /// The byte offset of `stx_size` inside Linux generic `struct statx`.
    protected static final int STATX_FILE_SIZE_OFFSET = 40;

    /// The byte offset of `stx_blocks` inside Linux generic `struct statx`.
    protected static final int STATX_BLOCK_COUNT_OFFSET = 48;

    /// The byte offset of `stx_attributes_mask` inside Linux generic `struct statx`.
    protected static final int STATX_ATTRIBUTES_MASK_OFFSET = 56;

    /// The byte offset of `stx_dev_major` inside Linux generic `struct statx`.
    protected static final int STATX_DEVICE_MAJOR_OFFSET = 136;

    /// The byte offset of `stx_dev_minor` inside Linux generic `struct statx`.
    protected static final int STATX_DEVICE_MINOR_OFFSET = 140;

    /// The byte offset of `stx_mnt_id` inside Linux generic `struct statx`.
    protected static final int STATX_MOUNT_ID_OFFSET = 144;

    /// The Linux `STATX_BASIC_STATS` bit mask returned by this simulator.
    protected static final int STATX_BASIC_STATS_MASK = 0x0000_07ff;

    /// The deterministic mount id returned by `statx`.
    protected static final long STATX_SYNTHETIC_MOUNT_ID = 1;

    /// The attribute mask returned by `statx`.
    protected static final long STATX_ATTRIBUTES_MASK = 0;

    /// The Linux `S_IFCHR` file type bit used for character devices.
    protected static final int STAT_MODE_CHARACTER_DEVICE = 0020000;

    /// The Linux `S_IFIFO` file type bit used for pipe endpoints.
    protected static final int STAT_MODE_FIFO = 0010000;

    /// The Linux `S_IFDIR` file type bit used for directories.
    protected static final int STAT_MODE_DIRECTORY = 0040000;

    /// The Linux `S_IFLNK` file type bit used for symbolic links.
    protected static final int STAT_MODE_SYMBOLIC_LINK = 0120000;

    /// The Linux `S_IFREG` file type bit used for regular files.
    protected static final int STAT_MODE_REGULAR_FILE = 0100000;

    /// The file permission bits exposed for standard streams.
    protected static final int STAT_MODE_READ_WRITE_ALL = 0666;

    /// The file permission bits exposed for symbolic links.
    protected static final int STAT_MODE_ALL = 0777;

    /// The Linux `S_ISGID` special mode bit.
    protected static final int STAT_MODE_SET_GROUP_ID = 02000;

    /// The Linux `S_ISUID` special mode bit.
    protected static final int STAT_MODE_SET_USER_ID = 04000;

    /// The Linux `S_ISVTX` sticky directory special mode bit.
    protected static final int STAT_MODE_STICKY = 01000;

    /// The file permission and special mode bits changed by `chmod`.
    protected static final int STAT_MODE_CHANGE_BITS = 07777;

    /// The file permission bits exposed for read-only host files.
    protected static final int STAT_MODE_READ_ALL = 0444;

    /// The file permission bits exposed for readable host directories.
    protected static final int STAT_MODE_READ_EXECUTE_ALL = 0555;

    /// The `st_mode` value exposed for the simulator standard streams.
    protected static final int STANDARD_STREAM_STAT_MODE = STAT_MODE_CHARACTER_DEVICE | STAT_MODE_READ_WRITE_ALL;

    /// The block size exposed for standard streams.
    protected static final int STANDARD_STREAM_BLOCK_SIZE = 4096;

    /// The synthetic filesystem magic returned by `statfs`.
    protected static final long STATFS_MAGIC = 0x0102_1994L;

    /// The synthetic filesystem block size returned by `statfs`.
    protected static final long STATFS_BLOCK_SIZE = 4096;

    /// The synthetic filesystem block count returned by `statfs`.
    protected static final long STATFS_BLOCK_COUNT = 1_048_576;

    /// The synthetic filesystem file count returned by `statfs`.
    protected static final long STATFS_FILE_COUNT = 1_048_576;

    /// The maximum guest filename length returned by `statfs`.
    protected static final long STATFS_NAME_MAX = 255;

    /// Linux `PROC_SUPER_MAGIC`.
    protected static final long PROC_SUPER_MAGIC = 0x9fa0L;

    /// Linux `SYSFS_MAGIC`.
    protected static final long SYSFS_MAGIC = 0x6265_6572L;

    /// The guest path where the built-in virtual proc filesystem is mounted.
    protected static final String PROC_MOUNT_PATH = "/proc";

    /// The guest path where the built-in virtual device filesystem is mounted.
    protected static final String DEV_MOUNT_PATH = "/dev";

    /// The guest path where the built-in virtual sys filesystem is mounted.
    protected static final String SYS_MOUNT_PATH = "/sys";

    /// The guest resolver configuration path.
    protected static final String RESOLV_CONF_PATH = "/etc/resolv.conf";

    /// Synthetic inode base used for virtual proc entries.
    protected static final long PROC_INODE_BASE = 0x7000_0000L;

    /// The non-cryptographic seed used for deterministic `getrandom` bytes.
    protected static final long RANDOM_SEED = 0x4752_4953_4356_0001L;

    /// Linux `GRND_NONBLOCK`; accepted because simulator randomness never blocks.
    protected static final long GRND_NONBLOCK = 0x0001;

    /// Linux `GRND_RANDOM`; accepted and mapped to the same deterministic source.
    protected static final long GRND_RANDOM = 0x0002;

    /// The supported Linux `getrandom` flags mask.
    protected static final long GETRANDOM_SUPPORTED_FLAGS = GRND_NONBLOCK | GRND_RANDOM;

    /// The guest memory accessed by syscall buffers.
    protected final Memory memory;

    /// The host input stream used for guest stdin reads.
    protected final InputStream in;

    /// The host output stream used for guest stdout writes.
    protected final OutputStream out;

    /// The host output stream used for guest stderr writes.
    protected final OutputStream err;

    /// Runs guest thread states created by Linux `clone`.
    protected final @Nullable GuestThreadRunner guestThreadRunner;

    /// The guest filesystem mount namespace used by sandboxed file syscalls.
    protected final GuestFileSystem fileSystem;

    /// The synthetic host-file metadata owned by this guest filesystem view.
    protected final GuestFileMetadataStore fileMetadataStore;

    /// The filesystem namespace before process-local default virtual mounts are attached.
    protected final GuestFileSystem baseFileSystem;

    /// The process-shared terminal exposed through standard descriptors and `/dev/tty`.
    protected final TerminalDevice terminalDevice;

    /// The optional framebuffer device configured for graphical guest integrations.
    protected final @Nullable FramebufferDevice framebufferDevice;

    /// Removes the currently registered framebuffer refresh hook, or null when no hook is registered.
    private @Nullable Runnable framebufferRefreshHookRemoval;

    /// The Linux user and group identity exposed to this guest process.
    protected GuestCredentials credentials;

    /// The Linux file creation mask applied to `openat(O_CREAT)` and `mkdirat`.
    protected volatile int fileCreationMask;

    /// The guest-visible current working directory in absolute Linux path syntax.
    protected String guestWorkingDirectory = "/";

    /// The serialized Linux auxiliary vector returned by `PR_GET_AUXV`.
    protected byte @Unmodifiable [] auxiliaryVectorBytes = encodeAuxiliaryVector(new long[]{0, 0});

    /// The process command line exposed through `/proc/self/cmdline`.
    protected byte @Unmodifiable [] procCommandLineBytes = new byte[0];

    /// The process environment exposed through `/proc/self/environ`.
    protected byte @Unmodifiable [] procEnvironmentBytes = new byte[0];

    /// The executable path exposed through `/proc/self/exe`.
    protected String procExecutablePath = "/";

    /// The lowest program break accepted by the `brk` syscall.
    protected long initialProgramBreak;

    /// The current guest program break returned by `brk`.
    protected long programBreak;

    /// The highest program-break address that currently has guest memory backing.
    protected long programBreakBackingEnd;

    /// The active mappings created by `mmap`.
    protected final CopyOnWriteArrayList<MemoryMapping> memoryMappings = new CopyOnWriteArrayList<>();

    /// The guest base page size used for page-based memory syscalls.
    protected final long pageSize;

    /// The guest file descriptor table for host files opened by `openat`.
    protected final ArrayList<@Nullable OpenFile> openFiles = new ArrayList<>();

    /// Overrides for standard descriptors when guest code redirects stdin, stdout, or stderr.
    protected final @Nullable OpenFile[] standardFiles = new @Nullable OpenFile[3];

    /// Whether each standard descriptor remains open in this process.
    protected final boolean[] standardFileOpen = {true, true, true};

    /// Descriptor flags for standard descriptors.
    protected final boolean[] standardFileCloseOnExec = new boolean[3];

    /// Descriptor flags for guest-opened file descriptors.
    protected final ArrayList<Boolean> openFileCloseOnExecFlags = new ArrayList<>();

    /// Descriptors carrying the FreeBSD `FD_CLOFORK` flag.
    protected final HashSet<Integer> fileDescriptorsCloseOnFork = new HashSet<>();

    /// The most recently allocated pseudoterminal pair exposed through `/dev/pts/0`.
    protected @Nullable PtyDevice currentPtyDevice;

    /// Allocates process and thread ids for this emulator run.
    protected final GuestProcessRegistry processRegistry;

    /// Process-level state shared by all guest threads.
    protected final GuestProcess process;

    /// The process-wide generation visible to guest instruction fetches after cross-thread icache flushes.
    private volatile long processInstructionFetchGeneration;

    /// The parent process that can wait for this process, or null for the initial process.
    protected final @Nullable GuestSyscalls parentProcess;

    /// Guards guest thread, futex, and process-exit state.
    protected final Object threadLock = new Object();

    /// Guards child process exit and reaping state.
    protected final Object childProcessLock = new Object();

    /// Wakes host threads blocked in descriptor-readiness polling syscalls.
    protected final Object pollLock = new Object();

    /// Increments whenever guest-visible descriptor readiness may have changed.
    protected volatile long pollGeneration;

    /// Host threads currently executing cloned guest threads.
    protected final ArrayList<Thread> guestThreads = new ArrayList<>();

    /// Child processes created by process-style `clone`.
    protected final ArrayList<ChildProcess> childProcesses = new ArrayList<>();

    /// Futex waiters currently blocked in guest syscalls.
    protected final ArrayList<FutexWaiter> futexWaiters = new ArrayList<>();

    /// The number of live guest threads, including the initial thread.
    protected int liveThreadCount = 1;

    /// Whether a guest `exit_group` has requested process termination.
    protected volatile boolean processExitRequested;

    /// The exit code requested by `exit_group` or by the last exiting thread.
    protected volatile long processExitCode;

    /// A host exception thrown while executing a guest thread, or null when none has failed.
    protected volatile @Nullable Throwable threadFailure;

    /// Whether guest dispatch needs to poll process-wide thread and exit state between blocks.
    protected volatile boolean processStatusPollingRequired;

    /// Whether the final process exit has already been reported to the parent process.
    protected boolean parentExitNotified;

    /// The signal reported by `PR_GET_PDEATHSIG`, or zero when unset.
    protected int parentDeathSignal;

    /// The dumpable state reported by `PR_GET_DUMPABLE`.
    protected int dumpable = 1;

    /// The process name reported by `PR_GET_NAME`.
    protected final byte[] processName = initialProcessName();

    /// The timer slack value reported by `PR_GET_TIMERSLACK`.
    protected long timerSlackNanoseconds = DEFAULT_TIMER_SLACK_NANOSECONDS;

    /// The guest-visible scheduling policy for this process.
    protected int schedulerPolicy = SCHED_OTHER;

    /// The guest-visible scheduling priority for this process.
    protected int schedulerPriority;

    /// Whether this single-process guest is marked as a child subreaper.
    protected boolean childSubreaper;

    /// Whether `PR_SET_NO_NEW_PRIVS` has been applied.
    protected boolean noNewPrivileges;

    /// The transparent huge page disable state reported by `PR_GET_THP_DISABLE`.
    protected int transparentHugePagesDisabled;

    /// The current soft resource limits returned by `prlimit64`.
    protected final long[] resourceLimitCurrent = DEFAULT_RESOURCE_LIMIT_CURRENT.clone();

    /// The current hard resource limits returned by `prlimit64`.
    protected final long[] resourceLimitMaximum = DEFAULT_RESOURCE_LIMIT_MAXIMUM.clone();

    /// The next deterministic random state used by `getrandom`.
    protected long randomState = RANDOM_SEED;

    /// The time source exposed to guest time syscalls.
    protected final TimeSource timeSource;

    /// Interval timer repeat values in microseconds.
    protected final long[] intervalTimerIntervalMicroseconds = new long[ITIMER_COUNT];

    /// Interval timer initial values in microseconds.
    protected final long[] intervalTimerValueMicroseconds = new long[ITIMER_COUNT];

    /// Elapsed guest time when each interval timer was last armed.
    protected final long[] intervalTimerStartMicroseconds = new long[ITIMER_COUNT];

    /// Creates the default process name used by `PR_GET_NAME`.
    protected static byte[] initialProcessName() {
        byte[] name = new byte[TASK_COMMAND_LENGTH];
        byte[] defaultName = RiscVContext.ID.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(defaultName, 0, name, 0, Math.min(defaultName.length, TASK_COMMAND_LENGTH - 1));
        return name;
    }

    /// Creates the default soft Linux resource-limit table.
    protected static long @Unmodifiable [] initialResourceLimitCurrent() {
        long[] limits = new long[RESOURCE_LIMIT_COUNT];
        for (int index = 0; index < limits.length; index++) {
            limits[index] = RLIM_INFINITY;
        }
        limits[RLIMIT_STACK] = DEFAULT_STACK_LIMIT;
        limits[RLIMIT_NOFILE] = DEFAULT_OPEN_FILE_LIMIT;
        return limits;
    }

    /// Creates the default hard Linux resource-limit table.
    protected static long @Unmodifiable [] initialResourceLimitMaximum() {
        long[] limits = new long[RESOURCE_LIMIT_COUNT];
        for (int index = 0; index < limits.length; index++) {
            limits[index] = RLIM_INFINITY;
        }
        limits[RLIMIT_NOFILE] = DEFAULT_OPEN_FILE_LIMIT;
        return limits;
    }

    /// Adds process-local default virtual filesystems unless the user already supplied those mount points.
    protected GuestFileSystem addDefaultVirtualMounts(GuestFileSystem fileSystem) {
        GuestFileSystem mountedFileSystem = fileSystem
                .withDefaultVirtualMount(DEV_MOUNT_PATH, new DevFileSystem(framebufferDevice))
                .withDefaultVirtualMount(PROC_MOUNT_PATH, new ProcFileSystem())
                .withDefaultVirtualMount(SYS_MOUNT_PATH, new SysFileSystem());
        if (!guestRegularFileExists(mountedFileSystem, RESOLV_CONF_PATH)) {
            mountedFileSystem = mountedFileSystem.withDefaultVirtualMount(
                    RESOLV_CONF_PATH,
                    new ResolvConfFileSystem());
        }
        return mountedFileSystem;
    }

    /// Returns true when a guest path resolves to an existing regular file.
    protected static boolean guestRegularFileExists(GuestFileSystem fileSystem, String absoluteGuestPath) {
        @Nullable Mount mount = fileSystem.mountForGuestPath(absoluteGuestPath);
        if (mount instanceof TarMount) {
            @Nullable TarPath tarPath = fileSystem.resolveTarPath(absoluteGuestPath, true);
            @Nullable TarNode node = tarPath == null ? null : tarPath.node();
            return node != null && node.isFile();
        }
        if (mount instanceof VirtualMount virtualMount) {
            @Nullable VirtualPath virtualPath = fileSystem.resolveVirtualPath(virtualMount, absoluteGuestPath, true);
            @Nullable VirtualNode node = virtualPath == null ? null : virtualPath.node();
            return node != null && node.isFile();
        }
        if (mount instanceof HostMount hostMount) {
            @Nullable Path hostFile = GuestFileSystem.resolveHostFile(absoluteGuestPath, hostMount);
            try {
                return hostFile != null && Files.isRegularFile(hostFile);
            } catch (SecurityException exception) {
                return false;
            }
        }
        return false;
    }

    /// Creates a syscall handler backed by the supplied host streams and heap boundary.
    protected GuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak) {
        this(
                memory,
                in,
                out,
                err,
                initialProgramBreak,
                GuestFileSystem.empty(),
                TimeSource.system(),
                false,
                GuestCredentials.defaultUser(),
                null);
    }

    /// Creates a syscall handler backed by the supplied host streams, heap boundary, and resolved root mount.
    protected GuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            @Nullable Path hostRoot) {
        this(memory, in, out, err, initialProgramBreak, hostRoot, TimeSource.system());
    }

    /// Creates a syscall handler backed by the supplied streams, resolved root mount, and guest time source.
    protected GuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            @Nullable Path hostRoot,
            TimeSource timeSource) {
        this(
                memory,
                in,
                out,
                err,
                initialProgramBreak,
                GuestFileSystem.forHostRoot(hostRoot),
                timeSource,
                false,
                GuestCredentials.defaultUser(),
                null);
    }

    /// Creates a syscall handler backed by the supplied streams, filesystem namespace, and guest time source.
    protected GuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            GuestFileSystem fileSystem,
            TimeSource timeSource) {
        this(
                memory,
                in,
                out,
                err,
                initialProgramBreak,
                fileSystem,
                timeSource,
                false,
                GuestCredentials.defaultUser(),
                null);
    }

    /// Creates a syscall handler backed by streams, filesystem namespace, guest time source, and credentials.
    protected GuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            GuestFileSystem fileSystem,
            TimeSource timeSource,
            GuestCredentials credentials) {
        this(memory, in, out, err, initialProgramBreak, fileSystem, timeSource, false, credentials, null);
    }

    /// Creates a syscall handler backed by the supplied host streams, heap boundary, and lazy root mount.
    protected GuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String hostRootPath) {
        this(memory, in, out, err, initialProgramBreak, hostRootPath, TimeSource.system());
    }

    /// Creates a syscall handler backed by the supplied streams, lazy root mount, and guest time source.
    protected GuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String hostRootPath,
            TimeSource timeSource) {
        this(
                memory,
                in,
                out,
                err,
                initialProgramBreak,
                GuestFileSystem.forMountSpecs(new String[]{
                        new FilesystemMountSpec("/", hostRootPath, FilesystemMountSpec.Type.BIND, null, false).encode()
                }),
                timeSource,
                false,
                GuestCredentials.defaultUser(),
                null);
    }

    /// Creates a syscall handler backed by streams, lazy root mount, guest time source, and guest thread runner.
    protected GuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String hostRootPath,
            TimeSource timeSource,
            GuestThreadRunner guestThreadRunner) {
        this(memory, in, out, err, initialProgramBreak, hostRootPath, timeSource, false, guestThreadRunner);
    }

    /// Creates a syscall handler backed by streams, lazy root mount, guest time source, terminal option,
    /// and guest thread runner.
    protected GuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String hostRootPath,
            TimeSource timeSource,
            boolean useHostTty,
            GuestThreadRunner guestThreadRunner) {
        this(
                memory,
                in,
                out,
                err,
                initialProgramBreak,
                GuestFileSystem.forMountSpecs(new String[]{
                        new FilesystemMountSpec("/", hostRootPath, FilesystemMountSpec.Type.BIND, null, false).encode()
                }),
                timeSource,
                useHostTty,
                GuestCredentials.defaultUser(),
                guestThreadRunner);
    }

    /// Creates a syscall handler backed by the supplied streams, lazy filesystem mounts, and guest time source.
    protected GuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String @Unmodifiable [] filesystemMountSpecs,
            TimeSource timeSource) {
        this(
                memory,
                in,
                out,
                err,
                initialProgramBreak,
                GuestFileSystem.forMountSpecs(filesystemMountSpecs),
                timeSource,
                false,
                GuestCredentials.defaultUser(),
                null);
    }

    /// Creates a syscall handler backed by streams, lazy filesystem mounts, guest time source, and guest thread runner.
    protected GuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String @Unmodifiable [] filesystemMountSpecs,
            TimeSource timeSource,
            GuestThreadRunner guestThreadRunner) {
        this(memory, in, out, err, initialProgramBreak, filesystemMountSpecs, timeSource, false, guestThreadRunner);
    }

    /// Creates a syscall handler backed by streams, lazy filesystem mounts, guest time source, terminal option,
    /// and guest thread runner.
    protected GuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String @Unmodifiable [] filesystemMountSpecs,
            TimeSource timeSource,
            boolean useHostTty,
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
                GuestCredentials.defaultUser(),
                guestThreadRunner);
    }

    /// Creates a syscall handler backed by streams, lazy filesystem mounts, time source, credentials,
    /// terminal option, and guest thread runner.
    protected GuestSyscalls(
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
                GuestFileSystem.forMountSpecs(filesystemMountSpecs),
                timeSource,
                useHostTty,
                credentials,
                guestThreadRunner);
    }

    /// Creates a syscall handler with an explicit filesystem namespace.
    protected GuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            GuestFileSystem fileSystem,
            TimeSource timeSource,
            boolean useHostTty,
            GuestCredentials credentials,
            @Nullable GuestThreadRunner guestThreadRunner) {
        this(
                memory,
                in,
                out,
                err,
                initialProgramBreak,
                fileSystem,
                timeSource,
                useHostTty,
                credentials,
                guestThreadRunner,
                null);
    }

    /// Creates a syscall handler with an explicit filesystem namespace and optional framebuffer device.
    protected GuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            GuestFileSystem fileSystem,
            TimeSource timeSource,
            boolean useHostTty,
            GuestCredentials credentials,
            @Nullable GuestThreadRunner guestThreadRunner,
            @Nullable FramebufferDevice framebufferDevice) {
        if (initialProgramBreak < memory.baseAddress() || initialProgramBreak > memory.endAddress()) {
            throw new RiscVException("Initial program break is outside guest memory: address=0x"
                    + Long.toUnsignedString(initialProgramBreak, 16));
        }

        this.memory = memory;
        this.in = in;
        this.out = out;
        this.err = err;
        this.guestThreadRunner = guestThreadRunner;
        this.baseFileSystem = fileSystem;
        this.terminalDevice = TerminalDevice.open(in, out, useHostTty);
        this.framebufferDevice = framebufferDevice;
        this.fileSystem = addDefaultVirtualMounts(fileSystem);
        this.fileMetadataStore = new GuestFileMetadataStore();
        this.credentials = credentials;
        this.initialProgramBreak = initialProgramBreak;
        this.programBreak = initialProgramBreak;
        this.programBreakBackingEnd = initialProgramBreak;
        this.pageSize = memory.pageSize();
        this.timeSource = timeSource;
        this.processRegistry = new GuestProcessRegistry();
        this.process = GuestProcess.initial();
        this.parentProcess = null;
    }

    /// Creates a child-process syscall handler by copying fork-inherited parent state.
    protected GuestSyscalls(GuestSyscalls parent, Memory memory, GuestProcess process) {
        this.memory = memory;
        this.in = parent.in;
        this.out = parent.out;
        this.err = parent.err;
        this.guestThreadRunner = parent.guestThreadRunner;
        this.baseFileSystem = parent.fileSystem.withoutVirtualMounts();
        this.terminalDevice = parent.terminalDevice.retain();
        this.framebufferDevice = parent.framebufferDevice;
        this.fileSystem = addDefaultVirtualMounts(baseFileSystem);
        this.fileMetadataStore = parent.fileMetadataStore;
        this.credentials = parent.credentials;
        this.fileCreationMask = parent.fileCreationMask;
        this.guestWorkingDirectory = parent.guestWorkingDirectory;
        this.auxiliaryVectorBytes = parent.auxiliaryVectorBytes.clone();
        this.procCommandLineBytes = parent.procCommandLineBytes.clone();
        this.procEnvironmentBytes = parent.procEnvironmentBytes.clone();
        this.procExecutablePath = parent.procExecutablePath;
        this.initialProgramBreak = parent.initialProgramBreak;
        this.programBreak = parent.programBreak;
        this.programBreakBackingEnd = parent.programBreakBackingEnd;
        this.memoryMappings.addAll(parent.memoryMappings);
        updateFramebufferRefreshHook();
        this.pageSize = memory.pageSize();
        this.processRegistry = parent.processRegistry;
        this.process = process;
        this.parentProcess = parent;
        this.parentDeathSignal = 0;
        this.dumpable = parent.dumpable;
        System.arraycopy(parent.processName, 0, processName, 0, processName.length);
        this.timerSlackNanoseconds = parent.timerSlackNanoseconds;
        this.schedulerPolicy = parent.schedulerPolicy;
        this.schedulerPriority = parent.schedulerPriority;
        this.childSubreaper = parent.childSubreaper;
        this.noNewPrivileges = parent.noNewPrivileges;
        this.transparentHugePagesDisabled = parent.transparentHugePagesDisabled;
        System.arraycopy(parent.resourceLimitCurrent, 0, resourceLimitCurrent, 0, resourceLimitCurrent.length);
        System.arraycopy(parent.resourceLimitMaximum, 0, resourceLimitMaximum, 0, resourceLimitMaximum.length);
        this.randomState = parent.randomState;
        this.timeSource = parent.timeSource;
        this.currentPtyDevice = parent.currentPtyDevice;
        copyStandardFilesFrom(parent);
        copyOpenFilesFrom(parent);
    }

    /// Captures the auxiliary vector from the initialized Linux stack for later `PR_GET_AUXV` calls.
    public void recordInitialAuxiliaryVector(long stackPointer) {
        long address = stackPointer;
        if (!memory.isBacked(address, Long.BYTES)) {
            throw new RiscVException("Initial Linux stack is not backed at argc");
        }

        long argumentCount = memory.readLong(address);
        if (argumentCount < 0 || argumentCount > 65536) {
            throw new RiscVException("Initial Linux stack contains invalid argc: " + argumentCount);
        }
        address += Long.BYTES;

        ArrayList<Long> argumentPointers = new ArrayList<>();
        for (long index = 0; index < argumentCount; index++) {
            if (!memory.isBacked(address, Long.BYTES)) {
                throw new RiscVException("Initial Linux stack has a truncated argument vector");
            }
            argumentPointers.add(memory.readLong(address));
            address += Long.BYTES;
        }
        if (!memory.isBacked(address, Long.BYTES) || memory.readLong(address) != 0) {
            throw new RiscVException("Initial Linux stack has an unterminated argument vector");
        }
        address += Long.BYTES;

        ArrayList<Long> environmentPointers = new ArrayList<>();
        for (int index = 0; index < 65536; index++) {
            if (!memory.isBacked(address, Long.BYTES)) {
                throw new RiscVException("Initial Linux stack has an unterminated environment vector");
            }
            long environmentPointer = memory.readLong(address);
            address += Long.BYTES;
            if (environmentPointer == 0) {
                break;
            }
            environmentPointers.add(environmentPointer);
            if (index == 65535) {
                throw new RiscVException("Initial Linux stack environment vector is too long");
            }
        }

        procCommandLineBytes = encodeNullSeparatedStrings(argumentPointers);
        procEnvironmentBytes = encodeNullSeparatedStrings(environmentPointers);

        ArrayList<Long> words = new ArrayList<>();
        for (int index = 0; index < 256; index++) {
            if (!memory.isBacked(address, 2L * Long.BYTES)) {
                throw new RiscVException("Initial Linux stack has an unterminated auxiliary vector");
            }
            long type = memory.readLong(address);
            long value = memory.readLong(address + Long.BYTES);
            words.add(type);
            words.add(value);
            address += 2L * Long.BYTES;
            if (type == 0) {
                auxiliaryVectorBytes = encodeAuxiliaryVector(words);
                procExecutablePath = executablePathFromAuxiliaryVector(words);
                return;
            }
        }

        throw new RiscVException("Initial Linux stack auxiliary vector is too long");
    }

    /// Reads a regular file from the configured guest filesystem mounts.
    public static byte @Unmodifiable [] readMountedFile(
            String @Unmodifiable [] filesystemMountSpecs,
            String guestPath) {
        return GuestFileSystem.readMountedFile(filesystemMountSpecs, guestPath);
    }

    /// Returns the process-leader thread state used by the initial architectural state.
    GuestThread initialThread() {
        return process.initialThread();
    }

    /// Returns the process-wide instruction-fetch visibility generation.
    long processInstructionFetchGeneration() {
        return processInstructionFetchGeneration;
    }

    /// Makes instruction bytes visible to every guest thread in this process.
    void fenceProcessInstructionFetch() {
        processInstructionFetchGeneration = RiscVThreadState.nextInstructionFetchGeneration();
    }

    /// Executes the syscall described by the guest argument registers at the supplied program counter.
    public abstract void handle(RiscVThreadState state, long pc);

    /// Gives an ABI-specific runtime a chance to deliver an illegal-instruction signal.
    public boolean handleIllegalInstruction(RiscVThreadState state, IllegalInstructionException exception) {
        return false;
    }

    /// Gives an ABI-specific runtime a chance to deliver a memory-access signal.
    public boolean handleMemoryAccess(RiscVThreadState state, MemoryAccessException exception) {
        return false;
    }

    /// Creates a child-process syscall handler of the same guest ABI as this handler.
    protected abstract GuestSyscalls createChildSyscalls(Memory childMemory, GuestProcess childProcess);

    /// Closes all host files opened by guest file descriptors.
    @Override
    public void close() {
        syncSharedDeviceMappings();
        closeFramebufferRefreshHook();
        closeChildProcesses();
        for (int index = 0; index < standardFiles.length; index++) {
            @Nullable OpenFile openFile = standardFiles[index];
            standardFiles[index] = null;
            standardFileOpen[index] = false;
            standardFileCloseOnExec[index] = false;
            setFileDescriptorCloseOnFork(index, false);
            if (openFile != null) {
                try {
                    releaseOpenFile(openFile);
                } catch (IOException exception) {
                    throw new RiscVException("Failed to close guest standard file descriptor", exception);
                }
            }
        }
        for (int index = 0; index < openFiles.size(); index++) {
            @Nullable OpenFile openFile = openFiles.get(index);
            if (openFile == null) {
                continue;
            }

            try {
                openFiles.set(index, null);
                setFileDescriptorCloseOnFork(index + 3, false);
                releaseOpenFile(openFile);
            } catch (IOException exception) {
                throw new RiscVException("Failed to close guest file descriptor", exception);
            }
        }
        try {
            terminalDevice.close();
        } catch (IOException exception) {
            throw new RiscVException("Failed to close guest terminal", exception);
        }
    }

    /// Requests any still-running child processes to stop and joins their host threads.
    protected void closeChildProcesses() {
        ChildProcess[] children;
        synchronized (childProcessLock) {
            children = childProcesses.toArray(ChildProcess[]::new);
            childProcesses.clear();
        }

        for (ChildProcess child : children) {
            child.syscalls().requestProcessExit(processExitCode);
        }
        for (ChildProcess child : children) {
            joinChildProcess(child);
        }
    }

    /// Builds a diagnostic message for a syscall that is not implemented by the simulator.
    protected static String unsupportedEcallMessage(RiscVThreadState state, long pc, long callNumber) {
        return "Unsupported ecall number: " + callNumber
                + ", pc=0x" + unsignedHex(pc)
                + ", a0=0x" + unsignedHex(state.register(10))
                + ", a1=0x" + unsignedHex(state.register(11))
                + ", a2=0x" + unsignedHex(state.register(12))
                + ", a3=0x" + unsignedHex(state.register(13))
                + ", a4=0x" + unsignedHex(state.register(14))
                + ", a5=0x" + unsignedHex(state.register(15))
                + ", a6=0x" + unsignedHex(state.register(16))
                + ", a7=0x" + unsignedHex(state.register(17));
    }

    /// Formats a guest register value as an unsigned hexadecimal string.
    protected static String unsignedHex(long value) {
        return Long.toUnsignedString(value, 16);
    }

    /// Writes the deterministic guest working directory path.
    protected long getcwd(long bufferAddress, long bufferSize) {
        byte[] pathBytes = guestWorkingDirectory.getBytes(StandardCharsets.UTF_8);
        byte[] currentDirectory = new byte[pathBytes.length + 1];
        System.arraycopy(pathBytes, 0, currentDirectory, 0, pathBytes.length);
        if (bufferSize < currentDirectory.length) {
            return ERANGE;
        }
        memory.writeBytes(bufferAddress, currentDirectory, 0, currentDirectory.length);
        return currentDirectory.length;
    }

    /// Duplicates a file descriptor to the lowest available non-standard descriptor.
    protected long dup(int fileDescriptor) {
        @Nullable OpenFile duplicate = duplicateOpenFile(fileDescriptor);
        if (duplicate == null) {
            return EBADF;
        }

        return addOpenFile(duplicate);
    }

    /// Duplicates a file descriptor to an explicit non-standard descriptor.
    protected long dup3(int oldFileDescriptor, int newFileDescriptor, long flags) {
        if ((flags & ~SUPPORTED_DUP3_FLAGS) != 0 || oldFileDescriptor == newFileDescriptor) {
            return EINVAL;
        }
        if (newFileDescriptor < 0) {
            return EBADF;
        }

        @Nullable OpenFile source = duplicateOpenFile(oldFileDescriptor);
        if (source == null) {
            return EBADF;
        }

        try {
            replaceOpenFile(newFileDescriptor, source, (flags & O_CLOEXEC) != 0);
            return newFileDescriptor;
        } catch (IOException exception) {
            try {
                releaseOpenFile(source);
            } catch (IOException cleanupException) {
                exception.addSuppressed(cleanupException);
            }
            throw new RiscVException("Guest dup3 syscall failed", exception);
        }
    }

    /// Creates an in-memory Linux `eventfd` counter.
    protected long eventfd2(long initialValue, long flags) {
        if ((flags & ~SUPPORTED_EVENTFD2_FLAGS) != 0) {
            return EINVAL;
        }

        long counterValue = initialValue & 0xffff_ffffL;
        EventCounter counter = new EventCounter(
                counterValue,
                (flags & EFD_SEMAPHORE) != 0,
                (flags & O_NONBLOCK) != 0,
                this::notifyPollWaiters);
        return addOpenFile(OpenFile.eventFile(counter), (flags & O_CLOEXEC) != 0);
    }

    /// Creates an in-memory Linux `timerfd` timer.
    protected long timerfdCreate(long clockId, long flags) {
        if (!isSupportedTimerfdClock(clockId) || (flags & ~SUPPORTED_TIMERFD_CREATE_FLAGS) != 0) {
            return EINVAL;
        }

        TimerFile timerFile = new TimerFile(
                clockId,
                (flags & O_NONBLOCK) != 0,
                this::timerfdClockNanoseconds,
                this::notifyPollWaiters);
        return addOpenFile(OpenFile.timerFile(timerFile), (flags & O_CLOEXEC) != 0);
    }

    /// Arms, rearms, or disarms a Linux `timerfd` timer.
    protected long timerfdSettime(int fileDescriptor, long flags, long newValueAddress, long oldValueAddress) {
        if ((flags & ~SUPPORTED_TIMERFD_SETTIME_FLAGS) != 0) {
            return EINVAL;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }
        if (!openFile.isTimerFile()) {
            return EINVAL;
        }
        if (!memory.isBacked(newValueAddress, ITIMERSPEC_SIZE)
                || (oldValueAddress != 0 && !memory.isBacked(oldValueAddress, ITIMERSPEC_SIZE))) {
            return EFAULT;
        }

        long intervalSeconds = memory.readLong(newValueAddress + ITIMERSPEC_INTERVAL_OFFSET + TIMESPEC_SECONDS_OFFSET);
        long intervalNanoseconds =
                memory.readLong(newValueAddress + ITIMERSPEC_INTERVAL_OFFSET + TIMESPEC_NANOSECONDS_OFFSET);
        long valueSeconds = memory.readLong(newValueAddress + ITIMERSPEC_VALUE_OFFSET + TIMESPEC_SECONDS_OFFSET);
        long valueNanoseconds =
                memory.readLong(newValueAddress + ITIMERSPEC_VALUE_OFFSET + TIMESPEC_NANOSECONDS_OFFSET);
        if (!isValidTimespec(intervalSeconds, intervalNanoseconds)
                || !isValidTimespec(valueSeconds, valueNanoseconds)) {
            return EINVAL;
        }

        TimerFile timerFile = openFile.timerFile();
        TimerFileSpec oldSpec = timerFile.setTime(
                (flags & TFD_TIMER_ABSTIME) != 0,
                timespecToSaturatedNanoseconds(intervalSeconds, intervalNanoseconds),
                timespecToSaturatedNanoseconds(valueSeconds, valueNanoseconds));
        if (oldValueAddress != 0) {
            writeItimerspec(oldValueAddress, oldSpec);
        }
        return 0;
    }

    /// Writes the current Linux `timerfd` timer configuration.
    protected long timerfdGettime(int fileDescriptor, long currentValueAddress) {
        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }
        if (!openFile.isTimerFile()) {
            return EINVAL;
        }
        if (!memory.isBacked(currentValueAddress, ITIMERSPEC_SIZE)) {
            return EFAULT;
        }

        writeItimerspec(currentValueAddress, openFile.timerFile().currentSpec());
        return 0;
    }

    /// Writes a Linux RISC-V 64-bit `struct itimerspec` from nanosecond timer fields.
    protected void writeItimerspec(long itimerspecAddress, TimerFileSpec spec) {
        writeTimespecFromNanoseconds(
                itimerspecAddress + ITIMERSPEC_INTERVAL_OFFSET,
                spec.intervalNanoseconds());
        writeTimespecFromNanoseconds(
                itimerspecAddress + ITIMERSPEC_VALUE_OFFSET,
                spec.valueNanoseconds());
    }

    /// Creates an in-memory Linux `epoll` descriptor.
    protected long epollCreate1(long flags) {
        if ((flags & ~SUPPORTED_EPOLL_CREATE1_FLAGS) != 0) {
            return EINVAL;
        }
        return addOpenFile(OpenFile.epollFile(new EpollSet()), (flags & O_CLOEXEC) != 0);
    }

    /// Adds, modifies, or removes one descriptor interest from an in-memory `epoll` set.
    protected long epollCtl(int epollFileDescriptor, int operation, int fileDescriptor, long eventAddress) {
        @Nullable OpenFile epollFile = openFile(epollFileDescriptor);
        if (epollFile == null) {
            return EBADF;
        }
        if (!epollFile.isEpollFile()) {
            return EINVAL;
        }
        if (!isOpenFileDescriptor(fileDescriptor)) {
            return EBADF;
        }
        if (fileDescriptor == epollFileDescriptor) {
            return EINVAL;
        }

        EpollSet epollSet = epollFile.epollSet();
        if (operation == EPOLL_CTL_DEL) {
            long result = epollSet.remove(fileDescriptor);
            if (result == 0) {
                notifyPollWaiters();
            }
            return result;
        }
        if (operation != EPOLL_CTL_ADD && operation != EPOLL_CTL_MOD) {
            return EINVAL;
        }
        if (eventAddress == 0) {
            return EINVAL;
        }

        int events = memory.readInt(eventAddress + EPOLL_EVENT_EVENTS_OFFSET);
        long data = readLongUnaligned(eventAddress + EPOLL_EVENT_DATA_OFFSET);
        long result = operation == EPOLL_CTL_ADD
                ? epollSet.add(fileDescriptor, events, data)
                : epollSet.modify(fileDescriptor, events, data);
        if (result == 0) {
            notifyPollWaiters();
        }
        return result;
    }

    /// Reports events from an in-memory `epoll` descriptor, waiting for readiness or timeout when needed.
    protected long epollPwait(
            RiscVThreadState state,
            int epollFileDescriptor,
            long eventsAddress,
            int maximumEvents,
            int timeoutMilliseconds,
            long signalMaskAddress,
            long signalSetSize) {
        return epollPwaitWithTimeout(
                state,
                epollFileDescriptor,
                eventsAddress,
                maximumEvents,
                epollTimeoutNanoseconds(timeoutMilliseconds),
                timeoutMilliseconds == 0,
                signalMaskAddress,
                signalSetSize);
    }

    /// Reports events from an in-memory `epoll` descriptor with a nanosecond `timespec` timeout.
    protected long epollPwait2(
            RiscVThreadState state,
            int epollFileDescriptor,
            long eventsAddress,
            int maximumEvents,
            long timeoutAddress,
            long signalMaskAddress,
            long signalSetSize) {
        long timeoutNanoseconds = -1;
        boolean immediateTimeout = false;
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
            immediateTimeout = timeoutNanoseconds == 0;
        }
        return epollPwaitWithTimeout(
                state,
                epollFileDescriptor,
                eventsAddress,
                maximumEvents,
                timeoutNanoseconds,
                immediateTimeout,
                signalMaskAddress,
                signalSetSize);
    }

    /// Reports events from an in-memory `epoll` descriptor with a precomputed timeout.
    protected long epollPwaitWithTimeout(
            RiscVThreadState state,
            int epollFileDescriptor,
            long eventsAddress,
            int maximumEvents,
            long timeoutNanoseconds,
            boolean immediateTimeout,
            long signalMaskAddress,
            long signalSetSize) {
        if (maximumEvents <= 0) {
            return EINVAL;
        }
        if (signalMaskAddress != 0 && signalSetSize != KERNEL_SIGSET_SIZE) {
            return EINVAL;
        }
        if (signalMaskAddress != 0 && !memory.isBacked(signalMaskAddress, KERNEL_SIGSET_SIZE)) {
            return EFAULT;
        }
        long eventsByteSize = (long) maximumEvents * EPOLL_EVENT_SIZE;
        if (!memory.isBacked(eventsAddress, eventsByteSize)) {
            return EFAULT;
        }

        @Nullable OpenFile epollFile = openFile(epollFileDescriptor);
        if (epollFile == null) {
            return EBADF;
        }
        if (!epollFile.isEpollFile()) {
            return EINVAL;
        }

        GuestThread thread = state.guestThread();
        long savedSignalMask = thread.signalMask();
        if (signalMaskAddress != 0) {
            thread.setSignalMask(memory.readLong(signalMaskAddress) & ~UNBLOCKABLE_SIGNAL_MASK);
        }
        long deadlineNanoseconds = pollDeadlineNanoseconds(timeoutNanoseconds);
        try {
            EpollSet epollSet = epollFile.epollSet();
            while (true) {
                long observedPollGeneration = pollGeneration;
                int count = reportEpollEvents(epollSet, eventsAddress, maximumEvents);
                if (count != 0 || immediateTimeout) {
                    return count;
                }
                if (hasExitedChildProcess()) {
                    return EINTR;
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
        } finally {
            if (signalMaskAddress != 0) {
                thread.setSignalMask(savedSignalMask);
            }
        }
    }

    /// Writes currently ready `epoll` events and returns the number of reported interests.
    protected int reportEpollEvents(EpollSet epollSet, long eventsAddress, int maximumEvents) {
        synchronized (epollSet) {
            int count = 0;
            for (int index = 0; index < epollSet.size() && count < maximumEvents; index++) {
                EpollInterest interest = epollSet.interest(index);
                int readyEvents = readyEventsFor(interest.fileDescriptor());
                int reportedEvents = (readyEvents & interest.events()) | (readyEvents & (EPOLLERR | EPOLLHUP));
                if (reportedEvents == 0) {
                    continue;
                }

                writeEpollEvent(eventsAddress + (long) count * EPOLL_EVENT_SIZE, reportedEvents, interest.data());
                count++;
            }
            return count;
        }
    }

    /// Converts a Linux `epoll_wait` millisecond timeout to nanoseconds.
    protected static long epollTimeoutNanoseconds(int timeoutMilliseconds) {
        if (timeoutMilliseconds < 0) {
            return -1;
        }
        long milliseconds = timeoutMilliseconds;
        return milliseconds > Long.MAX_VALUE / NANOSECONDS_PER_MILLISECOND
                ? Long.MAX_VALUE
                : milliseconds * NANOSECONDS_PER_MILLISECOND;
    }

    /// Reports descriptor readiness through Linux `pselect6`, waiting for readiness or timeout when needed.
    protected long pselect6(
            RiscVThreadState state,
            long fileDescriptorLimit,
            long readFileDescriptorsAddress,
            long writeFileDescriptorsAddress,
            long exceptionFileDescriptorsAddress,
            long timeoutAddress,
            long signalArgumentAddress) {
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

        long signalMaskAddress = 0;
        if (signalArgumentAddress != 0) {
            if (!memory.isBacked(signalArgumentAddress, PSELECT6_SIGNAL_ARGUMENT_SIZE)) {
                return EFAULT;
            }
            signalMaskAddress = readLongUnaligned(signalArgumentAddress + PSELECT6_SIGNAL_MASK_ADDRESS_OFFSET);
            long signalSetSize = readLongUnaligned(signalArgumentAddress + PSELECT6_SIGNAL_SET_SIZE_OFFSET);
            if (signalMaskAddress != 0 && signalSetSize != KERNEL_SIGSET_SIZE) {
                return EINVAL;
            }
            if (signalMaskAddress != 0 && !memory.isBacked(signalMaskAddress, KERNEL_SIGSET_SIZE)) {
                return EFAULT;
            }
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

    /// Reports selected descriptor readiness using a validated timeout and optional low-word signal mask.
    protected long selectWithTimeout(
            RiscVThreadState state,
            int descriptorLimit,
            long fileDescriptorSetSize,
            long readFileDescriptorsAddress,
            long writeFileDescriptorsAddress,
            long exceptionFileDescriptorsAddress,
            long timeoutNanoseconds,
            boolean immediateTimeout,
            long signalMaskAddress) {
        boolean[] requestedReadFileDescriptors = readFdSet(readFileDescriptorsAddress, descriptorLimit);
        boolean[] requestedWriteFileDescriptors = readFdSet(writeFileDescriptorsAddress, descriptorLimit);
        boolean[] requestedExceptionFileDescriptors = readFdSet(exceptionFileDescriptorsAddress, descriptorLimit);
        for (int fileDescriptor = 0; fileDescriptor < descriptorLimit; fileDescriptor++) {
            if ((requestedReadFileDescriptors[fileDescriptor]
                    || requestedWriteFileDescriptors[fileDescriptor]
                    || requestedExceptionFileDescriptors[fileDescriptor])
                    && !isOpenFileDescriptor(fileDescriptor)) {
                return EBADF;
            }
        }

        GuestThread thread = state.guestThread();
        long savedSignalMask = thread.signalMask();
        if (signalMaskAddress != 0) {
            thread.setSignalMask(memory.readLong(signalMaskAddress) & ~UNBLOCKABLE_SIGNAL_MASK);
        }
        long deadlineNanoseconds = pollDeadlineNanoseconds(timeoutNanoseconds);
        try {
            while (true) {
                long observedPollGeneration = pollGeneration;
                clearFdSet(readFileDescriptorsAddress, fileDescriptorSetSize);
                clearFdSet(writeFileDescriptorsAddress, fileDescriptorSetSize);
                clearFdSet(exceptionFileDescriptorsAddress, fileDescriptorSetSize);

                int readyCount = 0;
                for (int fileDescriptor = 0; fileDescriptor < descriptorLimit; fileDescriptor++) {
                    int readyEvents = readyEventsFor(fileDescriptor, immediateTimeout);
                    boolean descriptorReady = false;
                    if (requestedReadFileDescriptors[fileDescriptor]
                            && (readyEvents & (EPOLLIN | EPOLLERR | EPOLLHUP)) != 0) {
                        setFdSetBit(readFileDescriptorsAddress, fileDescriptor);
                        descriptorReady = true;
                    }
                    if (requestedWriteFileDescriptors[fileDescriptor] && (readyEvents & (EPOLLOUT | EPOLLERR)) != 0) {
                        setFdSetBit(writeFileDescriptorsAddress, fileDescriptor);
                        descriptorReady = true;
                    }
                    if (descriptorReady) {
                        readyCount++;
                    }
                }
                if (readyCount != 0 || immediateTimeout) {
                    return readyCount;
                }
                if (hasExitedChildProcess()) {
                    return EINTR;
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
        } finally {
            if (signalMaskAddress != 0) {
                thread.setSignalMask(savedSignalMask);
            }
        }
    }

    /// Returns the byte width needed for a Linux `fd_set` covering descriptors below `descriptorLimit`.
    protected static long fdSetByteSize(int descriptorLimit) {
        if (descriptorLimit == 0) {
            return 0;
        }
        return ((long) descriptorLimit + FD_SET_BITS_PER_WORD - 1L) / FD_SET_BITS_PER_WORD * Long.BYTES;
    }

    /// Returns true when a nullable `fd_set` pointer is backed for the requested descriptor range.
    protected boolean isBackedFdSet(long fileDescriptorSetAddress, long byteSize) {
        return fileDescriptorSetAddress == 0 || byteSize == 0 || memory.isBacked(fileDescriptorSetAddress, byteSize);
    }

    /// Reads one nullable Linux `fd_set` into a descriptor-indexed selection array.
    protected boolean[] readFdSet(long fileDescriptorSetAddress, int descriptorLimit) {
        boolean[] selected = new boolean[descriptorLimit];
        if (fileDescriptorSetAddress == 0) {
            return selected;
        }
        for (int fileDescriptor = 0; fileDescriptor < descriptorLimit; fileDescriptor++) {
            selected[fileDescriptor] = isFdSetBitSet(fileDescriptorSetAddress, fileDescriptor);
        }
        return selected;
    }

    /// Clears one nullable Linux `fd_set` over the descriptor range used by `pselect6`.
    protected void clearFdSet(long fileDescriptorSetAddress, long byteSize) {
        if (fileDescriptorSetAddress != 0 && byteSize != 0) {
            memory.clear(fileDescriptorSetAddress, byteSize);
        }
    }

    /// Returns true when one descriptor bit is set in a Linux `fd_set`.
    protected boolean isFdSetBitSet(long fileDescriptorSetAddress, int fileDescriptor) {
        long wordAddress = fileDescriptorSetAddress + (long) (fileDescriptor / FD_SET_BITS_PER_WORD) * Long.BYTES;
        long word = readLongUnaligned(wordAddress);
        return (word & fdSetBit(fileDescriptor)) != 0;
    }

    /// Sets one descriptor bit in a nullable Linux `fd_set`.
    protected void setFdSetBit(long fileDescriptorSetAddress, int fileDescriptor) {
        if (fileDescriptorSetAddress == 0) {
            return;
        }
        long wordAddress = fileDescriptorSetAddress + (long) (fileDescriptor / FD_SET_BITS_PER_WORD) * Long.BYTES;
        writeLongUnaligned(wordAddress, readLongUnaligned(wordAddress) | fdSetBit(fileDescriptor));
    }

    /// Returns the word-local bit mask for one descriptor in a Linux `fd_set`.
    protected static long fdSetBit(int fileDescriptor) {
        return 1L << (fileDescriptor % FD_SET_BITS_PER_WORD);
    }

    /// Reports descriptor readiness through millisecond-timeout `poll` semantics.
    protected long poll(
            RiscVThreadState state,
            long fileDescriptorsAddress,
            long fileDescriptorCount,
            int timeoutMilliseconds) {
        if (fileDescriptorCount < 0 || fileDescriptorCount > Integer.MAX_VALUE) {
            return EINVAL;
        }
        long fileDescriptorsSize = fileDescriptorCount * POLL_FD_SIZE;
        if (fileDescriptorCount > 0 && !memory.isBacked(fileDescriptorsAddress, fileDescriptorsSize)) {
            return EFAULT;
        }
        return pollWithTimeout(
                state,
                fileDescriptorsAddress,
                fileDescriptorCount,
                epollTimeoutNanoseconds(timeoutMilliseconds),
                timeoutMilliseconds == 0,
                0);
    }

    /// Reports descriptor readiness through Linux `ppoll`, waiting for readiness or timeout when needed.
    protected long ppoll(
            RiscVThreadState state,
            long fileDescriptorsAddress,
            long fileDescriptorCount,
            long timeoutAddress,
            long signalMaskAddress,
            long signalSetSize) {
        if (fileDescriptorCount < 0 || fileDescriptorCount > Integer.MAX_VALUE) {
            return EINVAL;
        }
        if (signalMaskAddress != 0 && signalSetSize != KERNEL_SIGSET_SIZE) {
            return EINVAL;
        }

        long fileDescriptorsSize = fileDescriptorCount * POLL_FD_SIZE;
        if (fileDescriptorCount > 0 && !memory.isBacked(fileDescriptorsAddress, fileDescriptorsSize)) {
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
        if (signalMaskAddress != 0 && !memory.isBacked(signalMaskAddress, KERNEL_SIGSET_SIZE)) {
            return EFAULT;
        }

        return pollWithTimeout(
                state,
                fileDescriptorsAddress,
                fileDescriptorCount,
                timeoutNanoseconds,
                immediateTimeout,
                signalMaskAddress);
    }

    /// Reports polled descriptor readiness using a validated timeout and optional low-word signal mask.
    protected long pollWithTimeout(
            RiscVThreadState state,
            long fileDescriptorsAddress,
            long fileDescriptorCount,
            long timeoutNanoseconds,
            boolean immediateTimeout,
            long signalMaskAddress) {
        GuestThread thread = state.guestThread();
        long savedSignalMask = thread.signalMask();
        if (signalMaskAddress != 0) {
            thread.setSignalMask(memory.readLong(signalMaskAddress) & ~UNBLOCKABLE_SIGNAL_MASK);
        }
        long deadlineNanoseconds = pollDeadlineNanoseconds(timeoutNanoseconds);
        try {
            while (true) {
                long observedPollGeneration = pollGeneration;
                int readyCount = 0;
                for (long index = 0; index < fileDescriptorCount; index++) {
                    long pollFileDescriptorAddress = fileDescriptorsAddress + index * POLL_FD_SIZE;
                    int fileDescriptor = memory.readInt(pollFileDescriptorAddress + POLL_FD_FILE_DESCRIPTOR_OFFSET);
                    int requestedEvents = memory.readUnsignedShort(pollFileDescriptorAddress + POLL_FD_EVENTS_OFFSET);

                    int reportedEvents;
                    if (fileDescriptor < 0) {
                        reportedEvents = 0;
                    } else if (!isOpenFileDescriptor(fileDescriptor)) {
                        reportedEvents = POLLNVAL;
                    } else {
                        int readyEvents = readyEventsFor(fileDescriptor, immediateTimeout);
                        reportedEvents = (readyEvents & requestedEvents) | (readyEvents & (POLLERR | POLLHUP));
                    }

                    memory.writeShort(
                            pollFileDescriptorAddress + POLL_FD_REVENTS_OFFSET,
                            (short) reportedEvents);
                    if (reportedEvents != 0) {
                        readyCount++;
                    }
                }
                if (readyCount != 0 || immediateTimeout) {
                    return readyCount;
                }
                if (hasExitedChildProcess()) {
                    return EINTR;
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
        } finally {
            if (signalMaskAddress != 0) {
                thread.setSignalMask(savedSignalMask);
            }
        }
    }

    /// Returns true when a child process has an unreaped exit status.
    protected boolean hasExitedChildProcess() {
        synchronized (childProcessLock) {
            for (ChildProcess child : childProcesses) {
                if (child.exited()) {
                    return true;
                }
            }
            return false;
        }
    }

    /// Returns the host `System.nanoTime()` deadline for a poll timeout, or `-1` for no timeout.
    protected static long pollDeadlineNanoseconds(long timeoutNanoseconds) {
        if (timeoutNanoseconds < 0) {
            return -1;
        }
        return System.nanoTime() + timeoutNanoseconds;
    }

    /// Returns the remaining poll timeout in nanoseconds, or `-1` for no timeout.
    protected static long remainingPollNanoseconds(long deadlineNanoseconds) {
        if (deadlineNanoseconds < 0) {
            return -1;
        }
        long remainingNanoseconds = deadlineNanoseconds - System.nanoTime();
        return remainingNanoseconds <= 0 ? 0 : remainingNanoseconds;
    }

    /// Wakes guest threads blocked in descriptor-readiness polling syscalls.
    protected void notifyPollWaiters() {
        synchronized (pollLock) {
            pollGeneration++;
            pollLock.notifyAll();
        }
    }

    /// Waits for descriptor readiness to change or for a bounded host-socket polling slice to pass.
    protected long waitForPollChange(long observedPollGeneration, long timeoutNanoseconds) {
        long waitNanoseconds = timeoutNanoseconds < 0
                ? NANOSECONDS_PER_MILLISECOND
                : Math.min(timeoutNanoseconds, NANOSECONDS_PER_MILLISECOND);
        if (waitNanoseconds <= 0) {
            return 0;
        }
        synchronized (pollLock) {
            if (pollGeneration != observedPollGeneration) {
                return 0;
            }
            try {
                pollLock.wait(
                        waitNanoseconds / NANOSECONDS_PER_MILLISECOND,
                        (int) (waitNanoseconds % NANOSECONDS_PER_MILLISECOND));
                return 0;
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                return EINTR;
            }
        }
    }

    /// Creates an in-memory pipe and writes its read and write descriptors to guest memory.
    protected long pipe2(long pipeAddress, long flags) {
        if ((flags & ~SUPPORTED_PIPE2_FLAGS) != 0) {
            return EINVAL;
        }

        boolean nonblocking = (flags & O_NONBLOCK) != 0;
        boolean closeOnExec = (flags & O_CLOEXEC) != 0;
        PipeBuffer pipe = new PipeBuffer(this::notifyPollWaiters);
        long readFileDescriptor = addOpenFile(OpenFile.pipeReader(pipe, nonblocking), closeOnExec);
        long writeFileDescriptor = addOpenFile(OpenFile.pipeWriter(pipe, nonblocking), closeOnExec);
        memory.writeInt(pipeAddress, (int) readFileDescriptor);
        memory.writeInt(pipeAddress + Integer.BYTES, (int) writeFileDescriptor);
        return 0;
    }

    /// Reads Linux `struct linux_dirent64` records from an open directory descriptor.
    protected long getdents64(int fileDescriptor, long bufferAddress, long byteCount) {
        if (byteCount <= 0) {
            return EINVAL;
        }
        if (isStandardFileDescriptor(fileDescriptor)) {
            return ENOTDIR;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }
        if (!openFile.isDirectory()) {
            return ENOTDIR;
        }

        try {
            DirectoryEntry[] entries = directoryEntries(openFile);
            long written = 0;
            int index = openFile.directoryEntryIndex();
            while (index < entries.length) {
                DirectoryEntry entry = entries[index];
                byte[] name = entry.name().getBytes(StandardCharsets.UTF_8);
                int recordLength = directoryEntryRecordLength(name.length);
                if (recordLength > byteCount - written) {
                    if (written > 0) {
                        openFile.setDirectoryEntryIndex(index);
                    }
                    return written == 0 ? EINVAL : written;
                }

                writeDirectoryEntry(bufferAddress + written, entry, index + 1L, name, recordLength);
                written += recordLength;
                index++;
            }

            openFile.setDirectoryEntryIndex(index);
            return written;
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Returns the cached entries for an open directory descriptor, loading them on first use.
    protected DirectoryEntry[] directoryEntries(OpenFile openFile) throws IOException {
        @Nullable DirectoryEntry[] cachedEntries = openFile.directoryEntries();
        if (cachedEntries != null) {
            return cachedEntries;
        }

        @Nullable Path path = openFile.path();
        @Nullable TarNode tarNode = openFile.tarNode();
        @Nullable VirtualNode virtualNode = openFile.virtualNode();
        @Nullable VirtualMount virtualMount = openFile.virtualMount();
        if (virtualNode != null && virtualMount != null) {
            DirectoryEntry[] result = fileSystem.virtualDirectoryEntries(virtualMount, virtualNode);
            openFile.setDirectoryEntries(result);
            return result;
        }
        if (tarNode != null) {
            DirectoryEntry[] result = tarDirectoryEntries(openFile, tarNode);
            openFile.setDirectoryEntries(result);
            return result;
        }
        if (path == null) {
            throw new IOException("Directory descriptor has no path");
        }

        ArrayList<DirectoryEntry> entries = new ArrayList<>();
        entries.add(new DirectoryEntry(".", syntheticInode(path), DIRECTORY_ENTRY_DIRECTORY));
        entries.add(new DirectoryEntry("..", syntheticInode(parentDirectoryForDotDot(path)), DIRECTORY_ENTRY_DIRECTORY));

        ArrayList<DirectoryEntry> childEntries = new ArrayList<>();
        for (Path child : listHostDirectory(path)) {
            childEntries.add(new DirectoryEntry(hostFileName(child), syntheticInode(child), directoryEntryType(child)));
        }
        childEntries.sort((left, right) -> left.name().compareTo(right.name()));
        entries.addAll(childEntries);

        DirectoryEntry[] result = entries.toArray(DirectoryEntry[]::new);
        openFile.setDirectoryEntries(result);
        return result;
    }

    /// Returns deterministic directory entries for an open tar directory.
    protected static DirectoryEntry[] tarDirectoryEntries(OpenFile openFile, TarNode directory) throws IOException {
        @Nullable String guestPath = openFile.guestPath();
        if (guestPath == null) {
            throw new IOException("Tar directory descriptor has no guest path");
        }

        ArrayList<DirectoryEntry> entries = new ArrayList<>();
        entries.add(new DirectoryEntry(".", directory.inode(), DIRECTORY_ENTRY_DIRECTORY));
        entries.add(new DirectoryEntry("..", directory.parentInode(), DIRECTORY_ENTRY_DIRECTORY));
        for (TarNode child : directory.children().values()) {
            entries.add(new DirectoryEntry(child.name(), child.inode(), child.directoryEntryType()));
        }
        return entries.toArray(DirectoryEntry[]::new);
    }

    /// Lists immediate children of a sandboxed host directory.
    protected static Path @Unmodifiable [] listHostDirectory(Path path) throws IOException {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(path)) {
            ArrayList<Path> result = new ArrayList<>();
            for (Path child : stream) {
                result.add(child);
            }
            return result.toArray(Path[]::new);
        }
    }

    /// Returns the final host path component.
    protected static String hostFileName(Path path) {
        @Nullable Path fileName = path.getFileName();
        return fileName == null ? path.toString() : fileName.toString();
    }

    /// Returns the parent directory represented by the `..` entry without escaping the selected mount root.
    protected Path parentDirectoryForDotDot(Path path) {
        @Nullable HostMount mount = mountForHostFile(path);
        @Nullable Path parent = path.getParent();
        if (mount != null && parent != null && parent.normalize().startsWith(mount.root())) {
            return parent.normalize();
        }
        return path;
    }

    /// Returns the Linux directory entry type for a sandboxed host path.
    protected static byte directoryEntryType(Path path) {
        try {
            if (Files.isSymbolicLink(path)) {
                return DIRECTORY_ENTRY_SYMBOLIC_LINK;
            }
            if (Files.isDirectory(path)) {
                return DIRECTORY_ENTRY_DIRECTORY;
            }
            if (Files.isRegularFile(path)) {
                return DIRECTORY_ENTRY_REGULAR_FILE;
            }
            return DIRECTORY_ENTRY_UNKNOWN;
        } catch (SecurityException exception) {
            return DIRECTORY_ENTRY_UNKNOWN;
        }
    }

    /// Computes the aligned byte length of one Linux `struct linux_dirent64` record.
    protected static int directoryEntryRecordLength(int nameLength) {
        return (int) alignUp(DIRENT64_NAME_OFFSET + nameLength + 1L, DIRENT64_RECORD_ALIGNMENT);
    }

    /// Writes one Linux `struct linux_dirent64` record to guest memory.
    protected void writeDirectoryEntry(
            long address,
            DirectoryEntry entry,
            long nextOffset,
            byte[] name,
            int recordLength) {
        memory.clear(address, recordLength);
        memory.writeLong(address + DIRENT64_INODE_OFFSET, entry.inode());
        memory.writeLong(address + DIRENT64_NEXT_OFFSET, nextOffset);
        memory.writeShort(address + DIRENT64_RECORD_LENGTH_OFFSET, (short) recordLength);
        memory.writeByte(address + DIRENT64_TYPE_OFFSET, entry.type());
        memory.writeBytes(address + DIRENT64_NAME_OFFSET, name, 0, name.length);
    }

    /// Checks access to a sandboxed host path or open file descriptor.
    protected long faccessat(long directoryFileDescriptor, long pathAddress, long mode, long flags) {
        if ((mode & ~ACCESS_MODE_MASK) != 0 || (flags & ~SUPPORTED_FACCESSAT2_FLAGS) != 0) {
            return EINVAL;
        }

        @Nullable String guestPath = readGuestPath(pathAddress);
        if (guestPath == null) {
            return ENAMETOOLONG;
        }

        if (guestPath.isEmpty()) {
            if ((flags & AT_EMPTY_PATH) == 0) {
                return ENOENT;
            }
            if (directoryFileDescriptor == AT_FDCWD) {
                @Nullable Path currentDirectory = currentHostWorkingDirectory();
                return currentDirectory == null ? EACCES : accessHostFile(currentDirectory, mode);
            }
            return accessFileDescriptor((int) directoryFileDescriptor, mode);
        }

        if (!canResolvePathFrom(directoryFileDescriptor, guestPath)) {
            return EBADF;
        }

        @Nullable TarPath tarPath = resolveTarPath(
                directoryFileDescriptor,
                guestPath,
                (flags & AT_SYMLINK_NOFOLLOW) == 0);
        if (tarPath != null) {
            return accessTarPath(tarPath, mode);
        }

        @Nullable VirtualPath procPath = resolveVirtualPath(
                directoryFileDescriptor,
                guestPath,
                (flags & AT_SYMLINK_NOFOLLOW) == 0);
        if (procPath != null) {
            return accessVirtualNode(procPath.node(), mode);
        }

        @Nullable Path hostFile = resolveHostFile(directoryFileDescriptor, guestPath);
        if (hostFile == null) {
            return EACCES;
        }
        return accessHostFile(hostFile, mode);
    }

    /// Checks access bits on an open guest file descriptor.
    protected long accessFileDescriptor(int fileDescriptor, long mode) {
        int standardFileDescriptor = standardFileDescriptorFor(fileDescriptor);
        if (standardFileDescriptor >= 0) {
            if ((mode & W_OK) != 0 && standardFileDescriptor == 0) {
                return EACCES;
            }
            if ((mode & R_OK) != 0 && standardFileDescriptor != 0) {
                return EACCES;
            }
            return 0;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }
        @Nullable Path path = openFile.path();
        if (path != null) {
            return accessHostFile(path, mode, false);
        }
        @Nullable TarNode tarNode = openFile.tarNode();
        if (tarNode != null) {
            @Nullable String guestPath = openFile.guestPath();
            @Nullable TarPath tarPath = guestPath == null ? null : fileSystem.resolveTarPath(guestPath, false);
            return tarPath == null ? EACCES : accessTarNode(tarPath, mode);
        }
        @Nullable VirtualNode virtualNode = openFile.virtualNode();
        if (virtualNode != null) {
            return accessVirtualNode(virtualNode, mode);
        }
        if ((mode & R_OK) != 0 && !openFile.readable()) {
            return EACCES;
        }
        if ((mode & W_OK) != 0 && !openFile.writable()) {
            return EACCES;
        }
        return (mode & X_OK) != 0 && !openFile.isDirectory() ? EACCES : 0;
    }

    /// Checks access bits on a sandboxed host file.
    protected long accessHostFile(Path hostFile, long mode) {
        return accessHostFile(hostFile, mode, true);
    }

    /// Checks access bits on a sandboxed host file with optional parent search validation.
    protected long accessHostFile(Path hostFile, long mode, boolean requireParentSearch) {
        try {
            if (!Files.exists(hostFile)) {
                return ENOENT;
            }
            if (!canonicalFileStaysBelowMount(hostFile)) {
                return EACCES;
            }
            if (requireParentSearch) {
                long parentAccess = accessHostParent(hostFile);
                if (parentAccess != 0) {
                    return parentAccess;
                }
            }
            if ((mode & W_OK) != 0 && hostFileOnReadOnlyMount(hostFile)) {
                return EACCES;
            }
            boolean directory = Files.isDirectory(hostFile);
            GuestFileMetadata metadata = hostFileMetadata(hostFile, directory);
            if (!canAccess(metadata, mode, directory)) {
                return EACCES;
            }
            return 0;
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Creates a directory below a configured filesystem mount without applying guest mode bits.
    protected long mkdirat(long directoryFileDescriptor, long pathAddress, long mode) {
        @Nullable String guestPath = readGuestPath(pathAddress);
        if (guestPath == null) {
            return ENAMETOOLONG;
        }
        if (guestPath.isEmpty()) {
            return ENOENT;
        }

        if (!canResolvePathFrom(directoryFileDescriptor, guestPath)) {
            return EBADF;
        }

        @Nullable TarPath tarPath = resolveTarPath(directoryFileDescriptor, guestPath);
        if (tarPath != null) {
            return mkdirTarPath(tarPath, mode);
        }
        if (resolveVirtualPath(directoryFileDescriptor, guestPath) != null) {
            return EROFS;
        }

        @Nullable Path hostFile = resolveHostFile(directoryFileDescriptor, guestPath);
        if (hostFile == null) {
            return EACCES;
        }

        long parentError = validateSandboxedParent(hostFile);
        if (parentError != 0) {
            return parentError;
        }
        @Nullable Path parent = hostFile.getParent();
        if (parent == null) {
            return EACCES;
        }
        long parentAccess = accessHostFile(parent, W_OK | X_OK);
        if (parentAccess != 0) {
            return parentAccess;
        }
        if (hostFileOnReadOnlyMount(hostFile)) {
            return EROFS;
        }

        try {
            if (pathEntryExists(hostFile)) {
                return EEXIST;
            }
            GuestFileMetadata parentMetadata = hostFileMetadata(parent, true);
            Files.createDirectory(hostFile);
            fileMetadataStore.put(
                    hostFile,
                    new GuestFileMetadata(
                            credentials.effectiveUserId(),
                            createdEntryGroupId(parentMetadata),
                            createdDirectoryMode(parentMetadata, mode)));
            return 0;
        } catch (FileAlreadyExistsException exception) {
            return EEXIST;
        } catch (IOException | UnsupportedOperationException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Creates a directory in a writable memory tar mount.
    protected long mkdirTarPath(TarPath tarPath, long mode) {
        TarMount mount = tarPath.mount();
        if (mount.readOnly()) {
            return EROFS;
        }
        if (tarPath.node() != null) {
            return EEXIST;
        }
        @Nullable TarNode parent = tarParentDirectory(mount, tarPath.guestPath());
        if (parent == null) {
            return ENOENT;
        }
        if (!canAccessTarDirectory(parent, W_OK | X_OK)) {
            return EACCES;
        }

        String relativePath = GuestFileSystem.relativeGuestPath(tarPath.guestPath(), mount.guestPath());
        @Nullable TarNode directory = mount.fileSystem().createDirectory(
                relativePath,
                createdDirectoryMode(parent, mode),
                credentials.effectiveUserId(),
                createdEntryGroupId(parent));
        return directory == null ? ENOENT : 0;
    }

    /// Creates a symbolic link below a configured filesystem mount.
    protected long symlinkat(long targetAddress, long directoryFileDescriptor, long linkPathAddress) {
        @Nullable String target = readGuestPath(targetAddress);
        if (target == null) {
            return ENAMETOOLONG;
        }
        @Nullable String linkPath = readGuestPath(linkPathAddress);
        if (linkPath == null) {
            return ENAMETOOLONG;
        }
        if (target.isEmpty() || linkPath.isEmpty()) {
            return ENOENT;
        }
        if (!canResolvePathFrom(directoryFileDescriptor, linkPath)) {
            return EBADF;
        }

        @Nullable TarPath tarPath = resolveTarPath(directoryFileDescriptor, linkPath, false);
        if (tarPath != null) {
            return symlinkTarPath(tarPath, target);
        }
        if (resolveVirtualPath(directoryFileDescriptor, linkPath, false) != null) {
            return EROFS;
        }

        @Nullable Path hostFile = resolveHostFile(directoryFileDescriptor, linkPath);
        if (hostFile == null) {
            return EACCES;
        }
        long parentError = validateSandboxedParent(hostFile);
        if (parentError != 0) {
            return parentError;
        }
        @Nullable Path parent = hostFile.getParent();
        if (parent == null) {
            return EACCES;
        }
        long parentAccess = accessHostFile(parent, W_OK | X_OK);
        if (parentAccess != 0) {
            return parentAccess;
        }
        if (hostFileOnReadOnlyMount(hostFile)) {
            return EROFS;
        }

        try {
            if (pathEntryExists(hostFile)) {
                return EEXIST;
            }
            Files.createSymbolicLink(hostFile, Path.of(target));
            return 0;
        } catch (FileAlreadyExistsException exception) {
            return EEXIST;
        } catch (InvalidPathException exception) {
            return EINVAL;
        } catch (IOException | UnsupportedOperationException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Creates a symbolic link inside a writable memory tar mount.
    protected long symlinkTarPath(TarPath tarPath, String target) {
        TarMount mount = tarPath.mount();
        if (mount.readOnly()) {
            return EROFS;
        }
        if (tarPath.node() != null) {
            return EEXIST;
        }
        @Nullable TarNode parent = tarParentDirectory(mount, tarPath.guestPath());
        if (parent == null) {
            return ENOENT;
        }
        if (!canAccessTarDirectory(parent, W_OK | X_OK)) {
            return EACCES;
        }

        String relativePath = GuestFileSystem.relativeGuestPath(tarPath.guestPath(), mount.guestPath());
        @Nullable TarNode link = mount.fileSystem().createSymbolicLink(
                relativePath,
                target,
                STAT_MODE_ALL,
                credentials.effectiveUserId(),
                createdEntryGroupId(parent));
        return link == null ? ENOENT : 0;
    }

    /// Creates a hard link below configured filesystem mounts.
    protected long linkat(
            long oldDirectoryFileDescriptor,
            long oldPathAddress,
            long newDirectoryFileDescriptor,
            long newPathAddress,
            long flags) {
        if ((flags & ~AT_SYMLINK_FOLLOW) != 0) {
            return EINVAL;
        }

        @Nullable String oldGuestPath = readGuestPath(oldPathAddress);
        if (oldGuestPath == null) {
            return ENAMETOOLONG;
        }
        @Nullable String newGuestPath = readGuestPath(newPathAddress);
        if (newGuestPath == null) {
            return ENAMETOOLONG;
        }
        if (oldGuestPath.isEmpty() || newGuestPath.isEmpty()) {
            return ENOENT;
        }
        if (!canResolvePathFrom(oldDirectoryFileDescriptor, oldGuestPath)
                || !canResolvePathFrom(newDirectoryFileDescriptor, newGuestPath)) {
            return EBADF;
        }

        @Nullable String oldAbsoluteGuestPath = absoluteGuestPath(oldDirectoryFileDescriptor, oldGuestPath);
        @Nullable String newAbsoluteGuestPath = absoluteGuestPath(newDirectoryFileDescriptor, newGuestPath);
        if (oldAbsoluteGuestPath == null || newAbsoluteGuestPath == null) {
            return EACCES;
        }
        @Nullable Mount oldMount = mountForGuestPath(oldAbsoluteGuestPath);
        @Nullable Mount newMount = mountForGuestPath(newAbsoluteGuestPath);
        if (oldMount == null || newMount == null) {
            return EACCES;
        }
        if (oldMount != newMount) {
            return EXDEV;
        }

        boolean followSource = (flags & AT_SYMLINK_FOLLOW) != 0;
        if (oldMount instanceof TarMount) {
            @Nullable TarPath oldTarPath = fileSystem.resolveTarPath(oldAbsoluteGuestPath, followSource);
            @Nullable TarPath newTarPath = fileSystem.resolveTarPath(newAbsoluteGuestPath, false);
            if (oldTarPath == null || newTarPath == null) {
                return EXDEV;
            }
            return linkTarPath(oldTarPath, newTarPath);
        }
        if (oldMount instanceof VirtualMount) {
            return EROFS;
        }

        @Nullable Path oldHostFile = resolveHostFile(oldDirectoryFileDescriptor, oldGuestPath);
        @Nullable Path newHostFile = resolveHostFile(newDirectoryFileDescriptor, newGuestPath);
        if (oldHostFile == null || newHostFile == null) {
            return EACCES;
        }
        return linkHostFile(oldHostFile, newHostFile, followSource);
    }

    /// Creates a hard link between two sandboxed host paths.
    protected long linkHostFile(Path oldHostFile, Path newHostFile, boolean followSource) {
        long newParentError = validateSandboxedParent(newHostFile);
        if (newParentError != 0) {
            return newParentError;
        }
        @Nullable Path newParent = newHostFile.getParent();
        if (newParent == null) {
            return EACCES;
        }
        long newParentAccess = accessHostFile(newParent, W_OK | X_OK);
        if (newParentAccess != 0) {
            return newParentAccess;
        }
        if (hostFileOnReadOnlyMount(newHostFile)) {
            return EROFS;
        }

        try {
            if (!pathEntryExists(oldHostFile)) {
                return ENOENT;
            }
            long oldParentAccess = accessHostParent(oldHostFile);
            if (oldParentAccess != 0) {
                return oldParentAccess;
            }
            boolean symbolicLink = Files.isSymbolicLink(oldHostFile);
            Path source = followSource && symbolicLink ? oldHostFile.toRealPath() : oldHostFile;
            if (!symbolicLink || followSource) {
                if (!canonicalFileStaysBelowMount(source)) {
                    return EACCES;
                }
            }
            if (Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS)) {
                return EPERM;
            }
            if (pathEntryExists(newHostFile)) {
                return EEXIST;
            }

            @Nullable GuestFileMetadata metadata = symbolicLink && !followSource
                    ? null
                    : hostFileMetadata(source, false);
            Files.createLink(newHostFile, source);
            if (metadata != null) {
                fileMetadataStore.put(newHostFile, metadata);
            }
            return 0;
        } catch (FileAlreadyExistsException exception) {
            return EEXIST;
        } catch (NoSuchFileException exception) {
            return ENOENT;
        } catch (IOException | UnsupportedOperationException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Creates a hard link inside a writable memory tar mount.
    protected long linkTarPath(TarPath oldTarPath, TarPath newTarPath) {
        TarMount mount = oldTarPath.mount();
        if (mount != newTarPath.mount()) {
            return EXDEV;
        }
        if (mount.readOnly()) {
            return EROFS;
        }
        @Nullable TarNode oldNode = oldTarPath.node();
        if (oldNode == null) {
            return ENOENT;
        }
        if (oldNode.isDirectory()) {
            return EPERM;
        }
        if (newTarPath.node() != null) {
            return EEXIST;
        }
        if (!canSearchTarAncestors(oldNode)) {
            return EACCES;
        }
        @Nullable TarNode newParent = tarParentDirectory(mount, newTarPath.guestPath());
        if (newParent == null) {
            return ENOENT;
        }
        if (!canAccessTarDirectory(newParent, W_OK | X_OK)) {
            return EACCES;
        }

        String relativePath = GuestFileSystem.relativeGuestPath(newTarPath.guestPath(), mount.guestPath());
        return mount.fileSystem().createHardLink(relativePath, oldNode) == null ? ENOENT : 0;
    }

    /// Removes a file or empty directory below a configured filesystem mount.
    protected long unlinkat(long directoryFileDescriptor, long pathAddress, long flags) {
        if ((flags & ~AT_REMOVEDIR) != 0) {
            return EINVAL;
        }

        @Nullable String guestPath = readGuestPath(pathAddress);
        if (guestPath == null) {
            return ENAMETOOLONG;
        }
        if (guestPath.isEmpty()) {
            return ENOENT;
        }

        if (!canResolvePathFrom(directoryFileDescriptor, guestPath)) {
            return EBADF;
        }

        @Nullable TarPath tarPath = resolveTarPath(
                directoryFileDescriptor,
                guestPath,
                false);
        if (tarPath != null) {
            return unlinkTarPath(tarPath, (flags & AT_REMOVEDIR) != 0);
        }
        if (resolveVirtualPath(directoryFileDescriptor, guestPath, false) != null) {
            return EROFS;
        }

        @Nullable Path hostFile = resolveHostFile(directoryFileDescriptor, guestPath);
        if (hostFile == null) {
            return EACCES;
        }

        long parentError = validateSandboxedParent(hostFile);
        if (parentError != 0) {
            return parentError;
        }
        @Nullable Path parent = hostFile.getParent();
        if (parent == null) {
            return EACCES;
        }
        long parentAccess = accessHostFile(parent, W_OK | X_OK);
        if (parentAccess != 0) {
            return parentAccess;
        }
        if (hostFileOnReadOnlyMount(hostFile)) {
            return EROFS;
        }

        boolean removeDirectory = (flags & AT_REMOVEDIR) != 0;
        try {
            boolean symbolicLink = Files.isSymbolicLink(hostFile);
            if (!pathEntryExists(hostFile)) {
                return ENOENT;
            }
            if (removeDirectory) {
                if (symbolicLink || !Files.isDirectory(hostFile)) {
                    return ENOTDIR;
                }
            } else if (!symbolicLink && Files.isDirectory(hostFile)) {
                return EISDIR;
            }

            GuestFileMetadata parentMetadata = hostFileMetadata(parent, true);
            if (hasStickyMutationRestriction(parentMetadata)) {
                GuestFileMetadata metadata = hostFileMetadata(hostFile, removeDirectory && !symbolicLink);
                if (!canMutateStickyDirectory(parentMetadata, metadata)) {
                    return EPERM;
                }
            }

            String metadataKey = fileMetadataStore.key(hostFile);
            Files.delete(hostFile);
            fileMetadataStore.remove(metadataKey);
            return 0;
        } catch (NoSuchFileException exception) {
            return ENOENT;
        } catch (DirectoryNotEmptyException exception) {
            return ENOTEMPTY;
        } catch (IOException | UnsupportedOperationException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Removes a file or empty directory from a writable memory tar mount.
    protected long unlinkTarPath(TarPath tarPath, boolean removeDirectory) {
        TarMount mount = tarPath.mount();
        if (mount.readOnly()) {
            return EROFS;
        }

        @Nullable TarNode node = tarPath.node();
        if (node == null) {
            return ENOENT;
        }
        if (removeDirectory) {
            if (!node.isDirectory()) {
                return ENOTDIR;
            }
            if (!node.children().isEmpty()) {
                return ENOTEMPTY;
            }
        } else if (node.isDirectory()) {
            return EISDIR;
        }
        @Nullable TarNode parent = node.parent();
        if (parent == null) {
            return EACCES;
        }
        if (!canAccessTarDirectory(parent, W_OK | X_OK)) {
            return EACCES;
        }
        if (hasStickyMutationRestriction(parent) && !canMutateStickyDirectory(parent, node)) {
            return EPERM;
        }
        return mount.fileSystem().removeNode(node) ? 0 : EACCES;
    }

    /// Renames a sandboxed host path to another sandboxed host path.
    protected long renameat(
            long oldDirectoryFileDescriptor,
            long oldPathAddress,
            long newDirectoryFileDescriptor,
            long newPathAddress) {
        @Nullable String oldGuestPath = readGuestPath(oldPathAddress);
        if (oldGuestPath == null) {
            return ENAMETOOLONG;
        }
        @Nullable String newGuestPath = readGuestPath(newPathAddress);
        if (newGuestPath == null) {
            return ENAMETOOLONG;
        }
        if (oldGuestPath.isEmpty() || newGuestPath.isEmpty()) {
            return ENOENT;
        }

        if (!canResolvePathFrom(oldDirectoryFileDescriptor, oldGuestPath)
                || !canResolvePathFrom(newDirectoryFileDescriptor, newGuestPath)) {
            return EBADF;
        }

        @Nullable String oldAbsoluteGuestPath = absoluteGuestPath(oldDirectoryFileDescriptor, oldGuestPath);
        @Nullable String newAbsoluteGuestPath = absoluteGuestPath(newDirectoryFileDescriptor, newGuestPath);
        if (oldAbsoluteGuestPath == null || newAbsoluteGuestPath == null) {
            return EACCES;
        }

        @Nullable TarPath oldTarPath = fileSystem.resolveTarPath(oldAbsoluteGuestPath, false);
        @Nullable TarPath newTarPath = fileSystem.resolveTarPath(newAbsoluteGuestPath, false);
        if (oldTarPath != null || newTarPath != null) {
            if (oldTarPath == null || newTarPath == null) {
                return EXDEV;
            }
            return renameTarPath(oldTarPath, newTarPath);
        }
        if (resolveVirtualPath(oldDirectoryFileDescriptor, oldGuestPath) != null
                || resolveVirtualPath(newDirectoryFileDescriptor, newGuestPath) != null) {
            return EROFS;
        }

        @Nullable Path oldHostFile = resolveHostFile(oldDirectoryFileDescriptor, oldGuestPath);
        @Nullable Path newHostFile = resolveHostFile(newDirectoryFileDescriptor, newGuestPath);
        if (oldHostFile == null || newHostFile == null) {
            return EACCES;
        }

        long oldParentError = validateSandboxedParent(oldHostFile);
        if (oldParentError != 0) {
            return oldParentError;
        }
        long newParentError = validateSandboxedParent(newHostFile);
        if (newParentError != 0) {
            return newParentError;
        }
        @Nullable Path oldParent = oldHostFile.getParent();
        @Nullable Path newParent = newHostFile.getParent();
        if (oldParent == null || newParent == null) {
            return EACCES;
        }
        long oldParentAccess = accessHostFile(oldParent, W_OK | X_OK);
        if (oldParentAccess != 0) {
            return oldParentAccess;
        }
        long newParentAccess = accessHostFile(newParent, W_OK | X_OK);
        if (newParentAccess != 0) {
            return newParentAccess;
        }
        if (hostFileOnReadOnlyMount(oldHostFile) || hostFileOnReadOnlyMount(newHostFile)) {
            return EROFS;
        }

        try {
            if (!pathEntryExists(oldHostFile)) {
                return ENOENT;
            }

            boolean oldDirectory = !Files.isSymbolicLink(oldHostFile) && Files.isDirectory(oldHostFile);
            GuestFileMetadata oldParentMetadata = hostFileMetadata(oldParent, true);
            if (hasStickyMutationRestriction(oldParentMetadata)) {
                GuestFileMetadata oldMetadata = hostFileMetadata(oldHostFile, oldDirectory);
                if (!canMutateStickyDirectory(oldParentMetadata, oldMetadata)) {
                    return EPERM;
                }
            }

            if (pathEntryExists(newHostFile)) {
                boolean newDirectory = !Files.isSymbolicLink(newHostFile) && Files.isDirectory(newHostFile);
                if (oldDirectory && !newDirectory) {
                    return ENOTDIR;
                }
                if (!oldDirectory && newDirectory) {
                    return EISDIR;
                }
                GuestFileMetadata newParentMetadata = hostFileMetadata(newParent, true);
                if (hasStickyMutationRestriction(newParentMetadata)) {
                    GuestFileMetadata newMetadata = hostFileMetadata(newHostFile, newDirectory);
                    if (!canMutateStickyDirectory(newParentMetadata, newMetadata)) {
                        return EPERM;
                    }
                }
            }

            String oldMetadataKey = fileMetadataStore.key(oldHostFile);
            Files.move(oldHostFile, newHostFile, StandardCopyOption.REPLACE_EXISTING);
            fileMetadataStore.move(oldMetadataKey, newHostFile);
            return 0;
        } catch (NoSuchFileException exception) {
            return ENOENT;
        } catch (DirectoryNotEmptyException exception) {
            return ENOTEMPTY;
        } catch (FileAlreadyExistsException exception) {
            return EEXIST;
        } catch (IOException | UnsupportedOperationException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Renames a node inside a writable memory tar mount.
    protected long renameTarPath(TarPath oldTarPath, TarPath newTarPath) {
        TarMount mount = oldTarPath.mount();
        if (mount != newTarPath.mount()) {
            return EXDEV;
        }
        if (mount.readOnly()) {
            return EROFS;
        }

        @Nullable TarNode oldNode = oldTarPath.node();
        if (oldNode == null) {
            return ENOENT;
        }
        @Nullable TarNode oldParent = oldNode.parent();
        @Nullable TarNode newParent = tarParentDirectory(mount, newTarPath.guestPath());
        if (oldParent == null || newParent == null) {
            return ENOENT;
        }
        if (!canAccessTarDirectory(oldParent, W_OK | X_OK)
                || !canAccessTarDirectory(newParent, W_OK | X_OK)) {
            return EACCES;
        }

        @Nullable TarNode newNode = newTarPath.node();
        if (oldNode == newNode) {
            return 0;
        }
        if (oldNode.isDirectory() && guestPathMatchesMount(newTarPath.guestPath(), oldTarPath.guestPath())) {
            return EINVAL;
        }
        if (hasStickyMutationRestriction(oldParent) && !canMutateStickyDirectory(oldParent, oldNode)) {
            return EPERM;
        }
        if (newNode != null) {
            if (oldNode.isDirectory() && !newNode.isDirectory()) {
                return ENOTDIR;
            }
            if (!oldNode.isDirectory() && newNode.isDirectory()) {
                return EISDIR;
            }
            if (newNode.isDirectory() && !newNode.children().isEmpty()) {
                return ENOTEMPTY;
            }
            if (hasStickyMutationRestriction(newParent) && !canMutateStickyDirectory(newParent, newNode)) {
                return EPERM;
            }
            if (!mount.fileSystem().removeNode(newNode)) {
                return EACCES;
            }
        }

        String relativePath = GuestFileSystem.relativeGuestPath(newTarPath.guestPath(), mount.guestPath());
        return mount.fileSystem().moveNode(oldNode, relativePath) == null ? ENOENT : 0;
    }

    /// Handles extended guest rename entry points that do not request nonzero rename flags.
    protected long renameat2(
            long oldDirectoryFileDescriptor,
            long oldPathAddress,
            long newDirectoryFileDescriptor,
            long newPathAddress,
            long flags) {
        if (flags != 0) {
            return EINVAL;
        }
        return renameat(oldDirectoryFileDescriptor, oldPathAddress, newDirectoryFileDescriptor, newPathAddress);
    }

    /// Truncates a sandboxed host file selected by path.
    protected long truncate(long pathAddress, long length) {
        if (length < 0) {
            return EINVAL;
        }

        @Nullable String guestPath = readGuestPath(pathAddress);
        if (guestPath == null) {
            return ENAMETOOLONG;
        }
        if (guestPath.isEmpty()) {
            return ENOENT;
        }

        @Nullable TarPath tarPath = resolveTarPath(AT_FDCWD, guestPath);
        if (tarPath != null) {
            return truncateTarPath(tarPath, length);
        }
        if (resolveVirtualPath(AT_FDCWD, guestPath) != null) {
            return EROFS;
        }

        @Nullable Path hostFile = resolveHostFile(AT_FDCWD, guestPath);
        if (hostFile == null) {
            return EACCES;
        }

        try {
            if (!pathEntryExists(hostFile)) {
                return ENOENT;
            }
            if (!canonicalFileStaysBelowMount(hostFile)) {
                return EACCES;
            }
            long parentAccess = accessHostParent(hostFile);
            if (parentAccess != 0) {
                return parentAccess;
            }
            if (Files.isDirectory(hostFile)) {
                return EISDIR;
            }
            if (!Files.isRegularFile(hostFile)) {
                return ENODEV;
            }
            GuestFileMetadata metadata = hostFileMetadata(hostFile, false);
            if (!canAccess(metadata, W_OK, false)) {
                return EACCES;
            }
            if (!Files.isWritable(hostFile)) {
                return EACCES;
            }
            if (hostFileOnReadOnlyMount(hostFile)) {
                return EROFS;
            }

            try (SeekableByteChannel channel = Files.newByteChannel(hostFile, EnumSet.of(StandardOpenOption.WRITE))) {
                resizeHostChannel(channel, length);
            }
            return 0;
        } catch (NoSuchFileException exception) {
            return ENOENT;
        } catch (IOException | UnsupportedOperationException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Truncates a regular file in a writable memory tar mount.
    protected long truncateTarPath(TarPath tarPath, long length) {
        TarMount mount = tarPath.mount();
        if (mount.readOnly()) {
            return EROFS;
        }
        @Nullable TarNode node = tarPath.node();
        if (node == null) {
            return ENOENT;
        }
        if (node.isDirectory()) {
            return EISDIR;
        }
        if (!node.isFile()) {
            return ENODEV;
        }
        if (!canSearchTarAncestors(node) || !canAccess(node, W_OK)) {
            return EACCES;
        }

        try (SeekableByteChannel channel = mount.fileSystem().openFileChannel(node, true)) {
            resizeHostChannel(channel, length);
            return 0;
        } catch (IOException exception) {
            throw new RiscVException("Guest tar truncate syscall failed", exception);
        }
    }

    /// Truncates the open host file referenced by a guest file descriptor.
    protected long ftruncate(int fileDescriptor, long length) {
        if (length < 0) {
            return EINVAL;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }
        if (!openFile.isHostFile()) {
            return EINVAL;
        }
        if (!openFile.writable()) {
            return EBADF;
        }

        try {
            resizeHostChannel(openFile.channel(), length);
            return 0;
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Allocates a regular file range without changing existing data or the open-file offset.
    protected long posixFallocate(int fileDescriptor, long offset, long length) {
        if (offset < 0 || length <= 0) {
            return EINVAL;
        }
        if (offset > Long.MAX_VALUE - length) {
            return EFBIG;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }
        if (!openFile.writable()) {
            return EBADF;
        }
        if (openFile.isPipe()) {
            return ESPIPE;
        }
        if (!openFile.isHostFile() || openFile.isDirectory() || openFile.isCharacterDevice()) {
            return ENODEV;
        }

        long end = offset + length;
        try {
            SeekableByteChannel channel = openFile.channel();
            if (end > channel.size()) {
                resizeHostChannel(channel, end);
            }
            return 0;
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Handles Linux `fallocate` mode zero through the shared POSIX allocation operation.
    protected long fallocate(int fileDescriptor, long mode, long offset, long length) {
        return mode == 0 ? posixFallocate(fileDescriptor, offset, length) : ENOTSUP;
    }

    /// Zeroes the portion of a writable regular-file range before EOF without changing its size or open-file offset.
    protected long zeroFileRange(int fileDescriptor, long offset, long length) {
        if (offset < 0 || length <= 0 || offset > Long.MAX_VALUE - length) {
            return EINVAL;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }
        if (!openFile.writable()) {
            return EBADF;
        }
        if (openFile.isPipe()) {
            return ESPIPE;
        }
        if (!openFile.isHostFile() || openFile.isDirectory() || openFile.isCharacterDevice()) {
            return ENODEV;
        }

        try {
            SeekableByteChannel channel = openFile.channel();
            long size = channel.size();
            long zeroLength = offset >= size ? 0 : Math.min(length, size - offset);
            writeZeroFileRange(channel, offset, zeroLength);
            return zeroLength;
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Writes zero bytes at a fixed host-file range while preserving the channel position.
    protected static void writeZeroFileRange(SeekableByteChannel channel, long offset, long length) throws IOException {
        if (length == 0) {
            return;
        }

        byte[] zeros = new byte[(int) Math.min(length, FILE_COPY_BUFFER_SIZE)];
        long position = channel.position();
        try {
            channel.position(offset);
            long remaining = length;
            while (remaining > 0) {
                ByteBuffer buffer = ByteBuffer.wrap(zeros, 0, (int) Math.min(remaining, zeros.length));
                while (buffer.hasRemaining()) {
                    if (channel.write(buffer) <= 0) {
                        throw new IOException("Host file channel made no progress while zeroing a guest range");
                    }
                }
                remaining -= buffer.limit();
            }
        } finally {
            channel.position(position);
        }
    }

    /// Validates a POSIX file-access hint for a seekable regular file.
    protected long posixFadvise(int fileDescriptor, long offset, long length, long advice) {
        if (offset < 0 || length < 0 || offset > Long.MAX_VALUE - length) {
            return EINVAL;
        }
        if (advice < POSIX_FADV_NORMAL || advice > POSIX_FADV_NOREUSE) {
            return EINVAL;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }
        if (openFile.isDirectory() || openFile.isCharacterDevice()) {
            return ENODEV;
        }
        if (!openFile.isHostFile()) {
            return ESPIPE;
        }
        return 0;
    }

    /// Changes the guest-visible current working directory to a sandboxed host directory.
    protected long chdir(long pathAddress) {
        @Nullable String guestPath = readGuestPath(pathAddress);
        if (guestPath == null) {
            return ENAMETOOLONG;
        }
        if (guestPath.isEmpty()) {
            return ENOENT;
        }

        @Nullable TarPath tarPath = resolveTarPath(AT_FDCWD, guestPath);
        if (tarPath != null) {
            return changeWorkingDirectory(tarPath);
        }

        @Nullable VirtualPath procPath = resolveVirtualPath(AT_FDCWD, guestPath);
        if (procPath != null) {
            return changeWorkingDirectory(procPath);
        }

        @Nullable Path hostFile = resolveHostFile(AT_FDCWD, guestPath);
        if (hostFile == null) {
            return EACCES;
        }
        return changeWorkingDirectory(hostFile);
    }

    /// Changes the guest-visible current working directory to an open directory descriptor.
    protected long fchdir(int fileDescriptor) {
        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }
        if (!openFile.isDirectory()) {
            return ENOTDIR;
        }

        @Nullable TarNode tarNode = openFile.tarNode();
        if (tarNode != null) {
            @Nullable String guestPath = openFile.guestPath();
            if (guestPath == null) {
                return EBADF;
            }
            if (!canAccess(tarNode, X_OK)) {
                return EACCES;
            }
            guestWorkingDirectory = guestPath;
            return 0;
        }
        @Nullable VirtualNode virtualNode = openFile.virtualNode();
        if (virtualNode != null) {
            @Nullable String guestPath = openFile.guestPath();
            if (guestPath == null) {
                return EBADF;
            }
            if (!canAccess(virtualNode, X_OK)) {
                return EACCES;
            }
            guestWorkingDirectory = guestPath;
            return 0;
        }

        @Nullable Path path = openFile.path();
        if (path == null) {
            return EBADF;
        }
        return changeWorkingDirectory(path);
    }

    /// Applies a host directory as the guest-visible current working directory.
    protected long changeWorkingDirectory(Path hostFile) {
        try {
            if (!pathEntryExists(hostFile)) {
                return ENOENT;
            }
            if (!canonicalFileStaysBelowMount(hostFile)) {
                return EACCES;
            }
            if (!Files.isDirectory(hostFile)) {
                return ENOTDIR;
            }
            long parentAccess = accessHostParent(hostFile);
            if (parentAccess != 0) {
                return parentAccess;
            }
            GuestFileMetadata metadata = hostFileMetadata(hostFile, true);
            if (!canAccess(metadata, X_OK, true)) {
                return EACCES;
            }

            @Nullable String guestPath = guestPathForHostFile(hostFile);
            if (guestPath == null) {
                return EACCES;
            }
            guestWorkingDirectory = guestPath;
            return 0;
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Applies a tar directory as the guest-visible current working directory.
    protected long changeWorkingDirectory(TarPath tarPath) {
        @Nullable TarNode node = tarPath.node();
        if (node == null) {
            return ENOENT;
        }
        if (!node.isDirectory()) {
            return ENOTDIR;
        }
        if (!canSearchTarAncestors(node) || !canAccess(node, X_OK)) {
            return EACCES;
        }
        guestWorkingDirectory = tarPath.guestPath();
        return 0;
    }

    /// Applies a proc directory as the guest-visible current working directory.
    protected long changeWorkingDirectory(VirtualPath procPath) {
        @Nullable VirtualNode node = procPath.node();
        if (node == null) {
            return ENOENT;
        }
        if (!node.isDirectory()) {
            return ENOTDIR;
        }
        if (!canAccess(node, X_OK)) {
            return EACCES;
        }
        guestWorkingDirectory = procPath.guestPath();
        return 0;
    }

    /// Changes ownership metadata for an open file descriptor.
    protected long fchown(int fileDescriptor, long owner, long group) {
        if (!isChownId(owner) || !isChownId(group)) {
            return EINVAL;
        }
        return chownFileDescriptor(fileDescriptor, owner, group);
    }

    /// Changes ownership metadata for an open descriptor or sandboxed path.
    protected long fchownat(long directoryFileDescriptor, long pathAddress, long owner, long group, long flags) {
        if ((flags & ~SUPPORTED_FCHOWNAT_FLAGS) != 0 || !isChownId(owner) || !isChownId(group)) {
            return EINVAL;
        }
        if (pathAddress == 0) {
            return EFAULT;
        }

        @Nullable String guestPath = readGuestPath(pathAddress);
        if (guestPath == null) {
            return ENAMETOOLONG;
        }

        if (guestPath.isEmpty()) {
            if ((flags & AT_EMPTY_PATH) == 0) {
                return ENOENT;
            }
            if (directoryFileDescriptor == AT_FDCWD) {
                @Nullable Path currentDirectory = currentHostWorkingDirectory();
                return currentDirectory == null ? EACCES : chownHostFile(currentDirectory, owner, group, flags, true);
            }
            if (directoryFileDescriptor < Integer.MIN_VALUE || directoryFileDescriptor > Integer.MAX_VALUE) {
                return EBADF;
            }
            return chownFileDescriptor((int) directoryFileDescriptor, owner, group);
        }

        if (!canResolvePathFrom(directoryFileDescriptor, guestPath)) {
            return EBADF;
        }

        @Nullable TarPath tarPath = resolveTarPath(
                directoryFileDescriptor,
                guestPath,
                (flags & AT_SYMLINK_NOFOLLOW) == 0);
        if (tarPath != null) {
            return chownTarPath(tarPath, owner, group, true);
        }

        @Nullable VirtualPath procPath = resolveVirtualPath(
                directoryFileDescriptor,
                guestPath,
                (flags & AT_SYMLINK_NOFOLLOW) == 0);
        if (procPath != null) {
            return chownVirtualPath(procPath, owner, group);
        }

        @Nullable Path hostFile = resolveHostFile(directoryFileDescriptor, guestPath);
        if (hostFile == null) {
            return EACCES;
        }
        return chownHostFile(hostFile, owner, group, flags, true);
    }

    /// Returns true when a Linux `chown` uid or gid argument is valid.
    protected static boolean isChownId(long id) {
        return id == -1L || id >= 0 && id <= GuestCredentials.MAX_ID;
    }

    /// Changes ownership metadata for an existing open file descriptor.
    protected long chownFileDescriptor(int fileDescriptor, long owner, long group) {
        if (isStandardFileDescriptor(fileDescriptor)) {
            return owner == -1L && group == -1L ? 0 : EINVAL;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }

        @Nullable Path path = openFile.path();
        if (path != null) {
            return chownHostFile(path, owner, group, 0, false);
        }
        @Nullable TarNode tarNode = openFile.tarNode();
        if (tarNode != null) {
            @Nullable String guestPath = openFile.guestPath();
            @Nullable TarPath tarPath = guestPath == null ? null : fileSystem.resolveTarPath(guestPath, false);
            return tarPath == null ? EACCES : chownTarPath(tarPath, owner, group, false);
        }
        @Nullable VirtualNode virtualNode = openFile.virtualNode();
        if (virtualNode != null) {
            return chownVirtualNode(virtualNode, owner, group);
        }
        return owner == -1L && group == -1L ? 0 : EINVAL;
    }

    /// Changes ownership metadata for an existing sandboxed host filesystem entry.
    protected long chownHostFile(
            Path hostFile,
            long owner,
            long group,
            long flags,
            boolean requireParentSearch) {
        try {
            if (!pathEntryExists(hostFile)) {
                return ENOENT;
            }
            if ((flags & AT_SYMLINK_NOFOLLOW) == 0) {
                if (!canonicalFileStaysBelowMount(hostFile)) {
                    return EACCES;
                }
            } else if (Files.isSymbolicLink(hostFile)) {
                return owner == -1L && group == -1L ? 0 : ENOTSUP;
            } else {
                @Nullable HostMount mount = mountForHostFile(hostFile);
                if (mount == null) {
                    return EACCES;
                }
            }

            if (owner == -1L && group == -1L) {
                return 0;
            }
            if (requireParentSearch) {
                long parentAccess = accessHostParent(hostFile);
                if (parentAccess != 0) {
                    return parentAccess;
                }
            }
            if (hostFileOnReadOnlyMount(hostFile)) {
                return EROFS;
            }

            boolean directory = Files.isDirectory(hostFile);
            GuestFileMetadata metadata = hostFileMetadata(hostFile, directory);
            if (!canChangeOwner(metadata, owner, group)) {
                return EPERM;
            }
            fileMetadataStore.put(hostFile, metadata.withOwner(
                    owner == -1L ? metadata.userId() : owner,
                    group == -1L ? metadata.groupId() : group));
            return 0;
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Changes ownership metadata for a tar filesystem node.
    protected long chownTarPath(TarPath tarPath, long owner, long group, boolean requireParentSearch) {
        @Nullable TarNode node = tarPath.node();
        if (node == null) {
            return ENOENT;
        }
        if (owner == -1L && group == -1L) {
            return 0;
        }
        if (tarPath.mount().readOnly()) {
            return EROFS;
        }
        if (requireParentSearch && !canSearchTarAncestors(node)) {
            return EACCES;
        }
        if (!canChangeOwner(node.userId(), node.groupId(), owner, group)) {
            return EPERM;
        }
        node.setOwner(owner == -1L ? node.userId() : owner, group == -1L ? node.groupId() : group);
        return 0;
    }

    /// Changes ownership metadata for a virtual filesystem path.
    protected long chownVirtualPath(VirtualPath virtualPath, long owner, long group) {
        @Nullable VirtualNode node = virtualPath.node();
        if (node == null) {
            return ENOENT;
        }
        return chownVirtualNode(node, owner, group);
    }

    /// Changes ownership metadata for a virtual filesystem node.
    protected long chownVirtualNode(VirtualNode node, long owner, long group) {
        return owner == -1L && group == -1L || deviceFileFor(node) == DeviceFile.PTS0 ? 0 : EROFS;
    }

    /// Sets the process file creation mask and returns the previous mask.
    protected long umask(long mask) {
        synchronized (threadLock) {
            int previousMask = fileCreationMask;
            fileCreationMask = (int) mask & STAT_MODE_ALL;
            return previousMask;
        }
    }

    /// Returns true when the current credentials may apply a Linux ownership change.
    protected boolean canChangeOwner(GuestFileMetadata metadata, long owner, long group) {
        return canChangeOwner(metadata.userId(), metadata.groupId(), owner, group);
    }

    /// Returns true when the current credentials may apply a Linux ownership change.
    protected boolean canChangeOwner(long currentOwner, long currentGroup, long owner, long group) {
        if (credentials.effectiveUserId() == 0) {
            return true;
        }
        if (owner != -1L && owner != currentOwner) {
            return false;
        }
        if (group == -1L || group == currentGroup) {
            return currentOwner == credentials.effectiveUserId();
        }
        return currentOwner == credentials.effectiveUserId() && ownsGroup(group);
    }

    /// Returns true when the current credentials include the supplied group.
    protected boolean ownsGroup(long groupId) {
        if (credentials.effectiveGroupId() == groupId) {
            return true;
        }
        for (int index = 0; index < credentials.supplementaryGroupCount(); index++) {
            if (credentials.supplementaryGroupAt(index) == groupId) {
                return true;
            }
        }
        return false;
    }

    /// Changes permission metadata for an open file descriptor.
    protected long fchmod(int fileDescriptor, long mode) {
        return chmodFileDescriptor(fileDescriptor, mode);
    }

    /// Changes permission metadata for an open descriptor or sandboxed path.
    protected long fchmodat(long directoryFileDescriptor, long pathAddress, long mode, long flags) {
        if ((flags & ~SUPPORTED_FCHMODAT2_FLAGS) != 0) {
            return EINVAL;
        }
        if (pathAddress == 0) {
            return EFAULT;
        }

        @Nullable String guestPath = readGuestPath(pathAddress);
        if (guestPath == null) {
            return ENAMETOOLONG;
        }

        if (guestPath.isEmpty()) {
            if ((flags & AT_EMPTY_PATH) == 0) {
                return ENOENT;
            }
            if (directoryFileDescriptor == AT_FDCWD) {
                @Nullable Path currentDirectory = currentHostWorkingDirectory();
                return currentDirectory == null ? EACCES : chmodHostFile(currentDirectory, mode, flags, true);
            }
            if (directoryFileDescriptor < Integer.MIN_VALUE || directoryFileDescriptor > Integer.MAX_VALUE) {
                return EBADF;
            }
            return chmodFileDescriptor((int) directoryFileDescriptor, mode);
        }

        if (!canResolvePathFrom(directoryFileDescriptor, guestPath)) {
            return EBADF;
        }

        @Nullable TarPath tarPath = resolveTarPath(
                directoryFileDescriptor,
                guestPath,
                (flags & AT_SYMLINK_NOFOLLOW) == 0);
        if (tarPath != null) {
            return chmodTarPath(tarPath, mode, flags, true);
        }

        @Nullable VirtualPath virtualPath = resolveVirtualPath(
                directoryFileDescriptor,
                guestPath,
                (flags & AT_SYMLINK_NOFOLLOW) == 0);
        if (virtualPath != null) {
            return chmodVirtualPath(virtualPath, mode);
        }

        @Nullable Path hostFile = resolveHostFile(directoryFileDescriptor, guestPath);
        if (hostFile == null) {
            return EACCES;
        }
        return chmodHostFile(hostFile, mode, flags, true);
    }

    /// Changes permission metadata for an existing open file descriptor.
    protected long chmodFileDescriptor(int fileDescriptor, long mode) {
        if (isStandardFileDescriptor(fileDescriptor)) {
            return EINVAL;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }

        @Nullable Path path = openFile.path();
        if (path != null) {
            return chmodHostFile(path, mode, 0, false);
        }
        @Nullable TarNode tarNode = openFile.tarNode();
        if (tarNode != null) {
            @Nullable String guestPath = openFile.guestPath();
            @Nullable TarPath tarPath = guestPath == null ? null : fileSystem.resolveTarPath(guestPath, false);
            return tarPath == null ? EACCES : chmodTarPath(tarPath, mode, 0, false);
        }
        @Nullable VirtualNode virtualNode = openFile.virtualNode();
        if (virtualNode != null) {
            return chmodVirtualNode(virtualNode, mode);
        }
        return EINVAL;
    }

    /// Changes permission metadata for an existing sandboxed host filesystem entry.
    protected long chmodHostFile(Path hostFile, long mode, long flags, boolean requireParentSearch) {
        try {
            if (!pathEntryExists(hostFile)) {
                return ENOENT;
            }
            if ((flags & AT_SYMLINK_NOFOLLOW) != 0 && Files.isSymbolicLink(hostFile)) {
                return ENOTSUP;
            }
            if (!canonicalFileStaysBelowMount(hostFile)) {
                return EACCES;
            }
            if (hostFileOnReadOnlyMount(hostFile)) {
                return EROFS;
            }
            if (requireParentSearch) {
                long parentAccess = accessHostParent(hostFile);
                if (parentAccess != 0) {
                    return parentAccess;
                }
            }

            boolean directory = Files.isDirectory(hostFile);
            GuestFileMetadata metadata = hostFileMetadata(hostFile, directory);
            if (!canChangeMode(metadata.userId())) {
                return EPERM;
            }
            fileMetadataStore.put(hostFile, metadata.withMode(normalizeChangedMode(metadata.groupId(), mode)));
            return 0;
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Changes permission metadata for a tar filesystem node.
    protected long chmodTarPath(TarPath tarPath, long mode, long flags, boolean requireParentSearch) {
        @Nullable TarNode node = tarPath.node();
        if (node == null) {
            return ENOENT;
        }
        if ((flags & AT_SYMLINK_NOFOLLOW) != 0 && node.isSymbolicLink()) {
            return ENOTSUP;
        }
        if (tarPath.mount().readOnly()) {
            return EROFS;
        }
        if (requireParentSearch && !canSearchTarAncestors(node)) {
            return EACCES;
        }
        if (!canChangeMode(node.userId())) {
            return EPERM;
        }
        node.setPermissions(normalizeChangedMode(node.groupId(), mode));
        return 0;
    }

    /// Changes permission metadata for a virtual filesystem path.
    protected long chmodVirtualPath(VirtualPath virtualPath, long mode) {
        @Nullable VirtualNode node = virtualPath.node();
        return node == null ? ENOENT : chmodVirtualNode(node, mode);
    }

    /// Changes permission metadata for a virtual filesystem node.
    protected long chmodVirtualNode(VirtualNode node, long mode) {
        return deviceFileFor(node) == DeviceFile.PTS0 ? 0 : EROFS;
    }

    /// Returns true when the current credentials may change a file's Linux mode.
    protected boolean canChangeMode(long ownerId) {
        return credentials.effectiveUserId() == 0 || credentials.effectiveUserId() == ownerId;
    }

    /// Returns normalized Linux mode bits for `chmod`-style updates.
    protected int normalizeChangedMode(long groupId, long mode) {
        int normalizedMode = (int) mode & STAT_MODE_CHANGE_BITS;
        if (credentials.effectiveUserId() != 0
                && (normalizedMode & STAT_MODE_SET_GROUP_ID) != 0
                && !ownsGroup(groupId)) {
            normalizedMode &= ~STAT_MODE_SET_GROUP_ID;
        }
        return normalizedMode;
    }

    /// Updates access and modification times for a sandboxed path or open descriptor.
    protected long utimensat(long directoryFileDescriptor, long pathAddress, long timesAddress, long flags) {
        return utimensat(
                directoryFileDescriptor,
                pathAddress,
                timesAddress,
                flags,
                UTIME_NOW,
                UTIME_OMIT);
    }

    /// Updates timestamps using ABI-specific `UTIME_NOW` and `UTIME_OMIT` nanosecond sentinels.
    protected long utimensat(
            long directoryFileDescriptor,
            long pathAddress,
            long timesAddress,
            long flags,
            long nowNanoseconds,
            long omitNanoseconds) {
        if ((flags & ~SUPPORTED_UTIMENSAT_FLAGS) != 0) {
            return EINVAL;
        }
        if (pathAddress == 0) {
            return EFAULT;
        }

        TimestampUpdate @Nullable [] updates = timestampUpdates(timesAddress, nowNanoseconds, omitNanoseconds);
        if (updates == null) {
            return timesAddress == 0 || memory.isBacked(timesAddress, 2L * TIMESPEC_SIZE) ? EINVAL : EFAULT;
        }
        TimestampUpdate accessTime = updates[0];
        TimestampUpdate modificationTime = updates[1];

        @Nullable String guestPath = readGuestPath(pathAddress);
        if (guestPath == null) {
            return ENAMETOOLONG;
        }

        if (guestPath.isEmpty()) {
            if ((flags & AT_EMPTY_PATH) == 0) {
                return ENOENT;
            }
            if (directoryFileDescriptor == AT_FDCWD) {
                @Nullable Path currentDirectory = currentHostWorkingDirectory();
                return currentDirectory == null
                        ? EACCES
                        : updateHostFileTimes(currentDirectory, accessTime, modificationTime, flags, true);
            }
            if (directoryFileDescriptor < Integer.MIN_VALUE || directoryFileDescriptor > Integer.MAX_VALUE) {
                return EBADF;
            }
            return updateFileDescriptorTimes(
                    (int) directoryFileDescriptor,
                    accessTime,
                    modificationTime);
        }

        if (!canResolvePathFrom(directoryFileDescriptor, guestPath)) {
            return EBADF;
        }

        boolean followFinalSymlink = (flags & AT_SYMLINK_NOFOLLOW) == 0;
        @Nullable TarPath tarPath = resolveTarPath(directoryFileDescriptor, guestPath, followFinalSymlink);
        if (tarPath != null) {
            return updateTarPathTimes(tarPath, accessTime, modificationTime, true);
        }

        @Nullable VirtualPath virtualPath = resolveVirtualPath(directoryFileDescriptor, guestPath, followFinalSymlink);
        if (virtualPath != null) {
            return updateVirtualPathTimes(virtualPath, accessTime, modificationTime);
        }

        @Nullable Path hostFile = resolveHostFile(directoryFileDescriptor, guestPath);
        if (hostFile == null) {
            return EACCES;
        }
        return updateHostFileTimes(hostFile, accessTime, modificationTime, flags, true);
    }

    /// Updates an open descriptor's timestamps using ABI-specific nanosecond sentinels.
    protected long futimens(
            int fileDescriptor,
            long timesAddress,
            long nowNanoseconds,
            long omitNanoseconds) {
        TimestampUpdate @Nullable [] updates = timestampUpdates(timesAddress, nowNanoseconds, omitNanoseconds);
        if (updates == null) {
            return timesAddress == 0 || memory.isBacked(timesAddress, 2L * TIMESPEC_SIZE) ? EINVAL : EFAULT;
        }
        return updateFileDescriptorTimes(fileDescriptor, updates[0], updates[1]);
    }

    /// Updates access and modification times for an open descriptor.
    private long updateFileDescriptorTimes(
            int fileDescriptor,
            TimestampUpdate accessTime,
            TimestampUpdate modificationTime) {
        if (isStandardFileDescriptor(fileDescriptor)) {
            return accessTime.omit() && modificationTime.omit() ? 0 : EINVAL;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }

        @Nullable Path path = openFile.path();
        if (path != null) {
            return updateHostFileTimes(path, accessTime, modificationTime, 0, false);
        }
        @Nullable TarNode tarNode = openFile.tarNode();
        if (tarNode != null) {
            @Nullable String guestPath = openFile.guestPath();
            @Nullable TarPath tarPath = guestPath == null ? null : fileSystem.resolveTarPath(guestPath, false);
            return tarPath == null ? EACCES : updateTarPathTimes(tarPath, accessTime, modificationTime, false);
        }
        @Nullable VirtualNode virtualNode = openFile.virtualNode();
        if (virtualNode != null) {
            return updateVirtualNodeTimes(virtualNode, accessTime, modificationTime);
        }
        return accessTime.omit() && modificationTime.omit() ? 0 : EINVAL;
    }

    /// Updates access and modification times for an existing sandboxed host filesystem entry.
    private long updateHostFileTimes(
            Path hostFile,
            TimestampUpdate accessTime,
            TimestampUpdate modificationTime,
            long flags,
            boolean requireParentSearch) {
        try {
            if (!pathEntryExists(hostFile)) {
                return ENOENT;
            }
            if ((flags & AT_SYMLINK_NOFOLLOW) == 0 || !Files.isSymbolicLink(hostFile)) {
                if (!canonicalFileStaysBelowMount(hostFile)) {
                    return EACCES;
                }
            } else if (mountForHostFile(hostFile) == null) {
                return EACCES;
            }
            if (requireParentSearch) {
                long parentAccess = accessHostParent(hostFile);
                if (parentAccess != 0) {
                    return parentAccess;
                }
            }
            if (accessTime.omit() && modificationTime.omit()) {
                return 0;
            }
            if (hostFileOnReadOnlyMount(hostFile)) {
                return EROFS;
            }

            BasicFileAttributeView view = (flags & AT_SYMLINK_NOFOLLOW) == 0
                    ? Files.getFileAttributeView(hostFile, BasicFileAttributeView.class)
                    : Files.getFileAttributeView(hostFile, BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            if (view == null) {
                return ENOTSUP;
            }
            view.setTimes(modificationTime.fileTime(), accessTime.fileTime(), null);
            return 0;
        } catch (NoSuchFileException exception) {
            return ENOENT;
        } catch (UnsupportedOperationException exception) {
            return ENOTSUP;
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Updates access and modification times for a tar filesystem node.
    private long updateTarPathTimes(
            TarPath tarPath,
            TimestampUpdate accessTime,
            TimestampUpdate modificationTime,
            boolean requireParentSearch) {
        @Nullable TarNode node = tarPath.node();
        if (node == null) {
            return ENOENT;
        }
        if (accessTime.omit() && modificationTime.omit()) {
            return 0;
        }
        if (tarPath.mount().readOnly()) {
            return EROFS;
        }
        if (requireParentSearch && !canSearchTarAncestors(node)) {
            return EACCES;
        }
        return 0;
    }

    /// Updates access and modification times for a virtual filesystem path.
    private long updateVirtualPathTimes(
            VirtualPath virtualPath,
            TimestampUpdate accessTime,
            TimestampUpdate modificationTime) {
        @Nullable VirtualNode node = virtualPath.node();
        return node == null ? ENOENT : updateVirtualNodeTimes(node, accessTime, modificationTime);
    }

    /// Updates access and modification times for a virtual filesystem node.
    private long updateVirtualNodeTimes(
            VirtualNode node,
            TimestampUpdate accessTime,
            TimestampUpdate modificationTime) {
        return accessTime.omit() && modificationTime.omit() ? 0 : EROFS;
    }

    /// Reads the two `timespec` updates supplied to `utimensat`.
    private TimestampUpdate @Nullable [] timestampUpdates(
            long timesAddress,
            long nowNanoseconds,
            long omitNanoseconds) {
        if (timesAddress == 0) {
            Instant now = timeSource.realtimeInstant();
            return new TimestampUpdate[]{
                    TimestampUpdate.set(FileTime.from(now)),
                    TimestampUpdate.set(FileTime.from(now))
            };
        }
        if (!memory.isBacked(timesAddress, 2L * TIMESPEC_SIZE)) {
            return null;
        }

        Instant now = timeSource.realtimeInstant();
        @Nullable TimestampUpdate accessTime = timestampUpdate(
                timesAddress,
                now,
                nowNanoseconds,
                omitNanoseconds);
        @Nullable TimestampUpdate modificationTime = timestampUpdate(
                timesAddress + TIMESPEC_SIZE,
                now,
                nowNanoseconds,
                omitNanoseconds);
        if (accessTime == null || modificationTime == null) {
            return null;
        }
        return new TimestampUpdate[]{accessTime, modificationTime};
    }

    /// Reads one `timespec` timestamp update.
    private @Nullable TimestampUpdate timestampUpdate(
            long address,
            Instant now,
            long nowNanoseconds,
            long omitNanoseconds) {
        long seconds = memory.readLong(address + TIMESPEC_SECONDS_OFFSET);
        long nanoseconds = memory.readLong(address + TIMESPEC_NANOSECONDS_OFFSET);
        if (nanoseconds == omitNanoseconds) {
            return TimestampUpdate.omitted();
        }
        if (nanoseconds == nowNanoseconds) {
            return TimestampUpdate.set(FileTime.from(now));
        }
        if (nanoseconds < 0 || nanoseconds >= NANOSECONDS_PER_SECOND) {
            return null;
        }
        try {
            return TimestampUpdate.set(FileTime.from(Instant.ofEpochSecond(seconds, nanoseconds)));
        } catch (ArithmeticException | DateTimeException exception) {
            return null;
        }
    }

    /// Describes one access-time or modification-time update.
    ///
    /// @param omit whether this timestamp should be left unchanged
    /// @param fileTime the timestamp to apply, or null when omitted
    private record TimestampUpdate(boolean omit, @Nullable FileTime fileTime) {
        /// Creates a timestamp update that leaves the existing value unchanged.
        static TimestampUpdate omitted() {
            return new TimestampUpdate(true, null);
        }

        /// Creates a timestamp update that applies a concrete value.
        static TimestampUpdate set(FileTime fileTime) {
            return new TimestampUpdate(false, fileTime);
        }
    }

    /// Opens a host file or directory below a configured filesystem mount.
    protected long openat(long directoryFileDescriptor, long pathAddress, long flags, long mode) {
        long accessMode = flags & O_ACCMODE;
        if (accessMode != O_RDONLY && accessMode != O_WRONLY && accessMode != O_RDWR) {
            return EINVAL;
        }

        @Nullable String guestPath = readGuestPath(pathAddress);
        if (guestPath == null) {
            return ENAMETOOLONG;
        }
        if (guestPath.isEmpty()) {
            return ENOENT;
        }

        if (!canResolvePathFrom(directoryFileDescriptor, guestPath)) {
            return EBADF;
        }

        @Nullable String absoluteGuestPath = absoluteGuestPath(directoryFileDescriptor, guestPath);
        if (absoluteGuestPath == null) {
            return EACCES;
        }

        boolean create = (flags & O_CREAT) != 0;
        boolean directoryOnly = (flags & O_DIRECTORY) != 0;
        if (directoryOnly && create) {
            return EINVAL;
        }

        return openMountedPath(absoluteGuestPath, flags, mode);
    }

    /// Opens an absolute guest path below its selected filesystem mount.
    protected long openMountedPath(String absoluteGuestPath, long flags, long mode) {
        @Nullable Mount filesystemMount = mountForGuestPath(absoluteGuestPath);
        if (filesystemMount instanceof TarMount tarMount) {
            return openTarPath(tarMount, absoluteGuestPath, flags, mode);
        }
        if (filesystemMount instanceof VirtualMount virtualMount) {
            return openVirtualPath(virtualMount, absoluteGuestPath, flags);
        }
        if (!(filesystemMount instanceof HostMount hostMount)) {
            return EACCES;
        }

        return openHostPath(hostMount, absoluteGuestPath, flags, mode);
    }

    /// Opens a host file or directory below a configured host filesystem mount.
    protected long openHostPath(HostMount hostMount, String absoluteGuestPath, long flags, long mode) {
        long accessMode = flags & O_ACCMODE;
        boolean readable = accessMode == O_RDONLY || accessMode == O_RDWR;
        boolean writable = accessMode == O_WRONLY || accessMode == O_RDWR;
        boolean create = (flags & O_CREAT) != 0;
        boolean truncate = (flags & O_TRUNC) != 0;
        boolean append = (flags & O_APPEND) != 0;
        boolean directoryOnly = (flags & O_DIRECTORY) != 0;
        boolean closeOnExec = (flags & O_CLOEXEC) != 0;
        boolean writeIntent = writable || create || truncate || append;

        if (hostMount.readOnly() && writeIntent) {
            return EROFS;
        }

        @Nullable Path hostFile = GuestFileSystem.resolveHostFile(absoluteGuestPath, hostMount);
        if (hostFile == null) {
            return EACCES;
        }

        boolean exists;
        try {
            exists = Files.exists(hostFile);
        } catch (SecurityException exception) {
            return EACCES;
        }
        if (!exists && !create) {
            return ENOENT;
        }
        if (exists && create && (flags & O_EXCL) != 0) {
            return EEXIST;
        }
        if ((truncate || append) && !writable) {
            return EACCES;
        }
        @Nullable GuestFileMetadata createParentMetadata = null;
        try {
            @Nullable HostMount mount = mountForHostFile(hostFile);
            if (mount == null) {
                return EACCES;
            }
            Path realMountRoot = mount.root().toRealPath();
            if (exists) {
                if (!hostFile.toRealPath().startsWith(realMountRoot)) {
                    return EACCES;
                }
                long parentAccess = accessHostParent(hostFile);
                if (parentAccess != 0) {
                    return parentAccess;
                }
            } else {
                @Nullable Path parent = hostFile.getParent();
                if (parent == null
                        || !Files.isDirectory(parent)
                        || !parent.toRealPath().startsWith(realMountRoot)) {
                    return EACCES;
                }
                long parentAccess = accessHostFile(parent, W_OK | X_OK);
                if (parentAccess != 0) {
                    return parentAccess;
                }
                createParentMetadata = hostFileMetadata(parent, true);
            }
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
        try {
            exists = Files.exists(hostFile);
            if (exists && Files.isDirectory(hostFile)) {
                if (writable || truncate || append) {
                    return EISDIR;
                }
                GuestFileMetadata metadata = hostFileMetadata(hostFile, true);
                if (!canAccess(metadata, R_OK | X_OK, true)) {
                    return EACCES;
                }
                return addOpenFile(OpenFile.hostDirectory(hostFile, absoluteGuestPath), closeOnExec);
            }
            if (directoryOnly) {
                return ENOTDIR;
            }
            if (exists && !Files.isRegularFile(hostFile)) {
                return ENODEV;
            }
            if (exists) {
                GuestFileMetadata metadata = hostFileMetadata(hostFile, false);
                if ((readable && !canAccess(metadata, R_OK, false))
                        || (writable && !canAccess(metadata, W_OK, false))) {
                    return EACCES;
                }
                if (readable && !Files.isReadable(hostFile)) {
                    return EACCES;
                }
                if (writable && !Files.isWritable(hostFile)) {
                    return EACCES;
                }
            }
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }

        try {
            Set<StandardOpenOption> options = EnumSet.noneOf(StandardOpenOption.class);
            if (readable) {
                options.add(StandardOpenOption.READ);
            }
            if (writable) {
                options.add(StandardOpenOption.WRITE);
            }
            if (create) {
                options.add(StandardOpenOption.CREATE);
            }
            if (truncate) {
                options.add(StandardOpenOption.TRUNCATE_EXISTING);
            }

            SeekableByteChannel channel = Files.newByteChannel(hostFile, options);
            if (!exists && create) {
                if (createParentMetadata == null) {
                    return EACCES;
                }
                fileMetadataStore.put(
                        hostFile,
                        new GuestFileMetadata(
                                credentials.effectiveUserId(),
                                createdEntryGroupId(createParentMetadata),
                                createdFileMode(mode)));
            }
            return addOpenFile(
                    OpenFile.hostFile(hostFile, absoluteGuestPath, channel, readable, writable, append),
                    closeOnExec);
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Opens a file or directory from a tar filesystem mount.
    protected long openTarPath(TarMount mount, String absoluteGuestPath, long flags, long mode) {
        long accessMode = flags & O_ACCMODE;
        boolean readable = accessMode == O_RDONLY || accessMode == O_RDWR;
        boolean writable = accessMode == O_WRONLY || accessMode == O_RDWR;
        boolean create = (flags & O_CREAT) != 0;
        boolean truncate = (flags & O_TRUNC) != 0;
        boolean append = (flags & O_APPEND) != 0;
        boolean directoryOnly = (flags & O_DIRECTORY) != 0;
        boolean closeOnExec = (flags & O_CLOEXEC) != 0;

        if ((truncate || append) && !writable) {
            return EACCES;
        }

        @Nullable TarPath tarPath = fileSystem.resolveTarPath(absoluteGuestPath, true);
        @Nullable TarNode node = tarPath == null ? null : tarPath.node();
        if (node == null) {
            if (create && !mount.readOnly()) {
                @Nullable TarNode parent = tarParentDirectory(mount, tarPath == null
                        ? absoluteGuestPath
                        : tarPath.guestPath());
                if (parent == null) {
                    return ENOENT;
                }
                if (!canAccessTarDirectory(parent, W_OK | X_OK)) {
                    return EACCES;
                }

                String relativePath = GuestFileSystem.relativeGuestPath(tarPath == null
                        ? absoluteGuestPath
                        : tarPath.guestPath(), mount.guestPath());
                @Nullable TarNode created = mount.fileSystem().createFile(
                        relativePath,
                        createdFileMode(mode),
                        credentials.effectiveUserId(),
                        createdEntryGroupId(parent));
                if (created == null) {
                    return ENOENT;
                }
                try {
                    SeekableByteChannel channel = mount.fileSystem().openFileChannel(created, writable || truncate || append);
                    return addOpenFile(
                            OpenFile.tarFile(created, absoluteGuestPath, channel, readable, writable, append),
                            closeOnExec);
                } catch (IOException exception) {
                    throw new RiscVException("Guest tar open syscall failed", exception);
                }
            }
            return create ? EROFS : ENOENT;
        }
        if (create && (flags & O_EXCL) != 0) {
            return EEXIST;
        }
        if (mount.readOnly() && (writable || truncate || append)) {
            return EROFS;
        }
        if (!canSearchTarAncestors(node)) {
            return EACCES;
        }
        if ((readable && !canAccess(node, R_OK))
                || ((writable || truncate || append) && !canAccess(node, W_OK))) {
            return EACCES;
        }
        if (node.isDirectory()) {
            if (!canAccess(node, X_OK)) {
                return EACCES;
            }
            return addOpenFile(OpenFile.tarDirectory(node, absoluteGuestPath), closeOnExec);
        }
        if (directoryOnly) {
            return ENOTDIR;
        }
        if (!node.isFile()) {
            return ENODEV;
        }

        try {
            SeekableByteChannel channel = mount.fileSystem().openFileChannel(node, writable || truncate || append);
            if (truncate) {
                resizeHostChannel(channel, 0);
            }
            if (append) {
                channel.position(channel.size());
            }
            return addOpenFile(
                    OpenFile.tarFile(node, absoluteGuestPath, channel, readable, writable, append),
                    closeOnExec);
        } catch (IOException exception) {
            throw new RiscVException("Guest tar open syscall failed", exception);
        }
    }

    /// Opens a read-only file or directory from a virtual filesystem.
    protected long openVirtualPath(VirtualMount mount, String absoluteGuestPath, long flags) {
        long accessMode = flags & O_ACCMODE;
        boolean readable = accessMode == O_RDONLY || accessMode == O_RDWR;
        boolean writable = accessMode == O_WRONLY || accessMode == O_RDWR;
        boolean create = (flags & O_CREAT) != 0;
        boolean truncate = (flags & O_TRUNC) != 0;
        boolean append = (flags & O_APPEND) != 0;
        boolean directoryOnly = (flags & O_DIRECTORY) != 0;
        boolean closeOnExec = (flags & O_CLOEXEC) != 0;

        @Nullable VirtualPath virtualPath = resolveVirtualPath(mount, absoluteGuestPath, true);
        @Nullable VirtualNode node = virtualPath == null ? null : virtualPath.node();
        if (node == null) {
            return create ? EROFS : ENOENT;
        }
        if (create && (flags & O_EXCL) != 0) {
            return EEXIST;
        }
        if (node.isCharacterDevice()) {
            if ((readable && !canAccess(node, R_OK)) || (writable && !canAccess(node, W_OK))) {
                return EACCES;
            }
            return openVirtualCharacterDevice(
                    node,
                    virtualPath.mount(),
                    virtualPath.guestPath(),
                    flags,
                    readable,
                    writable);
        }
        if (writable || truncate || append) {
            return EROFS;
        }
        if (node.isDirectory()) {
            if ((readable && !canAccess(node, R_OK)) || !canAccess(node, X_OK)) {
                return EACCES;
            }
            return addOpenFile(
                    OpenFile.virtualDirectory(node, virtualPath.mount(), virtualPath.guestPath()),
                    closeOnExec);
        }
        if (node.isSymbolicLink()) {
            return openVirtualLinkTarget(virtualPath.mount(), node, flags);
        }
        if (directoryOnly) {
            return ENOTDIR;
        }
        if (!node.isFile()) {
            return ENODEV;
        }
        if (readable && !canAccess(node, R_OK)) {
            return EACCES;
        }

        return addOpenFile(OpenFile.virtualFile(
                node,
                virtualPath.mount(),
                virtualPath.guestPath(),
                new ByteArraySeekableByteChannel(virtualPath.mount().fileSystem().fileData(node)),
                true), closeOnExec);
    }

    /// Opens one virtual character device node.
    protected long openVirtualCharacterDevice(
            VirtualNode node,
            VirtualMount mount,
            String guestPath,
            long flags,
            boolean readable,
            boolean writable) {
        if ((flags & O_DIRECTORY) != 0) {
            return ENOTDIR;
        }

        Object fileKey = node.fileKey();
        if (!(fileKey instanceof DeviceFile deviceFile)) {
            return ENODEV;
        }

        boolean closeOnExec = (flags & O_CLOEXEC) != 0;
        return switch (deviceFile) {
            case NULL -> addOpenFile(OpenFile.nullDevice(node, mount, guestPath, readable, writable), closeOnExec);
            case ZERO, RANDOM, URANDOM -> addOpenFile(OpenFile.characterDevice(
                    node,
                    mount,
                    guestPath,
                    readable,
                    writable), closeOnExec);
            case FRAMEBUFFER -> framebufferDevice == null
                    ? ENODEV
                    : addOpenFile(OpenFile.characterDevice(
                            node,
                            mount,
                            guestPath,
                            readable,
                            writable), closeOnExec);
            case PTMX -> openPtyMaster(node, mount, guestPath, flags, readable, writable);
            case PTS0 -> openPtySlave(node, mount, guestPath, flags, readable, writable);
            case TTY, CONSOLE -> addOpenFile(OpenFile.terminalDevice(
                    node,
                    mount,
                    guestPath,
                    terminalDevice,
                    readable,
                    writable), closeOnExec);
        };
    }

    /// Opens `/dev/ptmx` as a new pseudoterminal master endpoint.
    protected long openPtyMaster(
            VirtualNode node,
            VirtualMount mount,
            String guestPath,
            long flags,
            boolean readable,
            boolean writable) {
        PtyDevice ptyDevice = new PtyDevice(0, this::notifyPollWaiters);
        currentPtyDevice = ptyDevice;
        return addOpenFile(OpenFile.ptyEndpoint(
                node,
                mount,
                guestPath,
                PtyEndpoint.master(ptyDevice),
                readable,
                writable,
                (flags & O_NONBLOCK) != 0), (flags & O_CLOEXEC) != 0);
    }

    /// Opens `/dev/pts/0` as the slave endpoint of the current pseudoterminal.
    protected long openPtySlave(
            VirtualNode node,
            VirtualMount mount,
            String guestPath,
            long flags,
            boolean readable,
            boolean writable) {
        @Nullable PtyDevice ptyDevice = currentPtyDevice;
        if (ptyDevice == null) {
            ptyDevice = new PtyDevice(0, this::notifyPollWaiters);
            currentPtyDevice = ptyDevice;
        }
        return addOpenFile(OpenFile.ptyEndpoint(
                node,
                mount,
                guestPath,
                PtyEndpoint.slave(ptyDevice),
                readable,
                writable,
                (flags & O_NONBLOCK) != 0), (flags & O_CLOEXEC) != 0);
    }

    /// Opens the target of a virtual symbolic link through normal guest path resolution.
    protected long openVirtualLinkTarget(VirtualMount mount, VirtualNode node, long flags) {
        String target = mount.fileSystem().linkTarget(node);
        String targetPath = target.startsWith("/")
                ? target
                : GuestFileSystem.appendGuestPath(GuestFileSystem.parentPath(node.guestPath()), target);
        @Nullable String normalizedTargetPath = normalizeAbsoluteGuestPath(targetPath);
        if (normalizedTargetPath == null) {
            return ENOENT;
        }
        if (normalizedTargetPath.equals(node.guestPath())) {
            return ELOOP;
        }
        return openMountedPath(normalizedTargetPath, flags, 0);
    }

    /// Reads bytes from guest stdin, an open host file, or a pipe endpoint into guest memory.
    protected long read(int fileDescriptor, long address, long length) {
        if (length < 0) {
            return EINVAL;
        }
        if (length > Integer.MAX_VALUE) {
            throw new RiscVException("Guest read syscall buffer is too large: " + length);
        }
        if (length == 0) {
            return 0;
        }

        try {
            @Nullable TerminalDevice terminalInput = terminalInputFor(fileDescriptor);
            if (terminalInput != null) {
                byte[] buffer = new byte[(int) length];
                int count = terminalInput.read(buffer, buffer.length, descriptorNonblocking(fileDescriptor));
                if (count == TerminalDevice.READ_WOULD_BLOCK) {
                    return EAGAIN;
                }
                memory.writeBytes(address, buffer, 0, count);
                return count;
            }

            @Nullable InputStream stream = inputStreamFor(fileDescriptor);
            if (stream != null) {
                byte[] buffer = new byte[(int) length];
                int count = stream.read(buffer);
                if (count < 0) {
                    return 0;
                }

                memory.writeBytes(address, buffer, 0, count);
                return count;
            }

            @Nullable OpenFile openFile = openFile(fileDescriptor);
            if (openFile == null || !openFile.readable()) {
                return EBADF;
            }
            if (openFile.isEventFile()) {
                return readEventFile(openFile.eventCounter(), address, length, openFile.nonblocking());
            }
            if (openFile.isTimerFile()) {
                return readTimerFile(openFile.timerFile(), address, length, openFile.nonblocking());
            }
            if (openFile.isEpollFile()) {
                return EINVAL;
            }
            if (openFile.isDirectory()) {
                return EISDIR;
            }
            if (openFile.isTerminalDevice()) {
                byte[] buffer = new byte[(int) length];
                int count = openFile.terminalDevice().read(buffer, buffer.length, openFile.nonblocking());
                if (count == TerminalDevice.READ_WOULD_BLOCK) {
                    return EAGAIN;
                }
                memory.writeBytes(address, buffer, 0, count);
                return count;
            }
            if (openFile.isPtyEndpoint()) {
                byte[] buffer = new byte[(int) length];
                int count = openFile.ptyEndpoint().read(buffer, buffer.length, openFile.nonblocking());
                if (count < 0) {
                    return count;
                }
                memory.writeBytes(address, buffer, 0, count);
                return count;
            }
            @Nullable DeviceFile deviceFile = deviceFileFor(openFile);
            if (deviceFile != null) {
                if (deviceFile == DeviceFile.FRAMEBUFFER) {
                    return readFramebufferDevice(openFile, address, length);
                }
                return readDeviceFile(deviceFile, address, length);
            }

            byte[] buffer = new byte[(int) length];
            int count;
            if (openFile.isPipeReader()) {
                count = openFile.pipe().read(buffer, buffer.length, openFile.nonblocking());
                if (count < 0) {
                    return EAGAIN;
                }
            } else if (openFile.isHostFile()) {
                count = openFile.channel().read(ByteBuffer.wrap(buffer));
            } else {
                return EBADF;
            }
            if (count < 0) {
                return 0;
            }

            memory.writeBytes(address, buffer, 0, count);
            return count;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return EINTR;
        } catch (IOException exception) {
            throw new RiscVException("Guest read syscall failed", exception);
        }
    }

    /// Writes guest memory bytes to stdout, stderr, an open host file, or a pipe endpoint.
    protected long write(int fileDescriptor, long address, long length) {
        if (length < 0) {
            return EINVAL;
        }
        if (length == 0) {
            return 0;
        }

        try {
            @Nullable TerminalDevice terminalOutput = terminalOutputFor(fileDescriptor);
            if (terminalOutput != null) {
                byte[] bytes = memory.readBytes(address, length);
                terminalOutput.write(bytes, bytes.length);
                return bytes.length;
            }

            OutputStream stream = outputStreamFor(fileDescriptor);
            if (stream != null) {
                byte[] bytes = memory.readBytes(address, length);
                stream.write(bytes);
                stream.flush();
            } else {
                @Nullable OpenFile openFile = openFile(fileDescriptor);
                if (openFile == null || !openFile.writable()) {
                    return EBADF;
                }
                if (openFile.isEventFile()) {
                    return writeEventFile(openFile.eventCounter(), address, length, openFile.nonblocking());
                }
                if (openFile.isTimerFile()) {
                    return EINVAL;
                }
                if (openFile.isEpollFile()) {
                    return EINVAL;
                }
                byte[] bytes = memory.readBytes(address, length);
                @Nullable DeviceFile deviceFile = deviceFileFor(openFile);
                if (deviceFile == DeviceFile.FRAMEBUFFER) {
                    return writeFramebufferDevice(openFile, bytes);
                }
                if (isDiscardingDeviceFile(openFile)) {
                    return bytes.length;
                }
                long count = writeOpenFile(openFile, bytes);
                if (count < 0) {
                    return count;
                }
                return bytes.length;
            }
            return length;
        } catch (IOException exception) {
            throw new RiscVException("Guest write syscall failed", exception);
        }
    }

    /// Reads bytes from guest stdin, an open host file, or a pipe endpoint into a guest `struct iovec` array.
    protected long readv(int fileDescriptor, long iovecAddress, long iovecCount) {
        if (iovecCount < 0 || iovecCount > IOV_MAX) {
            return EINVAL;
        }
        if (!isBackedIovecArray(iovecAddress, iovecCount)) {
            return EFAULT;
        }
        if (inputStreamFor(fileDescriptor) == null) {
            @Nullable OpenFile openFile = openFile(fileDescriptor);
            if (openFile == null || !openFile.readable()) {
                return EBADF;
            }
        }

        long total = 0;
        for (long index = 0; index < iovecCount; index++) {
            long entryAddress = iovecAddress + index * IOVEC_SIZE;
            long baseAddress = memory.readLong(entryAddress + IOVEC_BASE_OFFSET);
            long length = memory.readLong(entryAddress + IOVEC_LENGTH_OFFSET);
            if (length < 0) {
                return EINVAL;
            }
            if (length > Integer.MAX_VALUE) {
                throw new RiscVException("Guest readv syscall buffer is too large: " + length);
            }
            if (length == 0) {
                continue;
            }

            long count = read(fileDescriptor, baseAddress, length);
            if (count < 0) {
                return count;
            }

            total += count;
            if (count < length) {
                return total;
            }
        }
        return total;
    }

    /// Writes buffers from a guest `struct iovec` array to stdout, stderr, an open host file, or a pipe endpoint.
    protected long writev(int fileDescriptor, long iovecAddress, long iovecCount) {
        if (iovecCount < 0 || iovecCount > IOV_MAX) {
            return EINVAL;
        }
        if (!isBackedIovecArray(iovecAddress, iovecCount)) {
            return EFAULT;
        }

        if (outputStreamFor(fileDescriptor) == null) {
            @Nullable OpenFile openFile = openFile(fileDescriptor);
            if (openFile == null || !openFile.writable()) {
                return EBADF;
            }
        }

        long total = 0;
        for (long index = 0; index < iovecCount; index++) {
            long entryAddress = iovecAddress + index * IOVEC_SIZE;
            long baseAddress = memory.readLong(entryAddress + IOVEC_BASE_OFFSET);
            long length = memory.readLong(entryAddress + IOVEC_LENGTH_OFFSET);
            if (length < 0) {
                return EINVAL;
            }
            if (length > Integer.MAX_VALUE) {
                throw new RiscVException("Guest writev syscall buffer is too large: " + length);
            }

            long count = write(fileDescriptor, baseAddress, length);
            if (count < 0) {
                return total == 0 ? count : total;
            }
            total += count;
            if (count < length) {
                return total;
            }
        }
        return total;
    }

    /// Reads bytes from a host file at a fixed offset without changing the descriptor offset.
    protected long pread64(int fileDescriptor, long address, long length, long offset) {
        if (length < 0 || offset < 0) {
            return EINVAL;
        }
        if (length > Integer.MAX_VALUE) {
            throw new RiscVException("Guest pread64 syscall buffer is too large: " + length);
        }
        if (length == 0) {
            return 0;
        }
        if (standardFileDescriptorFor(fileDescriptor) >= 0) {
            return ESPIPE;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null || !openFile.readable()) {
            return EBADF;
        }
        if (openFile.isDirectory()) {
            return EISDIR;
        }
        if (!openFile.isHostFile()) {
            return ESPIPE;
        }

        try {
            byte[] buffer = new byte[(int) length];
            int count = readHostFileAt(openFile.channel(), offset, ByteBuffer.wrap(buffer));
            if (count < 0) {
                return 0;
            }

            memory.writeBytes(address, buffer, 0, count);
            return count;
        } catch (IOException exception) {
            throw new RiscVException("Guest pread64 syscall failed", exception);
        }
    }

    /// Writes guest memory bytes to a host file at a fixed offset without changing the descriptor offset.
    protected long pwrite64(int fileDescriptor, long address, long length, long offset) {
        if (length < 0 || offset < 0) {
            return EINVAL;
        }
        if (length > Integer.MAX_VALUE) {
            throw new RiscVException("Guest pwrite64 syscall buffer is too large: " + length);
        }
        if (length == 0) {
            return 0;
        }
        if (standardFileDescriptorFor(fileDescriptor) >= 0) {
            return fileDescriptor == 0 ? EBADF : ESPIPE;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null || !openFile.writable()) {
            return EBADF;
        }
        if (openFile.isDirectory()) {
            return EISDIR;
        }
        if (!openFile.isHostFile()) {
            return ESPIPE;
        }

        try {
            return writeHostFileAt(openFile, memory.readBytes(address, length), offset);
        } catch (IOException exception) {
            throw new RiscVException("Guest pwrite64 syscall failed", exception);
        }
    }

    /// Reads guest `struct iovec` buffers from a seekable file at a fixed offset.
    protected long preadv(int fileDescriptor, long iovecAddress, long iovecCount, long offset) {
        if (offset < 0) {
            return EINVAL;
        }
        return preadv2(fileDescriptor, iovecAddress, iovecCount, offset, 0);
    }

    /// Writes guest `struct iovec` buffers to a seekable file at a fixed offset.
    protected long pwritev(int fileDescriptor, long iovecAddress, long iovecCount, long offset) {
        if (offset < 0) {
            return EINVAL;
        }
        return pwritev2(fileDescriptor, iovecAddress, iovecCount, offset, 0);
    }

    /// Reads guest `struct iovec` buffers using Linux `preadv2` semantics.
    protected long preadv2(int fileDescriptor, long iovecAddress, long iovecCount, long offset, long flags) {
        if (flags != 0) {
            return ENOTSUP;
        }
        if (offset < -1) {
            return EINVAL;
        }
        if (iovecCount < 0 || iovecCount > IOV_MAX) {
            return EINVAL;
        }
        if (!isBackedIovecArray(iovecAddress, iovecCount)) {
            return EFAULT;
        }
        if (standardFileDescriptorFor(fileDescriptor) >= 0) {
            return ESPIPE;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null || !openFile.readable()) {
            return EBADF;
        }
        if (openFile.isDirectory()) {
            return EISDIR;
        }
        if (!openFile.isHostFile()) {
            return ESPIPE;
        }

        try {
            long currentOffset = offset;
            long total = 0;
            for (long index = 0; index < iovecCount; index++) {
                long entryAddress = iovecAddress + index * IOVEC_SIZE;
                long baseAddress = memory.readLong(entryAddress + IOVEC_BASE_OFFSET);
                long length = memory.readLong(entryAddress + IOVEC_LENGTH_OFFSET);
                if (length < 0) {
                    return EINVAL;
                }
                if (length > Integer.MAX_VALUE) {
                    throw new RiscVException("Guest preadv2 iovec is too large: " + length);
                }
                if (length == 0) {
                    continue;
                }
                if (!memory.isBacked(baseAddress, length)) {
                    return EFAULT;
                }

                byte[] buffer = new byte[(int) length];
                ByteBuffer byteBuffer = ByteBuffer.wrap(buffer);
                int count = currentOffset == -1
                        ? openFile.channel().read(byteBuffer)
                        : readHostFileAt(openFile.channel(), currentOffset, byteBuffer);
                if (count < 0) {
                    return total;
                }

                memory.writeBytes(baseAddress, buffer, 0, count);
                total += count;
                if (currentOffset != -1) {
                    currentOffset += count;
                }
                if (count < length) {
                    return total;
                }
            }
            return total;
        } catch (IOException exception) {
            throw new RiscVException("Guest preadv2 syscall failed", exception);
        }
    }

    /// Writes guest `struct iovec` buffers using Linux `pwritev2` semantics.
    protected long pwritev2(int fileDescriptor, long iovecAddress, long iovecCount, long offset, long flags) {
        if (flags != 0) {
            return ENOTSUP;
        }
        if (offset < -1) {
            return EINVAL;
        }
        if (iovecCount < 0 || iovecCount > IOV_MAX) {
            return EINVAL;
        }
        if (!isBackedIovecArray(iovecAddress, iovecCount)) {
            return EFAULT;
        }
        if (standardFileDescriptorFor(fileDescriptor) >= 0) {
            return fileDescriptor == 0 ? EBADF : ESPIPE;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null || !openFile.writable()) {
            return EBADF;
        }
        if (openFile.isDirectory()) {
            return EISDIR;
        }
        if (!openFile.isHostFile()) {
            return ESPIPE;
        }

        try {
            long currentOffset = offset;
            long total = 0;
            for (long index = 0; index < iovecCount; index++) {
                long entryAddress = iovecAddress + index * IOVEC_SIZE;
                long baseAddress = memory.readLong(entryAddress + IOVEC_BASE_OFFSET);
                long length = memory.readLong(entryAddress + IOVEC_LENGTH_OFFSET);
                if (length < 0) {
                    return EINVAL;
                }
                if (length > Integer.MAX_VALUE) {
                    throw new RiscVException("Guest pwritev2 iovec is too large: " + length);
                }
                if (length == 0) {
                    continue;
                }
                if (!memory.isBacked(baseAddress, length)) {
                    return EFAULT;
                }

                byte[] bytes = memory.readBytes(baseAddress, length);
                long count = currentOffset == -1
                        ? writeOpenFile(openFile, bytes)
                        : writeHostFileAt(openFile, bytes, currentOffset);
                total += count;
                if (currentOffset != -1) {
                    currentOffset += count;
                }
                if (count < length) {
                    return total;
                }
            }
            return total;
        } catch (IOException exception) {
            throw new RiscVException("Guest pwritev2 syscall failed", exception);
        }
    }

    /// Returns true when a validated-count guest `struct iovec` array can be read completely.
    protected boolean isBackedIovecArray(long iovecAddress, long iovecCount) {
        return iovecCount == 0 || memory.isBacked(iovecAddress, iovecCount * IOVEC_SIZE);
    }

    /// Copies a byte range between regular files using Linux-compatible offset semantics.
    protected long copyFileRange(
            int inputFileDescriptor,
            long inputOffsetAddress,
            int outputFileDescriptor,
            long outputOffsetAddress,
            long length,
            long flags) {
        if (flags != 0) {
            return EINVAL;
        }
        if (!isOpenFileDescriptor(inputFileDescriptor)
                || !isOpenFileDescriptor(outputFileDescriptor)) {
            return EBADF;
        }

        long inputStatusFlags = statusFlagsFor(inputFileDescriptor);
        long outputStatusFlags = statusFlagsFor(outputFileDescriptor);
        if ((inputStatusFlags & O_ACCMODE) == O_WRONLY
                || (outputStatusFlags & O_ACCMODE) == O_RDONLY
                || (outputStatusFlags & O_APPEND) != 0) {
            return EBADF;
        }

        @Nullable OpenFile inputFile = openFile(inputFileDescriptor);
        @Nullable OpenFile outputFile = openFile(outputFileDescriptor);
        if (inputFile != null && inputFile.isDirectory()
                || outputFile != null && outputFile.isDirectory()) {
            return EISDIR;
        }
        if (inputFile == null || outputFile == null
                || !inputFile.isHostFile() || !outputFile.isHostFile()
                || inputFile.isCharacterDevice() || outputFile.isCharacterDevice()) {
            return EINVAL;
        }

        long inputOffset;
        if (inputOffsetAddress == 0) {
            try {
                inputOffset = inputFile.channel().position();
            } catch (IOException exception) {
                throw new RiscVException("Guest copy_file_range input offset query failed", exception);
            }
        } else {
            if (!memory.isBacked(inputOffsetAddress, Long.BYTES)) {
                return EFAULT;
            }
            inputOffset = memory.readLong(inputOffsetAddress);
        }

        long outputOffset;
        if (outputOffsetAddress == 0) {
            try {
                outputOffset = outputFile.channel().position();
            } catch (IOException exception) {
                throw new RiscVException("Guest copy_file_range output offset query failed", exception);
            }
        } else {
            if (!memory.isBacked(outputOffsetAddress, Long.BYTES)) {
                return EFAULT;
            }
            outputOffset = memory.readLong(outputOffsetAddress);
        }

        if (inputOffset < 0 || outputOffset < 0) {
            return EINVAL;
        }
        long requestedLength = length < 0 ? Long.MAX_VALUE : length;
        if (requestedLength == 0) {
            return 0;
        }

        try {
            boolean sameFile = sameRegularFile(inputFile, outputFile);
            if (inputFile == outputFile && inputOffsetAddress == 0 && outputOffsetAddress == 0
                    || sameFile && fileRangesOverlap(inputOffset, outputOffset, requestedLength)) {
                return EINVAL;
            }

            byte[] buffer = new byte[(int) Math.min(requestedLength, FILE_COPY_BUFFER_SIZE)];
            long total = 0;
            while (total < requestedLength) {
                int requested = (int) Math.min(buffer.length, requestedLength - total);
                ByteBuffer inputBuffer = ByteBuffer.wrap(buffer, 0, requested);
                int readCount = inputOffsetAddress == 0
                        ? inputFile.channel().read(inputBuffer)
                        : readHostFileAt(inputFile.channel(), inputOffset, inputBuffer);
                if (readCount <= 0) {
                    return total;
                }

                long written = writeCopyFileRangeChunk(
                        outputFile,
                        outputOffsetAddress,
                        outputOffset,
                        buffer,
                        readCount);
                if (written <= 0) {
                    return total;
                }

                total += written;
                if (inputOffsetAddress != 0) {
                    inputOffset = addFileOffset(inputOffset, written);
                    if (inputOffset < 0) {
                        return total == written ? EOVERFLOW : total;
                    }
                    memory.writeLong(inputOffsetAddress, inputOffset);
                }
                if (outputOffsetAddress != 0) {
                    outputOffset = addFileOffset(outputOffset, written);
                    if (outputOffset < 0) {
                        return total == written ? EOVERFLOW : total;
                    }
                    memory.writeLong(outputOffsetAddress, outputOffset);
                }
                if (written < readCount || readCount < requested) {
                    return total;
                }
            }
            return total;
        } catch (IOException exception) {
            throw new RiscVException("Guest copy_file_range syscall failed", exception);
        }
    }

    /// Returns true when two open regular-file descriptions refer to the same underlying file.
    protected static boolean sameRegularFile(OpenFile first, OpenFile second) throws IOException {
        if (first == second) {
            return true;
        }
        @Nullable Path firstPath = first.path();
        @Nullable Path secondPath = second.path();
        if (firstPath != null && secondPath != null) {
            return Files.isSameFile(firstPath, secondPath);
        }
        if (first.tarNode() != null && first.tarNode() == second.tarNode()) {
            return true;
        }
        return first.virtualNode() != null
                && first.virtualNode() == second.virtualNode()
                && first.virtualMount() == second.virtualMount();
    }

    /// Returns true when two nonnegative, equal-length file ranges overlap.
    protected static boolean fileRangesOverlap(long firstOffset, long secondOffset, long length) {
        return firstOffset <= secondOffset
                ? secondOffset - firstOffset < length
                : firstOffset - secondOffset < length;
    }

    /// Adds a copied byte count to a nonnegative file offset, returning `-1` on overflow.
    protected static long addFileOffset(long offset, long count) {
        return offset > Long.MAX_VALUE - count ? -1 : offset + count;
    }

    /// Writes one copied chunk at either the current or an explicitly supplied output offset.
    protected static long writeCopyFileRangeChunk(
            OpenFile outputFile,
            long outputOffsetAddress,
            long outputOffset,
            byte[] buffer,
            int length) throws IOException {
        SeekableByteChannel channel = outputFile.channel();
        long originalPosition = channel.position();
        try {
            if (outputOffsetAddress != 0) {
                channel.position(outputOffset);
            }
            ByteBuffer outputBuffer = ByteBuffer.wrap(buffer, 0, length);
            long written = 0;
            while (outputBuffer.hasRemaining()) {
                int count = channel.write(outputBuffer);
                if (count <= 0) {
                    return written;
                }
                written += count;
            }
            return written;
        } finally {
            if (outputOffsetAddress != 0) {
                channel.position(originalPosition);
            }
        }
    }

    /// Copies bytes between two descriptors for Linux `splice`.
    protected long splice(
            int inputFileDescriptor,
            long inputOffsetAddress,
            int outputFileDescriptor,
            long outputOffsetAddress,
            long length,
            long flags) {
        if (length < 0 || (flags & ~SUPPORTED_SPLICE_FLAGS) != 0) {
            return EINVAL;
        }
        if (length == 0) {
            return 0;
        }

        long inputOffset = 0;
        if (inputOffsetAddress != 0) {
            if (!memory.isBacked(inputOffsetAddress, Long.BYTES)) {
                return EFAULT;
            }
            inputOffset = memory.readLong(inputOffsetAddress);
            if (inputOffset < 0) {
                return EINVAL;
            }
        }

        long outputOffset = 0;
        if (outputOffsetAddress != 0) {
            if (!memory.isBacked(outputOffsetAddress, Long.BYTES)) {
                return EFAULT;
            }
            outputOffset = memory.readLong(outputOffsetAddress);
            if (outputOffset < 0) {
                return EINVAL;
            }
        }

        byte[] buffer = new byte[(int) Math.min(length, SPLICE_BUFFER_SIZE)];
        boolean nonblocking = (flags & SPLICE_F_NONBLOCK) != 0;
        long total = 0;
        try {
            while (total < length) {
                int requested = (int) Math.min(buffer.length, length - total);
                long readCount = readSpliceInput(
                        inputFileDescriptor,
                        inputOffsetAddress,
                        inputOffset,
                        buffer,
                        requested,
                        nonblocking);
                if (readCount < 0) {
                    return total == 0 ? readCount : total;
                }
                if (readCount == 0) {
                    return total;
                }

                long writeCount = writeSpliceOutput(
                        outputFileDescriptor,
                        outputOffsetAddress,
                        outputOffset,
                        buffer,
                        (int) readCount);
                if (writeCount < 0) {
                    return total == 0 ? writeCount : total;
                }
                if (writeCount == 0) {
                    return total;
                }

                if (inputOffsetAddress != 0) {
                    inputOffset += readCount;
                    memory.writeLong(inputOffsetAddress, inputOffset);
                }
                if (outputOffsetAddress != 0) {
                    outputOffset += writeCount;
                    memory.writeLong(outputOffsetAddress, outputOffset);
                }

                total += writeCount;
                if (writeCount < readCount) {
                    return total;
                }
                if (readCount < requested) {
                    return total;
                }
            }
            return total;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return EINTR;
        } catch (IOException exception) {
            throw new RiscVException("Guest splice syscall failed", exception);
        }
    }

    /// Reads a `splice` chunk from a standard stream, pipe, or seekable guest file.
    protected long readSpliceInput(
            int fileDescriptor,
            long offsetAddress,
            long offset,
            byte[] buffer,
            int length,
            boolean nonblocking) throws IOException, InterruptedException {
        @Nullable TerminalDevice terminalInput = terminalInputFor(fileDescriptor);
        if (terminalInput != null) {
            if (offsetAddress != 0) {
                return ESPIPE;
            }
            int count = terminalInput.read(buffer, length, nonblocking || descriptorNonblocking(fileDescriptor));
            return count == TerminalDevice.READ_WOULD_BLOCK ? EAGAIN : count;
        }

        @Nullable InputStream stream = inputStreamFor(fileDescriptor);
        if (stream != null) {
            if (offsetAddress != 0) {
                return ESPIPE;
            }
            int count = stream.read(buffer, 0, length);
            return count < 0 ? 0 : count;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null || !openFile.readable()) {
            return EBADF;
        }
        if (openFile.isDirectory()) {
            return EISDIR;
        }
        if (openFile.isEventFile() || openFile.isEpollFile()) {
            return EINVAL;
        }
        if (openFile.isTerminalDevice()) {
            if (offsetAddress != 0) {
                return ESPIPE;
            }
            int count = openFile.terminalDevice().read(buffer, length, nonblocking || openFile.nonblocking());
            return count == TerminalDevice.READ_WOULD_BLOCK ? EAGAIN : count;
        }
        if (openFile.isPtyEndpoint()) {
            if (offsetAddress != 0) {
                return ESPIPE;
            }
            return openFile.ptyEndpoint().read(buffer, length, nonblocking || openFile.nonblocking());
        }
        @Nullable DeviceFile deviceFile = deviceFileFor(openFile);
        if (deviceFile != null) {
            if (offsetAddress != 0) {
                return ESPIPE;
            }
            return readDeviceFile(deviceFile, buffer, length);
        }
        if (openFile.isPipeReader()) {
            if (offsetAddress != 0) {
                return ESPIPE;
            }
            return openFile.pipe().read(buffer, length, openFile.nonblocking() || nonblocking);
        }
        if (!openFile.isHostFile()) {
            return EINVAL;
        }

        ByteBuffer byteBuffer = ByteBuffer.wrap(buffer, 0, length);
        int count = offsetAddress == 0
                ? openFile.channel().read(byteBuffer)
                : readHostFileAt(openFile.channel(), offset, byteBuffer);
        return count < 0 ? 0 : count;
    }

    /// Writes a `splice` chunk to a standard stream, pipe, or seekable guest file.
    protected long writeSpliceOutput(
            int fileDescriptor,
            long offsetAddress,
            long offset,
            byte[] buffer,
            int length) throws IOException {
        @Nullable OutputStream stream = outputStreamFor(fileDescriptor);
        if (stream != null) {
            if (offsetAddress != 0) {
                return ESPIPE;
            }
            stream.write(buffer, 0, length);
            stream.flush();
            return length;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null || !openFile.writable()) {
            return EBADF;
        }
        if (openFile.isDirectory()) {
            return EISDIR;
        }
        if (openFile.isEventFile() || openFile.isEpollFile()) {
            return EINVAL;
        }
        if (openFile.isTerminalDevice()) {
            if (offsetAddress != 0) {
                return ESPIPE;
            }
            openFile.terminalDevice().write(buffer, length);
            return length;
        }
        if (openFile.isPtyEndpoint()) {
            if (offsetAddress != 0) {
                return ESPIPE;
            }
            return openFile.ptyEndpoint().write(copyBufferPrefix(buffer, length));
        }
        if (isDiscardingDeviceFile(openFile)) {
            if (offsetAddress != 0) {
                return ESPIPE;
            }
            return length;
        }
        if (openFile.isPipeWriter()) {
            if (offsetAddress != 0) {
                return ESPIPE;
            }
            return openFile.pipe().write(copyBufferPrefix(buffer, length));
        }
        if (!openFile.isHostFile()) {
            return EINVAL;
        }

        SeekableByteChannel channel = openFile.channel();
        long position = channel.position();
        try {
            if (offsetAddress != 0) {
                channel.position(openFile.append() ? channel.size() : offset);
            } else if (openFile.append()) {
                channel.position(channel.size());
            }

            ByteBuffer byteBuffer = ByteBuffer.wrap(buffer, 0, length);
            long written = 0;
            while (byteBuffer.hasRemaining()) {
                int count = channel.write(byteBuffer);
                if (count <= 0) {
                    return written;
                }
                written += count;
            }
            return written;
        } finally {
            if (offsetAddress != 0) {
                channel.position(position);
            }
        }
    }

    /// Copies the populated prefix of a reusable transfer buffer.
    protected static byte[] copyBufferPrefix(byte[] buffer, int length) {
        byte[] copy = new byte[length];
        System.arraycopy(buffer, 0, copy, 0, length);
        return copy;
    }

    /// Writes all bytes to an open host file or pipe endpoint.
    protected static long writeOpenFile(OpenFile openFile, byte[] bytes) throws IOException {
        if (openFile.isTerminalDevice()) {
            openFile.terminalDevice().write(bytes, bytes.length);
            return bytes.length;
        }
        if (openFile.isPtyEndpoint()) {
            return openFile.ptyEndpoint().write(bytes);
        }
        if (isDiscardingDeviceFile(openFile)) {
            return bytes.length;
        }
        if (openFile.isPipeWriter()) {
            return openFile.pipe().write(bytes);
        }
        if (openFile.append()) {
            openFile.channel().position(openFile.channel().size());
        }

        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) {
            openFile.channel().write(buffer);
        }
        return bytes.length;
    }

    /// Reads bytes from the configured framebuffer device using the descriptor's current offset.
    protected long readFramebufferDevice(OpenFile openFile, long address, long length) {
        @Nullable FramebufferDevice device = framebufferDevice;
        if (device == null) {
            return ENODEV;
        }
        if (length > Integer.MAX_VALUE) {
            throw new RiscVException("Guest framebuffer read buffer is too large: " + length);
        }

        byte[] bytes = new byte[(int) length];
        int count = device.read(openFile.deviceOffset(), bytes, 0, bytes.length);
        openFile.advanceDeviceOffset(count);
        memory.writeBytes(address, bytes, 0, count);
        return count;
    }

    /// Writes bytes to the configured framebuffer device using the descriptor's current offset.
    protected long writeFramebufferDevice(OpenFile openFile, byte[] bytes) {
        @Nullable FramebufferDevice device = framebufferDevice;
        if (device == null) {
            return ENODEV;
        }

        int count = device.write(openFile.deviceOffset(), bytes, 0, bytes.length);
        openFile.advanceDeviceOffset(count);
        return count;
    }

    /// Reads from one built-in virtual character device into guest memory.
    protected long readDeviceFile(DeviceFile deviceFile, long address, long length) {
        return switch (deviceFile) {
            case NULL -> 0;
            case ZERO -> {
                memory.clear(address, length);
                yield length;
            }
            case RANDOM, URANDOM -> writeDeterministicRandomBytes(address, length);
            case FRAMEBUFFER -> EINVAL;
            case TTY, CONSOLE, PTMX, PTS0 -> EBADF;
        };
    }

    /// Reads from one built-in virtual character device into a host transfer buffer.
    protected long readDeviceFile(DeviceFile deviceFile, byte[] buffer, int length) {
        return switch (deviceFile) {
            case NULL -> 0;
            case ZERO -> {
                Arrays.fill(buffer, 0, length, (byte) 0);
                yield length;
            }
            case RANDOM, URANDOM -> {
                fillDeterministicRandomBytes(buffer, 0, length);
                yield length;
            }
            case FRAMEBUFFER -> EINVAL;
            case TTY, CONSOLE, PTMX, PTS0 -> EBADF;
        };
    }

    /// Returns true when writes to a built-in character device are accepted and discarded.
    protected static boolean isDiscardingDeviceFile(OpenFile openFile) {
        @Nullable DeviceFile deviceFile = deviceFileFor(openFile);
        return deviceFile == DeviceFile.NULL
                || deviceFile == DeviceFile.ZERO
                || deviceFile == DeviceFile.RANDOM
                || deviceFile == DeviceFile.URANDOM;
    }

    /// Returns the built-in virtual device file for an open descriptor entry.
    protected static @Nullable DeviceFile deviceFileFor(OpenFile openFile) {
        @Nullable VirtualNode node = openFile.virtualNode();
        return node == null ? null : deviceFileFor(node);
    }

    /// Returns the built-in virtual device file for a virtual filesystem node.
    protected static @Nullable DeviceFile deviceFileFor(VirtualNode node) {
        if (!node.isCharacterDevice()) {
            return null;
        }
        Object fileKey = node.fileKey();
        return fileKey instanceof DeviceFile deviceFile ? deviceFile : null;
    }

    /// Reads one little-endian counter value from an `eventfd` descriptor.
    protected long readEventFile(EventCounter counter, long address, long length, boolean nonblocking) {
        if (length < Long.BYTES) {
            return EINVAL;
        }

        try {
            EventReadResult result = counter.read(nonblocking);
            if (result.error() != 0) {
                return result.error();
            }
            writeLongUnaligned(address, result.value());
            return Long.BYTES;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return EINTR;
        }
    }

    /// Writes one little-endian counter increment to an `eventfd` descriptor.
    protected long writeEventFile(EventCounter counter, long address, long length, boolean nonblocking) {
        if (length != Long.BYTES) {
            return EINVAL;
        }

        try {
            long result = counter.write(readLongUnaligned(address), nonblocking);
            return result < 0 ? result : Long.BYTES;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return EINTR;
        }
    }

    /// Reads one little-endian expiration counter from a `timerfd` descriptor.
    protected long readTimerFile(TimerFile timerFile, long address, long length, boolean nonblocking) {
        if (length < Long.BYTES) {
            return EINVAL;
        }

        try {
            long result = timerFile.read(nonblocking);
            if (result < 0) {
                return result;
            }
            writeLongUnaligned(address, result);
            return Long.BYTES;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return EINTR;
        }
    }

    /// Computes the currently ready low-level `epoll` event bits for one guest descriptor.
    protected int readyEventsFor(int fileDescriptor) {
        return readyEventsFor(fileDescriptor, false);
    }

    /// Computes the currently ready low-level `epoll` event bits for one guest descriptor.
    protected int readyEventsFor(int fileDescriptor, boolean requireImmediateTerminalInput) {
        int standardFileDescriptor = standardFileDescriptorFor(fileDescriptor);
        if (standardFileDescriptor == 0) {
            if (!requireImmediateTerminalInput || !terminalDevice.supportsStandardFileDescriptors()) {
                return EPOLLIN;
            }
            return terminalDevice.hasReadableInput() ? EPOLLIN : 0;
        }
        if (standardFileDescriptor == 1 || standardFileDescriptor == 2) {
            return EPOLLOUT;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EPOLLHUP;
        }
        if (openFile.isProcessFile()) {
            ProcessFile processFile = openFile.processFile();
            if (!processFile.exited()) {
                return 0;
            }
            return processFile.reaped() ? EPOLLIN | EPOLLHUP : EPOLLIN;
        }
        if (openFile.isEventFile()) {
            EventCounter counter = openFile.eventCounter();
            int events = 0;
            if (counter.isReadable()) {
                events |= EPOLLIN;
            }
            if (counter.isWritable()) {
                events |= EPOLLOUT;
            }
            return events;
        }
        if (openFile.isTimerFile()) {
            return openFile.timerFile().isReadable() ? EPOLLIN : 0;
        }
        if (openFile.isPtyEndpoint()) {
            PtyEndpoint endpoint = openFile.ptyEndpoint();
            int events = 0;
            if (openFile.readable() && endpoint.isReadable()) {
                events |= EPOLLIN;
            }
            if (openFile.writable()) {
                events |= endpoint.isPeerReaderOpen() ? EPOLLOUT : EPOLLERR;
            }
            if (!endpoint.isPeerWriterOpen()) {
                events |= EPOLLHUP;
            }
            return events;
        }
        if (openFile.isPipeReader()) {
            int events = openFile.pipe().isReadable() ? EPOLLIN : 0;
            if (!openFile.pipe().isWriterOpen()) {
                events |= EPOLLHUP;
            }
            return events;
        }
        if (openFile.isPipeWriter()) {
            return openFile.pipe().isReaderOpen() ? EPOLLOUT : EPOLLERR;
        }
        if (openFile.isTerminalDevice() || openFile.isCharacterDevice()) {
            int events = 0;
            if (openFile.readable()) {
                if (!requireImmediateTerminalInput
                        || !openFile.isTerminalDevice()
                        || openFile.terminalDevice().hasReadableInput()) {
                    events |= EPOLLIN;
                }
            }
            if (openFile.writable()) {
                events |= EPOLLOUT;
            }
            return events;
        }
        if (openFile.isHostFile() || openFile.isDirectory()) {
            int events = 0;
            if (openFile.readable()) {
                events |= EPOLLIN;
            }
            if (openFile.writable()) {
                events |= EPOLLOUT;
            }
            return events;
        }
        return 0;
    }

    /// Writes a packed Linux generic `struct epoll_event` to guest memory.
    protected void writeEpollEvent(long eventAddress, int events, long data) {
        memory.writeInt(eventAddress + EPOLL_EVENT_EVENTS_OFFSET, events);
        writeLongUnaligned(eventAddress + EPOLL_EVENT_DATA_OFFSET, data);
    }

    /// Reads bytes at a fixed host file offset while preserving the channel position.
    protected static int readHostFileAt(SeekableByteChannel channel, long offset, ByteBuffer buffer) throws IOException {
        long position = channel.position();
        try {
            channel.position(offset);
            return channel.read(buffer);
        } finally {
            channel.position(position);
        }
    }

    /// Writes bytes at a fixed host file offset while preserving the channel position.
    protected static long writeHostFileAt(OpenFile openFile, byte[] bytes, long offset) throws IOException {
        SeekableByteChannel channel = openFile.channel();
        long position = channel.position();
        try {
            channel.position(openFile.append() ? channel.size() : offset);
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            return bytes.length;
        } finally {
            channel.position(position);
        }
    }

    /// Handles `close` for standard streams and guest-opened file descriptors.
    protected long close(int fileDescriptor) {
        if (isStandardFileDescriptor(fileDescriptor)) {
            if (!standardFileOpen[fileDescriptor]) {
                return EBADF;
            }
            @Nullable OpenFile openFile = standardFiles[fileDescriptor];
            try {
                standardFiles[fileDescriptor] = null;
                standardFileOpen[fileDescriptor] = false;
                standardFileCloseOnExec[fileDescriptor] = false;
                setFileDescriptorCloseOnFork(fileDescriptor, false);
                if (openFile != null) {
                    releaseOpenFile(openFile);
                }
                notifyPollWaiters();
            } catch (IOException exception) {
                throw new RiscVException("Guest close syscall failed", exception);
            }
            return 0;
        }

        int index = openFileIndex(fileDescriptor);
        if (index < 0 || index >= openFiles.size()) {
            return EBADF;
        }

        @Nullable OpenFile openFile = openFiles.get(index);
        if (openFile == null) {
            return EBADF;
        }

        try {
            openFiles.set(index, null);
            setOpenFileCloseOnExec(index, false);
            setFileDescriptorCloseOnFork(fileDescriptor, false);
            releaseOpenFile(openFile);
            notifyPollWaiters();
            return 0;
        } catch (IOException exception) {
            throw new RiscVException("Guest close syscall failed", exception);
        }
    }

    /// Handles Linux `close_range` for open descriptors in the current descriptor table.
    protected long closeRange(long firstFileDescriptor, long lastFileDescriptor, long flags) {
        return closeRange(firstFileDescriptor, lastFileDescriptor, flags, SUPPORTED_CLOSE_RANGE_FLAGS);
    }

    /// Handles a descriptor range with an ABI-specific set of accepted flags.
    protected long closeRange(
            long firstFileDescriptor,
            long lastFileDescriptor,
            long flags,
            long supportedFlags) {
        long first = unsignedIntArgument(firstFileDescriptor);
        long last = unsignedIntArgument(lastFileDescriptor);
        if (first < 0 || last < 0 || first > last || (flags & ~supportedFlags) != 0) {
            return EINVAL;
        }

        boolean closeOnExec = (flags & CLOSE_RANGE_CLOEXEC) != 0;
        boolean closeOnFork = (flags & CLOSE_RANGE_CLOFORK) != 0;
        boolean closedAny = false;
        try {
            for (int fileDescriptor = 0; fileDescriptor < standardFiles.length; fileDescriptor++) {
                if (fileDescriptor < first || fileDescriptor > last || !standardFileOpen[fileDescriptor]) {
                    continue;
                }
                if (closeOnExec || closeOnFork) {
                    if (closeOnExec) {
                        standardFileCloseOnExec[fileDescriptor] = true;
                    }
                    if (closeOnFork) {
                        setFileDescriptorCloseOnFork(fileDescriptor, true);
                    }
                    continue;
                }

                @Nullable OpenFile openFile = standardFiles[fileDescriptor];
                standardFiles[fileDescriptor] = null;
                standardFileOpen[fileDescriptor] = false;
                standardFileCloseOnExec[fileDescriptor] = false;
                setFileDescriptorCloseOnFork(fileDescriptor, false);
                if (openFile != null) {
                    releaseOpenFile(openFile);
                }
                closedAny = true;
            }

            for (int index = 0; index < openFiles.size(); index++) {
                long fileDescriptor = index + 3L;
                if (fileDescriptor < first || fileDescriptor > last) {
                    continue;
                }
                @Nullable OpenFile openFile = openFiles.get(index);
                if (openFile == null) {
                    continue;
                }
                if (closeOnExec || closeOnFork) {
                    if (closeOnExec) {
                        setOpenFileCloseOnExec(index, true);
                    }
                    if (closeOnFork) {
                        setFileDescriptorCloseOnFork((int) fileDescriptor, true);
                    }
                    continue;
                }

                openFiles.set(index, null);
                setOpenFileCloseOnExec(index, false);
                setFileDescriptorCloseOnFork((int) fileDescriptor, false);
                releaseOpenFile(openFile);
                closedAny = true;
            }
            if (closedAny) {
                notifyPollWaiters();
            }
            return 0;
        } catch (IOException exception) {
            throw new RiscVException("Guest close_range syscall failed", exception);
        }
    }

    /// Interprets a syscall argument as a Linux unsigned int, accepting sign-extended values.
    protected static long unsignedIntArgument(long value) {
        if ((value & 0xffff_ffff_0000_0000L) == 0) {
            return value;
        }
        if ((value & 0xffff_ffff_0000_0000L) == 0xffff_ffff_0000_0000L) {
            return Integer.toUnsignedLong((int) value);
        }
        return -1;
    }

    /// Handles `lseek` for guest-opened host files while rejecting standard streams.
    protected long lseek(int fileDescriptor, long offset, int whence) {
        if (whence < 0 || whence > 2) {
            return EINVAL;
        }
        if (standardFileDescriptorFor(fileDescriptor) >= 0) {
            return ESPIPE;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }
        if (deviceFileFor(openFile) == DeviceFile.FRAMEBUFFER) {
            return lseekFramebufferDevice(openFile, offset, whence);
        }
        if (!openFile.isHostFile()) {
            return ESPIPE;
        }

        try {
            long basePosition = switch (whence) {
                case 0 -> 0;
                case 1 -> openFile.channel().position();
                case 2 -> openFile.channel().size();
                default -> throw new AssertionError("validated whence");
            };
            if (offset > 0 && basePosition > Long.MAX_VALUE - offset) {
                return EINVAL;
            }
            if (offset < 0 && basePosition < Long.MIN_VALUE - offset) {
                return EINVAL;
            }

            long position = basePosition + offset;
            if (position < 0) {
                return EINVAL;
            }
            openFile.channel().position(position);
            return position;
        } catch (IOException exception) {
            throw new RiscVException("Guest lseek syscall failed", exception);
        }
    }

    /// Handles `lseek` for the framebuffer character device offset.
    protected long lseekFramebufferDevice(OpenFile openFile, long offset, int whence) {
        @Nullable FramebufferDevice device = framebufferDevice;
        if (device == null) {
            return ENODEV;
        }

        long basePosition = switch (whence) {
            case 0 -> 0;
            case 1 -> openFile.deviceOffset();
            case 2 -> device.geometry().bufferSizeBytes();
            default -> throw new AssertionError("validated whence");
        };
        if (offset > 0 && basePosition > Long.MAX_VALUE - offset) {
            return EINVAL;
        }
        if (offset < 0 && basePosition < Long.MIN_VALUE - offset) {
            return EINVAL;
        }

        long position = basePosition + offset;
        if (position < 0) {
            return EINVAL;
        }
        openFile.setDeviceOffset(position);
        return position;
    }

    /// Reads a sandboxed symbolic link target into guest memory.
    protected long readlinkat(long directoryFileDescriptor, long pathAddress, long bufferAddress, long bufferSize) {
        if (bufferSize <= 0 || bufferSize > Integer.MAX_VALUE) {
            return EINVAL;
        }

        @Nullable String guestPath = readGuestPath(pathAddress);
        if (guestPath == null) {
            return ENAMETOOLONG;
        }
        if (guestPath.isEmpty()) {
            return ENOENT;
        }

        if (!canResolvePathFrom(directoryFileDescriptor, guestPath)) {
            return EBADF;
        }

        @Nullable TarPath tarPath = resolveTarPath(directoryFileDescriptor, guestPath, false);
        if (tarPath != null) {
            long access = accessTarPath(tarPath, F_OK);
            return access == 0 ? readlinkTarPath(tarPath.node(), bufferAddress, bufferSize) : access;
        }

        @Nullable VirtualPath procPath = resolveVirtualPath(directoryFileDescriptor, guestPath, false);
        if (procPath != null) {
            return readlinkVirtualPath(procPath.node(), procPath.mount(), bufferAddress, bufferSize);
        }

        @Nullable Path hostFile = resolveHostFile(directoryFileDescriptor, guestPath);
        if (hostFile == null) {
            return EACCES;
        }

        try {
            if (!pathEntryExists(hostFile)) {
                return ENOENT;
            }
            if (!Files.isSymbolicLink(hostFile)) {
                return EINVAL;
            }
            long parentAccess = accessHostParent(hostFile);
            if (parentAccess != 0) {
                return parentAccess;
            }

            String target = Files.readSymbolicLink(hostFile).toString();
            byte[] targetBytes = target.getBytes(StandardCharsets.UTF_8);
            int length = Math.min(targetBytes.length, (int) bufferSize);
            memory.writeBytes(bufferAddress, targetBytes, 0, length);
            return length;
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Reports a missing extended attribute for a mounted guest path.
    protected long getxattr(long pathAddress, long nameAddress, long valueAddress, long size, boolean followFinalSymlink) {
        long pathResult = validateXattrPath(pathAddress, followFinalSymlink);
        if (pathResult != 0) {
            return pathResult;
        }
        return getMissingXattr(nameAddress, valueAddress, size);
    }

    /// Reports a missing extended attribute for an open guest file descriptor.
    protected long fgetxattr(int fileDescriptor, long nameAddress, long valueAddress, long size) {
        if (!isOpenFileDescriptor(fileDescriptor)) {
            return EBADF;
        }
        return getMissingXattr(nameAddress, valueAddress, size);
    }

    /// Reports an empty extended-attribute list for a mounted guest path.
    protected long listxattr(long pathAddress, long listAddress, long size, boolean followFinalSymlink) {
        long pathResult = validateXattrPath(pathAddress, followFinalSymlink);
        if (pathResult != 0) {
            return pathResult;
        }
        return emptyXattrList(listAddress, size);
    }

    /// Reports an empty extended-attribute list for an open guest file descriptor.
    protected long flistxattr(int fileDescriptor, long listAddress, long size) {
        if (!isOpenFileDescriptor(fileDescriptor)) {
            return EBADF;
        }
        return emptyXattrList(listAddress, size);
    }

    /// Validates a path argument for extended-attribute queries.
    protected long validateXattrPath(long pathAddress, boolean followFinalSymlink) {
        String guestPath;
        try {
            @Nullable String path = readGuestPath(pathAddress);
            if (path == null) {
                return ENAMETOOLONG;
            }
            guestPath = path;
        } catch (RiscVException exception) {
            return EFAULT;
        }

        if (guestPath.isEmpty()) {
            return ENOENT;
        }

        @Nullable TarPath tarPath = resolveTarPath(AT_FDCWD, guestPath, followFinalSymlink);
        if (tarPath != null) {
            return accessTarPath(tarPath, F_OK);
        }

        @Nullable VirtualPath virtualPath = resolveVirtualPath(AT_FDCWD, guestPath, followFinalSymlink);
        if (virtualPath != null) {
            return virtualPath.node() == null ? ENOENT : 0;
        }

        @Nullable Path hostFile = resolveHostFile(AT_FDCWD, guestPath);
        return hostFile == null ? EACCES : accessHostFile(hostFile, F_OK);
    }

    /// Reports that the requested extended attribute does not exist.
    protected long getMissingXattr(long nameAddress, long valueAddress, long size) {
        if (size < 0) {
            return EINVAL;
        }
        try {
            @Nullable String name = readGuestPath(nameAddress);
            if (name == null) {
                return ENAMETOOLONG;
            }
        } catch (RiscVException exception) {
            return EFAULT;
        }
        return ENODATA;
    }

    /// Reports a mounted guest file with no extended attributes.
    protected static long emptyXattrList(long listAddress, long size) {
        return size < 0 ? EINVAL : 0;
    }

    /// Writes a minimal Linux generic 64-bit `struct stat` for a path or file descriptor.
    protected long newfstatat(long directoryFileDescriptor, long pathAddress, long statAddress, long flags) {
        if ((flags & ~SUPPORTED_NEWFSTATAT_FLAGS) != 0) {
            return EINVAL;
        }

        String guestPath;
        if (pathAddress == 0) {
            if ((flags & AT_EMPTY_PATH) == 0) {
                return EFAULT;
            }
            guestPath = "";
        } else {
            @Nullable String path = readGuestPath(pathAddress);
            if (path == null) {
                return ENAMETOOLONG;
            }
            guestPath = path;
        }

        if (guestPath.isEmpty()) {
            if ((flags & AT_EMPTY_PATH) == 0) {
                return ENOENT;
            }
            if (directoryFileDescriptor == AT_FDCWD) {
                @Nullable Path currentDirectory = currentHostWorkingDirectory();
                return currentDirectory == null ? EACCES : statHostFile(currentDirectory, statAddress, true);
            }
            return fstat((int) directoryFileDescriptor, statAddress);
        }

        if (!canResolvePathFrom(directoryFileDescriptor, guestPath)) {
            return EBADF;
        }

        @Nullable TarPath tarPath = resolveTarPath(
                directoryFileDescriptor,
                guestPath,
                (flags & AT_SYMLINK_NOFOLLOW) == 0);
        if (tarPath != null) {
            long access = accessTarPath(tarPath, F_OK);
            return access == 0 ? statTarNode(tarPath.node(), statAddress) : access;
        }

        @Nullable VirtualPath procPath = resolveVirtualPath(
                directoryFileDescriptor,
                guestPath,
                (flags & AT_SYMLINK_NOFOLLOW) == 0);
        if (procPath != null) {
            return statVirtualNode(procPath.node(), procPath.mount(), statAddress);
        }

        @Nullable Path hostFile = resolveHostFile(directoryFileDescriptor, guestPath);
        if (hostFile == null) {
            return EACCES;
        }
        return statHostFile(hostFile, statAddress, true, flags);
    }

    /// Writes a minimal Linux generic 64-bit `struct stat` for a file descriptor.
    protected long fstat(int fileDescriptor, long statAddress) {
        int standardFileDescriptor = standardFileDescriptorFor(fileDescriptor);
        if (standardFileDescriptor >= 0) {
            writeStat(statAddress, standardFileDescriptor + 1L, STANDARD_STREAM_STAT_MODE, 0);
            return 0;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }
        if (openFile.isPipe()) {
            int permissions = (openFile.readable() ? STAT_MODE_READ_ALL : 0)
                    | (openFile.writable() ? 0222 : 0);
            writeStat(statAddress, fileDescriptor + 1L, STAT_MODE_FIFO | permissions, 0);
            return 0;
        }
        if (openFile.isEventFile() || openFile.isEpollFile()) {
            int permissions = (openFile.readable() ? 0400 : 0) | (openFile.writable() ? 0200 : 0);
            writeStat(statAddress, fileDescriptor + 1L, STAT_MODE_REGULAR_FILE | permissions, 0);
            return 0;
        }
        if (openFile.isDirectory()) {
            @Nullable VirtualNode virtualNode = openFile.virtualNode();
            @Nullable VirtualMount virtualMount = openFile.virtualMount();
            if (virtualNode != null && virtualMount != null) {
                writeVirtualStat(virtualNode, virtualMount, statAddress);
                return 0;
            }
            @Nullable TarNode tarNode = openFile.tarNode();
            if (tarNode != null) {
                writeTarStat(tarNode, statAddress);
            } else {
                @Nullable Path path = openFile.path();
                return path == null ? EACCES : statHostFile(path, statAddress, false);
            }
            return 0;
        }
        @Nullable VirtualNode virtualNode = openFile.virtualNode();
        @Nullable VirtualMount virtualMount = openFile.virtualMount();
        if (virtualNode != null && virtualMount != null) {
            writeVirtualStat(virtualNode, virtualMount, statAddress);
            return 0;
        }
        @Nullable TarNode tarNode = openFile.tarNode();
        if (tarNode != null) {
            writeTarStat(tarNode, statAddress);
            return 0;
        }

        @Nullable Path path = openFile.path();
        return path == null ? EACCES : statHostFile(path, statAddress, false);
    }

    /// Handles Linux `sync`, which is a process-wide best-effort flush.
    protected static long sync() {
        return 0;
    }

    /// Flushes host file metadata and data for a guest file descriptor.
    protected long fsync(int fileDescriptor) {
        return syncFileDescriptor(fileDescriptor, true);
    }

    /// Flushes host file data for a guest file descriptor.
    protected long fdatasync(int fileDescriptor) {
        return syncFileDescriptor(fileDescriptor, false);
    }

    /// Flushes the sandbox filesystem referenced by a guest file descriptor.
    protected long syncfs(int fileDescriptor) {
        if (isStandardFileDescriptor(fileDescriptor)) {
            return 0;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        return openFile == null ? EBADF : 0;
    }

    /// Flushes a regular host file channel when the backing implementation supports it.
    protected long syncFileDescriptor(int fileDescriptor, boolean metadata) {
        if (isStandardFileDescriptor(fileDescriptor)) {
            return EINVAL;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }
        if (openFile.isPipe()) {
            return EINVAL;
        }
        if (openFile.isEventFile() || openFile.isEpollFile()) {
            return EINVAL;
        }
        if (openFile.isTerminalDevice() || openFile.isCharacterDevice()) {
            return EINVAL;
        }
        if (openFile.isDirectory()) {
            return 0;
        }

        try {
            SeekableByteChannel channel = openFile.channel();
            if (channel instanceof FileChannel fileChannel) {
                fileChannel.force(metadata);
            }
            return 0;
        } catch (IOException exception) {
            throw new RiscVException("Guest file sync syscall failed", exception);
        }
    }

    /// Writes a Linux generic `struct statx` for a path or file descriptor.
    protected long statx(
            long directoryFileDescriptor,
            long pathAddress,
            long flags,
            long requestedMask,
            long statxAddress) {
        if ((flags & ~SUPPORTED_STATX_FLAGS) != 0) {
            return EINVAL;
        }

        String guestPath;
        if (pathAddress == 0) {
            if ((flags & AT_EMPTY_PATH) == 0) {
                return EFAULT;
            }
            guestPath = "";
        } else {
            @Nullable String path = readGuestPath(pathAddress);
            if (path == null) {
                return ENAMETOOLONG;
            }
            guestPath = path;
        }

        if (guestPath.isEmpty()) {
            if ((flags & AT_EMPTY_PATH) == 0) {
                return ENOENT;
            }
            if (directoryFileDescriptor == AT_FDCWD) {
                @Nullable Path currentDirectory = currentHostWorkingDirectory();
                return currentDirectory == null
                        ? EACCES
                        : statxHostFile(currentDirectory, statxAddress, flags, requestedMask, true);
            }
            return statxFileDescriptor((int) directoryFileDescriptor, requestedMask, statxAddress);
        }

        if (!canResolvePathFrom(directoryFileDescriptor, guestPath)) {
            return EBADF;
        }

        @Nullable TarPath tarPath = resolveTarPath(
                directoryFileDescriptor,
                guestPath,
                (flags & AT_SYMLINK_NOFOLLOW) == 0);
        if (tarPath != null) {
            long access = accessTarPath(tarPath, F_OK);
            return access == 0 ? statxTarNode(tarPath.node(), statxAddress, flags, requestedMask) : access;
        }

        @Nullable VirtualPath procPath = resolveVirtualPath(
                directoryFileDescriptor,
                guestPath,
                (flags & AT_SYMLINK_NOFOLLOW) == 0);
        if (procPath != null) {
            return statxVirtualNode(procPath.node(), procPath.mount(), statxAddress, requestedMask);
        }

        @Nullable Path hostFile = resolveHostFile(directoryFileDescriptor, guestPath);
        if (hostFile == null) {
            return EACCES;
        }
        return statxHostFile(hostFile, statxAddress, flags, requestedMask, true);
    }

    /// Writes a Linux generic `struct statx` for a file descriptor.
    protected long statxFileDescriptor(int fileDescriptor, long requestedMask, long statxAddress) {
        int standardFileDescriptor = standardFileDescriptorFor(fileDescriptor);
        if (standardFileDescriptor >= 0) {
            writeStatx(statxAddress, standardFileDescriptor + 1L, STANDARD_STREAM_STAT_MODE, 0, requestedMask);
            return 0;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }
        if (openFile.isPipe()) {
            int permissions = (openFile.readable() ? STAT_MODE_READ_ALL : 0)
                    | (openFile.writable() ? 0222 : 0);
            writeStatx(statxAddress, fileDescriptor + 1L, STAT_MODE_FIFO | permissions, 0, requestedMask);
            return 0;
        }
        if (openFile.isEventFile() || openFile.isEpollFile()) {
            int permissions = (openFile.readable() ? 0400 : 0) | (openFile.writable() ? 0200 : 0);
            writeStatx(statxAddress, fileDescriptor + 1L, STAT_MODE_REGULAR_FILE | permissions, 0, requestedMask);
            return 0;
        }
        if (openFile.isDirectory()) {
            @Nullable VirtualNode virtualNode = openFile.virtualNode();
            @Nullable VirtualMount virtualMount = openFile.virtualMount();
            if (virtualNode != null && virtualMount != null) {
                writeVirtualStatx(virtualNode, virtualMount, statxAddress, requestedMask);
                return 0;
            }
            @Nullable TarNode tarNode = openFile.tarNode();
            if (tarNode != null) {
                writeTarStatx(tarNode, statxAddress, requestedMask);
                return 0;
            }
            @Nullable Path path = openFile.path();
            return path == null ? EACCES : statxHostFile(path, statxAddress, AT_EMPTY_PATH, requestedMask, false);
        }
        @Nullable VirtualNode virtualNode = openFile.virtualNode();
        @Nullable VirtualMount virtualMount = openFile.virtualMount();
        if (virtualNode != null && virtualMount != null) {
            writeVirtualStatx(virtualNode, virtualMount, statxAddress, requestedMask);
            return 0;
        }
        @Nullable TarNode tarNode = openFile.tarNode();
        if (tarNode != null) {
            writeTarStatx(tarNode, statxAddress, requestedMask);
            return 0;
        }

        @Nullable Path path = openFile.path();
        return path == null ? EACCES : statxHostFile(path, statxAddress, AT_EMPTY_PATH, requestedMask, false);
    }

    /// Writes a deterministic Linux generic 64-bit `struct statfs` for a sandboxed path.
    protected long statfs(long pathAddress, long statfsAddress) {
        @Nullable String guestPath = readGuestPath(pathAddress);
        if (guestPath == null) {
            return ENAMETOOLONG;
        }
        if (guestPath.isEmpty()) {
            return ENOENT;
        }

        @Nullable TarPath tarPath = resolveTarPath(AT_FDCWD, guestPath);
        if (tarPath != null) {
            long access = accessTarPath(tarPath, F_OK);
            return access == 0 ? writeStatfsResult(statfsAddress) : access;
        }

        @Nullable VirtualPath virtualPath = resolveVirtualPath(AT_FDCWD, guestPath);
        if (virtualPath != null) {
            return virtualPath.node() == null ? ENOENT : writeVirtualStatfsResult(virtualPath.mount(), statfsAddress);
        }

        @Nullable Path hostFile = resolveHostFile(AT_FDCWD, guestPath);
        if (hostFile == null) {
            return EACCES;
        }
        return statfsHostFile(hostFile, statfsAddress, true);
    }

    /// Writes a deterministic Linux generic 64-bit `struct statfs` for a file descriptor.
    protected long fstatfs(int fileDescriptor, long statfsAddress) {
        if (isStandardFileDescriptor(fileDescriptor)) {
            writeStatfs(statfsAddress);
            return 0;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return EBADF;
        }
        if (openFile.isPipe()) {
            writeStatfs(statfsAddress);
            return 0;
        }
        if (openFile.isTarEntry()) {
            writeStatfs(statfsAddress);
            return 0;
        }
        if (openFile.isVirtualEntry()) {
            @Nullable VirtualMount virtualMount = openFile.virtualMount();
            if (virtualMount == null) {
                return EBADF;
            }
            writeVirtualStatfs(virtualMount, statfsAddress);
            return 0;
        }

        @Nullable Path path = openFile.path();
        return path == null ? EACCES : statfsHostFile(path, statfsAddress, false);
    }

    /// Writes `statfs` metadata and returns a successful syscall result.
    protected long writeStatfsResult(long statfsAddress) {
        writeStatfs(statfsAddress);
        return 0;
    }

    /// Writes virtual filesystem `statfs` metadata and returns a successful syscall result.
    protected long writeVirtualStatfsResult(VirtualMount mount, long statfsAddress) {
        writeVirtualStatfs(mount, statfsAddress);
        return 0;
    }

    /// Writes deterministic filesystem metadata for an existing sandboxed host path.
    protected long statfsHostFile(Path hostFile, long statfsAddress, boolean requireParentSearch) {
        try {
            if (!pathEntryExists(hostFile)) {
                return ENOENT;
            }
            if (!canonicalFileStaysBelowMount(hostFile)) {
                return EACCES;
            }
            if (requireParentSearch) {
                long parentAccess = accessHostParent(hostFile);
                if (parentAccess != 0) {
                    return parentAccess;
                }
            }
            writeStatfs(statfsAddress);
            return 0;
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Writes a minimal Linux generic 64-bit `struct stat` for a sandboxed host file.
    protected long statHostFile(Path hostFile, long statAddress, boolean requireParentSearch) {
        return statHostFile(hostFile, statAddress, requireParentSearch, 0);
    }

    /// Writes a minimal Linux generic 64-bit `struct stat` for a sandboxed host path with `*at` flags.
    protected long statHostFile(Path hostFile, long statAddress, boolean requireParentSearch, long flags) {
        try {
            boolean noFollow = (flags & AT_SYMLINK_NOFOLLOW) != 0;
            if (noFollow ? !pathEntryExists(hostFile) : !Files.exists(hostFile)) {
                return ENOENT;
            }
            if (requireParentSearch) {
                long parentAccess = accessHostParent(hostFile);
                if (parentAccess != 0) {
                    return parentAccess;
                }
            }
            if (noFollow && Files.isSymbolicLink(hostFile)) {
                String target = Files.readSymbolicLink(hostFile).toString();
                writeStat(
                        statAddress,
                        syntheticInode(hostFile),
                        STAT_MODE_SYMBOLIC_LINK | STAT_MODE_ALL,
                        target.getBytes(StandardCharsets.UTF_8).length);
                writeHostStatTimestamps(hostFile, statAddress, true);
                return 0;
            }
            if (!canonicalFileStaysBelowMount(hostFile)) {
                return EACCES;
            }

            if (Files.isDirectory(hostFile)) {
                GuestFileMetadata metadata = hostFileMetadata(hostFile, true);
                writeStat(
                        statAddress,
                        syntheticInode(hostFile),
                        STAT_MODE_DIRECTORY | metadata.mode(),
                        0,
                        metadata.userId(),
                        metadata.groupId());
                writeHostStatTimestamps(hostFile, statAddress, false);
                return 0;
            }
            if (Files.isRegularFile(hostFile)) {
                long size = Files.size(hostFile);
                GuestFileMetadata metadata = hostFileMetadata(hostFile, false);
                writeStat(
                        statAddress,
                        syntheticInode(hostFile),
                        STAT_MODE_REGULAR_FILE | metadata.mode(),
                        size,
                        metadata.userId(),
                        metadata.groupId());
                writeHostStatTimestamps(hostFile, statAddress, false);
                return 0;
            }
            return ENODEV;
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Writes a Linux generic `struct statx` for a sandboxed host file.
    protected long statxHostFile(
            Path hostFile,
            long statxAddress,
            long flags,
            long requestedMask,
            boolean requireParentSearch) {
        try {
            if (!pathEntryExists(hostFile)) {
                return ENOENT;
            }
            if (requireParentSearch) {
                long parentAccess = accessHostParent(hostFile);
                if (parentAccess != 0) {
                    return parentAccess;
                }
            }
            if ((flags & AT_SYMLINK_NOFOLLOW) != 0 && Files.isSymbolicLink(hostFile)) {
                String target = Files.readSymbolicLink(hostFile).toString();
                long size = target.getBytes(StandardCharsets.UTF_8).length;
                writeStatx(
                        statxAddress,
                        syntheticInode(hostFile),
                        STAT_MODE_SYMBOLIC_LINK | STAT_MODE_ALL,
                        size,
                        requestedMask);
                return 0;
            }
            if (!Files.exists(hostFile)) {
                return ENOENT;
            }
            if (!canonicalFileStaysBelowMount(hostFile)) {
                return EACCES;
            }

            if (Files.isDirectory(hostFile)) {
                GuestFileMetadata metadata = hostFileMetadata(hostFile, true);
                writeStatx(
                        statxAddress,
                        syntheticInode(hostFile),
                        STAT_MODE_DIRECTORY | metadata.mode(),
                        0,
                        requestedMask,
                        metadata.userId(),
                        metadata.groupId());
                return 0;
            }
            if (Files.isRegularFile(hostFile)) {
                long size = Files.size(hostFile);
                GuestFileMetadata metadata = hostFileMetadata(hostFile, false);
                writeStatx(
                        statxAddress,
                        syntheticInode(hostFile),
                        STAT_MODE_REGULAR_FILE | metadata.mode(),
                        size,
                        requestedMask,
                        metadata.userId(),
                        metadata.groupId());
                return 0;
            }
            return ENODEV;
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Checks access bits on a tar filesystem node.
    protected long accessTarPath(TarPath tarPath, long mode) {
        @Nullable TarNode node = tarPath.node();
        if (node == null) {
            return ENOENT;
        }
        if ((mode & W_OK) != 0 && tarPath.mount().readOnly()) {
            return EACCES;
        }
        return canSearchTarAncestors(node) && canAccess(node, mode) ? 0 : EACCES;
    }

    /// Checks access bits on a tar filesystem node selected by an open file descriptor.
    protected long accessTarNode(TarPath tarPath, long mode) {
        @Nullable TarNode node = tarPath.node();
        if (node == null) {
            return ENOENT;
        }
        if ((mode & W_OK) != 0 && tarPath.mount().readOnly()) {
            return EACCES;
        }
        return canAccess(node, mode) ? 0 : EACCES;
    }

    /// Checks access bits on a virtual proc filesystem node.
    protected long accessVirtualNode(@Nullable VirtualNode node, long mode) {
        if (node == null) {
            return ENOENT;
        }
        return canAccess(node, mode) ? 0 : EACCES;
    }

    /// Reads a tar symbolic link target into guest memory.
    protected long readlinkTarPath(@Nullable TarNode node, long bufferAddress, long bufferSize) {
        if (node == null) {
            return ENOENT;
        }
        if (!node.isSymbolicLink()) {
            return EINVAL;
        }

        String target = node.linkTarget();
        byte[] targetBytes = target.getBytes(StandardCharsets.UTF_8);
        int length = Math.min(targetBytes.length, (int) bufferSize);
        memory.writeBytes(bufferAddress, targetBytes, 0, length);
        return length;
    }

    /// Reads a virtual symbolic link target into guest memory.
    protected long readlinkVirtualPath(
            @Nullable VirtualNode node,
            VirtualMount mount,
            long bufferAddress,
            long bufferSize) {
        if (node == null) {
            return ENOENT;
        }
        if (!node.isSymbolicLink()) {
            return EINVAL;
        }

        String target = mount.fileSystem().linkTarget(node);
        byte[] targetBytes = target.getBytes(StandardCharsets.UTF_8);
        int length = Math.min(targetBytes.length, (int) bufferSize);
        memory.writeBytes(bufferAddress, targetBytes, 0, length);
        return length;
    }

    /// Writes tar metadata for a path selected by `newfstatat`.
    protected long statTarNode(@Nullable TarNode node, long statAddress) {
        if (node == null) {
            return ENOENT;
        }
        writeTarStat(node, statAddress);
        return 0;
    }

    /// Writes a Linux generic 64-bit `struct stat` for a tar node.
    protected void writeTarStat(TarNode node, long statAddress) {
        writeStat(statAddress, node.inode(), node.statMode(), node.size(), node.userId(), node.groupId());
    }

    /// Writes virtual filesystem metadata for a path selected by `newfstatat`.
    protected long statVirtualNode(@Nullable VirtualNode node, VirtualMount mount, long statAddress) {
        if (node == null) {
            return ENOENT;
        }
        writeVirtualStat(node, mount, statAddress);
        return 0;
    }

    /// Writes a Linux generic 64-bit `struct stat` for a virtual node.
    protected void writeVirtualStat(VirtualNode node, VirtualMount mount, long statAddress) {
        writeStat(statAddress, node.inode(), node.statMode(), virtualNodeSize(mount, node));
    }

    /// Writes tar metadata for a path selected by `statx`.
    protected long statxTarNode(@Nullable TarNode node, long statxAddress, long flags, long requestedMask) {
        if (node == null) {
            return ENOENT;
        }
        if (node.isSymbolicLink() && (flags & AT_SYMLINK_NOFOLLOW) == 0) {
            return ENODEV;
        }
        writeTarStatx(node, statxAddress, requestedMask);
        return 0;
    }

    /// Writes a Linux generic `struct statx` for a tar node.
    protected void writeTarStatx(TarNode node, long statxAddress, long requestedMask) {
        writeStatx(statxAddress, node.inode(), node.statMode(), node.size(), requestedMask, node.userId(), node.groupId());
    }

    /// Writes virtual filesystem metadata for a path selected by `statx`.
    protected long statxVirtualNode(
            @Nullable VirtualNode node,
            VirtualMount mount,
            long statxAddress,
            long requestedMask) {
        if (node == null) {
            return ENOENT;
        }
        writeVirtualStatx(node, mount, statxAddress, requestedMask);
        return 0;
    }

    /// Writes a Linux generic `struct statx` for a virtual node.
    protected void writeVirtualStatx(VirtualNode node, VirtualMount mount, long statxAddress, long requestedMask) {
        writeStatx(statxAddress, node.inode(), node.statMode(), virtualNodeSize(mount, node), requestedMask);
    }

    /// Writes the shared subset of Linux generic 64-bit `struct stat` fields.
    protected void writeStat(long statAddress, long inode, int mode, long size) {
        writeStat(statAddress, inode, mode, size, credentials.effectiveUserId(), credentials.effectiveGroupId());
    }

    /// Writes the shared subset of Linux generic 64-bit `struct stat` fields with explicit ownership.
    protected void writeStat(long statAddress, long inode, int mode, long size, long userId, long groupId) {
        memory.clear(statAddress, STAT_SIZE);
        memory.writeLong(statAddress + STAT_INODE_OFFSET, inode);
        memory.writeInt(statAddress + STAT_MODE_OFFSET, mode);
        memory.writeInt(statAddress + STAT_LINK_COUNT_OFFSET, 1);
        memory.writeInt(statAddress + STAT_UID_OFFSET, GuestCredentials.idToInt(userId));
        memory.writeInt(statAddress + STAT_GID_OFFSET, GuestCredentials.idToInt(groupId));
        memory.writeLong(statAddress + STAT_SIZE_OFFSET, size);
        memory.writeInt(statAddress + STAT_BLOCK_SIZE_OFFSET, STANDARD_STREAM_BLOCK_SIZE);
        memory.writeLong(statAddress + STAT_BLOCK_COUNT_OFFSET, (size + 511L) / 512L);
    }

    /// Writes host timestamps into the active ABI's `struct stat` layout.
    protected void writeStatTimestamps(
            long statAddress,
            FileTime accessTime,
            FileTime modificationTime,
            @Nullable FileTime changeTime,
            @Nullable FileTime birthTime) {
        writeFileTime(statAddress + STAT_ACCESS_TIME_OFFSET, accessTime);
        writeFileTime(statAddress + STAT_MODIFICATION_TIME_OFFSET, modificationTime);
        if (changeTime != null) {
            writeFileTime(statAddress + STAT_CHANGE_TIME_OFFSET, changeTime);
        }
    }

    /// Reads host timestamps and writes them without following the final symbolic link when requested.
    private void writeHostStatTimestamps(Path hostFile, long statAddress, boolean noFollow) throws IOException {
        BasicFileAttributes attributes = noFollow
                ? Files.readAttributes(hostFile, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)
                : Files.readAttributes(hostFile, BasicFileAttributes.class);
        writeStatTimestamps(
                statAddress,
                attributes.lastAccessTime(),
                attributes.lastModifiedTime(),
                null,
                attributes.creationTime());
    }

    /// Writes one Java file timestamp as a native 64-bit `struct timespec`.
    protected void writeFileTime(long address, FileTime fileTime) {
        Instant instant = fileTime.toInstant();
        memory.writeLong(address + TIMESPEC_SECONDS_OFFSET, instant.getEpochSecond());
        memory.writeLong(address + TIMESPEC_NANOSECONDS_OFFSET, instant.getNano());
    }

    /// Writes deterministic Linux generic `struct statx` fields.
    protected void writeStatx(long statxAddress, long inode, int mode, long size, long requestedMask) {
        writeStatx(
                statxAddress,
                inode,
                mode,
                size,
                requestedMask,
                credentials.effectiveUserId(),
                credentials.effectiveGroupId());
    }

    /// Writes deterministic Linux generic `struct statx` fields with explicit ownership.
    protected void writeStatx(
            long statxAddress,
            long inode,
            int mode,
            long size,
            long requestedMask,
            long userId,
            long groupId) {
        int returnedMask = (int) (requestedMask & STATX_BASIC_STATS_MASK);
        if (returnedMask == 0) {
            returnedMask = STATX_BASIC_STATS_MASK;
        }
        memory.clear(statxAddress, STATX_SIZE);
        memory.writeInt(statxAddress + STATX_MASK_OFFSET, returnedMask);
        memory.writeInt(statxAddress + STATX_BLOCK_SIZE_OFFSET, STANDARD_STREAM_BLOCK_SIZE);
        memory.writeLong(statxAddress + STATX_ATTRIBUTES_OFFSET, 0);
        memory.writeInt(statxAddress + STATX_LINK_COUNT_OFFSET, 1);
        memory.writeInt(statxAddress + STATX_UID_OFFSET, GuestCredentials.idToInt(userId));
        memory.writeInt(statxAddress + STATX_GID_OFFSET, GuestCredentials.idToInt(groupId));
        memory.writeShort(statxAddress + STATX_MODE_OFFSET, (short) mode);
        memory.writeLong(statxAddress + STATX_INODE_OFFSET, inode);
        memory.writeLong(statxAddress + STATX_FILE_SIZE_OFFSET, size);
        memory.writeLong(statxAddress + STATX_BLOCK_COUNT_OFFSET, (size + 511L) / 512L);
        memory.writeLong(statxAddress + STATX_ATTRIBUTES_MASK_OFFSET, STATX_ATTRIBUTES_MASK);
        memory.writeInt(statxAddress + STATX_DEVICE_MAJOR_OFFSET, 0);
        memory.writeInt(statxAddress + STATX_DEVICE_MINOR_OFFSET, 0);
        memory.writeLong(statxAddress + STATX_MOUNT_ID_OFFSET, STATX_SYNTHETIC_MOUNT_ID);
    }

    /// Writes deterministic Linux generic 64-bit `struct statfs` fields.
    protected void writeStatfs(long statfsAddress) {
        memory.clear(statfsAddress, STATFS_SIZE);
        memory.writeLong(statfsAddress + STATFS_TYPE_OFFSET, STATFS_MAGIC);
        memory.writeLong(statfsAddress + STATFS_BLOCK_SIZE_OFFSET, STATFS_BLOCK_SIZE);
        memory.writeLong(statfsAddress + STATFS_BLOCKS_OFFSET, STATFS_BLOCK_COUNT);
        memory.writeLong(statfsAddress + STATFS_BLOCKS_FREE_OFFSET, STATFS_BLOCK_COUNT);
        memory.writeLong(statfsAddress + STATFS_BLOCKS_AVAILABLE_OFFSET, STATFS_BLOCK_COUNT);
        memory.writeLong(statfsAddress + STATFS_FILES_OFFSET, STATFS_FILE_COUNT);
        memory.writeLong(statfsAddress + STATFS_FILES_FREE_OFFSET, STATFS_FILE_COUNT);
        memory.writeLong(statfsAddress + STATFS_NAME_LENGTH_OFFSET, STATFS_NAME_MAX);
        memory.writeLong(statfsAddress + STATFS_FRAGMENT_SIZE_OFFSET, STATFS_BLOCK_SIZE);
        memory.writeLong(statfsAddress + STATFS_FLAGS_OFFSET, 0);
    }

    /// Writes deterministic procfs Linux generic 64-bit `struct statfs` fields.
    protected void writeProcStatfs(long statfsAddress) {
        memory.clear(statfsAddress, STATFS_SIZE);
        memory.writeLong(statfsAddress + STATFS_TYPE_OFFSET, PROC_SUPER_MAGIC);
        memory.writeLong(statfsAddress + STATFS_BLOCK_SIZE_OFFSET, STATFS_BLOCK_SIZE);
        memory.writeLong(statfsAddress + STATFS_BLOCKS_OFFSET, 0);
        memory.writeLong(statfsAddress + STATFS_BLOCKS_FREE_OFFSET, 0);
        memory.writeLong(statfsAddress + STATFS_BLOCKS_AVAILABLE_OFFSET, 0);
        memory.writeLong(statfsAddress + STATFS_FILES_OFFSET, STATFS_FILE_COUNT);
        memory.writeLong(statfsAddress + STATFS_FILES_FREE_OFFSET, STATFS_FILE_COUNT);
        memory.writeLong(statfsAddress + STATFS_NAME_LENGTH_OFFSET, STATFS_NAME_MAX);
        memory.writeLong(statfsAddress + STATFS_FRAGMENT_SIZE_OFFSET, STATFS_BLOCK_SIZE);
        memory.writeLong(statfsAddress + STATFS_FLAGS_OFFSET, 0);
    }

    /// Writes deterministic sysfs Linux generic 64-bit `struct statfs` fields.
    protected void writeSysStatfs(long statfsAddress) {
        memory.clear(statfsAddress, STATFS_SIZE);
        memory.writeLong(statfsAddress + STATFS_TYPE_OFFSET, SYSFS_MAGIC);
        memory.writeLong(statfsAddress + STATFS_BLOCK_SIZE_OFFSET, STATFS_BLOCK_SIZE);
        memory.writeLong(statfsAddress + STATFS_BLOCKS_OFFSET, 0);
        memory.writeLong(statfsAddress + STATFS_BLOCKS_FREE_OFFSET, 0);
        memory.writeLong(statfsAddress + STATFS_BLOCKS_AVAILABLE_OFFSET, 0);
        memory.writeLong(statfsAddress + STATFS_FILES_OFFSET, STATFS_FILE_COUNT);
        memory.writeLong(statfsAddress + STATFS_FILES_FREE_OFFSET, STATFS_FILE_COUNT);
        memory.writeLong(statfsAddress + STATFS_NAME_LENGTH_OFFSET, STATFS_NAME_MAX);
        memory.writeLong(statfsAddress + STATFS_FRAGMENT_SIZE_OFFSET, STATFS_BLOCK_SIZE);
        memory.writeLong(statfsAddress + STATFS_FLAGS_OFFSET, 0);
    }

    /// Writes deterministic Linux generic 64-bit `struct statfs` fields for a virtual filesystem mount.
    protected void writeVirtualStatfs(VirtualMount mount, long statfsAddress) {
        if (PROC_MOUNT_PATH.equals(mount.guestPath())) {
            writeProcStatfs(statfsAddress);
        } else if (SYS_MOUNT_PATH.equals(mount.guestPath())) {
            writeSysStatfs(statfsAddress);
        } else {
            writeStatfs(statfsAddress);
        }
    }

    /// Returns a deterministic synthetic inode number for a sandboxed host path.
    protected static long syntheticInode(Path hostFile) {
        return Integer.toUnsignedLong(hostFile.toString().hashCode()) + 1024L;
    }

    /// Handles tty-related ioctls used by common `isatty` and stdio setup paths.
    protected long ioctl(int fileDescriptor, long request, long argument) {
        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile != null && deviceFileFor(openFile) == DeviceFile.FRAMEBUFFER) {
            return framebufferIoctl(request, argument);
        }
        if (openFile != null && openFile.isPtyEndpoint()) {
            return ptyIoctl(openFile, request, argument);
        }

        @Nullable TerminalDevice terminal = terminalDeviceFor(fileDescriptor);
        if (terminal == null) {
            if (!isOpenFileDescriptor(fileDescriptor)) {
                return EBADF;
            }
            return ENOTTY;
        }
        return terminalIoctl(terminal, request, argument);
    }

    /// Handles pseudoterminal-specific ioctls before falling back to terminal ioctls.
    protected long ptyIoctl(OpenFile openFile, long request, long argument) {
        PtyEndpoint endpoint = openFile.ptyEndpoint();
        if (request == TIOCGPTN) {
            if (!endpoint.master()) {
                return ENOTTY;
            }
            if (!memory.isBacked(argument, Integer.BYTES)) {
                return EFAULT;
            }
            memory.writeInt(argument, endpoint.device().number());
            return 0;
        }
        if (request == TIOCSPTLCK) {
            if (!endpoint.master()) {
                return ENOTTY;
            }
            if (!memory.isBacked(argument, Integer.BYTES)) {
                return EFAULT;
            }
            endpoint.device().setLocked(memory.readInt(argument) != 0);
            return 0;
        }
        if (request == TIOCGPTPEER) {
            if (!endpoint.master()) {
                return ENOTTY;
            }
            return openPtyPeer(openFile, argument);
        }
        return terminalIoctl(terminalDevice, request, argument);
    }

    /// Opens the slave peer for a pseudoterminal master through `TIOCGPTPEER`.
    protected long openPtyPeer(OpenFile masterFile, long flags) {
        long accessMode = flags & O_ACCMODE;
        if (accessMode != O_RDONLY && accessMode != O_WRONLY && accessMode != O_RDWR) {
            return EINVAL;
        }
        if ((flags & ~SUPPORTED_TIOCGPTPEER_FLAGS) != 0) {
            return EINVAL;
        }

        @Nullable VirtualMount mount = masterFile.virtualMount();
        if (mount == null) {
            return ENODEV;
        }
        boolean readable = accessMode == O_RDONLY || accessMode == O_RDWR;
        boolean writable = accessMode == O_WRONLY || accessMode == O_RDWR;
        return addOpenFile(OpenFile.ptyEndpoint(
                ptySlaveNode(),
                mount,
                DEV_MOUNT_PATH + "/pts/0",
                PtyEndpoint.slave(masterFile.ptyEndpoint().device()),
                readable,
                writable,
                (flags & O_NONBLOCK) != 0), (flags & O_CLOEXEC) != 0);
    }

    /// Returns the built-in `/dev/pts/0` virtual node.
    protected static VirtualNode ptySlaveNode() {
        return VirtualNode.characterDevice(DEV_MOUNT_PATH + "/pts/0", DeviceFile.PTS0);
    }

    /// Handles terminal-like ioctls shared by controlling terminals and pseudoterminals.
    protected long terminalIoctl(TerminalDevice terminal, long request, long argument) {
        if (request == TCGETS) {
            if (!memory.isBacked(argument, TERMIOS_SIZE)) {
                return EFAULT;
            }
            terminal.writeTermios(memory, argument);
            return 0;
        }
        if (request == TCGETS2) {
            if (!memory.isBacked(argument, TERMIOS2_SIZE)) {
                return EFAULT;
            }
            terminal.writeTermios2(memory, argument);
            return 0;
        }
        if (request == TCSETS || request == TCSETSW || request == TCSETSF) {
            if (!memory.isBacked(argument, TERMIOS_SIZE)) {
                return EFAULT;
            }
            terminal.readTermios(memory, argument, request);
            return 0;
        }
        if (request == TCSETS2 || request == TCSETSW2 || request == TCSETSF2) {
            if (!memory.isBacked(argument, TERMIOS2_SIZE)) {
                return EFAULT;
            }
            terminal.readTermios(memory, argument, legacyTermiosRequest(request));
            return 0;
        }
        if (request == TIOCGWINSZ) {
            if (!memory.isBacked(argument, WINSIZE_SIZE)) {
                return EFAULT;
            }
            terminal.writeWindowSize(memory, argument);
            return 0;
        }
        if (request == TIOCSWINSZ) {
            if (!memory.isBacked(argument, WINSIZE_SIZE)) {
                return EFAULT;
            }
            terminal.readWindowSize(memory, argument);
            return 0;
        }
        if (request == TIOCGPGRP) {
            if (!memory.isBacked(argument, Integer.BYTES)) {
                return EFAULT;
            }
            memory.writeInt(argument, process.processGroupId());
            return 0;
        }
        if (request == TIOCSPGRP) {
            if (!memory.isBacked(argument, Integer.BYTES)) {
                return EFAULT;
            }
            int processGroupId = memory.readInt(argument);
            return processGroupId <= 0 ? EINVAL : 0;
        }
        if (request == TIOCSCTTY) {
            return 0;
        }
        if (request == TIOCGSID) {
            if (!memory.isBacked(argument, Integer.BYTES)) {
                return EFAULT;
            }
            memory.writeInt(argument, process.processGroupId());
            return 0;
        }
        return ENOTTY;
    }

    /// Handles Linux framebuffer ioctls for the configured framebuffer device.
    protected long framebufferIoctl(long request, long argument) {
        @Nullable FramebufferDevice device = framebufferDevice;
        if (device == null) {
            return ENODEV;
        }
        if (request == FBIOGET_VSCREENINFO) {
            return writeFramebufferVariableScreenInfo(device.geometry(), argument);
        }
        if (request == FBIOGET_FSCREENINFO) {
            return writeFramebufferFixedScreenInfo(device.geometry(), argument);
        }
        return ENOTTY;
    }

    /// Writes Linux `struct fb_var_screeninfo` for the configured framebuffer.
    protected long writeFramebufferVariableScreenInfo(FramebufferGeometry geometry, long address) {
        int size = 160;
        if (!memory.isBacked(address, size)) {
            return EFAULT;
        }

        FramebufferPixelFormat format = geometry.pixelFormat();
        memory.clear(address, size);
        memory.writeInt(address, geometry.width());
        memory.writeInt(address + 4, geometry.height());
        memory.writeInt(address + 8, geometry.width());
        memory.writeInt(address + 12, geometry.height());
        memory.writeInt(address + 24, format.bitsPerPixel());
        writeFramebufferBitfield(address + 32, format.redOffset(), format.redLength());
        writeFramebufferBitfield(address + 44, format.greenOffset(), format.greenLength());
        writeFramebufferBitfield(address + 56, format.blueOffset(), format.blueLength());
        writeFramebufferBitfield(address + 68, format.transparencyOffset(), format.transparencyLength());
        memory.writeInt(address + 88, -1);
        memory.writeInt(address + 92, -1);
        return 0;
    }

    /// Writes Linux `struct fb_fix_screeninfo` for the configured framebuffer.
    protected long writeFramebufferFixedScreenInfo(FramebufferGeometry geometry, long address) {
        int size = 80;
        if (!memory.isBacked(address, size)) {
            return EFAULT;
        }

        memory.clear(address, size);
        byte[] id = "JRISC-V FB".getBytes(StandardCharsets.US_ASCII);
        memory.writeBytes(address, id, 0, Math.min(id.length, 15));
        memory.writeInt(address + 24, geometry.bufferSizeBytes());
        memory.writeInt(address + 28, 0);
        memory.writeInt(address + 32, 0);
        memory.writeInt(address + 36, 2);
        memory.writeInt(address + 48, geometry.strideBytes());
        return 0;
    }

    /// Writes Linux `struct fb_bitfield`.
    protected void writeFramebufferBitfield(long address, int offset, int length) {
        memory.writeInt(address, offset);
        memory.writeInt(address + 4, length);
        memory.writeInt(address + 8, 0);
    }

    /// Maps a Linux `termios2` set request to the matching legacy `termios` set request.
    protected static long legacyTermiosRequest(long request) {
        if (request == TCSETS2) {
            return TCSETS;
        }
        if (request == TCSETSW2) {
            return TCSETSW;
        }
        if (request == TCSETSF2) {
            return TCSETSF;
        }
        throw new AssertionError("Unexpected termios2 request: 0x" + Long.toHexString(request));
    }

    /// Returns the terminal backing a descriptor that resolves to standard input.
    protected @Nullable TerminalDevice terminalInputFor(int fileDescriptor) {
        return standardFileDescriptorFor(fileDescriptor) == 0 && terminalDevice.supportsStandardFileDescriptors()
                ? terminalDevice
                : null;
    }

    /// Returns the terminal backing a descriptor that resolves to standard output or standard error.
    protected @Nullable TerminalDevice terminalOutputFor(int fileDescriptor) {
        int standardFileDescriptor = standardFileDescriptorFor(fileDescriptor);
        return (standardFileDescriptor == 1 || standardFileDescriptor == 2)
                && terminalDevice.supportsStandardFileDescriptors()
                ? terminalDevice
                : null;
    }

    /// Returns the terminal backing a descriptor, or null when the descriptor is not terminal-like.
    protected @Nullable TerminalDevice terminalDeviceFor(int fileDescriptor) {
        if (standardFileDescriptorFor(fileDescriptor) >= 0) {
            return terminalDevice.supportsStandardFileDescriptors() ? terminalDevice : null;
        }
        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null || !openFile.isTerminalDevice()) {
            return null;
        }
        return openFile.terminalDevice();
    }

    /// Handles the minimal `fcntl` subset used by static single-process libc code.
    protected long fcntl(int fileDescriptor, long command, long argument) {
        if (!isOpenFileDescriptor(fileDescriptor)) {
            return EBADF;
        }

        if (command == F_DUPFD || command == F_DUPFD_CLOEXEC) {
            if (argument < 0 || argument > Integer.MAX_VALUE) {
                return EINVAL;
            }
            @Nullable OpenFile duplicate = duplicateOpenFile(fileDescriptor);
            if (duplicate == null) {
                return EBADF;
            }
            return addOpenFileAtLeast(duplicate, (int) argument, command == F_DUPFD_CLOEXEC);
        }
        if (command == F_GETFD) {
            return fileDescriptorCloseOnExec(fileDescriptor) ? FD_CLOEXEC : 0;
        }
        if (command == F_SETFD) {
            setFileDescriptorCloseOnExec(fileDescriptor, (argument & FD_CLOEXEC) != 0);
            return 0;
        }
        if (command == F_GETFL) {
            return statusFlagsFor(fileDescriptor);
        }
        if (command == F_SETFL) {
            @Nullable OpenFile openFile = openFile(fileDescriptor);
            if (openFile == null && isStandardFileDescriptor(fileDescriptor) && standardFileOpen[fileDescriptor]) {
                openFile = OpenFile.standardFileDescriptor(fileDescriptor);
                standardFiles[fileDescriptor] = openFile;
            }
            if (openFile != null) {
                openFile.setNonblocking((argument & O_NONBLOCK) != 0);
            }
            return 0;
        }
        if (command == F_GETLK) {
            memory.writeShort(argument + FLOCK_TYPE_OFFSET, F_UNLCK);
            return 0;
        }
        if (command == F_SETLK || command == F_SETLKW) {
            return 0;
        }
        return EINVAL;
    }

    /// Throws when another guest thread has failed or process termination has been requested.
    public void checkProcessStatus() {
        if (!processStatusPollingRequired) {
            return;
        }

        checkProcessStatusSlow();
    }

    /// Performs the uncommon cross-thread process-status checks after polling has been enabled.
    protected void checkProcessStatusSlow() {
        @Nullable Throwable failure = threadFailure;
        if (failure != null) {
            throw guestThreadFailure(failure);
        }
        if (processExitRequested) {
            throw new ProgramExitException(processExitCode);
        }
    }

    /// Requests process-wide termination and wakes all guest threads blocked in host waits.
    public void requestProcessExit(long exitCode) {
        synchronized (threadLock) {
            if (!processExitRequested) {
                processExitRequested = true;
                processExitCode = exitCode;
                processStatusPollingRequired = true;
            }
            threadLock.notifyAll();
        }
        synchronized (childProcessLock) {
            childProcessLock.notifyAll();
        }
    }

    /// Records that a guest thread exited and returns the process exit code once it is known.
    public long completeThreadExit(RiscVThreadState state, long exitCode) {
        recordThreadExit(state, exitCode);
        return waitForProcessExit();
    }

    /// Records a guest thread exit and performs Linux clear-child-TID wakeup side effects.
    public void recordThreadExit(RiscVThreadState state, long exitCode) {
        synchronized (threadLock) {
            state.guestThread().markExited();
            clearChildTidAndWake(state);
            if (liveThreadCount > 0) {
                liveThreadCount--;
            }
            guestThreads.remove(Thread.currentThread());
            process.unregisterThread(state.guestThread());
            if (!processExitRequested && liveThreadCount == 0) {
                processExitRequested = true;
                processExitCode = exitCode;
                processStatusPollingRequired = true;
            }
            notifyParentProcessExitLocked();
            notifyPollWaiters();
            threadLock.notifyAll();
        }
    }

    /// Records a host-side failure from a guest thread and wakes the process owner.
    public void recordThreadFailure(Throwable throwable) {
        synchronized (threadLock) {
            if (threadFailure == null) {
                threadFailure = throwable;
            }
            processExitRequested = true;
            processExitCode = 1;
            processStatusPollingRequired = true;
            notifyParentProcessExitLocked();
            threadLock.notifyAll();
        }
    }

    /// Reports this process exit to its parent once all guest threads have exited.
    protected void notifyParentProcessExitLocked() {
        if (parentProcess == null || parentExitNotified || !processExitRequested || liveThreadCount != 0) {
            return;
        }
        parentExitNotified = true;
        parentProcess.recordChildProcessExit(process.id(), processExitCode);
    }

    /// Joins all guest host threads before the shared guest memory is closed.
    public void joinGuestThreads() {
        while (true) {
            Thread[] threads;
            synchronized (threadLock) {
                threads = guestThreads.toArray(Thread[]::new);
                if (threads.length == 0) {
                    if (threadFailure != null) {
                        throw guestThreadFailure(threadFailure);
                    }
                    return;
                }
            }

            Thread currentThread = Thread.currentThread();
            for (Thread thread : threads) {
                if (thread == currentThread) {
                    continue;
                }
                try {
                    thread.join();
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw new RiscVException("Interrupted while waiting for guest threads to exit", exception);
                }
            }

            synchronized (threadLock) {
                for (int index = 0; index < guestThreads.size(); ) {
                    if (guestThreads.get(index).isAlive()) {
                        index++;
                    } else {
                        guestThreads.remove(index);
                    }
                }
            }
        }
    }

    /// Waits until the process exit code is known.
    protected long waitForProcessExit() {
        synchronized (threadLock) {
            while (!processExitRequested && threadFailure == null) {
                try {
                    threadLock.wait();
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw new RiscVException("Interrupted while waiting for guest process exit", exception);
                }
            }
            if (threadFailure != null) {
                throw guestThreadFailure(threadFailure);
            }
            return processExitCode;
        }
    }

    /// Records that one child process has exited and wakes waiters.
    protected void recordChildProcessExit(int processId, long exitCode) {
        synchronized (childProcessLock) {
            for (ChildProcess child : childProcesses) {
                if (child.processId() == processId) {
                    child.recordExit(exitCode);
                    childProcessLock.notifyAll();
                    notifyPollWaiters();
                    return;
                }
            }
        }
    }

    /// Removes a child process whose host thread could not be started.
    protected void removeUnstartedChildProcess(ChildProcess childProcess) {
        synchronized (childProcessLock) {
            childProcesses.remove(childProcess);
            childProcessLock.notifyAll();
        }
    }

    /// Returns true when a process id names a known child process.
    protected boolean isKnownChildProcessId(long processId) {
        if (processId != (int) processId) {
            return false;
        }
        synchronized (childProcessLock) {
            return childProcess((int) processId) != null;
        }
    }

    /// Returns a tracked child process by process id while the child-process lock is held.
    protected @Nullable ChildProcess childProcess(int processId) {
        for (ChildProcess child : childProcesses) {
            if (child.processId() == processId) {
                return child;
            }
        }
        return null;
    }

    /// Joins the host thread that executed a child process.
    protected static void joinChildProcess(ChildProcess childProcess) {
        Thread thread = childProcess.thread();
        if (thread == Thread.currentThread()) {
            return;
        }
        try {
            thread.join();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new RiscVException("Interrupted while waiting for guest child process", exception);
        }
    }

    /// Clears a thread's child-TID word and wakes one matching futex waiter.
    protected void clearChildTidAndWake(RiscVThreadState state) {
        long clearAddress = state.clearChildTidAddress();
        if (clearAddress == 0 || !memory.isBacked(clearAddress, Integer.BYTES)) {
            return;
        }

        memory.writeInt(clearAddress, 0);
        futexWakeLocked(clearAddress, 1, FUTEX_BITSET_MATCH_ANY);
    }

    /// Creates an exception that reports a failed guest worker thread.
    protected static RiscVException guestThreadFailure(Throwable failure) {
        if (failure instanceof RiscVException exception) {
            return exception;
        }
        return new RiscVException("Guest thread failed", failure);
    }

    /// Stores the guest clear-child-TID pointer and returns this guest thread id.
    protected static long setTidAddress(RiscVThreadState state, long address) {
        state.setClearChildTidAddress(address);
        return state.threadId();
    }

    /// Exits the current guest thread.
    protected void exitThread(RiscVThreadState state, long exitCode) {
        synchronized (threadLock) {
            if (liveThreadCount <= 1) {
                if (!processExitRequested) {
                    processExitRequested = true;
                    processExitCode = exitCode;
                    processStatusPollingRequired = true;
                }
                threadLock.notifyAll();
                throw new ProgramExitException(exitCode);
            }
        }
        throw new ThreadExitException(exitCode);
    }

    /// Handles Linux futex wait and wake operations.
    protected long futex(
            long address,
            long operation,
            long expectedValue,
            long timeoutAddress,
            long secondAddress,
            long thirdValue) {
        if ((address & (Integer.BYTES - 1L)) != 0) {
            return EINVAL;
        }

        long command = operation & FUTEX_COMMAND_MASK;
        long flags = operation & ~FUTEX_COMMAND_MASK;
        if ((flags & ~SUPPORTED_FUTEX_FLAGS) != 0) {
            return EINVAL;
        }
        if ((flags & FUTEX_CLOCK_REALTIME) != 0 && command != FUTEX_WAIT && command != FUTEX_WAIT_BITSET) {
            return EINVAL;
        }

        return switch ((int) command) {
            case (int) FUTEX_WAIT -> futexWait(
                    address,
                    expectedValue,
                    timeoutAddress,
                    FUTEX_BITSET_MATCH_ANY,
                    false,
                    (flags & FUTEX_CLOCK_REALTIME) != 0);
            case (int) FUTEX_WAKE -> futexWake(address, expectedValue, FUTEX_BITSET_MATCH_ANY);
            case (int) FUTEX_WAIT_BITSET -> futexWait(
                    address,
                    expectedValue,
                    timeoutAddress,
                    thirdValue,
                    true,
                    (flags & FUTEX_CLOCK_REALTIME) != 0);
            case (int) FUTEX_WAKE_BITSET -> futexWake(address, expectedValue, thirdValue);
            default -> ENOSYS;
        };
    }

    /// Handles a futex wait, blocking only when guest threading is active.
    protected long futexWait(
            long address,
            long expectedValue,
            long timeoutAddress,
            long bitset,
            boolean absoluteTimeout,
            boolean realtimeTimeout) {
        if ((bitset & 0xffff_ffffL) == 0) {
            return EINVAL;
        }

        long timeoutNanos = -1;
        if (timeoutAddress != 0) {
            long seconds = memory.readLong(timeoutAddress + TIMESPEC_SECONDS_OFFSET);
            long nanoseconds = memory.readLong(timeoutAddress + TIMESPEC_NANOSECONDS_OFFSET);
            if (!isValidTimespec(seconds, nanoseconds)) {
                return EINVAL;
            }
            timeoutNanos = futexTimeoutNanos(seconds, nanoseconds, absoluteTimeout, realtimeTimeout);
        }

        return futexWaitWithTimeoutNanos(address, expectedValue, bitset, timeoutNanos);
    }

    /// Handles a futex wait after the caller has converted any timeout to a relative nanosecond count.
    protected long futexWaitWithTimeoutNanos(
            long address,
            long expectedValue,
            long bitset,
            long timeoutNanos) {
        if ((bitset & 0xffff_ffffL) == 0 || timeoutNanos < -1) {
            return EINVAL;
        }

        synchronized (threadLock) {
            int currentValue = memory.readInt(address);
            if (currentValue != (int) expectedValue) {
                return EAGAIN;
            }
            if (!guestThreadingEnabled()) {
                return ETIMEDOUT;
            }
            if (timeoutNanos == 0) {
                return ETIMEDOUT;
            }

            FutexWaiter waiter = new FutexWaiter(address, bitset);
            futexWaiters.add(waiter);
            try {
                long remainingNanos = timeoutNanos;
                long lastNanos = timeoutNanos >= 0 ? timeSource.monotonicNanoseconds() : 0;
                while (!waiter.woken && !processExitRequested && threadFailure == null) {
                    if (remainingNanos >= 0) {
                        if (remainingNanos <= 0) {
                            return ETIMEDOUT;
                        }
                        waitNanos(remainingNanos);
                        long now = timeSource.monotonicNanoseconds();
                        long elapsed = Math.max(0, now - lastNanos);
                        remainingNanos = elapsed >= remainingNanos ? 0 : remainingNanos - elapsed;
                        lastNanos = now;
                    } else {
                        threadLock.wait();
                    }
                }
                if (threadFailure != null || processExitRequested) {
                    return EINTR;
                }
                return 0;
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                return EINTR;
            } finally {
                futexWaiters.remove(waiter);
            }
        }
    }

    /// Handles a futex wake against guest waiters.
    protected long futexWake(long address, long count, long bitset) {
        if (count < 0 || (bitset & 0xffff_ffffL) == 0) {
            return EINVAL;
        }

        synchronized (threadLock) {
            long woken = futexWakeLocked(address, count, bitset);
            if (woken > 0) {
                threadLock.notifyAll();
            }
            return woken;
        }
    }

    /// Wakes matching futex waiters while `threadLock` is held.
    protected long futexWakeLocked(long address, long count, long bitset) {
        long woken = 0;
        for (FutexWaiter waiter : futexWaiters) {
            if (woken >= count) {
                break;
            }
            if (waiter.address == address && (waiter.bitset & bitset) != 0) {
                waiter.woken = true;
                woken++;
            }
        }
        if (woken > 0) {
            threadLock.notifyAll();
        }
        return woken;
    }

    /// Waits on `threadLock` for at most the supplied nanosecond count.
    protected void waitNanos(long nanoseconds) throws InterruptedException {
        long millis = nanoseconds / 1_000_000L;
        int nanos = (int) (nanoseconds % 1_000_000L);
        threadLock.wait(millis, nanos);
    }

    /// Converts a futex timeout to a relative nanosecond count.
    protected long futexTimeoutNanos(
            long seconds,
            long nanoseconds,
            boolean absoluteTimeout,
            boolean realtimeTimeout) {
        long targetNanos = timespecToSaturatedNanoseconds(seconds, nanoseconds);
        if (!absoluteTimeout) {
            return targetNanos;
        }

        long nowNanos = realtimeTimeout
                ? instantToSaturatedNanoseconds(timeSource.realtimeInstant())
                : timeSource.monotonicNanoseconds();
        return targetNanos <= nowNanos ? 0 : targetNanos - nowNanos;
    }

    /// Converts an instant to saturated nanoseconds since the Unix epoch.
    protected static long instantToSaturatedNanoseconds(Instant instant) {
        long seconds = instant.getEpochSecond();
        int nanoseconds = instant.getNano();
        if (seconds <= 0) {
            return 0;
        }
        return timespecToSaturatedNanoseconds(seconds, nanoseconds);
    }

    /// Returns the current nanosecond value for a clock accepted by `timerfd_create`.
    protected long timerfdClockNanoseconds(long clockId) {
        if (clockId == CLOCK_REALTIME) {
            return instantToSaturatedNanoseconds(timeSource.realtimeInstant());
        }
        return durationToSaturatedNanoseconds(elapsedDuration());
    }

    /// Returns true when clone-created guest threads can be started.
    protected boolean guestThreadingEnabled() {
        return guestThreadRunner != null;
    }

    /// Replaces the current process image with a mounted guest executable.
    protected long execve(RiscVThreadState state, long pathAddress, long argvAddress, long envpAddress) {
        String rawPath;
        String[] arguments;
        String[] environment;
        try {
            @Nullable String path = readGuestPath(pathAddress);
            if (path == null) {
                return ENAMETOOLONG;
            }
            rawPath = path;
            @Nullable String[] readArguments = readGuestStringVector(argvAddress);
            @Nullable String[] readEnvironment = readGuestStringVector(envpAddress);
            if (readArguments == null || readEnvironment == null) {
                return E2BIG;
            }
            arguments = readArguments.length == 0 ? new String[]{rawPath} : readArguments;
            environment = readEnvironment;
        } catch (RiscVException exception) {
            return EFAULT;
        }

        if (rawPath.isEmpty()) {
            return ENOENT;
        }
        @Nullable String executablePath = absoluteGuestPath(AT_FDCWD, rawPath);
        if (executablePath == null) {
            return EACCES;
        }
        if (!canReplaceCurrentProcessImage(state)) {
            return EAGAIN;
        }

        LinuxProgramLoader.LoadedProgram program;
        GuestCredentials execCredentials;
        try {
            byte[] executableBytes = fileSystem.readFile(executablePath);
            LinuxProgramLoader.ResolvedExecutable resolvedExecutable =
                    LinuxProgramLoader.resolveExecutable(executableBytes, executablePath, fileSystem, arguments);
            execCredentials = credentialsForExec(resolvedExecutable.executablePath());
            program = LinuxProgramLoader.load(
                    resolvedExecutable.executableBytes(),
                    resolvedExecutable.executablePath(),
                    fileSystem,
                    pageSize);
            arguments = resolvedExecutable.arguments();
        } catch (RiscVException exception) {
            return execveLoadError(exception);
        }
        if (!loadedProgramFitsMemory(program)) {
            return ENOMEM;
        }

        replaceCurrentProcessImage(state, program, arguments, environment, execCredentials);
        throw new ProcessImageReplacedException();
    }

    /// Returns true when this process is in a state that can be replaced without racing another guest thread.
    protected boolean canReplaceCurrentProcessImage(RiscVThreadState state) {
        synchronized (threadLock) {
            return liveThreadCount == 1
                    && process.threadCount() == 1
                    && state.guestThread() == process.initialThread()
                    && !processExitRequested
                    && threadFailure == null;
        }
    }

    /// Returns true when every loadable segment in a program fits the current guest memory window.
    protected boolean loadedProgramFitsMemory(LinuxProgramLoader.LoadedProgram program) {
        for (LinuxProgramLoader.LoadedImage loadedImage : program.images()) {
            for (ElfImage.LoadSegment segment : loadedImage.image().loadSegments()) {
                if (segment.memorySize() == 0) {
                    continue;
                }
                long runtimeAddress = loadedImage.runtimeAddress(segment.virtualAddress());
                if (runtimeAddress > Long.MAX_VALUE - segment.memorySize()) {
                    return false;
                }
                long pageStart = alignDown(runtimeAddress, pageSize);
                long pageEnd = alignUp(runtimeAddress + segment.memorySize(), pageSize);
                if (pageEnd < 0 || pageStart < memory.baseAddress() || pageEnd > memory.endAddress()) {
                    return false;
                }
            }
        }
        return true;
    }

    /// Returns credentials after applying setuid and setgid bits for an executable path.
    protected GuestCredentials credentialsForExec(@Nullable String executablePath) {
        long effectiveUserId = credentials.effectiveUserId();
        long effectiveGroupId = credentials.effectiveGroupId();
        if (executablePath != null) {
            @Nullable GuestFileMetadata metadata = executableMetadata(executablePath);
            if (metadata != null) {
                if ((metadata.mode() & STAT_MODE_SET_USER_ID) != 0) {
                    effectiveUserId = metadata.userId();
                }
                if ((metadata.mode() & STAT_MODE_SET_GROUP_ID) != 0) {
                    effectiveGroupId = metadata.groupId();
                }
            }
        }
        return credentials.withExecEffectiveIds(effectiveUserId, effectiveGroupId);
    }

    /// Returns guest-visible metadata for a regular executable path.
    protected @Nullable GuestFileMetadata executableMetadata(String absoluteGuestPath) {
        @Nullable Mount mount = fileSystem.mountForGuestPath(absoluteGuestPath);
        if (mount instanceof TarMount) {
            @Nullable TarPath tarPath = fileSystem.resolveTarPath(absoluteGuestPath, true);
            @Nullable TarNode node = tarPath == null ? null : tarPath.node();
            if (node == null || !node.isFile()) {
                return null;
            }
            return new GuestFileMetadata(node.userId(), node.groupId(), node.permissions());
        }
        if (mount instanceof HostMount hostMount) {
            @Nullable Path hostFile = GuestFileSystem.resolveHostFile(absoluteGuestPath, hostMount);
            if (hostFile == null) {
                return null;
            }
            try {
                if (!Files.isRegularFile(hostFile)) {
                    return null;
                }
                return hostFileMetadata(hostFile, false);
            } catch (IOException | SecurityException exception) {
                return null;
            }
        }
        return null;
    }

    /// Installs an already loaded executable into the current process state.
    protected void replaceCurrentProcessImage(
            RiscVThreadState state,
            LinuxProgramLoader.LoadedProgram program,
            String @Unmodifiable [] arguments,
            String @Unmodifiable [] environment,
            GuestCredentials execCredentials) {
        syncSharedDeviceMappings();
        closeFramebufferRefreshHook();
        memory.resetAddressSpace();
        credentials = execCredentials;
        LinuxProgramLoader.LoadedProcess loadedProcess =
                LinuxProgramLoader.initialize(memory, program, arguments, environment, execCredentials, pageSize);
        resetForExec(state, loadedProcess.initialProgramBreak(), program.executablePath());
        recordInitialAuxiliaryVector(loadedProcess.stackPointer());
        state.resetForExec(
                program.entryPoint(),
                loadedProcess.stackPointer(),
                program.executable().runtimeOptionalAddress(program.executable().image().tohostAddress()),
                program.executable().runtimeOptionalAddress(program.executable().image().fromhostAddress()));
        initializeExecEntryState(state, loadedProcess.stackPointer());
    }

    /// Applies ABI-specific register values required at a newly executed program's entry point.
    protected void initializeExecEntryState(RiscVThreadState state, long stackPointer) {
    }

    /// Resets syscall-owned process metadata after a successful `execve`.
    protected void resetForExec(RiscVThreadState state, long newInitialProgramBreak, @Nullable String executablePath) {
        closeFileDescriptorsOnExec();
        initialProgramBreak = newInitialProgramBreak;
        programBreak = newInitialProgramBreak;
        programBreakBackingEnd = newInitialProgramBreak;
        closeFramebufferRefreshHook();
        memoryMappings.clear();
        auxiliaryVectorBytes = encodeAuxiliaryVector(new long[]{0, 0});
        procCommandLineBytes = new byte[0];
        procEnvironmentBytes = new byte[0];
        procExecutablePath = executablePath == null ? "/" : executablePath;
        futexWaiters.clear();
        state.guestThread().resetForExec();
        setProcessNameFromExecutablePath(executablePath);
    }

    /// Closes non-inherited descriptors after a successful `execve`.
    protected void closeFileDescriptorsOnExec() {
        for (int index = 0; index < standardFiles.length; index++) {
            if (!standardFileCloseOnExec[index]) {
                continue;
            }
            standardFileCloseOnExec[index] = false;
            @Nullable OpenFile openFile = standardFiles[index];
            standardFiles[index] = null;
            standardFileOpen[index] = false;
            setFileDescriptorCloseOnFork(index, false);
            if (openFile != null) {
                try {
                    releaseOpenFile(openFile);
                } catch (IOException exception) {
                    throw new RiscVException("Guest execve close-on-exec failed", exception);
                }
            }
        }

        for (int index = 0; index < openFiles.size(); index++) {
            if (!openFileCloseOnExec(index)) {
                continue;
            }
            setOpenFileCloseOnExec(index, false);
            @Nullable OpenFile openFile = openFiles.get(index);
            if (openFile == null) {
                continue;
            }
            openFiles.set(index, null);
            setFileDescriptorCloseOnFork(index + 3, false);
            try {
                releaseOpenFile(openFile);
            } catch (IOException exception) {
                throw new RiscVException("Guest execve close-on-exec failed", exception);
            }
        }
    }

    /// Updates the Linux task command name from an executable path.
    protected void setProcessNameFromExecutablePath(@Nullable String executablePath) {
        for (int index = 0; index < processName.length; index++) {
            processName[index] = 0;
        }
        if (executablePath == null || executablePath.isEmpty()) {
            return;
        }

        String leaf = GuestFileSystem.leafName(executablePath);
        byte[] bytes = leaf.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(bytes, 0, processName, 0, Math.min(bytes.length, TASK_COMMAND_LENGTH - 1));
    }

    /// Converts loader diagnostics into Linux `execve` errno values.
    protected static long execveLoadError(RiscVException exception) {
        @Nullable String message = exception.getMessage();
        if (message == null) {
            return ENOEXEC;
        }
        if (message.contains("does not exist")) {
            return ENOENT;
        }
        if (message.contains("recursion limit exceeded")) {
            return ELOOP;
        }
        if (message.contains("not a regular file")
                || message.contains("outside configured mounts")
                || message.contains("escapes configured mount")
                || message.contains("not covered by a configured mount")) {
            return EACCES;
        }
        return ENOEXEC;
    }

    /// Removes a child thread that failed before it could start running guest code.
    protected void unregisterUnstartedGuestThread(Thread thread, GuestThread guestThread) {
        synchronized (threadLock) {
            guestThreads.remove(thread);
            process.unregisterThread(guestThread);
            if (liveThreadCount > 0) {
                liveThreadCount--;
            }
            threadLock.notifyAll();
        }
    }

    /// Sleeps for the requested Linux RISC-V 64-bit `struct timespec` duration.
    protected long nanosleep(long requestAddress, long remainingAddress) {
        long seconds = memory.readLong(requestAddress + TIMESPEC_SECONDS_OFFSET);
        long nanoseconds = memory.readLong(requestAddress + TIMESPEC_NANOSECONDS_OFFSET);
        if (!isValidTimespec(seconds, nanoseconds)) {
            return EINVAL;
        }

        long totalNanoseconds = timespecToSaturatedNanoseconds(seconds, nanoseconds);
        return sleepNanoseconds(totalNanoseconds, remainingAddress);
    }

    /// Sleeps for a Linux `clock_nanosleep` request against a supported guest clock.
    protected long clockNanosleep(long clockId, long flags, long requestAddress, long remainingAddress) {
        if (!isSupportedClock(clockId) || (flags & ~SUPPORTED_CLOCK_NANOSLEEP_FLAGS) != 0) {
            return EINVAL;
        }
        if (clockId == CLOCK_THREAD_CPUTIME_ID) {
            return EINVAL;
        }
        if (clockId == CLOCK_PROCESS_CPUTIME_ID) {
            return ENOTSUP;
        }

        long seconds = memory.readLong(requestAddress + TIMESPEC_SECONDS_OFFSET);
        long nanoseconds = memory.readLong(requestAddress + TIMESPEC_NANOSECONDS_OFFSET);
        if (!isValidTimespec(seconds, nanoseconds)) {
            return EINVAL;
        }

        boolean absolute = (flags & TIMER_ABSTIME) != 0;
        long totalNanoseconds = absolute
                ? absoluteClockSleepNanoseconds(clockId, seconds, nanoseconds)
                : timespecToSaturatedNanoseconds(seconds, nanoseconds);
        return sleepNanoseconds(totalNanoseconds, absolute ? 0 : remainingAddress);
    }

    /// Sleeps for a relative duration and writes the remaining duration when interrupted.
    protected long sleepNanoseconds(long totalNanoseconds, long remainingAddress) {
        if (totalNanoseconds == 0) {
            return 0;
        }

        long startNanoseconds = timeSource.monotonicNanoseconds();
        try {
            Thread.sleep(
                    totalNanoseconds / NANOSECONDS_PER_MILLISECOND,
                    (int) (totalNanoseconds % NANOSECONDS_PER_MILLISECOND));
            return 0;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            if (remainingAddress != 0) {
                long elapsedNanoseconds = Math.max(0, timeSource.monotonicNanoseconds() - startNanoseconds);
                long remainingNanoseconds = Math.max(0, totalNanoseconds - elapsedNanoseconds);
                writeTimespecFromNanoseconds(remainingAddress, remainingNanoseconds);
            }
            return EINTR;
        }
    }

    /// Returns the relative wait needed to reach an absolute clock time.
    protected long absoluteClockSleepNanoseconds(long clockId, long targetSeconds, long targetNanoseconds) {
        if (isRealtimeClock(clockId)) {
            Instant instant = timeSource.realtimeInstant();
            return relativeNanosecondsUntil(targetSeconds, targetNanoseconds, instant.getEpochSecond(), instant.getNano());
        }

        Duration elapsed = elapsedDuration();
        return relativeNanosecondsUntil(targetSeconds, targetNanoseconds, elapsed.getSeconds(), elapsed.getNano());
    }

    /// Returns the saturated non-negative nanosecond distance from one timespec value to another.
    protected static long relativeNanosecondsUntil(
            long targetSeconds,
            long targetNanoseconds,
            long currentSeconds,
            int currentNanoseconds) {
        if (targetSeconds < currentSeconds
                || (targetSeconds == currentSeconds && targetNanoseconds <= currentNanoseconds)) {
            return 0;
        }

        long seconds = targetSeconds - currentSeconds;
        long nanoseconds = targetNanoseconds - currentNanoseconds;
        if (nanoseconds < 0) {
            seconds--;
            nanoseconds += NANOSECONDS_PER_SECOND;
        }
        return timespecToSaturatedNanoseconds(seconds, nanoseconds);
    }

    /// Yields the host thread for a guest scheduling-yield syscall.
    protected static long schedYield() {
        Thread.yield();
        return 0;
    }

    /// Returns the current guest process scheduling policy.
    protected long schedGetscheduler(long processId) {
        return isKnownSchedulerTarget(processId) ? schedulerPolicy : ESRCH;
    }

    /// Updates the current guest process scheduling policy and priority.
    protected long schedSetscheduler(long processId, long policy, long parameterAddress) {
        if (!isKnownSchedulerTarget(processId)) {
            return ESRCH;
        }

        long basePolicy = policy & ~SCHED_RESET_ON_FORK;
        if (!isSupportedSchedulerPolicy(basePolicy)) {
            return EINVAL;
        }

        int priority = memory.readInt(parameterAddress + SCHED_PARAM_PRIORITY_OFFSET);
        if (!isValidSchedulerPriority(basePolicy, priority)) {
            return EINVAL;
        }

        schedulerPolicy = (int) basePolicy;
        schedulerPriority = priority;
        return 0;
    }

    /// Reports the current guest process scheduling priority.
    protected long schedGetparam(long processId, long parameterAddress) {
        if (!isKnownSchedulerTarget(processId)) {
            return ESRCH;
        }

        memory.writeInt(parameterAddress + SCHED_PARAM_PRIORITY_OFFSET, schedulerPriority);
        return 0;
    }

    /// Updates the current guest process scheduling priority.
    protected long schedSetparam(long processId, long parameterAddress) {
        if (!isKnownSchedulerTarget(processId)) {
            return ESRCH;
        }

        int priority = memory.readInt(parameterAddress + SCHED_PARAM_PRIORITY_OFFSET);
        if (!isValidSchedulerPriority(schedulerPolicy, priority)) {
            return EINVAL;
        }

        schedulerPriority = priority;
        return 0;
    }

    /// Reports the maximum priority for a Linux scheduling policy.
    protected static long schedGetPriorityMax(long policy) {
        return switch ((int) policy) {
            case SCHED_OTHER, SCHED_BATCH, SCHED_IDLE -> 0;
            case SCHED_FIFO, SCHED_RR -> SCHED_REALTIME_PRIORITY_MAXIMUM;
            default -> EINVAL;
        };
    }

    /// Reports the minimum priority for a Linux scheduling policy.
    protected static long schedGetPriorityMin(long policy) {
        return switch ((int) policy) {
            case SCHED_OTHER, SCHED_BATCH, SCHED_IDLE -> 0;
            case SCHED_FIFO, SCHED_RR -> SCHED_REALTIME_PRIORITY_MINIMUM;
            default -> EINVAL;
        };
    }

    /// Reports a deterministic round-robin interval for the simulated scheduler.
    protected long schedRrGetInterval(long processId, long intervalAddress) {
        if (!isKnownSchedulerTarget(processId)) {
            return ESRCH;
        }

        writeTimespecFromNanoseconds(intervalAddress, SCHED_RR_INTERVAL_NANOSECONDS);
        return 0;
    }

    /// Returns true when a scheduling syscall target names this process or one of its guest threads.
    protected boolean isKnownSchedulerTarget(long processId) {
        return processId == 0 || processId == process.id() || isKnownGuestThreadId(processId);
    }

    /// Returns true when this simulator accepts the supplied Linux scheduling policy.
    protected static boolean isSupportedSchedulerPolicy(long policy) {
        return policy == SCHED_OTHER
                || policy == SCHED_FIFO
                || policy == SCHED_RR
                || policy == SCHED_BATCH
                || policy == SCHED_IDLE;
    }

    /// Returns true when the priority is in range for the supplied scheduling policy.
    protected static boolean isValidSchedulerPriority(long policy, int priority) {
        return switch ((int) policy) {
            case SCHED_OTHER, SCHED_BATCH, SCHED_IDLE -> priority == 0;
            case SCHED_FIFO, SCHED_RR -> priority >= SCHED_REALTIME_PRIORITY_MINIMUM
                    && priority <= SCHED_REALTIME_PRIORITY_MAXIMUM;
            default -> false;
        };
    }

    /// Applies Linux `setpriority` target selection and partial-update error retention.
    protected long setLinuxProcessPriority(long which, long who, long priority) {
        return setProcessPriority(which, who, priority, false, true);
    }

    /// Applies FreeBSD `setpriority` target selection and last-target error reporting.
    protected long setFreeBsdProcessPriority(long which, long who, long priority) {
        return setProcessPriority(which, who, priority, true, false);
    }

    /// Returns the lowest nice value selected by Linux `getpriority`.
    protected PriorityResult linuxProcessPriority(long which, long who) {
        return processPriority(which, who, false);
    }

    /// Returns the lowest nice value selected by FreeBSD `getpriority`.
    protected PriorityResult freeBsdProcessPriority(long which, long who) {
        return processPriority(which, who, true);
    }

    /// Applies one ABI's priority target selection, clamping, permissions, and multi-target error rule.
    private long setProcessPriority(
            long whichArgument,
            long whoArgument,
            long priorityArgument,
            boolean selectEffectiveUserId,
            boolean retainPreviousFailure) {
        int which = (int) whichArgument;
        if (which < PRIO_PROCESS || which > PRIO_USER) {
            return EINVAL;
        }

        int requestedNiceValue = (int) priorityArgument;
        int niceValue = Math.max(NICE_MINIMUM, Math.min(NICE_MAXIMUM, requestedNiceValue));
        ArrayList<GuestSyscalls> targets = processPriorityTargets(which, (int) whoArgument, selectEffectiveUserId);
        if (targets.isEmpty()) {
            return ESRCH;
        }

        long error = ESRCH;
        for (GuestSyscalls target : targets) {
            long targetError = setOneProcessPriority(target, niceValue);
            if (targetError != 0) {
                error = targetError;
            } else if (!retainPreviousFailure || error == ESRCH) {
                error = 0;
            }
        }
        return error;
    }

    /// Returns one ABI's lowest selected nice value without conflating negative values with errno results.
    private PriorityResult processPriority(long whichArgument, long whoArgument, boolean selectEffectiveUserId) {
        int which = (int) whichArgument;
        if (which < PRIO_PROCESS || which > PRIO_USER) {
            return new PriorityResult(0, EINVAL);
        }

        ArrayList<GuestSyscalls> targets = processPriorityTargets(which, (int) whoArgument, selectEffectiveUserId);
        if (targets.isEmpty()) {
            return new PriorityResult(0, ESRCH);
        }

        int niceValue = NICE_MAXIMUM;
        for (GuestSyscalls target : targets) {
            niceValue = Math.min(niceValue, target.process.niceValue());
        }
        return new PriorityResult(niceValue, 0);
    }

    /// Returns the current process and live direct children selected by one priority request.
    private ArrayList<GuestSyscalls> processPriorityTargets(
            int which,
            int who,
            boolean selectEffectiveUserId) {
        ArrayList<GuestSyscalls> targets = new ArrayList<>();
        if (which == PRIO_PROCESS) {
            if (who == 0 || who == process.id()) {
                targets.add(this);
                return targets;
            }
            synchronized (childProcessLock) {
                @Nullable ChildProcess child = childProcess(who);
                if (child != null && !child.exited()) {
                    targets.add(child.syscalls());
                }
            }
            return targets;
        }

        if (which == PRIO_PROCESS_GROUP) {
            int processGroupId = who == 0 ? process.processGroupId() : who;
            if (processGroupId <= 0) {
                return targets;
            }
            if (process.processGroupId() == processGroupId) {
                targets.add(this);
            }
            synchronized (childProcessLock) {
                for (ChildProcess child : childProcesses) {
                    if (!child.exited() && child.processGroupId() == processGroupId) {
                        targets.add(child.syscalls());
                    }
                }
            }
            return targets;
        }

        long userId = who == 0
                ? processPriorityUserId(this, selectEffectiveUserId)
                : Integer.toUnsignedLong(who);
        if (processPriorityUserId(this, selectEffectiveUserId) == userId) {
            targets.add(this);
        }
        synchronized (childProcessLock) {
            for (ChildProcess child : childProcesses) {
                GuestSyscalls childSyscalls = child.syscalls();
                if (!child.exited() && processPriorityUserId(childSyscalls, selectEffectiveUserId) == userId) {
                    targets.add(childSyscalls);
                }
            }
        }
        return targets;
    }

    /// Returns the real or effective user id used by one ABI's `PRIO_USER` selector.
    private static long processPriorityUserId(GuestSyscalls target, boolean selectEffectiveUserId) {
        return selectEffectiveUserId
                ? target.credentials.effectiveUserId()
                : target.credentials.realUserId();
    }

    /// Updates one target nice value after ownership and privilege checks.
    private long setOneProcessPriority(GuestSyscalls target, int niceValue) {
        long effectiveUserId = credentials.effectiveUserId();
        if (effectiveUserId != 0
                && effectiveUserId != target.credentials.realUserId()
                && effectiveUserId != target.credentials.effectiveUserId()) {
            return EPERM;
        }

        synchronized (target.process) {
            if (niceValue < target.process.niceValue() && effectiveUserId != 0) {
                return EACCES;
            }
            target.process.setNiceValue(niceValue);
        }
        return 0;
    }

    /// Accepts signal sends that target known guest processes.
    protected long kill(long processId, long signalNumber) {
        if (!isValidSignalNumber(signalNumber)) {
            return EINVAL;
        }
        if (processId == 0
                || processId == -1
                || processId == process.id()
                || processId == -process.processGroupId()
                || isKnownChildProcessId(processId)) {
            return 0;
        }
        return ESRCH;
    }

    /// Updates a current or direct-child process group under POSIX session constraints.
    protected long setpgid(long processId, long processGroupId) {
        int requestedProcessId = (int) processId;
        int requestedProcessGroupId = (int) processGroupId;
        if (requestedProcessGroupId < 0) {
            return EINVAL;
        }
        if (requestedProcessId < 0) {
            return ESRCH;
        }

        int targetProcessId = requestedProcessId == 0 ? process.id() : requestedProcessId;
        int targetProcessGroupId = requestedProcessGroupId == 0 ? targetProcessId : requestedProcessGroupId;
        if (targetProcessGroupId <= 0) {
            return EINVAL;
        }

        synchronized (childProcessLock) {
            GuestProcess targetProcess;
            @Nullable ChildProcess child;
            if (targetProcessId == process.id()) {
                targetProcess = process;
                child = null;
            } else {
                child = childProcess(targetProcessId);
                if (child == null || child.exited()) {
                    return ESRCH;
                }
                targetProcess = child.syscalls().process;
            }

            GuestSession currentSession = process.session();
            if (targetProcess.session() != currentSession || targetProcess.isSessionLeader()) {
                return EPERM;
            }

            @Nullable GuestSession targetGroupSession = knownProcessGroupSession(targetProcessGroupId);
            if (targetGroupSession == null && targetProcessGroupId != targetProcessId
                    || targetGroupSession != null && targetGroupSession != currentSession) {
                return EPERM;
            }

            targetProcess.setProcessGroupId(targetProcessGroupId);
            if (child == null) {
                updateParentChildProcessGroup(targetProcessGroupId);
            } else {
                child.setProcessGroupId(targetProcessGroupId);
            }
            return 0;
        }
    }

    /// Updates the parent process child record for this process when the parent is known.
    protected void updateParentChildProcessGroup(int processGroupId) {
        if (parentProcess == null) {
            return;
        }
        synchronized (parentProcess.childProcessLock) {
            @Nullable ChildProcess child = parentProcess.childProcess(process.id());
            if (child != null) {
                child.setProcessGroupId(processGroupId);
            }
        }
    }

    /// Returns the session containing a known process group, or null when the group is not represented.
    protected @Nullable GuestSession knownProcessGroupSession(int processGroupId) {
        if (process.processGroupId() == processGroupId) {
            return process.session();
        }
        synchronized (childProcessLock) {
            for (ChildProcess child : childProcesses) {
                if (!child.exited() && child.processGroupId() == processGroupId) {
                    return child.syscalls().process.session();
                }
            }
        }
        return parentProcess == null ? null : parentProcess.knownProcessGroupSession(processGroupId);
    }

    /// Returns true when a process group id names a represented live process group.
    protected boolean isKnownOrSelfProcessGroupId(int processGroupId) {
        return knownProcessGroupSession(processGroupId) != null;
    }

    /// Creates a new session and process group unless this process already leads a process group.
    protected long setsid() {
        synchronized (process) {
            if (process.isProcessGroupLeader() || knownProcessGroupSession(process.id()) != null) {
                return EPERM;
            }
            process.startNewSession();
        }
        updateParentChildProcessGroup(process.id());
        return process.id();
    }

    /// Returns true when a signal number is zero or a regular Linux signal.
    protected static boolean isValidSignalNumber(long signalNumber) {
        return signalNumber == 0 || (signalNumber >= MIN_SIGNAL_NUMBER && signalNumber <= MAX_SIGNAL_NUMBER);
    }

    /// Returns the Linux `sigset_t` bit for a signal number.
    protected static long signalMask(long signalNumber) {
        return 1L << (signalNumber - 1L);
    }

    /// Returns true when a thread id belongs to a live thread in the current guest process.
    protected boolean isKnownGuestThreadId(long threadId) {
        return guestThread(threadId) != null;
    }

    /// Returns the requested guest thread, or the current thread when the request id is zero.
    protected @Nullable GuestThread guestThread(RiscVThreadState currentState, long threadId) {
        if (threadId == 0) {
            return currentState.guestThread();
        }
        return guestThread(threadId);
    }

    /// Returns the live guest thread with the supplied thread id, or null when none is known.
    protected @Nullable GuestThread guestThread(long threadId) {
        if (threadId != (int) threadId) {
            return null;
        }

        synchronized (threadLock) {
            return guestThreadLocked((int) threadId);
        }
    }

    /// Returns the live guest thread with the supplied thread id while `threadLock` is held.
    protected @Nullable GuestThread guestThreadLocked(int threadId) {
        return process.thread(threadId);
    }

    /// Writes deterministic Linux `struct rusage` values for the supported `who` selectors.
    protected long getrusage(long who, long rusageAddress) {
        if (who != RUSAGE_SELF && who != RUSAGE_CHILDREN && who != RUSAGE_THREAD) {
            return EINVAL;
        }

        memory.clear(rusageAddress, RUSAGE_SIZE);
        if (who != RUSAGE_CHILDREN) {
            writeTimevalFromDuration(rusageAddress + RUSAGE_USER_TIME_OFFSET, elapsedDuration());
            writeTimevalFromDuration(rusageAddress + RUSAGE_SYSTEM_TIME_OFFSET, Duration.ZERO);
        }
        return 0;
    }

    /// Waits for an exited child process and reports its Linux wait status.
    protected long wait4(
            RiscVThreadState state,
            long processId,
            long statusAddress,
            long options,
            long rusageAddress) {
        long normalizedOptions = Integer.toUnsignedLong((int) options);
        if ((normalizedOptions & ~SUPPORTED_WAIT_OPTIONS) != 0) {
            return EINVAL;
        }
        if (statusAddress != 0 && !memory.isBacked(statusAddress, Integer.BYTES)) {
            return EFAULT;
        }
        if (rusageAddress != 0 && !memory.isBacked(rusageAddress, RUSAGE_SIZE)) {
            return EFAULT;
        }
        boolean waitForAllChildren = (normalizedOptions & WAIT_ALL_CHILDREN) != 0;
        boolean waitForCloneChildren = (normalizedOptions & WAIT_CLONE_CHILDREN) != 0;

        ChildWaitResult waitResult = waitForExitedChild(
                (int) processId,
                true,
                (normalizedOptions & WAIT_NO_HANG) != 0,
                false,
                waitForAllChildren || !waitForCloneChildren,
                waitForAllChildren || waitForCloneChildren,
                (normalizedOptions & WAIT_NOT_THREAD) != 0 ? state.guestThread().id() : 0);
        if (waitResult.result() <= 0) {
            return waitResult.result();
        }

        @Nullable ChildProcess exitedChild = waitResult.child();
        if (exitedChild == null) {
            throw new AssertionError("Successful child wait did not return a child process");
        }
        if (statusAddress != 0) {
            memory.writeInt(statusAddress, exitedChild.waitStatus());
        }
        if (rusageAddress != 0) {
            memory.clear(rusageAddress, RUSAGE_SIZE);
        }
        return exitedChild.processId();
    }

    /// Waits for a matching child exit, optionally observing it without consuming its wait status.
    ///
    /// @param processId the child id, `-1` for any child, zero for the current process group, or a negated group id
    /// @param reportExited whether normal child exits are reportable events
    /// @param noHang whether to return zero instead of blocking while a matching child is still running
    /// @param preserveWaitStatus whether to leave a reported child waitable by a later call
    /// @param includeNormalChildren whether children using `SIGCHLD` selection are eligible
    /// @param includeCloneChildren whether clone children using another exit signal are eligible
    /// @param parentThreadId the required creator thread id, or zero to accept children from any thread
    /// @return the wait result and the observed child when one was reported
    protected ChildWaitResult waitForExitedChild(
            long processId,
            boolean reportExited,
            boolean noHang,
            boolean preserveWaitStatus,
            boolean includeNormalChildren,
            boolean includeCloneChildren,
            int parentThreadId) {
        @Nullable ChildProcess exitedChild = null;
        while (true) {
            synchronized (childProcessLock) {
                if (processExitRequested || threadFailure != null) {
                    return new ChildWaitResult(EINTR, null);
                }
                boolean hasMatchingChild = false;
                for (int index = 0; index < childProcesses.size(); index++) {
                    ChildProcess child = childProcesses.get(index);
                    if (!child.matches(processId, process.processGroupId())) {
                        continue;
                    }
                    if (child.cloneChild() ? !includeCloneChildren : !includeNormalChildren) {
                        continue;
                    }
                    if (parentThreadId != 0 && child.parentThreadId() != parentThreadId) {
                        continue;
                    }
                    if (child.exited()) {
                        if (reportExited) {
                            hasMatchingChild = true;
                            exitedChild = child;
                            if (!preserveWaitStatus) {
                                childProcesses.remove(index);
                                child.markReaped();
                                notifyPollWaiters();
                            }
                            break;
                        }
                        continue;
                    }
                    hasMatchingChild = true;
                }

                if (exitedChild == null && hasMatchingChild) {
                    if (noHang) {
                        return new ChildWaitResult(0, null);
                    }
                    try {
                        childProcessLock.wait();
                    } catch (InterruptedException exception) {
                        Thread.currentThread().interrupt();
                        return new ChildWaitResult(EINTR, null);
                    }
                    continue;
                }
                if (!hasMatchingChild) {
                    return new ChildWaitResult(ECHILD, null);
                }
                break;
            }
        }

        joinChildProcess(exitedChild);
        return new ChildWaitResult(exitedChild.processId(), exitedChild);
    }

    /// Reports the simulated single CPU and NUMA node.
    protected long getcpu(long cpuAddress, long nodeAddress) {
        if (cpuAddress != 0) {
            memory.writeInt(cpuAddress, 0);
        }
        if (nodeAddress != 0) {
            memory.writeInt(nodeAddress, 0);
        }
        return 0;
    }

    /// Writes Linux `struct timeval` and optional `struct timezone` values.
    protected long gettimeofday(long timevalAddress, long timezoneAddress) {
        if (timevalAddress != 0) {
            Instant instant = timeSource.realtimeInstant();
            memory.writeLong(timevalAddress + TIMEVAL_SECONDS_OFFSET, instant.getEpochSecond());
            memory.writeLong(timevalAddress + TIMEVAL_MICROSECONDS_OFFSET, instant.getNano() / 1000L);
        }
        if (timezoneAddress != 0) {
            memory.writeInt(timezoneAddress + TIMEZONE_MINUTESWEST_OFFSET, 0);
            memory.writeInt(timezoneAddress + TIMEZONE_DSTTIME_OFFSET, 0);
        }
        return 0;
    }

    /// Reports the current value of a Linux interval timer.
    protected long getitimer(long which, long currentValueAddress) {
        int index = intervalTimerIndex(which);
        if (index < 0) {
            return EINVAL;
        }
        if (!memory.isBacked(currentValueAddress, ITIMERVAL_SIZE)) {
            return EFAULT;
        }

        writeIntervalTimerValue(index, currentValueAddress);
        return 0;
    }

    /// Sets a Linux interval timer and optionally reports its previous value.
    protected long setitimer(long which, long newValueAddress, long oldValueAddress) {
        int index = intervalTimerIndex(which);
        if (index < 0) {
            return EINVAL;
        }
        if (!memory.isBacked(newValueAddress, ITIMERVAL_SIZE)
                || (oldValueAddress != 0 && !memory.isBacked(oldValueAddress, ITIMERVAL_SIZE))) {
            return EFAULT;
        }

        long intervalMicroseconds = readTimevalMicroseconds(newValueAddress + ITIMERVAL_INTERVAL_OFFSET);
        long valueMicroseconds = readTimevalMicroseconds(newValueAddress + ITIMERVAL_VALUE_OFFSET);
        if (intervalMicroseconds < 0 || valueMicroseconds < 0) {
            return EINVAL;
        }

        if (oldValueAddress != 0) {
            writeIntervalTimerValue(index, oldValueAddress);
        }
        intervalTimerIntervalMicroseconds[index] = intervalMicroseconds;
        intervalTimerValueMicroseconds[index] = valueMicroseconds;
        intervalTimerStartMicroseconds[index] = elapsedMicroseconds();
        return 0;
    }

    /// Returns the tracked interval timer index for a Linux timer selector.
    protected static int intervalTimerIndex(long which) {
        return which >= ITIMER_REAL && which <= ITIMER_PROF ? (int) which : -1;
    }

    /// Writes the current tracked value for one Linux interval timer.
    protected void writeIntervalTimerValue(int index, long address) {
        writeItimerval(
                address,
                intervalTimerIntervalMicroseconds[index],
                currentIntervalTimerValueMicroseconds(index));
    }

    /// Returns the current remaining value for one Linux interval timer.
    protected long currentIntervalTimerValueMicroseconds(int index) {
        long valueMicroseconds = intervalTimerValueMicroseconds[index];
        if (valueMicroseconds == 0) {
            return 0;
        }

        long elapsedMicroseconds = elapsedMicroseconds() - intervalTimerStartMicroseconds[index];
        if (elapsedMicroseconds <= 0) {
            return valueMicroseconds;
        }
        if (elapsedMicroseconds < valueMicroseconds) {
            return valueMicroseconds - elapsedMicroseconds;
        }

        long intervalMicroseconds = intervalTimerIntervalMicroseconds[index];
        if (intervalMicroseconds == 0) {
            return 0;
        }

        long elapsedAfterFirstExpiry = elapsedMicroseconds - valueMicroseconds;
        long elapsedInsideInterval = elapsedAfterFirstExpiry % intervalMicroseconds;
        return elapsedInsideInterval == 0 ? intervalMicroseconds : intervalMicroseconds - elapsedInsideInterval;
    }

    /// Reads one Linux `struct timeval` as a non-negative microsecond duration.
    protected long readTimevalMicroseconds(long timevalAddress) {
        long seconds = memory.readLong(timevalAddress + TIMEVAL_SECONDS_OFFSET);
        long microseconds = memory.readLong(timevalAddress + TIMEVAL_MICROSECONDS_OFFSET);
        if (seconds < 0 || microseconds < 0 || microseconds >= 1_000_000L) {
            return -1;
        }
        if (seconds > (Long.MAX_VALUE - microseconds) / 1_000_000L) {
            return -1;
        }
        return seconds * 1_000_000L + microseconds;
    }

    /// Writes one Linux `struct itimerval` from microsecond durations.
    protected void writeItimerval(long itimervalAddress, long intervalMicroseconds, long valueMicroseconds) {
        writeTimevalFromMicroseconds(itimervalAddress + ITIMERVAL_INTERVAL_OFFSET, intervalMicroseconds);
        writeTimevalFromMicroseconds(itimervalAddress + ITIMERVAL_VALUE_OFFSET, valueMicroseconds);
    }

    /// Writes one Linux `struct timeval` from a non-negative microsecond duration.
    protected void writeTimevalFromMicroseconds(long timevalAddress, long microseconds) {
        memory.writeLong(timevalAddress + TIMEVAL_SECONDS_OFFSET, microseconds / 1_000_000L);
        memory.writeLong(timevalAddress + TIMEVAL_MICROSECONDS_OFFSET, microseconds % 1_000_000L);
    }

    /// Returns elapsed guest time in microseconds, saturating on overflow.
    protected long elapsedMicroseconds() {
        Duration duration = elapsedDuration();
        long seconds = duration.getSeconds();
        long micros = duration.getNano() / 1000L;
        return seconds > (Long.MAX_VALUE - micros) / 1_000_000L
                ? Long.MAX_VALUE
                : seconds * 1_000_000L + micros;
    }

    /// Returns the non-negative elapsed duration since the syscall handler was created.
    protected Duration elapsedDuration() {
        return timeSource.elapsedDuration();
    }

    /// Returns elapsed Linux clock ticks since the syscall handler was created.
    protected long elapsedClockTicks() {
        return durationToClockTicks(elapsedDuration());
    }

    /// Writes a Linux RISC-V 64-bit `struct timespec` for common clock ids.
    protected long clockGettime(long clockId, long timespecAddress) {
        if (!isSupportedClock(clockId)) {
            return EINVAL;
        }

        if (isRealtimeClock(clockId)) {
            writeTimespecFromInstant(timespecAddress, timeSource.realtimeInstant());
        } else {
            writeTimespecFromDuration(timespecAddress, elapsedDuration());
        }
        return 0;
    }

    /// Writes the resolution for a supported Linux clock.
    protected long clockGetres(long clockId, long timespecAddress) {
        if (!isSupportedClock(clockId)) {
            return EINVAL;
        }
        if (timespecAddress != 0) {
            memory.writeLong(timespecAddress + TIMESPEC_SECONDS_OFFSET, 0);
            memory.writeLong(timespecAddress + TIMESPEC_NANOSECONDS_OFFSET, 1);
        }
        return 0;
    }

    /// Writes a Linux RISC-V 64-bit `struct timeval` from a non-negative elapsed duration.
    protected void writeTimevalFromDuration(long timevalAddress, Duration duration) {
        memory.writeLong(timevalAddress + TIMEVAL_SECONDS_OFFSET, duration.getSeconds());
        memory.writeLong(timevalAddress + TIMEVAL_MICROSECONDS_OFFSET, duration.getNano() / 1000L);
    }

    /// Writes a Linux RISC-V 64-bit `struct timespec` from a clock instant.
    protected void writeTimespecFromInstant(long timespecAddress, Instant instant) {
        memory.writeLong(timespecAddress + TIMESPEC_SECONDS_OFFSET, instant.getEpochSecond());
        memory.writeLong(timespecAddress + TIMESPEC_NANOSECONDS_OFFSET, instant.getNano());
    }

    /// Writes a Linux RISC-V 64-bit `struct timespec` from a non-negative elapsed duration.
    protected void writeTimespecFromDuration(long timespecAddress, Duration duration) {
        if (duration.isNegative()) {
            memory.writeLong(timespecAddress + TIMESPEC_SECONDS_OFFSET, 0);
            memory.writeLong(timespecAddress + TIMESPEC_NANOSECONDS_OFFSET, 0);
            return;
        }

        memory.writeLong(timespecAddress + TIMESPEC_SECONDS_OFFSET, duration.getSeconds());
        memory.writeLong(timespecAddress + TIMESPEC_NANOSECONDS_OFFSET, duration.getNano());
    }

    /// Writes a Linux RISC-V 64-bit `struct timespec` from a non-negative nanosecond count.
    protected void writeTimespecFromNanoseconds(long timespecAddress, long nanoseconds) {
        memory.writeLong(timespecAddress + TIMESPEC_SECONDS_OFFSET, nanoseconds / NANOSECONDS_PER_SECOND);
        memory.writeLong(timespecAddress + TIMESPEC_NANOSECONDS_OFFSET, nanoseconds % NANOSECONDS_PER_SECOND);
    }

    /// Returns true when the supplied timespec fields represent a valid non-negative duration.
    protected static boolean isValidTimespec(long seconds, long nanoseconds) {
        return seconds >= 0 && nanoseconds >= 0 && nanoseconds < NANOSECONDS_PER_SECOND;
    }

    /// Converts a valid timespec to nanoseconds, saturating very large values.
    protected static long timespecToSaturatedNanoseconds(long seconds, long nanoseconds) {
        if (seconds > (Long.MAX_VALUE - nanoseconds) / NANOSECONDS_PER_SECOND) {
            return Long.MAX_VALUE;
        }
        return seconds * NANOSECONDS_PER_SECOND + nanoseconds;
    }

    /// Converts a non-negative duration to nanoseconds, saturating very large values.
    protected static long durationToSaturatedNanoseconds(Duration duration) {
        if (duration.isNegative()) {
            return 0;
        }
        return timespecToSaturatedNanoseconds(duration.getSeconds(), duration.getNano());
    }

    /// Converts a non-negative duration to Linux clock ticks, saturating very large values.
    protected static long durationToClockTicks(Duration duration) {
        long seconds = duration.getSeconds();
        long nanoseconds = duration.getNano();
        if (seconds > (Long.MAX_VALUE - CLOCK_TICKS_PER_SECOND) / CLOCK_TICKS_PER_SECOND) {
            return Long.MAX_VALUE;
        }
        long secondTicks = seconds * CLOCK_TICKS_PER_SECOND;
        long fractionalTicks = nanoseconds * CLOCK_TICKS_PER_SECOND / NANOSECONDS_PER_SECOND;
        return secondTicks > Long.MAX_VALUE - fractionalTicks ? Long.MAX_VALUE : secondTicks + fractionalTicks;
    }

    /// Returns true when `clock_gettime` accepts the supplied Linux clock id.
    protected static boolean isSupportedClock(long clockId) {
        return clockId == CLOCK_REALTIME
                || clockId == CLOCK_MONOTONIC
                || clockId == CLOCK_PROCESS_CPUTIME_ID
                || clockId == CLOCK_THREAD_CPUTIME_ID
                || clockId == CLOCK_MONOTONIC_RAW
                || clockId == CLOCK_REALTIME_COARSE
                || clockId == CLOCK_MONOTONIC_COARSE
                || clockId == CLOCK_BOOTTIME;
    }

    /// Returns true when `timerfd_create` accepts the supplied Linux clock id.
    protected static boolean isSupportedTimerfdClock(long clockId) {
        return clockId == CLOCK_REALTIME || clockId == CLOCK_MONOTONIC || clockId == CLOCK_BOOTTIME;
    }

    /// Returns true when the Linux clock id represents a wall-clock source.
    protected static boolean isRealtimeClock(long clockId) {
        return clockId == CLOCK_REALTIME || clockId == CLOCK_REALTIME_COARSE;
    }

    /// Adds two non-negative nanosecond values, saturating on overflow.
    protected static long saturatingAddNanoseconds(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    /// Multiplies two non-negative nanosecond values, saturating on overflow.
    protected static long saturatingMultiplyNanoseconds(long left, long right) {
        if (left == 0 || right == 0) {
            return 0;
        }
        return left > Long.MAX_VALUE / right ? Long.MAX_VALUE : left * right;
    }

    /// Implements `mmap` allocations and private regular-file mappings in the guest address space.
    protected long mmap(long address, long length, long protection, long flags, long fileDescriptor, long offset) {
        if (length <= 0 || offset < 0 || !isPageAligned(offset)) {
            return EINVAL;
        }
        if ((protection & ~SUPPORTED_MMAP_PROTECTION_MASK) != 0) {
            return EINVAL;
        }

        long mappingType = flags & MAP_TYPE;
        if (mappingType != MAP_PRIVATE && mappingType != MAP_SHARED && mappingType != MAP_SHARED_VALIDATE) {
            return EINVAL;
        }
        boolean shared = mappingType == MAP_SHARED || mappingType == MAP_SHARED_VALIDATE;
        boolean anonymous = (flags & MAP_ANONYMOUS) != 0;
        @Nullable OpenFile mappedFile = null;
        @Nullable DeviceFile mappedDeviceFile = null;
        if (!anonymous) {
            if (fileDescriptor < 0) {
                return EBADF;
            }
            mappedFile = openFile((int) fileDescriptor);
            if (mappedFile == null || mappedFile.isDirectory()) {
                return EBADF;
            }
            mappedDeviceFile = deviceFileFor(mappedFile);
            if (mappedDeviceFile != null) {
                if (mappedDeviceFile != DeviceFile.FRAMEBUFFER || framebufferDevice == null) {
                    return ENODEV;
                }
                if (!shared) {
                    return EINVAL;
                }
                if ((protection & Memory.PROTECTION_WRITE) != 0 && !mappedFile.writable()) {
                    return EACCES;
                }
            } else if (!mappedFile.isHostFile()) {
                return EBADF;
            }
            if (!mappedFile.readable()) {
                return EACCES;
            }
            if (mappedDeviceFile == null && shared && (protection & Memory.PROTECTION_WRITE) != 0) {
                return EACCES;
            }
        }

        boolean hugeTlb = (flags & MAP_HUGETLB) != 0;
        if (!anonymous && hugeTlb) {
            return ENODEV;
        }
        long mappingAlignment = hugeTlb ? memory.hugePageSize() : pageSize;
        long alignedLength = alignUp(length, mappingAlignment);
        if (alignedLength <= 0) {
            return ENOMEM;
        }

        long mappingAddress;
        if (requiresFixedMapping(flags)) {
            if (!isPageAligned(address) || (hugeTlb && !isAligned(address, mappingAlignment))
                    || !isValidGuestRange(address, alignedLength)) {
                return ENOMEM;
            }
            if ((flags & MAP_FIXED_NOREPLACE) != 0 && overlapsMemoryMappings(address, alignedLength)) {
                return EEXIST;
            }
            removeMemoryMappings(address, alignedLength);
            mappingAddress = address;
        } else {
            mappingAddress = findMmapAddress(address, alignedLength, mappingAlignment);
            if (mappingAddress == 0) {
                return ENOMEM;
            }
        }

        long backingProtection = anonymous || !isMemoryBackedProtection(protection)
                ? protection
                : Memory.PROTECTION_READ_WRITE_EXECUTE;
        if (!ensureMemoryBacking(mappingAddress, alignedLength, backingProtection, hugeTlb)) {
            return ENOMEM;
        }
        if (anonymous) {
            if (isMemoryBackedProtection(protection)) {
                memory.clear(mappingAddress, alignedLength);
            }
        } else if (isMemoryBackedProtection(protection)) {
            assert mappedFile != null;
            long loadResult = mappedDeviceFile == DeviceFile.FRAMEBUFFER
                    ? loadFramebufferMapping(mappingAddress, length, alignedLength, offset, protection)
                    : loadFileMapping(mappedFile, mappingAddress, length, alignedLength, offset, protection);
            if (loadResult != 0) {
                memory.unmap(mappingAddress, alignedLength);
                return loadResult;
            }
        }
        addMemoryMapping(
                mappingAddress,
                alignedLength,
                protection,
                mappedFile == null ? null : mappedFile.guestPath(),
                mappedFile == null ? 0 : offset,
                shared,
                mappedDeviceFile);
        return mappingAddress;
    }

    /// Copies a private file mapping into guest memory and applies the requested final protection.
    protected long loadFileMapping(
            OpenFile mappedFile,
            long mappingAddress,
            long requestedLength,
            long alignedLength,
            long offset,
            long protection) {
        SeekableByteChannel channel = mappedFile.channel();
        try {
            memory.clear(mappingAddress, alignedLength);
            long fileSize = channel.size();
            if (offset < fileSize) {
                long remaining = Math.min(requestedLength, fileSize - offset);
                long destinationAddress = mappingAddress;
                long previousPosition = channel.position();
                try {
                    channel.position(offset);
                    ByteBuffer buffer = ByteBuffer.allocate(8192);
                    while (remaining > 0) {
                        buffer.clear();
                        buffer.limit((int) Math.min(buffer.capacity(), remaining));
                        int count = channel.read(buffer);
                        if (count < 0) {
                            break;
                        }
                        memory.writeBytes(destinationAddress, buffer.array(), 0, count);
                        destinationAddress += count;
                        remaining -= count;
                    }
                } finally {
                    channel.position(previousPosition);
                }
            }
            if (!memory.protect(mappingAddress, alignedLength, protection)) {
                return ENOMEM;
            }
            return 0;
        } catch (IOException | RiscVException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Copies framebuffer bytes into guest memory and applies the requested final protection.
    protected long loadFramebufferMapping(
            long mappingAddress,
            long requestedLength,
            long alignedLength,
            long offset,
            long protection) {
        @Nullable FramebufferDevice device = framebufferDevice;
        if (device == null) {
            return ENODEV;
        }

        try {
            memory.clear(mappingAddress, alignedLength);
            long framebufferSize = device.geometry().bufferSizeBytes();
            if (offset < framebufferSize) {
                long remaining = Math.min(requestedLength, framebufferSize - offset);
                long destinationAddress = mappingAddress;
                long framebufferOffset = offset;
                byte[] buffer = new byte[(int) Math.min(8192L, remaining)];
                while (remaining > 0) {
                    int chunkLength = (int) Math.min(buffer.length, remaining);
                    int count = device.read(framebufferOffset, buffer, 0, chunkLength);
                    if (count <= 0) {
                        break;
                    }
                    memory.writeBytes(destinationAddress, buffer, 0, count);
                    destinationAddress += count;
                    framebufferOffset += count;
                    remaining -= count;
                }
            }
            if (!memory.protect(mappingAddress, alignedLength, protection)) {
                return ENOMEM;
            }
            return 0;
        } catch (IndexOutOfBoundsException | RiscVException exception) {
            return EACCES;
        }
    }

    /// Implements `munmap` by releasing tracked anonymous mappings.
    protected long munmap(long address, long length) {
        if (length <= 0 || !isPageAligned(address)) {
            return EINVAL;
        }

        long alignedLength = alignUp(length, pageSize);
        if (alignedLength <= 0 || !isValidGuestRange(address, alignedLength)) {
            return EINVAL;
        }

        removeMemoryMappings(address, alignedLength);
        return 0;
    }

    /// Writes the configured real, effective, and saved user or group id values.
    protected long getresid(
            long realIdAddress,
            long effectiveIdAddress,
            long savedIdAddress,
            long realId,
            long effectiveId,
            long savedId) {
        if (!memory.isBacked(realIdAddress, Integer.BYTES)
                || !memory.isBacked(effectiveIdAddress, Integer.BYTES)
                || !memory.isBacked(savedIdAddress, Integer.BYTES)) {
            return EFAULT;
        }
        memory.writeInt(realIdAddress, GuestCredentials.idToInt(realId));
        memory.writeInt(effectiveIdAddress, GuestCredentials.idToInt(effectiveId));
        memory.writeInt(savedIdAddress, GuestCredentials.idToInt(savedId));
        return 0;
    }

    /// Implements `mprotect` for tracked anonymous mappings and the initial memory window.
    protected long mprotect(long address, long length, long protection) {
        if (!isPageAligned(address) || length < 0 || (protection & ~SUPPORTED_MMAP_PROTECTION_MASK) != 0) {
            return EINVAL;
        }
        if (length == 0) {
            return 0;
        }

        long alignedLength = alignUp(length, pageSize);
        if (alignedLength <= 0 || !isValidGuestRange(address, alignedLength)) {
            return ENOMEM;
        }
        if (!isMappedRange(address, alignedLength)) {
            return ENOMEM;
        }
        if (!prepareMemoryProtection(address, alignedLength, protection)) {
            return ENOMEM;
        }

        updateMemoryMappingsProtection(address, alignedLength, protection);
        return 0;
    }

    /// Implements Linux `madvise` hints that static runtimes commonly emit.
    protected long madvise(long address, long length, long advice) {
        if (!isPageAligned(address) || length < 0 || !isSupportedMemoryAdvice(advice)) {
            return EINVAL;
        }
        if (length == 0) {
            return 0;
        }

        long alignedLength = alignUp(length, pageSize);
        if (alignedLength <= 0 || !isValidGuestRange(address, alignedLength)) {
            return ENOMEM;
        }
        if (!isMappedRange(address, alignedLength)) {
            return ENOMEM;
        }

        if (advice == MADV_DONTNEED || advice == MADV_FREE || advice == MADV_DONTNEED_LOCKED) {
            clearAdvisedMemory(address, alignedLength);
        } else if (advice == MADV_HUGEPAGE || advice == MADV_NOHUGEPAGE) {
            memory.adviseHugePagePreference(address, alignedLength, advice == MADV_HUGEPAGE);
        }
        return 0;
    }

    /// Accepts `msync` for mapped guest pages without host file-sync side effects.
    protected long msync(long address, long length, long flags) {
        if (!isPageAligned(address) || length < 0 || !isSupportedMemorySyncFlags(flags)) {
            return EINVAL;
        }
        if (length == 0) {
            return 0;
        }

        long alignedLength = alignUp(length, pageSize);
        if (alignedLength <= 0 || !isValidGuestRange(address, alignedLength)) {
            return ENOMEM;
        }
        return isMappedRange(address, alignedLength) ? 0 : ENOMEM;
    }

    /// Returns true when Linux `msync` flags are supported and not contradictory.
    protected static boolean isSupportedMemorySyncFlags(long flags) {
        if ((flags & ~(MS_ASYNC | MS_INVALIDATE | MS_SYNC)) != 0) {
            return false;
        }
        return (flags & (MS_ASYNC | MS_SYNC)) != (MS_ASYNC | MS_SYNC);
    }

    /// Accepts `mlock` for mapped guest pages without host page-locking side effects.
    protected long mlock(long address, long length) {
        return validateMemoryLockRange(address, length);
    }

    /// Accepts `mlock2` for mapped guest pages without host page-locking side effects.
    protected long mlock2(long address, long length, long flags) {
        if ((flags & ~MLOCK_ONFAULT) != 0) {
            return EINVAL;
        }
        return validateMemoryLockRange(address, length);
    }

    /// Accepts `munlock` for mapped guest pages without host page-locking side effects.
    protected long munlock(long address, long length) {
        return validateMemoryLockRange(address, length);
    }

    /// Accepts Linux process-wide memory-lock requests as deterministic no-ops.
    protected static long mlockall(long flags) {
        long lockSelectionFlags = flags & (MCL_CURRENT | MCL_FUTURE);
        if ((flags & ~(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)) != 0
                || lockSelectionFlags == 0) {
            return EINVAL;
        }
        return 0;
    }

    /// Accepts Linux process-wide memory unlock requests as deterministic no-ops.
    protected static long munlockall() {
        return 0;
    }

    /// Validates a Linux memory lock range after applying page-boundary rounding.
    protected long validateMemoryLockRange(long address, long length) {
        if (length < 0) {
            return EINVAL;
        }
        if (length == 0) {
            return 0;
        }
        if (!isValidGuestRange(address, length)) {
            return ENOMEM;
        }

        long alignedAddress = alignDown(address, pageSize);
        long endAddress = address + length;
        long alignedEndAddress = alignUp(endAddress, pageSize);
        if (alignedEndAddress <= 0 || alignedEndAddress < alignedAddress) {
            return ENOMEM;
        }

        long alignedLength = alignedEndAddress - alignedAddress;
        return isMappedRange(alignedAddress, alignedLength) ? 0 : ENOMEM;
    }

    /// Writes a Linux RISC-V 64-bit `struct rlimit64`.
    protected void writeResourceLimit(long address, long current, long maximum) {
        memory.writeLong(address + RLIMIT_CURRENT_OFFSET, current);
        memory.writeLong(address + RLIMIT_MAXIMUM_OFFSET, maximum);
    }

    /// Fills a guest buffer with bytes from the deterministic random source.
    protected long writeDeterministicRandomBytes(long address, long length) {
        byte[] bytes = new byte[(int) length];
        fillDeterministicRandomBytes(bytes, 0, bytes.length);
        memory.writeBytes(address, bytes, 0, bytes.length);
        return bytes.length;
    }

    /// Fills a host byte array range from the deterministic random source.
    protected void fillDeterministicRandomBytes(byte[] bytes, int offset, int length) {
        for (int index = 0; index < length; index++) {
            bytes[offset + index] = nextRandomByte();
        }
    }

    /// Reads a null-terminated UTF-8 path string from guest memory.
    protected @Nullable String readGuestPath(long address) {
        byte[] bytes = new byte[PATH_MAX];
        for (int index = 0; index < bytes.length; index++) {
            int value = memory.readUnsignedByte(address + index);
            if (value == 0) {
                return new String(bytes, 0, index, StandardCharsets.UTF_8);
            }
            bytes[index] = (byte) value;
        }
        return null;
    }

    /// Reads a null-terminated guest pointer vector containing UTF-8 strings for `execve`.
    protected String @Nullable @Unmodifiable [] readGuestStringVector(long vectorAddress) {
        if (vectorAddress == 0) {
            return new String[0];
        }

        long totalBytes = 0;
        ArrayList<String> strings = new ArrayList<>();
        for (int index = 0; index < EXECVE_MAX_VECTOR_ENTRIES; index++) {
            long pointer = memory.readLong(vectorAddress + (long) index * Long.BYTES);
            if (pointer == 0) {
                return strings.toArray(String[]::new);
            }

            byte[] bytes = readGuestCStringBytes(pointer, EXECVE_MAX_STRING_BYTES);
            if (bytes.length >= EXECVE_MAX_STRING_BYTES) {
                return null;
            }
            totalBytes += bytes.length + 1L;
            if (totalBytes > EXECVE_MAX_TOTAL_STRING_BYTES) {
                return null;
            }
            strings.add(new String(bytes, StandardCharsets.UTF_8));
        }
        return null;
    }

    /// Resolves a guest path below a configured virtual filesystem.
    protected @Nullable VirtualPath resolveVirtualPath(long directoryFileDescriptor, String guestPath) {
        return resolveVirtualPath(directoryFileDescriptor, guestPath, true);
    }

    /// Resolves a guest path below a configured virtual filesystem.
    protected @Nullable VirtualPath resolveVirtualPath(
            long directoryFileDescriptor,
            String guestPath,
            boolean followFinalSymbolicLink) {
        @Nullable String absoluteGuestPath = absoluteGuestPath(directoryFileDescriptor, guestPath);
        if (absoluteGuestPath == null) {
            return null;
        }
        return fileSystem.resolveVirtualPath(absoluteGuestPath, followFinalSymbolicLink);
    }

    /// Resolves an absolute guest path below a selected virtual filesystem.
    protected @Nullable VirtualPath resolveVirtualPath(
            VirtualMount virtualMount,
            String absoluteGuestPath,
            boolean followFinalSymbolicLink) {
        return fileSystem.resolveVirtualPath(virtualMount, absoluteGuestPath, followFinalSymbolicLink);
    }

    /// Reads a little-endian 64-bit value without requiring guest alignment.
    protected long readLongUnaligned(long address) {
        long value = 0;
        for (int index = 0; index < Long.BYTES; index++) {
            value |= (long) memory.readUnsignedByte(address + index) << (index * Byte.SIZE);
        }
        return value;
    }

    /// Writes a little-endian 64-bit value without requiring guest alignment.
    protected void writeLongUnaligned(long address, long value) {
        byte[] bytes = new byte[Long.BYTES];
        for (int index = 0; index < bytes.length; index++) {
            bytes[index] = (byte) (value >>> (index * Byte.SIZE));
        }
        memory.writeBytes(address, bytes, 0, bytes.length);
    }

    /// Provides a container-style resolver configuration when the mounted root lacks one.
    protected static final class ResolvConfFileSystem implements GuestFileSystem.VirtualFileSystem {
        /// Returns the synthetic resolver configuration node.
        @Override
        public @Nullable VirtualNode node(String absoluteGuestPath) {
            return RESOLV_CONF_PATH.equals(absoluteGuestPath)
                    ? VirtualNode.file(RESOLV_CONF_PATH, RESOLV_CONF_PATH)
                    : null;
        }

        /// Returns no children because this virtual mount is a single regular file.
        @Override
        public VirtualNode @Unmodifiable [] childNodes(String directoryGuestPath) {
            return new VirtualNode[0];
        }

        /// Returns host resolver configuration bytes, falling back to public recursive resolvers.
        @Override
        public byte @Unmodifiable [] fileData(VirtualNode node) {
            return resolvConfData();
        }

        /// Returns an empty link target because this virtual filesystem has no symbolic links.
        @Override
        public String linkTarget(VirtualNode node) {
            return "";
        }

        /// Returns resolver configuration bytes copied from the host when available.
        private static byte @Unmodifiable [] resolvConfData() {
            try {
                byte[] bytes = Files.readAllBytes(Path.of(RESOLV_CONF_PATH));
                if (bytes.length > 0 && bytes.length <= 64 * 1024 && containsNameserverDirective(bytes)) {
                    return bytes;
                }
            } catch (IOException | SecurityException exception) {
                return fallbackResolvConfData();
            }
            return fallbackResolvConfData();
        }

        /// Returns true when resolver bytes contain a `nameserver` directive.
        private static boolean containsNameserverDirective(byte @Unmodifiable [] bytes) {
            for (String line : new String(bytes, StandardCharsets.US_ASCII).split("\n")) {
                if (line.stripLeading().startsWith("nameserver")) {
                    return true;
                }
            }
            return false;
        }

        /// Returns a small static resolver configuration for hosts without `/etc/resolv.conf`.
        private static byte @Unmodifiable [] fallbackResolvConfData() {
            return asciiBytes("nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
        }
    }

    /// Identifies the built-in virtual device nodes exposed below `/dev`.
    protected enum DeviceFile {
        /// The guest controlling terminal.
        TTY,

        /// The guest console alias for the controlling terminal.
        CONSOLE,

        /// The byte sink and end-of-file source exposed as `/dev/null`.
        NULL,

        /// The zero byte source exposed as `/dev/zero`.
        ZERO,

        /// The blocking random source exposed as `/dev/random`.
        RANDOM,

        /// The non-blocking random source exposed as `/dev/urandom`.
        URANDOM,

        /// The pseudoterminal multiplexer exposed as `/dev/ptmx`.
        PTMX,

        /// The first pseudoterminal slave exposed as `/dev/pts/0`.
        PTS0,

        /// The optional linear framebuffer exposed as `/dev/fb0`.
        FRAMEBUFFER
    }

    /// Provides the built-in process-local `/dev` filesystem.
    protected static final class DevFileSystem implements GuestFileSystem.VirtualFileSystem {
        /// The optional framebuffer device exposed as `/dev/fb0`.
        private final @Nullable FramebufferDevice framebufferDevice;

        /// Creates a device filesystem.
        private DevFileSystem(@Nullable FramebufferDevice framebufferDevice) {
            this.framebufferDevice = framebufferDevice;
        }

        /// Returns a device node at an absolute guest path, or null when absent.
        @Override
        public @Nullable VirtualNode node(String absoluteGuestPath) {
            return devNode(absoluteGuestPath, framebufferDevice != null);
        }

        /// Returns the child device nodes for `/dev` or `/dev/pts`.
        @Override
        public VirtualNode @Unmodifiable [] childNodes(String directoryGuestPath) {
            if (DEV_MOUNT_PATH.concat("/pts").equals(directoryGuestPath)) {
                return new VirtualNode[]{VirtualNode.characterDevice(DEV_MOUNT_PATH + "/pts/0", DeviceFile.PTS0)};
            }
            if (!DEV_MOUNT_PATH.equals(directoryGuestPath)) {
                return new VirtualNode[0];
            }
            ArrayList<VirtualNode> children = new ArrayList<>();
            children.add(VirtualNode.characterDevice(DEV_MOUNT_PATH + "/console", DeviceFile.CONSOLE));
            if (framebufferDevice != null) {
                children.add(VirtualNode.characterDevice(DEV_MOUNT_PATH + "/fb0", DeviceFile.FRAMEBUFFER));
            }
            children.add(VirtualNode.symbolicLink(DEV_MOUNT_PATH + "/fd", PROC_MOUNT_PATH + "/self/fd"));
            children.add(VirtualNode.characterDevice(DEV_MOUNT_PATH + "/null", DeviceFile.NULL));
            children.add(VirtualNode.characterDevice(DEV_MOUNT_PATH + "/ptmx", DeviceFile.PTMX));
            children.add(VirtualNode.directory(DEV_MOUNT_PATH + "/pts"));
            children.add(VirtualNode.characterDevice(DEV_MOUNT_PATH + "/random", DeviceFile.RANDOM));
            children.add(VirtualNode.symbolicLink(DEV_MOUNT_PATH + "/stderr", PROC_MOUNT_PATH + "/self/fd/2"));
            children.add(VirtualNode.symbolicLink(DEV_MOUNT_PATH + "/stdin", PROC_MOUNT_PATH + "/self/fd/0"));
            children.add(VirtualNode.symbolicLink(DEV_MOUNT_PATH + "/stdout", PROC_MOUNT_PATH + "/self/fd/1"));
            children.add(VirtualNode.characterDevice(DEV_MOUNT_PATH + "/tty", DeviceFile.TTY));
            children.add(VirtualNode.characterDevice(DEV_MOUNT_PATH + "/urandom", DeviceFile.URANDOM));
            children.add(VirtualNode.characterDevice(DEV_MOUNT_PATH + "/zero", DeviceFile.ZERO));
            return children.toArray(VirtualNode[]::new);
        }

        /// Returns empty bytes because `/dev` does not expose regular files.
        @Override
        public byte @Unmodifiable [] fileData(VirtualNode node) {
            return new byte[0];
        }

        /// Returns the target of the `/dev/fd` symbolic link.
        @Override
        public String linkTarget(VirtualNode node) {
            @Nullable String target = node.linkTarget();
            return target == null ? "" : target;
        }

        /// Returns one built-in `/dev` node.
        private static @Nullable VirtualNode devNode(String absoluteGuestPath, boolean hasFramebuffer) {
            return switch (absoluteGuestPath) {
                case DEV_MOUNT_PATH -> VirtualNode.directory(DEV_MOUNT_PATH);
                case DEV_MOUNT_PATH + "/console" ->
                        VirtualNode.characterDevice(absoluteGuestPath, DeviceFile.CONSOLE);
                case DEV_MOUNT_PATH + "/fb0" -> hasFramebuffer
                        ? VirtualNode.characterDevice(absoluteGuestPath, DeviceFile.FRAMEBUFFER)
                        : null;
                case DEV_MOUNT_PATH + "/fd" ->
                        VirtualNode.symbolicLink(absoluteGuestPath, PROC_MOUNT_PATH + "/self/fd");
                case DEV_MOUNT_PATH + "/null" ->
                        VirtualNode.characterDevice(absoluteGuestPath, DeviceFile.NULL);
                case DEV_MOUNT_PATH + "/ptmx" ->
                        VirtualNode.characterDevice(absoluteGuestPath, DeviceFile.PTMX);
                case DEV_MOUNT_PATH + "/pts" ->
                        VirtualNode.directory(absoluteGuestPath);
                case DEV_MOUNT_PATH + "/pts/0" ->
                        VirtualNode.characterDevice(absoluteGuestPath, DeviceFile.PTS0);
                case DEV_MOUNT_PATH + "/random" ->
                        VirtualNode.characterDevice(absoluteGuestPath, DeviceFile.RANDOM);
                case DEV_MOUNT_PATH + "/stderr" ->
                        VirtualNode.symbolicLink(absoluteGuestPath, PROC_MOUNT_PATH + "/self/fd/2");
                case DEV_MOUNT_PATH + "/stdin" ->
                        VirtualNode.symbolicLink(absoluteGuestPath, PROC_MOUNT_PATH + "/self/fd/0");
                case DEV_MOUNT_PATH + "/stdout" ->
                        VirtualNode.symbolicLink(absoluteGuestPath, PROC_MOUNT_PATH + "/self/fd/1");
                case DEV_MOUNT_PATH + "/tty" ->
                        VirtualNode.characterDevice(absoluteGuestPath, DeviceFile.TTY);
                case DEV_MOUNT_PATH + "/urandom" ->
                        VirtualNode.characterDevice(absoluteGuestPath, DeviceFile.URANDOM);
                case DEV_MOUNT_PATH + "/zero" ->
                        VirtualNode.characterDevice(absoluteGuestPath, DeviceFile.ZERO);
                default -> null;
            };
        }
    }

    /// Identifies sys regular files whose payload is generated on demand.
    protected enum SysFile {
        /// `/sys/devices/virtual/dmi/id/board_name`.
        BOARD_NAME,

        /// `/sys/devices/virtual/dmi/id/board_vendor`.
        BOARD_VENDOR,

        /// `/sys/devices/virtual/dmi/id/product_family`.
        PRODUCT_FAMILY,

        /// `/sys/devices/virtual/dmi/id/product_name`.
        PRODUCT_NAME,

        /// `/sys/devices/virtual/dmi/id/sys_vendor`.
        SYS_VENDOR
    }

    /// Provides the built-in read-only virtual sys filesystem.
    protected static final class SysFileSystem implements GuestFileSystem.VirtualFileSystem {
        /// Returns a sys node at an absolute guest path, or null when absent.
        @Override
        public @Nullable VirtualNode node(String absoluteGuestPath) {
            return switch (absoluteGuestPath) {
                case SYS_MOUNT_PATH -> VirtualNode.directory(absoluteGuestPath);
                case SYS_MOUNT_PATH + "/bus" -> VirtualNode.directory(absoluteGuestPath);
                case SYS_MOUNT_PATH + "/bus/pci" -> VirtualNode.directory(absoluteGuestPath);
                case SYS_MOUNT_PATH + "/bus/pci/devices" -> VirtualNode.directory(absoluteGuestPath);
                case SYS_MOUNT_PATH + "/class" -> VirtualNode.directory(absoluteGuestPath);
                case SYS_MOUNT_PATH + "/class/dmi" -> VirtualNode.directory(absoluteGuestPath);
                case SYS_MOUNT_PATH + "/class/dmi/id" ->
                        VirtualNode.symbolicLink(absoluteGuestPath, SYS_MOUNT_PATH + "/devices/virtual/dmi/id");
                case SYS_MOUNT_PATH + "/class/drm" -> VirtualNode.directory(absoluteGuestPath);
                case SYS_MOUNT_PATH + "/class/graphics" -> VirtualNode.directory(absoluteGuestPath);
                case SYS_MOUNT_PATH + "/class/power_supply" -> VirtualNode.directory(absoluteGuestPath);
                case SYS_MOUNT_PATH + "/devices" -> VirtualNode.directory(absoluteGuestPath);
                case SYS_MOUNT_PATH + "/devices/virtual" -> VirtualNode.directory(absoluteGuestPath);
                case SYS_MOUNT_PATH + "/devices/virtual/dmi" -> VirtualNode.directory(absoluteGuestPath);
                case SYS_MOUNT_PATH + "/devices/virtual/dmi/id" -> VirtualNode.directory(absoluteGuestPath);
                case SYS_MOUNT_PATH + "/devices/virtual/dmi/id/board_name" ->
                        VirtualNode.file(absoluteGuestPath, SysFile.BOARD_NAME);
                case SYS_MOUNT_PATH + "/devices/virtual/dmi/id/board_vendor" ->
                        VirtualNode.file(absoluteGuestPath, SysFile.BOARD_VENDOR);
                case SYS_MOUNT_PATH + "/devices/virtual/dmi/id/product_family" ->
                        VirtualNode.file(absoluteGuestPath, SysFile.PRODUCT_FAMILY);
                case SYS_MOUNT_PATH + "/devices/virtual/dmi/id/product_name" ->
                        VirtualNode.file(absoluteGuestPath, SysFile.PRODUCT_NAME);
                case SYS_MOUNT_PATH + "/devices/virtual/dmi/id/sys_vendor" ->
                        VirtualNode.file(absoluteGuestPath, SysFile.SYS_VENDOR);
                default -> null;
            };
        }

        /// Returns child sys nodes for a directory.
        @Override
        public VirtualNode @Unmodifiable [] childNodes(String directoryGuestPath) {
            return switch (directoryGuestPath) {
                case SYS_MOUNT_PATH -> new VirtualNode[]{
                        VirtualNode.directory(SYS_MOUNT_PATH + "/bus"),
                        VirtualNode.directory(SYS_MOUNT_PATH + "/class"),
                        VirtualNode.directory(SYS_MOUNT_PATH + "/devices")
                };
                case SYS_MOUNT_PATH + "/bus" -> new VirtualNode[]{
                        VirtualNode.directory(SYS_MOUNT_PATH + "/bus/pci")
                };
                case SYS_MOUNT_PATH + "/bus/pci" -> new VirtualNode[]{
                        VirtualNode.directory(SYS_MOUNT_PATH + "/bus/pci/devices")
                };
                case SYS_MOUNT_PATH + "/bus/pci/devices" -> new VirtualNode[0];
                case SYS_MOUNT_PATH + "/class" -> new VirtualNode[]{
                        VirtualNode.directory(SYS_MOUNT_PATH + "/class/dmi"),
                        VirtualNode.directory(SYS_MOUNT_PATH + "/class/drm"),
                        VirtualNode.directory(SYS_MOUNT_PATH + "/class/graphics"),
                        VirtualNode.directory(SYS_MOUNT_PATH + "/class/power_supply")
                };
                case SYS_MOUNT_PATH + "/class/dmi" -> new VirtualNode[]{
                        VirtualNode.symbolicLink(
                                SYS_MOUNT_PATH + "/class/dmi/id",
                                SYS_MOUNT_PATH + "/devices/virtual/dmi/id")
                };
                case SYS_MOUNT_PATH + "/class/drm",
                     SYS_MOUNT_PATH + "/class/graphics",
                     SYS_MOUNT_PATH + "/class/power_supply" -> new VirtualNode[0];
                case SYS_MOUNT_PATH + "/devices" -> new VirtualNode[]{
                        VirtualNode.directory(SYS_MOUNT_PATH + "/devices/virtual")
                };
                case SYS_MOUNT_PATH + "/devices/virtual" -> new VirtualNode[]{
                        VirtualNode.directory(SYS_MOUNT_PATH + "/devices/virtual/dmi")
                };
                case SYS_MOUNT_PATH + "/devices/virtual/dmi" -> new VirtualNode[]{
                        VirtualNode.directory(SYS_MOUNT_PATH + "/devices/virtual/dmi/id")
                };
                case SYS_MOUNT_PATH + "/devices/virtual/dmi/id" -> new VirtualNode[]{
                        VirtualNode.file(SYS_MOUNT_PATH + "/devices/virtual/dmi/id/board_name", SysFile.BOARD_NAME),
                        VirtualNode.file(SYS_MOUNT_PATH + "/devices/virtual/dmi/id/board_vendor", SysFile.BOARD_VENDOR),
                        VirtualNode.file(
                                SYS_MOUNT_PATH + "/devices/virtual/dmi/id/product_family",
                                SysFile.PRODUCT_FAMILY),
                        VirtualNode.file(SYS_MOUNT_PATH + "/devices/virtual/dmi/id/product_name", SysFile.PRODUCT_NAME),
                        VirtualNode.file(SYS_MOUNT_PATH + "/devices/virtual/dmi/id/sys_vendor", SysFile.SYS_VENDOR)
                };
                default -> new VirtualNode[0];
            };
        }

        /// Returns generated bytes for a sys regular file.
        @Override
        public byte @Unmodifiable [] fileData(VirtualNode node) {
            Object fileKey = node.fileKey();
            if (!(fileKey instanceof SysFile file)) {
                return new byte[0];
            }

            return switch (file) {
                case BOARD_NAME, PRODUCT_NAME -> asciiBytes("JRISC-V\n");
                case BOARD_VENDOR, SYS_VENDOR -> asciiBytes("Glavo\n");
                case PRODUCT_FAMILY -> asciiBytes("RV64 user-mode emulator\n");
            };
        }

        /// Returns the target of a sys symbolic link.
        @Override
        public String linkTarget(VirtualNode node) {
            @Nullable String target = node.linkTarget();
            return target == null ? "" : target;
        }
    }

    /// Identifies proc regular files whose payload is generated on demand.
    protected enum ProcFile {
        /// `/proc/cpuinfo`.
        CPUINFO,

        /// `/proc/meminfo`.
        MEMINFO,

        /// `/proc/stat`.
        STAT,

        /// `/proc/uptime`.
        UPTIME,

        /// `/proc/version`.
        VERSION,

        /// `/proc/self/auxv`.
        AUXV,

        /// `/proc/self/cmdline`.
        CMDLINE,

        /// `/proc/self/environ`.
        ENVIRON,

        /// `/proc/self/maps`.
        MAPS,

        /// `/proc/self/mountinfo`.
        MOUNTINFO,

        /// `/proc/self/mounts`.
        MOUNTS,

        /// `/proc/self/stat`.
        PROCESS_STAT,

        /// `/proc/self/status`.
        STATUS
    }

    /// Returns the proc node at an absolute guest path, or null when it is absent.
    protected @Nullable VirtualNode procNode(String absoluteGuestPath) {
        @Nullable String path = normalizeAbsoluteGuestPath(absoluteGuestPath);
        if (path == null || !guestPathMatchesMount(path, PROC_MOUNT_PATH)) {
            return null;
        }

        if (PROC_MOUNT_PATH.equals(path)) {
            return VirtualNode.directory(path);
        }
        if ((PROC_MOUNT_PATH + "/self").equals(path)) {
            return VirtualNode.symbolicLink(path, Integer.toString(process.id()));
        }
        if ((PROC_MOUNT_PATH + "/" + process.id()).equals(path)) {
            return VirtualNode.directory(path);
        }
        if ((PROC_MOUNT_PATH + "/cpuinfo").equals(path)) {
            return VirtualNode.file(path, ProcFile.CPUINFO);
        }
        if ((PROC_MOUNT_PATH + "/meminfo").equals(path)) {
            return VirtualNode.file(path, ProcFile.MEMINFO);
        }
        if ((PROC_MOUNT_PATH + "/mounts").equals(path)) {
            return VirtualNode.symbolicLink(path, "self/mounts");
        }
        if ((PROC_MOUNT_PATH + "/stat").equals(path)) {
            return VirtualNode.file(path, ProcFile.STAT);
        }
        if ((PROC_MOUNT_PATH + "/uptime").equals(path)) {
            return VirtualNode.file(path, ProcFile.UPTIME);
        }
        if ((PROC_MOUNT_PATH + "/version").equals(path)) {
            return VirtualNode.file(path, ProcFile.VERSION);
        }

        String processPrefix = PROC_MOUNT_PATH + "/" + process.id();
        if ((processPrefix + "/auxv").equals(path)) {
            return VirtualNode.file(path, ProcFile.AUXV);
        }
        if ((processPrefix + "/cmdline").equals(path)) {
            return VirtualNode.file(path, ProcFile.CMDLINE);
        }
        if ((processPrefix + "/cwd").equals(path)) {
            return VirtualNode.symbolicLink(path, guestWorkingDirectory);
        }
        if ((processPrefix + "/environ").equals(path)) {
            return VirtualNode.file(path, ProcFile.ENVIRON);
        }
        if ((processPrefix + "/exe").equals(path)) {
            return VirtualNode.symbolicLink(path, procExecutablePath);
        }
        if ((processPrefix + "/fd").equals(path)) {
            return VirtualNode.directory(path);
        }
        if (path.startsWith(processPrefix + "/fd/")) {
            @Nullable Integer fileDescriptor = parseProcFileDescriptor(path.substring((processPrefix + "/fd/").length()));
            if (fileDescriptor == null || !isOpenFileDescriptor(fileDescriptor)) {
                return null;
            }
            return VirtualNode.symbolicLink(path, procFileDescriptorTarget(fileDescriptor));
        }
        if ((processPrefix + "/maps").equals(path)) {
            return VirtualNode.file(path, ProcFile.MAPS);
        }
        if ((processPrefix + "/mountinfo").equals(path)) {
            return VirtualNode.file(path, ProcFile.MOUNTINFO);
        }
        if ((processPrefix + "/mounts").equals(path)) {
            return VirtualNode.file(path, ProcFile.MOUNTS);
        }
        if ((processPrefix + "/root").equals(path)) {
            return VirtualNode.symbolicLink(path, "/");
        }
        if ((processPrefix + "/stat").equals(path)) {
            return VirtualNode.file(path, ProcFile.PROCESS_STAT);
        }
        if ((processPrefix + "/status").equals(path)) {
            return VirtualNode.file(path, ProcFile.STATUS);
        }

        return null;
    }

    /// Returns child proc nodes for a directory.
    protected ArrayList<VirtualNode> procChildNodes(String directoryGuestPath) {
        ArrayList<VirtualNode> children = new ArrayList<>();
        if (PROC_MOUNT_PATH.equals(directoryGuestPath)) {
            addProcChild(children, PROC_MOUNT_PATH + "/" + process.id());
            addProcChild(children, PROC_MOUNT_PATH + "/cpuinfo");
            addProcChild(children, PROC_MOUNT_PATH + "/meminfo");
            addProcChild(children, PROC_MOUNT_PATH + "/mounts");
            addProcChild(children, PROC_MOUNT_PATH + "/self");
            addProcChild(children, PROC_MOUNT_PATH + "/stat");
            addProcChild(children, PROC_MOUNT_PATH + "/uptime");
            addProcChild(children, PROC_MOUNT_PATH + "/version");
            return children;
        }

        String processPrefix = PROC_MOUNT_PATH + "/" + process.id();
        if (processPrefix.equals(directoryGuestPath)) {
            addProcChild(children, processPrefix + "/auxv");
            addProcChild(children, processPrefix + "/cmdline");
            addProcChild(children, processPrefix + "/cwd");
            addProcChild(children, processPrefix + "/environ");
            addProcChild(children, processPrefix + "/exe");
            addProcChild(children, processPrefix + "/fd");
            addProcChild(children, processPrefix + "/maps");
            addProcChild(children, processPrefix + "/mountinfo");
            addProcChild(children, processPrefix + "/mounts");
            addProcChild(children, processPrefix + "/root");
            addProcChild(children, processPrefix + "/stat");
            addProcChild(children, processPrefix + "/status");
            return children;
        }

        if ((processPrefix + "/fd").equals(directoryGuestPath)) {
            for (int fileDescriptor = 0; fileDescriptor <= 2; fileDescriptor++) {
                addProcChild(children, directoryGuestPath + "/" + fileDescriptor);
            }
            for (int index = 0; index < openFiles.size(); index++) {
                if (openFiles.get(index) != null) {
                    addProcChild(children, directoryGuestPath + "/" + (index + 3));
                }
            }
        }
        return children;
    }

    /// Adds an existing proc child to a directory listing.
    protected void addProcChild(ArrayList<VirtualNode> children, String guestPath) {
        @Nullable VirtualNode node = procNode(guestPath);
        if (node != null) {
            children.add(node);
        }
    }

    /// Provides process-local virtual procfs nodes to the shared guest filesystem layer.
    protected final class ProcFileSystem implements GuestFileSystem.VirtualFileSystem {
        /// Returns the proc node at an absolute guest path, or null when absent.
        @Override
        public @Nullable VirtualNode node(String absoluteGuestPath) {
            return procNode(absoluteGuestPath);
        }

        /// Returns child proc nodes for a directory.
        @Override
        public VirtualNode @Unmodifiable [] childNodes(String directoryGuestPath) {
            return procChildNodes(directoryGuestPath).toArray(VirtualNode[]::new);
        }

        /// Returns generated bytes for a proc regular file.
        @Override
        public byte @Unmodifiable [] fileData(VirtualNode node) {
            return procFileData(node);
        }

        /// Returns the symbolic-link target for a proc symbolic link.
        @Override
        public String linkTarget(VirtualNode node) {
            return procLinkTarget(node);
        }
    }

    /// Returns generated file bytes for a proc regular file.
    protected byte @Unmodifiable [] procFileData(VirtualNode node) {
        Object fileKey = node.fileKey();
        if (!(fileKey instanceof ProcFile file)) {
            return new byte[0];
        }

        return switch (file) {
            case AUXV -> auxiliaryVectorBytes.clone();
            case CMDLINE -> procCommandLineBytes.clone();
            case CPUINFO -> asciiBytes(procCpuinfo());
            case ENVIRON -> procEnvironmentBytes.clone();
            case MAPS -> asciiBytes(procMaps());
            case MEMINFO -> asciiBytes(procMeminfo());
            case MOUNTINFO -> asciiBytes(procMountinfo());
            case MOUNTS -> asciiBytes(procMounts());
            case PROCESS_STAT -> asciiBytes(procProcessStat());
            case STAT -> asciiBytes(procStat());
            case STATUS -> asciiBytes(procStatus());
            case UPTIME -> asciiBytes(procUptime());
            case VERSION -> asciiBytes("Linux version 6.12.0 (jriscv) #1 SMP riscv64\n");
        };
    }

    /// Returns the byte size exposed for a virtual node.
    protected long virtualNodeSize(VirtualMount mount, VirtualNode node) {
        if (node.fileKey() == DeviceFile.FRAMEBUFFER && framebufferDevice != null) {
            return framebufferDevice.geometry().bufferSizeBytes();
        }
        if (node.isFile()) {
            return mount.fileSystem().fileData(node).length;
        }
        if (node.isSymbolicLink()) {
            return mount.fileSystem().linkTarget(node).getBytes(StandardCharsets.UTF_8).length;
        }
        return 0;
    }

    /// Returns the symbolic-link target for a proc node.
    protected String procLinkTarget(VirtualNode node) {
        @Nullable String target = node.linkTarget();
        return target == null ? "" : target;
    }

    /// Returns the target exposed by `/proc/self/fd/<n>`.
    protected String procFileDescriptorTarget(int fileDescriptor) {
        int standardFileDescriptor = standardFileDescriptorFor(fileDescriptor);
        if (standardFileDescriptor >= 0) {
            return "/dev/tty";
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null) {
            return "/dev/null";
        }
        @Nullable String guestPath = openFile.guestPath();
        if (guestPath != null) {
            return guestPath;
        }
        if (openFile.isPipe()) {
            return "pipe:[" + fileDescriptor + "]";
        }
        if (openFile.isEventFile()) {
            return "anon_inode:[eventfd]";
        }
        if (openFile.isEpollFile()) {
            return "anon_inode:[eventpoll]";
        }
        return "anon_inode:[jriscv]";
    }

    /// Parses a decimal file descriptor from a proc path segment.
    protected static @Nullable Integer parseProcFileDescriptor(String value) {
        if (value.isEmpty()) {
            return null;
        }
        int result = 0;
        for (int index = 0; index < value.length(); index++) {
            char ch = value.charAt(index);
            if (ch < '0' || ch > '9') {
                return null;
            }
            int digit = ch - '0';
            if (result > (Integer.MAX_VALUE - digit) / 10) {
                return null;
            }
            result = result * 10 + digit;
        }
        return result;
    }

    /// Encodes US-ASCII proc text.
    protected static byte @Unmodifiable [] asciiBytes(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    /// Returns `/proc/cpuinfo` content.
    protected static String procCpuinfo() {
        return "processor\t: 0\n"
                + "hart\t\t: 0\n"
                + "isa\t\t: rv64imafdc_zicsr_zifencei_zba_zbb_zbs_v\n"
                + "mmu\t\t: sv48\n"
                + "uarch\t\t: glavo,jriscv\n"
                + "java_version\t: " + procCpuinfoProperty("java.version") + "\n"
                + "java_vm_name\t: " + procCpuinfoProperty("java.vm.name") + "\n"
                + "java_vm_version\t: " + procCpuinfoProperty("java.vm.version") + "\n"
                + "java_vendor\t: " + procCpuinfoProperty("java.vendor") + "\n";
    }

    /// Returns a host Java system property sanitized for `/proc/cpuinfo`.
    protected static String procCpuinfoProperty(String propertyName) {
        return sanitizeProcCpuinfoValue(System.getProperty(propertyName, "unknown"));
    }

    /// Restricts generated `/proc/cpuinfo` values to one printable ASCII line.
    protected static String sanitizeProcCpuinfoValue(String value) {
        StringBuilder result = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char ch = value.charAt(index);
            result.append(ch >= 0x20 && ch <= 0x7e ? ch : ' ');
        }

        String sanitized = result.toString().trim();
        return sanitized.isEmpty() ? "unknown" : sanitized;
    }

    /// Returns `/proc/meminfo` content.
    protected String procMeminfo() {
        long totalKiB = Math.max(1L, memory.size() / 1024L);
        long freeKiB = Math.max(1L, (memory.endAddress() - programBreak) / 1024L);
        return "MemTotal:       " + totalKiB + " kB\n"
                + "MemFree:        " + freeKiB + " kB\n"
                + "MemAvailable:   " + freeKiB + " kB\n"
                + "Buffers:        0 kB\n"
                + "Cached:         0 kB\n";
    }

    /// Returns `/proc/stat` content.
    protected String procStat() {
        long ticks = elapsedClockTicks();
        return "cpu  " + ticks + " 0 0 0 0 0 0 0 0 0\n"
                + "cpu0 " + ticks + " 0 0 0 0 0 0 0 0 0\n"
                + "intr 0\n"
                + "ctxt 0\n"
                + "btime 0\n"
                + "processes 1\n"
                + "procs_running 1\n"
                + "procs_blocked 0\n";
    }

    /// Returns `/proc/uptime` content.
    protected String procUptime() {
        long nanoseconds = Math.max(0L, elapsedDuration().toNanos());
        long seconds = nanoseconds / NANOSECONDS_PER_SECOND;
        long centiseconds = nanoseconds % NANOSECONDS_PER_SECOND / 10_000_000L;
        return seconds + "." + twoDigits(centiseconds) + " " + seconds + "." + twoDigits(centiseconds) + "\n";
    }

    /// Returns `/proc/self/maps` content for tracked mappings.
    protected String procMaps() {
        StringBuilder builder = new StringBuilder();
        for (MemoryMapping mapping : memoryMappings) {
            builder.append(Long.toUnsignedString(mapping.address(), 16))
                    .append('-')
                    .append(Long.toUnsignedString(mapping.endAddress(), 16))
                    .append(' ')
                    .append(memoryProtectionString(mapping.protection(), mapping.shared()))
                    .append(' ');
            appendPaddedHex(builder, mapping.fileOffset(), 8);
            builder.append(" 00:00 0");
            @Nullable String path = mapping.path();
            if (path != null) {
                builder.append("    ").append(path);
            }
            builder.append('\n');
        }
        return builder.toString();
    }

    /// Returns `/proc/self/mountinfo` content for the synthetic guest root mount.
    protected static String procMountinfo() {
        return "1 0 0:1 / / rw,relatime - jriscv jriscv rw\n";
    }

    /// Returns `/proc/self/mounts` content for the synthetic guest root mount.
    protected static String procMounts() {
        return "jriscv / jriscv rw,relatime 0 0\n";
    }

    /// Returns `/proc/self/stat` content.
    protected String procProcessStat() {
        long ticks = elapsedClockTicks();
        return process.id() + " (" + processNameString() + ") R "
                + process.parentId() + ' '
                + process.processGroupId() + ' '
                + process.processGroupId()
                + " 0 -1 0 0 0 0 0 "
                + ticks + ' ' + ticks
                + " 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
    }

    /// Returns `/proc/self/status` content.
    protected String procStatus() {
        return "Name:\t" + processNameString() + "\n"
                + "State:\tR (running)\n"
                + "Tgid:\t" + process.id() + "\n"
                + "Pid:\t" + process.id() + "\n"
                + "PPid:\t" + process.parentId() + "\n"
                + "TracerPid:\t0\n"
                + "Uid:\t" + credentials.realUserId()
                + "\t" + credentials.effectiveUserId()
                + "\t" + credentials.savedUserId()
                + "\t" + credentials.effectiveUserId() + "\n"
                + "Gid:\t" + credentials.realGroupId()
                + "\t" + credentials.effectiveGroupId()
                + "\t" + credentials.savedGroupId()
                + "\t" + credentials.effectiveGroupId() + "\n"
                + "Threads:\t" + process.threadCount() + "\n";
    }

    /// Returns the current process name without trailing nul bytes.
    protected String processNameString() {
        int length = 0;
        while (length < processName.length && processName[length] != 0) {
            length++;
        }
        return length == 0 ? "jriscv" : new String(processName, 0, length, StandardCharsets.US_ASCII);
    }

    /// Formats a two-digit non-negative decimal number below 100.
    protected static String twoDigits(long value) {
        return value < 10 ? "0" + value : Long.toString(value);
    }

    /// Returns Linux `maps` permission text for a memory protection mask.
    protected static String memoryProtectionString(long protection, boolean shared) {
        return ((protection & Memory.PROTECTION_READ) != 0 ? "r" : "-")
                + ((protection & Memory.PROTECTION_WRITE) != 0 ? "w" : "-")
                + ((protection & Memory.PROTECTION_EXECUTE) != 0 ? "x" : "-")
                + (shared ? "s" : "p");
    }

    /// Appends an unsigned hexadecimal value padded to at least the requested digit count.
    protected static void appendPaddedHex(StringBuilder builder, long value, int digits) {
        String text = Long.toUnsignedString(value, 16);
        for (int index = text.length(); index < digits; index++) {
            builder.append('0');
        }
        builder.append(text);
    }

    /// Returns true when a non-empty guest path can be resolved from the supplied directory descriptor.
    protected boolean canResolvePathFrom(long directoryFileDescriptor, String guestPath) {
        if (directoryFileDescriptor == AT_FDCWD || isAbsoluteGuestPath(guestPath)) {
            return true;
        }
        if (directoryFileDescriptor < Integer.MIN_VALUE || directoryFileDescriptor > Integer.MAX_VALUE) {
            return false;
        }

        @Nullable OpenFile openFile = openFile((int) directoryFileDescriptor);
        return openFile != null && openFile.isDirectory();
    }

    /// Resolves a guest path below a configured filesystem mount or an open directory descriptor.
    protected @Nullable Path resolveHostFile(long directoryFileDescriptor, String guestPath) {
        @Nullable String absoluteGuestPath = absoluteGuestPath(directoryFileDescriptor, guestPath);
        if (absoluteGuestPath == null) {
            return null;
        }

        return fileSystem.resolveHostFile(absoluteGuestPath);
    }

    /// Resolves a guest path below a configured tar filesystem mount.
    protected @Nullable TarPath resolveTarPath(long directoryFileDescriptor, String guestPath) {
        return resolveTarPath(directoryFileDescriptor, guestPath, true);
    }

    /// Resolves a guest path below a configured tar filesystem mount with optional final symlink following.
    protected @Nullable TarPath resolveTarPath(
            long directoryFileDescriptor,
            String guestPath,
            boolean followFinalSymbolicLink) {
        @Nullable String absoluteGuestPath = absoluteGuestPath(directoryFileDescriptor, guestPath);
        if (absoluteGuestPath == null) {
            return null;
        }

        return fileSystem.resolveTarPath(absoluteGuestPath, followFinalSymbolicLink);
    }

    /// Converts a guest path and directory descriptor into an absolute normalized Linux path.
    protected @Nullable String absoluteGuestPath(long directoryFileDescriptor, String guestPath) {
        if (guestPath.indexOf('\\') >= 0 || guestPath.indexOf(':') >= 0) {
            return null;
        }
        if (isAbsoluteGuestPath(guestPath)) {
            return normalizeAbsoluteGuestPath(guestPath);
        }

        String basePath;
        if (directoryFileDescriptor != AT_FDCWD) {
            @Nullable OpenFile directory = openFile((int) directoryFileDescriptor);
            if (directory == null || !directory.isDirectory()) {
                return null;
            }
            @Nullable String descriptorGuestPath = directory.guestPath();
            if (descriptorGuestPath != null) {
                basePath = descriptorGuestPath;
            } else {
                @Nullable Path path = directory.path();
                if (path == null) {
                    return null;
                }
                @Nullable String guestDirectoryPath = guestPathForHostFile(path);
                if (guestDirectoryPath == null) {
                    return null;
                }
                basePath = guestDirectoryPath;
            }
        } else {
            basePath = guestWorkingDirectory;
        }

        return normalizeAbsoluteGuestPath(basePath + "/" + guestPath);
    }

    /// Returns true when the guest path is absolute in Linux path syntax.
    protected static boolean isAbsoluteGuestPath(String guestPath) {
        return GuestFileSystem.isAbsoluteGuestPath(guestPath);
    }

    /// Normalizes an absolute Linux guest path without allowing it to escape above `/`.
    protected static @Nullable String normalizeAbsoluteGuestPath(String guestPath) {
        return GuestFileSystem.normalizeAbsoluteGuestPath(guestPath);
    }

    /// Returns true when a host file's canonical location stays below its selected mount root.
    protected boolean canonicalFileStaysBelowMount(Path hostFile) throws IOException {
        @Nullable HostMount mount = mountForHostFile(hostFile);
        if (mount == null) {
            return false;
        }
        return hostFile.toRealPath().startsWith(mount.root().toRealPath());
    }

    /// Returns true when a host file is selected by a read-only bind mount.
    protected boolean hostFileOnReadOnlyMount(Path hostFile) {
        @Nullable HostMount mount = mountForHostFile(hostFile);
        return mount != null && mount.readOnly();
    }

    /// Checks search permission on the parent directory used to reach a host path.
    protected long accessHostParent(Path hostFile) throws IOException {
        @Nullable HostMount mount = mountForHostFile(hostFile);
        if (mount == null) {
            return EACCES;
        }
        Path canonicalRoot = mount.root().toRealPath();
        try {
            Path canonicalHostFile = hostFile.toRealPath();
            if (canonicalHostFile.toString().equals(canonicalRoot.toString())) {
                return 0;
            }
        } catch (IOException exception) {
            // A nofollow operation can still access the parent of a broken or external symlink.
        }

        @Nullable Path parent = hostFile.getParent();
        if (parent == null) {
            return EACCES;
        }
        Path canonicalParent = parent.toRealPath();
        if (!canonicalParent.startsWith(canonicalRoot)) {
            return EACCES;
        }

        ArrayList<Path> ancestors = new ArrayList<>();
        @Nullable Path current = canonicalParent;
        while (current != null) {
            if (!current.startsWith(canonicalRoot)) {
                return EACCES;
            }
            ancestors.add(current);
            if (current.toString().equals(canonicalRoot.toString())) {
                break;
            }
            current = current.getParent();
        }
        if (ancestors.isEmpty() || !ancestors.get(ancestors.size() - 1).toString().equals(canonicalRoot.toString())) {
            return EACCES;
        }

        for (int index = ancestors.size() - 1; index >= 0; index--) {
            GuestFileMetadata metadata = hostFileMetadata(ancestors.get(index), true);
            if (!canAccess(metadata, X_OK, true)) {
                return EACCES;
            }
        }
        return 0;
    }

    /// Returns the guest-visible metadata for a host file.
    protected GuestFileMetadata hostFileMetadata(Path hostFile, boolean directory) throws IOException {
        return fileMetadataStore.getOrCreate(hostFile, initialHostFileMetadata(hostFile, directory));
    }

    /// Returns the guest-visible metadata inferred for a host file before guest-side changes.
    protected GuestFileMetadata initialHostFileMetadata(Path hostFile, boolean directory) {
        return new GuestFileMetadata(credentials.effectiveUserId(), credentials.effectiveGroupId(), initialHostFileMode(hostFile, directory));
    }

    /// Returns the initial guest-visible permission bits inferred for a host file.
    protected int initialHostFileMode(Path hostFile, boolean directory) {
        int permissions = 0;
        if (Files.isReadable(hostFile)) {
            permissions |= directory ? STAT_MODE_READ_EXECUTE_ALL : STAT_MODE_READ_ALL;
        }
        if (!hostFileOnReadOnlyMount(hostFile) && Files.isWritable(hostFile)) {
            permissions |= 0222;
        }
        return permissions;
    }

    /// Returns true when the current effective credentials can access a metadata record.
    protected boolean canAccess(GuestFileMetadata metadata, long accessMode, boolean directory) {
        return canAccess(metadata.mode(), metadata.userId(), metadata.groupId(), accessMode, directory);
    }

    /// Returns true when the current effective credentials can access a tar node.
    protected boolean canAccess(TarNode node, long accessMode) {
        return canAccess(node.permissions(), node.userId(), node.groupId(), accessMode, node.isDirectory());
    }

    /// Returns true when all tar parent directories are searchable by the current credentials.
    protected boolean canSearchTarAncestors(TarNode node) {
        @Nullable TarNode parent = node.parent();
        while (parent != null) {
            if (!canAccess(parent, X_OK)) {
                return false;
            }
            parent = parent.parent();
        }
        return true;
    }

    /// Returns true when a tar directory and its parent directories satisfy path access.
    protected boolean canAccessTarDirectory(TarNode directory, long accessMode) {
        return directory.isDirectory() && canAccess(directory, accessMode) && canSearchTarAncestors(directory);
    }

    /// Returns the group id assigned to a newly created host entry below a directory.
    protected long createdEntryGroupId(GuestFileMetadata parentMetadata) {
        return (parentMetadata.mode() & STAT_MODE_SET_GROUP_ID) != 0
                ? parentMetadata.groupId()
                : credentials.effectiveGroupId();
    }

    /// Returns the group id assigned to a newly created tar entry below a directory.
    protected long createdEntryGroupId(TarNode parent) {
        return (parent.permissions() & STAT_MODE_SET_GROUP_ID) != 0
                ? parent.groupId()
                : credentials.effectiveGroupId();
    }

    /// Returns the mode assigned to a newly created regular file.
    protected int createdFileMode(long mode) {
        return ((int) mode & STAT_MODE_CHANGE_BITS) & ~fileCreationMask;
    }

    /// Returns the mode assigned to a newly created host directory below a directory.
    protected int createdDirectoryMode(GuestFileMetadata parentMetadata, long mode) {
        int directoryMode = ((int) mode & STAT_MODE_CHANGE_BITS) & ~fileCreationMask;
        return (parentMetadata.mode() & STAT_MODE_SET_GROUP_ID) == 0
                ? directoryMode
                : directoryMode | STAT_MODE_SET_GROUP_ID;
    }

    /// Returns the mode assigned to a newly created tar directory below a directory.
    protected int createdDirectoryMode(TarNode parent, long mode) {
        int directoryMode = ((int) mode & STAT_MODE_CHANGE_BITS) & ~fileCreationMask;
        return (parent.permissions() & STAT_MODE_SET_GROUP_ID) == 0
                ? directoryMode
                : directoryMode | STAT_MODE_SET_GROUP_ID;
    }

    /// Returns true when a sticky directory needs ownership checks for entry mutation.
    protected boolean hasStickyMutationRestriction(GuestFileMetadata directoryMetadata) {
        return credentials.effectiveUserId() != 0 && (directoryMetadata.mode() & STAT_MODE_STICKY) != 0;
    }

    /// Returns true when a sticky tar directory needs ownership checks for entry mutation.
    protected boolean hasStickyMutationRestriction(TarNode directory) {
        return credentials.effectiveUserId() != 0 && (directory.permissions() & STAT_MODE_STICKY) != 0;
    }

    /// Returns true when the current credentials may mutate an entry in a sticky host directory.
    protected boolean canMutateStickyDirectory(GuestFileMetadata directoryMetadata, GuestFileMetadata nodeMetadata) {
        long userId = credentials.effectiveUserId();
        return userId == directoryMetadata.userId() || userId == nodeMetadata.userId();
    }

    /// Returns true when the current credentials may mutate an entry in a sticky tar directory.
    protected boolean canMutateStickyDirectory(TarNode directory, TarNode node) {
        long userId = credentials.effectiveUserId();
        return userId == directory.userId() || userId == node.userId();
    }

    /// Returns the tar parent directory selected by an absolute guest path.
    protected @Nullable TarNode tarParentDirectory(TarMount mount, String guestPath) {
        String relativePath = GuestFileSystem.relativeGuestPath(guestPath, mount.guestPath());
        int separator = relativePath.lastIndexOf('/');
        String parentPath = separator < 0 ? "" : relativePath.substring(0, separator);
        @Nullable TarNode parent = mount.fileSystem().node(parentPath);
        return parent != null && parent.isDirectory() ? parent : null;
    }

    /// Returns true when the current effective credentials can access a virtual node.
    protected boolean canAccess(VirtualNode node, long accessMode) {
        return canAccess(
                node.permissions(),
                credentials.effectiveUserId(),
                credentials.effectiveGroupId(),
                accessMode,
                node.isDirectory());
    }

    /// Returns true when the current effective credentials satisfy Linux owner, group, or other permissions.
    protected boolean canAccess(int permissions, long ownerId, long groupId, long accessMode, boolean directory) {
        if (accessMode == F_OK) {
            return true;
        }
        if (credentials.effectiveUserId() == 0) {
            return (accessMode & X_OK) == 0 || directory || (permissions & 0111) != 0;
        }
        int permissionClass = permissionClass(permissions, ownerId, groupId);
        return hasRequestedAccess(permissionClass, accessMode);
    }

    /// Returns the three permission bits selected by Linux owner, group, and other matching.
    protected int permissionClass(int permissions, long ownerId, long groupId) {
        int permissionBits = permissions & STAT_MODE_ALL;
        if (credentials.effectiveUserId() == ownerId) {
            return (permissionBits >>> 6) & 07;
        }
        if (credentials.effectiveGroupId() == groupId || hasSupplementaryGroup(groupId)) {
            return (permissionBits >>> 3) & 07;
        }
        return permissionBits & 07;
    }

    /// Returns true when the effective supplementary groups contain the supplied gid.
    protected boolean hasSupplementaryGroup(long groupId) {
        for (int index = 0; index < credentials.supplementaryGroupCount(); index++) {
            if (credentials.supplementaryGroupAt(index) == groupId) {
                return true;
            }
        }
        return false;
    }

    /// Returns true when a selected permission class satisfies a requested Linux access mode.
    protected static boolean hasRequestedAccess(int permissionClass, long accessMode) {
        if ((accessMode & R_OK) != 0 && (permissionClass & 04) == 0) {
            return false;
        }
        if ((accessMode & W_OK) != 0 && (permissionClass & 02) == 0) {
            return false;
        }
        return (accessMode & X_OK) == 0 || (permissionClass & 01) != 0;
    }

    /// Returns the sandboxed host directory backing the guest-visible current working directory.
    protected @Nullable Path currentHostWorkingDirectory() {
        return resolveHostFile(AT_FDCWD, guestWorkingDirectory);
    }

    /// Converts a sandboxed host path to an absolute guest-visible Linux path.
    protected @Nullable String guestPathForHostFile(Path hostFile) {
        @Nullable HostMount mount = mountForHostFile(hostFile);
        if (mount == null) {
            return null;
        }

        Path normalizedRoot = mount.root().normalize();
        Path normalizedHostFile = hostFile.normalize();
        if (!normalizedHostFile.startsWith(normalizedRoot)) {
            return null;
        }

        try {
            String relativePath = normalizedRoot.relativize(normalizedHostFile).toString().replace('\\', '/');
            if (relativePath.isEmpty()) {
                return mount.guestPath();
            }
            return "/".equals(mount.guestPath()) ? "/" + relativePath : mount.guestPath() + "/" + relativePath;
        } catch (IllegalArgumentException | SecurityException exception) {
            return null;
        }
    }

    /// Validates that a file's parent directory exists inside the selected filesystem mount.
    protected long validateSandboxedParent(Path hostFile) {
        try {
            @Nullable HostMount mount = mountForHostFile(hostFile);
            if (mount == null) {
                return EACCES;
            }

            @Nullable Path parent = hostFile.getParent();
            if (parent == null) {
                return EACCES;
            }
            if (!Files.exists(parent)) {
                return ENOENT;
            }
            if (!Files.isDirectory(parent)) {
                return ENOTDIR;
            }
            if (!parent.toRealPath().startsWith(mount.root().toRealPath())) {
                return EACCES;
            }
            return 0;
        } catch (IOException | SecurityException exception) {
            return EACCES;
        }
    }

    /// Returns true when the host path names an existing entry or a symbolic link.
    protected static boolean pathEntryExists(Path hostFile) {
        return GuestFileSystem.pathEntryExists(hostFile);
    }

    /// Encodes Linux auxiliary-vector words as little-endian guest bytes.
    protected static byte @Unmodifiable [] encodeAuxiliaryVector(long @Unmodifiable [] words) {
        byte[] bytes = new byte[words.length * Long.BYTES];
        for (int index = 0; index < words.length; index++) {
            writeLittleEndianLong(bytes, index * Long.BYTES, words[index]);
        }
        return bytes;
    }

    /// Encodes Linux auxiliary-vector words as little-endian guest bytes.
    protected static byte @Unmodifiable [] encodeAuxiliaryVector(ArrayList<Long> words) {
        byte[] bytes = new byte[words.size() * Long.BYTES];
        for (int index = 0; index < words.size(); index++) {
            writeLittleEndianLong(bytes, index * Long.BYTES, words.get(index));
        }
        return bytes;
    }

    /// Encodes guest strings referenced by pointers as nul-separated procfs bytes.
    protected byte @Unmodifiable [] encodeNullSeparatedStrings(ArrayList<Long> pointers) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (long pointer : pointers) {
            byte[] stringBytes = readGuestCStringBytes(pointer, 64 * 1024);
            output.writeBytes(stringBytes);
            output.write(0);
        }
        return output.toByteArray();
    }

    /// Reads the executable path pointer from a captured auxiliary vector.
    protected String executablePathFromAuxiliaryVector(ArrayList<Long> words) {
        for (int index = 0; index + 1 < words.size(); index += 2) {
            if (words.get(index) == AT_EXECFN) {
                byte[] bytes = readGuestCStringBytes(words.get(index + 1), PATH_MAX);
                return bytes.length == 0 ? "/" : new String(bytes, StandardCharsets.UTF_8);
            }
        }
        return "/";
    }

    /// Reads a nul-terminated guest string as raw bytes with a defensive maximum length.
    protected byte @Unmodifiable [] readGuestCStringBytes(long address, int maximumLength) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (int index = 0; index < maximumLength; index++) {
            int value = memory.readUnsignedByte(address + index);
            if (value == 0) {
                return output.toByteArray();
            }
            output.write(value);
        }
        return output.toByteArray();
    }

    /// Writes one little-endian 64-bit value into a host byte array.
    protected static void writeLittleEndianLong(byte[] bytes, int offset, long value) {
        for (int index = 0; index < Long.BYTES; index++) {
            bytes[offset + index] = (byte) (value >>> (index * Byte.SIZE));
        }
    }

    /// Resizes a writable host file channel while preserving its current offset.
    protected static void resizeHostChannel(SeekableByteChannel channel, long length) throws IOException {
        long position = channel.position();
        try {
            long size = channel.size();
            if (length <= size) {
                channel.truncate(length);
                return;
            }

            channel.position(length - 1);
            channel.write(ByteBuffer.wrap(new byte[]{0}));
        } finally {
            channel.position(position);
        }
    }

    /// Returns the mount selected for an absolute guest path.
    protected @Nullable Mount mountForGuestPath(String guestPath) {
        return fileSystem.mountForGuestPath(guestPath);
    }

    /// Returns the mount whose host mount root contains a host path.
    protected @Nullable HostMount mountForHostFile(Path hostFile) {
        return fileSystem.mountForHostFile(hostFile);
    }

    /// Returns true when an absolute guest path is inside a mount point.
    protected static boolean guestPathMatchesMount(String guestPath, String mountPoint) {
        return GuestFileSystem.guestPathMatchesMount(guestPath, mountPoint);
    }

    /// Adds an open file description to the guest descriptor table.
    protected long addOpenFile(OpenFile openFile) {
        return addOpenFile(openFile, false);
    }

    /// Adds an open file description to the guest descriptor table.
    protected long addOpenFile(OpenFile openFile, boolean closeOnExec) {
        for (int fileDescriptor = 0; fileDescriptor < standardFiles.length; fileDescriptor++) {
            if (standardFileOpen[fileDescriptor]) {
                continue;
            }
            standardFiles[fileDescriptor] = openFile;
            standardFileOpen[fileDescriptor] = true;
            standardFileCloseOnExec[fileDescriptor] = closeOnExec;
            setFileDescriptorCloseOnFork(fileDescriptor, false);
            return fileDescriptor;
        }
        for (int index = 0; index < openFiles.size(); index++) {
            if (openFiles.get(index) == null) {
                openFiles.set(index, openFile);
                setOpenFileCloseOnExec(index, closeOnExec);
                int fileDescriptor = index + 3;
                setFileDescriptorCloseOnFork(fileDescriptor, false);
                return fileDescriptor;
            }
        }

        openFiles.add(openFile);
        openFileCloseOnExecFlags.add(closeOnExec);
        int fileDescriptor = openFiles.size() + 2;
        setFileDescriptorCloseOnFork(fileDescriptor, false);
        return fileDescriptor;
    }

    /// Adds an open file description to the lowest guest descriptor no lower than the requested minimum.
    protected long addOpenFileAtLeast(OpenFile openFile, int minimumFileDescriptor) {
        return addOpenFileAtLeast(openFile, minimumFileDescriptor, false);
    }

    /// Adds an open file description to the lowest guest descriptor no lower than the requested minimum.
    protected long addOpenFileAtLeast(OpenFile openFile, int minimumFileDescriptor, boolean closeOnExec) {
        for (int fileDescriptor = Math.max(0, minimumFileDescriptor);
             fileDescriptor < standardFiles.length;
             fileDescriptor++) {
            if (standardFileOpen[fileDescriptor]) {
                continue;
            }
            standardFiles[fileDescriptor] = openFile;
            standardFileOpen[fileDescriptor] = true;
            standardFileCloseOnExec[fileDescriptor] = closeOnExec;
            setFileDescriptorCloseOnFork(fileDescriptor, false);
            return fileDescriptor;
        }
        int startIndex = Math.max(0, openFileIndex(minimumFileDescriptor));
        for (int index = startIndex; index < openFiles.size(); index++) {
            if (openFiles.get(index) == null) {
                openFiles.set(index, openFile);
                setOpenFileCloseOnExec(index, closeOnExec);
                int fileDescriptor = index + 3;
                setFileDescriptorCloseOnFork(fileDescriptor, false);
                return fileDescriptor;
            }
        }

        while (openFiles.size() < startIndex) {
            openFiles.add(null);
            openFileCloseOnExecFlags.add(false);
        }
        openFiles.add(openFile);
        openFileCloseOnExecFlags.add(closeOnExec);
        int fileDescriptor = openFiles.size() + 2;
        setFileDescriptorCloseOnFork(fileDescriptor, false);
        return fileDescriptor;
    }

    /// Stores an open file description at an explicit non-standard descriptor.
    protected void replaceOpenFile(int fileDescriptor, OpenFile openFile) throws IOException {
        replaceOpenFile(fileDescriptor, openFile, false);
    }

    /// Stores an open file description at an explicit descriptor.
    protected void replaceOpenFile(int fileDescriptor, OpenFile openFile, boolean closeOnExec) throws IOException {
        @Nullable OpenFile previous = openFile(fileDescriptor);
        if (previous != null) {
            setOpenFile(fileDescriptor, null);
            releaseOpenFile(previous);
        }
        setOpenFile(fileDescriptor, openFile);
        setFileDescriptorCloseOnExec(fileDescriptor, closeOnExec);
        setFileDescriptorCloseOnFork(fileDescriptor, false);
        notifyPollWaiters();
    }

    /// Stores an open file description at an explicit descriptor.
    protected void setOpenFile(int fileDescriptor, @Nullable OpenFile openFile) {
        if (isStandardFileDescriptor(fileDescriptor)) {
            standardFiles[fileDescriptor] = openFile;
            standardFileOpen[fileDescriptor] = openFile != null;
            if (openFile == null) {
                standardFileCloseOnExec[fileDescriptor] = false;
                setFileDescriptorCloseOnFork(fileDescriptor, false);
            }
            return;
        }

        int index = openFileIndex(fileDescriptor);
        while (openFiles.size() <= index) {
            openFiles.add(null);
            openFileCloseOnExecFlags.add(false);
        }
        openFiles.set(index, openFile);
        if (openFile == null) {
            setOpenFileCloseOnExec(index, false);
            setFileDescriptorCloseOnFork(fileDescriptor, false);
        }
    }

    /// Returns true when a descriptor has `FD_CLOEXEC` set.
    protected boolean fileDescriptorCloseOnExec(int fileDescriptor) {
        if (isStandardFileDescriptor(fileDescriptor)) {
            return standardFileCloseOnExec[fileDescriptor];
        }

        int index = openFileIndex(fileDescriptor);
        return openFileCloseOnExec(index);
    }

    /// Updates whether a descriptor has `FD_CLOEXEC` set.
    protected void setFileDescriptorCloseOnExec(int fileDescriptor, boolean closeOnExec) {
        if (isStandardFileDescriptor(fileDescriptor)) {
            standardFileCloseOnExec[fileDescriptor] = closeOnExec;
            return;
        }

        setOpenFileCloseOnExec(openFileIndex(fileDescriptor), closeOnExec);
    }

    /// Returns true when a non-standard descriptor table slot has `FD_CLOEXEC` set.
    protected boolean openFileCloseOnExec(int index) {
        return index >= 0 && index < openFileCloseOnExecFlags.size() && openFileCloseOnExecFlags.get(index);
    }

    /// Updates whether a non-standard descriptor table slot has `FD_CLOEXEC` set.
    protected void setOpenFileCloseOnExec(int index, boolean closeOnExec) {
        while (openFileCloseOnExecFlags.size() <= index) {
            openFileCloseOnExecFlags.add(false);
        }
        openFileCloseOnExecFlags.set(index, closeOnExec);
    }

    /// Returns true when a descriptor has the FreeBSD `FD_CLOFORK` flag set.
    protected boolean fileDescriptorCloseOnFork(int fileDescriptor) {
        return fileDescriptorsCloseOnFork.contains(fileDescriptor);
    }

    /// Updates whether a descriptor has the FreeBSD `FD_CLOFORK` flag set.
    protected void setFileDescriptorCloseOnFork(int fileDescriptor, boolean closeOnFork) {
        if (closeOnFork) {
            fileDescriptorsCloseOnFork.add(fileDescriptor);
        } else {
            fileDescriptorsCloseOnFork.remove(fileDescriptor);
        }
    }

    /// Copies the parent's descriptor table using Linux fork-style shared open file descriptions.
    protected void copyStandardFilesFrom(GuestSyscalls parent) {
        for (int index = 0; index < standardFiles.length; index++) {
            if (!parent.standardFileOpen[index] || parent.fileDescriptorCloseOnFork(index)) {
                standardFileOpen[index] = false;
                standardFileCloseOnExec[index] = false;
                continue;
            }
            @Nullable OpenFile openFile = parent.standardFiles[index];
            if (openFile != null) {
                openFile.retain();
            }
            standardFiles[index] = openFile;
            standardFileOpen[index] = true;
            standardFileCloseOnExec[index] = parent.standardFileCloseOnExec[index];
        }
    }

    /// Copies the parent's non-standard descriptor table using Linux fork-style shared open file descriptions.
    protected void copyOpenFilesFrom(GuestSyscalls parent) {
        for (int index = 0; index < parent.openFiles.size(); index++) {
            int fileDescriptor = index + 3;
            @Nullable OpenFile openFile = parent.openFiles.get(index);
            if (parent.fileDescriptorCloseOnFork(fileDescriptor)) {
                openFiles.add(null);
                openFileCloseOnExecFlags.add(false);
                continue;
            }
            if (openFile != null) {
                openFile.retain();
            }
            openFiles.add(openFile);
            openFileCloseOnExecFlags.add(parent.openFileCloseOnExec(index));
        }
    }

    /// Returns a new descriptor entry that duplicates the supplied file descriptor.
    protected @Nullable OpenFile duplicateOpenFile(int fileDescriptor) {
        if (!isOpenFileDescriptor(fileDescriptor)) {
            return null;
        }
        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile != null) {
            openFile.retain();
            return openFile;
        }
        return isStandardFileDescriptor(fileDescriptor) ? OpenFile.standardFileDescriptor(fileDescriptor) : null;
    }

    /// Releases a descriptor table entry and closes its backing object when it was the last reference.
    protected static void releaseOpenFile(OpenFile openFile) throws IOException {
        if (openFile.release()) {
            openFile.close();
        }
    }

    /// Returns an open file description for a guest file descriptor.
    protected @Nullable OpenFile openFile(int fileDescriptor) {
        if (isStandardFileDescriptor(fileDescriptor)) {
            return standardFiles[fileDescriptor];
        }

        int index = openFileIndex(fileDescriptor);
        if (index < 0 || index >= openFiles.size()) {
            return null;
        }
        return openFiles.get(index);
    }

    /// Returns true when the descriptor has `O_NONBLOCK` set on its open file description.
    protected boolean descriptorNonblocking(int fileDescriptor) {
        @Nullable OpenFile openFile = openFile(fileDescriptor);
        return openFile != null && openFile.nonblocking();
    }

    /// Returns true when a file descriptor refers to a standard stream or open guest descriptor.
    protected boolean isOpenFileDescriptor(int fileDescriptor) {
        return isStandardFileDescriptor(fileDescriptor)
                ? standardFileOpen[fileDescriptor]
                : openFile(fileDescriptor) != null;
    }

    /// Returns Linux status flags for a standard stream or open guest descriptor.
    protected long statusFlagsFor(int fileDescriptor) {
        int standardFileDescriptor = standardFileDescriptorFor(fileDescriptor);
        if (standardFileDescriptor >= 0) {
            long flags = standardFileDescriptor == 0 ? O_RDONLY : O_WRONLY;
            if (descriptorNonblocking(fileDescriptor)) {
                flags |= O_NONBLOCK;
            }
            return flags;
        }

        OpenFile openFile = openFile(fileDescriptor);
        assert openFile != null;

        long flags = openFile.readable() && openFile.writable()
                ? O_RDWR
                : openFile.writable() ? O_WRONLY : O_RDONLY;
        if (openFile.append()) {
            flags |= O_APPEND;
        }
        if (openFile.nonblocking()) {
            flags |= O_NONBLOCK;
        }
        if (openFile.isDirectory()) {
            flags |= O_DIRECTORY;
        }
        return flags;
    }

    /// Converts a guest file descriptor to an open-file table index.
    protected static int openFileIndex(int fileDescriptor) {
        return fileDescriptor - 3;
    }

    /// Finds the first free page range for a new anonymous mapping.
    protected long findMmapAddress(long requestedAddress, long length, long alignment) {
        if (requestedAddress != 0) {
            long alignedAddress = alignUp(requestedAddress, alignment);
            if (alignedAddress > 0 && isMmapRangeAvailable(alignedAddress, length)) {
                return alignedAddress;
            }
        }

        long candidateAddress = alignUp(programBreak, alignment);
        while (candidateAddress > 0 && fitsGuestMemory(candidateAddress, length)) {
            MemoryMapping overlap = overlappingMemoryMapping(candidateAddress, length);
            long backingOverlapEnd = overlappingExplicitBackingEnd(candidateAddress, length);
            if (overlap == null && backingOverlapEnd == candidateAddress) {
                return candidateAddress;
            }
            long nextAddress = overlap == null ? backingOverlapEnd : overlap.endAddress();
            if (nextAddress <= candidateAddress) {
                nextAddress = candidateAddress + alignment;
            }
            candidateAddress = alignUp(nextAddress, alignment);
        }

        return findSparseMmapAddress(length, alignment);
    }

    /// Finds the first free sparse range outside the initial memory window.
    protected long findSparseMmapAddress(long length, long alignment) {
        long candidateAddress = alignUp(Math.max(memory.endAddress(), programBreak), alignment);
        while (candidateAddress > 0 && isValidGuestRange(candidateAddress, length)) {
            MemoryMapping overlap = overlappingMemoryMapping(candidateAddress, length);
            if (overlap == null) {
                return candidateAddress;
            }
            candidateAddress = alignUp(overlap.endAddress(), alignment);
        }
        return 0;
    }

    /// Returns true when a guest range is suitable for a new anonymous mapping.
    protected boolean isMmapRangeAvailable(long address, long length) {
        return isValidGuestRange(address, length)
                && address >= programBreak
                && !overlapsMemoryMappings(address, length)
                && overlappingExplicitBackingEnd(address, length) == address
                && (fitsGuestMemory(address, length) || !overlapsInitialMemory(address, length));
    }

    /// Adds an active anonymous mapping in address order.
    protected void addMemoryMapping(long address, long length, long protection) {
        addMemoryMapping(address, length, protection, null, 0, false);
    }

    /// Adds an active mapping in address order.
    protected void addMemoryMapping(
            long address,
            long length,
            long protection,
            @Nullable String path,
            long fileOffset,
            boolean shared) {
        addMemoryMapping(address, length, protection, path, fileOffset, shared, null);
    }

    /// Adds an active mapping in address order.
    protected void addMemoryMapping(
            long address,
            long length,
            long protection,
            @Nullable String path,
            long fileOffset,
            boolean shared,
            @Nullable DeviceFile deviceFile) {
        MemoryMapping mapping = new MemoryMapping(address, length, protection, path, fileOffset, shared, deviceFile);
        int insertionIndex = 0;
        while (insertionIndex < memoryMappings.size()
                && Long.compareUnsigned(memoryMappings.get(insertionIndex).address(), address) < 0) {
            insertionIndex++;
        }
        memoryMappings.add(insertionIndex, mapping);
        if (deviceFile != null && shared) {
            ensureFramebufferRefreshHook();
        }
    }

    /// Removes or splits active anonymous mappings overlapped by a guest range.
    protected void removeMemoryMappings(long address, long length) {
        long endAddress = address + length;
        for (int index = 0; index < memoryMappings.size(); ) {
            MemoryMapping mapping = memoryMappings.get(index);
            if (!rangesOverlap(address, endAddress, mapping.address(), mapping.endAddress())) {
                index++;
                continue;
            }

            memoryMappings.remove(index);
            long clearStart = Math.max(address, mapping.address());
            long clearEnd = Math.min(endAddress, mapping.endAddress());
            releaseRemovedMappingMemory(mapping, clearStart, clearEnd - clearStart);

            if (mapping.address() < address) {
                memoryMappings.add(index, mapping.withRange(
                        mapping.address(),
                        address - mapping.address()));
                index++;
            }
            if (endAddress < mapping.endAddress()) {
                memoryMappings.add(index, mapping.withRange(
                        endAddress,
                        mapping.endAddress() - endAddress));
                index++;
            }
        }
        updateFramebufferRefreshHook();
    }

    /// Resizes tracked metadata for a mapping that stayed at the same guest address.
    protected void resizeMemoryMapping(MemoryMapping mapping, long newLength) {
        int index = memoryMappings.indexOf(mapping);
        if (index < 0) {
            throw new RiscVException("Failed to find guest memory mapping metadata for mremap.");
        }
        memoryMappings.set(index, mapping.withRange(mapping.address(), newLength));
    }

    /// Moves tracked mapping data to a new guest address.
    protected long moveMemoryMapping(MemoryMapping mapping, long oldLength, long newAddress, long newLength) {
        long oldAddress = mapping.address();
        long protection = mapping.protection();
        if (!ensureMemoryBacking(newAddress, newLength, Memory.PROTECTION_READ_WRITE_EXECUTE, false)) {
            return ENOMEM;
        }

        try {
            long copyLength = Math.min(oldLength, newLength);
            if (mapping.isBacked() && copyLength > 0) {
                byte[] bytes = memory.readBytes(oldAddress, copyLength);
                memory.writeBytes(newAddress, bytes, 0, bytes.length);
            }
            if (!memory.protect(newAddress, newLength, protection)) {
                memory.unmap(newAddress, newLength);
                return ENOMEM;
            }
        } catch (RiscVException exception) {
            memory.unmap(newAddress, newLength);
            return ENOMEM;
        }

        addMemoryMapping(
                newAddress,
                newLength,
                protection,
                mapping.path(),
                mapping.fileOffset(),
                mapping.shared(),
                mapping.deviceFile());
        removeMemoryMappings(oldAddress, oldLength);
        return newAddress;
    }

    /// Ensures that the supplied range has native backing for non-`PROT_NONE` access.
    protected boolean ensureMemoryBacking(long address, long length) {
        return ensureMemoryBacking(address, length, Memory.PROTECTION_READ_WRITE_EXECUTE, false);
    }

    /// Ensures that the supplied range has guest memory backing with the requested protection.
    protected boolean ensureMemoryBacking(long address, long length, long protection, boolean hugeTlb) {
        if (!isValidGuestRange(address, length)) {
            return false;
        }
        if (memory.isBacked(address, length)) {
            return memory.protect(address, length, protection);
        }
        return hugeTlb ? memory.mapHuge(address, length, protection) : memory.map(address, length, protection);
    }

    /// Ensures the newly grown part of the process heap has native backing.
    protected boolean ensureProgramBreakBacking(long address, long length) {
        if (length == 0 || memory.isBacked(address, length)) {
            return true;
        }
        return memory.map(address, length);
    }

    /// Releases or clears native backing for a removed mapping range.
    protected void releaseRemovedMappingMemory(MemoryMapping mapping, long address, long length) {
        syncSharedDeviceMappingRange(mapping, address, length);
        if (memory.hasDenseInitialBacking() && fitsGuestMemory(address, length)) {
            if (mapping.isBacked()) {
                memory.clear(address, length);
            }
            if (!memory.protect(address, length, Memory.PROTECTION_READ_WRITE_EXECUTE)) {
                throw new RiscVException("Failed to restore dense guest memory protection: address=0x"
                        + Long.toUnsignedString(address, 16)
                        + ", length="
                        + length);
            }
        } else {
            memory.unmap(address, length);
        }
    }

    /// Synchronizes every shared device mapping back to its backing device.
    protected void syncSharedDeviceMappings() {
        for (MemoryMapping mapping : memoryMappings) {
            syncSharedDeviceMappingRange(mapping, mapping.address(), mapping.length());
        }
    }

    /// Ensures the framebuffer device refreshes live mappings before host snapshots.
    private void ensureFramebufferRefreshHook() {
        if (framebufferRefreshHookRemoval != null) {
            return;
        }

        @Nullable FramebufferDevice device = framebufferDevice;
        if (device != null) {
            framebufferRefreshHookRemoval = device.registerRefreshHook(this::syncSharedDeviceMappings);
        }
    }

    /// Removes the framebuffer refresh hook when no live device mapping remains.
    private void closeFramebufferRefreshHook() {
        @Nullable Runnable removal = framebufferRefreshHookRemoval;
        if (removal != null) {
            framebufferRefreshHookRemoval = null;
            removal.run();
        }
    }

    /// Updates whether this process needs a framebuffer refresh hook.
    private void updateFramebufferRefreshHook() {
        if (hasSharedDeviceMapping()) {
            ensureFramebufferRefreshHook();
        } else {
            closeFramebufferRefreshHook();
        }
    }

    /// Returns true when at least one shared device mapping is still active.
    private boolean hasSharedDeviceMapping() {
        for (MemoryMapping mapping : memoryMappings) {
            if (mapping.deviceFile() != null && mapping.shared()) {
                return true;
            }
        }
        return false;
    }

    /// Synchronizes a shared device-backed mapping range back to its backing device.
    protected void syncSharedDeviceMappingRange(MemoryMapping mapping, long address, long length) {
        if (mapping.deviceFile() != DeviceFile.FRAMEBUFFER || !mapping.shared() || !mapping.isBacked()) {
            return;
        }

        @Nullable FramebufferDevice device = framebufferDevice;
        if (device == null) {
            return;
        }

        long framebufferOffset = mapping.fileOffset() + (address - mapping.address());
        long framebufferSize = device.geometry().bufferSizeBytes();
        if (length <= 0 || framebufferOffset < 0 || framebufferOffset >= framebufferSize) {
            return;
        }

        long remaining = Math.min(length, framebufferSize - framebufferOffset);
        long cursor = address;
        long originalProtection = mapping.protection();
        boolean restoreProtection = (originalProtection & Memory.PROTECTION_READ) == 0;
        if (restoreProtection && !memory.protect(address, length, originalProtection | Memory.PROTECTION_READ)) {
            throw new RiscVException("Failed to read guest device mapping before synchronization.");
        }

        try {
            while (remaining > 0) {
                long chunkLength = Math.min(8192L, remaining);
                byte[] bytes = memory.readBytes(cursor, chunkLength);
                byte[] currentBytes = new byte[bytes.length];
                device.read(framebufferOffset, currentBytes, 0, currentBytes.length);
                if (!Arrays.equals(bytes, currentBytes)) {
                    device.write(framebufferOffset, bytes, 0, bytes.length);
                }
                cursor += bytes.length;
                framebufferOffset += bytes.length;
                remaining -= bytes.length;
            }
        } finally {
            if (restoreProtection && !memory.protect(address, length, originalProtection)) {
                throw new RiscVException("Failed to restore guest device mapping protection.");
            }
        }
    }

    /// Allocates native backing needed before changing mappings to a backed protection.
    protected boolean prepareMemoryProtection(long address, long length, long protection) {
        if (!isMemoryBackedProtection(protection)) {
            return true;
        }

        ArrayList<MemoryRange> allocatedRanges = new ArrayList<>();
        long endAddress = address + length;
        for (MemoryMapping mapping : memoryMappings) {
            if (!rangesOverlap(address, endAddress, mapping.address(), mapping.endAddress()) || mapping.isBacked()) {
                continue;
            }

            long protectStart = Math.max(address, mapping.address());
            long protectEnd = Math.min(endAddress, mapping.endAddress());
            long protectLength = protectEnd - protectStart;
            if (memory.isBacked(protectStart, protectLength)) {
                if (!memory.protect(protectStart, protectLength, protection)) {
                    rollbackAllocatedMemory(allocatedRanges);
                    return false;
                }
                continue;
            }
            if (!memory.map(protectStart, protectLength, protection)) {
                rollbackAllocatedMemory(allocatedRanges);
                return false;
            }
            allocatedRanges.add(new MemoryRange(protectStart, protectLength));
        }
        return true;
    }

    /// Rolls back sparse memory backing allocated during a failed protection change.
    protected void rollbackAllocatedMemory(ArrayList<MemoryRange> ranges) {
        for (MemoryRange range : ranges) {
            memory.unmap(range.address(), range.length());
        }
    }

    /// Updates tracked mapping protection metadata, splitting mappings as needed.
    protected void updateMemoryMappingsProtection(long address, long length, long protection) {
        long endAddress = address + length;
        for (int index = 0; index < memoryMappings.size(); ) {
            MemoryMapping mapping = memoryMappings.get(index);
            if (!rangesOverlap(address, endAddress, mapping.address(), mapping.endAddress())) {
                index++;
                continue;
            }

            memoryMappings.remove(index);
            long protectStart = Math.max(address, mapping.address());
            long protectEnd = Math.min(endAddress, mapping.endAddress());
            long protectLength = protectEnd - protectStart;
            if ((mapping.protection() & Memory.PROTECTION_WRITE) != 0
                    && (protection & Memory.PROTECTION_WRITE) == 0) {
                syncSharedDeviceMappingRange(mapping, protectStart, protectLength);
            }
            if (!memory.protect(protectStart, protectLength, protection)) {
                throw new RiscVException("Failed to update guest memory protection: address=0x"
                        + Long.toUnsignedString(protectStart, 16)
                        + ", length="
                        + protectLength);
            }

            if (mapping.address() < protectStart) {
                memoryMappings.add(index, mapping.withRange(
                        mapping.address(),
                        protectStart - mapping.address()));
                index++;
            }
            memoryMappings.add(index, mapping.withRangeAndProtection(protectStart, protectLength, protection));
            index++;
            if (protectEnd < mapping.endAddress()) {
                memoryMappings.add(index, mapping.withRange(
                        protectEnd,
                        mapping.endAddress() - protectEnd));
                index++;
            }
        }
    }

    /// Clears backed anonymous memory ranges covered by discard-style `madvise` hints.
    protected void clearAdvisedMemory(long address, long length) {
        long endAddress = address + length;
        for (MemoryMapping mapping : memoryMappings) {
            if (!mapping.isBacked() || !rangesOverlap(address, endAddress, mapping.address(), mapping.endAddress())) {
                continue;
            }

            long clearStart = Math.max(address, mapping.address());
            long clearEnd = Math.min(endAddress, mapping.endAddress());
            memory.clear(clearStart, clearEnd - clearStart);
        }
    }

    /// Returns true when an advisory memory hint can be accepted by this simulator.
    protected static boolean isSupportedMemoryAdvice(long advice) {
        return advice == MADV_NORMAL
                || advice == MADV_RANDOM
                || advice == MADV_SEQUENTIAL
                || advice == MADV_WILLNEED
                || advice == MADV_DONTNEED
                || advice == MADV_FREE
                || advice == MADV_DONTFORK
                || advice == MADV_DOFORK
                || advice == MADV_MERGEABLE
                || advice == MADV_UNMERGEABLE
                || advice == MADV_HUGEPAGE
                || advice == MADV_NOHUGEPAGE
                || advice == MADV_DONTDUMP
                || advice == MADV_DODUMP
                || advice == MADV_WIPEONFORK
                || advice == MADV_KEEPONFORK
                || advice == MADV_COLD
                || advice == MADV_PAGEOUT
                || advice == MADV_POPULATE_READ
                || advice == MADV_POPULATE_WRITE
                || advice == MADV_DONTNEED_LOCKED
                || advice == MADV_COLLAPSE;
    }

    /// Returns true when a guest range is mapped by the initial window or anonymous mappings.
    protected boolean isMappedRange(long address, long length) {
        if (!isValidGuestRange(address, length)) {
            return false;
        }

        long endAddress = address + length;
        long cursor = address;
        while (cursor < endAddress) {
            long backedEndAddress = memory.backedRangeEnd(cursor);
            if (backedEndAddress > cursor) {
                cursor = Math.min(endAddress, backedEndAddress);
                continue;
            }

            @Nullable MemoryMapping mapping = memoryMappingCovering(cursor);
            if (mapping == null) {
                return false;
            }
            cursor = Math.min(endAddress, mapping.endAddress());
        }
        return true;
    }

    /// Returns the anonymous mapping covering a guest address, or null when absent.
    protected @Nullable MemoryMapping memoryMappingCovering(long address) {
        for (MemoryMapping mapping : memoryMappings) {
            if (address >= mapping.address() && address < mapping.endAddress()) {
                return mapping;
            }
            if (address < mapping.address()) {
                return null;
            }
        }
        return null;
    }

    /// Returns true when a guest range overlaps an active anonymous mapping.
    protected boolean overlapsMemoryMappings(long address, long length) {
        return overlappingMemoryMapping(address, length) != null;
    }

    /// Returns the first active anonymous mapping overlapped by a guest range.
    protected @Nullable MemoryMapping overlappingMemoryMapping(long address, long length) {
        long endAddress = address + length;
        for (MemoryMapping mapping : memoryMappings) {
            if (rangesOverlap(address, endAddress, mapping.address(), mapping.endAddress())) {
                return mapping;
            }
        }
        return null;
    }

    /// Returns true when a mapping flag combination requires an exact address.
    protected static boolean requiresFixedMapping(long flags) {
        return (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0;
    }

    /// Returns true when a protection value requires guest memory to be backed.
    protected static boolean isMemoryBackedProtection(long protection) {
        return protection != PROT_NONE;
    }

    /// Returns true when an address is aligned to the guest page size.
    protected boolean isPageAligned(long address) {
        return (address & (pageSize - 1L)) == 0;
    }

    /// Returns true when an address is aligned to the supplied power-of-two alignment.
    protected static boolean isAligned(long address, long alignment) {
        return (address & (alignment - 1L)) == 0;
    }

    /// Rounds a positive guest size or address up to a power-of-two alignment.
    protected static long alignUp(long value, long alignment) {
        long mask = alignment - 1;
        if (value > Long.MAX_VALUE - mask) {
            return -1;
        }
        return (value + mask) & ~mask;
    }

    /// Rounds a non-negative guest address down to a power-of-two alignment.
    protected static long alignDown(long value, long alignment) {
        return value & -alignment;
    }

    /// Returns true when the supplied range is non-negative and does not overflow.
    protected static boolean isValidGuestRange(long address, long length) {
        return address >= 0 && length >= 0 && address <= Long.MAX_VALUE - length;
    }

    /// Returns true when the supplied guest range fits in the memory window.
    protected boolean fitsGuestMemory(long address, long length) {
        return address >= memory.baseAddress()
                && length >= 0
                && address <= memory.endAddress()
                && length <= memory.endAddress() - address;
    }

    /// Returns true when the supplied guest range overlaps the initial memory window.
    protected boolean overlapsInitialMemory(long address, long length) {
        return rangesOverlap(address, address + length, memory.baseAddress(), memory.endAddress());
    }

    /// Returns the end address of explicit sparse backing overlapped by a range, or the start address when none exists.
    protected long overlappingExplicitBackingEnd(long address, long length) {
        return memory.hasDenseInitialBacking() ? address : memory.overlappingBackingEnd(address, length);
    }

    /// Returns true when two half-open address ranges overlap.
    protected static boolean rangesOverlap(long firstStart, long firstEnd, long secondStart, long secondEnd) {
        return firstStart < secondEnd && secondStart < firstEnd;
    }

    /// Returns the next deterministic pseudo-random byte.
    protected byte nextRandomByte() {
        randomState = randomState * 6364136223846793005L + 1442695040888963407L;
        return (byte) (randomState >>> 56);
    }

    /// Returns the host output stream mapped to a guest file descriptor.
    protected @Nullable OutputStream outputStreamFor(int fileDescriptor) {
        int standardFileDescriptor = standardFileDescriptorFor(fileDescriptor);
        if (standardFileDescriptor == 1) {
            return out;
        }
        if (standardFileDescriptor == 2) {
            return err;
        }
        return null;
    }

    /// Returns the host input stream mapped to a guest file descriptor.
    protected @Nullable InputStream inputStreamFor(int fileDescriptor) {
        return standardFileDescriptorFor(fileDescriptor) == 0 ? in : null;
    }

    /// Returns the underlying standard descriptor number, or `-1` for non-standard descriptors.
    protected int standardFileDescriptorFor(int fileDescriptor) {
        if (isStandardFileDescriptor(fileDescriptor)) {
            if (!standardFileOpen[fileDescriptor]) {
                return -1;
            }
            @Nullable OpenFile openFile = standardFiles[fileDescriptor];
            if (openFile != null) {
                return openFile.isStandardFileDescriptor() ? openFile.standardFileDescriptor() : -1;
            }
            return fileDescriptor;
        }

        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile != null && openFile.isStandardFileDescriptor()) {
            return openFile.standardFileDescriptor();
        }
        return -1;
    }

    /// Returns true when the file descriptor is one of stdin, stdout, or stderr.
    protected static boolean isStandardFileDescriptor(int fileDescriptor) {
        return fileDescriptor >= 0 && fileDescriptor <= 2;
    }

    /// Stores one process-style child tracked by its parent process.
    protected static final class ChildProcess {
        /// The guest process id visible to the parent.
        private final int processId;

        /// The guest process group id visible to wait selectors.
        private int processGroupId;

        /// Whether the child uses clone-child rather than `SIGCHLD` wait selection.
        private final boolean cloneChild;

        /// The guest thread id that created the child process.
        private final int parentThreadId;

        /// The syscall handler owned by the child process.
        private final GuestSyscalls syscalls;

        /// The host thread running the child process leader.
        private final Thread thread;

        /// Whether the child process has reported a final exit code.
        private volatile boolean exited;

        /// Whether a wait operation has consumed the child's final status.
        private volatile boolean reaped;

        /// The low eight bits of the child process exit code.
        private int exitCode;

        /// Creates a tracked child process.
        protected ChildProcess(
                int processId,
                int processGroupId,
                boolean cloneChild,
                int parentThreadId,
                GuestSyscalls syscalls,
                Thread thread) {
            this.processId = processId;
            this.processGroupId = processGroupId;
            this.cloneChild = cloneChild;
            this.parentThreadId = parentThreadId;
            this.syscalls = syscalls;
            this.thread = thread;
        }

        /// Returns the guest process id visible to the parent.
        protected int processId() {
            return processId;
        }

        /// Returns the child process syscall handler.
        protected GuestSyscalls syscalls() {
            return syscalls;
        }

        /// Returns the guest process group id visible to wait selectors.
        protected int processGroupId() {
            return processGroupId;
        }

        /// Returns true when clone-specific wait options select this child.
        protected boolean cloneChild() {
            return cloneChild;
        }

        /// Returns the guest thread id that created this child process.
        private int parentThreadId() {
            return parentThreadId;
        }

        /// Updates the Linux process group id visible to wait selectors.
        private void setProcessGroupId(int processGroupId) {
            this.processGroupId = processGroupId;
        }

        /// Returns the host thread running the child process leader.
        private Thread thread() {
            return thread;
        }

        /// Returns true when this child matches a `wait4`-style process selector.
        private boolean matches(long waitProcessId, int currentProcessGroupId) {
            if (waitProcessId == -1) {
                return true;
            }
            if (waitProcessId == 0) {
                return processGroupId == currentProcessGroupId;
            }
            if (waitProcessId > 0) {
                return waitProcessId == processId;
            }
            return waitProcessId < -1 && -waitProcessId == processGroupId;
        }

        /// Records the final child exit code.
        private void recordExit(long exitCode) {
            if (!exited) {
                this.exitCode = (int) exitCode & 0xff;
                exited = true;
            }
        }

        /// Returns true after the child has exited.
        protected boolean exited() {
            return exited;
        }

        /// Records that a wait operation consumed the child's final status.
        private void markReaped() {
            reaped = true;
        }

        /// Returns true after a wait operation has consumed the child's final status.
        private boolean reaped() {
            return reaped;
        }

        /// Returns the low eight bits of the normal process exit code.
        protected int exitCode() {
            return exitCode;
        }

        /// Returns the real user id held by the child at observation time.
        protected long userId() {
            return syscalls.credentials.realUserId();
        }

        /// Returns the wait status for a normal process exit.
        protected int waitStatus() {
            return exitCode << 8;
        }
    }

    /// Describes one child-wait attempt.
    ///
    /// @param result the positive child process id, zero for a nonblocking miss, or a negative errno
    /// @param child the observed child, or null when no child event was returned
    @NotNullByDefault
    protected record ChildWaitResult(long result, @Nullable ChildProcess child) {
    }

    /// Describes a `getpriority` lookup without conflating a negative nice value with an error.
    ///
    /// @param niceValue the lowest nice value among selected processes when `error` is zero
    /// @param error zero on success, or a raw negative errno when no value is available
    @NotNullByDefault
    protected record PriorityResult(int niceValue, long error) {
    }

    /// Describes a Linux process file descriptor target.
    ///
    /// @param processId the stable guest process or thread id represented by the descriptor
    /// @param syscalls the syscall handler owned by the target process
    /// @param childProcess the caller's tracked child record, or null when the target is not its child
    /// @param thread the specific target thread, or null when the descriptor refers to the whole process
    @NotNullByDefault
    protected record ProcessFile(
            int processId,
            GuestSyscalls syscalls,
            @Nullable ChildProcess childProcess,
            @Nullable GuestThread thread) {
        /// Returns true after the target process has exited.
        protected boolean exited() {
            return syscalls.processExitRequested || thread != null && thread.exited();
        }

        /// Returns true after the caller has consumed the target child's wait status.
        protected boolean reaped() {
            return childProcess != null && childProcess.reaped();
        }
    }

    /// Stores Linux metadata that the guest sees for one host filesystem entry.
    ///
    /// @param userId the Linux uid exposed as owner
    /// @param groupId the Linux gid exposed as group
    /// @param mode the Linux permission and special mode bits
    protected record GuestFileMetadata(long userId, long groupId, int mode) {
        /// Creates normalized guest metadata.
        protected GuestFileMetadata {
            GuestCredentials.validateId("userId", userId);
            GuestCredentials.validateId("groupId", groupId);
            mode &= STAT_MODE_CHANGE_BITS;
        }

        /// Returns this metadata with updated mode bits.
        protected GuestFileMetadata withMode(int mode) {
            return new GuestFileMetadata(userId, groupId, mode);
        }

        /// Returns this metadata with updated ownership.
        protected GuestFileMetadata withOwner(long userId, long groupId) {
            return new GuestFileMetadata(userId, groupId, mode);
        }
    }

    /// Stores synthetic Linux metadata for host files without changing host ownership.
    protected static final class GuestFileMetadataStore {
        /// Metadata keyed by canonical host path where possible.
        private final HashMap<String, GuestFileMetadata> hostFiles = new HashMap<>();

        /// Returns existing metadata for a host path, or installs the supplied fallback.
        synchronized GuestFileMetadata getOrCreate(Path path, GuestFileMetadata fallback) throws IOException {
            String key = metadataKey(path);
            @Nullable GuestFileMetadata metadata = hostFiles.get(key);
            if (metadata != null) {
                return metadata;
            }
            hostFiles.put(key, fallback);
            return fallback;
        }

        /// Replaces metadata for a host path.
        synchronized void put(Path path, GuestFileMetadata metadata) throws IOException {
            hostFiles.put(metadataKey(path), metadata);
        }

        /// Returns a canonical metadata key for an existing host path.
        synchronized String key(Path path) throws IOException {
            return metadataKey(path);
        }

        /// Removes metadata by canonical key.
        synchronized void remove(String key) {
            hostFiles.remove(key);
        }

        /// Moves metadata from one canonical source key to an existing host path.
        synchronized void move(String sourceKey, Path target) throws IOException {
            @Nullable GuestFileMetadata metadata = hostFiles.remove(sourceKey);
            String targetKey = metadataKey(target);
            if (metadata != null) {
                hostFiles.put(targetKey, metadata);
            } else {
                hostFiles.remove(targetKey);
            }
        }

        /// Returns the canonical metadata key for an existing host path.
        private static String metadataKey(Path path) throws IOException {
            return path.toRealPath().toString();
        }

    }

    /// Describes a guest memory mapping tracked by the syscall layer.
    ///
    /// @param address the inclusive guest start address of the mapping
    /// @param length the byte length of the mapping
    /// @param protection the Linux protection flags currently tracked for the mapping
    /// @param path the guest-visible mapped file path, or null for anonymous mappings
    /// @param fileOffset the file offset backing the first mapped byte
    /// @param shared whether the mapping was created as shared
    /// @param deviceFile the mapped virtual device, or null for anonymous and regular-file mappings
    protected record MemoryMapping(
            long address,
            long length,
            long protection,
            @Nullable String path,
            long fileOffset,
            boolean shared,
            @Nullable DeviceFile deviceFile) {
        /// Returns the exclusive guest end address of the mapping.
        long endAddress() {
            return address + length;
        }

        /// Returns true when this mapping should have host memory backing.
        boolean isBacked() {
            return isMemoryBackedProtection(protection);
        }

        /// Returns this mapping metadata with a different address range.
        MemoryMapping withRange(long newAddress, long newLength) {
            return new MemoryMapping(
                    newAddress,
                    newLength,
                    protection,
                    path,
                    fileOffset + (newAddress - address),
                    shared,
                    deviceFile);
        }

        /// Returns this mapping metadata with a different address range and protection.
        MemoryMapping withRangeAndProtection(long newAddress, long newLength, long newProtection) {
            return new MemoryMapping(
                    newAddress,
                    newLength,
                    newProtection,
                    path,
                    fileOffset + (newAddress - address),
                    shared,
                    deviceFile);
        }
    }

    /// Describes a guest memory range allocated while changing protections.
    ///
    /// @param address the inclusive guest start address of the range
    /// @param length the byte length of the range
    protected record MemoryRange(
            long address,
            long length) {
    }

    /// Stores one guest thread blocked in a futex wait operation.
    protected static final class FutexWaiter {
        /// The guest futex word address being waited on.
        private final long address;

        /// The futex bitset mask used to match wake operations.
        private final long bitset;

        /// Whether a matching futex wake selected this waiter.
        private boolean woken;

        /// Creates a waiter for the supplied futex word and bitset.
        private FutexWaiter(long address, long bitset) {
            this.address = address;
            this.bitset = bitset;
        }
    }

    /// Stores the result of one Linux `eventfd` read operation.
    ///
    /// @param value the unsigned counter value to copy to guest memory
    /// @param error the raw negative Linux error, or zero when `value` is valid
    protected record EventReadResult(long value, long error) {
        /// Creates a successful `eventfd` read result.
        static EventReadResult value(long value) {
            return new EventReadResult(value, 0);
        }

        /// Creates a failed `eventfd` read result.
        static EventReadResult error(long error) {
            return new EventReadResult(0, error);
        }
    }

    /// Stores the user-visible configuration of one Linux `timerfd` timer.
    ///
    /// @param intervalNanoseconds the periodic interval, or zero for a one-shot timer
    /// @param valueNanoseconds the remaining time before the next expiration, or zero when disarmed
    protected record TimerFileSpec(long intervalNanoseconds, long valueNanoseconds) {
    }

    /// Stores the timer state for one Linux `timerfd` open-file description.
    protected static final class TimerFile {
        /// The Linux clock id used by this timer.
        private final long clockId;

        /// Whether the initial open-file status flags include `O_NONBLOCK`.
        private final boolean nonblocking;

        /// Supplies the current nanosecond value for `clockId`.
        private final LongUnaryOperator clockReader;

        /// Notifies blocking poll syscalls that readiness may have changed.
        private final @Nullable Runnable changeNotifier;

        /// The periodic interval in nanoseconds, or zero for a one-shot timer.
        private long intervalNanoseconds;

        /// The absolute next expiration in the timer clock domain, or `-1` when disarmed.
        private long nextExpirationNanoseconds = -1;

        /// Expirations not yet consumed by `read`.
        private long expirations;

        /// Creates a disarmed timer for the supplied Linux clock.
        TimerFile(
                long clockId,
                boolean nonblocking,
                LongUnaryOperator clockReader,
                @Nullable Runnable changeNotifier) {
            this.clockId = clockId;
            this.nonblocking = nonblocking;
            this.clockReader = clockReader;
            this.changeNotifier = changeNotifier;
        }

        /// Returns true when a read can complete without blocking.
        synchronized boolean isReadable() {
            refresh(clockNanoseconds());
            return expirations != 0;
        }

        /// Returns true when the initial open-file status flags include `O_NONBLOCK`.
        boolean nonblocking() {
            return nonblocking;
        }

        /// Returns the current `itimerspec` values visible through `timerfd_gettime`.
        synchronized TimerFileSpec currentSpec() {
            long nowNanoseconds = clockNanoseconds();
            refresh(nowNanoseconds);
            return currentSpec(nowNanoseconds);
        }

        /// Arms, rearms, or disarms the timer and returns the previous `itimerspec`.
        synchronized TimerFileSpec setTime(boolean absolute, long intervalNanoseconds, long valueNanoseconds) {
            long nowNanoseconds = clockNanoseconds();
            refresh(nowNanoseconds);
            TimerFileSpec oldSpec = currentSpec(nowNanoseconds);

            this.intervalNanoseconds = intervalNanoseconds;
            expirations = 0;
            nextExpirationNanoseconds = valueNanoseconds == 0
                    ? -1
                    : absolute ? valueNanoseconds : saturatingAddNanoseconds(nowNanoseconds, valueNanoseconds);
            notifyReadyChange();
            return oldSpec;
        }

        /// Reads and clears the accumulated expiration count or returns a raw negative Linux error.
        synchronized long read(boolean nonblocking) throws InterruptedException {
            while (true) {
                long nowNanoseconds = clockNanoseconds();
                refresh(nowNanoseconds);
                if (expirations != 0) {
                    long result = expirations;
                    expirations = 0;
                    notifyReadyChange();
                    return result;
                }
                if (nonblocking) {
                    return EAGAIN;
                }
                if (nextExpirationNanoseconds < 0) {
                    wait();
                } else {
                    waitNanoseconds(Math.max(1, nextExpirationNanoseconds - nowNanoseconds));
                }
            }
        }

        /// Returns the current timer clock value in nanoseconds.
        private long clockNanoseconds() {
            return clockReader.applyAsLong(clockId);
        }

        /// Returns the current timer specification after pending expirations have been refreshed.
        private TimerFileSpec currentSpec(long nowNanoseconds) {
            long valueNanoseconds = nextExpirationNanoseconds < 0
                    ? 0
                    : Math.max(0, nextExpirationNanoseconds - nowNanoseconds);
            return new TimerFileSpec(intervalNanoseconds, valueNanoseconds);
        }

        /// Moves elapsed timer expirations into the unread expiration counter.
        private void refresh(long nowNanoseconds) {
            if (nextExpirationNanoseconds < 0 || nowNanoseconds < nextExpirationNanoseconds) {
                return;
            }

            if (intervalNanoseconds == 0) {
                expirations = saturatingAddNanoseconds(expirations, 1);
                nextExpirationNanoseconds = -1;
                return;
            }

            long elapsedNanoseconds = nowNanoseconds - nextExpirationNanoseconds;
            long elapsedIntervals = elapsedNanoseconds / intervalNanoseconds;
            long expirationsToAdd = elapsedIntervals == Long.MAX_VALUE ? Long.MAX_VALUE : elapsedIntervals + 1;
            expirations = saturatingAddNanoseconds(expirations, expirationsToAdd);
            long advanceNanoseconds = saturatingMultiplyNanoseconds(intervalNanoseconds, expirationsToAdd);
            nextExpirationNanoseconds = saturatingAddNanoseconds(nextExpirationNanoseconds, advanceNanoseconds);
        }

        /// Waits on this timer monitor for at most the supplied nanosecond count.
        private void waitNanoseconds(long nanoseconds) throws InterruptedException {
            wait(
                    nanoseconds / NANOSECONDS_PER_MILLISECOND,
                    (int) (nanoseconds % NANOSECONDS_PER_MILLISECOND));
        }

        /// Notifies readers and poll waiters when a timer state transition can affect readiness.
        private void notifyReadyChange() {
            notifyAll();
            if (changeNotifier != null) {
                changeNotifier.run();
            }
        }
    }

    /// Stores the shared counter state for one Linux `eventfd` open-file description.
    protected static final class EventCounter {
        /// The current unsigned 64-bit counter value.
        private long value;

        /// Whether reads decrement the counter by one and return `1`.
        private final boolean semaphore;

        /// Whether the open-file status flags include `O_NONBLOCK`.
        private final boolean nonblocking;

        /// Notifies blocking poll syscalls that readiness may have changed.
        private final @Nullable Runnable changeNotifier;

        /// Creates an event counter with the supplied initial value and flags.
        EventCounter(long value, boolean semaphore, boolean nonblocking, @Nullable Runnable changeNotifier) {
            this.value = value;
            this.semaphore = semaphore;
            this.nonblocking = nonblocking;
            this.changeNotifier = changeNotifier;
        }

        /// Returns true when a read can complete without blocking.
        synchronized boolean isReadable() {
            return value != 0;
        }

        /// Returns true when a write can increment the counter without overflowing.
        synchronized boolean isWritable() {
            return canWrite(1);
        }

        /// Returns true when the open-file status flags include `O_NONBLOCK`.
        boolean nonblocking() {
            return nonblocking;
        }

        /// Reads the current counter value and applies Linux `eventfd` decrement rules.
        synchronized EventReadResult read(boolean nonblocking) throws InterruptedException {
            while (value == 0) {
                if (nonblocking) {
                    return EventReadResult.error(EAGAIN);
                }
                wait();
            }

            if (semaphore) {
                value--;
                notifyReadyChange();
                return EventReadResult.value(1);
            }

            long result = value;
            value = 0;
            notifyReadyChange();
            return EventReadResult.value(result);
        }

        /// Adds an unsigned increment to the counter or returns a raw negative Linux error.
        synchronized long write(long increment, boolean nonblocking) throws InterruptedException {
            if (increment == -1L) {
                return EINVAL;
            }

            while (!canWrite(increment)) {
                if (nonblocking) {
                    return EAGAIN;
                }
                wait();
            }

            value += increment;
            notifyReadyChange();
            return 0;
        }

        /// Returns true when the supplied increment can be added without exceeding the Linux counter limit.
        private boolean canWrite(long increment) {
            long sum = value + increment;
            return Long.compareUnsigned(sum, value) >= 0 && sum != -1L;
        }

        /// Notifies poll waiters when a counter transition can affect readiness.
        private void notifyReadyChange() {
            notifyAll();
            if (changeNotifier != null) {
                changeNotifier.run();
            }
        }
    }

    /// One descriptor interest stored in an in-memory Linux `epoll` set.
    ///
    /// @param fileDescriptor the watched guest file descriptor
    /// @param events the event mask requested by the guest
    /// @param data the opaque guest data returned with readiness notifications
    protected record EpollInterest(
            int fileDescriptor,
            int events,
            long data) {
    }

    /// Stores descriptor interests for a single in-memory Linux `epoll` descriptor.
    protected static final class EpollSet {
        /// Ordered descriptor interests registered by the guest.
        private final ArrayList<EpollInterest> interests = new ArrayList<>();

        /// Adds a new descriptor interest or returns a raw negative Linux error.
        synchronized long add(int fileDescriptor, int events, long data) {
            if (findIndex(fileDescriptor) >= 0) {
                return EEXIST;
            }

            interests.add(new EpollInterest(fileDescriptor, events, data));
            return 0;
        }

        /// Replaces an existing descriptor interest or returns a raw negative Linux error.
        synchronized long modify(int fileDescriptor, int events, long data) {
            int index = findIndex(fileDescriptor);
            if (index < 0) {
                return ENOENT;
            }

            interests.set(index, new EpollInterest(fileDescriptor, events, data));
            return 0;
        }

        /// Removes an existing descriptor interest or returns a raw negative Linux error.
        synchronized long remove(int fileDescriptor) {
            int index = findIndex(fileDescriptor);
            if (index < 0) {
                return ENOENT;
            }

            interests.remove(index);
            return 0;
        }

        /// Returns the number of registered descriptor interests.
        synchronized int size() {
            return interests.size();
        }

        /// Returns the descriptor interest at the supplied index.
        synchronized EpollInterest interest(int index) {
            return interests.get(index);
        }

        /// Returns the index of the descriptor interest, or `-1` when absent.
        private int findIndex(int fileDescriptor) {
            for (int index = 0; index < interests.size(); index++) {
                if (interests.get(index).fileDescriptor() == fileDescriptor) {
                    return index;
                }
            }
            return -1;
        }
    }

    /// Stores buffered bytes for a single in-memory pipe.
    protected static final class PipeBuffer {
        /// The initial pipe buffer capacity used before the first expansion.
        private static final int INITIAL_CAPACITY = 64;

        /// The circular byte buffer containing unread pipe bytes.
        private byte[] buffer = new byte[INITIAL_CAPACITY];

        /// The index of the first unread byte in `buffer`.
        private int start;

        /// The number of unread bytes currently stored in `buffer`.
        private int length;

        /// Whether at least one read endpoint is still open.
        private boolean readerOpen = true;

        /// Whether at least one write endpoint is still open.
        private boolean writerOpen = true;

        /// Notifies blocking poll syscalls that readiness may have changed.
        private final @Nullable Runnable changeNotifier;

        /// Creates a pipe buffer without an external readiness notifier.
        PipeBuffer() {
            this(null);
        }

        /// Creates a pipe buffer with an optional readiness notifier.
        PipeBuffer(@Nullable Runnable changeNotifier) {
            this.changeNotifier = changeNotifier;
        }

        /// Reads up to the requested byte count into the supplied destination.
        synchronized int read(byte[] destination, int maximumLength, boolean nonblocking) throws InterruptedException {
            if (length == 0) {
                if (nonblocking) {
                    return writerOpen ? (int) EAGAIN : 0;
                }
                while (length == 0 && writerOpen) {
                    wait();
                }
                if (length == 0) {
                    return 0;
                }
            }

            int count = Math.min(maximumLength, length);
            int firstCount = Math.min(count, buffer.length - start);
            System.arraycopy(buffer, start, destination, 0, firstCount);
            int secondCount = count - firstCount;
            if (secondCount > 0) {
                System.arraycopy(buffer, 0, destination, firstCount, secondCount);
            }

            start = (start + count) % buffer.length;
            length -= count;
            if (length == 0) {
                start = 0;
            }
            return count;
        }

        /// Writes all supplied bytes to the pipe buffer.
        synchronized long write(byte[] source) {
            if (!readerOpen) {
                return EPIPE;
            }

            ensureCapacity(length + source.length);
            int writeIndex = (start + length) % buffer.length;
            int firstCount = Math.min(source.length, buffer.length - writeIndex);
            System.arraycopy(source, 0, buffer, writeIndex, firstCount);
            int secondCount = source.length - firstCount;
            if (secondCount > 0) {
                System.arraycopy(source, firstCount, buffer, 0, secondCount);
            }
            length += source.length;
            notifyAll();
            notifyReadyChange();
            return source.length;
        }

        /// Marks the read endpoint as closed.
        synchronized void closeReader() {
            readerOpen = false;
            notifyAll();
            notifyReadyChange();
        }

        /// Marks the write endpoint as closed.
        synchronized void closeWriter() {
            writerOpen = false;
            notifyAll();
            notifyReadyChange();
        }

        /// Returns true when a read endpoint would observe data or end-of-file immediately.
        synchronized boolean isReadable() {
            return length > 0 || !writerOpen;
        }

        /// Returns true when at least one read endpoint is still open.
        synchronized boolean isReaderOpen() {
            return readerOpen;
        }

        /// Returns true when at least one write endpoint is still open.
        synchronized boolean isWriterOpen() {
            return writerOpen;
        }

        /// Expands the circular buffer while preserving unread byte order.
        private void ensureCapacity(int requestedCapacity) {
            if (requestedCapacity <= buffer.length) {
                return;
            }

            int newCapacity = buffer.length;
            while (newCapacity < requestedCapacity) {
                newCapacity *= 2;
            }

            byte[] newBuffer = new byte[newCapacity];
            int firstCount = Math.min(length, buffer.length - start);
            System.arraycopy(buffer, start, newBuffer, 0, firstCount);
            int secondCount = length - firstCount;
            if (secondCount > 0) {
                System.arraycopy(buffer, 0, newBuffer, firstCount, secondCount);
            }

            buffer = newBuffer;
            start = 0;
        }

        /// Notifies poll waiters when a buffer transition can affect readiness.
        private void notifyReadyChange() {
            if (changeNotifier != null) {
                changeNotifier.run();
            }
        }
    }

    /// Stores the two byte streams that make up one pseudoterminal pair.
    protected static final class PtyDevice {
        /// The stable slave number exposed below `/dev/pts`.
        private final int number;

        /// Bytes written by the slave endpoint and read by the master endpoint.
        private final PipeBuffer masterInput;

        /// Bytes written by the master endpoint and read by the slave endpoint.
        private final PipeBuffer slaveInput;

        /// Whether the slave endpoint is currently locked against path-based opens.
        private boolean locked = true;

        /// Creates a pseudoterminal pair with the supplied slave number.
        PtyDevice(int number, @Nullable Runnable changeNotifier) {
            this.number = number;
            this.masterInput = new PipeBuffer(changeNotifier);
            this.slaveInput = new PipeBuffer(changeNotifier);
        }

        /// Returns the slave number exposed through `TIOCGPTN`.
        int number() {
            return number;
        }

        /// Updates whether the slave endpoint is locked.
        synchronized void setLocked(boolean locked) {
            this.locked = locked;
        }

        /// Returns whether the slave endpoint is locked.
        synchronized boolean locked() {
            return locked;
        }

        /// Returns the buffer read by the master endpoint.
        PipeBuffer masterInput() {
            return masterInput;
        }

        /// Returns the buffer read by the slave endpoint.
        PipeBuffer slaveInput() {
            return slaveInput;
        }
    }

    /// Describes one open endpoint of a pseudoterminal pair.
    ///
    /// @param device the pseudoterminal pair backing this endpoint
    /// @param master whether this endpoint is the master side
    protected record PtyEndpoint(PtyDevice device, boolean master) {
        /// Creates the master endpoint of a pseudoterminal pair.
        static PtyEndpoint master(PtyDevice device) {
            return new PtyEndpoint(device, true);
        }

        /// Creates the slave endpoint of a pseudoterminal pair.
        static PtyEndpoint slave(PtyDevice device) {
            return new PtyEndpoint(device, false);
        }

        /// Reads bytes visible to this endpoint.
        int read(byte[] destination, int maximumLength, boolean nonblocking) throws InterruptedException {
            return input().read(destination, maximumLength, nonblocking);
        }

        /// Writes bytes to the peer endpoint.
        long write(byte[] source) {
            return output().write(source);
        }

        /// Returns true when a read can complete immediately.
        boolean isReadable() {
            return input().isReadable();
        }

        /// Returns true when the peer still has a write endpoint open.
        boolean isPeerWriterOpen() {
            return input().isWriterOpen();
        }

        /// Returns true when the peer still has a read endpoint open.
        boolean isPeerReaderOpen() {
            return output().isReaderOpen();
        }

        /// Closes this endpoint's read and write sides.
        void close() {
            input().closeReader();
            output().closeWriter();
        }

        /// Returns the buffer this endpoint reads from.
        private PipeBuffer input() {
            return master ? device.masterInput() : device.slaveInput();
        }

        /// Returns the buffer this endpoint writes to.
        private PipeBuffer output() {
            return master ? device.slaveInput() : device.masterInput();
        }
    }

    /// Describes an open file description referenced by one or more guest file descriptors.
    @NotNullByDefault
    protected static final class OpenFile {
        /// The original standard descriptor number, or `-1` for non-standard entries.
        private final int standardFileDescriptor;

        /// The resolved host path backing the guest file descriptor.
        private final @Nullable Path path;

        /// The guest-visible absolute path backing this descriptor, or null when none exists.
        private final @Nullable String guestPath;

        /// The tar node backing this descriptor, or null for non-tar entries.
        private final @Nullable TarNode tarNode;

        /// The virtual node backing this descriptor, or null for non-virtual entries.
        private final @Nullable VirtualNode virtualNode;

        /// The virtual mount backing this descriptor, or null for non-virtual entries.
        private final @Nullable VirtualMount virtualMount;

        /// The host file channel backing a regular host or tar file descriptor.
        private final @Nullable SeekableByteChannel channel;

        /// The pipe buffer backing a pipe endpoint.
        private final @Nullable PipeBuffer pipe;

        /// The counter backing an eventfd descriptor.
        private final @Nullable EventCounter eventCounter;

        /// The timer backing a timerfd descriptor.
        private final @Nullable TimerFile timerFile;

        /// The interest set backing an epoll descriptor.
        private final @Nullable EpollSet epollSet;

        /// The socket object backing this descriptor, or null for non-socket entries.
        private final @Nullable GuestSocket socket;

        /// The terminal device backing this descriptor, or null for non-terminal entries.
        private final @Nullable TerminalDevice terminalDevice;

        /// The pseudoterminal endpoint backing this descriptor, or null for non-PTY entries.
        private final @Nullable PtyEndpoint ptyEndpoint;

        /// The process target backing this descriptor, or null for non-pidfd entries.
        private final @Nullable ProcessFile processFile;

        /// Whether this descriptor is backed by `/dev/null`.
        private final boolean nullDevice;

        /// Whether this descriptor refers to a directory.
        private final boolean directory;

        /// Whether this descriptor is the read endpoint of a pipe.
        private final boolean pipeReader;

        /// Whether this descriptor is the write endpoint of a pipe.
        private final boolean pipeWriter;

        /// Whether the guest file descriptor permits reads.
        private final boolean readable;

        /// Whether the guest file descriptor permits writes.
        private final boolean writable;

        /// Whether writes append to the current end of a host file.
        private final boolean append;

        /// Whether empty pipe reads should return `EAGAIN`.
        private boolean nonblocking;

        /// The cached directory entries for this descriptor, or null until first `getdents64`.
        private @Nullable DirectoryEntry[] directoryEntries;

        /// The next directory entry index returned by `getdents64`.
        private int directoryEntryIndex;

        /// The current byte offset for seekable virtual character devices.
        private long deviceOffset;

        /// The number of guest descriptor table slots sharing this entry.
        private int references = 1;

        /// Creates a non-socket file descriptor entry.
        private OpenFile(
                int standardFileDescriptor,
                @Nullable Path path,
                @Nullable String guestPath,
                @Nullable TarNode tarNode,
                @Nullable VirtualNode virtualNode,
                @Nullable VirtualMount virtualMount,
                @Nullable SeekableByteChannel channel,
                @Nullable PipeBuffer pipe,
                @Nullable EventCounter eventCounter,
                @Nullable EpollSet epollSet,
                @Nullable TerminalDevice terminalDevice,
                boolean nullDevice,
                boolean directory,
                boolean pipeReader,
                boolean pipeWriter,
                boolean readable,
                boolean writable,
                boolean append,
                boolean nonblocking) {
            this(
                    standardFileDescriptor,
                    path,
                    guestPath,
                    tarNode,
                    virtualNode,
                    virtualMount,
                    channel,
                    pipe,
                    eventCounter,
                    null,
                    epollSet,
                    null,
                    terminalDevice,
                    null,
                    nullDevice,
                    directory,
                    pipeReader,
                    pipeWriter,
                    readable,
                    writable,
                    append,
                    nonblocking);
        }

        /// Creates a file descriptor entry.
        private OpenFile(
                int standardFileDescriptor,
                @Nullable Path path,
                @Nullable String guestPath,
                @Nullable TarNode tarNode,
                @Nullable VirtualNode virtualNode,
                @Nullable VirtualMount virtualMount,
                @Nullable SeekableByteChannel channel,
                @Nullable PipeBuffer pipe,
                @Nullable EventCounter eventCounter,
                @Nullable TimerFile timerFile,
                @Nullable EpollSet epollSet,
                @Nullable GuestSocket socket,
                @Nullable TerminalDevice terminalDevice,
                @Nullable PtyEndpoint ptyEndpoint,
                boolean nullDevice,
                boolean directory,
                boolean pipeReader,
                boolean pipeWriter,
                boolean readable,
                boolean writable,
                boolean append,
                boolean nonblocking) {
            this.standardFileDescriptor = standardFileDescriptor;
            this.path = path;
            this.guestPath = guestPath;
            this.tarNode = tarNode;
            this.virtualNode = virtualNode;
            this.virtualMount = virtualMount;
            this.channel = channel;
            this.pipe = pipe;
            this.eventCounter = eventCounter;
            this.timerFile = timerFile;
            this.epollSet = epollSet;
            this.socket = socket;
            this.terminalDevice = terminalDevice;
            this.ptyEndpoint = ptyEndpoint;
            this.processFile = null;
            this.nullDevice = nullDevice;
            this.directory = directory;
            this.pipeReader = pipeReader;
            this.pipeWriter = pipeWriter;
            this.readable = readable;
            this.writable = writable;
            this.append = append;
            this.nonblocking = nonblocking;
        }

        /// Creates a Linux process file descriptor entry.
        private OpenFile(ProcessFile processFile, boolean nonblocking) {
            this.standardFileDescriptor = -1;
            this.path = null;
            this.guestPath = null;
            this.tarNode = null;
            this.virtualNode = null;
            this.virtualMount = null;
            this.channel = null;
            this.pipe = null;
            this.eventCounter = null;
            this.timerFile = null;
            this.epollSet = null;
            this.socket = null;
            this.terminalDevice = null;
            this.ptyEndpoint = null;
            this.processFile = processFile;
            this.nullDevice = false;
            this.directory = false;
            this.pipeReader = false;
            this.pipeWriter = false;
            this.readable = true;
            this.writable = true;
            this.append = false;
            this.nonblocking = nonblocking;
        }

        /// Creates an entry backed by a host file channel.
        static OpenFile hostFile(
                Path path,
                @Nullable String guestPath,
                SeekableByteChannel channel,
                boolean readable,
                boolean writable,
                boolean append) {
            return new OpenFile(
                    -1,
                    path,
                    guestPath,
                    null,
                    null,
                    null,
                    channel,
                    null,
                    null,
                    null,
                    null,
                    false,
                    false,
                    false,
                    false,
                    readable,
                    writable,
                    append,
                    false);
        }

        /// Creates an entry backed by a host directory path.
        static OpenFile hostDirectory(Path path, String guestPath) {
            return new OpenFile(
                    -1,
                    path,
                    guestPath,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    false,
                    true,
                    false,
                    false,
                    true,
                    false,
                    false,
                    false);
        }

        /// Creates an entry backed by a tar file.
        static OpenFile tarFile(
                TarNode node,
                String guestPath,
                SeekableByteChannel channel,
                boolean readable,
                boolean writable,
                boolean append) {
            return new OpenFile(
                    -1,
                    null,
                    guestPath,
                    node,
                    null,
                    null,
                    channel,
                    null,
                    null,
                    null,
                    null,
                    false,
                    false,
                    false,
                    false,
                    readable,
                    writable,
                    append,
                    false);
        }

        /// Creates an entry backed by a tar directory.
        static OpenFile tarDirectory(TarNode node, String guestPath) {
            return new OpenFile(
                    -1,
                    null,
                    guestPath,
                    node,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    false,
                    true,
                    false,
                    false,
                    true,
                    false,
                    false,
                    false);
        }

        /// Creates an entry backed by a read-only virtual file.
        static OpenFile virtualFile(
                VirtualNode node,
                VirtualMount mount,
                String guestPath,
                SeekableByteChannel channel,
                boolean readable) {
            return new OpenFile(
                    -1,
                    null,
                    guestPath,
                    null,
                    node,
                    mount,
                    channel,
                    null,
                    null,
                    null,
                    null,
                    false,
                    false,
                    false,
                    false,
                    readable,
                    false,
                    false,
                    false);
        }

        /// Creates an entry backed by a virtual directory.
        static OpenFile virtualDirectory(VirtualNode node, VirtualMount mount, String guestPath) {
            return new OpenFile(
                    -1,
                    null,
                    guestPath,
                    null,
                    node,
                    mount,
                    null,
                    null,
                    null,
                    null,
                    null,
                    false,
                    true,
                    false,
                    false,
                    true,
                    false,
                    false,
                    false);
        }

        /// Creates an entry backed by a virtual terminal character device.
        static OpenFile terminalDevice(
                VirtualNode node,
                VirtualMount mount,
                String guestPath,
                TerminalDevice terminalDevice,
                boolean readable,
                boolean writable) {
            return new OpenFile(
                    -1,
                    null,
                    guestPath,
                    null,
                    node,
                    mount,
                    null,
                    null,
                    null,
                    null,
                    terminalDevice,
                    false,
                    false,
                    false,
                    false,
                    readable,
                    writable,
                    false,
                    false);
        }

        /// Creates an entry backed by a virtual pseudoterminal endpoint.
        static OpenFile ptyEndpoint(
                VirtualNode node,
                VirtualMount mount,
                String guestPath,
                PtyEndpoint ptyEndpoint,
                boolean readable,
                boolean writable,
                boolean nonblocking) {
            return new OpenFile(
                    -1,
                    null,
                    guestPath,
                    null,
                    node,
                    mount,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    ptyEndpoint,
                    false,
                    false,
                    false,
                    false,
                    readable,
                    writable,
                    false,
                    nonblocking);
        }

        /// Creates an entry backed by the virtual `/dev/null` character device.
        static OpenFile nullDevice(
                VirtualNode node,
                VirtualMount mount,
                String guestPath,
                boolean readable,
                boolean writable) {
            return new OpenFile(
                    -1,
                    null,
                    guestPath,
                    null,
                    node,
                    mount,
                    null,
                    null,
                    null,
                    null,
                    null,
                    true,
                    false,
                    false,
                    false,
                    readable,
                    writable,
                    false,
                    false);
        }

        /// Creates an entry backed by a non-terminal virtual character device.
        static OpenFile characterDevice(
                VirtualNode node,
                VirtualMount mount,
                String guestPath,
                boolean readable,
                boolean writable) {
            return new OpenFile(
                    -1,
                    null,
                    guestPath,
                    null,
                    node,
                    mount,
                    null,
                    null,
                    null,
                    null,
                    null,
                    false,
                    false,
                    false,
                    false,
                    readable,
                    writable,
                    false,
                    false);
        }

        /// Creates an entry that duplicates a standard stream descriptor.
        static OpenFile standardFileDescriptor(int fileDescriptor) {
            return standardFileDescriptor(fileDescriptor, null);
        }

        /// Creates an entry that duplicates a standard stream descriptor with a guest-visible path.
        static OpenFile standardFileDescriptor(int fileDescriptor, @Nullable String guestPath) {
            return new OpenFile(
                    fileDescriptor,
                    null,
                    guestPath,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    false,
                    false,
                    false,
                    false,
                    fileDescriptor == 0,
                    fileDescriptor == 1 || fileDescriptor == 2,
                    false,
                    false);
        }

        /// Creates the read endpoint of a pipe.
        static OpenFile pipeReader(PipeBuffer pipe, boolean nonblocking) {
            return new OpenFile(
                    -1,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    pipe,
                    null,
                    null,
                    null,
                    false,
                    false,
                    true,
                    false,
                    true,
                    false,
                    false,
                    nonblocking);
        }

        /// Creates the write endpoint of a pipe.
        static OpenFile pipeWriter(PipeBuffer pipe, boolean nonblocking) {
            return new OpenFile(
                    -1,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    pipe,
                    null,
                    null,
                    null,
                    false,
                    false,
                    false,
                    true,
                    false,
                    true,
                    false,
                    nonblocking);
        }

        /// Creates an entry backed by an eventfd counter.
        static OpenFile eventFile(EventCounter eventCounter) {
            return new OpenFile(
                    -1,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    eventCounter,
                    null,
                    null,
                    false,
                    false,
                    false,
                    false,
                    true,
                    true,
                    false,
                    eventCounter.nonblocking());
        }

        /// Creates an entry backed by a timerfd timer.
        static OpenFile timerFile(TimerFile timerFile) {
            return new OpenFile(
                    -1,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    timerFile,
                    null,
                    null,
                    null,
                    null,
                    false,
                    false,
                    false,
                    false,
                    true,
                    true,
                    false,
                    timerFile.nonblocking());
        }

        /// Creates an entry backed by an epoll interest set.
        static OpenFile epollFile(EpollSet epollSet) {
            return new OpenFile(
                    -1,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    epollSet,
                    null,
                    false,
                    false,
                    false,
                    false,
                    true,
                    false,
                    false,
                    false);
        }

        /// Creates an entry backed by a guest socket object.
        static OpenFile socket(GuestSocket socket, boolean nonblocking) {
            return new OpenFile(
                    -1,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    socket,
                    null,
                    null,
                    false,
                    false,
                    false,
                    false,
                    true,
                    true,
                    false,
                    nonblocking);
        }

        /// Creates an entry backed by a Linux process file descriptor target.
        static OpenFile processFile(ProcessFile processFile, boolean nonblocking) {
            return new OpenFile(processFile, nonblocking);
        }

        /// Returns true when this entry duplicates one of the original standard streams.
        boolean isStandardFileDescriptor() {
            return standardFileDescriptor >= 0;
        }

        /// Returns the original standard descriptor number.
        int standardFileDescriptor() {
            return standardFileDescriptor;
        }

        /// Returns true when this entry is backed by a seekable file channel.
        boolean isHostFile() {
            return channel != null;
        }

        /// Returns true when this entry is backed by a pipe endpoint.
        boolean isPipe() {
            return pipe != null;
        }

        /// Returns true when this entry is backed by an eventfd counter.
        boolean isEventFile() {
            return eventCounter != null;
        }

        /// Returns true when this entry is backed by a timerfd timer.
        boolean isTimerFile() {
            return timerFile != null;
        }

        /// Returns true when this entry is backed by an epoll interest set.
        boolean isEpollFile() {
            return epollSet != null;
        }

        /// Returns true when this entry is backed by a guest socket.
        boolean isSocket() {
            return socket != null;
        }

        /// Returns true when this entry is backed by a Linux process file descriptor target.
        boolean isProcessFile() {
            return processFile != null;
        }

        /// Returns true when this entry is backed by a virtual terminal device.
        boolean isTerminalDevice() {
            return terminalDevice != null;
        }

        /// Returns true when this entry is backed by a pseudoterminal endpoint.
        boolean isPtyEndpoint() {
            return ptyEndpoint != null;
        }

        /// Returns true when this entry is backed by `/dev/null`.
        boolean isNullDevice() {
            return nullDevice;
        }

        /// Returns true when this entry refers to a directory.
        boolean isDirectory() {
            return directory;
        }

        /// Returns true when this entry is a pipe read endpoint.
        boolean isPipeReader() {
            return pipeReader;
        }

        /// Returns true when this entry is a pipe write endpoint.
        boolean isPipeWriter() {
            return pipeWriter;
        }

        /// Returns the seekable channel backing this descriptor.
        SeekableByteChannel channel() {
            assert channel != null;
            return channel;
        }

        /// Returns the pipe buffer backing this descriptor.
        PipeBuffer pipe() {
            assert pipe != null;
            return pipe;
        }

        /// Returns the eventfd counter backing this descriptor.
        EventCounter eventCounter() {
            assert eventCounter != null;
            return eventCounter;
        }

        /// Returns the timerfd timer backing this descriptor.
        TimerFile timerFile() {
            assert timerFile != null;
            return timerFile;
        }

        /// Returns the epoll interest set backing this descriptor.
        EpollSet epollSet() {
            assert epollSet != null;
            return epollSet;
        }

        /// Returns the guest socket backing this descriptor.
        GuestSocket socket() {
            assert socket != null;
            return socket;
        }

        /// Returns the Linux process file descriptor target backing this descriptor.
        ProcessFile processFile() {
            assert processFile != null;
            return processFile;
        }

        /// Returns the terminal device backing this descriptor.
        TerminalDevice terminalDevice() {
            assert terminalDevice != null;
            return terminalDevice;
        }

        /// Returns the pseudoterminal endpoint backing this descriptor.
        PtyEndpoint ptyEndpoint() {
            assert ptyEndpoint != null;
            return ptyEndpoint;
        }

        /// Returns the host path backing this descriptor.
        @Nullable Path path() {
            return path;
        }

        /// Returns the guest-visible absolute path backing this descriptor.
        @Nullable String guestPath() {
            return guestPath;
        }

        /// Returns the tar node backing this descriptor.
        @Nullable TarNode tarNode() {
            return tarNode;
        }

        /// Returns the virtual node backing this descriptor.
        @Nullable VirtualNode virtualNode() {
            return virtualNode;
        }

        /// Returns the virtual mount backing this descriptor.
        @Nullable VirtualMount virtualMount() {
            return virtualMount;
        }

        /// Returns true when this entry is backed by a tar filesystem node.
        boolean isTarEntry() {
            return tarNode != null;
        }

        /// Returns true when this entry is backed by a virtual filesystem node.
        boolean isVirtualEntry() {
            return virtualNode != null;
        }

        /// Returns true when this entry is backed by a virtual character device node.
        boolean isCharacterDevice() {
            return virtualNode != null && virtualNode.isCharacterDevice();
        }

        /// Returns the current byte offset for seekable virtual character devices.
        long deviceOffset() {
            return deviceOffset;
        }

        /// Updates the current byte offset for seekable virtual character devices.
        void setDeviceOffset(long deviceOffset) {
            this.deviceOffset = deviceOffset;
        }

        /// Advances the current byte offset for seekable virtual character devices.
        void advanceDeviceOffset(long count) {
            deviceOffset += count;
        }

        /// Returns true when reads are permitted.
        boolean readable() {
            return readable;
        }

        /// Returns true when writes are permitted.
        boolean writable() {
            return writable;
        }

        /// Returns true when host file writes append to the end of file.
        boolean append() {
            return append;
        }

        /// Returns true when pipe reads are nonblocking.
        boolean nonblocking() {
            return nonblocking;
        }

        /// Updates whether the open-file status flags include `O_NONBLOCK`.
        void setNonblocking(boolean nonblocking) {
            this.nonblocking = nonblocking;
        }

        /// Returns cached directory entries, or null when the descriptor has not been listed yet.
        @Nullable DirectoryEntry[] directoryEntries() {
            return directoryEntries;
        }

        /// Stores cached directory entries for repeated `getdents64` calls.
        void setDirectoryEntries(DirectoryEntry[] directoryEntries) {
            this.directoryEntries = directoryEntries;
        }

        /// Returns the next directory entry index for `getdents64`.
        int directoryEntryIndex() {
            return directoryEntryIndex;
        }

        /// Updates the next directory entry index for `getdents64`.
        void setDirectoryEntryIndex(int directoryEntryIndex) {
            this.directoryEntryIndex = directoryEntryIndex;
        }

        /// Adds one guest descriptor reference to this entry.
        synchronized void retain() {
            references++;
        }

        /// Removes one guest descriptor reference and returns true when this entry is no longer referenced.
        synchronized boolean release() {
            references--;
            if (references < 0) {
                throw new AssertionError("open file reference count became negative");
            }
            return references == 0;
        }

        /// Closes the backing object after the last guest descriptor reference is released.
        void close() throws IOException {
            if (channel != null) {
                channel.close();
                return;
            }
            if (pipe != null) {
                if (pipeReader) {
                    pipe.closeReader();
                }
                if (pipeWriter) {
                    pipe.closeWriter();
                }
                return;
            }
            if (ptyEndpoint != null) {
                ptyEndpoint.close();
                return;
            }
            if (socket != null) {
                socket.close();
            }
        }
    }
}
