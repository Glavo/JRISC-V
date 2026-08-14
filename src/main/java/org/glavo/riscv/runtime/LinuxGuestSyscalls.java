// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.riscv.runtime;

import org.glavo.riscv.exception.IllegalInstructionException;
import org.glavo.riscv.exception.MemoryAccessException;
import org.glavo.riscv.exception.ProgramExitException;
import org.glavo.riscv.constants.RiscVExtensions;
import org.glavo.riscv.constants.Rva22Profile;
import org.glavo.riscv.constants.Rva23Profile;
import org.glavo.riscv.exception.RiscVException;
import org.glavo.riscv.memory.Memory;
import org.glavo.riscv.runtime.fs.GuestFileSystem;
import org.glavo.riscv.runtime.net.GuestNetworkBackend;
import org.glavo.riscv.runtime.net.GuestNetworkMode;
import org.glavo.riscv.runtime.net.GuestSocket;
import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Unmodifiable;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.BindException;
import java.net.ConnectException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.ProtocolFamily;
import java.net.ProtocolException;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.StandardProtocolFamily;
import java.net.StandardSocketOptions;
import java.net.UnknownHostException;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AlreadyConnectedException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ConnectionPendingException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.NetworkChannel;
import java.nio.channels.NoConnectionPendingException;
import java.nio.channels.NotYetConnectedException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.UnresolvedAddressException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;

/// Handles the Linux-compatible syscall subset exposed by the simulator.
@NotNullByDefault
public non-sealed class LinuxGuestSyscalls extends GuestSyscalls {
    /// The backend used for guest Internet sockets.
    protected GuestNetworkBackend networkBackend = GuestNetworkMode.NONE.backend();

    /// Creates a Linux syscall handler backed by the supplied host streams and heap boundary.
    public LinuxGuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak) {
        super(memory, in, out, err, initialProgramBreak);
    }

    /// Creates a Linux syscall handler backed by the supplied host streams, heap boundary, and resolved root mount.
    public LinuxGuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            @Nullable Path hostRoot) {
        super(memory, in, out, err, initialProgramBreak, hostRoot);
    }

    /// Creates a Linux syscall handler backed by the supplied streams, resolved root mount, and guest time source.
    public LinuxGuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            @Nullable Path hostRoot,
            TimeSource timeSource) {
        super(memory, in, out, err, initialProgramBreak, hostRoot, timeSource);
    }

    /// Creates a Linux syscall handler backed by the supplied streams, filesystem namespace, and guest time source.
    public LinuxGuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            GuestFileSystem fileSystem,
            TimeSource timeSource) {
        super(memory, in, out, err, initialProgramBreak, fileSystem, timeSource);
    }

    /// Creates a Linux syscall handler backed by streams, filesystem namespace, guest time source, and credentials.
    public LinuxGuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            GuestFileSystem fileSystem,
            TimeSource timeSource,
            GuestCredentials credentials) {
        super(memory, in, out, err, initialProgramBreak, fileSystem, timeSource, credentials);
    }

    /// Creates a Linux syscall handler backed by the supplied host streams, heap boundary, and lazy root mount.
    public LinuxGuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String hostRootPath) {
        super(memory, in, out, err, initialProgramBreak, hostRootPath);
    }

    /// Creates a Linux syscall handler backed by the supplied streams, lazy root mount, and guest time source.
    public LinuxGuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String hostRootPath,
            TimeSource timeSource) {
        super(memory, in, out, err, initialProgramBreak, hostRootPath, timeSource);
    }

    /// Creates a Linux syscall handler backed by streams, lazy root mount, guest time source, and guest thread runner.
    public LinuxGuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String hostRootPath,
            TimeSource timeSource,
            GuestThreadRunner guestThreadRunner) {
        super(memory, in, out, err, initialProgramBreak, hostRootPath, timeSource, guestThreadRunner);
    }

    /// Creates a Linux syscall handler backed by streams, lazy root mount, guest time source, terminal option,
    /// and guest thread runner.
    public LinuxGuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String hostRootPath,
            TimeSource timeSource,
            boolean useHostTty,
            GuestThreadRunner guestThreadRunner) {
        super(memory, in, out, err, initialProgramBreak, hostRootPath, timeSource, useHostTty, guestThreadRunner);
    }

    /// Creates a Linux syscall handler backed by the supplied streams, lazy filesystem mounts, and guest time source.
    public LinuxGuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String @Unmodifiable [] filesystemMountSpecs,
            TimeSource timeSource) {
        super(memory, in, out, err, initialProgramBreak, filesystemMountSpecs, timeSource);
    }

    /// Creates a Linux syscall handler backed by streams, lazy filesystem mounts, guest time source,
    /// and guest thread runner.
    public LinuxGuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String @Unmodifiable [] filesystemMountSpecs,
            TimeSource timeSource,
            GuestThreadRunner guestThreadRunner) {
        super(memory, in, out, err, initialProgramBreak, filesystemMountSpecs, timeSource, guestThreadRunner);
    }

    /// Creates a Linux syscall handler backed by streams, lazy filesystem mounts, guest time source,
    /// terminal option, and guest thread runner.
    public LinuxGuestSyscalls(
            Memory memory,
            InputStream in,
            OutputStream out,
            OutputStream err,
            long initialProgramBreak,
            String @Unmodifiable [] filesystemMountSpecs,
            TimeSource timeSource,
            boolean useHostTty,
            GuestThreadRunner guestThreadRunner) {
        super(
                memory,
                in,
                out,
                err,
                initialProgramBreak,
                filesystemMountSpecs,
                timeSource,
                useHostTty,
                guestThreadRunner);
    }

    /// Creates a Linux syscall handler backed by streams, lazy filesystem mounts, time source, credentials,
    /// terminal option, and guest thread runner.
    public LinuxGuestSyscalls(
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
                guestThreadRunner);
    }

    /// Creates a Linux syscall handler backed by streams, lazy filesystem mounts, time source, credentials,
    /// terminal option, guest thread runner, and framebuffer device.
    public LinuxGuestSyscalls(
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

    /// Creates a Linux syscall handler backed by streams, filesystem, devices, and networking.
    public LinuxGuestSyscalls(
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
                GuestFileSystem.forMountSpecs(filesystemMountSpecs),
                timeSource,
                useHostTty,
                credentials,
                guestThreadRunner,
                framebufferDevice);
        this.networkBackend = networkBackend;
    }

    /// Linux `CLONE_VM`.
    private static final long CLONE_VM = 0x00000100L;

    /// Linux `CSIGNAL` clone exit-signal mask.
    private static final long CLONE_EXIT_SIGNAL_MASK = 0xffL;

    /// Linux `SIGCHLD`.
    private static final long SIGNAL_CHILD = 17L;

    /// Linux `P_ALL` wait selector.
    private static final int WAIT_ID_ALL = 0;

    /// Linux `P_PID` wait selector.
    private static final int WAIT_ID_PROCESS = 1;

    /// Linux `P_PGID` wait selector.
    private static final int WAIT_ID_PROCESS_GROUP = 2;

    /// Linux `P_PIDFD` wait selector.
    private static final int WAIT_ID_PROCESS_FILE_DESCRIPTOR = 3;

    /// Linux `PIDFD_NONBLOCK`.
    private static final long PIDFD_NONBLOCK = O_NONBLOCK;

    /// Linux `PIDFD_THREAD`.
    private static final long PIDFD_THREAD = O_EXCL;

    /// Linux flags accepted by `pidfd_open`.
    private static final long SUPPORTED_PIDFD_OPEN_FLAGS = PIDFD_NONBLOCK | PIDFD_THREAD;

    /// Linux `WEXITED`.
    private static final long WAIT_ID_EXITED = 0x0000_0004L;

    /// Linux `WNOWAIT`.
    private static final long WAIT_ID_NO_WAIT = 0x0100_0000L;

    /// Linux internal `__WNOTHREAD`.
    private static final long WAIT_ID_NOT_THREAD = 0x2000_0000L;

    /// Linux internal `__WALL`.
    private static final long WAIT_ID_ALL_CHILDREN = 0x4000_0000L;

    /// Linux internal `__WCLONE`.
    private static final long WAIT_ID_CLONE_CHILDREN = 0x8000_0000L;

    /// Linux `waitid` option bits accepted by the simulator.
    private static final long SUPPORTED_WAIT_ID_OPTIONS = WAIT_NO_HANG
            | WAIT_UNTRACED
            | WAIT_ID_EXITED
            | WAIT_CONTINUED
            | WAIT_ID_NO_WAIT
            | WAIT_ID_NOT_THREAD
            | WAIT_ID_ALL_CHILDREN
            | WAIT_ID_CLONE_CHILDREN;

    /// Linux `waitid` option bits that select reportable child events.
    private static final long WAIT_ID_EVENT_OPTIONS = WAIT_UNTRACED | WAIT_ID_EXITED | WAIT_CONTINUED;

    /// The byte size of Linux RISC-V `siginfo_t`.
    private static final long WAIT_ID_SIGNAL_INFO_SIZE = 128;

    /// The byte offset of `si_signo` inside Linux RISC-V `siginfo_t`.
    private static final long WAIT_ID_SIGNAL_NUMBER_OFFSET = 0;

    /// The byte offset of `si_errno` inside Linux RISC-V `siginfo_t`.
    private static final long WAIT_ID_ERRNO_OFFSET = Integer.BYTES;

    /// The byte offset of `si_code` inside Linux RISC-V `siginfo_t`.
    private static final long WAIT_ID_CODE_OFFSET = 2L * Integer.BYTES;

    /// The byte offset of `si_pid` inside Linux RISC-V `siginfo_t`.
    private static final long WAIT_ID_PROCESS_ID_OFFSET = 4L * Integer.BYTES;

    /// The byte offset of `si_uid` inside Linux RISC-V `siginfo_t`.
    private static final long WAIT_ID_USER_ID_OFFSET = 5L * Integer.BYTES;

    /// The byte offset of `si_status` inside Linux RISC-V `siginfo_t`.
    private static final long WAIT_ID_STATUS_OFFSET = 6L * Integer.BYTES;

    /// Linux `CLD_EXITED`.
    private static final int WAIT_ID_CHILD_EXITED = 1;

    /// Linux `SIGILL`.
    private static final long SIGNAL_ILLEGAL_INSTRUCTION = 4L;

    /// Linux `SIGSEGV`.
    private static final long SIGNAL_SEGMENTATION_FAULT = 11L;

    /// Linux `SIG_DFL`.
    private static final long SIGNAL_DEFAULT_HANDLER = 0L;

    /// Linux `SIG_IGN`.
    private static final long SIGNAL_IGNORE_HANDLER = 1L;

    /// Linux capability ABI version 1.
    private static final int LINUX_CAPABILITY_VERSION_1 = 0x1998_0330;

    /// Linux capability ABI version 2.
    private static final int LINUX_CAPABILITY_VERSION_2 = 0x2007_1026;

    /// Linux capability ABI version 3.
    private static final int LINUX_CAPABILITY_VERSION_3 = 0x2008_0522;

    /// The byte offset of `version` inside `struct __user_cap_header_struct`.
    private static final long CAPABILITY_HEADER_VERSION_OFFSET = 0;

    /// The byte offset of `pid` inside `struct __user_cap_header_struct`.
    private static final long CAPABILITY_HEADER_PID_OFFSET = Integer.BYTES;

    /// The byte size of one `struct __user_cap_data_struct`.
    private static final long CAPABILITY_DATA_SIZE = 3L * Integer.BYTES;

    /// The byte offset of `effective` inside `struct __user_cap_data_struct`.
    private static final long CAPABILITY_EFFECTIVE_OFFSET = 0;

    /// The byte offset of `permitted` inside `struct __user_cap_data_struct`.
    private static final long CAPABILITY_PERMITTED_OFFSET = Integer.BYTES;

    /// The byte offset of `inheritable` inside `struct __user_cap_data_struct`.
    private static final long CAPABILITY_INHERITABLE_OFFSET = 2L * Integer.BYTES;

    /// Linux `CAP_LAST_CAP` exposed by the simulator.
    private static final int CAPABILITY_LAST_CAP = 40;

    /// Linux `ILL_ILLOPC`.
    private static final int SIGNAL_CODE_ILLEGAL_OPCODE = 1;

    /// Linux `SA_ONSTACK`.
    private static final long SIGNAL_ACTION_ON_STACK = 0x08000000L;

    /// Linux `SA_NODEFER`.
    private static final long SIGNAL_ACTION_NODEFER = 0x40000000L;

    /// Linux `SA_RESETHAND`.
    private static final long SIGNAL_ACTION_RESET_HAND = 0x80000000L;

    /// The byte size of Linux generic 64-bit `siginfo_t`.
    private static final long SIGNAL_INFO_SIZE = 128;

    /// The byte offset of `si_signo` inside Linux generic 64-bit `siginfo_t`.
    private static final long SIGNAL_INFO_SIGNO_OFFSET = 0;

    /// The byte offset of `si_errno` inside Linux generic 64-bit `siginfo_t`.
    private static final long SIGNAL_INFO_ERRNO_OFFSET = Integer.BYTES;

    /// The byte offset of `si_code` inside Linux generic 64-bit `siginfo_t`.
    private static final long SIGNAL_INFO_CODE_OFFSET = 2L * Integer.BYTES;

    /// The byte offset of `si_addr` inside the Linux generic 64-bit `siginfo_t` fault union.
    private static final long SIGNAL_INFO_FAULT_ADDRESS_OFFSET = 2L * Long.BYTES;

    /// The byte offset of `sa_handler` inside Linux RISC-V 64-bit kernel `struct sigaction`.
    private static final long SIGNAL_ACTION_HANDLER_OFFSET = 0;

    /// The byte offset of `sa_flags` inside Linux RISC-V 64-bit kernel `struct sigaction`.
    private static final long SIGNAL_ACTION_FLAGS_OFFSET = Long.BYTES;

    /// The byte offset of `sa_mask` inside Linux RISC-V 64-bit kernel `struct sigaction`.
    private static final long SIGNAL_ACTION_MASK_OFFSET = 2L * Long.BYTES;

    /// The byte offset of `uc_flags` inside Linux RISC-V 64-bit `ucontext_t`.
    private static final long SIGNAL_CONTEXT_FLAGS_OFFSET = 0;

    /// The byte offset of `uc_link` inside Linux RISC-V 64-bit `ucontext_t`.
    private static final long SIGNAL_CONTEXT_LINK_OFFSET = Long.BYTES;

    /// The byte offset of `uc_stack` inside Linux RISC-V 64-bit `ucontext_t`.
    private static final long SIGNAL_CONTEXT_STACK_OFFSET = 2L * Long.BYTES;

    /// The byte offset of `uc_sigmask` inside Linux RISC-V 64-bit `ucontext_t`.
    private static final long SIGNAL_CONTEXT_MASK_OFFSET = 5L * Long.BYTES;

    /// The byte offset of `uc_mcontext` inside Linux RISC-V 64-bit `ucontext_t`.
    /// `mcontext_t` is 16-byte aligned, so glibc inserts padding after `uc_sigmask`.
    private static final long SIGNAL_CONTEXT_MACHINE_OFFSET = 176;

    /// The byte offset of general registers inside Linux RISC-V 64-bit `mcontext_t`.
    private static final long SIGNAL_MACHINE_REGISTERS_OFFSET = 0;

    /// The byte offset of floating-point registers inside Linux RISC-V 64-bit `mcontext_t`.
    private static final long SIGNAL_MACHINE_FLOATING_POINT_OFFSET = 32L * Long.BYTES;

    /// The byte size of Linux RISC-V 64-bit `mcontext_t`.
    private static final long SIGNAL_MACHINE_CONTEXT_SIZE = SIGNAL_MACHINE_FLOATING_POINT_OFFSET + 528;

    /// The byte offset of `struct __riscv_extra_ext_header.reserved` inside `mcontext_t`.
    private static final long SIGNAL_MACHINE_EXTRA_RESERVED_OFFSET = SIGNAL_MACHINE_FLOATING_POINT_OFFSET + 516;

    /// The byte offset of `struct __riscv_extra_ext_header.hdr.magic` inside `mcontext_t`.
    private static final long SIGNAL_MACHINE_EXTRA_MAGIC_OFFSET = SIGNAL_MACHINE_FLOATING_POINT_OFFSET + 520;

    /// The byte offset of `struct __riscv_extra_ext_header.hdr.size` inside `mcontext_t`.
    private static final long SIGNAL_MACHINE_EXTRA_SIZE_OFFSET = SIGNAL_MACHINE_FLOATING_POINT_OFFSET + 524;

    /// The byte offset of `siginfo_t` inside Linux RISC-V 64-bit `rt_sigframe`.
    private static final long SIGNAL_FRAME_INFO_OFFSET = 0;

    /// The byte offset of `ucontext_t` inside Linux RISC-V 64-bit `rt_sigframe`.
    private static final long SIGNAL_FRAME_CONTEXT_OFFSET = SIGNAL_INFO_SIZE;

    /// The rounded byte size of Linux RISC-V 64-bit `rt_sigframe`.
    private static final long SIGNAL_FRAME_SIZE = 1088;

    /// `addi a7, zero, __NR_rt_sigreturn`.
    private static final int SIGNAL_TRAMPOLINE_LOAD_SYSCALL = 0x08b00893;

    /// `ecall`.
    private static final int SIGNAL_TRAMPOLINE_ECALL = 0x00000073;

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

    /// Linux clone flags required for the supported thread-style parent return path.
    private static final long REQUIRED_THREAD_CLONE_FLAGS =
            CLONE_VM | CLONE_SIGHAND | CLONE_THREAD;

    /// Linux clone flags accepted by the supported thread-style parent return path.
    private static final long SUPPORTED_THREAD_CLONE_FLAGS =
            REQUIRED_THREAD_CLONE_FLAGS
                    | CLONE_FS
                    | CLONE_FILES
                    | CLONE_SYSVSEM
                    | CLONE_SETTLS
                    | CLONE_PARENT_SETTID
                    | CLONE_CHILD_CLEARTID
                    | CLONE_DETACHED
                    | CLONE_CHILD_SETTID;

    /// Clone flags accepted for independent child-process creation.
    private static final long SUPPORTED_PROCESS_CLONE_FLAGS =
            CLONE_EXIT_SIGNAL_MASK
                    | CLONE_VM
                    | CLONE_FS
                    | CLONE_FILES
                    | CLONE_PIDFD
                    | CLONE_VFORK
                    | CLONE_SYSVSEM
                    | CLONE_SETTLS
                    | CLONE_PARENT_SETTID
                    | CLONE_CHILD_CLEARTID
                    | CLONE_CHILD_SETTID;

    /// The minimum supported Linux `struct clone_args` byte size.
    private static final long CLONE_ARGS_MINIMUM_SIZE = 64;

    /// The known Linux `struct clone_args` byte size.
    private static final long CLONE_ARGS_KNOWN_SIZE = 88;

    /// The byte offset of `flags` inside `struct clone_args`.
    private static final long CLONE_ARGS_FLAGS_OFFSET = 0;

    /// The byte offset of `pidfd` inside `struct clone_args`.
    private static final long CLONE_ARGS_PIDFD_OFFSET = Long.BYTES;

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

    /// The byte offset of `set_tid` inside `struct clone_args`.
    private static final long CLONE_ARGS_SET_TID_OFFSET = 64;

    /// The byte offset of `set_tid_size` inside `struct clone_args`.
    private static final long CLONE_ARGS_SET_TID_SIZE_OFFSET = 72;

    /// The byte offset of `cgroup` inside `struct clone_args`.
    private static final long CLONE_ARGS_CGROUP_OFFSET = 80;

    /// The byte size of Linux `struct riscv_hwprobe`.
    private static final long RISCV_HWPROBE_PAIR_SIZE = 16;

    /// The byte offset of `key` inside `struct riscv_hwprobe`.
    private static final long RISCV_HWPROBE_KEY_OFFSET = 0;

    /// The byte offset of `value` inside `struct riscv_hwprobe`.
    private static final long RISCV_HWPROBE_VALUE_OFFSET = Long.BYTES;

    /// Linux `RISCV_HWPROBE_WHICH_CPUS`.
    private static final long RISCV_HWPROBE_WHICH_CPUS = 1;

    /// Linux `SYS_RISCV_FLUSH_ICACHE_LOCAL` flag.
    private static final long RISCV_FLUSH_ICACHE_LOCAL = 1;

    /// Linux `RISCV_HWPROBE_KEY_MVENDORID`.
    private static final long RISCV_HWPROBE_KEY_MVENDORID = 0;

    /// Linux `RISCV_HWPROBE_KEY_MARCHID`.
    private static final long RISCV_HWPROBE_KEY_MARCHID = 1;

    /// Linux `RISCV_HWPROBE_KEY_MIMPID`.
    private static final long RISCV_HWPROBE_KEY_MIMPID = 2;

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

    /// The highest guest user address reported for an SV48-compatible Linux RISC-V process.
    private static final long RISCV_HIGHEST_SV48_USER_ADDRESS = (1L << 47) - 1;

    /// Linux `RISCV_HWPROBE_KEY_TIME_CSR_FREQ`.
    private static final long RISCV_HWPROBE_KEY_TIME_CSR_FREQ = 8;

    /// Linux `RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF`.
    private static final long RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF = 9;

    /// Linux `RISCV_HWPROBE_MISALIGNED_SCALAR_EMULATED`.
    private static final long RISCV_HWPROBE_MISALIGNED_SCALAR_EMULATED = 1;

    /// Linux `RISCV_HWPROBE_KEY_MISALIGNED_VECTOR_PERF`.
    private static final long RISCV_HWPROBE_KEY_MISALIGNED_VECTOR_PERF = 10;

    /// Linux `RISCV_HWPROBE_MISALIGNED_VECTOR_SLOW`.
    private static final long RISCV_HWPROBE_MISALIGNED_VECTOR_SLOW = 2;

    /// Linux `RISCV_HWPROBE_KEY_VENDOR_EXT_THEAD_0`.
    private static final long RISCV_HWPROBE_KEY_VENDOR_EXT_THEAD_0 = 11;

    /// Linux `RISCV_HWPROBE_KEY_ZICBOM_BLOCK_SIZE`.
    private static final long RISCV_HWPROBE_KEY_ZICBOM_BLOCK_SIZE = 12;

    /// Linux `RISCV_HWPROBE_KEY_VENDOR_EXT_SIFIVE_0`.
    private static final long RISCV_HWPROBE_KEY_VENDOR_EXT_SIFIVE_0 = 13;

    /// Linux `RISCV_HWPROBE_KEY_VENDOR_EXT_MIPS_0`.
    private static final long RISCV_HWPROBE_KEY_VENDOR_EXT_MIPS_0 = 14;

    /// Linux `RISCV_HWPROBE_KEY_ZICBOP_BLOCK_SIZE`.
    private static final long RISCV_HWPROBE_KEY_ZICBOP_BLOCK_SIZE = 15;

    /// Linux `MEMBARRIER_CMD_QUERY`.
    private static final long MEMBARRIER_CMD_QUERY = 0;

    /// The original Linux `struct rseq` byte size including padding.
    private static final long RSEQ_ORIGINAL_SIZE = 32;

    /// The Linux `struct rseq` alignment used for the original 32-byte layout.
    private static final long RSEQ_ALIGNMENT = 32;

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

    /// Guest signal actions installed through `rt_sigaction`.
    private final @Nullable SignalAction[] signalActions = new SignalAction[(int) MAX_SIGNAL_NUMBER + 1];

    /// Lazily mapped signal-return trampoline, or zero before allocation.
    private long signalTrampolineAddress;

    /// Whether a child-exit `SIGCHLD` is pending for this process.
    private boolean childSignalPending;

    /// The default disabled RISC-V userspace pointer mask length.
    private static final int POINTER_MASK_LENGTH_DISABLED = 0;

    /// The RISC-V userspace pointer mask length implemented by this simulator.
    private static final int POINTER_MASK_LENGTH_7 = 7;

    /// Linux `PR_SET_VMA`.
    private static final long PR_SET_VMA = 0x53564d41L;

    /// Linux `PR_SET_VMA_ANON_NAME`.
    private static final long PR_SET_VMA_ANON_NAME = 0;

    /// Handles the parent return path for Linux `clone` requests.
    protected long clone(
            RiscVThreadState state,
            long pc,
            long flags,
            long stackAddress,
            long parentTidAddress,
            long tlsAddress,
            long childTidAddress) {
        if ((flags & CLONE_PIDFD) != 0 && (flags & CLONE_PARENT_SETTID) != 0) {
            return EINVAL;
        }
        return cloneWithPidfdAddress(
                state,
                pc,
                flags,
                stackAddress,
                parentTidAddress,
                tlsAddress,
                childTidAddress,
                (flags & CLONE_PIDFD) != 0 ? parentTidAddress : 0);
    }

    /// Routes a Linux clone request while preserving the distinct `clone3` pidfd output pointer.
    protected long cloneWithPidfdAddress(
            RiscVThreadState state,
            long pc,
            long flags,
            long stackAddress,
            long parentTidAddress,
            long tlsAddress,
            long childTidAddress,
            long pidfdAddress) {
        long exitSignal = flags & CLONE_EXIT_SIGNAL_MASK;
        long controlFlags = flags & ~CLONE_EXIT_SIGNAL_MASK;
        if ((controlFlags & CLONE_THREAD) != 0) {
            if (exitSignal != 0) {
                return EINVAL;
            }
            return cloneThread(state, pc, controlFlags, stackAddress, parentTidAddress, tlsAddress, childTidAddress);
        }
        return cloneProcess(
                state,
                pc,
                flags,
                stackAddress,
                parentTidAddress,
                tlsAddress,
                childTidAddress,
                pidfdAddress);
    }

    /// Handles Linux `clone3` by translating `struct clone_args` to the existing clone implementation.
    protected long clone3(RiscVThreadState state, long pc, long argumentsAddress, long size) {
        if (size < CLONE_ARGS_MINIMUM_SIZE) {
            return EINVAL;
        }
        if (!memory.isBacked(argumentsAddress, Math.min(size, CLONE_ARGS_KNOWN_SIZE))) {
            return EFAULT;
        }
        if (size > CLONE_ARGS_KNOWN_SIZE) {
            long extraSize = size - CLONE_ARGS_KNOWN_SIZE;
            if (extraSize > Integer.MAX_VALUE) {
                return E2BIG;
            }
            if (!memory.isBacked(argumentsAddress + CLONE_ARGS_KNOWN_SIZE, extraSize)) {
                return EFAULT;
            }
            byte[] extraBytes = memory.readBytes(argumentsAddress + CLONE_ARGS_KNOWN_SIZE, extraSize);
            for (byte extraByte : extraBytes) {
                if (extraByte != 0) {
                    return E2BIG;
                }
            }
        }

        long flags = memory.readLong(argumentsAddress + CLONE_ARGS_FLAGS_OFFSET);
        long exitSignal = memory.readLong(argumentsAddress + CLONE_ARGS_EXIT_SIGNAL_OFFSET);
        if ((flags & CLONE_EXIT_SIGNAL_MASK) != 0 || (exitSignal & ~CLONE_EXIT_SIGNAL_MASK) != 0) {
            return EINVAL;
        }

        long pidfdAddress = memory.readLong(argumentsAddress + CLONE_ARGS_PIDFD_OFFSET);
        long childTidAddress = memory.readLong(argumentsAddress + CLONE_ARGS_CHILD_TID_OFFSET);
        long parentTidAddress = memory.readLong(argumentsAddress + CLONE_ARGS_PARENT_TID_OFFSET);
        long stackAddress = memory.readLong(argumentsAddress + CLONE_ARGS_STACK_OFFSET);
        long stackSize = memory.readLong(argumentsAddress + CLONE_ARGS_STACK_SIZE_OFFSET);
        long tlsAddress = memory.readLong(argumentsAddress + CLONE_ARGS_TLS_OFFSET);
        long setTidAddress = cloneArgumentLong(argumentsAddress, size, CLONE_ARGS_SET_TID_OFFSET);
        long setTidSize = cloneArgumentLong(argumentsAddress, size, CLONE_ARGS_SET_TID_SIZE_OFFSET);
        long cgroup = cloneArgumentLong(argumentsAddress, size, CLONE_ARGS_CGROUP_OFFSET);
        if (setTidAddress != 0 || setTidSize != 0 || cgroup != 0) {
            return EINVAL;
        }

        long childStackAddress = clone3ChildStackAddress(stackAddress, stackSize);
        if (childStackAddress < 0) {
            return EINVAL;
        }
        return cloneWithPidfdAddress(
                state,
                pc,
                flags | exitSignal,
                childStackAddress,
                parentTidAddress,
                tlsAddress,
                childTidAddress,
                pidfdAddress);
    }

    /// Reads an optional 64-bit `struct clone_args` field when it is present in the supplied size.
    protected long cloneArgumentLong(long argumentsAddress, long size, long offset) {
        return size >= offset + Long.BYTES ? memory.readLong(argumentsAddress + offset) : 0;
    }

    /// Converts a `clone3` stack base and size to the child stack pointer expected by `clone`.
    protected static long clone3ChildStackAddress(long stackAddress, long stackSize) {
        if (stackAddress == 0) {
            return stackSize == 0 ? 0 : -1;
        }
        if (stackSize < 0 || Long.MAX_VALUE - stackAddress < stackSize) {
            return -1;
        }
        return stackSize == 0 ? stackAddress : stackAddress + stackSize;
    }

    /// Handles the parent return path for Linux thread-style `clone` requests.
    protected long cloneThread(
            RiscVThreadState state,
            long pc,
            long flags,
            long stackAddress,
            long parentTidAddress,
            long tlsAddress,
            long childTidAddress) {
        if (stackAddress == 0
                || (flags & REQUIRED_THREAD_CLONE_FLAGS) != REQUIRED_THREAD_CLONE_FLAGS
                || (flags & ~SUPPORTED_THREAD_CLONE_FLAGS) != 0) {
            return EINVAL;
        }
        if (!guestThreadingEnabled()) {
            return EAGAIN;
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

        RiscVThreadState child = state.forkForClone(
                childThread,
                pc + Integer.BYTES,
                stackAddress,
                tlsAddress,
                (flags & CLONE_SETTLS) != 0);
        if ((flags & CLONE_CHILD_CLEARTID) != 0) {
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

        if ((flags & CLONE_PARENT_SETTID) != 0) {
            memory.writeInt(parentTidAddress, (int) threadId);
        }
        if ((flags & CLONE_CHILD_SETTID) != 0) {
            memory.writeInt(childTidAddress, (int) threadId);
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
        return threadId;
    }

    /// Handles the parent return path for Linux process-style `clone` requests.
    protected long cloneProcess(
            RiscVThreadState state,
            long pc,
            long flags,
            long stackAddress,
            long parentTidAddress,
            long tlsAddress,
            long childTidAddress,
            long pidfdAddress) {
        long exitSignal = flags & CLONE_EXIT_SIGNAL_MASK;
        if ((flags & ~SUPPORTED_PROCESS_CLONE_FLAGS) != 0
                || ((flags & CLONE_VM) != 0 && (flags & CLONE_VFORK) == 0)
                || exitSignal != SIGNAL_CHILD && exitSignal != 0) {
            return EINVAL;
        }
        if ((flags & CLONE_PIDFD) != 0 && !memory.isBacked(pidfdAddress, Integer.BYTES)) {
            return EFAULT;
        }
        if (!guestThreadingEnabled()) {
            return EAGAIN;
        }
        synchronized (threadLock) {
            if (processExitRequested || threadFailure != null) {
                return EAGAIN;
            }
        }

        @Nullable GuestProcess childProcess = processRegistry.createChildProcess(process);
        if (childProcess == null) {
            return ENOMEM;
        }

        Memory childMemory;
        try {
            childMemory = memory.fork();
        } catch (RiscVException exception) {
            return ENOMEM;
        }

        GuestSyscalls childSyscalls = createChildSyscalls(childMemory, childProcess);
        GuestThread childThread = childProcess.initialThread();
        childThread.setSignalMask(state.guestThread().signalMask());
        childThread.inheritExecutionControlsFrom(state.guestThread());
        if ((flags & CLONE_CHILD_CLEARTID) != 0) {
            childThread.setClearChildTidAddress(childTidAddress);
        }

        long childStackAddress = stackAddress == 0 ? state.register(2) : stackAddress;
        RiscVThreadState child = state.forkForProcess(
                childThread,
                childMemory,
                childSyscalls,
                pc + Integer.BYTES,
                childStackAddress,
                tlsAddress,
                (flags & CLONE_SETTLS) != 0);
        initializeProcessChildSyscallResult(child);

        if ((flags & CLONE_PARENT_SETTID) != 0) {
            memory.writeInt(parentTidAddress, childProcess.id());
        }
        if ((flags & CLONE_CHILD_SETTID) != 0) {
            childMemory.writeInt(childTidAddress, childProcess.id());
        }

        GuestThreadRunner currentRunner = guestThreadRunner;
        if (currentRunner == null) {
            childSyscalls.close();
            childMemory.close();
            return EAGAIN;
        }
        Thread thread;
        try {
            thread = new Thread(() -> {
                try {
                    currentRunner.runGuestThread(childMemory, child);
                } finally {
                    childSyscalls.joinGuestThreads();
                    childSyscalls.close();
                    childMemory.close();
                }
            }, "riscv-guest-process-" + childProcess.id());
        } catch (RuntimeException exception) {
            childSyscalls.close();
            childMemory.close();
            return EAGAIN;
        }
        thread.setUncaughtExceptionHandler((failedThread, throwable) -> childSyscalls.recordThreadFailure(throwable));

        ChildProcess childRecord = new ChildProcess(
                childProcess.id(),
                childProcess.processGroupId(),
                exitSignal != SIGNAL_CHILD,
                state.guestThread().id(),
                childSyscalls,
                thread);
        synchronized (childProcessLock) {
            childProcesses.add(childRecord);
        }

        try {
            thread.start();
        } catch (RuntimeException exception) {
            removeUnstartedChildProcess(childRecord);
            childSyscalls.close();
            childMemory.close();
            return EAGAIN;
        }
        if ((flags & CLONE_PIDFD) != 0) {
            long processFileDescriptor = addOpenFile(
                    OpenFile.processFile(
                            new ProcessFile(childProcess.id(), childSyscalls, childRecord, null),
                            false),
                    true);
            memory.writeInt(pidfdAddress, (int) processFileDescriptor);
        }
        return childProcess.id();
    }

    /// Creates a process with traditional `fork` register and signal semantics.
    protected long forkProcess(RiscVThreadState state, long pc) {
        return cloneProcess(state, pc, SIGNAL_CHILD, 0, 0, 0, 0, 0);
    }

    /// Applies ABI-specific successful-syscall registers to a newly forked child process.
    protected void initializeProcessChildSyscallResult(RiscVThreadState child) {
    }

    /// Opens a Linux process file descriptor for the current process, one of its threads, or a direct child.
    protected long pidfdOpen(long processId, long flags) {
        long normalizedFlags = Integer.toUnsignedLong((int) flags);
        if (processId <= 0
                || processId != (int) processId
                || (normalizedFlags & ~SUPPORTED_PIDFD_OPEN_FLAGS) != 0) {
            return EINVAL;
        }

        int targetId = (int) processId;
        @Nullable ChildProcess child = null;
        GuestSyscalls targetSyscalls;
        if (targetId == process.id()
                || (normalizedFlags & PIDFD_THREAD) != 0 && isKnownGuestThreadId(targetId)) {
            targetSyscalls = this;
        } else {
            synchronized (childProcessLock) {
                child = childProcess(targetId);
                if (child == null) {
                    return ESRCH;
                }
                targetSyscalls = child.syscalls();
            }
        }

        @Nullable GuestThread targetThread = null;
        if ((normalizedFlags & PIDFD_THREAD) != 0) {
            targetThread = targetSyscalls.guestThread(targetId);
            if (targetThread == null) {
                return ESRCH;
            }
        }

        return addOpenFile(
                OpenFile.processFile(
                        new ProcessFile(
                                targetId,
                                targetSyscalls,
                                child,
                                targetThread),
                        (normalizedFlags & PIDFD_NONBLOCK) != 0),
                true);
    }

    /// Sends or probes a signal through a Linux process file descriptor.
    protected long pidfdSendSignal(
            int processFileDescriptor,
            long signalNumber,
            long signalInfoAddress,
            long flags) {
        if (flags != 0 || !isValidSignalNumber(signalNumber)) {
            return EINVAL;
        }
        if (signalInfoAddress != 0) {
            return EINVAL;
        }

        @Nullable OpenFile openFile = openFile(processFileDescriptor);
        if (openFile == null || !openFile.isProcessFile()) {
            return EBADF;
        }
        ProcessFile processFile = openFile.processFile();
        if (processFile.exited()) {
            return ESRCH;
        }
        return 0;
    }

    /// Waits for a child event using Linux `waitid` selectors and output layouts.
    private long waitid(
            RiscVThreadState state,
            long idType,
            long id,
            long signalInfoAddress,
            long options,
            long rusageAddress) {
        long normalizedOptions = Integer.toUnsignedLong((int) options);
        if ((normalizedOptions & ~SUPPORTED_WAIT_ID_OPTIONS) != 0
                || (normalizedOptions & WAIT_ID_EVENT_OPTIONS) == 0) {
            return EINVAL;
        }
        if (signalInfoAddress != 0 && !memory.isBacked(signalInfoAddress, WAIT_ID_SIGNAL_INFO_SIZE)) {
            return EFAULT;
        }
        if (rusageAddress != 0 && !memory.isBacked(rusageAddress, RUSAGE_SIZE)) {
            return EFAULT;
        }

        int selectorType = (int) idType;
        int identifier = (int) id;
        long processSelector;
        boolean nonblockingProcessFile = false;
        switch (selectorType) {
            case WAIT_ID_ALL -> processSelector = -1;
            case WAIT_ID_PROCESS -> {
                if (identifier <= 0) {
                    return EINVAL;
                }
                processSelector = identifier;
            }
            case WAIT_ID_PROCESS_GROUP -> {
                if (identifier < 0) {
                    return EINVAL;
                }
                processSelector = identifier == 0 ? 0 : -(long) identifier;
            }
            case WAIT_ID_PROCESS_FILE_DESCRIPTOR -> {
                if (identifier < 0) {
                    return EINVAL;
                }
                @Nullable OpenFile openFile = openFile(identifier);
                if (openFile == null) {
                    return isOpenFileDescriptor(identifier) ? EINVAL : EBADF;
                }
                if (!openFile.isProcessFile()) {
                    return EINVAL;
                }
                processSelector = openFile.processFile().processId();
                nonblockingProcessFile = openFile.nonblocking();
            }
            default -> {
                return EINVAL;
            }
        }

        boolean noHang = (normalizedOptions & WAIT_NO_HANG) != 0;
        ChildWaitResult waitResult = waitForExitedChild(
                processSelector,
                (normalizedOptions & WAIT_ID_EXITED) != 0,
                noHang || nonblockingProcessFile,
                (normalizedOptions & WAIT_ID_NO_WAIT) != 0,
                (normalizedOptions & WAIT_ID_CLONE_CHILDREN) == 0
                        || (normalizedOptions & WAIT_ID_ALL_CHILDREN) != 0,
                (normalizedOptions & (WAIT_ID_CLONE_CHILDREN | WAIT_ID_ALL_CHILDREN)) != 0,
                (normalizedOptions & WAIT_ID_NOT_THREAD) != 0 ? state.guestThread().id() : 0);
        if (waitResult.result() < 0) {
            return waitResult.result();
        }
        if (waitResult.result() == 0) {
            if (nonblockingProcessFile && !noHang) {
                return EAGAIN;
            }
            writeWaitIdSignalInfo(signalInfoAddress, null);
            return 0;
        }

        @Nullable ChildProcess child = waitResult.child();
        if (child == null) {
            throw new AssertionError("Successful waitid did not return a child process");
        }
        writeWaitIdSignalInfo(signalInfoAddress, child);
        if (rusageAddress != 0) {
            memory.clear(rusageAddress, RUSAGE_SIZE);
        }
        return 0;
    }

    /// Writes the fields populated by Linux `waitid`, or a zeroed no-event result.
    private void writeWaitIdSignalInfo(long address, @Nullable ChildProcess child) {
        if (address == 0) {
            return;
        }
        memory.writeInt(address + WAIT_ID_SIGNAL_NUMBER_OFFSET, child == null ? 0 : (int) SIGNAL_CHILD);
        memory.writeInt(address + WAIT_ID_ERRNO_OFFSET, 0);
        memory.writeInt(address + WAIT_ID_CODE_OFFSET, child == null ? 0 : WAIT_ID_CHILD_EXITED);
        memory.writeInt(address + WAIT_ID_PROCESS_ID_OFFSET, child == null ? 0 : child.processId());
        memory.writeInt(address + WAIT_ID_USER_ID_OFFSET, child == null ? 0 : GuestCredentials.idToInt(child.userId()));
        memory.writeInt(address + WAIT_ID_STATUS_OFFSET, child == null ? 0 : child.exitCode());
    }


    /// Accepts a robust futex list registration for the current guest thread.
    protected static long setRobustList(RiscVThreadState state, long headAddress, long length) {
        if (length < 0) {
            return EINVAL;
        }
        state.guestThread().setRobustList(headAddress, length);
        return 0;
    }

    /// Reports the robust futex list registered for one guest thread.
    protected long getRobustList(RiscVThreadState state, long processId, long headAddress, long lengthAddress) {
        @Nullable GuestThread thread = guestThread(state, processId);
        if (thread == null) {
            return ESRCH;
        }
        memory.writeLong(headAddress, thread.robustListHeadAddress());
        memory.writeLong(lengthAddress, thread.robustListLength());
        return 0;
    }

    /// Registers or reports the alternate signal stack for the current guest thread.
    protected long sigaltstack(RiscVThreadState state, long stackAddress, long oldStackAddress) {
        long newStackPointer = 0;
        long newStackSize = 0;
        long newStackFlags = 0;
        if (stackAddress != 0) {
            newStackPointer = memory.readLong(stackAddress + SIGNAL_STACK_POINTER_OFFSET);
            newStackFlags = Integer.toUnsignedLong(memory.readInt(stackAddress + SIGNAL_STACK_FLAGS_OFFSET));
            newStackSize = memory.readLong(stackAddress + SIGNAL_STACK_SIZE_OFFSET);
            if ((newStackFlags & ~SUPPORTED_SIGNAL_STACK_FLAGS) != 0
                    || (newStackFlags & SS_ONSTACK) != 0
                    || newStackSize < 0) {
                return EINVAL;
            }
            if ((newStackFlags & SS_DISABLE) == 0 && newStackSize < MINIMUM_SIGNAL_STACK_SIZE) {
                return ENOMEM;
            }
        }

        if (oldStackAddress != 0) {
            writeSignalStack(state.guestThread(), oldStackAddress);
        }
        if (stackAddress != 0) {
            if ((newStackFlags & SS_DISABLE) != 0) {
                state.guestThread().disableAlternateSignalStack();
            } else {
                state.guestThread().setAlternateSignalStack(newStackPointer, newStackSize, newStackFlags);
            }
        }
        return 0;
    }

    /// Writes the current Linux RISC-V 64-bit `stack_t` alternate signal stack.
    protected void writeSignalStack(GuestThread thread, long stackAddress) {
        memory.writeLong(stackAddress + SIGNAL_STACK_POINTER_OFFSET, thread.alternateSignalStackPointer());
        memory.writeInt(stackAddress + SIGNAL_STACK_FLAGS_OFFSET, (int) thread.alternateSignalStackFlags());
        memory.writeInt(stackAddress + SIGNAL_STACK_FLAGS_PADDING_OFFSET, 0);
        memory.writeLong(stackAddress + SIGNAL_STACK_SIZE_OFFSET, thread.alternateSignalStackSize());
    }


    /// Reports a deterministic single-CPU affinity mask for static libc queries.
    protected long schedGetaffinity(long processId, long cpuSetSize, long cpuSetAddress) {
        if (!isKnownSchedulerTarget(processId)) {
            return ESRCH;
        }
        if (cpuSetSize < MINIMUM_CPU_AFFINITY_MASK_SIZE) {
            return EINVAL;
        }

        memory.clear(cpuSetAddress, cpuSetSize);
        memory.writeLong(cpuSetAddress, 1);
        return MINIMUM_CPU_AFFINITY_MASK_SIZE;
    }

    /// Accepts CPU affinity masks that keep the simulated CPU selected.
    protected long schedSetaffinity(long processId, long cpuSetSize, long cpuSetAddress) {
        if (!isKnownSchedulerTarget(processId)) {
            return ESRCH;
        }
        if (cpuSetSize < MINIMUM_CPU_AFFINITY_MASK_SIZE) {
            return EINVAL;
        }
        return cpuSetContainsGuestCpu(cpuSetAddress) ? 0 : EINVAL;
    }


    /// Reports deterministic RISC-V hardware probe values for the single simulated CPU.
    protected long riscvHwprobe(long pairsAddress, long pairCount, long cpuSetSize, long cpuSetAddress, long flags, RiscVThreadState state) {
        if (pairCount < 0
                || pairCount > Integer.MAX_VALUE
                || (flags & ~RISCV_HWPROBE_WHICH_CPUS) != 0
                || pairCount > Long.MAX_VALUE / RISCV_HWPROBE_PAIR_SIZE
                || (cpuSetAddress == 0 && cpuSetSize != 0)
                || (cpuSetAddress != 0 && cpuSetSize <= 0)) {
            return EINVAL;
        }

        if ((flags & RISCV_HWPROBE_WHICH_CPUS) == 0) {
            if (cpuSetAddress != 0 && !cpuSetContainsGuestCpu(cpuSetAddress)) {
                return EINVAL;
            }
            populateHwprobePairs(pairsAddress, pairCount, state);
            return 0;
        }

        if (cpuSetAddress == 0) {
            return EINVAL;
        }

        boolean selected = cpuSetContainsGuestCpu(cpuSetAddress) || cpuSetIsEmpty(cpuSetAddress, cpuSetSize);
        boolean matches = selected && hwprobePairsMatch(pairsAddress, pairCount, state);
        memory.clear(cpuSetAddress, cpuSetSize);
        if (matches) {
            memory.writeByte(cpuSetAddress, (byte) 1);
        }
        return 0;
    }

    /// Flushes guest instruction-fetch visibility for Linux `riscv_flush_icache`.
    protected long riscvFlushIcache(RiscVThreadState state, long startAddress, long endAddress, long flags) {
        if ((flags & ~RISCV_FLUSH_ICACHE_LOCAL) != 0 || Long.compareUnsigned(startAddress, endAddress) > 0) {
            return EINVAL;
        }

        fenceProcessInstructionFetch();
        if ((flags & RISCV_FLUSH_ICACHE_LOCAL) != 0) {
            state.fenceInstructionFetch();
        }
        return 0;
    }

    /// Writes values for all requested RISC-V hardware probe pairs.
    protected void populateHwprobePairs(long pairsAddress, long pairCount, RiscVThreadState state) {
        for (long index = 0; index < pairCount; index++) {
            long pairAddress = pairsAddress + index * RISCV_HWPROBE_PAIR_SIZE;
            long key = memory.readLong(pairAddress + RISCV_HWPROBE_KEY_OFFSET);
            if (isSupportedHwprobeKey(key)) {
                memory.writeLong(pairAddress + RISCV_HWPROBE_VALUE_OFFSET, hwprobeValue(key, state));
            } else {
                memory.writeLong(pairAddress + RISCV_HWPROBE_KEY_OFFSET, -1);
                memory.writeLong(pairAddress + RISCV_HWPROBE_VALUE_OFFSET, 0);
            }
        }
    }

    /// Returns true when all supplied RISC-V hardware probe constraints match the simulated CPU.
    protected boolean hwprobePairsMatch(long pairsAddress, long pairCount, RiscVThreadState state) {
        boolean matches = true;
        for (long index = 0; index < pairCount; index++) {
            long pairAddress = pairsAddress + index * RISCV_HWPROBE_PAIR_SIZE;
            long key = memory.readLong(pairAddress + RISCV_HWPROBE_KEY_OFFSET);
            long requestedValue = memory.readLong(pairAddress + RISCV_HWPROBE_VALUE_OFFSET);
            if (!isSupportedHwprobeKey(key)) {
                memory.writeLong(pairAddress + RISCV_HWPROBE_KEY_OFFSET, -1);
                memory.writeLong(pairAddress + RISCV_HWPROBE_VALUE_OFFSET, 0);
                matches = false;
                continue;
            }

            long actualValue = hwprobeValue(key, state);
            if (isHwprobeBitmaskKey(key)) {
                if ((actualValue & requestedValue) != requestedValue) {
                    matches = false;
                }
            } else if (actualValue != requestedValue) {
                matches = false;
            }
        }
        return matches;
    }

    /// Returns true when a hardware probe key is supported by this simulator.
    protected static boolean isSupportedHwprobeKey(long key) {
        return key >= RISCV_HWPROBE_KEY_MVENDORID && key <= RISCV_HWPROBE_KEY_ZICBOP_BLOCK_SIZE;
    }

    /// Returns the deterministic value for a supported RISC-V hardware probe key.
    protected static long hwprobeValue(long key, RiscVThreadState state) {
        return switch ((int) key) {
            case (int) RISCV_HWPROBE_KEY_MVENDORID,
                    (int) RISCV_HWPROBE_KEY_MARCHID,
                    (int) RISCV_HWPROBE_KEY_MIMPID,
                    (int) RISCV_HWPROBE_KEY_VENDOR_EXT_THEAD_0,
                    (int) RISCV_HWPROBE_KEY_VENDOR_EXT_SIFIVE_0,
                    (int) RISCV_HWPROBE_KEY_VENDOR_EXT_MIPS_0 -> 0;
            case (int) RISCV_HWPROBE_KEY_ZICBOZ_BLOCK_SIZE,
                    (int) RISCV_HWPROBE_KEY_ZICBOM_BLOCK_SIZE,
                    (int) RISCV_HWPROBE_KEY_ZICBOP_BLOCK_SIZE -> RiscVExtensions.CACHE_BLOCK_SIZE;
            case (int) RISCV_HWPROBE_KEY_BASE_BEHAVIOR -> RISCV_HWPROBE_BASE_BEHAVIOR_IMA;
            case (int) RISCV_HWPROBE_KEY_IMA_EXT_0 -> hwprobeImaExtensions(state);
            case (int) RISCV_HWPROBE_KEY_CPUPERF_0 -> RISCV_HWPROBE_MISALIGNED_EMULATED;
            case (int) RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF -> RISCV_HWPROBE_MISALIGNED_SCALAR_EMULATED;
            case (int) RISCV_HWPROBE_KEY_MISALIGNED_VECTOR_PERF -> RISCV_HWPROBE_MISALIGNED_VECTOR_SLOW;
            case (int) RISCV_HWPROBE_KEY_HIGHEST_VIRT_ADDRESS -> RISCV_HIGHEST_SV48_USER_ADDRESS;
            case (int) RISCV_HWPROBE_KEY_TIME_CSR_FREQ -> NANOSECONDS_PER_SECOND;
            default -> throw new AssertionError("validated RISC-V hardware probe key");
        };
    }

    /// Returns the ISA extension bits visible through Linux `riscv_hwprobe`.
    protected static long hwprobeImaExtensions(RiscVThreadState state) {
        return state.vectorUnit().vlenBits() >= Rva23Profile.MINIMUM_VLEN_BITS
                ? Rva23Profile.HWPROBE_REPORTED_EXTENSIONS
                : Rva22Profile.HWPROBE_REPORTED_EXTENSIONS;
    }

    /// Returns true when a hardware probe key uses bitmask matching.
    protected static boolean isHwprobeBitmaskKey(long key) {
        return key == RISCV_HWPROBE_KEY_BASE_BEHAVIOR
                || key == RISCV_HWPROBE_KEY_IMA_EXT_0
                || key == RISCV_HWPROBE_KEY_CPUPERF_0
                || key == RISCV_HWPROBE_KEY_VENDOR_EXT_THEAD_0
                || key == RISCV_HWPROBE_KEY_VENDOR_EXT_SIFIVE_0
                || key == RISCV_HWPROBE_KEY_VENDOR_EXT_MIPS_0;
    }

    /// Returns true when the supplied CPU set contains the simulator's only CPU.
    protected boolean cpuSetContainsGuestCpu(long cpuSetAddress) {
        return (memory.readUnsignedByte(cpuSetAddress) & 1) != 0;
    }

    /// Returns true when all bytes in a guest CPU set are zero.
    protected boolean cpuSetIsEmpty(long cpuSetAddress, long cpuSetSize) {
        for (long index = 0; index < cpuSetSize; index++) {
            if (memory.readUnsignedByte(cpuSetAddress + index) != 0) {
                return false;
            }
        }
        return true;
    }


    /// Accepts signal sends that target known guest thread ids.
    protected long tkill(long threadId, long signalNumber) {
        if (!isValidSignalNumber(signalNumber)) {
            return EINVAL;
        }
        return isKnownGuestThreadId(threadId) ? 0 : ESRCH;
    }

    /// Accepts signal sends that target known guest thread ids in the current process.
    protected long tgkill(long processId, long threadId, long signalNumber) {
        if (!isValidSignalNumber(signalNumber)) {
            return EINVAL;
        }
        if (processId != process.id()) {
            return ESRCH;
        }
        return isKnownGuestThreadId(threadId) ? 0 : ESRCH;
    }

    /// Reads Linux capability sets for the current process.
    protected long capget(long headerAddress, long dataAddress) {
        CapabilityHeader header = readCapabilityHeader(headerAddress);
        if (header.result() != 0) {
            return header.result();
        }
        if (dataAddress == 0) {
            return 0;
        }

        int wordCount = capabilityWordCount(header.version());
        long capabilities = credentials.effectiveUserId() == 0 ? rootCapabilityMask() : 0;
        try {
            for (int index = 0; index < wordCount; index++) {
                int word = (int) (capabilities >>> (Integer.SIZE * index));
                long entryAddress = dataAddress + (long) index * CAPABILITY_DATA_SIZE;
                memory.writeInt(entryAddress + CAPABILITY_EFFECTIVE_OFFSET, word);
                memory.writeInt(entryAddress + CAPABILITY_PERMITTED_OFFSET, word);
                memory.writeInt(entryAddress + CAPABILITY_INHERITABLE_OFFSET, 0);
            }
            return 0;
        } catch (RiscVException exception) {
            return EFAULT;
        }
    }

    /// Accepts Linux capability set updates that fit the current deterministic privilege model.
    protected long capset(long headerAddress, long dataAddress) {
        CapabilityHeader header = readCapabilityHeader(headerAddress);
        if (header.result() != 0) {
            return header.result();
        }
        if (dataAddress == 0) {
            return EFAULT;
        }

        int wordCount = capabilityWordCount(header.version());
        try {
            long requested = 0;
            for (int index = 0; index < wordCount; index++) {
                long entryAddress = dataAddress + (long) index * CAPABILITY_DATA_SIZE;
                requested |= memory.readUnsignedInt(entryAddress + CAPABILITY_EFFECTIVE_OFFSET)
                        << (Integer.SIZE * index);
                requested |= memory.readUnsignedInt(entryAddress + CAPABILITY_PERMITTED_OFFSET)
                        << (Integer.SIZE * index);
                requested |= memory.readUnsignedInt(entryAddress + CAPABILITY_INHERITABLE_OFFSET)
                        << (Integer.SIZE * index);
            }
            if (credentials.effectiveUserId() != 0 && requested != 0) {
                return EPERM;
            }
            return 0;
        } catch (RiscVException exception) {
            return EFAULT;
        }
    }

    /// Reads and validates the Linux capability syscall header.
    protected CapabilityHeader readCapabilityHeader(long headerAddress) {
        if (headerAddress == 0) {
            return new CapabilityHeader(0, 0, EFAULT);
        }
        try {
            int version = memory.readInt(headerAddress + CAPABILITY_HEADER_VERSION_OFFSET);
            int pid = memory.readInt(headerAddress + CAPABILITY_HEADER_PID_OFFSET);
            if (!isSupportedCapabilityVersion(version)) {
                memory.writeInt(headerAddress + CAPABILITY_HEADER_VERSION_OFFSET, LINUX_CAPABILITY_VERSION_3);
                return new CapabilityHeader(version, pid, EINVAL);
            }
            if (pid != 0 && pid != process.id()) {
                return new CapabilityHeader(version, pid, ESRCH);
            }
            return new CapabilityHeader(version, pid, 0);
        } catch (RiscVException exception) {
            return new CapabilityHeader(0, 0, EFAULT);
        }
    }

    /// Returns true when the Linux capability ABI version is supported.
    protected static boolean isSupportedCapabilityVersion(int version) {
        return version == LINUX_CAPABILITY_VERSION_1
                || version == LINUX_CAPABILITY_VERSION_2
                || version == LINUX_CAPABILITY_VERSION_3;
    }

    /// Returns the number of 32-bit capability words used by the supplied ABI version.
    protected static int capabilityWordCount(int version) {
        return version == LINUX_CAPABILITY_VERSION_1 ? 1 : 2;
    }

    /// Returns a mask containing every root capability exposed by this simulator.
    protected static long rootCapabilityMask() {
        return (1L << (CAPABILITY_LAST_CAP + 1)) - 1L;
    }

    /// Updates persistent Linux process priority for selected known processes.
    protected long setpriority(long which, long who, long priority) {
        return setLinuxProcessPriority(which, who, priority);
    }

    /// Returns the raw Linux priority encoding for the highest-priority selected process.
    protected long getpriority(long which, long who) {
        PriorityResult result = linuxProcessPriority(which, who);
        return result.error() != 0
                ? result.error()
                : LINUX_DEFAULT_RAW_PRIORITY - result.niceValue();
    }


    /// Returns the process group id for the current process or a tracked child process.
    protected long getpgid(long processId) {
        if (processId == 0 || processId == process.id()) {
            return process.processGroupId();
        }
        if (processId != (int) processId) {
            return ESRCH;
        }
        synchronized (childProcessLock) {
            @Nullable ChildProcess child = childProcess((int) processId);
            if (child != null) {
                return child.processGroupId();
            }
        }
        return ESRCH;
    }

    /// Returns the session id for the current process or a tracked child process.
    protected long getsid(long processId) {
        if (processId == 0 || processId == process.id()) {
            return process.sessionId();
        }
        if (processId != (int) processId) {
            return ESRCH;
        }
        synchronized (childProcessLock) {
            @Nullable ChildProcess child = childProcess((int) processId);
            if (child != null) {
                return child.syscalls().process.sessionId();
            }
        }
        return ESRCH;
    }


    /// Writes deterministic process CPU times and returns elapsed clock ticks.
    protected long times(long tmsAddress) {
        long elapsedTicks = elapsedClockTicks();
        if (tmsAddress != 0) {
            memory.clear(tmsAddress, TMS_SIZE);
            memory.writeLong(tmsAddress + TMS_USER_TIME_OFFSET, elapsedTicks);
            memory.writeLong(tmsAddress + TMS_SYSTEM_TIME_OFFSET, 0);
            memory.writeLong(tmsAddress + TMS_CHILD_USER_TIME_OFFSET, 0);
            memory.writeLong(tmsAddress + TMS_CHILD_SYSTEM_TIME_OFFSET, 0);
        }
        return elapsedTicks;
    }


    /// Writes a deterministic Linux `struct utsname` for the simulated guest.
    protected long uname(long utsnameAddress) {
        memory.clear(utsnameAddress, UTSNAME_SIZE);
        writeNullTerminatedAscii(utsnameAddress + UTSNAME_SYSNAME_OFFSET, "Linux", UTSNAME_FIELD_SIZE);
        writeNullTerminatedAscii(utsnameAddress + UTSNAME_NODENAME_OFFSET, "localhost", UTSNAME_FIELD_SIZE);
        writeNullTerminatedAscii(utsnameAddress + UTSNAME_RELEASE_OFFSET, "6.12.0", UTSNAME_FIELD_SIZE);
        writeNullTerminatedAscii(utsnameAddress + UTSNAME_VERSION_OFFSET, "#1 SMP", UTSNAME_FIELD_SIZE);
        writeNullTerminatedAscii(utsnameAddress + UTSNAME_MACHINE_OFFSET, "riscv64", UTSNAME_FIELD_SIZE);
        writeNullTerminatedAscii(utsnameAddress + UTSNAME_DOMAINNAME_OFFSET, "localdomain", UTSNAME_FIELD_SIZE);
        return 0;
    }

    /// Writes deterministic Linux `struct sysinfo` values for libc and coreutils memory queries.
    protected long sysinfo(long sysinfoAddress) {
        if (sysinfoAddress == 0) {
            return EFAULT;
        }

        long totalRam = memory.size();
        long committedRam = saturatedMultiply(memory.committedPages(), memory.pageSize());
        long freeRam = Math.max(0, totalRam - committedRam);
        short processes = (short) Math.min(Short.toUnsignedInt((short) -1), process.threadCount());

        memory.clear(sysinfoAddress, SYSINFO_SIZE);
        memory.writeLong(sysinfoAddress + SYSINFO_UPTIME_OFFSET, Math.max(0, elapsedDuration().getSeconds()));
        memory.writeLong(sysinfoAddress + SYSINFO_LOADS_OFFSET, 0);
        memory.writeLong(sysinfoAddress + SYSINFO_LOADS_OFFSET + Long.BYTES, 0);
        memory.writeLong(sysinfoAddress + SYSINFO_LOADS_OFFSET + 2L * Long.BYTES, 0);
        memory.writeLong(sysinfoAddress + SYSINFO_TOTAL_RAM_OFFSET, totalRam);
        memory.writeLong(sysinfoAddress + SYSINFO_FREE_RAM_OFFSET, freeRam);
        memory.writeLong(sysinfoAddress + SYSINFO_SHARED_RAM_OFFSET, 0);
        memory.writeLong(sysinfoAddress + SYSINFO_BUFFER_RAM_OFFSET, 0);
        memory.writeLong(sysinfoAddress + SYSINFO_TOTAL_SWAP_OFFSET, 0);
        memory.writeLong(sysinfoAddress + SYSINFO_FREE_SWAP_OFFSET, 0);
        memory.writeShort(sysinfoAddress + SYSINFO_PROCESSES_OFFSET, processes);
        memory.writeLong(sysinfoAddress + SYSINFO_TOTAL_HIGH_OFFSET, 0);
        memory.writeLong(sysinfoAddress + SYSINFO_FREE_HIGH_OFFSET, 0);
        memory.writeInt(sysinfoAddress + SYSINFO_MEMORY_UNIT_OFFSET, 1);
        return 0;
    }

    /// Returns a saturated product of two non-negative byte counts.
    protected static long saturatedMultiply(long left, long right) {
        if (left <= 0 || right <= 0) {
            return 0;
        }
        if (left > Long.MAX_VALUE / right) {
            return Long.MAX_VALUE;
        }
        return left * right;
    }

    /// Writes a null-terminated US-ASCII string into a fixed-size guest field.
    protected void writeNullTerminatedAscii(long address, String value, int fieldSize) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        int length = Math.min(bytes.length, fieldSize - 1);
        memory.writeBytes(address, bytes, 0, length);
    }


    /// Registers or reports a Linux signal action.
    protected long rtSigaction(long signalNumber, long actionAddress, long oldActionAddress, long sigsetSize) {
        if (sigsetSize != KERNEL_SIGSET_SIZE) {
            return EINVAL;
        }
        if (signalNumber < MIN_SIGNAL_NUMBER || signalNumber > MAX_SIGNAL_NUMBER) {
            return EINVAL;
        }
        if (actionAddress != 0 && (signalNumber == SIGKILL || signalNumber == SIGSTOP)) {
            return EINVAL;
        }

        if (oldActionAddress != 0) {
            writeSignalAction(oldActionAddress, signalActions[(int) signalNumber]);
        }
        if (actionAddress != 0) {
            signalActions[(int) signalNumber] = readSignalAction(actionAddress);
        }
        return 0;
    }

    /// Reads a Linux RISC-V kernel `struct sigaction`.
    protected SignalAction readSignalAction(long actionAddress) {
        return new SignalAction(
                memory.readLong(actionAddress + SIGNAL_ACTION_HANDLER_OFFSET),
                memory.readLong(actionAddress + SIGNAL_ACTION_FLAGS_OFFSET),
                memory.readLong(actionAddress + SIGNAL_ACTION_MASK_OFFSET) & ~UNBLOCKABLE_SIGNAL_MASK);
    }

    /// Writes a Linux RISC-V kernel `struct sigaction`.
    protected void writeSignalAction(long actionAddress, @Nullable SignalAction action) {
        memory.clear(actionAddress, KERNEL_SIGACTION_SIZE);
        if (action != null) {
            memory.writeLong(actionAddress + SIGNAL_ACTION_HANDLER_OFFSET, action.handler());
            memory.writeLong(actionAddress + SIGNAL_ACTION_FLAGS_OFFSET, action.flags());
            memory.writeLong(actionAddress + SIGNAL_ACTION_MASK_OFFSET, action.mask());
        }
    }

    /// Reads and updates the calling guest thread's signal mask.
    protected long rtSigprocmask(RiscVThreadState state, long how, long setAddress, long oldSetAddress, long sigsetSize) {
        if (sigsetSize != KERNEL_SIGSET_SIZE) {
            return EINVAL;
        }
        if (setAddress != 0 && how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK) {
            return EINVAL;
        }

        GuestThread thread = state.guestThread();
        long oldMask = thread.signalMask();
        if (oldSetAddress != 0) {
            memory.writeLong(oldSetAddress, oldMask);
        }
        if (setAddress != 0) {
            long requestedMask = memory.readLong(setAddress) & ~UNBLOCKABLE_SIGNAL_MASK;
            long updatedMask = oldMask;
            if (how == SIG_BLOCK) {
                updatedMask |= requestedMask;
            } else if (how == SIG_UNBLOCK) {
                updatedMask &= ~requestedMask;
            } else {
                updatedMask = requestedMask;
            }
            thread.setSignalMask(updatedMask);
        }
        return 0;
    }

    /// Delivers synchronous illegal-instruction faults to a registered guest `SIGILL` handler.
    @Override
    public boolean handleIllegalInstruction(RiscVThreadState state, IllegalInstructionException exception) {
        @Nullable SignalAction action = signalActions[(int) SIGNAL_ILLEGAL_INSTRUCTION];
        if (action == null
                || action.handler() == SIGNAL_DEFAULT_HANDLER
                || action.handler() == SIGNAL_IGNORE_HANDLER) {
            return false;
        }

        // Illegal instructions can be found while decoding a new dispatch target, before
        // the architectural PC has been materialized for that target.
        state.setPc(exception.address());
        deliverSignal(state, SIGNAL_ILLEGAL_INSTRUCTION, SIGNAL_CODE_ILLEGAL_OPCODE, exception.address(), action);
        return true;
    }

    /// Delivers synchronous memory-access faults to a registered guest `SIGSEGV` handler.
    @Override
    public boolean handleMemoryAccess(RiscVThreadState state, MemoryAccessException exception) {
        @Nullable SignalAction action = signalActions[(int) SIGNAL_SEGMENTATION_FAULT];
        if (action == null
                || action.handler() == SIGNAL_DEFAULT_HANDLER
                || action.handler() == SIGNAL_IGNORE_HANDLER) {
            return false;
        }

        deliverSignal(state, SIGNAL_SEGMENTATION_FAULT, exception.signalCode(), exception.address(), action);
        return true;
    }

    /// Records an exited child and queues the process-level `SIGCHLD` notification.
    @Override
    protected void recordChildProcessExit(int processId, long exitCode) {
        boolean queueChildSignal;
        synchronized (childProcessLock) {
            @Nullable ChildProcess child = childProcess(processId);
            queueChildSignal = child != null && !child.cloneChild();
        }
        super.recordChildProcessExit(processId, exitCode);
        if (!queueChildSignal) {
            return;
        }
        synchronized (childProcessLock) {
            childSignalPending = true;
            childProcessLock.notifyAll();
        }
    }

    /// Delivers a queued child-exit signal if the current guest thread can receive it.
    protected void deliverPendingChildSignal(RiscVThreadState state, long syscallPc) {
        @Nullable SignalAction action;
        synchronized (childProcessLock) {
            if (!childSignalPending) {
                return;
            }
            if ((state.guestThread().signalMask() & signalMask(SIGNAL_CHILD)) != 0) {
                return;
            }

            action = signalActions[(int) SIGNAL_CHILD];
            if (action == null
                    || action.handler() == SIGNAL_DEFAULT_HANDLER
                    || action.handler() == SIGNAL_IGNORE_HANDLER) {
                childSignalPending = false;
                return;
            }
            childSignalPending = false;
        }

        if (state.pc() == syscallPc) {
            state.setPc(syscallPc + Integer.BYTES);
        }
        deliverSignal(state, SIGNAL_CHILD, 0, 0, action);
    }

    /// Builds a Linux RISC-V `rt_sigframe` and redirects execution to a guest signal handler.
    protected void deliverSignal(
            RiscVThreadState state,
            long signalNumber,
            int signalCode,
            long faultAddress,
            SignalAction action) {
        long frameAddress = signalFrameAddress(state, action);
        if (!memory.isBacked(frameAddress, SIGNAL_FRAME_SIZE)) {
            throw new RiscVException("Guest signal frame is not backed: address=0x"
                    + Long.toUnsignedString(frameAddress, 16)
                    + ", size="
                    + SIGNAL_FRAME_SIZE);
        }

        memory.clear(frameAddress, SIGNAL_FRAME_SIZE);
        writeSignalInfo(frameAddress + SIGNAL_FRAME_INFO_OFFSET, signalNumber, signalCode, faultAddress);
        writeSignalContext(state, frameAddress + SIGNAL_FRAME_CONTEXT_OFFSET);

        long trampolineAddress = ensureSignalTrampoline(state);
        state.setRegister(1, trampolineAddress);
        state.setRegister(2, frameAddress);
        state.setRegister(10, signalNumber);
        state.setRegister(11, frameAddress + SIGNAL_FRAME_INFO_OFFSET);
        state.setRegister(12, frameAddress + SIGNAL_FRAME_CONTEXT_OFFSET);
        state.setPc(action.handler());

        GuestThread thread = state.guestThread();
        long blockedSignals = action.mask();
        if ((action.flags() & SIGNAL_ACTION_NODEFER) == 0) {
            blockedSignals |= signalMask(signalNumber);
        }
        thread.setSignalMask((thread.signalMask() | blockedSignals) & ~UNBLOCKABLE_SIGNAL_MASK);
        if ((action.flags() & SIGNAL_ACTION_RESET_HAND) != 0) {
            signalActions[(int) signalNumber] = null;
        }
    }

    /// Computes the guest stack address used for a new signal frame.
    protected long signalFrameAddress(RiscVThreadState state, SignalAction action) {
        GuestThread thread = state.guestThread();
        long stackPointer = state.register(2);
        if ((action.flags() & SIGNAL_ACTION_ON_STACK) != 0 && thread.alternateSignalStackSize() > 0) {
            stackPointer = thread.alternateSignalStackPointer() + thread.alternateSignalStackSize();
        }
        return alignDown(stackPointer - SIGNAL_FRAME_SIZE, 16);
    }

    /// Writes a Linux generic `siginfo_t` for a synchronous instruction fault.
    protected void writeSignalInfo(long infoAddress, long signalNumber, int signalCode, long faultAddress) {
        memory.writeInt(infoAddress + SIGNAL_INFO_SIGNO_OFFSET, (int) signalNumber);
        memory.writeInt(infoAddress + SIGNAL_INFO_ERRNO_OFFSET, 0);
        memory.writeInt(infoAddress + SIGNAL_INFO_CODE_OFFSET, signalCode);
        memory.writeLong(infoAddress + SIGNAL_INFO_FAULT_ADDRESS_OFFSET, faultAddress);
    }

    /// Writes a Linux RISC-V `ucontext_t` for signal delivery.
    protected void writeSignalContext(RiscVThreadState state, long contextAddress) {
        GuestThread thread = state.guestThread();
        memory.writeLong(contextAddress + SIGNAL_CONTEXT_FLAGS_OFFSET, 0);
        memory.writeLong(contextAddress + SIGNAL_CONTEXT_LINK_OFFSET, 0);
        writeSignalStack(thread, contextAddress + SIGNAL_CONTEXT_STACK_OFFSET);
        memory.writeLong(contextAddress + SIGNAL_CONTEXT_MASK_OFFSET, thread.signalMask());

        long machineContextAddress = contextAddress + SIGNAL_CONTEXT_MACHINE_OFFSET;
        state.writeSignalUserRegisters(machineContextAddress + SIGNAL_MACHINE_REGISTERS_OFFSET);
        state.writeSignalFloatingPointState(
                machineContextAddress + SIGNAL_MACHINE_FLOATING_POINT_OFFSET,
                SIGNAL_MACHINE_CONTEXT_SIZE - SIGNAL_MACHINE_FLOATING_POINT_OFFSET);
        memory.writeInt(machineContextAddress + SIGNAL_MACHINE_EXTRA_RESERVED_OFFSET, 0);
        memory.writeInt(machineContextAddress + SIGNAL_MACHINE_EXTRA_MAGIC_OFFSET, 0);
        memory.writeInt(machineContextAddress + SIGNAL_MACHINE_EXTRA_SIZE_OFFSET, 0);
    }

    /// Restores guest state from the Linux RISC-V signal frame at the current stack pointer.
    protected void rtSigreturn(RiscVThreadState state) {
        long frameAddress = state.register(2);
        if (!memory.isBacked(frameAddress, SIGNAL_FRAME_SIZE)) {
            throw new RiscVException("Guest signal return frame is not backed: address=0x"
                    + Long.toUnsignedString(frameAddress, 16)
                    + ", size="
                    + SIGNAL_FRAME_SIZE);
        }

        long contextAddress = frameAddress + SIGNAL_FRAME_CONTEXT_OFFSET;
        state.guestThread().setSignalMask(memory.readLong(contextAddress + SIGNAL_CONTEXT_MASK_OFFSET)
                & ~UNBLOCKABLE_SIGNAL_MASK);

        long machineContextAddress = contextAddress + SIGNAL_CONTEXT_MACHINE_OFFSET;
        state.readSignalUserRegisters(machineContextAddress + SIGNAL_MACHINE_REGISTERS_OFFSET);
        state.readSignalFloatingPointState(machineContextAddress + SIGNAL_MACHINE_FLOATING_POINT_OFFSET);
    }

    /// Ensures an executable guest trampoline for returning from signal handlers.
    protected long ensureSignalTrampoline(RiscVThreadState state) {
        if (signalTrampolineAddress != 0) {
            return signalTrampolineAddress;
        }

        long address = findMmapAddress(0, pageSize, pageSize);
        if (address == 0 || !ensureMemoryBacking(address, pageSize, Memory.PROTECTION_READ_WRITE_EXECUTE, false)) {
            throw new RiscVException("Failed to allocate guest signal trampoline");
        }

        addMemoryMapping(address, pageSize, Memory.PROTECTION_READ_WRITE_EXECUTE);
        memory.writeInt(address, SIGNAL_TRAMPOLINE_LOAD_SYSCALL);
        memory.writeInt(address + Integer.BYTES, SIGNAL_TRAMPOLINE_ECALL);
        signalTrampolineAddress = address;
        fenceProcessInstructionFetch();
        state.fenceInstructionFetch();
        return address;
    }

    /// Handles the Linux `prctl` operations needed by single-process user-mode guests.
    protected long prctl(
            RiscVThreadState state,
            long option,
            long argument2,
            long argument3,
            long argument4,
            long argument5) {
        if (option == PR_SET_PDEATHSIG) {
            return setParentDeathSignal(argument2, argument3, argument4, argument5);
        }
        if (option == PR_GET_PDEATHSIG) {
            return getParentDeathSignal(argument2, argument3, argument4, argument5);
        }
        if (option == PR_GET_DUMPABLE) {
            return noArguments(argument2, argument3, argument4, argument5) ? dumpable : EINVAL;
        }
        if (option == PR_SET_DUMPABLE) {
            return setDumpable(argument2, argument3, argument4, argument5);
        }
        if (option == PR_SET_NAME) {
            return setProcessName(argument2, argument3, argument4, argument5);
        }
        if (option == PR_GET_NAME) {
            return getProcessName(argument2, argument3, argument4, argument5);
        }
        if (option == PR_SET_TIMERSLACK) {
            return setTimerSlack(argument2, argument3, argument4, argument5);
        }
        if (option == PR_GET_TIMERSLACK) {
            return noArguments(argument2, argument3, argument4, argument5) ? timerSlackNanoseconds : EINVAL;
        }
        if (option == PR_SET_CHILD_SUBREAPER) {
            return setChildSubreaper(argument2, argument3, argument4, argument5);
        }
        if (option == PR_GET_CHILD_SUBREAPER) {
            return getChildSubreaper(argument2, argument3, argument4, argument5);
        }
        if (option == PR_SET_NO_NEW_PRIVS) {
            return setNoNewPrivileges(argument2, argument3, argument4, argument5);
        }
        if (option == PR_GET_NO_NEW_PRIVS) {
            return noArguments(argument2, argument3, argument4, argument5) ? (noNewPrivileges ? 1 : 0) : EINVAL;
        }
        if (option == PR_GET_TID_ADDRESS) {
            return getTidAddress(state, argument2, argument3, argument4, argument5);
        }
        if (option == PR_SET_THP_DISABLE) {
            return setTransparentHugePagesDisabled(argument2, argument3, argument4, argument5);
        }
        if (option == PR_GET_THP_DISABLE) {
            return noArguments(argument2, argument3, argument4, argument5) ? transparentHugePagesDisabled : EINVAL;
        }
        if (option == PR_SET_TAGGED_ADDR_CTRL) {
            return setTaggedAddressControl(state, argument2, argument3, argument4, argument5);
        }
        if (option == PR_GET_TAGGED_ADDR_CTRL) {
            return getTaggedAddressControl(state, argument2, argument3, argument4, argument5);
        }
        if (option == PR_GET_AUXV) {
            return getAuxiliaryVector(argument2, argument3, argument4, argument5);
        }
        if (option == PR_SET_VMA) {
            return setVirtualMemoryAreaName(argument2, argument3, argument4, argument5);
        }
        return EINVAL;
    }

    /// Stores the parent-death signal value used by `PR_GET_PDEATHSIG`.
    protected long setParentDeathSignal(long signalNumber, long argument3, long argument4, long argument5) {
        if (!unusedArgumentsAreZero(argument3, argument4, argument5)) {
            return EINVAL;
        }
        if (signalNumber != 0 && (signalNumber < MIN_SIGNAL_NUMBER || signalNumber > MAX_SIGNAL_NUMBER)) {
            return EINVAL;
        }
        parentDeathSignal = (int) signalNumber;
        return 0;
    }

    /// Writes the configured parent-death signal to a guest `int` pointer.
    protected long getParentDeathSignal(long address, long argument3, long argument4, long argument5) {
        if (!unusedArgumentsAreZero(argument3, argument4, argument5)) {
            return EINVAL;
        }
        memory.writeInt(address, parentDeathSignal);
        return 0;
    }

    /// Stores the dumpable state exposed by `PR_GET_DUMPABLE`.
    protected long setDumpable(long value, long argument3, long argument4, long argument5) {
        if (!unusedArgumentsAreZero(argument3, argument4, argument5) || (value != 0 && value != 1)) {
            return EINVAL;
        }
        dumpable = (int) value;
        return 0;
    }

    /// Copies a Linux task command name from guest memory.
    protected long setProcessName(long address, long argument3, long argument4, long argument5) {
        if (!unusedArgumentsAreZero(argument3, argument4, argument5)) {
            return EINVAL;
        }

        for (int index = 0; index < processName.length; index++) {
            processName[index] = 0;
        }
        for (int index = 0; index < TASK_COMMAND_LENGTH - 1; index++) {
            int value = memory.readUnsignedByte(address + index);
            if (value == 0) {
                return 0;
            }
            processName[index] = (byte) value;
        }
        return 0;
    }

    /// Copies the Linux task command name to guest memory.
    protected long getProcessName(long address, long argument3, long argument4, long argument5) {
        if (!unusedArgumentsAreZero(argument3, argument4, argument5)) {
            return EINVAL;
        }
        memory.writeBytes(address, processName, 0, processName.length);
        return 0;
    }

    /// Copies the initial Linux auxiliary vector for `PR_GET_AUXV`.
    protected long getAuxiliaryVector(long address, long byteCount, long argument4, long argument5) {
        if (argument4 != 0 || argument5 != 0) {
            return EINVAL;
        }
        if (Long.compareUnsigned(byteCount, auxiliaryVectorBytes.length) < 0) {
            return auxiliaryVectorBytes.length;
        }
        if (!memory.isBacked(address, auxiliaryVectorBytes.length)) {
            return EFAULT;
        }

        memory.writeBytes(address, auxiliaryVectorBytes, 0, auxiliaryVectorBytes.length);
        return auxiliaryVectorBytes.length;
    }

    /// Stores the timer slack value exposed by `PR_GET_TIMERSLACK`.
    protected long setTimerSlack(long value, long argument3, long argument4, long argument5) {
        if (!unusedArgumentsAreZero(argument3, argument4, argument5) || value < 0) {
            return EINVAL;
        }
        timerSlackNanoseconds = value == 0 ? DEFAULT_TIMER_SLACK_NANOSECONDS : value;
        return 0;
    }

    /// Stores the child-subreaper flag exposed by `PR_GET_CHILD_SUBREAPER`.
    protected long setChildSubreaper(long value, long argument3, long argument4, long argument5) {
        if (!unusedArgumentsAreZero(argument3, argument4, argument5) || (value != 0 && value != 1)) {
            return EINVAL;
        }
        childSubreaper = value == 1;
        return 0;
    }

    /// Writes the child-subreaper flag to a guest `int` pointer.
    protected long getChildSubreaper(long address, long argument3, long argument4, long argument5) {
        if (!unusedArgumentsAreZero(argument3, argument4, argument5)) {
            return EINVAL;
        }
        memory.writeInt(address, childSubreaper ? 1 : 0);
        return 0;
    }

    /// Applies the monotonic `PR_SET_NO_NEW_PRIVS` flag.
    protected long setNoNewPrivileges(long value, long argument3, long argument4, long argument5) {
        if (value != 1 || !unusedArgumentsAreZero(argument3, argument4, argument5)) {
            return EINVAL;
        }
        noNewPrivileges = true;
        return 0;
    }

    /// Writes the clear-child-TID address to a guest `long` pointer.
    protected long getTidAddress(RiscVThreadState state, long address, long argument3, long argument4, long argument5) {
        if (!unusedArgumentsAreZero(argument3, argument4, argument5)) {
            return EINVAL;
        }
        memory.writeLong(address, state.clearChildTidAddress());
        return 0;
    }

    /// Stores the transparent huge page disable state exposed by `PR_GET_THP_DISABLE`.
    protected long setTransparentHugePagesDisabled(long value, long argument3, long argument4, long argument5) {
        if (!unusedArgumentsAreZero(argument3, argument4, argument5) || (value != 0 && value != 1)) {
            return EINVAL;
        }
        transparentHugePagesDisabled = (int) value;
        return 0;
    }

    /// Stores the Linux RISC-V tagged-address control state for the current guest thread.
    protected static long setTaggedAddressControl(
            RiscVThreadState state,
            long control,
            long argument3,
            long argument4,
            long argument5) {
        if (!unusedArgumentsAreZero(argument3, argument4, argument5)) {
            return EINVAL;
        }
        if ((control & ~(PR_TAGGED_ADDR_ENABLE | PR_PMLEN_MASK)) != 0) {
            return EINVAL;
        }

        long requestedPointerMaskLength = (control & PR_PMLEN_MASK) >>> PR_PMLEN_SHIFT;
        int pointerMaskLength;
        if (requestedPointerMaskLength == POINTER_MASK_LENGTH_DISABLED) {
            pointerMaskLength = POINTER_MASK_LENGTH_DISABLED;
        } else if (requestedPointerMaskLength <= POINTER_MASK_LENGTH_7) {
            pointerMaskLength = POINTER_MASK_LENGTH_7;
        } else {
            return EINVAL;
        }

        state.guestThread().setTaggedAddressControl(
                pointerMaskLength,
                (control & PR_TAGGED_ADDR_ENABLE) != 0);
        return 0;
    }

    /// Returns the Linux RISC-V tagged-address control state for the current guest thread.
    protected static long getTaggedAddressControl(
            RiscVThreadState state,
            long argument2,
            long argument3,
            long argument4,
            long argument5) {
        if (!noArguments(argument2, argument3, argument4, argument5)) {
            return EINVAL;
        }

        GuestThread thread = state.guestThread();
        long control = (long) thread.pointerMaskLength() << PR_PMLEN_SHIFT;
        return thread.taggedAddressAbiEnabled()
                ? control | PR_TAGGED_ADDR_ENABLE
                : control;
    }

    /// Accepts Linux memory-area naming requests as a no-op in the flat guest memory model.
    protected static long setVirtualMemoryAreaName(long suboption, long startAddress, long length, long nameAddress) {
        if (suboption != PR_SET_VMA_ANON_NAME || startAddress < 0 || length < 0 || nameAddress < 0) {
            return EINVAL;
        }
        return 0;
    }

    /// Returns true when all `prctl` arguments are unused zero values.
    protected static boolean noArguments(long argument2, long argument3, long argument4, long argument5) {
        return argument2 == 0 && unusedArgumentsAreZero(argument3, argument4, argument5);
    }

    /// Returns true when all trailing `prctl` arguments are unused zero values.
    protected static boolean unusedArgumentsAreZero(long argument3, long argument4, long argument5) {
        return argument3 == 0 && argument4 == 0 && argument5 == 0;
    }


    /// Implements the Linux `brk` syscall within the simulator memory window.
    protected long brk(long requestedAddress) {
        if (requestedAddress == 0) {
            return programBreak;
        }
        if (requestedAddress >= initialProgramBreak
                && requestedAddress <= memory.endAddress()
                && !overlapsMemoryMappings(initialProgramBreak, requestedAddress - initialProgramBreak)) {
            if (requestedAddress > programBreakBackingEnd
                    && !ensureProgramBreakBacking(programBreakBackingEnd, requestedAddress - programBreakBackingEnd)) {
                return programBreak;
            }
            if (requestedAddress > programBreakBackingEnd) {
                programBreakBackingEnd = requestedAddress;
            }
            programBreak = requestedAddress;
        }
        return programBreak;
    }


    /// The maximum supplementary group count accepted by Linux.
    protected static final long MAX_SUPPLEMENTARY_GROUP_COUNT = 65536;

    /// Updates real, effective, and saved user ids.
    protected long setresuid(long requestedRealId, long requestedEffectiveId, long requestedSavedId) {
        long currentRealId = credentials.realUserId();
        long currentEffectiveId = credentials.effectiveUserId();
        long currentSavedId = credentials.savedUserId();
        long result = setresid(
                requestedRealId,
                requestedEffectiveId,
                requestedSavedId,
                currentRealId,
                currentEffectiveId,
                currentSavedId,
                currentEffectiveId == 0);
        if (result != 0) {
            return result;
        }
        credentials = credentials.withUserIds(
                setresidValue(requestedRealId, currentRealId),
                setresidValue(requestedEffectiveId, currentEffectiveId),
                setresidValue(requestedSavedId, currentSavedId));
        return 0;
    }

    /// Updates real, effective, and saved group ids.
    protected long setresgid(long requestedRealId, long requestedEffectiveId, long requestedSavedId) {
        long currentRealId = credentials.realGroupId();
        long currentEffectiveId = credentials.effectiveGroupId();
        long currentSavedId = credentials.savedGroupId();
        long result = setresid(
                requestedRealId,
                requestedEffectiveId,
                requestedSavedId,
                currentRealId,
                currentEffectiveId,
                currentSavedId,
                credentials.effectiveUserId() == 0);
        if (result != 0) {
            return result;
        }
        credentials = credentials.withGroupIds(
                setresidValue(requestedRealId, currentRealId),
                setresidValue(requestedEffectiveId, currentEffectiveId),
                setresidValue(requestedSavedId, currentSavedId));
        return 0;
    }

    /// Validates real, effective, and saved user or group id updates.
    protected static long setresid(
            long requestedRealId,
            long requestedEffectiveId,
            long requestedSavedId,
            long currentRealId,
            long currentEffectiveId,
            long currentSavedId,
            boolean privileged) {
        if (!isValidSetresidArgument(requestedRealId)
                || !isValidSetresidArgument(requestedEffectiveId)
                || !isValidSetresidArgument(requestedSavedId)) {
            return EINVAL;
        }
        if (!privileged
                && (!isUnchangedOrCurrentId(requestedRealId, currentRealId, currentEffectiveId, currentSavedId)
                || !isUnchangedOrCurrentId(requestedEffectiveId, currentRealId, currentEffectiveId, currentSavedId)
                || !isUnchangedOrCurrentId(requestedSavedId, currentRealId, currentEffectiveId, currentSavedId))) {
            return EPERM;
        }
        return 0;
    }

    /// Returns true when an id argument is valid for `setresuid` or `setresgid`.
    protected static boolean isValidSetresidArgument(long requestedId) {
        return isSetresidUnchanged(requestedId) || requestedId >= 0 && requestedId < GuestCredentials.MAX_ID;
    }

    /// Returns true for the `(uid_t) -1` sentinel that leaves one id unchanged.
    protected static boolean isSetresidUnchanged(long requestedId) {
        return requestedId == -1L || requestedId == GuestCredentials.MAX_ID;
    }

    /// Returns true when a requested id is the no-change sentinel or one current id.
    protected static boolean isUnchangedOrCurrentId(
            long requestedId,
            long currentRealId,
            long currentEffectiveId,
            long currentSavedId) {
        return isSetresidUnchanged(requestedId)
                || requestedId == currentRealId
                || requestedId == currentEffectiveId
                || requestedId == currentSavedId;
    }

    /// Returns the updated id value after applying the no-change sentinel.
    protected static long setresidValue(long requestedId, long currentId) {
        return isSetresidUnchanged(requestedId) ? currentId : requestedId;
    }

    /// Returns the unchanged filesystem user or group id.
    protected static long setfsid(long requestedId, long currentId) {
        if (!isValidSetresidArgument(requestedId)) {
            return currentId;
        }
        return currentId;
    }

    /// Writes the configured supplementary group list for identity queries.
    protected long getgroups(long size, long listAddress) {
        if (size < 0 || size > Integer.MAX_VALUE) {
            return EINVAL;
        }

        int groupCount = credentials.supplementaryGroupCount();
        if (size == 0) {
            return groupCount;
        }
        if (size < groupCount) {
            return EINVAL;
        }
        long bytes = (long) groupCount * Integer.BYTES;
        if (!memory.isBacked(listAddress, bytes)) {
            return EFAULT;
        }

        for (int index = 0; index < groupCount; index++) {
            memory.writeInt(listAddress + (long) index * Integer.BYTES,
                    GuestCredentials.idToInt(credentials.supplementaryGroupAt(index)));
        }
        return groupCount;
    }

    /// Updates the process supplementary group list.
    protected long setgroups(long size, long listAddress) {
        if (size < 0 || size > MAX_SUPPLEMENTARY_GROUP_COUNT) {
            return EINVAL;
        }
        if (credentials.effectiveUserId() != 0) {
            return EPERM;
        }

        long bytes = size * Integer.BYTES;
        if (size != 0 && !memory.isBacked(listAddress, bytes)) {
            return EFAULT;
        }

        long[] groups = new long[(int) size];
        try {
            for (int index = 0; index < groups.length; index++) {
                groups[index] = memory.readUnsignedInt(listAddress + (long) index * Integer.BYTES);
                GuestCredentials.validateId("group", groups[index]);
            }
        } catch (RiscVException exception) {
            return EFAULT;
        }
        credentials = credentials.withSupplementaryGroups(groups);
        return 0;
    }

    /// Linux address family number for netlink sockets.
    private static final long AF_NETLINK = 16;

    /// Linux address family number for Unix domain sockets.
    protected static final long AF_UNIX = 1;

    /// Linux address family number for IPv4 sockets.
    protected static final int AF_INET = 2;

    /// Linux address family number for IPv6 sockets.
    protected static final int AF_INET6 = 10;

    /// Linux socket type mask excluding socket creation flags.
    protected static final long SOCK_TYPE_MASK = 0xf;

    /// Linux stream socket type.
    protected static final long SOCK_STREAM = 1;

    /// Linux datagram socket type.
    protected static final long SOCK_DGRAM = 2;

    /// Linux raw socket type.
    private static final long SOCK_RAW = 3;

    /// Linux netlink protocol number for route and interface metadata.
    private static final long NETLINK_ROUTE = 0;

    /// Linux IPv4 protocol level.
    protected static final long IPPROTO_IP = 0;

    /// Linux TCP protocol number.
    protected static final long IPPROTO_TCP = 6;

    /// Linux UDP protocol number.
    protected static final long IPPROTO_UDP = 17;

    /// Linux IPv6 protocol level.
    protected static final long IPPROTO_IPV6 = 41;

    /// Linux `IP_RECVERR`.
    protected static final long IP_RECVERR = 11;

    /// Linux `IPV6_RECVERR`.
    protected static final long IPV6_RECVERR = 25;

    /// Linux socket option level for generic socket options.
    protected static final long SOL_SOCKET = 1;

    /// Linux `SO_REUSEADDR`.
    protected static final long SO_REUSEADDR = 2;

    /// Linux `SO_ERROR`.
    protected static final long SO_ERROR = 4;

    /// Linux `SO_BROADCAST`.
    protected static final long SO_BROADCAST = 6;

    /// Linux `SO_SNDBUF`.
    protected static final long SO_SNDBUF = 7;

    /// Linux `SO_RCVBUF`.
    protected static final long SO_RCVBUF = 8;

    /// Linux `SO_KEEPALIVE`.
    protected static final long SO_KEEPALIVE = 9;

    /// Linux `SO_REUSEPORT`.
    protected static final long SO_REUSEPORT = 15;

    /// Linux `TCP_NODELAY`.
    protected static final long TCP_NODELAY = 1;

    /// Linux `IPV6_V6ONLY`.
    protected static final long IPV6_V6ONLY = 26;

    /// Linux `MSG_DONTWAIT`.
    protected static final long MSG_DONTWAIT = 0x40L;

    /// Linux `MSG_NOSIGNAL`.
    protected static final long MSG_NOSIGNAL = 0x4000L;

    /// Linux `MSG_WAITFORONE`.
    private static final long MSG_WAITFORONE = 0x10000L;

    /// Linux message flags accepted by the host socket backend.
    protected static final long SUPPORTED_SOCKET_MESSAGE_FLAGS = MSG_DONTWAIT | MSG_NOSIGNAL;

    /// Linux `SHUT_RD`.
    private static final long SHUT_RD = 0;

    /// Linux `SHUT_WR`.
    private static final long SHUT_WR = 1;

    /// Linux `SHUT_RDWR`.
    private static final long SHUT_RDWR = 2;

    /// Byte size of Linux `struct sockaddr_nl`.
    private static final long SOCKADDR_NL_SIZE = 12;

    /// Byte offset of `nl_family` inside Linux `struct sockaddr_nl`.
    private static final long SOCKADDR_NL_FAMILY_OFFSET = 0;

    /// Byte offset of `nl_pid` inside Linux `struct sockaddr_nl`.
    private static final long SOCKADDR_NL_PID_OFFSET = 4;

    /// Byte offset of `nl_groups` inside Linux `struct sockaddr_nl`.
    private static final long SOCKADDR_NL_GROUPS_OFFSET = 8;

    /// Byte size of Linux `struct sockaddr_un`.
    private static final long SOCKADDR_UN_SIZE = 110;

    /// Byte offset of `sun_path` inside Linux `struct sockaddr_un`.
    private static final long SOCKADDR_UN_PATH_OFFSET = 2;

    /// Byte size of `sun_path` inside Linux `struct sockaddr_un`.
    private static final int SOCKADDR_UN_PATH_SIZE = 108;

    /// Byte size of Linux `struct sockaddr_in`.
    private static final long SOCKADDR_IN_SIZE = 16;

    /// Byte size of Linux `struct sockaddr_in6`.
    private static final long SOCKADDR_IN6_SIZE = 28;

    /// Byte offset of an Internet socket address family field.
    private static final long SOCKADDR_FAMILY_OFFSET = 0;

    /// Byte offset of the network-endian port field inside Internet socket addresses.
    private static final long SOCKADDR_PORT_OFFSET = 2;

    /// Byte offset of `sin_addr` inside Linux `struct sockaddr_in`.
    private static final long SOCKADDR_IN_ADDRESS_OFFSET = 4;

    /// Byte offset of `sin6_flowinfo` inside Linux `struct sockaddr_in6`.
    private static final long SOCKADDR_IN6_FLOWINFO_OFFSET = 4;

    /// Byte offset of `sin6_addr` inside Linux `struct sockaddr_in6`.
    private static final long SOCKADDR_IN6_ADDRESS_OFFSET = 8;

    /// Byte offset of `sin6_scope_id` inside Linux `struct sockaddr_in6`.
    private static final long SOCKADDR_IN6_SCOPE_ID_OFFSET = 24;

    /// Byte offset of `msg_name` inside Linux RISC-V 64-bit `struct msghdr`.
    private static final long MSGHDR_NAME_OFFSET = 0;

    /// Byte offset of `msg_namelen` inside Linux RISC-V 64-bit `struct msghdr`.
    private static final long MSGHDR_NAME_LENGTH_OFFSET = Long.BYTES;

    /// Byte offset of `msg_iov` inside Linux RISC-V 64-bit `struct msghdr`.
    private static final long MSGHDR_IOV_OFFSET = 2L * Long.BYTES;

    /// Byte offset of `msg_iovlen` inside Linux RISC-V 64-bit `struct msghdr`.
    private static final long MSGHDR_IOV_LENGTH_OFFSET = 3L * Long.BYTES;

    /// Byte offset of `msg_flags` inside Linux RISC-V 64-bit `struct msghdr`.
    private static final long MSGHDR_FLAGS_OFFSET = 6L * Long.BYTES;

    /// Byte offset of `msg_len` inside Linux RISC-V 64-bit `struct mmsghdr`.
    private static final long MMSGHDR_LENGTH_OFFSET = 7L * Long.BYTES;

    /// Byte size of Linux RISC-V 64-bit `struct mmsghdr`.
    private static final long MMSGHDR_SIZE = 8L * Long.BYTES;

    /// Byte size of Linux `struct nlmsghdr`.
    private static final int NETLINK_HEADER_SIZE = 16;

    /// Byte size of a minimal `NLMSG_DONE` response with a zero status payload.
    private static final int NETLINK_DONE_MESSAGE_SIZE = NETLINK_HEADER_SIZE + Integer.BYTES;

    /// Byte offset of `nlmsg_len` inside Linux `struct nlmsghdr`.
    private static final int NETLINK_HEADER_LENGTH_OFFSET = 0;

    /// Byte offset of `nlmsg_type` inside Linux `struct nlmsghdr`.
    private static final int NETLINK_HEADER_TYPE_OFFSET = Integer.BYTES;

    /// Byte offset of `nlmsg_flags` inside Linux `struct nlmsghdr`.
    private static final int NETLINK_HEADER_FLAGS_OFFSET = Integer.BYTES + Short.BYTES;

    /// Byte offset of `nlmsg_seq` inside Linux `struct nlmsghdr`.
    private static final int NETLINK_HEADER_SEQUENCE_OFFSET = 2 * Integer.BYTES;

    /// Byte offset of `nlmsg_pid` inside Linux `struct nlmsghdr`.
    private static final int NETLINK_HEADER_PORT_ID_OFFSET = 3 * Integer.BYTES;

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

    /// Linux netlink flag marking one message as part of a multipart response.
    private static final int NETLINK_FLAG_MULTI = 2;

    /// Linux route attribute type for the outgoing interface index.
    private static final int RTA_OIF = 4;

    /// Linux route attribute type for the gateway address.
    private static final int RTA_GATEWAY = 5;

    /// Linux route attribute type for the route metric.
    private static final int RTA_PRIORITY = 6;

    /// Linux route attribute type for the preferred source address.
    private static final int RTA_PREFSRC = 7;

    /// Linux interface attribute type for the interface name.
    private static final int IFLA_IFNAME = 3;

    /// Linux interface attribute type for the link-layer address.
    private static final int IFLA_ADDRESS = 1;

    /// Linux interface attribute type for the link-layer broadcast address.
    private static final int IFLA_BROADCAST = 2;

    /// Linux interface address attribute type for the protocol address.
    private static final int IFA_ADDRESS = 1;

    /// Linux interface address attribute type for the local address.
    private static final int IFA_LOCAL = 2;

    /// Linux interface address attribute type for the interface label.
    private static final int IFA_LABEL = 3;

    /// Linux interface address attribute type for the IPv4 broadcast address.
    private static final int IFA_BROADCAST = 4;

    /// Linux interface index used for the synthetic loopback interface.
    private static final int LOOPBACK_INTERFACE_INDEX = 1;

    /// Linux interface index used for the synthetic Ethernet interface.
    private static final int ETHERNET_INTERFACE_INDEX = 2;

    /// Linux ARPHRD_LOOPBACK hardware type.
    private static final int LOOPBACK_HARDWARE_TYPE = 772;

    /// Linux ARPHRD_ETHER hardware type.
    private static final int ETHERNET_HARDWARE_TYPE = 1;

    /// Linux interface flags for an up and running loopback interface.
    private static final int LOOPBACK_INTERFACE_FLAGS = 0x49;

    /// Linux interface flags for an up and running Ethernet interface.
    private static final int ETHERNET_INTERFACE_FLAGS = 0x11043;

    /// Linux rtnetlink host scope used by loopback addresses.
    private static final int RT_SCOPE_HOST = 254;

    /// Linux rtnetlink universe scope used by regular IPv4 addresses.
    private static final int RT_SCOPE_UNIVERSE = 0;

    /// Linux main routing table id.
    private static final int RT_TABLE_MAIN = 254;

    /// Linux static route protocol id.
    private static final int RTPROT_STATIC = 4;

    /// Linux unicast route type id.
    private static final int RTN_UNICAST = 1;

    /// Linux permanent interface-address flag.
    private static final int IFA_F_PERMANENT = 0x80;

    /// Linux socket type creation flags accepted by the minimal socket runtime.
    private static final long SUPPORTED_SOCKET_TYPE_FLAGS = O_NONBLOCK | O_CLOEXEC;

    /// Linux flags accepted by `accept4`.
    private static final long SUPPORTED_ACCEPT4_FLAGS = O_NONBLOCK | O_CLOEXEC;

    /// Linux `SIOCGIFNAME` ioctl request number.
    private static final long SIOCGIFNAME = 0x8910L;

    /// Linux `SIOCGIFINDEX` ioctl request number.
    private static final long SIOCGIFINDEX = 0x8933L;

    /// Linux `IFNAMSIZ`.
    private static final int INTERFACE_NAME_SIZE = 16;

    /// Byte offset of `ifr_ifindex` in Linux `struct ifreq`.
    private static final long IFREQ_INTERFACE_INDEX_OFFSET = INTERFACE_NAME_SIZE;

    /// Minimum byte size needed for Linux `struct ifreq` name/index ioctls.
    private static final long IFREQ_NAME_INDEX_SIZE = IFREQ_INTERFACE_INDEX_OFFSET + Integer.BYTES;

    /// Creates a guest socket for the minimal network-related Linux runtime.
    protected long socket(long domain, long type, long protocol) {
        long socketType = type & SOCK_TYPE_MASK;
        long typeFlags = type & ~SOCK_TYPE_MASK;
        if ((typeFlags & ~SUPPORTED_SOCKET_TYPE_FLAGS) != 0) {
            return EINVAL;
        }
        boolean nonblocking = (typeFlags & O_NONBLOCK) != 0;
        boolean closeOnExec = (typeFlags & O_CLOEXEC) != 0;
        if (domain == AF_INET || domain == AF_INET6) {
            return internetSocket((int) domain, socketType, protocol, nonblocking, closeOnExec);
        }
        if (domain == AF_NETLINK
                && (socketType == SOCK_RAW || socketType == SOCK_DGRAM)
                && protocol == NETLINK_ROUTE) {
            return addOpenFile(OpenFile.socket(new NetlinkRouteSocket(), nonblocking), closeOnExec);
        }
        if (domain == AF_UNIX && socketType == SOCK_STREAM && protocol == 0) {
            return unixStreamSocket(nonblocking, closeOnExec);
        }
        if (domain == AF_UNIX && socketType == SOCK_DGRAM && protocol == 0) {
            return addOpenFile(OpenFile.socket(new NetworkInterfaceIoctlSocket(), nonblocking), closeOnExec);
        }
        return EAFNOSUPPORT;
    }

    /// Creates a guest Internet socket through the configured network backend.
    private long internetSocket(
            int domain,
            long socketType,
            long protocol,
            boolean nonblocking,
            boolean closeOnExec) {
        if (!networkBackend.enabled()) {
            return EAFNOSUPPORT;
        }
        if (socketType == SOCK_STREAM) {
            if (protocol != 0 && protocol != IPPROTO_TCP) {
                return EPROTONOSUPPORT;
            }
        } else if (socketType == SOCK_DGRAM) {
            if (protocol != 0 && protocol != IPPROTO_UDP) {
                return EPROTONOSUPPORT;
            }
        } else {
            return EPROTONOSUPPORT;
        }

        try {
            return addOpenFile(
                    OpenFile.socket(new InternetSocket(domain, (int) socketType, protocol), nonblocking),
                    closeOnExec);
        } catch (IOException exception) {
            return networkException(exception);
        }
    }

    /// Creates a guest Unix-domain stream socket through the configured network backend.
    private long unixStreamSocket(boolean nonblocking, boolean closeOnExec) {
        if (!networkBackend.enabled()) {
            return EAFNOSUPPORT;
        }

        try {
            return addOpenFile(OpenFile.socket(new HostUnixStreamSocket(), nonblocking), closeOnExec);
        } catch (IOException exception) {
            return networkException(exception);
        } catch (UnsupportedOperationException exception) {
            return EAFNOSUPPORT;
        }
    }

    /// Creates a pair of connected in-memory Unix-domain stream sockets.
    protected long socketpair(long domain, long type, long protocol, long pairAddress) {
        long socketType = type & SOCK_TYPE_MASK;
        long typeFlags = type & ~SOCK_TYPE_MASK;
        if ((typeFlags & ~SUPPORTED_SOCKET_TYPE_FLAGS) != 0) {
            return EINVAL;
        }
        if (domain != AF_UNIX) {
            return EAFNOSUPPORT;
        }
        if (socketType != SOCK_STREAM) {
            return EPROTONOSUPPORT;
        }
        if (protocol != 0) {
            return EPROTONOSUPPORT;
        }
        if (!memory.isBacked(pairAddress, 2L * Integer.BYTES)) {
            return EFAULT;
        }

        PipeBuffer firstToSecond = new PipeBuffer(this::notifyPollWaiters);
        PipeBuffer secondToFirst = new PipeBuffer(this::notifyPollWaiters);
        boolean nonblocking = (typeFlags & O_NONBLOCK) != 0;
        boolean closeOnExec = (typeFlags & O_CLOEXEC) != 0;
        long firstFileDescriptor = addOpenFile(OpenFile.socket(
                new LocalUnixStreamSocket(secondToFirst, firstToSecond),
                nonblocking), closeOnExec);
        long secondFileDescriptor = addOpenFile(OpenFile.socket(
                new LocalUnixStreamSocket(firstToSecond, secondToFirst),
                nonblocking), closeOnExec);
        memory.writeInt(pairAddress, (int) firstFileDescriptor);
        memory.writeInt(pairAddress + Integer.BYTES, (int) secondFileDescriptor);
        return 0;
    }

    /// Handles Linux network-interface ioctl requests on generic ioctl sockets.
    @Override
    protected long ioctl(int fileDescriptor, long request, long argument) {
        if (networkInterfaceIoctlSocket(fileDescriptor) == null) {
            return super.ioctl(fileDescriptor, request, argument);
        }
        if (!memory.isBacked(argument, IFREQ_NAME_INDEX_SIZE)) {
            return EFAULT;
        }

        if (request == SIOCGIFNAME) {
            @Nullable String name = interfaceName(memory.readInt(argument + IFREQ_INTERFACE_INDEX_OFFSET));
            if (name == null) {
                return ENODEV;
            }
            writeInterfaceName(argument, name);
            return 0;
        }
        if (request == SIOCGIFINDEX) {
            int index = interfaceIndex(readInterfaceName(argument));
            if (index == 0) {
                return ENODEV;
            }
            memory.writeInt(argument + IFREQ_INTERFACE_INDEX_OFFSET, index);
            return 0;
        }
        return ENOTTY;
    }

    /// Returns the network-interface ioctl socket backing a descriptor, or null when it is not such a socket.
    private @Nullable NetworkInterfaceIoctlSocket networkInterfaceIoctlSocket(int fileDescriptor) {
        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null || !openFile.isSocket()) {
            return null;
        }

        GuestSocket socket = openFile.socket();
        return socket instanceof NetworkInterfaceIoctlSocket ioctlSocket ? ioctlSocket : null;
    }

    /// Returns the synthetic interface name for an index, or null when absent.
    private static @Nullable String interfaceName(int index) {
        return switch (index) {
            case LOOPBACK_INTERFACE_INDEX -> "lo";
            case ETHERNET_INTERFACE_INDEX -> "eth0";
            default -> null;
        };
    }

    /// Returns the synthetic interface index for a name, or zero when absent.
    private static int interfaceIndex(String name) {
        return switch (name) {
            case "lo" -> LOOPBACK_INTERFACE_INDEX;
            case "eth0" -> ETHERNET_INTERFACE_INDEX;
            default -> 0;
        };
    }

    /// Reads a null-terminated Linux interface name from a guest `struct ifreq`.
    private String readInterfaceName(long ifreqAddress) {
        byte[] bytes = memory.readBytes(ifreqAddress, INTERFACE_NAME_SIZE);
        int length = 0;
        while (length < bytes.length && bytes[length] != 0) {
            length++;
        }
        return new String(bytes, 0, length, StandardCharsets.UTF_8);
    }

    /// Writes a null-terminated Linux interface name into a guest `struct ifreq`.
    private void writeInterfaceName(long ifreqAddress, String name) {
        byte[] bytes = name.getBytes(StandardCharsets.UTF_8);
        int length = Math.min(bytes.length, INTERFACE_NAME_SIZE - 1);
        memory.clear(ifreqAddress, INTERFACE_NAME_SIZE);
        memory.writeBytes(ifreqAddress, bytes, 0, length);
    }

    /// Binds a minimal netlink socket to a local port id.
    protected long bind(int fileDescriptor, long address, long addressLength) {
        @Nullable InternetSocket internetSocket = internetSocket(fileDescriptor);
        if (internetSocket != null) {
            AddressResult result = readInetSocketAddress(address, addressLength);
            return result.error() != 0 ? result.error() : internetSocket.bind(result.address());
        }

        if (unixStreamSocket(fileDescriptor) != null) {
            return ENOTSUP;
        }

        @Nullable NetlinkRouteSocket socket = netlinkRouteSocket(fileDescriptor);
        if (socket == null) {
            return ENOTSOCK;
        }
        if (address != 0) {
            if (addressLength < SOCKADDR_NL_SIZE || !memory.isBacked(address, SOCKADDR_NL_SIZE)) {
                return EFAULT;
            }
            if (Short.toUnsignedLong(memory.readShort(address + SOCKADDR_NL_FAMILY_OFFSET)) != AF_NETLINK) {
                return EINVAL;
            }
            socket.bind(Integer.toUnsignedLong(memory.readInt(address + SOCKADDR_NL_PID_OFFSET)));
        } else {
            socket.bind(0);
        }
        return 0;
    }

    /// Connects a guest stream socket to a remote peer.
    protected long connect(int fileDescriptor, long address, long addressLength) {
        @Nullable InternetSocket internetSocket = internetSocket(fileDescriptor);
        if (internetSocket != null) {
            AddressResult result = readInetSocketAddress(address, addressLength);
            return result.error() != 0
                    ? result.error()
                    : internetSocket.connect(result.address(), socketNonblocking(fileDescriptor));
        }

        @Nullable UnixStreamSocket unixSocket = unixStreamSocket(fileDescriptor);
        if (unixSocket != null) {
            UnixAddressResult result = readUnixSocketAddress(address, addressLength);
            return result.error() != 0
                    ? result.error()
                    : unixSocket.connect(result.address(), socketNonblocking(fileDescriptor));
        }
        return ENOTSOCK;
    }

    /// Marks a guest stream socket as accepting incoming connections.
    protected long listen(int fileDescriptor, long backlog) {
        @Nullable InternetSocket socket = internetSocket(fileDescriptor);
        if (socket == null) {
            return unixStreamSocket(fileDescriptor) == null ? ENOTSOCK : ENOTSUP;
        }
        if (backlog < 0) {
            backlog = 0;
        }
        return socket.listen(backlog > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) backlog);
    }

    /// Accepts one incoming connection from a guest stream server socket.
    protected long accept(int fileDescriptor, long address, long lengthAddress, long flags) {
        if ((flags & ~SUPPORTED_ACCEPT4_FLAGS) != 0) {
            return EINVAL;
        }
        @Nullable InternetSocket socket = internetSocket(fileDescriptor);
        if (socket == null) {
            return unixStreamSocket(fileDescriptor) == null ? ENOTSOCK : ENOTSUP;
        }

        AcceptResult result = socket.accept(socketNonblocking(fileDescriptor), (flags & O_NONBLOCK) != 0);
        if (result.error() != 0) {
            return result.error();
        }
        @Nullable InternetSocket acceptedSocket = result.socket();
        assert acceptedSocket != null;
        @Nullable InetSocketAddress remoteAddress = result.address();
        if (remoteAddress != null) {
            long writeResult = writeInetSocketAddress(remoteAddress, acceptedSocket.domain(), address, lengthAddress);
            if (writeResult != 0) {
                try {
                    acceptedSocket.close();
                } catch (IOException exception) {
                    return networkException(exception);
                }
                return writeResult;
            }
        }
        return addOpenFile(
                OpenFile.socket(acceptedSocket, (flags & O_NONBLOCK) != 0),
                (flags & O_CLOEXEC) != 0);
    }

    /// Sets one supported guest socket option.
    protected long setsockopt(int fileDescriptor, long level, long option, long valueAddress, long valueLength) {
        @Nullable InternetSocket socket = internetSocket(fileDescriptor);
        @Nullable UnixStreamSocket unixSocket = unixStreamSocket(fileDescriptor);
        if (socket == null && unixSocket == null) {
            return ENOTSOCK;
        }
        if (valueLength < Integer.BYTES || !memory.isBacked(valueAddress, Integer.BYTES)) {
            return EFAULT;
        }
        if (socket != null) {
            return socket.setOption(level, option, memory.readInt(valueAddress));
        }
        return unixSocket.setOption(level, option, memory.readInt(valueAddress));
    }

    /// Gets one supported guest socket option.
    protected long getsockopt(int fileDescriptor, long level, long option, long valueAddress, long lengthAddress) {
        @Nullable InternetSocket socket = internetSocket(fileDescriptor);
        @Nullable UnixStreamSocket unixSocket = unixStreamSocket(fileDescriptor);
        if (socket == null && unixSocket == null) {
            return ENOTSOCK;
        }
        if (!memory.isBacked(lengthAddress, Integer.BYTES)) {
            return EFAULT;
        }
        int requestedLength = memory.readInt(lengthAddress);
        if (requestedLength < Integer.BYTES || !memory.isBacked(valueAddress, Integer.BYTES)) {
            return EFAULT;
        }
        OptionResult result;
        if (socket != null) {
            result = socket.getOption(level, option);
        } else {
            result = unixSocket.getOption(level, option);
        }
        if (result.error() != 0) {
            return result.error();
        }
        memory.writeInt(valueAddress, result.value());
        memory.writeInt(lengthAddress, Integer.BYTES);
        return 0;
    }

    /// Shuts down one or both halves of a connected stream socket.
    protected long shutdown(int fileDescriptor, long how) {
        @Nullable InternetSocket socket = internetSocket(fileDescriptor);
        if (socket != null) {
            return socket.shutdown(how);
        }
        @Nullable UnixStreamSocket unixSocket = unixStreamSocket(fileDescriptor);
        return unixSocket == null ? ENOTSOCK : unixSocket.shutdown(how);
    }

    /// Sends one minimal netlink route request and queues an empty dump response.
    protected long sendto(
            int fileDescriptor,
            long bufferAddress,
            long length,
            long flags,
            long destinationAddress,
            long destinationLength) {
        @Nullable InternetSocket internetSocket = internetSocket(fileDescriptor);
        if (internetSocket != null) {
            if ((flags & ~SUPPORTED_SOCKET_MESSAGE_FLAGS) != 0) {
                return EINVAL;
            }
            if (length < 0 || length > Integer.MAX_VALUE) {
                return EINVAL;
            }
            if (!memory.isBacked(bufferAddress, length)) {
                return EFAULT;
            }
            @Nullable InetSocketAddress destination = null;
            if (destinationAddress != 0) {
                AddressResult result = readInetSocketAddress(destinationAddress, destinationLength);
                if (result.error() != 0) {
                    return result.error();
                }
                destination = result.address();
            }
            return internetSocket.send(
                    ByteBuffer.wrap(memory.readBytes(bufferAddress, length)),
                    destination,
                    socketNonblocking(fileDescriptor) || (flags & MSG_DONTWAIT) != 0);
        }

        @Nullable UnixStreamSocket unixSocket = unixStreamSocket(fileDescriptor);
        if (unixSocket != null) {
            if ((flags & ~SUPPORTED_SOCKET_MESSAGE_FLAGS) != 0) {
                return EINVAL;
            }
            if (length < 0 || length > Integer.MAX_VALUE) {
                return EINVAL;
            }
            if (!memory.isBacked(bufferAddress, length)) {
                return EFAULT;
            }
            if (destinationAddress != 0) {
                UnixAddressResult result = readUnixSocketAddress(destinationAddress, destinationLength);
                if (result.error() != 0) {
                    return result.error();
                }
                return EISCONN;
            }
            return unixSocket.send(
                    ByteBuffer.wrap(memory.readBytes(bufferAddress, length)),
                    socketNonblocking(fileDescriptor) || (flags & MSG_DONTWAIT) != 0);
        }

        @Nullable NetlinkRouteSocket socket = netlinkRouteSocket(fileDescriptor);
        if (socket == null) {
            return ENOTSOCK;
        }
        if (length < 0 || length > Integer.MAX_VALUE) {
            return EINVAL;
        }
        if (!memory.isBacked(bufferAddress, length)) {
            return EFAULT;
        }
        if (destinationAddress != 0 && destinationLength < SOCKADDR_NL_SIZE) {
            return EINVAL;
        }

        byte[] request = memory.readBytes(bufferAddress, Math.min(length, NETLINK_HEADER_SIZE));
        socket.enqueueResponse(request, process.id());
        return length;
    }

    /// Receives one queued minimal netlink route response into a flat guest buffer.
    protected long recvfrom(
            int fileDescriptor,
            long bufferAddress,
            long length,
            long flags,
            long sourceAddress,
            long sourceLengthAddress) {
        @Nullable InternetSocket internetSocket = internetSocket(fileDescriptor);
        if (internetSocket != null) {
            if ((flags & ~SUPPORTED_SOCKET_MESSAGE_FLAGS) != 0) {
                return EINVAL;
            }
            if (length < 0 || length > Integer.MAX_VALUE) {
                return EINVAL;
            }
            if (!memory.isBacked(bufferAddress, length)) {
                return EFAULT;
            }
            byte[] buffer = new byte[(int) length];
            ReceiveResult result = internetSocket.receive(
                    ByteBuffer.wrap(buffer),
                    socketNonblocking(fileDescriptor) || (flags & MSG_DONTWAIT) != 0);
            if (result.error() != 0) {
                return result.error();
            }
            if (result.count() > 0) {
                memory.writeBytes(bufferAddress, buffer, 0, result.count());
            }
            @Nullable InetSocketAddress source = result.address();
            if (source != null) {
                long writeResult = writeInetSocketAddress(source, internetSocket.domain(), sourceAddress, sourceLengthAddress);
                if (writeResult != 0) {
                    return writeResult;
                }
            }
            return result.count();
        }

        @Nullable UnixStreamSocket unixSocket = unixStreamSocket(fileDescriptor);
        if (unixSocket != null) {
            if ((flags & ~SUPPORTED_SOCKET_MESSAGE_FLAGS) != 0) {
                return EINVAL;
            }
            if (length < 0 || length > Integer.MAX_VALUE) {
                return EINVAL;
            }
            if (!memory.isBacked(bufferAddress, length)) {
                return EFAULT;
            }
            byte[] buffer = new byte[(int) length];
            UnixReceiveResult result = unixSocket.receive(
                    ByteBuffer.wrap(buffer),
                    socketNonblocking(fileDescriptor) || (flags & MSG_DONTWAIT) != 0);
            if (result.error() != 0) {
                return result.error();
            }
            if (result.count() > 0) {
                memory.writeBytes(bufferAddress, buffer, 0, result.count());
            }
            @Nullable String source = result.address();
            if (source != null) {
                long writeResult = writeUnixSocketAddress(source, sourceAddress, sourceLengthAddress);
                if (writeResult != 0) {
                    return writeResult;
                }
            }
            return result.count();
        }

        @Nullable NetlinkRouteSocket socket = netlinkRouteSocket(fileDescriptor);
        if (socket == null) {
            return ENOTSOCK;
        }
        if (length < 0 || length > Integer.MAX_VALUE) {
            return EINVAL;
        }
        if (!memory.isBacked(bufferAddress, length)) {
            return EFAULT;
        }

        @Nullable byte[] response = socket.pollResponse();
        if (response == null) {
            return EAGAIN;
        }
        writeSockaddrNl(sourceAddress, sourceLengthAddress, 0);
        int count = (int) Math.min(length, response.length);
        memory.writeBytes(bufferAddress, response, 0, count);
        return count;
    }

    /// Returns the byte offset of `msg_flags` in the active guest ABI's socket message header.
    protected long socketMessageFlagsOffset() {
        return MSGHDR_FLAGS_OFFSET;
    }

    /// Reads `msg_iovlen` from the active guest ABI's socket message header.
    protected long socketMessageIovecCount(long messageAddress) {
        return memory.readLong(messageAddress + MSGHDR_IOV_LENGTH_OFFSET);
    }

    /// Sends one minimal netlink route request described by a guest `struct msghdr`.
    protected long sendmsg(int fileDescriptor, long messageAddress, long flags) {
        @Nullable InternetSocket internetSocket = internetSocket(fileDescriptor);
        if (internetSocket != null) {
            if ((flags & ~SUPPORTED_SOCKET_MESSAGE_FLAGS) != 0) {
                return EINVAL;
            }
            if (!memory.isBacked(messageAddress, socketMessageFlagsOffset() + Integer.BYTES)) {
                return EFAULT;
            }

            @Nullable InetSocketAddress destination = null;
            long nameAddress = memory.readLong(messageAddress + MSGHDR_NAME_OFFSET);
            long nameLength = Integer.toUnsignedLong(memory.readInt(messageAddress + MSGHDR_NAME_LENGTH_OFFSET));
            if (nameAddress != 0) {
                AddressResult addressResult = readInetSocketAddress(nameAddress, nameLength);
                if (addressResult.error() != 0) {
                    return addressResult.error();
                }
                destination = addressResult.address();
            }

            long iovecAddress = memory.readLong(messageAddress + MSGHDR_IOV_OFFSET);
            long iovecCount = socketMessageIovecCount(messageAddress);
            if (iovecCount < 0 || iovecCount > IOV_MAX) {
                return EINVAL;
            }
            long byteCount = iovByteCount(iovecAddress, iovecCount);
            if (byteCount < 0) {
                return byteCount;
            }
            if (byteCount > Integer.MAX_VALUE) {
                return EINVAL;
            }
            byte @Nullable [] bytes = readIovPrefix(iovecAddress, iovecCount, (int) byteCount);
            if (bytes == null) {
                return EFAULT;
            }
            return internetSocket.send(
                    ByteBuffer.wrap(bytes),
                    destination,
                    socketNonblocking(fileDescriptor) || (flags & MSG_DONTWAIT) != 0);
        }

        @Nullable UnixStreamSocket unixSocket = unixStreamSocket(fileDescriptor);
        if (unixSocket != null) {
            if ((flags & ~SUPPORTED_SOCKET_MESSAGE_FLAGS) != 0) {
                return EINVAL;
            }
            if (!memory.isBacked(messageAddress, socketMessageFlagsOffset() + Integer.BYTES)) {
                return EFAULT;
            }

            long nameAddress = memory.readLong(messageAddress + MSGHDR_NAME_OFFSET);
            long nameLength = Integer.toUnsignedLong(memory.readInt(messageAddress + MSGHDR_NAME_LENGTH_OFFSET));
            if (nameAddress != 0) {
                UnixAddressResult addressResult = readUnixSocketAddress(nameAddress, nameLength);
                if (addressResult.error() != 0) {
                    return addressResult.error();
                }
                return EISCONN;
            }

            long iovecAddress = memory.readLong(messageAddress + MSGHDR_IOV_OFFSET);
            long iovecCount = socketMessageIovecCount(messageAddress);
            if (iovecCount < 0 || iovecCount > IOV_MAX) {
                return EINVAL;
            }
            long byteCount = iovByteCount(iovecAddress, iovecCount);
            if (byteCount < 0) {
                return byteCount;
            }
            if (byteCount > Integer.MAX_VALUE) {
                return EINVAL;
            }
            byte @Nullable [] bytes = readIovPrefix(iovecAddress, iovecCount, (int) byteCount);
            if (bytes == null) {
                return EFAULT;
            }
            return unixSocket.send(
                    ByteBuffer.wrap(bytes),
                    socketNonblocking(fileDescriptor) || (flags & MSG_DONTWAIT) != 0);
        }

        @Nullable NetlinkRouteSocket socket = netlinkRouteSocket(fileDescriptor);
        if (socket == null) {
            return ENOTSOCK;
        }
        if (!memory.isBacked(messageAddress, socketMessageFlagsOffset() + Integer.BYTES)) {
            return EFAULT;
        }

        long iovecAddress = memory.readLong(messageAddress + MSGHDR_IOV_OFFSET);
        long iovecCount = socketMessageIovecCount(messageAddress);
        if (iovecCount < 0 || iovecCount > IOV_MAX) {
            return EINVAL;
        }

        byte[] request = readIovPrefix(iovecAddress, iovecCount, NETLINK_HEADER_SIZE);
        if (request == null) {
            return EFAULT;
        }
        long byteCount = iovByteCount(iovecAddress, iovecCount);
        if (byteCount < 0) {
            return byteCount;
        }
        socket.enqueueResponse(request, process.id());
        return byteCount;
    }

    /// Receives one queued minimal netlink route response into guest `struct msghdr` buffers.
    protected long recvmsg(int fileDescriptor, long messageAddress, long flags) {
        @Nullable InternetSocket internetSocket = internetSocket(fileDescriptor);
        if (internetSocket != null) {
            if ((flags & ~SUPPORTED_SOCKET_MESSAGE_FLAGS) != 0) {
                return EINVAL;
            }
            if (!memory.isBacked(messageAddress, socketMessageFlagsOffset() + Integer.BYTES)) {
                return EFAULT;
            }

            long iovecAddress = memory.readLong(messageAddress + MSGHDR_IOV_OFFSET);
            long iovecCount = socketMessageIovecCount(messageAddress);
            if (iovecCount < 0 || iovecCount > IOV_MAX) {
                return EINVAL;
            }
            long byteCount = iovByteCount(iovecAddress, iovecCount);
            if (byteCount < 0) {
                return byteCount;
            }
            if (byteCount > Integer.MAX_VALUE) {
                return EINVAL;
            }

            byte[] buffer = new byte[(int) byteCount];
            ReceiveResult result = internetSocket.receive(
                    ByteBuffer.wrap(buffer),
                    socketNonblocking(fileDescriptor) || (flags & MSG_DONTWAIT) != 0);
            if (result.error() != 0) {
                return result.error();
            }
            memory.writeInt(messageAddress + socketMessageFlagsOffset(), 0);
            long nameAddress = memory.readLong(messageAddress + MSGHDR_NAME_OFFSET);
            long nameLength = Integer.toUnsignedLong(memory.readInt(messageAddress + MSGHDR_NAME_LENGTH_OFFSET));
            @Nullable InetSocketAddress source = result.address();
            if (source != null && nameAddress != 0 && nameLength >= sockaddrSize(internetSocket.domain())) {
                long writeResult = writeInetSocketAddress(source, internetSocket.domain(), nameAddress, 0);
                if (writeResult != 0) {
                    return writeResult;
                }
                memory.writeInt(messageAddress + MSGHDR_NAME_LENGTH_OFFSET, (int) sockaddrSize(internetSocket.domain()));
            }
            return writeIovBytes(iovecAddress, iovecCount, result.count() == buffer.length
                    ? buffer
                    : copyBufferPrefix(buffer, result.count()));
        }

        @Nullable UnixStreamSocket unixSocket = unixStreamSocket(fileDescriptor);
        if (unixSocket != null) {
            if ((flags & ~SUPPORTED_SOCKET_MESSAGE_FLAGS) != 0) {
                return EINVAL;
            }
            if (!memory.isBacked(messageAddress, socketMessageFlagsOffset() + Integer.BYTES)) {
                return EFAULT;
            }

            long iovecAddress = memory.readLong(messageAddress + MSGHDR_IOV_OFFSET);
            long iovecCount = socketMessageIovecCount(messageAddress);
            if (iovecCount < 0 || iovecCount > IOV_MAX) {
                return EINVAL;
            }
            long byteCount = iovByteCount(iovecAddress, iovecCount);
            if (byteCount < 0) {
                return byteCount;
            }
            if (byteCount > Integer.MAX_VALUE) {
                return EINVAL;
            }

            byte[] buffer = new byte[(int) byteCount];
            UnixReceiveResult result = unixSocket.receive(
                    ByteBuffer.wrap(buffer),
                    socketNonblocking(fileDescriptor) || (flags & MSG_DONTWAIT) != 0);
            if (result.error() != 0) {
                return result.error();
            }
            memory.writeInt(messageAddress + socketMessageFlagsOffset(), 0);
            long nameAddress = memory.readLong(messageAddress + MSGHDR_NAME_OFFSET);
            long nameLength = Integer.toUnsignedLong(memory.readInt(messageAddress + MSGHDR_NAME_LENGTH_OFFSET));
            @Nullable String source = result.address();
            if (source != null && nameAddress != 0 && nameLength >= unixSockaddrSize(source)) {
                long writeResult = writeUnixSocketAddress(source, nameAddress, 0);
                if (writeResult != 0) {
                    return writeResult;
                }
                memory.writeInt(messageAddress + MSGHDR_NAME_LENGTH_OFFSET, (int) unixSockaddrSize(source));
            }
            return writeIovBytes(iovecAddress, iovecCount, result.count() == buffer.length
                    ? buffer
                    : copyBufferPrefix(buffer, result.count()));
        }

        @Nullable NetlinkRouteSocket socket = netlinkRouteSocket(fileDescriptor);
        if (socket == null) {
            return ENOTSOCK;
        }
        if (!memory.isBacked(messageAddress, socketMessageFlagsOffset() + Integer.BYTES)) {
            return EFAULT;
        }

        @Nullable byte[] response = socket.pollResponse();
        if (response == null) {
            return EAGAIN;
        }

        long nameAddress = memory.readLong(messageAddress + MSGHDR_NAME_OFFSET);
        long nameLength = Integer.toUnsignedLong(memory.readInt(messageAddress + MSGHDR_NAME_LENGTH_OFFSET));
        if (nameAddress != 0 && nameLength >= SOCKADDR_NL_SIZE) {
            writeSockaddrNl(nameAddress, 0, 0);
            memory.writeInt(messageAddress + MSGHDR_NAME_LENGTH_OFFSET, (int) SOCKADDR_NL_SIZE);
        }
        memory.writeInt(messageAddress + socketMessageFlagsOffset(), 0);

        long iovecAddress = memory.readLong(messageAddress + MSGHDR_IOV_OFFSET);
        long iovecCount = socketMessageIovecCount(messageAddress);
        if (iovecCount < 0 || iovecCount > IOV_MAX) {
            return EINVAL;
        }
        return writeIovBytes(iovecAddress, iovecCount, response);
    }

    /// Sends multiple datagrams described by Linux `struct mmsghdr` entries.
    protected long sendmmsg(int fileDescriptor, long messageVectorAddress, long messageCount, long flags) {
        if (messageCount < 0 || messageCount > IOV_MAX) {
            return EINVAL;
        }
        long messageVectorLength = messageCount * MMSGHDR_SIZE;
        if (messageVectorLength < 0 || !memory.isBacked(messageVectorAddress, messageVectorLength)) {
            return EFAULT;
        }

        int sent = 0;
        for (long index = 0; index < messageCount; index++) {
            long messageAddress = messageVectorAddress + index * MMSGHDR_SIZE;
            long result = sendmsg(fileDescriptor, messageAddress, flags);
            if (result < 0) {
                return sent > 0 ? sent : result;
            }
            memory.writeInt(messageAddress + MMSGHDR_LENGTH_OFFSET, (int) result);
            sent++;
        }
        return sent;
    }

    /// Receives multiple datagrams described by Linux `struct mmsghdr` entries.
    protected long recvmmsg(
            int fileDescriptor,
            long messageVectorAddress,
            long messageCount,
            long flags,
            long timeoutAddress) {
        if (messageCount < 0 || messageCount > IOV_MAX) {
            return EINVAL;
        }
        if ((flags & ~MSG_WAITFORONE & ~SUPPORTED_SOCKET_MESSAGE_FLAGS) != 0) {
            return EINVAL;
        }
        long messageVectorLength = messageCount * MMSGHDR_SIZE;
        if (messageVectorLength < 0
                || !memory.isBacked(messageVectorAddress, messageVectorLength)
                || (timeoutAddress != 0 && !memory.isBacked(timeoutAddress, 2L * Long.BYTES))) {
            return EFAULT;
        }

        long receiveFlags = flags & ~MSG_WAITFORONE;
        int received = 0;
        for (long index = 0; index < messageCount; index++) {
            long messageAddress = messageVectorAddress + index * MMSGHDR_SIZE;
            long result = recvmsg(fileDescriptor, messageAddress, receiveFlags);
            if (result < 0) {
                return received > 0 ? received : result;
            }
            memory.writeInt(messageAddress + MMSGHDR_LENGTH_OFFSET, (int) result);
            received++;
            if ((flags & MSG_WAITFORONE) != 0) {
                receiveFlags |= MSG_DONTWAIT;
            }
        }
        return received;
    }

    /// Writes the local netlink socket address for `getsockname`.
    protected long getsockname(int fileDescriptor, long address, long lengthAddress) {
        @Nullable InternetSocket internetSocket = internetSocket(fileDescriptor);
        if (internetSocket != null) {
            @Nullable InetSocketAddress socketAddress = internetSocket.localAddress();
            return socketAddress == null
                    ? writeWildcardInetSocketAddress(internetSocket.domain(), address, lengthAddress)
                    : writeInetSocketAddress(socketAddress, internetSocket.domain(), address, lengthAddress);
        }

        @Nullable UnixStreamSocket unixSocket = unixStreamSocket(fileDescriptor);
        if (unixSocket != null) {
            return writeUnixSocketAddress(unixSocket.localPath(), address, lengthAddress);
        }

        @Nullable NetlinkRouteSocket socket = netlinkRouteSocket(fileDescriptor);
        if (socket == null) {
            return ENOTSOCK;
        }
        return writeSockaddrNl(address, lengthAddress, socket.portId(process.id()));
    }

    /// Reports that the minimal netlink socket has no connected peer.
    protected long getpeername(int fileDescriptor, long address, long lengthAddress) {
        @Nullable InternetSocket internetSocket = internetSocket(fileDescriptor);
        if (internetSocket != null) {
            @Nullable InetSocketAddress socketAddress = internetSocket.peerAddress();
            return socketAddress == null
                    ? ENOTCONN
                    : writeInetSocketAddress(socketAddress, internetSocket.domain(), address, lengthAddress);
        }
        @Nullable UnixStreamSocket unixSocket = unixStreamSocket(fileDescriptor);
        if (unixSocket != null) {
            @Nullable String socketAddress = unixSocket.peerPath();
            return socketAddress == null ? ENOTCONN : writeUnixSocketAddress(socketAddress, address, lengthAddress);
        }
        return netlinkRouteSocket(fileDescriptor) == null ? ENOTSOCK : EINVAL;
    }

    /// Reads bytes from a guest network socket or falls back to generic descriptor reads.
    @Override
    protected long read(int fileDescriptor, long address, long length) {
        @Nullable InternetSocket socket = internetSocket(fileDescriptor);
        @Nullable UnixStreamSocket unixSocket = unixStreamSocket(fileDescriptor);
        if (socket == null && unixSocket == null) {
            return super.read(fileDescriptor, address, length);
        }
        if (length < 0 || length > Integer.MAX_VALUE) {
            return EINVAL;
        }
        if (!memory.isBacked(address, length)) {
            return EFAULT;
        }
        byte[] buffer = new byte[(int) length];
        int count;
        if (socket != null) {
            ReceiveResult result = socket.receive(ByteBuffer.wrap(buffer), socketNonblocking(fileDescriptor));
            if (result.error() != 0) {
                return result.error();
            }
            count = result.count();
        } else {
            UnixReceiveResult result = unixSocket.receive(ByteBuffer.wrap(buffer), socketNonblocking(fileDescriptor));
            if (result.error() != 0) {
                return result.error();
            }
            count = result.count();
        }
        if (count > 0) {
            memory.writeBytes(address, buffer, 0, count);
        }
        return count;
    }

    /// Writes bytes to a guest network socket or falls back to generic descriptor writes.
    @Override
    protected long write(int fileDescriptor, long address, long length) {
        @Nullable InternetSocket socket = internetSocket(fileDescriptor);
        @Nullable UnixStreamSocket unixSocket = unixStreamSocket(fileDescriptor);
        if (socket == null && unixSocket == null) {
            return super.write(fileDescriptor, address, length);
        }
        if (length < 0 || length > Integer.MAX_VALUE) {
            return EINVAL;
        }
        if (!memory.isBacked(address, length)) {
            return EFAULT;
        }
        ByteBuffer source = ByteBuffer.wrap(memory.readBytes(address, length));
        return socket != null
                ? socket.send(source, null, socketNonblocking(fileDescriptor))
                : unixSocket.send(source, socketNonblocking(fileDescriptor));
    }

    /// Computes readiness for guest network sockets or falls back to generic descriptor readiness.
    @Override
    protected int readyEventsFor(int fileDescriptor) {
        @Nullable InternetSocket socket = internetSocket(fileDescriptor);
        if (socket != null) {
            return socket.readyEvents();
        }
        @Nullable UnixStreamSocket unixSocket = unixStreamSocket(fileDescriptor);
        return unixSocket == null ? super.readyEventsFor(fileDescriptor) : unixSocket.readyEvents();
    }

    /// Computes readiness for guest network sockets or falls back to generic descriptor readiness.
    @Override
    protected int readyEventsFor(int fileDescriptor, boolean requireImmediateTerminalInput) {
        @Nullable InternetSocket socket = internetSocket(fileDescriptor);
        if (socket != null) {
            return socket.readyEvents();
        }
        @Nullable UnixStreamSocket unixSocket = unixStreamSocket(fileDescriptor);
        return unixSocket == null
                ? super.readyEventsFor(fileDescriptor, requireImmediateTerminalInput)
                : unixSocket.readyEvents();
    }

    /// Returns the Internet socket backing a descriptor, or null when it is not one.
    private @Nullable InternetSocket internetSocket(int fileDescriptor) {
        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null || !openFile.isSocket()) {
            return null;
        }

        GuestSocket socket = openFile.socket();
        return socket instanceof InternetSocket internetSocket ? internetSocket : null;
    }

    /// Returns the Unix-domain stream socket backing a descriptor, or null when it is not one.
    private @Nullable UnixStreamSocket unixStreamSocket(int fileDescriptor) {
        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null || !openFile.isSocket()) {
            return null;
        }

        GuestSocket socket = openFile.socket();
        return socket instanceof UnixStreamSocket unixSocket ? unixSocket : null;
    }

    /// Returns true when a socket descriptor is currently marked nonblocking.
    private boolean socketNonblocking(int fileDescriptor) {
        @Nullable OpenFile openFile = openFile(fileDescriptor);
        return openFile != null && openFile.nonblocking();
    }

    /// Reads one guest IPv4 or IPv6 socket address.
    protected AddressResult readInetSocketAddress(long address, long length) {
        if (address == 0 || length < Short.BYTES || !memory.isBacked(address, Short.BYTES)) {
            return AddressResult.error(EFAULT);
        }

        int family = memory.readUnsignedShort(address + SOCKADDR_FAMILY_OFFSET);
        try {
            if (family == AF_INET) {
                if (length < SOCKADDR_IN_SIZE || !memory.isBacked(address, SOCKADDR_IN_SIZE)) {
                    return AddressResult.error(EFAULT);
                }
                byte[] bytes = memory.readBytes(address + SOCKADDR_IN_ADDRESS_OFFSET, Integer.BYTES);
                return AddressResult.address(new InetSocketAddress(
                        Inet4Address.getByAddress(bytes),
                        readNetworkPort(address + SOCKADDR_PORT_OFFSET)));
            }
            if (family == AF_INET6) {
                if (length < SOCKADDR_IN6_SIZE || !memory.isBacked(address, SOCKADDR_IN6_SIZE)) {
                    return AddressResult.error(EFAULT);
                }
                byte[] bytes = memory.readBytes(address + SOCKADDR_IN6_ADDRESS_OFFSET, 16);
                int scopeId = memory.readInt(address + SOCKADDR_IN6_SCOPE_ID_OFFSET);
                return AddressResult.address(new InetSocketAddress(
                        Inet6Address.getByAddress(null, bytes, scopeId),
                        readNetworkPort(address + SOCKADDR_PORT_OFFSET)));
            }
            return AddressResult.error(EAFNOSUPPORT);
        } catch (UnknownHostException exception) {
            return AddressResult.error(EINVAL);
        }
    }

    /// Reads one guest Unix-domain socket address and maps it through the host filesystem namespace.
    protected UnixAddressResult readUnixSocketAddress(long address, long length) {
        if (address == 0 || length < Short.BYTES || !memory.isBacked(address, Short.BYTES)) {
            return UnixAddressResult.error(EFAULT);
        }
        if (Short.toUnsignedLong(memory.readShort(address + SOCKADDR_FAMILY_OFFSET)) != AF_UNIX) {
            return UnixAddressResult.error(EAFNOSUPPORT);
        }

        long suppliedPathLength = length - SOCKADDR_UN_PATH_OFFSET;
        if (suppliedPathLength <= 0) {
            return UnixAddressResult.error(EINVAL);
        }
        int pathLength = (int) Math.min(suppliedPathLength, SOCKADDR_UN_PATH_SIZE);
        if (!memory.isBacked(address + SOCKADDR_UN_PATH_OFFSET, pathLength)) {
            return UnixAddressResult.error(EFAULT);
        }

        byte[] pathBytes = memory.readBytes(address + SOCKADDR_UN_PATH_OFFSET, pathLength);
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

    /// Writes one host socket address as a guest IPv4 or IPv6 socket address.
    protected long writeInetSocketAddress(
            InetSocketAddress socketAddress,
            int domain,
            long address,
            long lengthAddress) {
        if (lengthAddress != 0 && !memory.isBacked(lengthAddress, Integer.BYTES)) {
            return EFAULT;
        }
        long size = sockaddrSize(domain);
        if (address != 0) {
            if (!memory.isBacked(address, size)) {
                return EFAULT;
            }
            memory.clear(address, size);
            memory.writeShort(address + SOCKADDR_FAMILY_OFFSET, (short) domain);
            writeNetworkPort(address + SOCKADDR_PORT_OFFSET, socketAddress.getPort());
            byte[] bytes = socketAddress.getAddress().getAddress();
            if (domain == AF_INET) {
                if (bytes.length != Integer.BYTES) {
                    return EAFNOSUPPORT;
                }
                memory.writeBytes(address + SOCKADDR_IN_ADDRESS_OFFSET, bytes, 0, bytes.length);
            } else if (domain == AF_INET6) {
                if (bytes.length != 16) {
                    return EAFNOSUPPORT;
                }
                memory.writeBytes(address + SOCKADDR_IN6_ADDRESS_OFFSET, bytes, 0, bytes.length);
                if (socketAddress.getAddress() instanceof Inet6Address inet6Address) {
                    memory.writeInt(address + SOCKADDR_IN6_SCOPE_ID_OFFSET, inet6Address.getScopeId());
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

    /// Writes one guest Unix-domain socket address.
    protected long writeUnixSocketAddress(@Nullable String guestPath, long address, long lengthAddress) {
        if (lengthAddress != 0 && !memory.isBacked(lengthAddress, Integer.BYTES)) {
            return EFAULT;
        }

        byte @Nullable [] pathBytes = guestPath == null ? null : guestPath.getBytes(StandardCharsets.UTF_8);
        if (pathBytes != null && pathBytes.length >= SOCKADDR_UN_PATH_SIZE) {
            return EINVAL;
        }

        long size = unixSockaddrSize(pathBytes);
        if (address != 0) {
            if (!memory.isBacked(address, size)) {
                return EFAULT;
            }
            memory.clear(address, size);
            memory.writeShort(address + SOCKADDR_FAMILY_OFFSET, (short) AF_UNIX);
            if (pathBytes != null && pathBytes.length > 0) {
                memory.writeBytes(address + SOCKADDR_UN_PATH_OFFSET, pathBytes, 0, pathBytes.length);
                memory.writeByte(address + SOCKADDR_UN_PATH_OFFSET + pathBytes.length, (byte) 0);
            }
        }
        if (lengthAddress != 0) {
            memory.writeInt(lengthAddress, (int) size);
        }
        return 0;
    }

    /// Returns the byte size of a guest Unix-domain socket address.
    protected static long unixSockaddrSize(@Nullable String guestPath) {
        return unixSockaddrSize(guestPath == null ? null : guestPath.getBytes(StandardCharsets.UTF_8));
    }

    /// Returns the byte size of a guest Unix-domain socket address.
    protected static long unixSockaddrSize(byte @Nullable [] pathBytes) {
        return pathBytes == null || pathBytes.length == 0
                ? SOCKADDR_UN_PATH_OFFSET
                : SOCKADDR_UN_PATH_OFFSET + pathBytes.length + 1L;
    }

    /// Writes a wildcard socket address for an unbound guest Internet socket.
    private long writeWildcardInetSocketAddress(int domain, long address, long lengthAddress) {
        try {
            return writeInetSocketAddress(new InetSocketAddress(wildcardAddress(domain), 0), domain, address, lengthAddress);
        } catch (UnknownHostException exception) {
            return EAFNOSUPPORT;
        }
    }

    /// Returns the byte size of the guest socket address for one Internet address family.
    protected static long sockaddrSize(int domain) {
        return domain == AF_INET6 ? SOCKADDR_IN6_SIZE : SOCKADDR_IN_SIZE;
    }

    /// Reads a network-endian port field from guest memory.
    protected int readNetworkPort(long address) {
        return (memory.readUnsignedByte(address) << Byte.SIZE) | memory.readUnsignedByte(address + 1);
    }

    /// Writes a network-endian port field to guest memory.
    protected void writeNetworkPort(long address, int port) {
        memory.writeByte(address, (byte) (port >>> Byte.SIZE));
        memory.writeByte(address + 1, (byte) port);
    }

    /// Returns the host wildcard address for a guest Internet address family.
    private static InetAddress wildcardAddress(int domain) throws UnknownHostException {
        return InetAddress.getByAddress(new byte[domain == AF_INET6 ? 16 : 4]);
    }

    /// Converts one guest Internet address family to a host protocol family.
    private static ProtocolFamily protocolFamily(int domain) {
        return domain == AF_INET6 ? StandardProtocolFamily.INET6 : StandardProtocolFamily.INET;
    }

    /// Waits until a nonblocking host channel is ready for the requested operation.
    private static long waitReady(SelectableChannel channel, int operations) {
        try (Selector selector = Selector.open()) {
            channel.register(selector, operations);
            while (selector.select() == 0) {
                Thread.onSpinWait();
            }
            return 0;
        } catch (ClosedChannelException exception) {
            return ENOTCONN;
        } catch (IOException exception) {
            return networkException(exception);
        }
    }

    /// Returns true when a nonblocking host channel is currently ready for the requested operation.
    private static boolean readyNow(SelectableChannel channel, int operations) {
        try (Selector selector = Selector.open()) {
            channel.register(selector, operations);
            return selector.selectNow() > 0;
        } catch (IOException exception) {
            return false;
        }
    }

    /// Converts one host network exception into a raw negative Linux errno.
    private static long networkException(IOException exception) {
        if (exception instanceof NoSuchFileException) {
            return ENOENT;
        }
        if (exception instanceof AccessDeniedException) {
            return EACCES;
        }
        if (exception instanceof BindException) {
            return EADDRINUSE;
        }
        if (exception instanceof ConnectException) {
            return ECONNREFUSED;
        }
        if (exception instanceof NoRouteToHostException) {
            return ENETUNREACH;
        }
        if (exception instanceof SocketTimeoutException) {
            return ETIMEDOUT;
        }
        if (exception instanceof ProtocolException) {
            return EPROTONOSUPPORT;
        }
        if (exception instanceof SocketException && exception.getMessage() != null) {
            String message = exception.getMessage().toLowerCase(java.util.Locale.ROOT);
            if (message.contains("reset")) {
                return ECONNRESET;
            }
            if (message.contains("no such file")) {
                return ENOENT;
            }
            if (message.contains("permission denied")) {
                return EACCES;
            }
        }
        return EINVAL;
    }

    /// Stores the result of reading a guest socket address.
    ///
    /// @param address the decoded host socket address
    /// @param error the raw negative Linux error, or zero on success
    protected record AddressResult(@Nullable InetSocketAddress address, long error) {
        /// Creates a successful address result.
        static AddressResult address(InetSocketAddress address) {
            return new AddressResult(address, 0);
        }

        /// Creates a failed address result.
        static AddressResult error(long error) {
            return new AddressResult(null, error);
        }
    }

    /// Stores the result of reading a guest Unix-domain socket address.
    ///
    /// @param address the decoded guest-to-host Unix-domain socket address
    /// @param error the raw negative Linux error, or zero on success
    protected record UnixAddressResult(@Nullable UnixSocketAddress address, long error) {
        /// Creates a successful address result.
        static UnixAddressResult address(UnixSocketAddress address) {
            return new UnixAddressResult(address, 0);
        }

        /// Creates a failed address result.
        static UnixAddressResult error(long error) {
            return new UnixAddressResult(null, error);
        }
    }

    /// Stores a guest-visible Unix path and the corresponding host socket address.
    ///
    /// @param guestPath the normalized guest path supplied to `connect`
    /// @param hostAddress the host Unix-domain socket address reached through a bind mount
    protected record UnixSocketAddress(String guestPath, UnixDomainSocketAddress hostAddress) {
    }

    /// Stores the result of receiving bytes from a guest Internet socket.
    ///
    /// @param count the number of received bytes
    /// @param address the source address, or null when not available
    /// @param error the raw negative Linux error, or zero on success
    private record ReceiveResult(int count, @Nullable InetSocketAddress address, long error) {
        /// Creates a successful receive result.
        static ReceiveResult success(int count, @Nullable InetSocketAddress address) {
            return new ReceiveResult(count, address, 0);
        }

        /// Creates a failed receive result.
        static ReceiveResult error(long error) {
            return new ReceiveResult(0, null, error);
        }
    }

    /// Stores the result of receiving bytes from a guest Unix-domain stream socket.
    ///
    /// @param count the number of received bytes
    /// @param address the peer guest path, or null when not available
    /// @param error the raw negative Linux error, or zero on success
    private record UnixReceiveResult(int count, @Nullable String address, long error) {
        /// Creates a successful receive result.
        static UnixReceiveResult success(int count, @Nullable String address) {
            return new UnixReceiveResult(count, address, 0);
        }

        /// Creates a failed receive result.
        static UnixReceiveResult error(long error) {
            return new UnixReceiveResult(0, null, error);
        }
    }

    /// Stores the result of accepting one stream socket connection.
    ///
    /// @param socket the accepted socket, or null on failure
    /// @param address the accepted peer address, or null when not available
    /// @param error the raw negative Linux error, or zero on success
    private record AcceptResult(
            @Nullable InternetSocket socket,
            @Nullable InetSocketAddress address,
            long error) {
        /// Creates a successful accept result.
        static AcceptResult success(InternetSocket socket, @Nullable InetSocketAddress address) {
            return new AcceptResult(socket, address, 0);
        }

        /// Creates a failed accept result.
        static AcceptResult error(long error) {
            return new AcceptResult(null, null, error);
        }
    }

    /// Stores the value returned by `getsockopt`.
    ///
    /// @param value the integer option value
    /// @param error the raw negative Linux error, or zero on success
    private record OptionResult(int value, long error) {
        /// Creates a successful option result.
        static OptionResult value(int value) {
            return new OptionResult(value, 0);
        }

        /// Creates a failed option result.
        static OptionResult error(long error) {
            return new OptionResult(0, error);
        }
    }

    /// Guest Unix-domain stream socket behavior shared by host-backed and local-pair sockets.
    private abstract class UnixStreamSocket implements GuestSocket {
        /// Connects the socket to a Unix-domain peer.
        abstract long connect(@Nullable UnixSocketAddress address, boolean nonblocking);

        /// Sends bytes to the connected peer.
        abstract long send(ByteBuffer source, boolean nonblocking);

        /// Receives bytes from the connected peer.
        abstract UnixReceiveResult receive(ByteBuffer target, boolean nonblocking);

        /// Returns the bound local guest path, or null for unnamed sockets.
        abstract @Nullable String localPath();

        /// Returns the connected peer guest path, or null when not connected or unnamed.
        abstract @Nullable String peerPath();

        /// Sets one supported Unix-domain socket option.
        abstract long setOption(long level, long option, int value);

        /// Gets one supported Unix-domain socket option.
        abstract OptionResult getOption(long level, long option);

        /// Shuts down one or both stream socket directions.
        abstract long shutdown(long how);

        /// Computes readiness events for poll and epoll.
        abstract int readyEvents();
    }

    /// Host-backed guest Unix-domain stream socket.
    private final class HostUnixStreamSocket extends UnixStreamSocket {
        /// The host Unix-domain stream channel.
        private final SocketChannel channel;

        /// The connected peer path in the guest namespace, or null when not connected.
        private @Nullable String peerPath;

        /// The configured send buffer size, or zero when not explicitly configured.
        private int sendBufferSize;

        /// The configured receive buffer size, or zero when not explicitly configured.
        private int receiveBufferSize;

        /// The pending socket error reported by `SO_ERROR`.
        private int socketError;

        /// Whether the read side has been shut down.
        private boolean readShutdown;

        /// Whether the write side has been shut down.
        private boolean writeShutdown;

        /// Creates an unconnected host-backed Unix-domain stream socket.
        HostUnixStreamSocket() throws IOException {
            channel = networkBackend.openUnixSocketChannel();
        }

        /// Connects the socket to a host Unix-domain socket reached through the guest namespace.
        long connect(@Nullable UnixSocketAddress address, boolean nonblocking) {
            if (address == null) {
                return EFAULT;
            }
            try {
                if (channel.isConnectionPending()) {
                    return nonblocking ? EALREADY : finishConnectBlocking();
                }
                if (channel.isConnected()) {
                    return EISCONN;
                }

                boolean connected = channel.connect(address.hostAddress());
                peerPath = address.guestPath();
                if (connected) {
                    return 0;
                }
                if (nonblocking) {
                    return EINPROGRESS;
                }
                return finishConnectBlocking();
            } catch (AlreadyConnectedException exception) {
                return EISCONN;
            } catch (ConnectionPendingException exception) {
                return EALREADY;
            } catch (IOException exception) {
                long error = networkException(exception);
                recordSocketError(error);
                return error;
            } catch (UnsupportedOperationException | UnresolvedAddressException exception) {
                return EADDRNOTAVAIL;
            }
        }

        /// Sends bytes to the connected peer.
        long send(ByteBuffer source, boolean nonblocking) {
            if (!source.hasRemaining()) {
                return 0;
            }
            if (writeShutdown) {
                return EPIPE;
            }
            try {
                SocketChannel connectedChannel = connectedChannel();
                int count = connectedChannel.write(source);
                if (count == 0 && !nonblocking) {
                    long ready = waitReady(connectedChannel, SelectionKey.OP_WRITE);
                    if (ready != 0) {
                        return ready;
                    }
                    count = connectedChannel.write(source);
                }
                return count == 0 ? EAGAIN : count;
            } catch (NotYetConnectedException exception) {
                return ENOTCONN;
            } catch (IOException exception) {
                return networkException(exception);
            }
        }

        /// Receives bytes from the connected peer.
        UnixReceiveResult receive(ByteBuffer target, boolean nonblocking) {
            if (!target.hasRemaining()) {
                return UnixReceiveResult.success(0, null);
            }
            if (readShutdown) {
                return UnixReceiveResult.success(0, peerPath);
            }
            try {
                SocketChannel connectedChannel = connectedChannel();
                int count = connectedChannel.read(target);
                if (count == 0 && !nonblocking) {
                    long ready = waitReady(connectedChannel, SelectionKey.OP_READ);
                    if (ready != 0) {
                        return UnixReceiveResult.error(ready);
                    }
                    count = connectedChannel.read(target);
                }
                return count < 0
                        ? UnixReceiveResult.success(0, peerPath)
                        : count == 0 ? UnixReceiveResult.error(EAGAIN) : UnixReceiveResult.success(count, peerPath);
            } catch (NotYetConnectedException exception) {
                return UnixReceiveResult.error(ENOTCONN);
            } catch (IOException exception) {
                return UnixReceiveResult.error(networkException(exception));
            }
        }

        /// Returns the bound local guest path, or null for unnamed client sockets.
        @Nullable String localPath() {
            return null;
        }

        /// Returns the connected peer guest path, or null when not connected.
        @Nullable String peerPath() {
            return channel.isConnected() ? peerPath : null;
        }

        /// Sets one supported Unix-domain socket option.
        long setOption(long level, long option, int value) {
            if (level != SOL_SOCKET) {
                return ENOPROTOOPT;
            }
            try {
                if (option == SO_SNDBUF) {
                    if (value <= 0) {
                        return EINVAL;
                    }
                    sendBufferSize = value;
                    channel.setOption(StandardSocketOptions.SO_SNDBUF, value);
                    return 0;
                }
                if (option == SO_RCVBUF) {
                    if (value <= 0) {
                        return EINVAL;
                    }
                    receiveBufferSize = value;
                    channel.setOption(StandardSocketOptions.SO_RCVBUF, value);
                    return 0;
                }
                return ENOPROTOOPT;
            } catch (IOException exception) {
                return networkException(exception);
            } catch (UnsupportedOperationException exception) {
                return ENOPROTOOPT;
            }
        }

        /// Gets one supported Unix-domain socket option.
        OptionResult getOption(long level, long option) {
            if (level != SOL_SOCKET) {
                return OptionResult.error(ENOPROTOOPT);
            }
            try {
                if (option == SO_SNDBUF) {
                    return OptionResult.value(integerOption(StandardSocketOptions.SO_SNDBUF, sendBufferSize));
                }
                if (option == SO_RCVBUF) {
                    return OptionResult.value(integerOption(StandardSocketOptions.SO_RCVBUF, receiveBufferSize));
                }
                if (option == SO_ERROR) {
                    if (channel.isConnectionPending()) {
                        long result = finishConnectIfReady();
                        if (result < 0 && result != EINPROGRESS) {
                            recordSocketError(result);
                        }
                    }
                    int result = socketError;
                    socketError = 0;
                    return OptionResult.value(result);
                }
                return OptionResult.error(ENOPROTOOPT);
            } catch (IOException exception) {
                return OptionResult.error(networkException(exception));
            } catch (UnsupportedOperationException exception) {
                return OptionResult.error(ENOPROTOOPT);
            }
        }

        /// Shuts down one or both stream socket directions.
        long shutdown(long how) {
            if (!channel.isConnected()) {
                return ENOTCONN;
            }
            if (how < SHUT_RD || how > SHUT_RDWR) {
                return EINVAL;
            }
            try {
                if (how == SHUT_RD || how == SHUT_RDWR) {
                    channel.shutdownInput();
                    readShutdown = true;
                }
                if (how == SHUT_WR || how == SHUT_RDWR) {
                    channel.shutdownOutput();
                    writeShutdown = true;
                }
                return 0;
            } catch (IOException exception) {
                return networkException(exception);
            }
        }

        /// Computes readiness events for poll and epoll.
        int readyEvents() {
            int events = 0;
            if (channel.isConnectionPending()) {
                return readyNow(channel, SelectionKey.OP_CONNECT) ? EPOLLOUT : 0;
            }
            if (!channel.isConnected()) {
                return EPOLLOUT;
            }
            if (!readShutdown && readyNow(channel, SelectionKey.OP_READ)) {
                events |= EPOLLIN;
            }
            if (!writeShutdown && readyNow(channel, SelectionKey.OP_WRITE)) {
                events |= EPOLLOUT;
            }
            return events;
        }

        /// Releases the host Unix-domain stream channel.
        @Override
        public void close() throws IOException {
            channel.close();
        }

        /// Returns the connected stream channel or throws a Linux-like Java exception.
        private SocketChannel connectedChannel() throws IOException {
            if (channel.isConnectionPending()) {
                long result = finishConnectIfReady();
                if (result != 0) {
                    throw new NotYetConnectedException();
                }
            }
            if (!channel.isConnected()) {
                throw new NotYetConnectedException();
            }
            return channel;
        }

        /// Completes a pending connect, blocking when necessary.
        private long finishConnectBlocking() throws IOException {
            long ready = waitReady(channel, SelectionKey.OP_CONNECT);
            if (ready != 0) {
                return ready;
            }
            return finishConnect();
        }

        /// Completes a pending connect when the host reports it is ready.
        private long finishConnectIfReady() throws IOException {
            if (!channel.isConnectionPending()) {
                return channel.isConnected() ? 0 : ENOTCONN;
            }
            if (!readyNow(channel, SelectionKey.OP_CONNECT)) {
                return EINPROGRESS;
            }
            return finishConnect();
        }

        /// Completes a pending connect now.
        private long finishConnect() throws IOException {
            try {
                return channel.finishConnect() ? 0 : EINPROGRESS;
            } catch (NoConnectionPendingException exception) {
                return channel.isConnected() ? 0 : ENOTCONN;
            } catch (IOException exception) {
                long error = networkException(exception);
                recordSocketError(error);
                return error;
            }
        }

        /// Gets an integer option from the open channel or returns the cached value.
        private int integerOption(java.net.SocketOption<Integer> option, int cachedValue) throws IOException {
            @Nullable Integer value = channel.getOption(option);
            return value == null ? cachedValue : value;
        }

        /// Stores a socket error for later `SO_ERROR` retrieval.
        private void recordSocketError(long error) {
            if (error < 0) {
                socketError = (int) -error;
            }
        }
    }

    /// In-memory Unix-domain stream socket returned by `socketpair`.
    private final class LocalUnixStreamSocket extends UnixStreamSocket {
        /// Bytes written by the peer and read by this socket.
        private final PipeBuffer inbound;

        /// Bytes written by this socket and read by the peer.
        private final PipeBuffer outbound;

        /// The configured send buffer size, or zero when not explicitly configured.
        private int sendBufferSize;

        /// The configured receive buffer size, or zero when not explicitly configured.
        private int receiveBufferSize;

        /// Whether the read side has been shut down.
        private boolean readShutdown;

        /// Whether the write side has been shut down.
        private boolean writeShutdown;

        /// Creates one connected end of a Unix-domain socket pair.
        LocalUnixStreamSocket(PipeBuffer inbound, PipeBuffer outbound) {
            this.inbound = inbound;
            this.outbound = outbound;
        }

        /// Reports that socket-pair endpoints are already connected.
        @Override
        long connect(@Nullable UnixSocketAddress address, boolean nonblocking) {
            return EISCONN;
        }

        /// Sends bytes to the paired endpoint.
        @Override
        long send(ByteBuffer source, boolean nonblocking) {
            if (!source.hasRemaining()) {
                return 0;
            }
            if (writeShutdown) {
                return EPIPE;
            }
            byte[] bytes = new byte[source.remaining()];
            source.get(bytes);
            return outbound.write(bytes);
        }

        /// Receives bytes from the paired endpoint.
        @Override
        UnixReceiveResult receive(ByteBuffer target, boolean nonblocking) {
            if (!target.hasRemaining()) {
                return UnixReceiveResult.success(0, "");
            }
            if (readShutdown) {
                return UnixReceiveResult.success(0, "");
            }
            byte[] bytes = new byte[target.remaining()];
            try {
                int count = inbound.read(bytes, bytes.length, nonblocking);
                if (count < 0) {
                    return UnixReceiveResult.error(count);
                }
                target.put(bytes, 0, count);
                return UnixReceiveResult.success(count, "");
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                return UnixReceiveResult.error(EINTR);
            }
        }

        /// Returns the unnamed local socket-pair address.
        @Override
        @Nullable String localPath() {
            return "";
        }

        /// Returns the unnamed peer socket-pair address.
        @Override
        @Nullable String peerPath() {
            return "";
        }

        /// Sets one supported in-memory Unix-domain socket option.
        @Override
        long setOption(long level, long option, int value) {
            if (level != SOL_SOCKET) {
                return ENOPROTOOPT;
            }
            if (option == SO_SNDBUF) {
                if (value <= 0) {
                    return EINVAL;
                }
                sendBufferSize = value;
                return 0;
            }
            if (option == SO_RCVBUF) {
                if (value <= 0) {
                    return EINVAL;
                }
                receiveBufferSize = value;
                return 0;
            }
            return ENOPROTOOPT;
        }

        /// Gets one supported in-memory Unix-domain socket option.
        @Override
        OptionResult getOption(long level, long option) {
            if (level != SOL_SOCKET) {
                return OptionResult.error(ENOPROTOOPT);
            }
            if (option == SO_SNDBUF) {
                return OptionResult.value(sendBufferSize);
            }
            if (option == SO_RCVBUF) {
                return OptionResult.value(receiveBufferSize);
            }
            if (option == SO_ERROR) {
                return OptionResult.value(0);
            }
            return OptionResult.error(ENOPROTOOPT);
        }

        /// Shuts down one or both stream socket directions.
        @Override
        long shutdown(long how) {
            if (how < SHUT_RD || how > SHUT_RDWR) {
                return EINVAL;
            }
            if (how == SHUT_RD || how == SHUT_RDWR) {
                inbound.closeReader();
                readShutdown = true;
            }
            if (how == SHUT_WR || how == SHUT_RDWR) {
                outbound.closeWriter();
                writeShutdown = true;
            }
            return 0;
        }

        /// Computes readiness events for poll and epoll.
        @Override
        int readyEvents() {
            int events = 0;
            if (!readShutdown && inbound.isReadable()) {
                events |= EPOLLIN;
            }
            if (!writeShutdown && outbound.isReaderOpen()) {
                events |= EPOLLOUT;
            }
            if (!inbound.isWriterOpen() || !outbound.isReaderOpen()) {
                events |= EPOLLHUP;
            }
            return events;
        }

        /// Releases this socket-pair endpoint.
        @Override
        public void close() {
            shutdown(SHUT_RDWR);
        }
    }

    /// Host-backed guest IPv4 or IPv6 socket.
    private final class InternetSocket implements GuestSocket {
        /// The Linux Internet address family.
        private final int domain;

        /// The Linux socket type.
        private final int socketType;

        /// The Linux protocol number.
        private final int protocol;

        /// The selector registered before host readiness transitions can occur.
        private final Selector readinessSelector;

        /// The TCP client channel, or null for datagram and listening sockets.
        private @Nullable SocketChannel streamChannel;

        /// The TCP server channel, or null for datagram and connected stream sockets.
        private @Nullable ServerSocketChannel serverChannel;

        /// The UDP channel, or null for stream sockets.
        private @Nullable DatagramChannel datagramChannel;

        /// The address requested by `bind`, or null until bound.
        private @Nullable InetSocketAddress boundAddress;

        /// The connected remote peer, or null when not connected.
        private @Nullable InetSocketAddress peerAddress;

        /// Whether this stream socket is a listening server.
        private boolean listening;

        /// Whether `SO_REUSEADDR` is enabled.
        private boolean reuseAddress;

        /// Whether `SO_REUSEPORT` is enabled.
        private boolean reusePort;

        /// Whether `SO_KEEPALIVE` is enabled.
        private boolean keepAlive;

        /// Whether `SO_BROADCAST` is enabled.
        private boolean broadcast;

        /// Whether `TCP_NODELAY` is enabled.
        private boolean tcpNoDelay;

        /// Whether `IP_RECVERR` is enabled.
        private boolean ipReceiveErrors;

        /// Whether `IPV6_RECVERR` is enabled.
        private boolean ipv6ReceiveErrors;

        /// Whether `IPV6_V6ONLY` is enabled.
        private boolean ipv6Only;

        /// The configured send buffer size, or zero when not explicitly configured.
        private int sendBufferSize;

        /// The configured receive buffer size, or zero when not explicitly configured.
        private int receiveBufferSize;

        /// The pending socket error reported by `SO_ERROR`.
        private int socketError;

        /// Whether the read side has been shut down.
        private boolean readShutdown;

        /// Whether the write side has been shut down.
        private boolean writeShutdown;

        /// Creates an unbound host-backed Internet socket.
        InternetSocket(int domain, int socketType, long protocol) throws IOException {
            this.domain = domain;
            this.socketType = socketType;
            this.protocol = protocol == 0
                    ? (socketType == SOCK_STREAM ? (int) IPPROTO_TCP : (int) IPPROTO_UDP)
                    : (int) protocol;
            readinessSelector = Selector.open();
            if (socketType == SOCK_DGRAM) {
                datagramChannel = networkBackend.openDatagramChannel(protocolFamily(domain));
                registerReadinessChannel(datagramChannel);
            }
        }

        /// Creates a connected stream socket returned by `accept`.
        InternetSocket(InternetSocket server, SocketChannel acceptedChannel) throws IOException {
            domain = server.domain;
            socketType = (int) SOCK_STREAM;
            protocol = (int) IPPROTO_TCP;
            readinessSelector = Selector.open();
            streamChannel = acceptedChannel;
            streamChannel.configureBlocking(false);
            registerReadinessChannel(streamChannel);
            boundAddress = socketAddress(streamChannel.getLocalAddress());
            peerAddress = socketAddress(streamChannel.getRemoteAddress());
            reuseAddress = server.reuseAddress;
            reusePort = server.reusePort;
            keepAlive = server.keepAlive;
            tcpNoDelay = server.tcpNoDelay;
            ipReceiveErrors = server.ipReceiveErrors;
            ipv6ReceiveErrors = server.ipv6ReceiveErrors;
            ipv6Only = server.ipv6Only;
            sendBufferSize = server.sendBufferSize;
            receiveBufferSize = server.receiveBufferSize;
            applyOptions(streamChannel);
        }

        /// Returns the Linux Internet address family.
        int domain() {
            return domain;
        }

        /// Binds the socket to a local host address.
        long bind(@Nullable InetSocketAddress address) {
            if (address == null) {
                return EFAULT;
            }
            try {
                if (socketType == SOCK_DGRAM) {
                    DatagramChannel channel = datagramChannel();
                    applyOptions(channel);
                    channel.bind(address);
                    boundAddress = socketAddress(channel.getLocalAddress());
                    return 0;
                }

                if (streamChannel != null || serverChannel != null) {
                    return EINVAL;
                }
                streamChannel = networkBackend.openSocketChannel(protocolFamily(domain));
                applyOptions(streamChannel);
                registerReadinessChannel(streamChannel);
                streamChannel.bind(address);
                boundAddress = socketAddress(streamChannel.getLocalAddress());
                return 0;
            } catch (IOException exception) {
                return networkException(exception);
            } catch (UnsupportedOperationException | UnresolvedAddressException exception) {
                return EADDRNOTAVAIL;
            }
        }

        /// Connects the socket to a remote host address.
        long connect(@Nullable InetSocketAddress address, boolean nonblocking) {
            if (address == null) {
                return EFAULT;
            }
            try {
                if (socketType == SOCK_DGRAM) {
                    DatagramChannel channel = datagramChannel();
                    channel.connect(address);
                    boundAddress = socketAddress(channel.getLocalAddress());
                    peerAddress = address;
                    return 0;
                }

                if (serverChannel != null) {
                    return ENOTSUP;
                }
                SocketChannel channel = streamChannel();
                if (channel.isConnectionPending()) {
                    return nonblocking ? EALREADY : finishConnectBlocking(channel);
                }
                if (channel.isConnected()) {
                    return EISCONN;
                }

                boolean connected = channel.connect(address);
                peerAddress = address;
                if (connected) {
                    boundAddress = socketAddress(channel.getLocalAddress());
                    return 0;
                }
                if (nonblocking) {
                    return EINPROGRESS;
                }
                return finishConnectBlocking(channel);
            } catch (AlreadyConnectedException exception) {
                return EISCONN;
            } catch (ConnectionPendingException exception) {
                return EALREADY;
            } catch (IOException exception) {
                long error = networkException(exception);
                recordSocketError(error);
                return error;
            } catch (UnsupportedOperationException | UnresolvedAddressException exception) {
                return EADDRNOTAVAIL;
            }
        }

        /// Marks a stream socket as listening.
        long listen(int backlog) {
            if (socketType != SOCK_STREAM) {
                return ENOTSUP;
            }
            if (streamChannel != null && (streamChannel.isConnected()
                    || streamChannel.isConnectionPending()
                    || boundAddress == null)) {
                return EINVAL;
            }
            try {
                if (serverChannel == null) {
                    @Nullable InetSocketAddress listenAddress = boundAddress;
                    if (streamChannel != null) {
                        unregisterReadinessChannel(streamChannel);
                        streamChannel.close();
                        streamChannel = null;
                    }
                    serverChannel = networkBackend.openServerSocketChannel(protocolFamily(domain));
                    applyOptions(serverChannel);
                    registerReadinessChannel(serverChannel);
                    serverChannel.bind(
                            listenAddress == null ? new InetSocketAddress(wildcardAddress(domain), 0) : listenAddress,
                            backlog);
                    boundAddress = socketAddress(serverChannel.getLocalAddress());
                }
                listening = true;
                return 0;
            } catch (IOException exception) {
                return networkException(exception);
            }
        }

        /// Accepts one pending stream connection.
        AcceptResult accept(boolean nonblocking, boolean acceptedNonblocking) {
            if (socketType != SOCK_STREAM || !listening || serverChannel == null) {
                return AcceptResult.error(EINVAL);
            }
            try {
                SocketChannel accepted = serverChannel.accept();
                if (accepted == null) {
                    if (nonblocking) {
                        return AcceptResult.error(EAGAIN);
                    }
                    long ready = waitReady(serverChannel, SelectionKey.OP_ACCEPT);
                    if (ready != 0) {
                        return AcceptResult.error(ready);
                    }
                    accepted = serverChannel.accept();
                    if (accepted == null) {
                        return AcceptResult.error(EAGAIN);
                    }
                }
                InternetSocket socket = new InternetSocket(this, accepted);
                return AcceptResult.success(socket, socket.peerAddress);
            } catch (IOException exception) {
                return AcceptResult.error(networkException(exception));
            }
        }

        /// Sends bytes to the connected peer or supplied datagram destination.
        long send(ByteBuffer source, @Nullable InetSocketAddress destination, boolean nonblocking) {
            if (!source.hasRemaining()) {
                return 0;
            }
            if (writeShutdown) {
                return EPIPE;
            }
            try {
                if (socketType == SOCK_DGRAM) {
                    DatagramChannel channel = datagramChannel();
                    int count;
                    if (destination != null) {
                        count = channel.send(source, destination);
                    } else {
                        if (!channel.isConnected()) {
                            return EDESTADDRREQ;
                        }
                        count = channel.write(source);
                    }
                    if (count == 0 && !nonblocking) {
                        long ready = waitReady(channel, SelectionKey.OP_WRITE);
                        if (ready != 0) {
                            return ready;
                        }
                        count = destination == null ? channel.write(source) : channel.send(source, destination);
                    }
                    return count == 0 ? EAGAIN : count;
                }

                SocketChannel channel = connectedStreamChannel();
                if (destination != null) {
                    return EISCONN;
                }
                int count = channel.write(source);
                if (count == 0 && !nonblocking) {
                    long ready = waitReady(channel, SelectionKey.OP_WRITE);
                    if (ready != 0) {
                        return ready;
                    }
                    count = channel.write(source);
                }
                return count == 0 ? EAGAIN : count;
            } catch (NotYetConnectedException exception) {
                return ENOTCONN;
            } catch (IOException exception) {
                return networkException(exception);
            }
        }

        /// Receives bytes from a connected stream or datagram socket.
        ReceiveResult receive(ByteBuffer target, boolean nonblocking) {
            if (!target.hasRemaining()) {
                return ReceiveResult.success(0, null);
            }
            if (readShutdown) {
                return ReceiveResult.success(0, peerAddress);
            }
            try {
                if (socketType == SOCK_DGRAM) {
                    DatagramChannel channel = datagramChannel();
                    SocketAddress source = channel.receive(target);
                    if (source == null && !nonblocking) {
                        long ready = waitReady(channel, SelectionKey.OP_READ);
                        if (ready != 0) {
                            return ReceiveResult.error(ready);
                        }
                        source = channel.receive(target);
                    }
                    if (source == null) {
                        return ReceiveResult.error(EAGAIN);
                    }
                    return ReceiveResult.success(target.position(), socketAddress(source));
                }

                SocketChannel channel = connectedStreamChannel();
                int count = channel.read(target);
                if (count == 0 && !nonblocking) {
                    long ready = waitReady(channel, SelectionKey.OP_READ);
                    if (ready != 0) {
                        return ReceiveResult.error(ready);
                    }
                    count = channel.read(target);
                }
                return count < 0
                        ? ReceiveResult.success(0, peerAddress)
                        : count == 0 ? ReceiveResult.error(EAGAIN) : ReceiveResult.success(count, peerAddress);
            } catch (NotYetConnectedException exception) {
                return ReceiveResult.error(ENOTCONN);
            } catch (IOException exception) {
                return ReceiveResult.error(networkException(exception));
            }
        }

        /// Returns the bound local address, or null when unbound.
        @Nullable InetSocketAddress localAddress() {
            try {
                if (socketType == SOCK_DGRAM) {
                    return socketAddress(datagramChannel().getLocalAddress());
                }
                if (streamChannel != null) {
                    return socketAddress(streamChannel.getLocalAddress());
                }
                if (serverChannel != null) {
                    return socketAddress(serverChannel.getLocalAddress());
                }
                return boundAddress;
            } catch (IOException exception) {
                return boundAddress;
            }
        }

        /// Returns the connected peer address, or null when not connected.
        @Nullable InetSocketAddress peerAddress() {
            try {
                if (socketType == SOCK_DGRAM && datagramChannel != null && datagramChannel.isConnected()) {
                    return socketAddress(datagramChannel.getRemoteAddress());
                }
                if (streamChannel != null && streamChannel.isConnected()) {
                    return socketAddress(streamChannel.getRemoteAddress());
                }
            } catch (IOException exception) {
                return peerAddress;
            }
            return peerAddress;
        }

        /// Sets one supported socket option.
        long setOption(long level, long option, int value) {
            try {
                if (level == SOL_SOCKET) {
                    return setSocketOption(option, value);
                }
                if (level == IPPROTO_TCP && option == TCP_NODELAY && socketType == SOCK_STREAM) {
                    tcpNoDelay = value != 0;
                    return setBooleanOption(StandardSocketOptions.TCP_NODELAY, tcpNoDelay);
                }
                if (level == IPPROTO_IP && option == IP_RECVERR && domain == AF_INET) {
                    ipReceiveErrors = value != 0;
                    return 0;
                }
                if (level == IPPROTO_IPV6 && option == IPV6_RECVERR && domain == AF_INET6) {
                    ipv6ReceiveErrors = value != 0;
                    return 0;
                }
                if (level == IPPROTO_IPV6 && option == IPV6_V6ONLY && domain == AF_INET6) {
                    ipv6Only = value != 0;
                    return 0;
                }
                return ENOPROTOOPT;
            } catch (IOException exception) {
                return networkException(exception);
            } catch (UnsupportedOperationException exception) {
                return ENOPROTOOPT;
            }
        }

        /// Gets one supported socket option.
        OptionResult getOption(long level, long option) {
            try {
                if (level == SOL_SOCKET) {
                    return getSocketOption(option);
                }
                if (level == IPPROTO_TCP && option == TCP_NODELAY && socketType == SOCK_STREAM) {
                    return OptionResult.value(booleanOption(StandardSocketOptions.TCP_NODELAY, tcpNoDelay) ? 1 : 0);
                }
                if (level == IPPROTO_IP && option == IP_RECVERR && domain == AF_INET) {
                    return OptionResult.value(ipReceiveErrors ? 1 : 0);
                }
                if (level == IPPROTO_IPV6 && option == IPV6_RECVERR && domain == AF_INET6) {
                    return OptionResult.value(ipv6ReceiveErrors ? 1 : 0);
                }
                if (level == IPPROTO_IPV6 && option == IPV6_V6ONLY && domain == AF_INET6) {
                    return OptionResult.value(ipv6Only ? 1 : 0);
                }
                return OptionResult.error(ENOPROTOOPT);
            } catch (IOException exception) {
                return OptionResult.error(networkException(exception));
            } catch (UnsupportedOperationException exception) {
                return OptionResult.error(ENOPROTOOPT);
            }
        }

        /// Shuts down one or both stream socket directions.
        long shutdown(long how) {
            if (socketType != SOCK_STREAM || streamChannel == null || !streamChannel.isConnected()) {
                return ENOTCONN;
            }
            if (how < SHUT_RD || how > SHUT_RDWR) {
                return EINVAL;
            }
            try {
                if (how == SHUT_RD || how == SHUT_RDWR) {
                    streamChannel.shutdownInput();
                    readShutdown = true;
                }
                if (how == SHUT_WR || how == SHUT_RDWR) {
                    streamChannel.shutdownOutput();
                    writeShutdown = true;
                }
                return 0;
            } catch (IOException exception) {
                return networkException(exception);
            }
        }

        /// Computes readiness events for poll and epoll.
        int readyEvents() {
            int events = 0;
            if (socketType == SOCK_DGRAM) {
                DatagramChannel channel = datagramChannel();
                int readyOperations = readyOperations(channel);
                if ((readyOperations & SelectionKey.OP_READ) != 0) {
                    events |= EPOLLIN;
                }
                events |= EPOLLOUT;
                return events;
            }
            if (serverChannel != null && listening) {
                return (readyOperations(serverChannel) & SelectionKey.OP_ACCEPT) != 0 ? EPOLLIN : 0;
            }
            if (streamChannel == null) {
                return EPOLLOUT;
            }
            if (streamChannel.isConnectionPending()) {
                return (readyOperations(streamChannel) & SelectionKey.OP_CONNECT) != 0 ? EPOLLOUT : 0;
            }
            if (!streamChannel.isConnected()) {
                return EPOLLHUP;
            }
            int readyOperations = readyOperations(streamChannel);
            if (!readShutdown && (readyOperations & SelectionKey.OP_READ) != 0) {
                events |= EPOLLIN;
            }
            if (!writeShutdown && (readyOperations & SelectionKey.OP_WRITE) != 0) {
                events |= EPOLLOUT;
            }
            return events;
        }

        /// Releases host network channels.
        @Override
        public void close() throws IOException {
            IOException failure = null;
            synchronized (readinessSelector) {
                failure = closeChannel(streamChannel, failure);
                failure = closeChannel(serverChannel, failure);
                failure = closeChannel(datagramChannel, failure);
                try {
                    readinessSelector.close();
                } catch (IOException exception) {
                    if (failure == null) {
                        failure = exception;
                    }
                }
            }
            if (failure != null) {
                throw failure;
            }
        }

        /// Returns or creates the stream channel.
        private SocketChannel streamChannel() throws IOException {
            if (streamChannel == null) {
                streamChannel = networkBackend.openSocketChannel(protocolFamily(domain));
                applyOptions(streamChannel);
                registerReadinessChannel(streamChannel);
            }
            return streamChannel;
        }

        /// Returns the connected stream channel or throws a Linux-like Java exception.
        private SocketChannel connectedStreamChannel() throws IOException {
            SocketChannel channel = streamChannel();
            if (channel.isConnectionPending()) {
                long result = finishConnectIfReady(channel);
                if (result != 0) {
                    throw new NotYetConnectedException();
                }
            }
            if (!channel.isConnected()) {
                throw new NotYetConnectedException();
            }
            return channel;
        }

        /// Returns the datagram channel.
        private DatagramChannel datagramChannel() {
            assert datagramChannel != null;
            return datagramChannel;
        }

        /// Completes a pending connect, blocking when necessary.
        private long finishConnectBlocking(SocketChannel channel) throws IOException {
            long ready = waitReady(channel, SelectionKey.OP_CONNECT);
            if (ready != 0) {
                return ready;
            }
            return finishConnect(channel);
        }

        /// Completes a pending connect when the host reports it is ready.
        private long finishConnectIfReady(SocketChannel channel) throws IOException {
            if (!channel.isConnectionPending()) {
                return channel.isConnected() ? 0 : ENOTCONN;
            }
            if ((readyOperations(channel) & SelectionKey.OP_CONNECT) == 0) {
                return EINPROGRESS;
            }
            return finishConnect(channel);
        }

        /// Completes a pending connect now.
        private long finishConnect(SocketChannel channel) throws IOException {
            try {
                if (!channel.finishConnect()) {
                    return EINPROGRESS;
                }
                boundAddress = socketAddress(channel.getLocalAddress());
                peerAddress = socketAddress(channel.getRemoteAddress());
                return 0;
            } catch (NoConnectionPendingException exception) {
                return channel.isConnected() ? 0 : ENOTCONN;
            } catch (IOException exception) {
                long error = networkException(exception);
                recordSocketError(error);
                return error;
            }
        }

        /// Sets a generic socket option.
        private long setSocketOption(long option, int value) throws IOException {
            if (option == SO_REUSEADDR) {
                reuseAddress = value != 0;
                return setBooleanOption(StandardSocketOptions.SO_REUSEADDR, reuseAddress);
            }
            if (option == SO_REUSEPORT) {
                reusePort = value != 0;
                return setBooleanOption(StandardSocketOptions.SO_REUSEPORT, reusePort);
            }
            if (option == SO_KEEPALIVE && socketType == SOCK_STREAM) {
                keepAlive = value != 0;
                return setBooleanOption(StandardSocketOptions.SO_KEEPALIVE, keepAlive);
            }
            if (option == SO_BROADCAST && socketType == SOCK_DGRAM) {
                broadcast = value != 0;
                return setBooleanOption(StandardSocketOptions.SO_BROADCAST, broadcast);
            }
            if (option == SO_SNDBUF) {
                if (value <= 0) {
                    return EINVAL;
                }
                sendBufferSize = value;
                return setIntegerOption(StandardSocketOptions.SO_SNDBUF, value);
            }
            if (option == SO_RCVBUF) {
                if (value <= 0) {
                    return EINVAL;
                }
                receiveBufferSize = value;
                return setIntegerOption(StandardSocketOptions.SO_RCVBUF, value);
            }
            return ENOPROTOOPT;
        }

        /// Gets a generic socket option.
        private OptionResult getSocketOption(long option) throws IOException {
            if (option == SO_REUSEADDR) {
                return OptionResult.value(booleanOption(StandardSocketOptions.SO_REUSEADDR, reuseAddress) ? 1 : 0);
            }
            if (option == SO_REUSEPORT) {
                return OptionResult.value(booleanOption(StandardSocketOptions.SO_REUSEPORT, reusePort) ? 1 : 0);
            }
            if (option == SO_KEEPALIVE && socketType == SOCK_STREAM) {
                return OptionResult.value(booleanOption(StandardSocketOptions.SO_KEEPALIVE, keepAlive) ? 1 : 0);
            }
            if (option == SO_BROADCAST && socketType == SOCK_DGRAM) {
                return OptionResult.value(booleanOption(StandardSocketOptions.SO_BROADCAST, broadcast) ? 1 : 0);
            }
            if (option == SO_SNDBUF) {
                return OptionResult.value(integerOption(StandardSocketOptions.SO_SNDBUF, sendBufferSize));
            }
            if (option == SO_RCVBUF) {
                return OptionResult.value(integerOption(StandardSocketOptions.SO_RCVBUF, receiveBufferSize));
            }
            if (option == SO_ERROR) {
                if (streamChannel != null && streamChannel.isConnectionPending()) {
                    long result = finishConnectIfReady(streamChannel);
                    if (result < 0 && result != EINPROGRESS) {
                        recordSocketError(result);
                    }
                }
                int result = socketError;
                socketError = 0;
                return OptionResult.value(result);
            }
            return OptionResult.error(ENOPROTOOPT);
        }

        /// Applies configured options to a newly opened channel.
        private void applyOptions(NetworkChannel channel) throws IOException {
            if (reuseAddress) {
                channel.setOption(StandardSocketOptions.SO_REUSEADDR, true);
            }
            if (reusePort) {
                channel.setOption(StandardSocketOptions.SO_REUSEPORT, true);
            }
            if (sendBufferSize > 0) {
                channel.setOption(StandardSocketOptions.SO_SNDBUF, sendBufferSize);
            }
            if (receiveBufferSize > 0) {
                channel.setOption(StandardSocketOptions.SO_RCVBUF, receiveBufferSize);
            }
            if (channel instanceof SocketChannel socketChannel) {
                socketChannel.setOption(StandardSocketOptions.SO_KEEPALIVE, keepAlive);
                socketChannel.setOption(StandardSocketOptions.TCP_NODELAY, tcpNoDelay);
            }
            if (channel instanceof DatagramChannel datagram) {
                datagram.setOption(StandardSocketOptions.SO_BROADCAST, broadcast);
            }
        }

        /// Sets one boolean option on every open channel.
        private long setBooleanOption(java.net.SocketOption<Boolean> option, boolean value) throws IOException {
            for (NetworkChannel channel : openNetworkChannels()) {
                channel.setOption(option, value);
            }
            return 0;
        }

        /// Sets one integer option on every open channel.
        private long setIntegerOption(java.net.SocketOption<Integer> option, int value) throws IOException {
            for (NetworkChannel channel : openNetworkChannels()) {
                channel.setOption(option, value);
            }
            return 0;
        }

        /// Gets a boolean option from an open channel or returns the cached value.
        private boolean booleanOption(java.net.SocketOption<Boolean> option, boolean cachedValue) throws IOException {
            NetworkChannel channel = firstOpenNetworkChannel();
            return channel == null ? cachedValue : Boolean.TRUE.equals(channel.getOption(option));
        }

        /// Gets an integer option from an open channel or returns the cached value.
        private int integerOption(java.net.SocketOption<Integer> option, int cachedValue) throws IOException {
            NetworkChannel channel = firstOpenNetworkChannel();
            @Nullable Integer value = channel == null ? null : channel.getOption(option);
            return value == null ? cachedValue : value;
        }

        /// Returns all currently open network channels.
        private NetworkChannel @Unmodifiable [] openNetworkChannels() {
            ArrayList<NetworkChannel> channels = new ArrayList<>(3);
            if (streamChannel != null) {
                channels.add(streamChannel);
            }
            if (serverChannel != null) {
                channels.add(serverChannel);
            }
            if (datagramChannel != null) {
                channels.add(datagramChannel);
            }
            return channels.toArray(NetworkChannel[]::new);
        }

        /// Returns the first currently open network channel, or null.
        private @Nullable NetworkChannel firstOpenNetworkChannel() {
            if (streamChannel != null) {
                return streamChannel;
            }
            if (serverChannel != null) {
                return serverChannel;
            }
            return datagramChannel;
        }

        /// Registers a newly opened channel for persistent readiness observation.
        private void registerReadinessChannel(SelectableChannel channel) throws ClosedChannelException {
            synchronized (readinessSelector) {
                channel.register(readinessSelector, channel.validOps());
            }
        }

        /// Cancels a channel's readiness registration and processes the cancellation immediately.
        private void unregisterReadinessChannel(SelectableChannel channel) throws IOException {
            synchronized (readinessSelector) {
                @Nullable SelectionKey key = channel.keyFor(readinessSelector);
                if (key != null) {
                    key.cancel();
                }
                readinessSelector.selectNow();
                readinessSelector.selectedKeys().clear();
            }
        }

        /// Returns the operations currently reported by this socket's persistent selector.
        private int readyOperations(SelectableChannel channel) {
            synchronized (readinessSelector) {
                @Nullable SelectionKey key = channel.keyFor(readinessSelector);
                if (key == null || !key.isValid()) {
                    return 0;
                }
                try {
                    readinessSelector.selectNow();
                    int operations = readinessSelector.selectedKeys().contains(key) ? key.readyOps() : 0;
                    readinessSelector.selectedKeys().clear();
                    return operations;
                } catch (IOException | java.nio.channels.CancelledKeyException exception) {
                    return 0;
                }
            }
        }

        /// Stores a socket error for later `SO_ERROR` retrieval.
        private void recordSocketError(long error) {
            if (error < 0) {
                socketError = (int) -error;
            }
        }

        /// Casts a host socket address to an Internet socket address.
        private @Nullable InetSocketAddress socketAddress(@Nullable SocketAddress address) {
            return address instanceof InetSocketAddress inetSocketAddress ? inetSocketAddress : null;
        }

        /// Closes one nullable channel and preserves the first close failure.
        private @Nullable IOException closeChannel(
                @Nullable java.nio.channels.Channel channel,
                @Nullable IOException previousFailure) {
            if (channel == null) {
                return previousFailure;
            }
            try {
                channel.close();
                return previousFailure;
            } catch (IOException exception) {
                return previousFailure == null ? exception : previousFailure;
            }
        }
    }

    /// Returns the netlink route socket backing a descriptor, or null when the descriptor is not such a socket.
    private @Nullable NetlinkRouteSocket netlinkRouteSocket(int fileDescriptor) {
        @Nullable OpenFile openFile = openFile(fileDescriptor);
        if (openFile == null || !openFile.isSocket()) {
            return null;
        }

        GuestSocket socket = openFile.socket();
        return socket instanceof NetlinkRouteSocket netlinkSocket ? netlinkSocket : null;
    }

    /// Writes a Linux `struct sockaddr_nl` through either direct or value-result length addressing.
    private long writeSockaddrNl(long address, long lengthAddress, long portId) {
        if (lengthAddress != 0 && !memory.isBacked(lengthAddress, Integer.BYTES)) {
            return EFAULT;
        }
        if (address != 0) {
            if (!memory.isBacked(address, SOCKADDR_NL_SIZE)) {
                return EFAULT;
            }
            memory.clear(address, SOCKADDR_NL_SIZE);
            memory.writeShort(address + SOCKADDR_NL_FAMILY_OFFSET, (short) AF_NETLINK);
            memory.writeInt(address + SOCKADDR_NL_PID_OFFSET, (int) portId);
            memory.writeInt(address + SOCKADDR_NL_GROUPS_OFFSET, 0);
        }
        if (lengthAddress != 0) {
            memory.writeInt(lengthAddress, (int) SOCKADDR_NL_SIZE);
        }
        return 0;
    }

    /// Reads the netlink sequence number from a request header prefix.
    private static int netlinkSequence(byte[] header) {
        return header.length >= NETLINK_HEADER_SEQUENCE_OFFSET + Integer.BYTES
                ? getLittleEndianInt(header, NETLINK_HEADER_SEQUENCE_OFFSET)
                : 0;
    }

    /// Reads the netlink message type from a request header prefix.
    private static int netlinkType(byte[] header) {
        return header.length >= NETLINK_HEADER_TYPE_OFFSET + Short.BYTES
                ? getLittleEndianShort(header, NETLINK_HEADER_TYPE_OFFSET)
                : 0;
    }

    /// Reads a little-endian unsigned 16-bit value from a byte array.
    private static int getLittleEndianShort(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8);
    }

    /// Reads a little-endian 32-bit value from a byte array.
    private static int getLittleEndianInt(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff)
                | ((bytes[offset + 1] & 0xff) << 8)
                | ((bytes[offset + 2] & 0xff) << 16)
                | ((bytes[offset + 3] & 0xff) << 24);
    }

    /// Writes a little-endian 16-bit value into a byte array.
    private static void putLittleEndianShort(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) value;
        bytes[offset + 1] = (byte) (value >>> 8);
    }

    /// Writes a little-endian 32-bit value into a byte array.
    private static void putLittleEndianInt(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) value;
        bytes[offset + 1] = (byte) (value >>> 8);
        bytes[offset + 2] = (byte) (value >>> 16);
        bytes[offset + 3] = (byte) (value >>> 24);
    }

    /// Returns a 4-byte aligned netlink payload size.
    private static int netlinkAlign(int value) {
        return (value + 3) & ~3;
    }

    /// Writes a netlink message header into a response buffer.
    private static void putNetlinkHeader(byte[] bytes, int type, int sequence, long portId) {
        putLittleEndianInt(bytes, NETLINK_HEADER_LENGTH_OFFSET, bytes.length);
        putLittleEndianShort(bytes, NETLINK_HEADER_TYPE_OFFSET, type);
        putLittleEndianShort(bytes, NETLINK_HEADER_FLAGS_OFFSET, NETLINK_FLAG_MULTI);
        putLittleEndianInt(bytes, NETLINK_HEADER_SEQUENCE_OFFSET, sequence);
        putLittleEndianInt(bytes, NETLINK_HEADER_PORT_ID_OFFSET, (int) portId);
    }

    /// Writes a Linux `struct rtattr` and its payload into a response buffer.
    private static void putRouteAttribute(byte[] bytes, int offset, int type, byte[] payload) {
        putLittleEndianShort(bytes, offset, Short.BYTES * 2 + payload.length);
        putLittleEndianShort(bytes, offset + Short.BYTES, type);
        System.arraycopy(payload, 0, bytes, offset + 2 * Short.BYTES, payload.length);
    }

    /// Returns a new byte array containing one little-endian 32-bit value.
    private static byte[] littleEndianIntBytes(int value) {
        byte[] bytes = new byte[Integer.BYTES];
        putLittleEndianInt(bytes, 0, value);
        return bytes;
    }

    /// Builds one synthetic `RTM_NEWLINK` message.
    private static byte[] netlinkLinkMessage(
            int sequence,
            long portId,
            int hardwareType,
            int interfaceIndex,
            int interfaceFlags,
            byte[] name,
            byte @Nullable [] hardwareAddress,
            byte @Nullable [] broadcastAddress) {
        int attributeOffset = NETLINK_HEADER_SIZE + 16;
        int nameAttributeSize = netlinkAlign(2 * Short.BYTES + name.length);
        int hardwareAddressAttributeSize = hardwareAddress == null
                ? 0
                : netlinkAlign(2 * Short.BYTES + hardwareAddress.length);
        int broadcastAddressAttributeSize = broadcastAddress == null
                ? 0
                : netlinkAlign(2 * Short.BYTES + broadcastAddress.length);
        int size = attributeOffset
                + hardwareAddressAttributeSize
                + broadcastAddressAttributeSize
                + nameAttributeSize;
        byte[] response = new byte[size];
        putNetlinkHeader(response, RTM_NEWLINK, sequence, portId);
        putLittleEndianShort(response, NETLINK_HEADER_SIZE + 2, hardwareType);
        putLittleEndianInt(response, NETLINK_HEADER_SIZE + 4, interfaceIndex);
        putLittleEndianInt(response, NETLINK_HEADER_SIZE + 8, interfaceFlags);
        putLittleEndianInt(response, NETLINK_HEADER_SIZE + 12, -1);
        int nextAttributeOffset = attributeOffset;
        if (hardwareAddress != null) {
            putRouteAttribute(response, nextAttributeOffset, IFLA_ADDRESS, hardwareAddress);
            nextAttributeOffset += hardwareAddressAttributeSize;
        }
        if (broadcastAddress != null) {
            putRouteAttribute(response, nextAttributeOffset, IFLA_BROADCAST, broadcastAddress);
            nextAttributeOffset += broadcastAddressAttributeSize;
        }
        putRouteAttribute(response, nextAttributeOffset, IFLA_IFNAME, name);
        return response;
    }

    /// Builds one synthetic IPv4 `RTM_NEWADDR` message.
    private static byte[] netlinkIpv4AddressMessage(
            int sequence,
            long portId,
            int prefixLength,
            int scope,
            int interfaceIndex,
            byte[] address,
            byte @Nullable [] broadcastAddress,
            byte[] label) {
        int attributeOffset = NETLINK_HEADER_SIZE + 8;
        int addressAttributeSize = netlinkAlign(2 * Short.BYTES + address.length);
        int broadcastAddressAttributeSize = broadcastAddress == null
                ? 0
                : netlinkAlign(2 * Short.BYTES + broadcastAddress.length);
        int labelAttributeSize = netlinkAlign(2 * Short.BYTES + label.length);
        byte[] response = new byte[attributeOffset
                + 2 * addressAttributeSize
                + broadcastAddressAttributeSize
                + labelAttributeSize];
        putNetlinkHeader(response, RTM_NEWADDR, sequence, portId);
        response[NETLINK_HEADER_SIZE] = AF_INET;
        response[NETLINK_HEADER_SIZE + 1] = (byte) prefixLength;
        response[NETLINK_HEADER_SIZE + 2] = (byte) IFA_F_PERMANENT;
        response[NETLINK_HEADER_SIZE + 3] = (byte) scope;
        putLittleEndianInt(response, NETLINK_HEADER_SIZE + 4, interfaceIndex);
        putRouteAttribute(response, attributeOffset, IFA_ADDRESS, address);
        putRouteAttribute(response, attributeOffset + addressAttributeSize, IFA_LOCAL, address);
        int nextAttributeOffset = attributeOffset + 2 * addressAttributeSize;
        if (broadcastAddress != null) {
            putRouteAttribute(response, nextAttributeOffset, IFA_BROADCAST, broadcastAddress);
            nextAttributeOffset += broadcastAddressAttributeSize;
        }
        putRouteAttribute(response, nextAttributeOffset, IFA_LABEL, label);
        return response;
    }

    /// Builds one synthetic loopback `RTM_NEWLINK` message.
    private static byte[] netlinkLoopbackLinkMessage(int sequence, long portId) {
        return netlinkLinkMessage(
                sequence,
                portId,
                LOOPBACK_HARDWARE_TYPE,
                LOOPBACK_INTERFACE_INDEX,
                LOOPBACK_INTERFACE_FLAGS,
                new byte[]{'l', 'o', 0},
                null,
                null);
    }

    /// Builds one synthetic Ethernet `RTM_NEWLINK` message.
    private static byte[] netlinkEthernetLinkMessage(int sequence, long portId) {
        return netlinkLinkMessage(
                sequence,
                portId,
                ETHERNET_HARDWARE_TYPE,
                ETHERNET_INTERFACE_INDEX,
                ETHERNET_INTERFACE_FLAGS,
                new byte[]{'e', 't', 'h', '0', 0},
                new byte[]{0x02, 0, 0, 0, 0, 0x01},
                new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff});
    }

    /// Builds one synthetic loopback IPv4 `RTM_NEWADDR` message.
    private static byte[] netlinkLoopbackAddressMessage(int sequence, long portId) {
        return netlinkIpv4AddressMessage(
                sequence,
                portId,
                8,
                RT_SCOPE_HOST,
                LOOPBACK_INTERFACE_INDEX,
                new byte[]{127, 0, 0, 1},
                null,
                new byte[]{'l', 'o', 0});
    }

    /// Builds one synthetic Ethernet IPv4 `RTM_NEWADDR` message.
    private static byte[] netlinkEthernetAddressMessage(int sequence, long portId) {
        return netlinkIpv4AddressMessage(
                sequence,
                portId,
                24,
                RT_SCOPE_UNIVERSE,
                ETHERNET_INTERFACE_INDEX,
                new byte[]{10, 0, 2, 15},
                new byte[]{10, 0, 2, (byte) 255},
                new byte[]{'e', 't', 'h', '0', 0});
    }

    /// Builds one synthetic IPv4 default-route `RTM_NEWROUTE` message.
    private static byte[] netlinkDefaultRouteMessage(int sequence, long portId) {
        int attributeOffset = NETLINK_HEADER_SIZE + 12;
        int integerAttributeSize = netlinkAlign(2 * Short.BYTES + Integer.BYTES);
        byte[] gateway = new byte[]{10, 0, 2, 2};
        byte[] preferredSource = new byte[]{10, 0, 2, 15};
        byte[] response = new byte[attributeOffset + 4 * integerAttributeSize];
        putNetlinkHeader(response, RTM_NEWROUTE, sequence, portId);
        response[NETLINK_HEADER_SIZE] = AF_INET;
        response[NETLINK_HEADER_SIZE + 4] = (byte) RT_TABLE_MAIN;
        response[NETLINK_HEADER_SIZE + 5] = RTPROT_STATIC;
        response[NETLINK_HEADER_SIZE + 6] = RT_SCOPE_UNIVERSE;
        response[NETLINK_HEADER_SIZE + 7] = RTN_UNICAST;
        putRouteAttribute(response, attributeOffset, RTA_OIF, littleEndianIntBytes(ETHERNET_INTERFACE_INDEX));
        putRouteAttribute(response, attributeOffset + integerAttributeSize, RTA_GATEWAY, gateway);
        putRouteAttribute(response, attributeOffset + 2 * integerAttributeSize, RTA_PRIORITY, littleEndianIntBytes(0));
        putRouteAttribute(response, attributeOffset + 3 * integerAttributeSize, RTA_PREFSRC, preferredSource);
        return response;
    }

    /// Builds one synthetic `NLMSG_DONE` message.
    private static byte[] netlinkDoneMessage(int sequence, long portId) {
        byte[] response = new byte[NETLINK_DONE_MESSAGE_SIZE];
        putNetlinkHeader(response, NETLINK_MESSAGE_DONE, sequence, portId);
        putLittleEndianInt(response, NETLINK_HEADER_SIZE, 0);
        return response;
    }

    /// Reads the first bytes from guest iovecs, returning null when any range is invalid.
    private byte @Nullable [] readIovPrefix(long iovecAddress, long iovecCount, int maximumLength) {
        if (maximumLength == 0) {
            return new byte[0];
        }
        if (iovecCount > 0 && !memory.isBacked(iovecAddress, iovecCount * IOVEC_SIZE)) {
            return null;
        }

        byte[] result = new byte[maximumLength];
        int copied = 0;
        for (long index = 0; index < iovecCount && copied < maximumLength; index++) {
            long entryAddress = iovecAddress + index * IOVEC_SIZE;
            long baseAddress = memory.readLong(entryAddress + IOVEC_BASE_OFFSET);
            long length = memory.readLong(entryAddress + IOVEC_LENGTH_OFFSET);
            if (length < 0 || length > Integer.MAX_VALUE || !memory.isBacked(baseAddress, length)) {
                return null;
            }
            int copyLength = (int) Math.min(length, maximumLength - copied);
            byte[] bytes = memory.readBytes(baseAddress, copyLength);
            System.arraycopy(bytes, 0, result, copied, copyLength);
            copied += copyLength;
        }

        if (copied == result.length) {
            return result;
        }

        byte[] truncated = new byte[copied];
        System.arraycopy(result, 0, truncated, 0, copied);
        return truncated;
    }

    /// Returns the total byte count described by guest iovecs, or a raw negative Linux error.
    private long iovByteCount(long iovecAddress, long iovecCount) {
        if (iovecCount > 0 && !memory.isBacked(iovecAddress, iovecCount * IOVEC_SIZE)) {
            return EFAULT;
        }
        long total = 0;
        for (long index = 0; index < iovecCount; index++) {
            long length = memory.readLong(iovecAddress + index * IOVEC_SIZE + IOVEC_LENGTH_OFFSET);
            if (length < 0 || Long.MAX_VALUE - total < length) {
                return EINVAL;
            }
            total += length;
        }
        return total;
    }

    /// Writes bytes into guest iovecs and returns the copied byte count, or a raw negative Linux error.
    private long writeIovBytes(long iovecAddress, long iovecCount, byte[] bytes) {
        if (iovecCount > 0 && !memory.isBacked(iovecAddress, iovecCount * IOVEC_SIZE)) {
            return EFAULT;
        }

        int copied = 0;
        for (long index = 0; index < iovecCount && copied < bytes.length; index++) {
            long entryAddress = iovecAddress + index * IOVEC_SIZE;
            long baseAddress = memory.readLong(entryAddress + IOVEC_BASE_OFFSET);
            long length = memory.readLong(entryAddress + IOVEC_LENGTH_OFFSET);
            if (length < 0 || length > Integer.MAX_VALUE || !memory.isBacked(baseAddress, length)) {
                return EFAULT;
            }
            int copyLength = (int) Math.min(length, bytes.length - copied);
            memory.writeBytes(baseAddress, bytes, copied, copyLength);
            copied += copyLength;
        }
        return copied;
    }

    /// Stores the queued responses for one minimal `NETLINK_ROUTE` socket.
    private static final class NetlinkRouteSocket implements GuestSocket {
        /// Queued response datagrams.
        private final ArrayDeque<byte[]> responses = new ArrayDeque<>();

        /// Local netlink port id, or zero until assigned lazily.
        private long portId;

        /// Stores the requested local port id.
        void bind(long requestedPortId) {
            this.portId = requestedPortId;
        }

        /// Returns the local port id, assigning the process id when the guest requested automatic binding.
        long portId(long processId) {
            if (portId == 0) {
                portId = processId;
            }
            return portId;
        }

        /// Queues synthetic responses for the supplied rtnetlink request.
        void enqueueResponse(byte[] request, long processId) {
            long localPortId = portId(processId);
            int sequence = netlinkSequence(request);
            int type = netlinkType(request);
            if (type == RTM_GETLINK) {
                responses.add(netlinkLoopbackLinkMessage(sequence, localPortId));
                responses.add(netlinkEthernetLinkMessage(sequence, localPortId));
            } else if (type == RTM_GETADDR) {
                responses.add(netlinkLoopbackAddressMessage(sequence, localPortId));
                responses.add(netlinkEthernetAddressMessage(sequence, localPortId));
            } else if (type == RTM_GETROUTE) {
                responses.add(netlinkDefaultRouteMessage(sequence, localPortId));
            }
            responses.add(netlinkDoneMessage(sequence, localPortId));
        }

        /// Returns and removes the next queued response, or null when none is available.
        @Nullable byte[] pollResponse() {
            return responses.poll();
        }
    }

    /// Marks a generic socket that exists only for Linux network-interface ioctl helpers.
    private static final class NetworkInterfaceIoctlSocket implements GuestSocket {
    }


    /// Implements Linux `mremap` for tracked anonymous mappings.
    protected long mremap(long oldAddress, long oldSize, long newSize, long flags, long newAddress) {
        if (!isPageAligned(oldAddress) || oldSize <= 0 || newSize <= 0 || (flags & ~SUPPORTED_MREMAP_FLAGS) != 0) {
            return EINVAL;
        }
        boolean fixed = (flags & MREMAP_FIXED) != 0;
        boolean mayMove = (flags & MREMAP_MAYMOVE) != 0;
        if (fixed && !mayMove) {
            return EINVAL;
        }

        long oldLength = alignUp(oldSize, pageSize);
        long newLength = alignUp(newSize, pageSize);
        if (oldLength <= 0 || newLength <= 0
                || !isValidGuestRange(oldAddress, oldLength)
                || (fixed && (!isPageAligned(newAddress) || !isValidGuestRange(newAddress, newLength)))) {
            return ENOMEM;
        }

        @Nullable MemoryMapping mapping = memoryMappingCovering(oldAddress);
        if (mapping == null || oldAddress != mapping.address() || oldLength != mapping.length()) {
            return ENOMEM;
        }
        if (mapping.deviceFile() != null) {
            return EINVAL;
        }
        if (fixed && rangesOverlap(oldAddress, oldAddress + oldLength, newAddress, newAddress + newLength)) {
            return EINVAL;
        }
        if (fixed) {
            removeMemoryMappings(newAddress, newLength);
        }

        if (!fixed && newLength == oldLength) {
            return oldAddress;
        }
        if (!fixed && newLength < oldLength) {
            removeMemoryMappings(oldAddress + newLength, oldLength - newLength);
            return oldAddress;
        }

        long growthLength = newLength - oldLength;
        if (!fixed && isMmapRangeAvailable(oldAddress + oldLength, growthLength)) {
            if (!ensureMemoryBacking(oldAddress + oldLength, growthLength, mapping.protection(), false)) {
                return ENOMEM;
            }
            resizeMemoryMapping(mapping, newLength);
            return oldAddress;
        }
        if (!mayMove) {
            return ENOMEM;
        }

        long targetAddress = fixed ? newAddress : findMmapAddress(0, newLength, pageSize);
        if (targetAddress == 0 || !isMmapRangeAvailable(targetAddress, newLength)) {
            return ENOMEM;
        }
        return moveMemoryMapping(mapping, oldLength, targetAddress, newLength);
    }


    /// Reports mapped guest pages as resident for Linux `mincore` probes.
    protected long mincore(long address, long length, long vectorAddress) {
        if (!isPageAligned(address) || length < 0) {
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

        long pageCount = alignedLength / pageSize;
        if (pageCount > Integer.MAX_VALUE) {
            throw new RiscVException("Guest mincore vector is too large: " + pageCount);
        }
        if (!memory.isBacked(vectorAddress, pageCount)) {
            return EFAULT;
        }

        byte[] vector = new byte[(int) pageCount];
        for (int index = 0; index < vector.length; index++) {
            vector[index] = 1;
        }
        memory.writeBytes(vectorAddress, vector, 0, vector.length);
        return 0;
    }


    /// Gets or lowers Linux resource limits for the current guest process.
    protected long prlimit64(long processId, long resource, long newLimitAddress, long oldLimitAddress) {
        if (processId != 0 && processId != process.id()) {
            return ESRCH;
        }
        if (resource < 0 || resource >= RESOURCE_LIMIT_COUNT) {
            return EINVAL;
        }

        int index = (int) resource;
        long oldCurrent = resourceLimitCurrent[index];
        long oldMaximum = resourceLimitMaximum[index];
        if (oldLimitAddress != 0) {
            writeResourceLimit(oldLimitAddress, oldCurrent, oldMaximum);
        }

        if (newLimitAddress != 0) {
            long newCurrent = memory.readLong(newLimitAddress + RLIMIT_CURRENT_OFFSET);
            long newMaximum = memory.readLong(newLimitAddress + RLIMIT_MAXIMUM_OFFSET);
            if (Long.compareUnsigned(newCurrent, newMaximum) > 0) {
                return EINVAL;
            }
            if (Long.compareUnsigned(newMaximum, oldMaximum) > 0) {
                return EPERM;
            }
            resourceLimitCurrent[index] = newCurrent;
            resourceLimitMaximum[index] = newMaximum;
        }
        return 0;
    }

    /// Gets Linux resource limits for the current guest process.
    protected long getrlimit(long resource, long limitAddress) {
        return prlimit64(0, resource, 0, limitAddress);
    }

    /// Lowers Linux resource limits for the current guest process.
    protected long setrlimit(long resource, long limitAddress) {
        return prlimit64(0, resource, limitAddress, 0);
    }


    /// Fills a guest buffer with deterministic bytes for the Linux `getrandom` syscall.
    protected long getrandom(long address, long length, long flags) {
        if ((flags & ~GETRANDOM_SUPPORTED_FLAGS) != 0) {
            return EINVAL;
        }
        if (length < 0) {
            return EINVAL;
        }
        if (length > Integer.MAX_VALUE) {
            throw new RiscVException("Guest getrandom syscall buffer is too large: " + length);
        }
        if (length == 0) {
            return 0;
        }

        return writeDeterministicRandomBytes(address, length);
    }

    /// Reports no supported Linux `membarrier` commands for runtime capability probes.
    protected static long membarrier(long command, long flags, long cpuId) {
        if (flags != 0 || cpuId != 0) {
            return EINVAL;
        }
        return command == MEMBARRIER_CMD_QUERY ? 0 : EINVAL;
    }

    /// Handles Linux restartable sequence registration for the current guest thread.
    protected long rseq(RiscVThreadState state, long address, long length, long flags, long signature) {
        long rseqLength = length & 0xffff_ffffL;
        long rseqFlags = flags & 0xffff_ffffL;
        long rseqSignature = signature & 0xffff_ffffL;
        GuestThread thread = state.guestThread();
        if ((rseqFlags & RSEQ_FLAG_UNREGISTER) != 0) {
            return unregisterRseq(thread, address, rseqLength, rseqFlags, rseqSignature);
        }

        if (rseqFlags != 0) {
            return EINVAL;
        }

        if (thread.hasRestartableSequence()) {
            if (thread.restartableSequenceAddress() != address || thread.restartableSequenceLength() != rseqLength) {
                return EINVAL;
            }
            if (thread.restartableSequenceSignature() != rseqSignature) {
                return EPERM;
            }
            return EBUSY;
        }

        if (rseqLength < RSEQ_ORIGINAL_SIZE || !isAligned(address, RSEQ_ALIGNMENT)) {
            return EINVAL;
        }
        if (!memory.isBacked(address, rseqLength)) {
            return EFAULT;
        }

        initializeRseqArea(address);
        thread.setRestartableSequence(address, rseqLength, rseqSignature);
        return 0;
    }

    /// Unregisters the current thread's restartable sequence area.
    protected long unregisterRseq(GuestThread thread, long address, long length, long flags, long signature) {
        if ((flags & ~RSEQ_FLAG_UNREGISTER) != 0) {
            return EINVAL;
        }
        if (!thread.hasRestartableSequence() || thread.restartableSequenceAddress() != address) {
            return EINVAL;
        }
        if (thread.restartableSequenceLength() != length) {
            return EINVAL;
        }
        if (thread.restartableSequenceSignature() != signature) {
            return EPERM;
        }
        if (!memory.isBacked(address, length)) {
            return EFAULT;
        }

        resetRseqArea(address);
        thread.clearRestartableSequence();
        return 0;
    }

    /// Initializes the guest-visible fields that Linux updates while rseq is registered.
    protected void initializeRseqArea(long address) {
        memory.writeLong(address + RSEQ_CRITICAL_SECTION_OFFSET, 0);
        memory.writeInt(address + RSEQ_CPU_ID_START_OFFSET, 0);
        memory.writeInt(address + RSEQ_CPU_ID_OFFSET, 0);
        memory.writeInt(address + RSEQ_FLAGS_OFFSET, 0);
        memory.writeInt(address + RSEQ_NODE_ID_OFFSET, 0);
        memory.writeInt(address + RSEQ_MEMORY_MAP_CONCURRENCY_ID_OFFSET, 0);
    }

    /// Resets the guest-visible fields that Linux invalidates during rseq unregistration.
    protected void resetRseqArea(long address) {
        memory.writeLong(address + RSEQ_CRITICAL_SECTION_OFFSET, 0);
        memory.writeInt(address + RSEQ_CPU_ID_START_OFFSET, -1);
        memory.writeInt(address + RSEQ_CPU_ID_OFFSET, -1);
        memory.writeInt(address + RSEQ_NODE_ID_OFFSET, 0);
        memory.writeInt(address + RSEQ_MEMORY_MAP_CONCURRENCY_ID_OFFSET, 0);
    }


    /// Creates a child-process Linux syscall handler by copying fork-inherited parent state.
    protected LinuxGuestSyscalls(LinuxGuestSyscalls parent, Memory memory, GuestProcess process) {
        super(parent, memory, process);
        networkBackend = parent.networkBackend;
        System.arraycopy(parent.signalActions, 0, signalActions, 0, signalActions.length);
        signalTrampolineAddress = parent.signalTrampolineAddress;
    }

    /// The Linux RISC-V syscall number for `getxattr`.
    private static final int SYS_GETXATTR = 8;

    /// The Linux RISC-V syscall number for `lgetxattr`.
    private static final int SYS_LGETXATTR = 9;

    /// The Linux RISC-V syscall number for `fgetxattr`.
    private static final int SYS_FGETXATTR = 10;

    /// The Linux RISC-V syscall number for `listxattr`.
    private static final int SYS_LISTXATTR = 11;

    /// The Linux RISC-V syscall number for `llistxattr`.
    private static final int SYS_LLISTXATTR = 12;

    /// The Linux RISC-V syscall number for `flistxattr`.
    private static final int SYS_FLISTXATTR = 13;

    /// The Linux RISC-V syscall number for `getcwd`.
    private static final int SYS_GETCWD = 17;

    /// The Linux RISC-V syscall number for `eventfd2`.
    private static final int SYS_EVENTFD2 = 19;

    /// The Linux RISC-V syscall number for `epoll_create1`.
    private static final int SYS_EPOLL_CREATE1 = 20;

    /// The Linux RISC-V syscall number for `epoll_ctl`.
    private static final int SYS_EPOLL_CTL = 21;

    /// The Linux RISC-V syscall number for `epoll_pwait`.
    private static final int SYS_EPOLL_PWAIT = 22;

    /// The Linux RISC-V syscall number for `dup`.
    private static final int SYS_DUP = 23;

    /// The Linux RISC-V syscall number for `dup3`.
    private static final int SYS_DUP3 = 24;

    /// The Linux RISC-V syscall number for `fcntl`.
    private static final int SYS_FCNTL = 25;

    /// The Linux RISC-V syscall number for `ioctl`.
    private static final int SYS_IOCTL = 29;

    /// The Linux RISC-V syscall number for `mkdirat`.
    private static final int SYS_MKDIRAT = 34;

    /// The Linux RISC-V syscall number for `unlinkat`.
    private static final int SYS_UNLINKAT = 35;

    /// The Linux RISC-V syscall number for `symlinkat`.
    private static final int SYS_SYMLINKAT = 36;

    /// The Linux RISC-V syscall number for `linkat`.
    private static final int SYS_LINKAT = 37;

    /// The Linux RISC-V syscall number for `renameat`.
    private static final int SYS_RENAMEAT = 38;

    /// The Linux RISC-V syscall number for `statfs`.
    private static final int SYS_STATFS = 43;

    /// The Linux RISC-V syscall number for `fstatfs`.
    private static final int SYS_FSTATFS = 44;

    /// The Linux RISC-V syscall number for `truncate`.
    private static final int SYS_TRUNCATE = 45;

    /// The Linux RISC-V syscall number for `ftruncate`.
    private static final int SYS_FTRUNCATE = 46;

    /// The Linux RISC-V syscall number for `fallocate`.
    private static final int SYS_FALLOCATE = 47;

    /// The Linux RISC-V syscall number for `faccessat`.
    private static final int SYS_FACCESSAT = 48;

    /// The Linux RISC-V syscall number for `chdir`.
    private static final int SYS_CHDIR = 49;

    /// The Linux RISC-V syscall number for `fchdir`.
    private static final int SYS_FCHDIR = 50;

    /// The Linux RISC-V syscall number for `fchmod`.
    private static final int SYS_FCHMOD = 52;

    /// The Linux RISC-V syscall number for `fchmodat`.
    private static final int SYS_FCHMODAT = 53;

    /// The Linux RISC-V syscall number for `fchownat`.
    private static final int SYS_FCHOWNAT = 54;

    /// The Linux RISC-V syscall number for `fchown`.
    private static final int SYS_FCHOWN = 55;

    /// The Linux RISC-V syscall number for `openat`.
    private static final int SYS_OPENAT = 56;

    /// The Linux RISC-V syscall number for `close`.
    private static final int SYS_CLOSE = 57;

    /// The Linux RISC-V syscall number for `pipe2`.
    private static final int SYS_PIPE2 = 59;

    /// The Linux RISC-V syscall number for `getdents64`.
    private static final int SYS_GETDENTS64 = 61;

    /// The Linux RISC-V syscall number for `lseek`.
    private static final int SYS_LSEEK = 62;

    /// The Linux RISC-V syscall number for `read`.
    private static final int SYS_READ = 63;

    /// The Linux RISC-V syscall number for `write`.
    private static final int SYS_WRITE = 64;

    /// The Linux RISC-V syscall number for `readv`.
    private static final int SYS_READV = 65;

    /// The Linux RISC-V syscall number for `writev`.
    private static final int SYS_WRITEV = 66;

    /// The Linux RISC-V syscall number for `pread64`.
    private static final int SYS_PREAD64 = 67;

    /// The Linux RISC-V syscall number for `pwrite64`.
    private static final int SYS_PWRITE64 = 68;

    /// The Linux RISC-V syscall number for `preadv`.
    private static final int SYS_PREADV = 69;

    /// The Linux RISC-V syscall number for `pwritev`.
    private static final int SYS_PWRITEV = 70;

    /// The Linux RISC-V syscall number for `pselect6`.
    private static final int SYS_PSELECT6 = 72;

    /// The Linux RISC-V syscall number for `ppoll`.
    private static final int SYS_PPOLL = 73;

    /// The Linux RISC-V syscall number for `splice`.
    private static final int SYS_SPLICE = 76;

    /// The Linux RISC-V syscall number for `readlinkat`.
    private static final int SYS_READLINKAT = 78;

    /// The Linux RISC-V syscall number for `newfstatat`.
    private static final int SYS_NEWFSTATAT = 79;

    /// The Linux RISC-V syscall number for `fstat`.
    private static final int SYS_FSTAT = 80;

    /// The Linux RISC-V syscall number for `sync`.
    private static final int SYS_SYNC = 81;

    /// The Linux RISC-V syscall number for `fsync`.
    private static final int SYS_FSYNC = 82;

    /// The Linux RISC-V syscall number for `fdatasync`.
    private static final int SYS_FDATASYNC = 83;

    /// The Linux RISC-V syscall number for `timerfd_create`.
    private static final int SYS_TIMERFD_CREATE = 85;

    /// The Linux RISC-V syscall number for `timerfd_settime`.
    private static final int SYS_TIMERFD_SETTIME = 86;

    /// The Linux RISC-V syscall number for `timerfd_gettime`.
    private static final int SYS_TIMERFD_GETTIME = 87;

    /// The Linux RISC-V syscall number for `utimensat`.
    private static final int SYS_UTIMENSAT = 88;

    /// The Linux RISC-V syscall number for `capget`.
    private static final int SYS_CAPGET = 90;

    /// The Linux RISC-V syscall number for `capset`.
    private static final int SYS_CAPSET = 91;

    /// The Linux RISC-V syscall number for `exit`.
    private static final int SYS_EXIT = 93;

    /// The Linux RISC-V syscall number for `exit_group`.
    private static final int SYS_EXIT_GROUP = 94;

    /// The Linux RISC-V syscall number for `waitid`.
    private static final int SYS_WAITID = 95;

    /// The Linux RISC-V syscall number for `set_tid_address`.
    private static final int SYS_SET_TID_ADDRESS = 96;

    /// The Linux RISC-V syscall number for `futex`.
    private static final int SYS_FUTEX = 98;

    /// The Linux RISC-V syscall number for `set_robust_list`.
    private static final int SYS_SET_ROBUST_LIST = 99;

    /// The Linux RISC-V syscall number for `get_robust_list`.
    private static final int SYS_GET_ROBUST_LIST = 100;

    /// The Linux RISC-V syscall number for `nanosleep`.
    private static final int SYS_NANOSLEEP = 101;

    /// The Linux RISC-V syscall number for `getitimer`.
    private static final int SYS_GETITIMER = 102;

    /// The Linux RISC-V syscall number for `setitimer`.
    private static final int SYS_SETITIMER = 103;

    /// The Linux RISC-V syscall number for `clock_gettime`.
    private static final int SYS_CLOCK_GETTIME = 113;

    /// The Linux RISC-V syscall number for `clock_getres`.
    private static final int SYS_CLOCK_GETRES = 114;

    /// The Linux RISC-V syscall number for `clock_nanosleep`.
    private static final int SYS_CLOCK_NANOSLEEP = 115;

    /// The Linux RISC-V syscall number for `sched_setparam`.
    private static final int SYS_SCHED_SETPARAM = 118;

    /// The Linux RISC-V syscall number for `sched_setscheduler`.
    private static final int SYS_SCHED_SETSCHEDULER = 119;

    /// The Linux RISC-V syscall number for `sched_getscheduler`.
    private static final int SYS_SCHED_GETSCHEDULER = 120;

    /// The Linux RISC-V syscall number for `sched_getparam`.
    private static final int SYS_SCHED_GETPARAM = 121;

    /// The Linux RISC-V syscall number for `sched_setaffinity`.
    private static final int SYS_SCHED_SETAFFINITY = 122;

    /// The Linux RISC-V syscall number for `sched_getaffinity`.
    private static final int SYS_SCHED_GETAFFINITY = 123;

    /// The Linux RISC-V syscall number for `sched_yield`.
    private static final int SYS_SCHED_YIELD = 124;

    /// The Linux RISC-V syscall number for `sched_get_priority_max`.
    private static final int SYS_SCHED_GET_PRIORITY_MAX = 125;

    /// The Linux RISC-V syscall number for `sched_get_priority_min`.
    private static final int SYS_SCHED_GET_PRIORITY_MIN = 126;

    /// The Linux RISC-V syscall number for `sched_rr_get_interval`.
    private static final int SYS_SCHED_RR_GET_INTERVAL = 127;

    /// The Linux RISC-V syscall number for `kill`.
    private static final int SYS_KILL = 129;

    /// The Linux RISC-V syscall number for `tkill`.
    private static final int SYS_TKILL = 130;

    /// The Linux RISC-V syscall number for `tgkill`.
    private static final int SYS_TGKILL = 131;

    /// The Linux RISC-V syscall number for `sigaltstack`.
    private static final int SYS_SIGALTSTACK = 132;

    /// The Linux RISC-V syscall number for `rt_sigaction`.
    private static final int SYS_RT_SIGACTION = 134;

    /// The Linux RISC-V syscall number for `rt_sigprocmask`.
    private static final int SYS_RT_SIGPROCMASK = 135;

    /// The Linux RISC-V syscall number for `rt_sigreturn`.
    private static final int SYS_RT_SIGRETURN = 139;

    /// The Linux RISC-V syscall number for `setpriority`.
    private static final int SYS_SETPRIORITY = 140;

    /// The Linux RISC-V syscall number for `getpriority`.
    private static final int SYS_GETPRIORITY = 141;

    /// The Linux RISC-V syscall number for `setregid`.
    private static final int SYS_SETREGID = 143;

    /// The Linux RISC-V syscall number for `setgid`.
    private static final int SYS_SETGID = 144;

    /// The Linux RISC-V syscall number for `setreuid`.
    private static final int SYS_SETREUID = 145;

    /// The Linux RISC-V syscall number for `setuid`.
    private static final int SYS_SETUID = 146;

    /// The Linux RISC-V syscall number for `setresuid`.
    private static final int SYS_SETRESUID = 147;

    /// The Linux RISC-V syscall number for `getresuid`.
    private static final int SYS_GETRESUID = 148;

    /// The Linux RISC-V syscall number for `setresgid`.
    private static final int SYS_SETRESGID = 149;

    /// The Linux RISC-V syscall number for `getresgid`.
    private static final int SYS_GETRESGID = 150;

    /// The Linux RISC-V syscall number for `setfsuid`.
    private static final int SYS_SETFSUID = 151;

    /// The Linux RISC-V syscall number for `setfsgid`.
    private static final int SYS_SETFSGID = 152;

    /// The Linux RISC-V syscall number for `times`.
    private static final int SYS_TIMES = 153;

    /// The Linux RISC-V syscall number for `setpgid`.
    private static final int SYS_SETPGID = 154;

    /// The Linux RISC-V syscall number for `getpgid`.
    private static final int SYS_GETPGID = 155;

    /// The Linux RISC-V syscall number for `getsid`.
    private static final int SYS_GETSID = 156;

    /// The Linux RISC-V syscall number for `setsid`.
    private static final int SYS_SETSID = 157;

    /// The Linux RISC-V syscall number for `getgroups`.
    private static final int SYS_GETGROUPS = 158;

    /// The Linux RISC-V syscall number for `setgroups`.
    private static final int SYS_SETGROUPS = 159;

    /// The Linux RISC-V syscall number for `uname`.
    private static final int SYS_UNAME = 160;

    /// The Linux RISC-V syscall number for `getrlimit`.
    private static final int SYS_GETRLIMIT = 163;

    /// The Linux RISC-V syscall number for `setrlimit`.
    private static final int SYS_SETRLIMIT = 164;

    /// The Linux RISC-V syscall number for `getrusage`.
    private static final int SYS_GETRUSAGE = 165;

    /// The Linux RISC-V syscall number for `umask`.
    private static final int SYS_UMASK = 166;

    /// The Linux RISC-V syscall number for `prctl`.
    private static final int SYS_PRCTL = 167;

    /// The Linux RISC-V syscall number for `getcpu`.
    private static final int SYS_GETCPU = 168;

    /// The Linux RISC-V syscall number for `gettimeofday`.
    private static final int SYS_GETTIMEOFDAY = 169;

    /// The Linux RISC-V syscall number for `getpid`.
    private static final int SYS_GETPID = 172;

    /// The Linux RISC-V syscall number for `getppid`.
    private static final int SYS_GETPPID = 173;

    /// The Linux RISC-V syscall number for `getuid`.
    private static final int SYS_GETUID = 174;

    /// The Linux RISC-V syscall number for `geteuid`.
    private static final int SYS_GETEUID = 175;

    /// The Linux RISC-V syscall number for `getgid`.
    private static final int SYS_GETGID = 176;

    /// The Linux RISC-V syscall number for `getegid`.
    private static final int SYS_GETEGID = 177;

    /// The Linux RISC-V syscall number for `gettid`.
    private static final int SYS_GETTID = 178;

    /// The Linux RISC-V syscall number for `sysinfo`.
    private static final int SYS_SYSINFO = 179;

    /// The Linux RISC-V syscall number for `socket`.
    private static final int SYS_SOCKET = 198;

    /// The Linux RISC-V syscall number for `socketpair`.
    private static final int SYS_SOCKETPAIR = 199;

    /// The Linux RISC-V syscall number for `bind`.
    private static final int SYS_BIND = 200;

    /// The Linux RISC-V syscall number for `listen`.
    private static final int SYS_LISTEN = 201;

    /// The Linux RISC-V syscall number for `accept`.
    private static final int SYS_ACCEPT = 202;

    /// The Linux RISC-V syscall number for `connect`.
    private static final int SYS_CONNECT = 203;

    /// The Linux RISC-V syscall number for `getsockname`.
    private static final int SYS_GETSOCKNAME = 204;

    /// The Linux RISC-V syscall number for `getpeername`.
    private static final int SYS_GETPEERNAME = 205;

    /// The Linux RISC-V syscall number for `sendto`.
    private static final int SYS_SENDTO = 206;

    /// The Linux RISC-V syscall number for `recvfrom`.
    private static final int SYS_RECVFROM = 207;

    /// The Linux RISC-V syscall number for `setsockopt`.
    private static final int SYS_SETSOCKOPT = 208;

    /// The Linux RISC-V syscall number for `getsockopt`.
    private static final int SYS_GETSOCKOPT = 209;

    /// The Linux RISC-V syscall number for `shutdown`.
    private static final int SYS_SHUTDOWN = 210;

    /// The Linux RISC-V syscall number for `sendmsg`.
    private static final int SYS_SENDMSG = 211;

    /// The Linux RISC-V syscall number for `recvmsg`.
    private static final int SYS_RECVMSG = 212;

    /// The Linux RISC-V syscall number for `brk`.
    private static final int SYS_BRK = 214;

    /// The Linux RISC-V syscall number for `munmap`.
    private static final int SYS_MUNMAP = 215;

    /// The Linux RISC-V syscall number for `mremap`.
    private static final int SYS_MREMAP = 216;

    /// The Linux RISC-V syscall number for `clone`.
    private static final int SYS_CLONE = 220;

    /// The Linux RISC-V syscall number for `fadvise64`.
    private static final int SYS_FADVISE64 = 223;

    /// The Linux RISC-V syscall number for `pidfd_send_signal`.
    private static final int SYS_PIDFD_SEND_SIGNAL = 424;

    /// The Linux RISC-V syscall number for `pidfd_open`.
    private static final int SYS_PIDFD_OPEN = 434;

    /// The Linux RISC-V syscall number for `clone3`.
    private static final int SYS_CLONE3 = 435;

    /// The Linux RISC-V syscall number for `close_range`.
    private static final int SYS_CLOSE_RANGE = 436;

    /// The Linux RISC-V syscall number for `execve`.
    private static final int SYS_EXECVE = 221;

    /// The Linux RISC-V syscall number for `mmap`.
    private static final int SYS_MMAP = 222;

    /// The Linux RISC-V syscall number for `mprotect`.
    private static final int SYS_MPROTECT = 226;

    /// The Linux RISC-V syscall number for `msync`.
    private static final int SYS_MSYNC = 227;

    /// The Linux RISC-V syscall number for `mlock`.
    private static final int SYS_MLOCK = 228;

    /// The Linux RISC-V syscall number for `munlock`.
    private static final int SYS_MUNLOCK = 229;

    /// The Linux RISC-V syscall number for `mlockall`.
    private static final int SYS_MLOCKALL = 230;

    /// The Linux RISC-V syscall number for `munlockall`.
    private static final int SYS_MUNLOCKALL = 231;

    /// The Linux RISC-V syscall number for `mincore`.
    private static final int SYS_MINCORE = 232;

    /// The Linux RISC-V syscall number for `accept4`.
    private static final int SYS_ACCEPT4 = 242;

    /// The Linux RISC-V syscall number for `recvmmsg`.
    private static final int SYS_RECVMMSG = 243;

    /// The Linux RISC-V syscall number for `madvise`.
    private static final int SYS_MADVISE = 233;

    /// The Linux RISC-V syscall number for `riscv_hwprobe`.
    private static final int SYS_RISCV_HWPROBE = 258;

    /// The Linux RISC-V syscall number for `riscv_flush_icache`.
    private static final int SYS_RISCV_FLUSH_ICACHE = 259;

    /// The Linux RISC-V syscall number for `wait4`.
    private static final int SYS_WAIT4 = 260;

    /// The Linux RISC-V syscall number for `prlimit64`.
    private static final int SYS_PRLIMIT64 = 261;

    /// The Linux RISC-V syscall number for `fanotify_init`.
    private static final int SYS_FANOTIFY_INIT = 262;

    /// The Linux RISC-V syscall number for `fanotify_mark`.
    private static final int SYS_FANOTIFY_MARK = 263;

    /// The Linux RISC-V syscall number for `name_to_handle_at`.
    private static final int SYS_NAME_TO_HANDLE_AT = 264;

    /// The Linux RISC-V syscall number for `open_by_handle_at`.
    private static final int SYS_OPEN_BY_HANDLE_AT = 265;

    /// The Linux RISC-V syscall number for `syncfs`.
    private static final int SYS_SYNCFS = 267;

    /// The Linux RISC-V syscall number for `sendmmsg`.
    private static final int SYS_SENDMMSG = 269;

    /// The Linux RISC-V syscall number for `renameat2`.
    private static final int SYS_RENAMEAT2 = 276;

    /// The Linux RISC-V syscall number for `getrandom`.
    private static final int SYS_GETRANDOM = 278;

    /// The Linux RISC-V syscall number for `membarrier`.
    private static final int SYS_MEMBARRIER = 283;

    /// The Linux RISC-V syscall number for `mlock2`.
    private static final int SYS_MLOCK2 = 284;

    /// The Linux RISC-V syscall number for `copy_file_range`.
    private static final int SYS_COPY_FILE_RANGE = 285;

    /// The Linux RISC-V syscall number for `preadv2`.
    private static final int SYS_PREADV2 = 286;

    /// The Linux RISC-V syscall number for `pwritev2`.
    private static final int SYS_PWRITEV2 = 287;

    /// The Linux RISC-V syscall number for `statx`.
    private static final int SYS_STATX = 291;

    /// The Linux RISC-V syscall number for `rseq`.
    private static final int SYS_RSEQ = 293;

    /// The Linux RISC-V syscall number for `faccessat2`.
    private static final int SYS_FACCESSAT2 = 439;

    /// The Linux RISC-V syscall number for `epoll_pwait2`.
    private static final int SYS_EPOLL_PWAIT2 = 441;

    /// The Linux RISC-V syscall number for `fchmodat2`.
    private static final int SYS_FCHMODAT2 = 452;

    /// Executes the Linux syscall described by the guest argument registers at the supplied program counter.
    @Override
    public void handle(RiscVThreadState state, long pc) {
        long callNumber = state.register(17);
        if (callNumber != (int) callNumber) {
            throw new RiscVException(unsupportedEcallMessage(state, pc, callNumber));
        }

        long previousMask = state.enterSyscallPointerMask();
        try {
            switch ((int) callNumber) {
                case SYS_GETXATTR -> state.setRegister(10, getxattr(
                        state.register(10),
                        state.register(11),
                        state.register(12),
                        state.register(13),
                        true));
                case SYS_LGETXATTR -> state.setRegister(10, getxattr(
                        state.register(10),
                        state.register(11),
                        state.register(12),
                        state.register(13),
                        false));
                case SYS_FGETXATTR -> state.setRegister(10, fgetxattr(
                        (int) state.register(10),
                        state.register(11),
                        state.register(12),
                        state.register(13)));
                case SYS_LISTXATTR -> state.setRegister(10, listxattr(
                        state.register(10),
                        state.register(11),
                        state.register(12),
                        true));
                case SYS_LLISTXATTR -> state.setRegister(10, listxattr(
                        state.register(10),
                        state.register(11),
                        state.register(12),
                        false));
                case SYS_FLISTXATTR -> state.setRegister(10, flistxattr(
                        (int) state.register(10),
                        state.register(11),
                        state.register(12)));
                case SYS_GETCWD -> state.setRegister(10, getcwd(state.register(10), state.register(11)));
            case SYS_EVENTFD2 -> state.setRegister(10, eventfd2(state.register(10), state.register(11)));
            case SYS_EPOLL_CREATE1 -> state.setRegister(10, epollCreate1(state.register(10)));
            case SYS_EPOLL_CTL -> state.setRegister(10, epollCtl(
                    (int) state.register(10),
                    (int) state.register(11),
                    (int) state.register(12),
                    state.register(13)));
            case SYS_EPOLL_PWAIT -> state.setRegister(10, epollPwait(
                    state,
                    (int) state.register(10),
                    state.register(11),
                    (int) state.register(12),
                    (int) state.register(13),
                    state.register(14),
                    state.register(15)));
            case SYS_DUP -> state.setRegister(10, dup((int) state.register(10)));
            case SYS_DUP3 -> state.setRegister(10, dup3((int) state.register(10), (int) state.register(11), state.register(12)));
            case SYS_FCNTL -> state.setRegister(10, fcntl((int) state.register(10), state.register(11), state.register(12)));
            case SYS_IOCTL -> state.setRegister(10, ioctl((int) state.register(10), state.register(11), state.register(12)));
            case SYS_MKDIRAT -> state.setRegister(10, mkdirat(state.register(10), state.register(11), state.register(12)));
            case SYS_UNLINKAT -> state.setRegister(10, unlinkat(state.register(10), state.register(11), state.register(12)));
            case SYS_SYMLINKAT -> state.setRegister(10, symlinkat(
                    state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_LINKAT -> state.setRegister(10, linkat(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14)));
            case SYS_RENAMEAT -> state.setRegister(10, renameat(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_STATFS -> state.setRegister(10, statfs(state.register(10), state.register(11)));
            case SYS_FSTATFS -> state.setRegister(10, fstatfs((int) state.register(10), state.register(11)));
            case SYS_TRUNCATE -> state.setRegister(10, truncate(state.register(10), state.register(11)));
            case SYS_FTRUNCATE -> state.setRegister(10, ftruncate((int) state.register(10), state.register(11)));
            case SYS_FALLOCATE -> state.setRegister(10, fallocate(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_FACCESSAT -> state.setRegister(10, faccessat(state.register(10), state.register(11), state.register(12), 0));
            case SYS_CHDIR -> state.setRegister(10, chdir(state.register(10)));
            case SYS_FCHDIR -> state.setRegister(10, fchdir((int) state.register(10)));
            case SYS_FCHMOD -> state.setRegister(10, fchmod((int) state.register(10), state.register(11)));
            case SYS_FCHMODAT -> state.setRegister(10, fchmodat(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    0));
            case SYS_FCHOWNAT -> state.setRegister(10, fchownat(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14)));
            case SYS_FCHOWN -> state.setRegister(10, fchown(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_OPENAT -> state.setRegister(10, openat(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_CLOSE -> state.setRegister(10, close((int) state.register(10)));
            case SYS_PIPE2 -> state.setRegister(10, pipe2(state.register(10), state.register(11)));
            case SYS_GETDENTS64 -> state.setRegister(10, getdents64((int) state.register(10), state.register(11), state.register(12)));
            case SYS_LSEEK -> state.setRegister(10, lseek((int) state.register(10), state.register(11), (int) state.register(12)));
            case SYS_READ -> state.setRegister(10, read((int) state.register(10), state.register(11), state.register(12)));
            case SYS_WRITE -> state.setRegister(10, write((int) state.register(10), state.register(11), state.register(12)));
            case SYS_READV -> state.setRegister(10, readv((int) state.register(10), state.register(11), state.register(12)));
            case SYS_WRITEV -> state.setRegister(10, writev((int) state.register(10), state.register(11), state.register(12)));
            case SYS_PREAD64 -> state.setRegister(10, pread64(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_PWRITE64 -> state.setRegister(10, pwrite64(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_PREADV -> state.setRegister(10, preadv(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_PWRITEV -> state.setRegister(10, pwritev(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_PSELECT6 -> state.setRegister(10, pselect6(
                    state,
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14),
                    state.register(15)));
            case SYS_PPOLL -> state.setRegister(10, ppoll(
                    state,
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14)));
            case SYS_SPLICE -> state.setRegister(10, splice(
                    (int) state.register(10),
                    state.register(11),
                    (int) state.register(12),
                    state.register(13),
                    state.register(14),
                    state.register(15)));
            case SYS_READLINKAT -> state.setRegister(10, readlinkat(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_NEWFSTATAT -> state.setRegister(10, newfstatat(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_FSTAT -> state.setRegister(10, fstat((int) state.register(10), state.register(11)));
            case SYS_SYNC -> state.setRegister(10, sync());
            case SYS_FSYNC -> state.setRegister(10, fsync((int) state.register(10)));
            case SYS_FDATASYNC -> state.setRegister(10, fdatasync((int) state.register(10)));
            case SYS_TIMERFD_CREATE -> state.setRegister(10, timerfdCreate(state.register(10), state.register(11)));
            case SYS_TIMERFD_SETTIME -> state.setRegister(10, timerfdSettime(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_TIMERFD_GETTIME -> state.setRegister(10, timerfdGettime(
                    (int) state.register(10),
                    state.register(11)));
            case SYS_UTIMENSAT -> state.setRegister(10, utimensat(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_CAPGET -> state.setRegister(10, capget(state.register(10), state.register(11)));
            case SYS_CAPSET -> state.setRegister(10, capset(state.register(10), state.register(11)));
            case SYS_EXIT_GROUP -> {
                requestProcessExit(state.register(10));
                throw new ProgramExitException(state.register(10));
            }
            case SYS_EXIT -> exitThread(state, state.register(10));
            case SYS_WAITID -> state.setRegister(10, waitid(
                    state,
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14)));
            case SYS_SET_TID_ADDRESS -> state.setRegister(10, setTidAddress(state, state.register(10)));
            case SYS_FUTEX -> state.setRegister(10, futex(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14),
                    state.register(15)));
            case SYS_SET_ROBUST_LIST -> state.setRegister(10, setRobustList(state, state.register(10), state.register(11)));
            case SYS_GET_ROBUST_LIST -> state.setRegister(10, getRobustList(
                    state,
                    state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_NANOSLEEP -> state.setRegister(10, nanosleep(state.register(10), state.register(11)));
            case SYS_GETITIMER -> state.setRegister(10, getitimer(state.register(10), state.register(11)));
            case SYS_SETITIMER -> state.setRegister(10, setitimer(
                    state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_CLOCK_GETTIME -> state.setRegister(10, clockGettime(state.register(10), state.register(11)));
            case SYS_CLOCK_GETRES -> state.setRegister(10, clockGetres(state.register(10), state.register(11)));
            case SYS_CLOCK_NANOSLEEP -> state.setRegister(10, clockNanosleep(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_SCHED_SETPARAM -> state.setRegister(10, schedSetparam(state.register(10), state.register(11)));
            case SYS_SCHED_SETSCHEDULER -> state.setRegister(10, schedSetscheduler(
                    state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_SCHED_GETSCHEDULER -> state.setRegister(10, schedGetscheduler(state.register(10)));
            case SYS_SCHED_GETPARAM -> state.setRegister(10, schedGetparam(state.register(10), state.register(11)));
            case SYS_SCHED_SETAFFINITY -> state.setRegister(10, schedSetaffinity(
                    state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_SCHED_GETAFFINITY -> state.setRegister(10, schedGetaffinity(state.register(10), state.register(11), state.register(12)));
            case SYS_SCHED_YIELD -> state.setRegister(10, schedYield());
            case SYS_SCHED_GET_PRIORITY_MAX -> state.setRegister(10, schedGetPriorityMax(state.register(10)));
            case SYS_SCHED_GET_PRIORITY_MIN -> state.setRegister(10, schedGetPriorityMin(state.register(10)));
            case SYS_SCHED_RR_GET_INTERVAL -> state.setRegister(10, schedRrGetInterval(state.register(10), state.register(11)));
            case SYS_KILL -> state.setRegister(10, kill(state.register(10), state.register(11)));
            case SYS_TKILL -> state.setRegister(10, tkill(state.register(10), state.register(11)));
            case SYS_TGKILL -> state.setRegister(10, tgkill(state.register(10), state.register(11), state.register(12)));
            case SYS_SIGALTSTACK -> state.setRegister(10, sigaltstack(state, state.register(10), state.register(11)));
            case SYS_RT_SIGACTION -> state.setRegister(10, rtSigaction(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_RT_SIGPROCMASK -> state.setRegister(10, rtSigprocmask(
                    state,
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_RT_SIGRETURN -> rtSigreturn(state);
            case SYS_SETPRIORITY -> state.setRegister(10, setpriority(
                    state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_GETPRIORITY -> state.setRegister(10, getpriority(state.register(10), state.register(11)));
            case SYS_SETREGID -> state.setRegister(10, setresgid(
                    state.register(10),
                    state.register(11),
                    -1));
            case SYS_SETGID -> state.setRegister(10, setresgid(
                    state.register(10),
                    state.register(10),
                    state.register(10)));
            case SYS_SETREUID -> state.setRegister(10, setresuid(
                    state.register(10),
                    state.register(11),
                    -1));
            case SYS_SETUID -> state.setRegister(10, setresuid(
                    state.register(10),
                    state.register(10),
                    state.register(10)));
            case SYS_GETRESUID -> state.setRegister(10, getresid(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    credentials.realUserId(),
                    credentials.effectiveUserId(),
                    credentials.savedUserId()));
            case SYS_SETRESUID -> state.setRegister(10, setresuid(
                    state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_GETRESGID -> state.setRegister(10, getresid(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    credentials.realGroupId(),
                    credentials.effectiveGroupId(),
                    credentials.savedGroupId()));
            case SYS_SETRESGID -> state.setRegister(10, setresgid(
                    state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_SETFSUID -> state.setRegister(10, setfsid(
                    state.register(10),
                    credentials.effectiveUserId()));
            case SYS_SETFSGID -> state.setRegister(10, setfsid(
                    state.register(10),
                    credentials.effectiveGroupId()));
            case SYS_TIMES -> state.setRegister(10, times(state.register(10)));
            case SYS_SETPGID -> state.setRegister(10, setpgid(state.register(10), state.register(11)));
            case SYS_GETPGID -> state.setRegister(10, getpgid(state.register(10)));
            case SYS_GETSID -> state.setRegister(10, getsid(state.register(10)));
            case SYS_SETSID -> state.setRegister(10, setsid());
            case SYS_GETGROUPS -> state.setRegister(10, getgroups(state.register(10), state.register(11)));
            case SYS_SETGROUPS -> state.setRegister(10, setgroups(state.register(10), state.register(11)));
            case SYS_UNAME -> state.setRegister(10, uname(state.register(10)));
            case SYS_GETRLIMIT -> state.setRegister(10, getrlimit(state.register(10), state.register(11)));
            case SYS_SETRLIMIT -> state.setRegister(10, setrlimit(state.register(10), state.register(11)));
            case SYS_GETRUSAGE -> state.setRegister(10, getrusage(state.register(10), state.register(11)));
            case SYS_UMASK -> state.setRegister(10, umask(state.register(10)));
            case SYS_PRCTL -> state.setRegister(10, prctl(
                    state,
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14)));
            case SYS_GETCPU -> state.setRegister(10, getcpu(state.register(10), state.register(11)));
            case SYS_GETTIMEOFDAY -> state.setRegister(10, gettimeofday(state.register(10), state.register(11)));
            case SYS_GETPID -> state.setRegister(10, process.id());
            case SYS_GETTID -> state.setRegister(10, state.threadId());
            case SYS_GETPPID -> state.setRegister(10, process.parentId());
            case SYS_GETUID -> state.setRegister(10, credentials.realUserId());
            case SYS_GETEUID -> state.setRegister(10, credentials.effectiveUserId());
            case SYS_GETGID -> state.setRegister(10, credentials.realGroupId());
            case SYS_GETEGID -> state.setRegister(10, credentials.effectiveGroupId());
            case SYS_SYSINFO -> state.setRegister(10, sysinfo(state.register(10)));
            case SYS_SOCKET -> state.setRegister(10, socket(state.register(10), state.register(11), state.register(12)));
            case SYS_SOCKETPAIR -> state.setRegister(10, socketpair(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_BIND -> state.setRegister(10, bind(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_LISTEN -> state.setRegister(10, listen(
                    (int) state.register(10),
                    state.register(11)));
            case SYS_ACCEPT -> state.setRegister(10, accept(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    0));
            case SYS_CONNECT -> state.setRegister(10, connect(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_GETSOCKNAME -> state.setRegister(10, getsockname(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_GETPEERNAME -> state.setRegister(10, getpeername(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_SENDTO -> state.setRegister(10, sendto(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14),
                    state.register(15)));
            case SYS_RECVFROM -> state.setRegister(10, recvfrom(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14),
                    state.register(15)));
            case SYS_SETSOCKOPT -> state.setRegister(10, setsockopt(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14)));
            case SYS_GETSOCKOPT -> state.setRegister(10, getsockopt(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14)));
            case SYS_SHUTDOWN -> state.setRegister(10, shutdown(
                    (int) state.register(10),
                    state.register(11)));
            case SYS_SENDMSG -> state.setRegister(10, sendmsg(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_RECVMSG -> state.setRegister(10, recvmsg(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_RECVMMSG -> state.setRegister(10, recvmmsg(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14)));
            case SYS_SENDMMSG -> state.setRegister(10, sendmmsg(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_CLONE -> state.setRegister(10, clone(
                    state,
                    pc,
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14)));
            case SYS_FADVISE64 -> state.setRegister(10, posixFadvise(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_CLONE3 -> state.setRegister(10, clone3(
                    state,
                    pc,
                    state.register(10),
                    state.register(11)));
            case SYS_EXECVE -> state.setRegister(10, execve(
                    state,
                    state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_BRK -> state.setRegister(10, brk(state.register(10)));
            case SYS_MUNMAP -> state.setRegister(10, munmap(state.register(10), state.register(11)));
            case SYS_MREMAP -> state.setRegister(10, mremap(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14)));
            case SYS_MMAP -> state.setRegister(10, mmap(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14),
                    state.register(15)));
            case SYS_MPROTECT -> state.setRegister(10, mprotect(state.register(10), state.register(11), state.register(12)));
            case SYS_MSYNC -> state.setRegister(10, msync(state.register(10), state.register(11), state.register(12)));
            case SYS_MLOCK -> state.setRegister(10, mlock(state.register(10), state.register(11)));
            case SYS_MUNLOCK -> state.setRegister(10, munlock(state.register(10), state.register(11)));
            case SYS_MLOCKALL -> state.setRegister(10, mlockall(state.register(10)));
            case SYS_MUNLOCKALL -> state.setRegister(10, munlockall());
            case SYS_MINCORE -> state.setRegister(10, mincore(state.register(10), state.register(11), state.register(12)));
            case SYS_MADVISE -> state.setRegister(10, madvise(state.register(10), state.register(11), state.register(12)));
            case SYS_ACCEPT4 -> state.setRegister(10, accept(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_RISCV_HWPROBE -> state.setRegister(10, riscvHwprobe(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14),
                    state));
            case SYS_RISCV_FLUSH_ICACHE -> state.setRegister(10, riscvFlushIcache(
                    state,
                    state.register(10),
                    state.register(11),
                    state.register(12)));
            case SYS_WAIT4 -> state.setRegister(10, wait4(
                    state,
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_PRLIMIT64 -> state.setRegister(10, prlimit64(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_FANOTIFY_INIT,
                 SYS_FANOTIFY_MARK,
                 SYS_NAME_TO_HANDLE_AT,
                 SYS_OPEN_BY_HANDLE_AT -> state.setRegister(10, ENOSYS);
            case SYS_SYNCFS -> state.setRegister(10, syncfs((int) state.register(10)));
            case SYS_RENAMEAT2 -> state.setRegister(10, renameat2(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14)));
            case SYS_GETRANDOM -> state.setRegister(10, getrandom(state.register(10), state.register(11), state.register(12)));
            case SYS_MEMBARRIER -> state.setRegister(10, membarrier(state.register(10), state.register(11), state.register(12)));
            case SYS_MLOCK2 -> state.setRegister(10, mlock2(state.register(10), state.register(11), state.register(12)));
            case SYS_COPY_FILE_RANGE -> state.setRegister(10, copyFileRange(
                    (int) state.register(10),
                    state.register(11),
                    (int) state.register(12),
                    state.register(13),
                    state.register(14),
                    state.register(15)));
            case SYS_PREADV2 -> state.setRegister(10, preadv2(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14)));
            case SYS_PWRITEV2 -> state.setRegister(10, pwritev2(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14)));
            case SYS_STATX -> state.setRegister(10, statx(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13),
                    state.register(14)));
            case SYS_RSEQ -> state.setRegister(10, rseq(
                    state,
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_FACCESSAT2 -> state.setRegister(10, faccessat(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_EPOLL_PWAIT2 -> state.setRegister(10, epollPwait2(
                    state,
                    (int) state.register(10),
                    state.register(11),
                    (int) state.register(12),
                    state.register(13),
                    state.register(14),
                    state.register(15)));
            case SYS_FCHMODAT2 -> state.setRegister(10, fchmodat(
                    state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_PIDFD_SEND_SIGNAL -> state.setRegister(10, pidfdSendSignal(
                    (int) state.register(10),
                    state.register(11),
                    state.register(12),
                    state.register(13)));
            case SYS_PIDFD_OPEN -> state.setRegister(10, pidfdOpen(
                    state.register(10),
                    state.register(11)));
            case SYS_CLOSE_RANGE -> state.setRegister(10, closeRange(
                    state.register(10),
                    state.register(11),
                    state.register(12)));
                default -> throw new RiscVException(unsupportedEcallMessage(state, pc, callNumber));
            }
        } finally {
            state.restorePointerMask(previousMask);
        }
        deliverPendingChildSignal(state, pc);
    }

    /// Creates a child-process Linux syscall handler.
    @Override
    protected GuestSyscalls createChildSyscalls(Memory childMemory, GuestProcess childProcess) {
        return new LinuxGuestSyscalls(this, childMemory, childProcess);
    }

    /// Stores a validated Linux capability syscall header.
    ///
    /// @param version the capability ABI version supplied by the guest
    /// @param processId the target process id supplied by the guest
    /// @param result the raw Linux syscall result for header validation
    @NotNullByDefault
    protected record CapabilityHeader(int version, int processId, long result) {
    }

    /// Linux RISC-V kernel signal action state.
    protected record SignalAction(long handler, long flags, long mask) {
    }
}
