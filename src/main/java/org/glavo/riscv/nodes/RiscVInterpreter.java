// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.riscv.nodes;

import org.glavo.riscv.RiscVContext;
import org.glavo.riscv.exception.IllegalInstructionException;
import org.glavo.riscv.exception.MemoryAccessException;
import org.glavo.riscv.exception.ProcessImageReplacedException;
import org.glavo.riscv.exception.ProgramExitException;
import org.glavo.riscv.exception.RiscVException;
import org.glavo.riscv.exception.ThreadExitException;
import org.glavo.riscv.memory.Memory;
import org.glavo.riscv.memory.MemoryAccess;
import org.glavo.riscv.memory.MemoryLayout;
import org.glavo.riscv.parser.DecodedBlock;
import org.glavo.riscv.parser.DecodedInstruction;
import org.glavo.riscv.parser.ElfImage;
import org.glavo.riscv.parser.ElfLoader;
import org.glavo.riscv.parser.RiscVDecoder;
import org.glavo.riscv.parser.RiscVOperation;
import org.glavo.riscv.runtime.FreeBsdGuestSyscalls;
import org.glavo.riscv.runtime.GuestAbi;
import org.glavo.riscv.runtime.GuestCredentials;
import org.glavo.riscv.runtime.GuestSyscalls;
import org.glavo.riscv.runtime.LinuxInitialStack;
import org.glavo.riscv.runtime.LinuxGuestSyscalls;
import org.glavo.riscv.runtime.LinuxProgramLoader;
import org.glavo.riscv.runtime.RiscVThreadState;
import org.glavo.riscv.runtime.fs.GuestFileSystem;
import org.glavo.riscv.runtime.fs.GuestFileSystem.TarNode;
import org.glavo.riscv.runtime.fs.GuestFileSystem.TarPath;
import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Unmodifiable;

import java.util.ArrayList;

/// Executes one loaded RISC-V ELF image.
@NotNullByDefault
public final class RiscVInterpreter {
    /// The initial Linux user stack backing size.
    private static final long INITIAL_STACK_SIZE = 8L * 1024L * 1024L;

    /// The deterministic base address used for guest-loaded position-independent executables.
    private static final long DYNAMIC_EXECUTABLE_BASE = 0x0040_0000L;

    /// The alignment used when assigning load bias values to `ET_DYN` images.
    private static final long DYNAMIC_LOAD_ALIGNMENT = 0x0020_0000L;

    /// The Linux `S_ISUID` special mode bit.
    private static final int STAT_MODE_SET_USER_ID = 04000;

    /// The Linux `S_ISGID` special mode bit.
    private static final int STAT_MODE_SET_GROUP_ID = 02000;

    /// The host-supplied source bytes, or an empty array when the executable is read from guest mounts.
    private final byte @Unmodifiable [] sourceBytes;

    /// The lazily populated block cache for this execution root.
    private final BlockCache blocks;

    /// The decoded block and trace dispatch state for this execution root.
    private final BlockDispatchNode dispatch;

    /// The PC-indexed segment fast dispatch state for this execution root.
    private final SegmentDispatchNode segmentDispatch;

    /// Creates a runner for a RISC-V ELF source.
    public RiscVInterpreter(byte @Unmodifiable [] sourceBytes) {
        this.sourceBytes = sourceBytes.clone();
        this.blocks = new BlockCache();
        this.dispatch = new BlockDispatchNode(blocks);
        this.segmentDispatch = new SegmentDispatchNode();
    }

    /// Executes the guest program and returns its exit code.
    public int execute(RiscVContext context) {
        LoadedProgram program = loadProgram(context);
        try (Memory memory = Memory.sparse(
                resolveMemoryBase(context, program),
                context.memorySize(),
                context.pageSize(),
                context.maxCommittedPages(),
                context.hugePageSize(),
                context.hugePages())) {
            RiscVThreadState state = createState(context, memory, program);
            try {
                return executeGuestLoop(memory, state);
            } catch (ProgramExitException exit) {
                state.syscalls().requestProcessExit(exit.exitCode());
                state.syscalls().recordThreadExit(state, exit.exitCode());
                return (int) exit.exitCode();
            } catch (RuntimeException | Error throwable) {
                state.syscalls().requestProcessExit(1);
                throw throwable;
            } finally {
                state.syscalls().joinGuestThreads();
                state.syscalls().close();
            }
        }
    }

    /// Runs the decoded-block dispatch loop for an initialized guest state.
    private int executeGuestLoop(Memory memory, RiscVThreadState state) {
        while (true) {
            try {
                executeDispatchLoop(new GuestLoopState(memory, state, state.pc()));
                throw new AssertionError("Guest loop returned without an exit signal");
            } catch (ProcessImageReplacedException ignored) {
                continue;
            } catch (ThreadExitException exit) {
                return (int) state.syscalls().completeThreadExit(state, exit.exitCode());
            } catch (IllegalInstructionException exception) {
                if (state.syscalls().handleIllegalInstruction(state, exception)) {
                    continue;
                }
                throw withGuestContext(exception, state);
            } catch (MemoryAccessException exception) {
                if (state.syscalls().handleMemoryAccess(state, exception)) {
                    continue;
                }
                throw withGuestContext(exception, state);
            } catch (RiscVException exception) {
                throw withGuestContext(exception, state);
            }
        }
    }

    /// Runs one clone-created guest thread on its host thread.
    private void runGuestThread(Memory memory, RiscVThreadState state) {
        try {
            executeGuestThreadLoop(memory, state);
        } catch (ThreadExitException exit) {
            state.syscalls().recordThreadExit(state, exit.exitCode());
        } catch (ProgramExitException exit) {
            state.syscalls().requestProcessExit(exit.exitCode());
            state.syscalls().recordThreadExit(state, exit.exitCode());
        } catch (Throwable throwable) {
            state.syscalls().recordThreadFailure(throwable);
            state.syscalls().recordThreadExit(state, 1);
        }
    }

    /// Runs the decoded-block dispatch loop for a clone-created guest thread.
    private void executeGuestThreadLoop(Memory memory, RiscVThreadState state) {
        while (true) {
            try {
                executeDispatchLoop(new GuestLoopState(memory, state, state.pc()));
                throw new AssertionError("Guest loop returned without an exit signal");
            } catch (ProcessImageReplacedException ignored) {
                continue;
            } catch (IllegalInstructionException exception) {
                if (state.syscalls().handleIllegalInstruction(state, exception)) {
                    continue;
                }
                throw withGuestContext(exception, state);
            } catch (MemoryAccessException exception) {
                if (state.syscalls().handleMemoryAccess(state, exception)) {
                    continue;
                }
                throw withGuestContext(exception, state);
            } catch (RiscVException exception) {
                throw withGuestContext(exception, state);
            }
        }
    }

    /// Runs guest blocks until the guest exits by throwing an execution-control exception.
    private void executeDispatchLoop(GuestLoopState loopState) {
        while (true) {
            loopState.syscalls().checkProcessStatus();
            loopState.refreshMemoryAccess();
            long pc = segmentDispatch.execute(loopState, loopState.state(), dispatch);
            loopState.setPc(pc);
        }
    }

    /// Adds the current architectural state to an unexpected guest failure.
    private static RiscVException withGuestContext(RiscVException exception, RiscVThreadState state) {
        String message = exception.getMessage();
        if (message != null && message.contains("Guest execution context:")) {
            return exception;
        }
        return new RiscVException(
                (message == null ? "Guest execution failed" : message)
                        + "\nGuest execution context: "
                        + state.formatExecutionContext(),
                exception);
    }

    /// Loads the main executable and its optional dynamic interpreter before guest memory is created.
    private LoadedProgram loadProgram(RiscVContext context) {
        GuestFileSystem fileSystem = GuestFileSystem.forMountSpecs(context.filesystemMounts());
        LinuxProgramLoader.ResolvedExecutable resolvedExecutable = LinuxProgramLoader.resolveExecutable(
                readExecutableBytes(context, fileSystem),
                context.guestProgramPath(),
                fileSystem,
                context.programArguments());
        ElfImage executable = ElfLoader.load(resolvedExecutable.executableBytes());
        GuestAbi abi = GuestAbi.fromElfOperatingSystem(executable.operatingSystem());
        LoadedImage loadedExecutable = loadImage(executable, DYNAMIC_EXECUTABLE_BASE, context.pageSize());
        GuestCredentials credentials = credentialsForInitialExec(
                context.guestCredentials(),
                fileSystem,
                resolvedExecutable.executablePath());
        @Nullable LoadedImage loadedInterpreter = null;
        @Nullable String interpreterPath = executable.interpreterPath();
        if (interpreterPath != null) {
            byte[] interpreterBytes = fileSystem.readFile(interpreterPath);
            ElfImage interpreter = ElfLoader.load(interpreterBytes);
            if (interpreter.hasInterpreter()) {
                throw new RiscVException("ELF interpreter must not request another interpreter: " + interpreterPath);
            }
            if (interpreter.operatingSystem() != executable.operatingSystem()) {
                throw new RiscVException("ELF interpreter OS ABI does not match executable: " + interpreterPath);
            }
            loadedInterpreter = loadImage(
                    interpreter,
                    alignUp(
                            Math.max(loadedExecutable.endAddress(), DYNAMIC_EXECUTABLE_BASE) + DYNAMIC_LOAD_ALIGNMENT,
                            DYNAMIC_LOAD_ALIGNMENT),
                    context.pageSize());
        }
        return new LoadedProgram(
                loadedExecutable,
                loadedInterpreter,
                resolvedExecutable.executablePath(),
                credentials,
                abi,
                resolvedExecutable.arguments());
    }

    /// Returns initial process credentials after applying tar setuid and setgid executable metadata.
    private static GuestCredentials credentialsForInitialExec(
            GuestCredentials credentials,
            GuestFileSystem fileSystem,
            @Nullable String executablePath) {
        if (executablePath == null) {
            return credentials.withExecEffectiveIds(credentials.effectiveUserId(), credentials.effectiveGroupId());
        }

        @Nullable TarPath tarPath = fileSystem.resolveTarPath(executablePath, true);
        @Nullable TarNode node = tarPath == null ? null : tarPath.node();
        if (node == null || !node.isFile()) {
            return credentials.withExecEffectiveIds(credentials.effectiveUserId(), credentials.effectiveGroupId());
        }

        long effectiveUserId = credentials.effectiveUserId();
        long effectiveGroupId = credentials.effectiveGroupId();
        if ((node.permissions() & STAT_MODE_SET_USER_ID) != 0) {
            effectiveUserId = node.userId();
        }
        if ((node.permissions() & STAT_MODE_SET_GROUP_ID) != 0) {
            effectiveGroupId = node.groupId();
        }
        return credentials.withExecEffectiveIds(effectiveUserId, effectiveGroupId);
    }

    /// Reads executable bytes from the source or from the configured guest filesystem mounts.
    private byte @Unmodifiable [] readExecutableBytes(RiscVContext context, GuestFileSystem fileSystem) {
        @Nullable String guestProgramPath = context.guestProgramPath();
        if (guestProgramPath == null) {
            return sourceBytes.clone();
        }
        return fileSystem.readFile(guestProgramPath);
    }

    /// Assigns a load bias to an ELF image.
    private static LoadedImage loadImage(ElfImage image, long requestedBase, long pageSize) {
        long loadBias = 0;
        if (image.isPositionIndependent()) {
            long minimumAddress = imageMinimumAddress(image);
            loadBias = alignUp(requestedBase, pageSize) - alignDown(minimumAddress, pageSize);
        }
        return new LoadedImage(image, loadBias);
    }

    /// Returns the lowest virtual address covered by a loadable image segment.
    private static long imageMinimumAddress(ElfImage image) {
        long minimumAddress = Long.MAX_VALUE;
        for (ElfImage.LoadSegment segment : image.loadSegments()) {
            minimumAddress = Math.min(minimumAddress, segment.virtualAddress());
        }
        if (minimumAddress == Long.MAX_VALUE) {
            throw new RiscVException("ELF image contains no PT_LOAD segments");
        }
        return minimumAddress;
    }

    /// Creates and initializes architectural state for a guest run.
    private RiscVThreadState createState(RiscVContext context, Memory memory, LoadedProgram program) {
        long initialProgramBreak = memory.baseAddress();
        ArrayList<ProtectionRange> protectionRanges = new ArrayList<>();
        for (LoadedImage loadedImage : program.images()) {
            for (ElfImage.LoadSegment segment : loadedImage.image().loadSegments()) {
                if (segment.memorySize() == 0) {
                    continue;
                }
                long runtimeAddress = loadedImage.runtimeAddress(segment.virtualAddress());
                long pageStart = alignDown(runtimeAddress, context.pageSize());
                long pageEnd = alignUp(runtimeAddress + segment.memorySize(), context.pageSize());
                long pageLength = pageEnd - pageStart;
                validateGuestRange(memory, pageStart, pageLength);
                if (!memory.hasDenseInitialBacking()) {
                    mapLoadSegment(memory, pageStart, pageLength);
                }
                addProtectionRange(protectionRanges, pageStart, pageEnd, segmentProtection(segment));
            }
        }

        for (LoadedImage loadedImage : program.images()) {
            for (ElfImage.LoadSegment segment : loadedImage.image().loadSegments()) {
                if (segment.memorySize() == 0) {
                    continue;
                }
                long runtimeAddress = loadedImage.runtimeAddress(segment.virtualAddress());
                long contentsLength = segment.contents().length;
                memory.load(runtimeAddress, segment.contents(), 0, (int) contentsLength);
                if (segment.memorySize() > contentsLength) {
                    memory.clear(runtimeAddress + contentsLength, segment.memorySize() - contentsLength);
                }
                initialProgramBreak = Math.max(
                        initialProgramBreak,
                        Math.min(alignUp(runtimeAddress + segment.memorySize(), 16), memory.endAddress()));
            }
        }

        for (ProtectionRange range : protectionRanges) {
            if (!memory.protect(range.startAddress(), range.endAddress() - range.startAddress(), range.protection())) {
                throw new RiscVException("Failed to protect ELF segment page range: segment="
                        + formatRange(range.startAddress(), range.endAddress()));
            }
        }

        GuestSyscalls syscalls = createSyscalls(context, memory, initialProgramBreak, program.credentials(), program.abi());
        long stackPointer = initializeLinuxStack(memory, context, program);
        syscalls.recordInitialAuxiliaryVector(stackPointer);
        RiscVThreadState state = new RiscVThreadState(
                memory,
                context.maxInstructions(),
                context.trace(),
                program.executable().runtimeOptionalAddress(program.executable().image().tohostAddress()),
                program.executable().runtimeOptionalAddress(program.executable().image().fromhostAddress()),
                syscalls,
                context.err(),
                context.vectorVlenBits());
        state.setPc(program.entryPoint());
        state.setRegister(2, stackPointer);
        if (program.abi() == GuestAbi.FREEBSD) {
            state.setRegister(10, stackPointer);
        }
        return state;
    }

    /// Creates the syscall handler selected by the loaded executable ABI.
    private GuestSyscalls createSyscalls(
            RiscVContext context,
            Memory memory,
            long initialProgramBreak,
            GuestCredentials credentials,
            GuestAbi abi) {
        return switch (abi) {
            case LINUX -> new LinuxGuestSyscalls(
                    memory,
                    context.in(),
                    context.out(),
                    context.err(),
                    initialProgramBreak,
                    context.filesystemMounts(),
                    context.timeSource(),
                    context.useHostTty(),
                    credentials,
                    this::runGuestThread,
                    context.framebufferDevice(),
                    context.networkBackend());
            case FREEBSD -> new FreeBsdGuestSyscalls(
                    memory,
                    context.in(),
                    context.out(),
                    context.err(),
                    initialProgramBreak,
                    context.filesystemMounts(),
                    context.timeSource(),
                    context.useHostTty(),
                    credentials,
                    this::runGuestThread,
                    context.framebufferDevice(),
                    context.networkBackend());
        };
    }

    /// Adds explicit backing for one ELF load segment.
    private static void mapLoadSegment(Memory memory, long runtimeAddress, long memorySize) {
        if (memorySize == 0) {
            return;
        }
        int pageSize = memory.pageSize();
        long endAddress = runtimeAddress + memorySize;
        for (long pageAddress = runtimeAddress; pageAddress < endAddress; pageAddress += pageSize) {
            long pageLength = Math.min(pageSize, endAddress - pageAddress);
            if (memory.isBacked(pageAddress, pageLength)) {
                continue;
            }
            if (!memory.map(pageAddress, pageLength)) {
                throw new RiscVException("ELF segment overlaps another guest memory region: segment="
                        + formatRange(runtimeAddress, runtimeAddress + memorySize)
                        + ", memory=" + formatRange(memory.baseAddress(), memory.endAddress()));
            }
        }
    }

    /// Adds one page-aligned ELF protection range, unioning permissions across overlapped segment pages.
    private static void addProtectionRange(
            ArrayList<ProtectionRange> ranges,
            long startAddress,
            long endAddress,
            long protection) {
        if (startAddress == endAddress) {
            return;
        }

        ArrayList<Long> boundaries = new ArrayList<>(2 + ranges.size() * 2);
        boundaries.add(startAddress);
        boundaries.add(endAddress);
        for (ProtectionRange range : ranges) {
            boundaries.add(range.startAddress());
            boundaries.add(range.endAddress());
        }
        boundaries.sort(Long::compare);

        ArrayList<ProtectionRange> updated = new ArrayList<>(boundaries.size());
        @Nullable Long previousBoundary = null;
        for (long boundary : boundaries) {
            if (previousBoundary == null) {
                previousBoundary = boundary;
                continue;
            }
            long intervalStart = previousBoundary;
            long intervalEnd = boundary;
            previousBoundary = boundary;
            if (intervalStart == intervalEnd) {
                continue;
            }

            long intervalProtection = 0;
            if (intervalStart >= startAddress && intervalEnd <= endAddress) {
                intervalProtection |= protection;
            }
            for (ProtectionRange range : ranges) {
                if (intervalStart >= range.startAddress() && intervalEnd <= range.endAddress()) {
                    intervalProtection |= range.protection();
                }
            }
            appendProtectionRange(updated, intervalStart, intervalEnd, intervalProtection);
        }

        ranges.clear();
        ranges.addAll(updated);
    }

    /// Appends one protection range, merging adjacent intervals with identical permissions.
    private static void appendProtectionRange(
            ArrayList<ProtectionRange> ranges,
            long startAddress,
            long endAddress,
            long protection) {
        if (protection == Memory.PROTECTION_NONE) {
            return;
        }

        int lastIndex = ranges.size() - 1;
        if (lastIndex >= 0) {
            ProtectionRange last = ranges.get(lastIndex);
            if (last.endAddress() == startAddress && last.protection() == protection) {
                ranges.set(lastIndex, new ProtectionRange(last.startAddress(), endAddress, protection));
                return;
            }
        }
        ranges.add(new ProtectionRange(startAddress, endAddress, protection));
    }

    /// Stores one page-aligned memory protection range.
    ///
    /// @param startAddress inclusive guest start address
    /// @param endAddress exclusive guest end address
    /// @param protection combined `Memory.PROTECTION_*` flags
    @NotNullByDefault
    private record ProtectionRange(long startAddress, long endAddress, long protection) {
    }

    /// Initializes the Linux user stack at the top of the contiguous guest memory segment.
    private long initializeLinuxStack(Memory memory, RiscVContext context, LoadedProgram program) {
        if (memory.hasDenseInitialBacking()) {
            return LinuxInitialStack.initialize(
                    memory,
                    memory.endAddress(),
                    program.arguments(),
                    program.executable().image(),
                    program.executable().loadBias(),
                    program.interpreterBase(),
                    program.executablePath(),
                    context.initialEnvironment(),
                    program.credentials(),
                    context.pageSize());
        }

        long stackTop = memory.endAddress();
        long stackSize = Math.min(INITIAL_STACK_SIZE, memory.size());
        long stackBase = alignDown(stackTop - stackSize, context.pageSize());
        if (stackBase < memory.baseAddress()) {
            stackBase = memory.baseAddress();
        }
        long stackLength = stackTop - stackBase;
        if (stackLength <= 0 || !memory.map(stackBase, stackLength)) {
            throw new RiscVException("Failed to allocate guest stack backing: stack="
                    + formatRange(stackBase, stackTop)
                    + ", memory=" + formatRange(memory.baseAddress(), memory.endAddress()));
        }
        return LinuxInitialStack.initialize(
                memory,
                stackTop,
                program.arguments(),
                program.executable().image(),
                program.executable().loadBias(),
                program.interpreterBase(),
                program.executablePath(),
                context.initialEnvironment(),
                program.credentials(),
                context.pageSize());
    }

    /// Resolves the memory base from context options or the lowest ELF load segment address.
    private long resolveMemoryBase(RiscVContext context, LoadedProgram program) {
        if (context.memoryBase() != RiscVContext.AUTO_MEMORY_BASE) {
            return context.memoryBase();
        }

        long baseAddress = Long.MAX_VALUE;
        for (LoadedImage loadedImage : program.images()) {
            for (ElfImage.LoadSegment segment : loadedImage.image().loadSegments()) {
                baseAddress = Math.min(baseAddress, loadedImage.runtimeAddress(segment.virtualAddress()));
            }
        }
        return baseAddress == Long.MAX_VALUE ? Memory.DEFAULT_BASE_ADDRESS : baseAddress;
    }

    /// Converts ELF segment flags into guest memory protection bits.
    private static long segmentProtection(ElfImage.LoadSegment segment) {
        long protection = 0;
        if ((segment.flags() & 0x4) != 0) {
            protection |= Memory.PROTECTION_READ;
        }
        if ((segment.flags() & 0x2) != 0) {
            protection |= Memory.PROTECTION_WRITE;
        }
        if ((segment.flags() & 0x1) != 0) {
            protection |= Memory.PROTECTION_EXECUTE;
        }
        return protection;
    }

    /// Ensures a loaded ELF segment fits in guest memory.
    private static void validateGuestRange(Memory memory, long address, long length) {
        if (length < 0) {
            throw new RiscVException(memoryLayoutError(
                    memory,
                    "segment length is negative",
                    address,
                    address,
                    length));
        }

        if (address > Long.MAX_VALUE - length) {
            throw new RiscVException("ELF segment is outside guest memory: reason=segment range overflows, "
                    + "segmentStart=" + formatHex(address)
                    + ", length=" + length
                    + ", memory=" + formatRange(memory.baseAddress(), memory.endAddress())
                    + ", memorySize=" + memory.size()
                    + "; use --memory-base auto or choose a lower --memory-base value");
        }

        long endAddress = address + length;
        if (address < memory.baseAddress() || endAddress > memory.endAddress()) {
            throw new RiscVException(memoryLayoutError(
                    memory,
                    memoryLayoutReason(memory, address, endAddress),
                    address,
                    endAddress,
                    length));
        }
    }

    /// Builds a guest memory layout error with range details and CLI hints.
    private static String memoryLayoutError(
            Memory memory,
            String reason,
            long segmentAddress,
            long segmentEndAddress,
            long segmentLength) {
        return "ELF segment is outside guest memory: reason=" + reason
                + ", segment=" + formatRange(segmentAddress, segmentEndAddress)
                + ", length=" + segmentLength
                + ", memory=" + formatRange(memory.baseAddress(), memory.endAddress())
                + ", memorySize=" + memory.size()
                + memoryLayoutHint(memory, segmentAddress, segmentEndAddress);
    }

    /// Describes which side of the guest memory range rejected a segment.
    private static String memoryLayoutReason(Memory memory, long segmentAddress, long segmentEndAddress) {
        boolean startsBeforeMemory = segmentAddress < memory.baseAddress();
        boolean exceedsMemoryEnd = segmentEndAddress > memory.endAddress();
        if (startsBeforeMemory && exceedsMemoryEnd) {
            return "segment starts before guest memory and exceeds guest memory end";
        }
        if (startsBeforeMemory) {
            return "segment starts before guest memory";
        }
        return "segment exceeds guest memory end";
    }

    /// Builds an actionable CLI hint for an invalid guest memory layout.
    private static String memoryLayoutHint(Memory memory, long segmentAddress, long segmentEndAddress) {
        StringBuilder hint = new StringBuilder();
        if (segmentAddress < memory.baseAddress()) {
            hint.append("; Use --memory-base auto or set --memory-base ").append(formatHex(segmentAddress));
        }

        if (segmentEndAddress > memory.endAddress()) {
            if (hint.isEmpty()) {
                hint.append("; Increase --memory-size");
            } else {
                hint.append("; with that base, use --memory-size");
            }

            long requiredBaseAddress = Math.min(segmentAddress, memory.baseAddress());
            long requiredSize = segmentEndAddress - requiredBaseAddress;
            hint.append(" to at least ").append(requiredSize).append(" bytes");
        }

        return hint.toString();
    }

    /// Formats an unsigned guest address as a lowercase hexadecimal string.
    private static String formatHex(long value) {
        return "0x" + Long.toUnsignedString(value, 16);
    }

    /// Formats an address range with an inclusive start and exclusive end.
    private static String formatRange(long startAddress, long endAddress) {
        return "[" + formatHex(startAddress) + "," + formatHex(endAddress) + ")";
    }

    /// Rounds an address up to the requested power-of-two alignment.
    private static long alignUp(long address, long alignment) {
        long mask = alignment - 1;
        if (address > Long.MAX_VALUE - mask) {
            return address;
        }
        return (address + mask) & ~mask;
    }

    /// Rounds an address down to the requested power-of-two alignment.
    private static long alignDown(long address, long alignment) {
        return address & -alignment;
    }

    /// Describes the fully load-biased program images that form one process startup.
    ///
    /// @param executable the main executable image
    /// @param interpreter the optional dynamic interpreter image
    /// @param executablePath the guest executable path used for `AT_EXECFN`, or null for host-loaded programs
    /// @param credentials the Linux credentials exposed to the initial process image
    /// @param abi the guest syscall ABI selected from the main executable
    /// @param arguments the argument vector exposed to the loaded image
    @NotNullByDefault
    private record LoadedProgram(
            LoadedImage executable,
            @Nullable LoadedImage interpreter,
            @Nullable String executablePath,
            GuestCredentials credentials,
            GuestAbi abi,
            String @Unmodifiable [] arguments) {
        /// Creates a loaded program snapshot.
        private LoadedProgram {
            arguments = arguments.clone();
        }

        /// Returns a copy of the argument vector exposed to the loaded image.
        @Override
        public String @Unmodifiable [] arguments() {
            return arguments.clone();
        }

        /// Returns the images that must be mapped before execution starts.
        private LoadedImage @Unmodifiable [] images() {
            return interpreter == null
                    ? new LoadedImage[]{executable}
                    : new LoadedImage[]{executable, interpreter};
        }

        /// Returns the initial program counter.
        private long entryPoint() {
            return interpreter == null ? executable.runtimeEntryPoint() : interpreter.runtimeEntryPoint();
        }

        /// Returns the interpreter load base exposed through `AT_BASE`, or `ABSENT_ADDRESS` for static programs.
        private long interpreterBase() {
            return interpreter == null ? ElfImage.ABSENT_ADDRESS : interpreter.loadBias();
        }
    }

    /// Describes one ELF image after applying its process load bias.
    ///
    /// @param image the parsed ELF image
    /// @param loadBias the additive address load bias used for this image
    @NotNullByDefault
    private record LoadedImage(ElfImage image, long loadBias) {
        /// Returns a load-biased runtime address.
        private long runtimeAddress(long address) {
            return address + loadBias;
        }

        /// Returns a load-biased optional runtime address.
        private long runtimeOptionalAddress(long address) {
            return address == ElfImage.ABSENT_ADDRESS ? ElfImage.ABSENT_ADDRESS : runtimeAddress(address);
        }

        /// Returns the runtime entry point.
        private long runtimeEntryPoint() {
            return runtimeAddress(image.entryPoint());
        }

        /// Returns the exclusive end of the highest loaded segment.
        private long endAddress() {
            long endAddress = 0;
            for (ElfImage.LoadSegment segment : image.loadSegments()) {
                endAddress = Math.max(endAddress, runtimeAddress(segment.virtualAddress()) + segment.memorySize());
            }
            return endAddress;
        }
    }

    /// Holds per-thread guest loop state while a host loop is executing.
    @NotNullByDefault
    private static final class GuestLoopState {
        /// Number of entries in the thread-local decoded-block lookup cache.
        private static final int LOCAL_BLOCK_CACHE_SIZE = 16;

        /// Number of entries in the thread-local decoded-segment lookup cache.
        private static final int LOCAL_SEGMENT_CACHE_SIZE = 64;

        /// The guest memory shared by the process.
        private final Memory memory;

        /// The immutable guest memory page layout for this loop.
        private final MemoryLayout memoryLayout;

        /// The architectural state for the running guest thread.
        private final RiscVThreadState state;

        /// The syscall handler shared by all guest threads in this process.
        private final GuestSyscalls syscalls;

        /// The execution policy shared by decoded blocks in this guest loop.
        private final byte executionPolicy;

        /// Reusable memory access facade for this host thread.
        private final MemoryAccess access;

        /// The next guest program counter to dispatch.
        private long pc;

        /// Guest PCs cached in `localBlocks`.
        private final long[] localBlockPcs = new long[LOCAL_BLOCK_CACHE_SIZE];

        /// Instruction-fetch generations cached in `localBlocks`.
        private final long[] localBlockGenerations = new long[LOCAL_BLOCK_CACHE_SIZE];

        /// Thread-local decoded block entries used before probing the shared cache.
        private final @Nullable BlockEntry[] localBlocks = new BlockEntry[LOCAL_BLOCK_CACHE_SIZE];

        /// Thread-local decoded page segments.
        private final @Nullable DecodedCodeSegment[] localSegments = new DecodedCodeSegment[LOCAL_SEGMENT_CACHE_SIZE];

        /// Reusable result container for segment fast-slice dispatch.
        private final DecodedCodeSegment.FastSliceResult fastSliceResult = new DecodedCodeSegment.FastSliceResult();

        /// Creates loop-local state for one guest thread.
        private GuestLoopState(Memory memory, RiscVThreadState state, long pc) {
            this.memory = memory;
            this.memoryLayout = memory.layout();
            this.state = state;
            this.syscalls = state.syscalls();
            this.executionPolicy = executionPolicy(state);
            this.access = memory.newAccess();
            this.pc = pc;
        }

        /// Returns the guest memory shared by the process.
        private Memory memory() {
            return memory;
        }

        /// Returns the immutable guest memory page layout for this loop.
        private MemoryLayout memoryLayout() {
            return memoryLayout;
        }

        /// Returns the architectural state for the running guest thread.
        private RiscVThreadState state() {
            return state;
        }

        /// Returns the syscall handler shared by all guest threads in this process.
        private GuestSyscalls syscalls() {
            return syscalls;
        }

        /// Returns the decoded-block execution policy for this guest loop.
        private byte executionPolicy() {
            return executionPolicy;
        }

        /// Returns the reusable memory access facade for decoded block execution.
        private MemoryAccess access() {
            return access;
        }

        /// Returns the reusable segment fast-slice result container.
        private DecodedCodeSegment.FastSliceResult fastSliceResult() {
            return fastSliceResult;
        }

        /// Refreshes memory generation-sensitive caches before dispatching another guest block.
        private void refreshMemoryAccess() {
            access.refreshGeneration();
        }

        /// Returns the next guest program counter to dispatch.
        private long pc() {
            return pc;
        }

        /// Updates the next guest program counter to dispatch.
        private void setPc(long pc) {
            this.pc = pc;
        }

        /// Returns the decoded block target for the current program counter.
        private BlockEntry blockFor(BlockCache blocks) {
            int slot = localBlockSlot(pc);
            long instructionFetchGeneration = state.instructionFetchGeneration();
            BlockEntry block = localBlocks[slot];
            if (block != null && localBlockPcs[slot] == pc && block.executionPolicy() == executionPolicy) {
                if (localBlockGenerations[slot] == instructionFetchGeneration) {
                    return block;
                }
            }

            block = blocks.getOrDecode(memory, pc, memoryLayout, executionPolicy, instructionFetchGeneration);
            localBlockPcs[slot] = pc;
            localBlockGenerations[slot] = instructionFetchGeneration;
            localBlocks[slot] = block;
            return block;
        }

        /// Returns a decoded segment for the supplied PC, replacing the local cache on a miss.
        private DecodedCodeSegment segmentFor(long pc, long instructionFetchGeneration) {
            int slot = localSegmentSlot(pc, memoryLayout);
            @Nullable DecodedCodeSegment segment = localSegments[slot];
            if (segment == null || !segment.matches(pc, memoryLayout, instructionFetchGeneration)) {
                segment = new DecodedCodeSegment(memory, pc, instructionFetchGeneration);
                localSegments[slot] = segment;
            }
            return segment;
        }

        /// Selects the guest-loop execution policy from stable machine-state flags.
        private static byte executionPolicy(RiscVThreadState state) {
            if (!state.canRetireBlock()) {
                return RiscVMicroBlockNode.CHECKED_MODE;
            }
            return state.hasStoreSideEffects()
                    ? RiscVMicroBlockNode.PRECISE_FAST_MODE
                    : RiscVMicroBlockNode.BATCHED_FAST_MODE;
        }

        /// Hashes a guest PC into the thread-local decoded-block cache.
        private static int localBlockSlot(long pc) {
            long hash = pc >>> 1;
            hash ^= hash >>> 4;
            return (int) hash & (LOCAL_BLOCK_CACHE_SIZE - 1);
        }

        /// Hashes a guest PC into the thread-local decoded-segment cache.
        private static int localSegmentSlot(long pc, MemoryLayout memoryLayout) {
            long hash = pc >>> memoryLayout.pageShift();
            hash ^= hash >>> 6;
            return (int) hash & (LOCAL_SEGMENT_CACHE_SIZE - 1);
        }
    }

    /// Dispatches decoded page segments before falling back to the general block interpreter.
    @NotNullByDefault
    private static final class SegmentDispatchNode {
        /// Maximum fast blocks executed before returning to the outer guest loop.
        private static final int FAST_BLOCKS_PER_SLICE = 128;

        /// Executes a fast segment slice, or falls back to the general block dispatcher.
        private long execute(GuestLoopState loopState, RiscVThreadState state, BlockDispatchNode fallback) {
            if (loopState.executionPolicy() != RiscVMicroBlockNode.BATCHED_FAST_MODE
                    || state.hasActiveReservation()) {
                return fallback.execute(loopState, state);
            }

            Memory memory = loopState.memory();
            MemoryAccess access = loopState.access();
            long instructionFetchGeneration = state.instructionFetchGeneration();
            long[] registers = state.decodedRegisters();
            long pointerMask = state.pointerMask();
            long pc = loopState.pc();
            int remainingBlocks = FAST_BLOCKS_PER_SLICE;
            DecodedCodeSegment.FastSliceResult result = loopState.fastSliceResult();

            while (remainingBlocks > 0) {
                DecodedCodeSegment segment = loopState.segmentFor(pc, instructionFetchGeneration);
                segment.executeFastSlice(
                        memory,
                        pc,
                        remainingBlocks,
                        state,
                        access,
                        registers,
                        pointerMask,
                        result);
                pc = result.pc();
                remainingBlocks -= result.executedBlocks();

                if (result.hitFallback()) {
                    state.setPc(pc);
                    loopState.setPc(pc);
                    return fallback.execute(loopState, state);
                }

                if (result.executedBlocks() == 0) {
                    state.setPc(pc);
                    return pc;
                }
            }

            state.setPc(pc);
            return pc;
        }
    }

    /// Dispatches decoded blocks through a small direct-call inline cache.
    @NotNullByDefault
    private static final class BlockDispatchNode {
        /// Consecutive executions required before a guest PC is promoted to a direct call.
        private static final int DIRECT_CALL_INSTALL_THRESHOLD = 128;

        /// The decoded block cache shared by all dispatch calls.
        private final BlockCache blocks;

        /// The hot trace cache shared by all dispatch calls.
        private final TraceCache traces;

        /// First direct-call entry for a stable hot guest trace.
        private @Nullable CachedTraceCallNode cachedTrace0;

        /// Second direct-call entry for a stable hot guest trace.
        private @Nullable CachedTraceCallNode cachedTrace1;

        /// Third direct-call entry for a stable hot guest trace.
        private @Nullable CachedTraceCallNode cachedTrace2;

        /// Fourth direct-call entry for a stable hot guest trace.
        private @Nullable CachedTraceCallNode cachedTrace3;

        /// Direct-call entry for a stable self-looping guest block.
        private @Nullable CachedBlockCallNode cachedCall;

        /// The guest PC currently being considered for direct-call promotion.
        private long candidatePc;

        /// Consecutive direct-call promotion observations for `candidatePc`.
        private int candidateCount;

        /// Creates a block dispatch node backed by the supplied decoded-block cache.
        private BlockDispatchNode(BlockCache blocks) {
            this.blocks = blocks;
            this.traces = new TraceCache();
        }

        /// Executes the decoded block for the supplied guest program counter.
        private long execute(GuestLoopState loopState, RiscVThreadState state) {
            long pc = loopState.pc();
            MemoryLayout memoryLayout = loopState.memoryLayout();
            byte executionPolicy = loopState.executionPolicy();
            long instructionFetchGeneration = state.instructionFetchGeneration();
            if (executionPolicy != RiscVMicroBlockNode.CHECKED_MODE) {
                @Nullable CachedTraceCallNode cachedTrace = cachedTrace(
                        pc,
                        memoryLayout,
                        executionPolicy,
                        instructionFetchGeneration);
                if (cachedTrace != null) {
                    cachedTrace.call(state, loopState.access());
                    return state.pc();
                }

                TraceEntry trace = traces.get(pc, memoryLayout, executionPolicy, instructionFetchGeneration);
                if (trace != null) {
                    return executeTraceMiss(loopState, state, trace);
                }
            }
            return executeBlockCachedOrMiss(loopState, state, pc, instructionFetchGeneration);
        }

        /// Handles a direct trace-call cache miss for the supplied trace.
        private long executeTraceMiss(GuestLoopState loopState, RiscVThreadState state, TraceEntry trace) {
            if (cachedTrace3 == null) {
                CachedTraceCallNode cachedTrace = installCachedTrace(trace);
                if (cachedTrace != null) {
                    cachedTrace.call(state, loopState.access());
                    return state.pc();
                }
            }

            trace.target().execute(state, loopState.access());
            return state.pc();
        }

        /// Executes a cached direct block call, or installs and executes a new cache entry.
        private long executeBlockCachedOrMiss(
                GuestLoopState loopState,
                RiscVThreadState state,
                long pc,
                long instructionFetchGeneration) {
            MemoryLayout memoryLayout = loopState.memoryLayout();
                CachedBlockCallNode cachedCall = this.cachedCall;
            if (cachedCall != null && cachedCall.matches(
                    pc,
                    memoryLayout,
                    loopState.executionPolicy(),
                    instructionFetchGeneration)) {
                cachedCall.call(state, loopState.access());
                long nextPc = state.pc();
                observeTransition(loopState.memory(), cachedCall.entry(), nextPc);
                return nextPc;
            }
            return executeBlockMiss(loopState, state, pc);
        }

        /// Handles a direct-call cache miss for the supplied guest program counter.
        private long executeBlockMiss(GuestLoopState loopState, RiscVThreadState state, long pc) {
            BlockEntry entry = loopState.blockFor(blocks);
            if (shouldInstallDirectCall(
                            pc,
                            loopState.memoryLayout(),
                            loopState.executionPolicy(),
                            entry.instructionFetchGeneration())) {
                CachedBlockCallNode cachedCall = installCachedCall(entry);
                if (cachedCall != null) {
                    cachedCall.call(state, loopState.access());
                    long nextPc = state.pc();
                    observeTransition(loopState.memory(), entry, nextPc);
                    return nextPc;
                }
            }

            entry.target().execute(state, loopState.access());
            long nextPc = state.pc();
            observeTransition(loopState.memory(), entry, nextPc);
            return nextPc;
        }

        /// Records a block transition and compiles a trace when the successor edge is hot.
        private void observeTransition(Memory memory, BlockEntry entry, long nextPc) {
            entry.recordSuccessor(nextPc);
            if (entry.executionPolicy() != RiscVMicroBlockNode.CHECKED_MODE) {
                traces.compileIfHot(memory, blocks, entry);
            }
        }

        /// Returns a cached direct trace call for the supplied PC, layout, policy, and generation, or null on miss.
        private @Nullable CachedTraceCallNode cachedTrace(
                long pc,
                MemoryLayout memoryLayout,
                byte executionPolicy,
                long instructionFetchGeneration) {
            @Nullable CachedTraceCallNode trace = cachedTrace0;
            if (trace != null && trace.matches(pc, memoryLayout, executionPolicy, instructionFetchGeneration)) {
                return trace;
            }
            trace = cachedTrace1;
            if (trace != null && trace.matches(pc, memoryLayout, executionPolicy, instructionFetchGeneration)) {
                return trace;
            }
            trace = cachedTrace2;
            if (trace != null && trace.matches(pc, memoryLayout, executionPolicy, instructionFetchGeneration)) {
                return trace;
            }
            trace = cachedTrace3;
            if (trace != null && trace.matches(pc, memoryLayout, executionPolicy, instructionFetchGeneration)) {
                return trace;
            }
            return null;
        }

        /// Installs a direct trace call node for a newly observed hot trace.
        private @Nullable CachedTraceCallNode installCachedTrace(TraceEntry trace) {
            synchronized (this) {
                @Nullable CachedTraceCallNode cachedTrace = cachedTrace(
                        trace.startPc(),
                        trace.memoryLayout(),
                        trace.executionPolicy(),
                        trace.instructionFetchGeneration());
                if (cachedTrace != null) {
                    return cachedTrace;
                }

                if (cachedTrace0 == null) {
                    cachedTrace = new CachedTraceCallNode(trace);
                    cachedTrace0 = cachedTrace;
                } else if (cachedTrace1 == null) {
                    cachedTrace = new CachedTraceCallNode(trace);
                    cachedTrace1 = cachedTrace;
                } else if (cachedTrace2 == null) {
                    cachedTrace = new CachedTraceCallNode(trace);
                    cachedTrace2 = cachedTrace;
                } else if (cachedTrace3 == null) {
                    cachedTrace = new CachedTraceCallNode(trace);
                    cachedTrace3 = cachedTrace;
                } else {
                    return null;
                }
                return cachedTrace;
            }
        }

        /// The memory layout currently being considered for direct-call promotion.
        private @Nullable MemoryLayout candidateMemoryLayout;

        /// The execution policy currently being considered for direct-call promotion.
        private byte candidateExecutionPolicy;

        /// The instruction-fetch generation currently being considered for direct-call promotion.
        private long candidateInstructionFetchGeneration;

        /// Returns true after a guest PC, layout, policy, and generation have shown stable self-loop behavior.
        private boolean shouldInstallDirectCall(
                long pc,
                MemoryLayout memoryLayout,
                byte executionPolicy,
                long instructionFetchGeneration) {
            if (cachedCall != null) {
                return false;
            }

            if (candidatePc == pc
                    && candidateMemoryLayout == memoryLayout
                    && candidateExecutionPolicy == executionPolicy
                    && candidateInstructionFetchGeneration == instructionFetchGeneration) {
                candidateCount++;
            } else {
                candidatePc = pc;
                candidateMemoryLayout = memoryLayout;
                candidateExecutionPolicy = executionPolicy;
                candidateInstructionFetchGeneration = instructionFetchGeneration;
                candidateCount = 1;
            }
            return candidateCount >= DIRECT_CALL_INSTALL_THRESHOLD;
        }

        /// Installs a direct call node for a newly observed guest block when capacity remains.
        private @Nullable CachedBlockCallNode installCachedCall(BlockEntry entry) {
            synchronized (this) {
                CachedBlockCallNode cachedCall = this.cachedCall;
                if (cachedCall != null) {
                    return cachedCall.matches(
                            entry.pc(),
                            entry.memoryLayout(),
                            entry.executionPolicy(),
                            entry.instructionFetchGeneration())
                            ? cachedCall
                            : null;
                }

                cachedCall = new CachedBlockCallNode(entry);
                this.cachedCall = cachedCall;
                return cachedCall;
            }
        }
    }

    /// Calls one hot decoded trace through a cached executable.
    @NotNullByDefault
    private static final class CachedTraceCallNode {
        /// The guest program counter handled by this cached trace.
        private final long pc;

        /// The memory layout handled by this cached trace.
        private final MemoryLayout memoryLayout;

        /// The execution policy handled by this cached trace.
        private final byte executionPolicy;

        /// The instruction-fetch generation handled by this cached trace.
        private final long instructionFetchGeneration;

        /// The decoded trace target.
        private final ExecutableTrace target;

        /// Creates a cached direct call for one decoded trace.
        private CachedTraceCallNode(TraceEntry trace) {
            this.pc = trace.startPc();
            this.memoryLayout = trace.memoryLayout();
            this.executionPolicy = trace.executionPolicy();
            this.instructionFetchGeneration = trace.instructionFetchGeneration();
            this.target = trace.target();
        }

        /// Returns true when this node handles the supplied trace start PC, layout, policy, and generation.
        private boolean matches(
                long pc,
                MemoryLayout memoryLayout,
                byte executionPolicy,
                long instructionFetchGeneration) {
            return this.pc == pc
                    && this.memoryLayout == memoryLayout
                    && this.executionPolicy == executionPolicy
                    && this.instructionFetchGeneration == instructionFetchGeneration;
        }

        /// Executes the cached decoded trace.
        private void call(RiscVThreadState state, MemoryAccess access) {
            target.execute(state, access);
        }
    }

    /// Calls one decoded block through a cached executable.
    @NotNullByDefault
    private static final class CachedBlockCallNode {
        /// The decoded block entry handled by this cached call.
        private final BlockEntry entry;

        /// The guest program counter handled by this cached direct call.
        private final long pc;

        /// The memory layout handled by this cached direct call.
        private final MemoryLayout memoryLayout;

        /// The execution policy handled by this cached direct call.
        private final byte executionPolicy;

        /// The instruction-fetch generation handled by this cached direct call.
        private final long instructionFetchGeneration;

        /// The decoded block target.
        private final ExecutableBlock target;

        /// Creates a cached direct call for one decoded block.
        private CachedBlockCallNode(BlockEntry entry) {
            this.entry = entry;
            this.pc = entry.pc();
            this.memoryLayout = entry.memoryLayout();
            this.executionPolicy = entry.executionPolicy();
            this.instructionFetchGeneration = entry.instructionFetchGeneration();
            this.target = entry.target();
        }

        /// Returns the decoded block entry handled by this cached call.
        private BlockEntry entry() {
            return entry;
        }

        /// Returns true when this node handles the supplied PC, layout, policy, and instruction-fetch generation.
        private boolean matches(
                long pc,
                MemoryLayout memoryLayout,
                byte executionPolicy,
                long instructionFetchGeneration) {
            return this.pc == pc
                    && this.memoryLayout == memoryLayout
                    && this.executionPolicy == executionPolicy
                    && this.instructionFetchGeneration == instructionFetchGeneration;
        }

        /// Executes the cached decoded block.
        private void call(RiscVThreadState state, MemoryAccess access) {
            target.execute(state, access);
        }
    }

    /// Stores immutable metadata and executable target for one decoded guest block.
    @NotNullByDefault
    private static final class BlockEntry {
        /// Successor observations required before a block can seed a trace.
        private static final int HOT_SUCCESSOR_THRESHOLD = 64;

        /// Saturating upper bound for successor observation counts.
        private static final int MAX_SUCCESSOR_COUNT = 1 << 20;

        /// The guest program counter where this block starts.
        private final long pc;

        /// The memory layout captured by this decoded block target.
        private final MemoryLayout memoryLayout;

        /// The execution policy captured by this decoded block target.
        private final byte executionPolicy;

        /// The instruction-fetch generation captured by this decoded block target.
        private final long instructionFetchGeneration;

        /// The decoded block metadata used for trace formation.
        private final DecodedBlock decodedBlock;

        /// The executable block target.
        private final ExecutableBlock target;

        /// The most recently stable successor PC observed after executing this block.
        private long successorPc;

        /// The number of consecutive observations for `successorPc`.
        private int successorCount;

        /// Creates a decoded block entry.
        private BlockEntry(
                long pc,
                MemoryLayout memoryLayout,
                byte executionPolicy,
                long instructionFetchGeneration,
                DecodedBlock decodedBlock,
                ExecutableBlock target) {
            this.pc = pc;
            this.memoryLayout = memoryLayout;
            this.executionPolicy = executionPolicy;
            this.instructionFetchGeneration = instructionFetchGeneration;
            this.decodedBlock = decodedBlock;
            this.target = target;
        }

        /// Returns the guest program counter where this block starts.
        private long pc() {
            return pc;
        }

        /// Returns the memory layout captured by this decoded block target.
        private MemoryLayout memoryLayout() {
            return memoryLayout;
        }

        /// Returns the execution policy captured by this decoded block target.
        private byte executionPolicy() {
            return executionPolicy;
        }

        /// Returns the instruction-fetch generation captured by this decoded block target.
        private long instructionFetchGeneration() {
            return instructionFetchGeneration;
        }

        /// Returns the decoded block metadata.
        private DecodedBlock decodedBlock() {
            return decodedBlock;
        }

        /// Returns the executable block target.
        private ExecutableBlock target() {
            return target;
        }

        /// Records the successor observed after executing this block once.
        private void recordSuccessor(long nextPc) {
            if (successorPc == nextPc) {
                if (successorCount < MAX_SUCCESSOR_COUNT) {
                    successorCount++;
                }
                return;
            }

            successorPc = nextPc;
            successorCount = 1;
        }

        /// Returns true when the block has a hot successor suitable for trace formation.
        private boolean hasHotSuccessor() {
            return successorCount >= HOT_SUCCESSOR_THRESHOLD;
        }

        /// Returns the hot successor PC observed for this block.
        private long hotSuccessorPc() {
            return successorPc;
        }

        /// Returns true when this block is safe to include in a trace root.
        private boolean isTraceable() {
            for (DecodedInstruction instruction : decodedBlock.instructions()) {
                RiscVOperation operation = instruction.operation();
                if (operation == RiscVOperation.ECALL
                        || operation == RiscVOperation.EBREAK
                        || operation == RiscVOperation.MRET
                        || operation == RiscVOperation.FENCE_I) {
                    return false;
                }
            }
            return true;
        }
    }

    /// Stores one compiled trace target.
    ///
    /// @param startPc the guest program counter where the trace starts
    /// @param memoryLayout the memory layout captured by the trace target
    /// @param executionPolicy the execution policy captured by the trace target
    /// @param instructionFetchGeneration the instruction-fetch generation captured by the trace target
    /// @param target the executable trace target
    @NotNullByDefault
    private record TraceEntry(
            long startPc,
            MemoryLayout memoryLayout,
            byte executionPolicy,
            long instructionFetchGeneration,
            ExecutableTrace target) {
    }

    /// Stores compiled hot traces in a PC and memory-layout keyed open-addressing map.
    @NotNullByDefault
    private static final class TraceCache {
        /// The initial number of slots in the trace cache.
        private static final int INITIAL_CAPACITY = 64;

        /// The maximum number of decoded blocks included in one trace.
        private static final int MAX_TRACE_BLOCKS = 64;

        /// The resize threshold numerator for the trace cache load factor.
        private static final int LOAD_FACTOR_NUMERATOR = 1;

        /// The resize threshold denominator for the trace cache load factor.
        private static final int LOAD_FACTOR_DENOMINATOR = 2;

        /// Guest program counters stored in cache slots.
        private volatile long[] keys = new long[INITIAL_CAPACITY];

        /// Memory layouts stored in cache slots.
        private volatile @Nullable MemoryLayout[] layouts = new MemoryLayout[INITIAL_CAPACITY];

        /// Execution policies stored in cache slots.
        private volatile byte[] executionPolicies = new byte[INITIAL_CAPACITY];

        /// Instruction-fetch generations stored in cache slots.
        private volatile long[] instructionFetchGenerations = new long[INITIAL_CAPACITY];

        /// Trace values stored in the slot matching `keys`.
        private volatile @Nullable TraceEntry[] values = new TraceEntry[INITIAL_CAPACITY];

        /// The number of occupied trace cache slots.
        private int size;

        /// Creates a trace cache for one dispatch node.
        /// Returns the compiled trace for a guest program counter, or null on miss.
        private @Nullable TraceEntry get(
                long pc,
                MemoryLayout memoryLayout,
                byte executionPolicy,
                long instructionFetchGeneration) {
            long[] currentKeys = keys;
            @Nullable MemoryLayout[] currentLayouts = layouts;
            byte[] currentExecutionPolicies = executionPolicies;
            long[] currentInstructionFetchGenerations = instructionFetchGenerations;
            @Nullable TraceEntry[] currentValues = values;
            int slot = findSlot(
                    pc,
                    memoryLayout,
                    executionPolicy,
                    instructionFetchGeneration,
                    currentKeys,
                    currentLayouts,
                    currentExecutionPolicies,
                    currentInstructionFetchGenerations,
                    currentValues);
            return currentValues[slot];
        }

        /// Compiles a trace for a block whose successor edge is hot, unless one already exists.
        private void compileIfHot(Memory memory, BlockCache blocks, BlockEntry start) {
            MemoryLayout memoryLayout = memory.layout();
            if (!start.hasHotSuccessor()
                    || !start.isTraceable()
                    || get(
                            start.pc(),
                            memoryLayout,
                            start.executionPolicy(),
                            start.instructionFetchGeneration()) != null) {
                return;
            }
            compileAndCache(memory, blocks, start);
        }

        /// Compiles and caches a trace after a miss on the unsynchronized fast path.
        private synchronized void compileAndCache(Memory memory, BlockCache blocks, BlockEntry start) {
            MemoryLayout memoryLayout = memory.layout();
            int slot = findSlot(
                    start.pc(),
                    memoryLayout,
                    start.executionPolicy(),
                    start.instructionFetchGeneration(),
                    keys,
                    layouts,
                    executionPolicies,
                    instructionFetchGenerations,
                    values);
            if (values[slot] != null || !start.hasHotSuccessor() || !start.isTraceable()) {
                return;
            }

            TraceBuildResult result = buildTrace(memory, blocks, start);
            if (result.blockCount() < 2) {
                return;
            }

            if ((size + 1) * LOAD_FACTOR_DENOMINATOR >= values.length * LOAD_FACTOR_NUMERATOR) {
                grow();
                slot = findSlot(
                        start.pc(),
                        memoryLayout,
                        start.executionPolicy(),
                        start.instructionFetchGeneration(),
                        keys,
                        layouts,
                        executionPolicies,
                        instructionFetchGenerations,
                        values);
            }

            TraceEntry trace = new TraceEntry(
                    start.pc(),
                    memoryLayout,
                    start.executionPolicy(),
                    start.instructionFetchGeneration(),
                    TraceCompiler.compile(
                            memoryLayout,
                            start.executionPolicy(),
                            result.decodedBlocks(),
                            result.expectedNextPcs()));
            keys[slot] = start.pc();
            layouts[slot] = memoryLayout;
            executionPolicies[slot] = start.executionPolicy();
            instructionFetchGenerations[slot] = start.instructionFetchGeneration();
            values[slot] = trace;
            size++;
        }

        /// Builds one linear trace by following currently hot successor edges.
        private TraceBuildResult buildTrace(Memory memory, BlockCache blocks, BlockEntry start) {
            DecodedBlock[] decodedBlocks = new DecodedBlock[MAX_TRACE_BLOCKS];
            long[] expectedNextPcs = new long[MAX_TRACE_BLOCKS - 1];
            long[] pcs = new long[MAX_TRACE_BLOCKS];
            int count = 0;
            BlockEntry current = start;

            while (count < MAX_TRACE_BLOCKS && current.isTraceable()) {
                pcs[count] = current.pc();
                decodedBlocks[count] = current.decodedBlock();
                count++;

                if (count == MAX_TRACE_BLOCKS) {
                    break;
                }

                if (!current.hasHotSuccessor()) {
                    break;
                }

                long successorPc = current.hotSuccessorPc();
                if (containsPc(pcs, count, successorPc)) {
                    break;
                }

                BlockEntry successor = blocks.getOrDecode(
                        memory,
                        successorPc,
                        start.memoryLayout(),
                        start.executionPolicy(),
                        start.instructionFetchGeneration());
                if (!successor.isTraceable()) {
                    break;
                }

                expectedNextPcs[count - 1] = successorPc;
                current = successor;
            }

            DecodedBlock[] trimmedDecodedBlocks = new DecodedBlock[count];
            System.arraycopy(decodedBlocks, 0, trimmedDecodedBlocks, 0, count);
            long[] trimmedExpectedNextPcs = new long[Math.max(0, count - 1)];
            System.arraycopy(expectedNextPcs, 0, trimmedExpectedNextPcs, 0, trimmedExpectedNextPcs.length);
            return new TraceBuildResult(trimmedDecodedBlocks, trimmedExpectedNextPcs);
        }

        /// Returns true when the supplied PC is already present in the trace prefix.
        private static boolean containsPc(long[] pcs, int count, long pc) {
            for (int index = 0; index < count; index++) {
                if (pcs[index] == pc) {
                    return true;
                }
            }
            return false;
        }

        /// Doubles the trace cache capacity and reinserts all existing entries.
        private void grow() {
            long[] oldKeys = keys;
            @Nullable MemoryLayout[] oldLayouts = layouts;
            byte[] oldExecutionPolicies = executionPolicies;
            long[] oldInstructionFetchGenerations = instructionFetchGenerations;
            @Nullable TraceEntry[] oldValues = values;
            keys = new long[oldKeys.length << 1];
            layouts = new MemoryLayout[keys.length];
            executionPolicies = new byte[keys.length];
            instructionFetchGenerations = new long[keys.length];
            values = new TraceEntry[keys.length];

            for (int index = 0; index < oldValues.length; index++) {
                TraceEntry trace = oldValues[index];
                if (trace != null) {
                    @Nullable MemoryLayout memoryLayout = oldLayouts[index];
                    if (memoryLayout == null) {
                        continue;
                    }
                    int slot = findSlot(
                            oldKeys[index],
                            memoryLayout,
                            oldExecutionPolicies[index],
                            oldInstructionFetchGenerations[index],
                            keys,
                            layouts,
                            executionPolicies,
                            instructionFetchGenerations,
                            values);
                    keys[slot] = oldKeys[index];
                    layouts[slot] = memoryLayout;
                    executionPolicies[slot] = oldExecutionPolicies[index];
                    instructionFetchGenerations[slot] = oldInstructionFetchGenerations[index];
                    values[slot] = trace;
                }
            }
        }

        /// Finds the trace cache slot containing the key or the first empty slot for it.
        private static int findSlot(
                long pc,
                MemoryLayout memoryLayout,
                byte executionPolicy,
                long instructionFetchGeneration,
                long[] keys,
                @Nullable MemoryLayout[] layouts,
                byte[] executionPolicies,
                long[] instructionFetchGenerations,
                @Nullable TraceEntry[] values) {
            int mask = values.length - 1;
            int slot = hash(pc, memoryLayout, executionPolicy, instructionFetchGeneration) & mask;
            while (true) {
                TraceEntry trace = values[slot];
                if (trace == null
                        || (keys[slot] == pc
                        && layouts[slot] == memoryLayout
                        && executionPolicies[slot] == executionPolicy
                        && instructionFetchGenerations[slot] == instructionFetchGeneration)) {
                    return slot;
                }
                slot = (slot + 1) & mask;
            }
        }

        /// Hashes a guest program counter, layout, execution policy, and generation for open addressing.
        private static int hash(
                long value,
                MemoryLayout memoryLayout,
                byte executionPolicy,
                long instructionFetchGeneration) {
            long hash = value >>> 1;
            hash ^= value >>> 9;
            hash ^= value >>> 17;
            hash ^= instructionFetchGeneration;
            hash ^= instructionFetchGeneration >>> 11;
            hash ^= memoryLayout.pageShift();
            hash ^= (long) executionPolicy << 24;
            return (int) hash;
        }
    }

    /// Stores temporary trace build arrays trimmed to the number of selected blocks.
    ///
    /// @param decodedBlocks the decoded blocks in trace order
    /// @param expectedNextPcs the expected successor PCs between adjacent trace blocks
    @NotNullByDefault
    private record TraceBuildResult(
            DecodedBlock @Unmodifiable [] decodedBlocks,
            long @Unmodifiable [] expectedNextPcs) {
        /// Returns the number of blocks in this trace.
        private int blockCount() {
            return decodedBlocks.length;
        }
    }

    /// Stores decoded guest blocks in a PC and memory-layout keyed open-addressing map.
    @NotNullByDefault
    private static final class BlockCache {
        /// The initial number of slots in the decoded block cache.
        private static final int INITIAL_CAPACITY = 256;

        /// The resize threshold numerator for the cache load factor.
        private static final int LOAD_FACTOR_NUMERATOR = 1;

        /// The resize threshold denominator for the cache load factor.
        private static final int LOAD_FACTOR_DENOMINATOR = 2;

        /// Guest program counters stored in cache slots.
        private volatile long[] keys = new long[INITIAL_CAPACITY];

        /// Memory layouts stored in cache slots.
        private volatile @Nullable MemoryLayout[] layouts = new MemoryLayout[INITIAL_CAPACITY];

        /// Execution policies stored in cache slots.
        private volatile byte[] executionPolicies = new byte[INITIAL_CAPACITY];

        /// Instruction-fetch generations stored in cache slots.
        private volatile long[] instructionFetchGenerations = new long[INITIAL_CAPACITY];

        /// Cache values stored in the slot matching `keys`.
        private volatile @Nullable BlockEntry[] values = new BlockEntry[INITIAL_CAPACITY];

        /// The number of occupied cache slots.
        private int size;

        /// Creates a decoded block cache for one root node.
        /// Returns the cached block for a guest program counter, layout, and execution policy.
        private BlockEntry getOrDecode(
                Memory memory,
                long pc,
                MemoryLayout memoryLayout,
                byte executionPolicy,
                long instructionFetchGeneration) {
            long[] currentKeys = keys;
            @Nullable MemoryLayout[] currentLayouts = layouts;
            byte[] currentExecutionPolicies = executionPolicies;
            long[] currentInstructionFetchGenerations = instructionFetchGenerations;
            @Nullable BlockEntry[] currentValues = values;
            int slot = findSlot(
                    pc,
                    memoryLayout,
                    executionPolicy,
                    instructionFetchGeneration,
                    currentKeys,
                    currentLayouts,
                    currentExecutionPolicies,
                    currentInstructionFetchGenerations,
                    currentValues);
            BlockEntry block = currentValues[slot];
            if (block != null) {
                return block;
            }

            return decodeAndCache(memory, pc, memoryLayout, executionPolicy, instructionFetchGeneration);
        }

        /// Decodes and caches a block after a miss on the unsynchronized fast path.
        private synchronized BlockEntry decodeAndCache(
                Memory memory,
                long pc,
                MemoryLayout memoryLayout,
                byte executionPolicy,
                long instructionFetchGeneration) {
            int slot = findSlot(
                    pc,
                    memoryLayout,
                    executionPolicy,
                    instructionFetchGeneration,
                    keys,
                    layouts,
                    executionPolicies,
                    instructionFetchGenerations,
                    values);
            BlockEntry block = values[slot];
            if (block != null) {
                return block;
            }

            if ((size + 1) * LOAD_FACTOR_DENOMINATOR >= values.length * LOAD_FACTOR_NUMERATOR) {
                grow();
                slot = findSlot(
                        pc,
                        memoryLayout,
                        executionPolicy,
                        instructionFetchGeneration,
                        keys,
                        layouts,
                        executionPolicies,
                        instructionFetchGenerations,
                        values);
            }

            DecodedBlock decodedBlock = RiscVDecoder.decodeBlock(memory, pc);
            block = new BlockEntry(
                    pc,
                    memoryLayout,
                    executionPolicy,
                    instructionFetchGeneration,
                    decodedBlock,
                    RiscVMicroBlockCompiler.compile(decodedBlock, memoryLayout, executionPolicy));
            keys[slot] = pc;
            layouts[slot] = memoryLayout;
            executionPolicies[slot] = executionPolicy;
            instructionFetchGenerations[slot] = instructionFetchGeneration;
            values[slot] = block;
            size++;
            return block;
        }

        /// Doubles the cache capacity and reinserts all existing entries.
        private void grow() {
            long[] oldKeys = keys;
            @Nullable MemoryLayout[] oldLayouts = layouts;
            byte[] oldExecutionPolicies = executionPolicies;
            long[] oldInstructionFetchGenerations = instructionFetchGenerations;
            @Nullable BlockEntry[] oldValues = values;
            keys = new long[oldKeys.length << 1];
            layouts = new MemoryLayout[keys.length];
            executionPolicies = new byte[keys.length];
            instructionFetchGenerations = new long[keys.length];
            values = new BlockEntry[keys.length];

            for (int index = 0; index < oldValues.length; index++) {
                BlockEntry block = oldValues[index];
                if (block != null) {
                    @Nullable MemoryLayout memoryLayout = oldLayouts[index];
                    if (memoryLayout == null) {
                        continue;
                    }
                    int slot = findSlot(
                            oldKeys[index],
                            memoryLayout,
                            oldExecutionPolicies[index],
                            oldInstructionFetchGenerations[index],
                            keys,
                            layouts,
                            executionPolicies,
                            instructionFetchGenerations,
                            values);
                    keys[slot] = oldKeys[index];
                    layouts[slot] = memoryLayout;
                    executionPolicies[slot] = oldExecutionPolicies[index];
                    instructionFetchGenerations[slot] = oldInstructionFetchGenerations[index];
                    values[slot] = block;
                }
            }
        }

        /// Finds the cache slot containing the key or the first empty slot for it.
        private static int findSlot(
                long pc,
                MemoryLayout memoryLayout,
                byte executionPolicy,
                long instructionFetchGeneration,
                long[] keys,
                @Nullable MemoryLayout[] layouts,
                byte[] executionPolicies,
                long[] instructionFetchGenerations,
                @Nullable BlockEntry[] values) {
            int mask = values.length - 1;
            int slot = hash(pc, memoryLayout, executionPolicy, instructionFetchGeneration) & mask;
            while (true) {
                BlockEntry block = values[slot];
                if (block == null
                        || (keys[slot] == pc
                        && layouts[slot] == memoryLayout
                        && executionPolicies[slot] == executionPolicy
                        && instructionFetchGenerations[slot] == instructionFetchGeneration)) {
                    return slot;
                }
                slot = (slot + 1) & mask;
            }
        }

        /// Hashes a guest program counter, layout, execution policy, and generation for open addressing.
        private static int hash(
                long value,
                MemoryLayout memoryLayout,
                byte executionPolicy,
                long instructionFetchGeneration) {
            long hash = value >>> 1;
            hash ^= value >>> 9;
            hash ^= value >>> 17;
            hash ^= instructionFetchGeneration;
            hash ^= instructionFetchGeneration >>> 11;
            hash ^= memoryLayout.pageShift();
            hash ^= (long) executionPolicy << 24;
            return (int) hash;
        }
    }
}
