// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.riscv.runtime.fs;

import kala.compress.archivers.tar.TarArchiveEntry;
import kala.compress.archivers.tar.TarArchiveInputStream;
import kala.compress.archivers.tar.TarArchiveReader;
import org.glavo.riscv.exception.RiscVException;
import org.glavo.riscv.runtime.GuestCredentials;
import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Unmodifiable;
import org.jetbrains.annotations.UnmodifiableView;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Map;
import java.util.TreeMap;
import java.util.zip.GZIPInputStream;

/// Describes the guest-visible filesystem mount namespace used by Linux syscalls.
///
/// `GuestFileSystem` keeps mount configuration separate from process state. Host
/// directory and tar mounts can be shared by future processes, while virtual
/// mounts are supplied as providers so each process can expose process-local
/// metadata such as `/proc/self` without sharing open-file tables.
@NotNullByDefault
public final class GuestFileSystem {
    /// Linux `DT_DIR` directory entry type.
    public static final byte DIRECTORY_ENTRY_DIRECTORY = 4;

    /// Linux `DT_REG` directory entry type.
    public static final byte DIRECTORY_ENTRY_REGULAR_FILE = 8;

    /// Linux `DT_LNK` directory entry type.
    public static final byte DIRECTORY_ENTRY_SYMBOLIC_LINK = 10;

    /// Linux `DT_CHR` directory entry type.
    public static final byte DIRECTORY_ENTRY_CHARACTER_DEVICE = 2;

    /// The Linux file-type bit for directories.
    public static final int STAT_MODE_DIRECTORY = 0040000;

    /// The Linux file-type bit for character devices.
    public static final int STAT_MODE_CHARACTER_DEVICE = 0020000;

    /// The Linux file-type bit for regular files.
    public static final int STAT_MODE_REGULAR_FILE = 0100000;

    /// The Linux file-type bit for symbolic links.
    public static final int STAT_MODE_SYMBOLIC_LINK = 0120000;

    /// Linux read permission bits for user, group, and other.
    public static final int STAT_MODE_READ_ALL = 0444;

    /// Linux execute permission bits for user, group, and other.
    public static final int STAT_MODE_EXECUTE_ALL = 0111;

    /// Linux read and execute permission bits for user, group, and other.
    public static final int STAT_MODE_READ_EXECUTE_ALL = STAT_MODE_READ_ALL | STAT_MODE_EXECUTE_ALL;

    /// Linux read and write permission bits for user, group, and other.
    public static final int STAT_MODE_READ_WRITE_ALL = 0666;

    /// Linux permission bits for user, group, and other.
    public static final int STAT_MODE_ALL = 0777;

    /// Linux sticky mode bit.
    public static final int STAT_MODE_STICKY = 01000;

    /// Linux permission and special mode bits changed by `chmod`.
    public static final int STAT_MODE_CHANGE_BITS = 07777;

    /// The maximum number of symbolic links followed during one path resolution.
    private static final int SYMBOLIC_LINK_LIMIT = 40;

    /// Eagerly resolved non-virtual mounts, or null when mounts must be resolved from specs.
    private final Mount @Nullable [] eagerMounts;

    /// Lazy mount specs in Docker-like key-value form.
    private final String @Unmodifiable [] mountSpecs;

    /// Virtual mounts appended to the mount namespace.
    private final VirtualMount @Unmodifiable [] virtualMounts;

    /// The resolved immutable mount snapshot, initialized lazily for spec-backed mounts.
    private volatile Mount @Nullable [] resolvedMounts;

    /// Creates a guest filesystem from eager mounts, lazy specs, and virtual mounts.
    private GuestFileSystem(
            Mount @Nullable [] eagerMounts,
            String @Unmodifiable [] mountSpecs,
            VirtualMount @Unmodifiable [] virtualMounts) {
        this.eagerMounts = eagerMounts == null ? null : eagerMounts.clone();
        this.mountSpecs = mountSpecs.clone();
        this.virtualMounts = virtualMounts.clone();
    }

    /// Creates a filesystem with only explicitly added virtual mounts.
    public static GuestFileSystem empty() {
        return new GuestFileSystem(null, new String[0], new VirtualMount[0]);
    }

    /// Creates a filesystem with an eager host root mount when one is supplied.
    public static GuestFileSystem forHostRoot(@Nullable Path hostRoot) {
        Mount @Nullable [] mounts = hostRoot == null
                ? null
                : new Mount[]{new HostMount("/", hostRoot.toAbsolutePath().normalize(), false)};
        return new GuestFileSystem(mounts, new String[0], new VirtualMount[0]);
    }

    /// Creates a filesystem whose host and tar mounts are resolved from mount specs.
    public static GuestFileSystem forMountSpecs(String @Unmodifiable [] mountSpecs) {
        return new GuestFileSystem(null, mountSpecs, new VirtualMount[0]);
    }

    /// Returns a filesystem with an additional virtual mount at the supplied guest path.
    public GuestFileSystem withVirtualMount(String guestPath, VirtualFileSystem fileSystem) {
        @Nullable String normalizedGuestPath = normalizeAbsoluteGuestPath(guestPath);
        if (normalizedGuestPath == null) {
            throw new RiscVException("Virtual filesystem mount path must be absolute: " + guestPath);
        }

        VirtualMount[] mounts = Arrays.copyOf(virtualMounts, virtualMounts.length + 1);
        mounts[virtualMounts.length] = new VirtualMount(normalizedGuestPath, fileSystem);
        return new GuestFileSystem(eagerMounts, mountSpecs, mounts);
    }

    /// Returns a filesystem with a virtual mount unless another mount already uses the same guest path.
    public GuestFileSystem withDefaultVirtualMount(String guestPath, VirtualFileSystem fileSystem) {
        @Nullable String normalizedGuestPath = normalizeAbsoluteGuestPath(guestPath);
        if (normalizedGuestPath == null) {
            throw new RiscVException("Virtual filesystem mount path must be absolute: " + guestPath);
        }
        return hasMountAt(normalizedGuestPath) ? this : withVirtualMount(normalizedGuestPath, fileSystem);
    }

    /// Returns a filesystem that inherits current non-virtual mounts and drops process-local virtual mounts.
    public GuestFileSystem withoutVirtualMounts() {
        Mount @Nullable [] mounts = resolvedMounts;
        if (mounts == null) {
            return new GuestFileSystem(eagerMounts, mountSpecs, new VirtualMount[0]);
        }

        ArrayList<Mount> inheritedMounts = new ArrayList<>(mounts.length);
        for (Mount mount : mounts) {
            if (!(mount instanceof VirtualMount)) {
                inheritedMounts.add(mount);
            }
        }
        return new GuestFileSystem(inheritedMounts.toArray(Mount[]::new), new String[0], new VirtualMount[0]);
    }

    /// Reads a regular file from a filesystem described by lazy mount specs.
    public static byte @Unmodifiable [] readMountedFile(
            String @Unmodifiable [] mountSpecs,
            String guestPath) {
        return forMountSpecs(mountSpecs).readFile(guestPath);
    }

    /// Reads a regular file from the configured guest filesystem mounts.
    public byte @Unmodifiable [] readFile(String guestPath) {
        @Nullable String absoluteGuestPath = normalizeAbsoluteGuestPath(guestPath);
        if (absoluteGuestPath == null) {
            throw new RiscVException("Guest executable path must use absolute Linux syntax: " + guestPath);
        }

        @Nullable Mount mount = mountForGuestPath(absoluteGuestPath);
        if (mount instanceof TarMount) {
            @Nullable TarPath tarPath = resolveTarPath(absoluteGuestPath, true);
            if (tarPath == null || tarPath.node() == null) {
                throw new RiscVException("Guest file does not exist: " + absoluteGuestPath);
            }
            if (!tarPath.node().isFile()) {
                throw new RiscVException("Guest path is not a regular file: " + absoluteGuestPath);
            }
            try {
                return tarPath.mount().fileSystem().readFileData(tarPath.node());
            } catch (IOException exception) {
                throw new RiscVException("Failed to read guest file: " + absoluteGuestPath, exception);
            }
        }
        if (mount instanceof VirtualMount) {
            @Nullable VirtualPath virtualPath = resolveVirtualPath(absoluteGuestPath, true);
            if (virtualPath == null || virtualPath.node() == null) {
                throw new RiscVException("Guest file does not exist: " + absoluteGuestPath);
            }
            if (!virtualPath.node().isFile()) {
                throw new RiscVException("Guest path is not a regular file: " + absoluteGuestPath);
            }
            return virtualPath.mount().fileSystem().fileData(virtualPath.node()).clone();
        }
        if (mount instanceof HostMount hostMount) {
            @Nullable Path hostFile = resolveHostFile(absoluteGuestPath, hostMount);
            if (hostFile == null) {
                throw new RiscVException("Guest file is outside configured mounts: " + absoluteGuestPath);
            }
            try {
                if (!hostFile.toRealPath().startsWith(hostMount.root().toRealPath())) {
                    throw new RiscVException("Guest file escapes configured mount: " + absoluteGuestPath);
                }
                if (!Files.isRegularFile(hostFile)) {
                    throw new RiscVException("Guest path is not a regular file: " + absoluteGuestPath);
                }
                try (InputStream input = Files.newInputStream(hostFile)) {
                    return readAllBytes(input);
                }
            } catch (IOException | SecurityException exception) {
                throw new RiscVException("Failed to read guest file: " + absoluteGuestPath, exception);
            }
        }
        throw new RiscVException("Guest file is not covered by a configured mount: " + absoluteGuestPath);
    }

    /// Returns the mount selected for an absolute guest path.
    public @Nullable Mount mountForGuestPath(String guestPath) {
        return mountForGuestPath(currentMounts(), guestPath);
    }

    /// Returns the mount whose host mount root contains a host path.
    public @Nullable HostMount mountForHostFile(Path hostFile) {
        Path normalizedHostFile = hostFile.normalize();
        @Nullable HostMount best = null;
        for (Mount filesystemMount : currentMounts()) {
            if (!(filesystemMount instanceof HostMount mount)) {
                continue;
            }
            Path normalizedRoot = mount.root().normalize();
            if (normalizedHostFile.startsWith(normalizedRoot)
                    && (best == null || normalizedRoot.toString().length() > best.root().normalize().toString().length())) {
                best = mount;
            }
        }
        return best;
    }

    /// Resolves an absolute guest path below a host-directory mount.
    public @Nullable Path resolveHostFile(String absoluteGuestPath) {
        @Nullable Mount mount = mountForGuestPath(absoluteGuestPath);
        if (!(mount instanceof HostMount hostMount)) {
            return null;
        }
        return resolveHostFile(absoluteGuestPath, hostMount);
    }

    /// Resolves an absolute guest path below a tar mount, following tar symlinks as requested.
    public @Nullable TarPath resolveTarPath(String absoluteGuestPath, boolean followFinalSymbolicLink) {
        @Nullable String currentGuestPath = normalizeAbsoluteGuestPath(absoluteGuestPath);
        if (currentGuestPath == null) {
            return null;
        }

        int symbolicLinks = 0;
        while (true) {
            @Nullable Mount mount = mountForGuestPath(currentGuestPath);
            if (!(mount instanceof TarMount tarMount)) {
                return null;
            }

            String relativePath = relativeGuestPath(currentGuestPath, tarMount.guestPath());
            TarNode currentNode = tarMount.fileSystem().root();
            String currentDirectoryGuestPath = tarMount.guestPath();
            if (relativePath.isEmpty()) {
                return new TarPath(currentGuestPath, tarMount, currentNode);
            }

            String[] segments = relativePath.split("/");
            for (int index = 0; index < segments.length; index++) {
                if (!currentNode.isDirectory()) {
                    return new TarPath(currentGuestPath, tarMount, null);
                }

                String segment = segments[index];
                @Nullable TarNode child = currentNode.children().get(segment);
                if (child == null) {
                    return new TarPath(currentGuestPath, tarMount, null);
                }

                boolean finalSegment = index == segments.length - 1;
                if (child.isSymbolicLink() && (!finalSegment || followFinalSymbolicLink)) {
                    symbolicLinks++;
                    if (symbolicLinks > SYMBOLIC_LINK_LIMIT) {
                        return new TarPath(currentGuestPath, tarMount, null);
                    }

                    String targetPath = child.linkTarget().startsWith("/")
                            ? child.linkTarget()
                            : appendGuestPath(currentDirectoryGuestPath, child.linkTarget());
                    String remainingPath = joinRemainingSegments(segments, index + 1);
                    if (!remainingPath.isEmpty()) {
                        targetPath = appendGuestPath(targetPath, remainingPath);
                    }
                    currentGuestPath = normalizeAbsoluteGuestPath(targetPath);
                    if (currentGuestPath == null) {
                        return new TarPath(absoluteGuestPath, tarMount, null);
                    }
                    break;
                }

                currentNode = child;
                if (!finalSegment) {
                    currentDirectoryGuestPath = appendGuestPath(currentDirectoryGuestPath, segment);
                } else {
                    return new TarPath(currentGuestPath, tarMount, currentNode);
                }
            }
        }
    }

    /// Resolves an absolute guest path below a virtual mount.
    public @Nullable VirtualPath resolveVirtualPath(String absoluteGuestPath, boolean followFinalSymbolicLink) {
        @Nullable String normalizedPath = normalizeAbsoluteGuestPath(absoluteGuestPath);
        if (normalizedPath == null) {
            return null;
        }
        @Nullable Mount mount = mountForGuestPath(normalizedPath);
        if (!(mount instanceof VirtualMount virtualMount)) {
            return null;
        }
        return resolveVirtualPath(virtualMount, normalizedPath, followFinalSymbolicLink);
    }

    /// Resolves an absolute guest path below a selected virtual mount.
    public @Nullable VirtualPath resolveVirtualPath(
            VirtualMount virtualMount,
            String absoluteGuestPath,
            boolean followFinalSymbolicLink) {
        @Nullable String currentGuestPath = normalizeAbsoluteGuestPath(absoluteGuestPath);
        if (currentGuestPath == null) {
            return null;
        }

        int symbolicLinks = 0;
        while (true) {
            @Nullable Mount mount = mountForGuestPath(currentGuestPath);
            if (!(mount instanceof VirtualMount currentMount)) {
                return null;
            }

            String relativePath = relativeGuestPath(currentGuestPath, currentMount.guestPath());
            @Nullable VirtualNode currentNode = currentMount.fileSystem().node(currentMount.guestPath());
            if (currentNode == null) {
                return new VirtualPath(currentGuestPath, currentMount, null);
            }
            String currentDirectoryGuestPath = currentMount.guestPath();
            if (relativePath.isEmpty()) {
                return new VirtualPath(currentGuestPath, currentMount, currentNode);
            }

            String[] segments = relativePath.split("/");
            for (int index = 0; index < segments.length; index++) {
                if (!currentNode.isDirectory()) {
                    return new VirtualPath(currentGuestPath, virtualMount, null);
                }

                String segment = segments[index];
                @Nullable String childGuestPath = normalizeAbsoluteGuestPath(
                        "/".equals(currentDirectoryGuestPath)
                                ? "/" + segment
                                : currentDirectoryGuestPath + "/" + segment);
                if (childGuestPath == null) {
                    return new VirtualPath(currentGuestPath, virtualMount, null);
                }

                @Nullable VirtualNode child = currentMount.fileSystem().node(childGuestPath);
                if (child == null) {
                    return new VirtualPath(currentGuestPath, virtualMount, null);
                }

                boolean finalSegment = index == segments.length - 1;
                if (child.isSymbolicLink() && (!finalSegment || followFinalSymbolicLink)) {
                    symbolicLinks++;
                    if (symbolicLinks > SYMBOLIC_LINK_LIMIT) {
                        return new VirtualPath(currentGuestPath, virtualMount, null);
                    }

                    String target = currentMount.fileSystem().linkTarget(child);
                    String targetPath = target.startsWith("/")
                            ? target
                            : appendGuestPath(currentDirectoryGuestPath, target);
                    String remainingPath = joinRemainingSegments(segments, index + 1);
                    if (!remainingPath.isEmpty()) {
                        targetPath = appendGuestPath(targetPath, remainingPath);
                    }
                    @Nullable String normalizedTargetPath = normalizeAbsoluteGuestPath(targetPath);
                    if (normalizedTargetPath == null) {
                        return new VirtualPath(absoluteGuestPath, virtualMount, null);
                    }
                    if (finalSegment && !(mountForGuestPath(normalizedTargetPath) instanceof VirtualMount)) {
                        return new VirtualPath(childGuestPath, currentMount, child);
                    }
                    currentGuestPath = normalizedTargetPath;
                    break;
                }

                currentNode = child;
                if (!finalSegment) {
                    currentDirectoryGuestPath = childGuestPath;
                } else {
                    return new VirtualPath(currentGuestPath, currentMount, currentNode);
                }
            }
        }
    }

    /// Returns deterministic directory entries for a virtual directory.
    public DirectoryEntry @Unmodifiable [] virtualDirectoryEntries(VirtualMount virtualMount, VirtualNode directory) {
        if (!guestPathMatchesMount(directory.guestPath(), virtualMount.guestPath())) {
            return new DirectoryEntry[0];
        }

        ArrayList<DirectoryEntry> entries = new ArrayList<>();
        entries.add(new DirectoryEntry(".", directory.inode(), DIRECTORY_ENTRY_DIRECTORY));
        @Nullable VirtualNode parent = virtualMount.fileSystem().node(parentPath(directory.guestPath()));
        entries.add(new DirectoryEntry(
                "..",
                parent == null ? directory.inode() : parent.inode(),
                DIRECTORY_ENTRY_DIRECTORY));

        for (VirtualNode child : virtualMount.fileSystem().childNodes(directory.guestPath())) {
            entries.add(new DirectoryEntry(child.name(), child.inode(), child.directoryEntryType()));
        }
        return entries.toArray(DirectoryEntry[]::new);
    }

    /// Returns the mount selected for an absolute guest path from the supplied mount list.
    public static @Nullable Mount mountForGuestPath(
            Mount @Unmodifiable [] mounts,
            String guestPath) {
        @Nullable Mount best = null;
        for (Mount mount : mounts) {
            if (guestPathMatchesMount(guestPath, mount.guestPath())
                    && (best == null || mount.guestPath().length() >= best.guestPath().length())) {
                best = mount;
            }
        }
        return best;
    }

    /// Resolves an absolute guest path below a host-directory mount.
    public static @Nullable Path resolveHostFile(String absoluteGuestPath, HostMount mount) {
        String relativePath = relativeGuestPath(absoluteGuestPath, mount.guestPath());
        try {
            Path hostFile = mount.root().resolve(relativePath).normalize();
            return hostFile.startsWith(mount.root()) ? hostFile : null;
        } catch (InvalidPathException exception) {
            return null;
        }
    }

    /// Appends a relative path to an absolute guest path and normalizes the result.
    public static String appendGuestPath(String basePath, String relativePath) {
        if (relativePath.isEmpty()) {
            return basePath;
        }
        String combined = "/".equals(basePath) ? "/" + relativePath : basePath + "/" + relativePath;
        @Nullable String normalized = normalizeAbsoluteGuestPath(combined);
        return normalized == null ? combined : normalized;
    }

    /// Joins the remaining path segments after a followed symbolic link.
    public static String joinRemainingSegments(String @Unmodifiable [] segments, int startIndex) {
        if (startIndex >= segments.length) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (int index = startIndex; index < segments.length; index++) {
            if (!builder.isEmpty()) {
                builder.append('/');
            }
            builder.append(segments[index]);
        }
        return builder.toString();
    }

    /// Returns true when the guest path is absolute in Linux path syntax.
    public static boolean isAbsoluteGuestPath(String guestPath) {
        return guestPath.startsWith("/");
    }

    /// Normalizes an absolute Linux guest path without allowing it to escape above `/`.
    public static @Nullable String normalizeAbsoluteGuestPath(String guestPath) {
        if (!isAbsoluteGuestPath(guestPath) || guestPath.indexOf('\\') >= 0 || guestPath.indexOf(':') >= 0) {
            return null;
        }

        ArrayList<String> segments = new ArrayList<>();
        for (String segment : guestPath.split("/")) {
            if (segment.isEmpty() || ".".equals(segment)) {
                continue;
            }
            if ("..".equals(segment)) {
                if (segments.isEmpty()) {
                    return null;
                }
                segments.remove(segments.size() - 1);
                continue;
            }
            segments.add(segment);
        }
        return segments.isEmpty() ? "/" : "/" + String.join("/", segments);
    }

    /// Removes every leading Linux path separator from an absolute guest path.
    public static String removeLeadingSlashes(String guestPath) {
        int index = 0;
        while (index < guestPath.length() && guestPath.charAt(index) == '/') {
            index++;
        }
        return guestPath.substring(index);
    }

    /// Returns true when an absolute guest path is inside a mount point.
    public static boolean guestPathMatchesMount(String guestPath, String mountPoint) {
        return "/".equals(mountPoint) || guestPath.equals(mountPoint) || guestPath.startsWith(mountPoint + "/");
    }

    /// Returns the relative guest path inside a selected mount point.
    public static String relativeGuestPath(String guestPath, String mountPoint) {
        if ("/".equals(mountPoint)) {
            return removeLeadingSlashes(guestPath);
        }
        if (guestPath.equals(mountPoint)) {
            return "";
        }
        return guestPath.substring(mountPoint.length() + 1);
    }

    /// Returns the final path segment in an absolute guest path.
    public static String leafName(String guestPath) {
        int separator = guestPath.lastIndexOf('/');
        return separator < 0 ? guestPath : guestPath.substring(separator + 1);
    }

    /// Returns the parent path for an absolute guest path.
    public static String parentPath(String guestPath) {
        int separator = guestPath.lastIndexOf('/');
        if (separator <= 0) {
            return "/";
        }
        return guestPath.substring(0, separator);
    }

    /// Returns true when the host path names an existing entry or a symbolic link.
    public static boolean pathEntryExists(Path hostFile) {
        return Files.exists(hostFile, LinkOption.NOFOLLOW_LINKS);
    }

    /// Returns resolved filesystem mounts.
    public Mount @Unmodifiable [] currentMounts() {
        Mount[] mounts = resolvedMounts;
        if (mounts != null) {
            return mounts;
        }
        synchronized (this) {
            mounts = resolvedMounts;
            if (mounts == null) {
                mounts = resolveCurrentMounts();
                resolvedMounts = mounts;
            }
            return mounts;
        }
    }

    /// Returns the resolved mount snapshot without synchronization.
    private Mount @Unmodifiable [] resolveCurrentMounts() {
        ArrayList<Mount> mounts = new ArrayList<>();
        if (eagerMounts != null) {
            mounts.addAll(Arrays.asList(eagerMounts));
        } else {
            for (String spec : mountSpecs) {
                @Nullable Mount mount = resolveMountSpec(spec);
                if (mount != null) {
                    mounts.add(mount);
                }
            }
        }
        mounts.addAll(Arrays.asList(virtualMounts));
        return mounts.toArray(Mount[]::new);
    }

    /// Returns true when any configured mount uses the supplied guest path exactly.
    private boolean hasMountAt(String guestPath) {
        if (eagerMounts != null) {
            for (Mount mount : eagerMounts) {
                if (mount.guestPath().equals(guestPath)) {
                    return true;
                }
            }
        }
        for (VirtualMount mount : virtualMounts) {
            if (mount.guestPath().equals(guestPath)) {
                return true;
            }
        }
        for (String spec : mountSpecs) {
            if (guestPath.equals(FilesystemMountSpec.parse(spec).guestPath())) {
                return true;
            }
        }
        return false;
    }

    /// Resolves one configured filesystem mount spec.
    private static @Nullable Mount resolveMountSpec(String spec) {
        FilesystemMountSpec mountSpec = FilesystemMountSpec.parse(spec);

        try {
            FilesystemMountSpec.Type type = mountSpec.type();
            if (type == FilesystemMountSpec.Type.TMPFS) {
                return new TarMount(
                        mountSpec.guestPath(),
                        TarFileSystem.emptyMemory(STAT_MODE_ALL | STAT_MODE_STICKY),
                        mountSpec.tmpfsReadOnly(),
                        true);
            }

            Path root = Path.of(mountSpec.hostPath()).toAbsolutePath().normalize();
            if (type == FilesystemMountSpec.Type.AUTO) {
                type = Files.isRegularFile(root) ? FilesystemMountSpec.Type.TAR : FilesystemMountSpec.Type.BIND;
            }

            if (type == FilesystemMountSpec.Type.BIND) {
                if (mountSpec.memory()) {
                    throw new RiscVException("Filesystem mount memory option is only valid for tar mounts");
                }
                return new HostMount(mountSpec.guestPath(), root, mountSpec.bindReadOnly());
            }

            if (!Files.isRegularFile(root)) {
                throw new RiscVException("Tar filesystem mount source is not a regular file: " + mountSpec.hostPath());
            }
            if (!mountSpec.memory() && Boolean.FALSE.equals(mountSpec.readOnly())) {
                throw new RiscVException("Writable tar mounts require memory=true");
            }
            TarFileSystem fileSystem = mountSpec.memory()
                    ? TarFileSystem.readMemory(root)
                    : TarFileSystem.readLazy(root);
            return new TarMount(mountSpec.guestPath(), fileSystem, mountSpec.tarReadOnly());
        } catch (IOException exception) {
            throw new RiscVException("Failed to read tar filesystem mount: " + mountSpec.hostPath(), exception);
        } catch (IllegalArgumentException | SecurityException exception) {
            return null;
        }
    }

    /// Reads all bytes from a host input stream.
    private static byte @Unmodifiable [] readAllBytes(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        while (true) {
            int count = input.read(buffer);
            if (count < 0) {
                return output.toByteArray();
            }
            output.write(buffer, 0, count);
        }
    }

    /// Describes one resolved filesystem mount.
    public interface Mount {
        /// Returns the absolute guest-visible mount point.
        String guestPath();
    }

    /// Provides nodes and payloads for a mounted virtual filesystem.
    ///
    /// Implementations should avoid storing open-file state. The syscall layer
    /// owns descriptor tables, which lets one mounted provider be shared by
    /// multiple future guest threads or replaced per guest process.
    public interface VirtualFileSystem {
        /// Returns the virtual node at an absolute guest path, or null when it is absent.
        @Nullable VirtualNode node(String absoluteGuestPath);

        /// Returns the child nodes for a virtual directory.
        VirtualNode @Unmodifiable [] childNodes(String directoryGuestPath);

        /// Returns generated bytes for a virtual regular file.
        byte @Unmodifiable [] fileData(VirtualNode node);

        /// Returns the symbolic-link target for a virtual symbolic link.
        String linkTarget(VirtualNode node);
    }

    /// Describes one resolved host-directory filesystem mount.
    ///
    /// @param guestPath the absolute guest-visible mount point
    /// @param root the resolved host path backing the mount point
    /// @param readOnly whether guest writes through this mount are rejected
    public record HostMount(String guestPath, Path root, boolean readOnly) implements Mount {
    }

    /// Describes one resolved tar filesystem mount.
    ///
    /// @param guestPath the absolute guest-visible mount point
    /// @param fileSystem the tar filesystem tree backing the mount point
    /// @param readOnly whether guest writes through this mount are rejected
    /// @param tmpfs whether this mount is an empty tmpfs tree rather than an archive-backed tree
    public record TarMount(String guestPath, TarFileSystem fileSystem, boolean readOnly, boolean tmpfs) implements Mount {
        /// Creates an archive-backed tar mount.
        public TarMount(String guestPath, TarFileSystem fileSystem, boolean readOnly) {
            this(guestPath, fileSystem, readOnly, false);
        }
    }

    /// Describes one mounted virtual filesystem provider.
    ///
    /// @param guestPath the absolute guest-visible mount point
    /// @param fileSystem the virtual filesystem provider backing the mount point
    public record VirtualMount(String guestPath, VirtualFileSystem fileSystem) implements Mount {
    }

    /// Stores a guest path resolved against a tar mount.
    ///
    /// @param guestPath the absolute guest path that was resolved
    /// @param mount the tar mount selected for the path
    /// @param node the tar node selected for the path, or null when the path is absent
    public record TarPath(String guestPath, TarMount mount, @Nullable TarNode node) {
    }

    /// Stores a guest path resolved against a virtual filesystem.
    ///
    /// @param guestPath the absolute guest path that was resolved
    /// @param mount the virtual mount selected for the path
    /// @param node the virtual node selected for the path, or null when the path is absent
    public record VirtualPath(String guestPath, VirtualMount mount, @Nullable VirtualNode node) {
    }

    /// Describes one cached Linux directory entry for a directory descriptor.
    ///
    /// @param name the entry name without a trailing null byte
    /// @param inode the deterministic inode value exposed to the guest
    /// @param type the Linux `DT_*` entry type
    public record DirectoryEntry(String name, long inode, byte type) {
    }

    /// Stores one virtual filesystem node.
    ///
    /// @param name the node name without path separators
    /// @param guestPath the absolute guest-visible path for this node
    /// @param directoryEntryType the Linux directory entry type exposed for this node
    /// @param statType the file-type bits exposed through metadata syscalls
    /// @param permissions the Linux permission bits for this node
    /// @param fileKey provider-specific node identity, or null when the provider does not need one
    /// @param linkTarget the symbolic link target, or null for non-link nodes
    public record VirtualNode(
            String name,
            String guestPath,
            byte directoryEntryType,
            int statType,
            int permissions,
            @Nullable Object fileKey,
            @Nullable String linkTarget) {
        /// Creates a virtual directory node.
        public static VirtualNode directory(String guestPath) {
            return new VirtualNode(
                    leafName(guestPath),
                    guestPath,
                    DIRECTORY_ENTRY_DIRECTORY,
                    STAT_MODE_DIRECTORY,
                    STAT_MODE_READ_EXECUTE_ALL,
                    null,
                    null);
        }

        /// Creates a virtual regular-file node.
        public static VirtualNode file(String guestPath, Object fileKey) {
            return new VirtualNode(
                    leafName(guestPath),
                    guestPath,
                    DIRECTORY_ENTRY_REGULAR_FILE,
                    STAT_MODE_REGULAR_FILE,
                    STAT_MODE_READ_ALL,
                    fileKey,
                    null);
        }

        /// Creates a virtual character-device node.
        public static VirtualNode characterDevice(String guestPath, Object fileKey) {
            return new VirtualNode(
                    leafName(guestPath),
                    guestPath,
                    DIRECTORY_ENTRY_CHARACTER_DEVICE,
                    STAT_MODE_CHARACTER_DEVICE,
                    STAT_MODE_ALL,
                    fileKey,
                    null);
        }

        /// Creates a virtual symbolic-link node.
        public static VirtualNode symbolicLink(String guestPath, String linkTarget) {
            return new VirtualNode(
                    leafName(guestPath),
                    guestPath,
                    DIRECTORY_ENTRY_SYMBOLIC_LINK,
                    STAT_MODE_SYMBOLIC_LINK,
                    STAT_MODE_ALL,
                    null,
                    linkTarget);
        }

        /// Returns true when this node is a directory.
        public boolean isDirectory() {
            return directoryEntryType == DIRECTORY_ENTRY_DIRECTORY;
        }

        /// Returns true when this node is a regular file.
        public boolean isFile() {
            return directoryEntryType == DIRECTORY_ENTRY_REGULAR_FILE;
        }

        /// Returns true when this node is a character device.
        public boolean isCharacterDevice() {
            return directoryEntryType == DIRECTORY_ENTRY_CHARACTER_DEVICE;
        }

        /// Returns true when this node is a symbolic link.
        public boolean isSymbolicLink() {
            return directoryEntryType == DIRECTORY_ENTRY_SYMBOLIC_LINK;
        }

        /// Returns the Linux `st_mode` value for this node.
        public int statMode() {
            return statType | permissions;
        }

        /// Returns a deterministic synthetic inode for this node.
        public long inode() {
            return Integer.toUnsignedLong(guestPath.hashCode()) + 0x7000_0000L;
        }
    }

    /// Stores a filesystem built from a tar archive.
    public static final class TarFileSystem {
        /// The synthetic root directory of the tree.
        private final TarNode root;

        /// The seekable tar reader used by lazy mounts, or null for memory mounts.
        private final @Nullable TarArchiveReader reader;

        /// Creates a tar filesystem.
        private TarFileSystem(@Nullable TarArchiveReader reader) {
            this(reader, STAT_MODE_ALL);
        }

        /// Creates a tar filesystem with the supplied root directory mode.
        private TarFileSystem(@Nullable TarArchiveReader reader, int rootMode) {
            this.root = TarNode.directory("", "", null, rootMode, 0, 0);
            this.reader = reader;
        }

        /// Returns the synthetic root directory of the archive.
        public TarNode root() {
            return root;
        }

        /// Creates an empty in-memory filesystem tree.
        static TarFileSystem emptyMemory(int rootMode) {
            return new TarFileSystem(null, rootMode);
        }

        /// Reads a tar archive into an in-memory filesystem tree.
        static TarFileSystem readMemory(Path archive) throws IOException {
            TarFileSystem fileSystem = new TarFileSystem(null);
            ArrayList<PendingTarHardLink> hardLinks = new ArrayList<>();
            try (InputStream input = openMemoryTarInputStream(archive);
                 TarArchiveInputStream tarInput = new TarArchiveInputStream(input)) {
                TarArchiveEntry entry;
                while ((entry = tarInput.getNextEntry()) != null) {
                    String relativePath = normalizeTarEntryName(entry.getName());
                    if (relativePath.isEmpty()) {
                        continue;
                    }

                    int mode = entry.getMode() & STAT_MODE_CHANGE_BITS;
                    long userId = tarId(entry.getLongUserId());
                    long groupId = tarId(entry.getLongGroupId());
                    if (entry.isDirectory()) {
                        fileSystem.addDirectory(relativePath, mode, userId, groupId);
                    } else if (entry.isSymbolicLink()) {
                        @Nullable String target = entry.getLinkName();
                        fileSystem.addSymbolicLink(relativePath, target == null ? "" : target, mode, userId, groupId);
                    } else if (entry.isLink()) {
                        @Nullable String target = entry.getLinkName();
                        String targetPath = normalizeTarEntryName(target == null ? "" : target);
                        if (!targetPath.isEmpty()) {
                            hardLinks.add(new PendingTarHardLink(relativePath, targetPath, mode, userId, groupId));
                        }
                    } else if (entry.isFile()) {
                        fileSystem.addFile(relativePath, new TarFileData(readEntryData(tarInput, entry), null), mode, userId, groupId);
                    }
                }
            }

            for (PendingTarHardLink hardLink : hardLinks) {
                fileSystem.addHardLink(hardLink.path(), hardLink.targetPath(), hardLink.mode(), hardLink.userId(), hardLink.groupId());
            }
            return fileSystem;
        }

        /// Opens a memory tar source, transparently unwrapping gzip-compressed archives.
        private static InputStream openMemoryTarInputStream(Path archive) throws IOException {
            BufferedInputStream input = new BufferedInputStream(Files.newInputStream(archive));
            input.mark(2);
            int first = input.read();
            int second = input.read();
            input.reset();
            return first == 0x1f && second == 0x8b ? new GZIPInputStream(input) : input;
        }

        /// Reads tar metadata while leaving regular file contents in the archive.
        static TarFileSystem readLazy(Path archive) throws IOException {
            TarArchiveReader reader = new TarArchiveReader(Files.newByteChannel(archive, EnumSet.of(StandardOpenOption.READ)));
            TarFileSystem fileSystem = new TarFileSystem(reader);
            ArrayList<PendingTarHardLink> hardLinks = new ArrayList<>();
            for (TarArchiveEntry entry : reader.getEntries()) {
                String relativePath = normalizeTarEntryName(entry.getName());
                if (relativePath.isEmpty()) {
                    continue;
                }

                int mode = entry.getMode() & STAT_MODE_CHANGE_BITS;
                long userId = tarId(entry.getLongUserId());
                long groupId = tarId(entry.getLongGroupId());
                if (entry.isDirectory()) {
                    fileSystem.addDirectory(relativePath, mode, userId, groupId);
                } else if (entry.isSymbolicLink()) {
                    @Nullable String target = entry.getLinkName();
                    fileSystem.addSymbolicLink(relativePath, target == null ? "" : target, mode, userId, groupId);
                } else if (entry.isLink()) {
                    @Nullable String target = entry.getLinkName();
                    String targetPath = normalizeTarEntryName(target == null ? "" : target);
                    if (!targetPath.isEmpty()) {
                        hardLinks.add(new PendingTarHardLink(relativePath, targetPath, mode, userId, groupId));
                    }
                } else if (entry.isFile()) {
                    fileSystem.addFile(relativePath, new TarFileData(null, entry), mode, userId, groupId);
                }
            }

            for (PendingTarHardLink hardLink : hardLinks) {
                fileSystem.addHardLink(hardLink.path(), hardLink.targetPath(), hardLink.mode(), hardLink.userId(), hardLink.groupId());
            }
            return fileSystem;
        }

        /// Reads a regular file node payload.
        public byte @Unmodifiable [] readFileData(TarNode node) throws IOException {
            if (!node.isFile()) {
                throw new IOException("Tar node is not a regular file: " + node.path());
            }

            TarFileData fileData = node.fileData();
            if (fileData.data != null) {
                return fileData.data.clone();
            }
            if (fileData.archiveEntry == null || reader == null) {
                return new byte[0];
            }
            synchronized (reader) {
                try (InputStream input = reader.getInputStream(fileData.archiveEntry)) {
                    return readEntryData(input, fileData.archiveEntry);
                }
            }
        }

        /// Opens a regular file node through a seekable channel.
        public SeekableByteChannel openFileChannel(TarNode node, boolean writable) throws IOException {
            return writable
                    ? new MutableTarSeekableByteChannel(node)
                    : new ByteArraySeekableByteChannel(readFileData(node));
        }

        /// Normalizes one tar entry name into a relative Linux guest path.
        private static String normalizeTarEntryName(String name) {
            @Nullable String normalized = normalizeAbsoluteGuestPath("/" + name);
            return normalized == null ? "" : removeLeadingSlashes(normalized);
        }

        /// Reads the current tar entry payload into memory.
        private static byte @Unmodifiable [] readEntryData(
                InputStream input,
                TarArchiveEntry entry) throws IOException {
            long size = entry.getSize();
            if (size < 0 || size > Integer.MAX_VALUE) {
                throw new IOException("Unsupported tar entry size: " + size);
            }

            ByteArrayOutputStream output = new ByteArrayOutputStream((int) size);
            byte[] buffer = new byte[8192];
            long remaining = size;
            while (remaining > 0) {
                int count = input.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                if (count < 0) {
                    throw new IOException("Truncated tar entry: " + entry.getName());
                }
                output.write(buffer, 0, count);
                remaining -= count;
            }
            return output.toByteArray();
        }

        /// Returns the node selected by a relative guest path, or null when it is absent.
        public @Nullable TarNode node(String relativePath) {
            if (relativePath.isEmpty()) {
                return root;
            }

            TarNode current = root;
            for (String segment : relativePath.split("/")) {
                if (!current.isDirectory()) {
                    return null;
                }
                @Nullable TarNode child = current.children().get(segment);
                if (child == null) {
                    return null;
                }
                current = child;
            }
            return current;
        }

        /// Adds or replaces a directory entry and any missing parents.
        private void addDirectory(String path, int mode, long userId, long groupId) {
            TarNode parent = ensureParentDirectory(path);
            String name = leafName(path);
            @Nullable TarNode existing = parent.children.get(name);
            if (existing != null && existing.isDirectory()) {
                return;
            }
            parent.children.put(name, TarNode.directory(name, path, parent, mode, userId, groupId));
        }

        /// Creates a regular file below an existing directory.
        public @Nullable TarNode createFile(String path, int mode, long userId, long groupId) {
            @Nullable TarNode parent = existingParentDirectory(path);
            if (parent == null) {
                return null;
            }
            TarNode node = TarNode.file(
                    leafName(path),
                    path,
                    parent,
                    new TarFileData(new byte[0], null),
                    mode,
                    userId,
                    groupId);
            node.setPermissions(mode);
            parent.children.put(leafName(path), node);
            return node;
        }

        /// Creates a directory below an existing directory.
        public @Nullable TarNode createDirectory(String path, int mode, long userId, long groupId) {
            @Nullable TarNode parent = existingParentDirectory(path);
            if (parent == null) {
                return null;
            }
            TarNode node = TarNode.directory(leafName(path), path, parent, mode, userId, groupId);
            node.setPermissions(mode);
            parent.children.put(leafName(path), node);
            return node;
        }

        /// Creates a symbolic link below an existing directory.
        public @Nullable TarNode createSymbolicLink(
                String path,
                String target,
                int mode,
                long userId,
                long groupId) {
            @Nullable TarNode parent = existingParentDirectory(path);
            if (parent == null) {
                return null;
            }
            TarNode node = TarNode.symbolicLink(
                    leafName(path),
                    path,
                    parent,
                    target,
                    mode,
                    userId,
                    groupId);
            parent.children.put(leafName(path), node);
            return node;
        }

        /// Creates a hard-link entry below an existing directory.
        public @Nullable TarNode createHardLink(String path, TarNode target) {
            @Nullable TarNode parent = existingParentDirectory(path);
            if (parent == null || target.isDirectory()) {
                return null;
            }

            TarNode node = target.isFile()
                    ? TarNode.file(
                            leafName(path),
                            path,
                            parent,
                            target.fileData(),
                            target.permissions(),
                            target.userId(),
                            target.groupId())
                    : TarNode.symbolicLink(
                            leafName(path),
                            path,
                            parent,
                            target.linkTarget(),
                            target.permissions(),
                            target.userId(),
                            target.groupId());
            parent.children.put(leafName(path), node);
            return node;
        }

        /// Removes a node from its parent directory.
        public boolean removeNode(TarNode node) {
            @Nullable TarNode parent = node.parent();
            return parent != null && parent.children.remove(node.name()) != null;
        }

        /// Moves a node below another existing directory and returns the moved replacement node.
        public @Nullable TarNode moveNode(TarNode node, String path) {
            @Nullable TarNode parent = existingParentDirectory(path);
            @Nullable TarNode oldParent = node.parent();
            if (parent == null || oldParent == null) {
                return null;
            }

            TarNode moved = cloneNode(node, leafName(path), path, parent);
            oldParent.children.remove(node.name());
            parent.children.put(moved.name(), moved);
            return moved;
        }

        /// Adds or replaces a regular file entry and any missing parents.
        private void addFile(String path, TarFileData data, int mode, long userId, long groupId) {
            TarNode parent = ensureParentDirectory(path);
            parent.children.put(leafName(path), TarNode.file(leafName(path), path, parent, data, mode, userId, groupId));
        }

        /// Adds or replaces a symbolic link entry and any missing parents.
        private void addSymbolicLink(String path, String target, int mode, long userId, long groupId) {
            TarNode parent = ensureParentDirectory(path);
            parent.children.put(leafName(path), TarNode.symbolicLink(leafName(path), path, parent, target, mode, userId, groupId));
        }

        /// Adds a hard-link entry by sharing the already-read regular-file payload.
        private void addHardLink(String path, String targetPath, int mode, long userId, long groupId) {
            @Nullable TarNode target = node(targetPath);
            if (target == null || !target.isFile()) {
                return;
            }

            int permissions = mode == 0 ? target.permissions() : mode;
            TarNode parent = ensureParentDirectory(path);
            parent.children.put(leafName(path), TarNode.file(leafName(path), path, parent, target.fileData(), permissions, userId, groupId));
        }

        /// Returns the existing parent directory for a relative path.
        private @Nullable TarNode existingParentDirectory(String path) {
            int separator = path.lastIndexOf('/');
            TarNode parent = separator < 0 ? root : node(path.substring(0, separator));
            return parent != null && parent.isDirectory() ? parent : null;
        }

        /// Clones a node and any children under a new parent and relative path.
        private static TarNode cloneNode(TarNode node, String name, String path, TarNode parent) {
            if (node.isDirectory()) {
                TarNode copy = TarNode.directory(name, path, parent, node.permissions(), node.userId(), node.groupId());
                for (TarNode child : node.children.values()) {
                    String childPath = path.isEmpty() ? child.name() : path + "/" + child.name();
                    copy.children.put(child.name(), cloneNode(child, child.name(), childPath, copy));
                }
                return copy;
            }
            if (node.isFile()) {
                return TarNode.file(name, path, parent, node.fileData(), node.permissions(), node.userId(), node.groupId());
            }
            return TarNode.symbolicLink(name, path, parent, node.linkTarget(), node.permissions(), node.userId(), node.groupId());
        }

        /// Ensures that all parent directories for a relative path exist.
        private TarNode ensureParentDirectory(String path) {
            int separator = path.lastIndexOf('/');
            if (separator < 0) {
                return root;
            }

            TarNode current = root;
            StringBuilder currentPath = new StringBuilder();
            for (String segment : path.substring(0, separator).split("/")) {
                if (segment.isEmpty()) {
                    continue;
                }
                if (!currentPath.isEmpty()) {
                    currentPath.append('/');
                }
                currentPath.append(segment);

                @Nullable TarNode child = current.children.get(segment);
                if (child == null || !child.isDirectory()) {
                    child = TarNode.directory(segment, currentPath.toString(), current, STAT_MODE_READ_EXECUTE_ALL, 0, 0);
                    current.children.put(segment, child);
                }
                current = child;
            }
            return current;
        }

        /// Returns a Linux uid or gid stored in a tar entry, defaulting unknown values to root.
        private static long tarId(long id) {
            return id < 0 || id > GuestCredentials.MAX_ID ? 0 : id;
        }
    }

    /// Stores a tar hard link that must be resolved after the archive has been read.
    ///
    /// @param path the archive-relative path where the hard link is exposed
    /// @param targetPath the archive-relative path of the hard-link target
    /// @param mode the permission bits from the hard-link tar entry
    /// @param userId the Linux uid from the hard-link tar entry
    /// @param groupId the Linux gid from the hard-link tar entry
    private record PendingTarHardLink(String path, String targetPath, int mode, long userId, long groupId) {
    }

    /// Stores regular-file payload state for one or more tar nodes.
    private static final class TarFileData {
        /// The in-memory regular-file payload, or null when the payload is lazy.
        private byte @Nullable [] data;

        /// The source archive entry for lazy payloads, or null for new memory-only files.
        private final @Nullable TarArchiveEntry archiveEntry;

        /// Creates regular-file payload state.
        private TarFileData(byte @Nullable [] data, @Nullable TarArchiveEntry archiveEntry) {
            this.data = data;
            this.archiveEntry = archiveEntry;
        }

        /// Returns the file size exposed through metadata syscalls.
        private long size() {
            if (data != null) {
                return data.length;
            }
            return archiveEntry == null ? 0 : archiveEntry.getSize();
        }
    }

    /// Stores one in-memory tar filesystem node.
    public static final class TarNode {
        /// The node name without path separators.
        private final String name;

        /// The archive-relative path for this node.
        private final String path;

        /// The parent directory, or null for the synthetic root node.
        private final @Nullable TarNode parent;

        /// The Linux mode bits exposed for this node.
        private int permissions;

        /// The Linux uid exposed as this node's owner.
        private long userId;

        /// The Linux gid exposed as this node's group.
        private long groupId;

        /// The Linux directory entry type exposed for this node.
        private final byte directoryEntryType;

        /// The file-type bits exposed through `stat` and `statx`.
        private final int statType;

        /// The regular-file payload metadata, or null for non-file nodes.
        private final @Nullable TarFileData fileData;

        /// The symbolic link target, or null for non-link nodes.
        private final @Nullable String linkTarget;

        /// The directory children keyed by entry name.
        private final Map<String, TarNode> children;

        /// Creates a tar node with its immutable metadata and mutable child map.
        private TarNode(
                String name,
                String path,
                @Nullable TarNode parent,
                int permissions,
                long userId,
                long groupId,
                byte directoryEntryType,
                int statType,
                @Nullable TarFileData fileData,
                @Nullable String linkTarget,
                Map<String, TarNode> children) {
            this.name = name;
            this.path = path;
            this.parent = parent;
            this.permissions = permissions;
            this.userId = userId;
            this.groupId = groupId;
            this.directoryEntryType = directoryEntryType;
            this.statType = statType;
            this.fileData = fileData;
            this.linkTarget = linkTarget;
            this.children = children;
        }

        /// Creates a directory tar node.
        static TarNode directory(String name, String path, @Nullable TarNode parent, int mode, long userId, long groupId) {
            return new TarNode(
                    name,
                    path,
                    parent,
                    mode & STAT_MODE_CHANGE_BITS,
                    userId,
                    groupId,
                    DIRECTORY_ENTRY_DIRECTORY,
                    STAT_MODE_DIRECTORY,
                    null,
                    null,
                    new TreeMap<>());
        }

        /// Creates a regular-file tar node.
        static TarNode file(
                String name,
                String path,
                TarNode parent,
                TarFileData fileData,
                int mode,
                long userId,
                long groupId) {
            return new TarNode(
                    name,
                    path,
                    parent,
                    mode & STAT_MODE_CHANGE_BITS,
                    userId,
                    groupId,
                    DIRECTORY_ENTRY_REGULAR_FILE,
                    STAT_MODE_REGULAR_FILE,
                    fileData,
                    null,
                    new TreeMap<>());
        }

        /// Creates a symbolic-link tar node.
        static TarNode symbolicLink(String name, String path, TarNode parent, String target, int mode, long userId, long groupId) {
            return new TarNode(
                    name,
                    path,
                    parent,
                    permissionsOrDefault(mode, STAT_MODE_ALL),
                    userId,
                    groupId,
                    DIRECTORY_ENTRY_SYMBOLIC_LINK,
                    STAT_MODE_SYMBOLIC_LINK,
                    null,
                    target,
                    new TreeMap<>());
        }

        /// Returns nonzero permission bits or the supplied fallback when the archive stores none.
        private static int permissionsOrDefault(int mode, int fallback) {
            int permissions = mode & STAT_MODE_CHANGE_BITS;
            return permissions == 0 ? fallback : permissions;
        }

        /// Returns the node name without path separators.
        public String name() {
            return name;
        }

        /// Returns the archive-relative path for this node.
        public String path() {
            return path;
        }

        /// Returns the parent directory node, or null for the root.
        public @Nullable TarNode parent() {
            return parent;
        }

        /// Returns true when this node is a directory.
        public boolean isDirectory() {
            return directoryEntryType == DIRECTORY_ENTRY_DIRECTORY;
        }

        /// Returns true when this node is a regular file.
        public boolean isFile() {
            return directoryEntryType == DIRECTORY_ENTRY_REGULAR_FILE;
        }

        /// Returns true when this node is a symbolic link.
        public boolean isSymbolicLink() {
            return directoryEntryType == DIRECTORY_ENTRY_SYMBOLIC_LINK;
        }

        /// Returns the Linux permission bits for this node.
        public int permissions() {
            return permissions;
        }

        /// Sets the Linux permission and special mode bits for this node.
        public void setPermissions(int permissions) {
            this.permissions = permissions & STAT_MODE_CHANGE_BITS;
        }

        /// Returns the Linux uid exposed as this node's owner.
        public long userId() {
            return userId;
        }

        /// Returns the Linux gid exposed as this node's group.
        public long groupId() {
            return groupId;
        }

        /// Updates the Linux owner and group exposed for this node.
        public void setOwner(long userId, long groupId) {
            this.userId = userId;
            this.groupId = groupId;
        }

        /// Returns the byte size exposed through metadata syscalls.
        public long size() {
            if (isFile()) {
                return fileData().size();
            }
            if (isSymbolicLink()) {
                assert linkTarget != null;
                return linkTarget.getBytes(StandardCharsets.UTF_8).length;
            }
            return 0;
        }

        /// Returns the regular-file payload metadata.
        private TarFileData fileData() {
            assert fileData != null;
            return fileData;
        }

        /// Returns the symbolic link target.
        public String linkTarget() {
            assert linkTarget != null;
            return linkTarget;
        }

        /// Returns an immutable view of directory children keyed by entry name.
        public @UnmodifiableView Map<String, TarNode> children() {
            return Collections.unmodifiableMap(children);
        }

        /// Returns a deterministic synthetic inode for this node.
        public long inode() {
            return Integer.toUnsignedLong(path.hashCode()) + 4096L;
        }

        /// Returns the parent inode used for a directory `..` entry.
        public long parentInode() {
            return parent == null ? inode() : parent.inode();
        }

        /// Returns the Linux directory entry type for this node.
        public byte directoryEntryType() {
            return directoryEntryType;
        }

        /// Returns the Linux `st_mode` value for this node.
        public int statMode() {
            return statType | permissions;
        }
    }

    /// Implements a read-only `SeekableByteChannel` over an immutable byte array.
    public static final class ByteArraySeekableByteChannel implements SeekableByteChannel {
        /// The immutable channel payload.
        private final byte @Unmodifiable [] data;

        /// The current channel position.
        private int position;

        /// Whether the channel is open.
        private boolean open = true;

        /// Creates a read-only byte-array channel over the supplied payload.
        public ByteArraySeekableByteChannel(byte @Unmodifiable [] data) {
            this.data = data;
        }

        /// Reads bytes from the current position into the destination buffer.
        @Override
        public int read(ByteBuffer destination) throws IOException {
            ensureOpen();
            if (position >= data.length) {
                return -1;
            }

            int count = Math.min(destination.remaining(), data.length - position);
            destination.put(data, position, count);
            position += count;
            return count;
        }

        /// Rejects writes because byte-array channels are read-only.
        @Override
        public int write(ByteBuffer source) throws IOException {
            ensureOpen();
            throw new NonWritableChannelException();
        }

        /// Returns the current channel position.
        @Override
        public long position() throws IOException {
            ensureOpen();
            return position;
        }

        /// Sets the current channel position.
        @Override
        public SeekableByteChannel position(long newPosition) throws IOException {
            ensureOpen();
            if (newPosition < 0 || newPosition > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("Invalid byte-array channel position: " + newPosition);
            }
            position = (int) newPosition;
            return this;
        }

        /// Returns the fixed payload size.
        @Override
        public long size() throws IOException {
            ensureOpen();
            return data.length;
        }

        /// Rejects truncation because byte-array channels are read-only.
        @Override
        public SeekableByteChannel truncate(long size) throws IOException {
            ensureOpen();
            if (size < data.length) {
                throw new NonWritableChannelException();
            }
            return this;
        }

        /// Returns true while the channel is open.
        @Override
        public boolean isOpen() {
            return open;
        }

        /// Closes this byte-array channel.
        @Override
        public void close() {
            open = false;
        }

        /// Throws when the channel is already closed.
        private void ensureOpen() throws ClosedChannelException {
            if (!open) {
                throw new ClosedChannelException();
            }
        }
    }

    /// Implements a writable `SeekableByteChannel` over a memory tar node.
    private static final class MutableTarSeekableByteChannel implements SeekableByteChannel {
        /// The tar regular-file node whose payload is mutated by this channel.
        private final TarNode node;

        /// The current channel position.
        private int position;

        /// Whether the channel is open.
        private boolean open = true;

        /// Creates a writable channel over a tar regular-file node.
        private MutableTarSeekableByteChannel(TarNode node) {
            this.node = node;
            TarFileData fileData = node.fileData();
            if (fileData.data == null) {
                fileData.data = new byte[0];
            }
        }

        /// Reads bytes from the current position into the destination buffer.
        @Override
        public int read(ByteBuffer destination) throws IOException {
            ensureOpen();
            byte[] data = data();
            if (position >= data.length) {
                return -1;
            }

            int count = Math.min(destination.remaining(), data.length - position);
            destination.put(data, position, count);
            position += count;
            return count;
        }

        /// Writes bytes from the source buffer into the node payload.
        @Override
        public int write(ByteBuffer source) throws IOException {
            ensureOpen();
            int count = source.remaining();
            long end = (long) position + count;
            if (end > Integer.MAX_VALUE) {
                throw new IOException("Memory tar file is too large: " + end);
            }

            TarFileData fileData = node.fileData();
            byte[] data = data();
            if (end > data.length) {
                data = Arrays.copyOf(data, (int) end);
                fileData.data = data;
            }
            source.get(data, position, count);
            position += count;
            return count;
        }

        /// Returns the current channel position.
        @Override
        public long position() throws IOException {
            ensureOpen();
            return position;
        }

        /// Sets the current channel position.
        @Override
        public SeekableByteChannel position(long newPosition) throws IOException {
            ensureOpen();
            if (newPosition < 0 || newPosition > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("Invalid memory tar channel position: " + newPosition);
            }
            position = (int) newPosition;
            return this;
        }

        /// Returns the current payload size.
        @Override
        public long size() throws IOException {
            ensureOpen();
            return data().length;
        }

        /// Truncates the node payload when the requested size is smaller.
        @Override
        public SeekableByteChannel truncate(long size) throws IOException {
            ensureOpen();
            if (size < 0 || size > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("Invalid memory tar channel size: " + size);
            }

            TarFileData fileData = node.fileData();
            byte[] data = data();
            if (size < data.length) {
                fileData.data = Arrays.copyOf(data, (int) size);
            }
            if (position > size) {
                position = (int) size;
            }
            return this;
        }

        /// Returns true while the channel is open.
        @Override
        public boolean isOpen() {
            return open;
        }

        /// Closes this channel.
        @Override
        public void close() {
            open = false;
        }

        /// Returns the current node payload.
        private byte[] data() {
            byte @Nullable [] data = node.fileData().data;
            assert data != null;
            return data;
        }

        /// Throws when the channel is already closed.
        private void ensureOpen() throws ClosedChannelException {
            if (!open) {
                throw new ClosedChannelException();
            }
        }
    }
}
