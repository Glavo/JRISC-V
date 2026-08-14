// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.riscv.runtime;

import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Nullable;

import java.util.HashMap;

/// Allocates deterministic process, thread, and FreeBSD CPU-set ids for one emulator run.
@NotNullByDefault
final class GuestProcessRegistry {
    /// The next synthetic Linux id available to child processes or threads.
    private long nextId = GuestProcess.PROCESS_ID + 1L;

    /// The next numbered FreeBSD CPU-set id available for allocation.
    private long nextFreeBsdCpuSetId = 3;

    /// Effective memory-domain policies keyed by numbered FreeBSD CPU-set id.
    private final HashMap<Integer, Integer> freeBsdCpuSetDomainPolicies = new HashMap<>();

    /// Creates a registry whose initial process id is already reserved.
    GuestProcessRegistry() {
        freeBsdCpuSetDomainPolicies.put(0, 2);
        freeBsdCpuSetDomainPolicies.put(1, 2);
        freeBsdCpuSetDomainPolicies.put(2, 4);
    }

    /// Creates a child process that inherits its parent's group, session, nice value, and FreeBSD CPU set.
    synchronized @Nullable GuestProcess createChildProcess(GuestProcess parent) {
        @Nullable Integer id = allocateId();
        if (id == null) {
            return null;
        }
        return new GuestProcess(
                id,
                parent.id(),
                parent.processGroupId(),
                parent.niceValue(),
                parent.freeBsdCpuSetId(),
                parent.session());
    }

    /// Creates a child thread id in the supplied process.
    synchronized @Nullable GuestThread createChildThread(GuestProcess process) {
        @Nullable Integer id = allocateId();
        return id == null ? null : process.createChildThread(id);
    }

    /// Allocates and records a numbered FreeBSD CPU set, or returns null after id exhaustion.
    synchronized @Nullable Integer createFreeBsdCpuSet() {
        long id = nextFreeBsdCpuSetId;
        if (id < 3 || id > Integer.MAX_VALUE) {
            return null;
        }
        nextFreeBsdCpuSetId++;
        freeBsdCpuSetDomainPolicies.put((int) id, 2);
        return (int) id;
    }

    /// Returns true when the supplied value names a known numbered FreeBSD CPU set.
    synchronized boolean isKnownFreeBsdCpuSetId(long id) {
        return id == (int) id && freeBsdCpuSetDomainPolicies.containsKey((int) id);
    }

    /// Returns the memory-domain policy of a numbered FreeBSD CPU set, or null when it is unknown.
    synchronized @Nullable Integer freeBsdCpuSetDomainPolicy(long id) {
        return id == (int) id ? freeBsdCpuSetDomainPolicies.get((int) id) : null;
    }

    /// Replaces the memory-domain policy of a known numbered FreeBSD CPU set.
    synchronized boolean setFreeBsdCpuSetDomainPolicy(long id, int policy) {
        if (id != (int) id || !freeBsdCpuSetDomainPolicies.containsKey((int) id)) {
            return false;
        }
        freeBsdCpuSetDomainPolicies.put((int) id, policy);
        return true;
    }

    /// Allocates one positive Linux id or null after the synthetic id space is exhausted.
    private @Nullable Integer allocateId() {
        long id = nextId;
        if (id <= GuestProcess.PROCESS_ID || id > Integer.MAX_VALUE) {
            return null;
        }
        nextId++;
        return (int) id;
    }
}
