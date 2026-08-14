// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.riscv.runtime;

import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;

/// Stores user-mode process state that is shared by all guest threads.
@NotNullByDefault
final class GuestProcess {
    /// The deterministic initial guest process id returned by process identity syscalls.
    static final int PROCESS_ID = 1;

    /// The fixed initial parent process id returned by `getppid`.
    static final int PARENT_PROCESS_ID = 0;

    /// The fixed initial process group id used by process-group syscalls.
    static final int PROCESS_GROUP_ID = PROCESS_ID;

    /// The guest process id represented by this process.
    private final int id;

    /// The guest parent process id represented by this process.
    private final int parentId;

    /// The guest process group id represented by this process.
    private int processGroupId;

    /// The POSIX session shared with other processes in the same session.
    private GuestSession session;

    /// The process nice value in the portable `-20` through `19` range.
    private int niceValue;

    /// The numbered FreeBSD CPU set assigned to all threads in this process.
    private int freeBsdCpuSetId;

    /// The process leader represented by the initial guest thread.
    private final GuestThread initialThread;

    /// Live guest threads in this process.
    private final ArrayList<GuestThread> threads = new ArrayList<>();

    /// Creates a guest process with its initial thread registered.
    GuestProcess(
            int id,
            int parentId,
            int processGroupId,
            int niceValue,
            int freeBsdCpuSetId,
            GuestSession session) {
        this.id = id;
        this.parentId = parentId;
        this.processGroupId = processGroupId;
        this.niceValue = niceValue;
        this.freeBsdCpuSetId = freeBsdCpuSetId;
        this.session = session;
        this.initialThread = new GuestThread(id);
        threads.add(initialThread);
    }

    /// Creates the initial guest process.
    static GuestProcess initial() {
        return new GuestProcess(
                PROCESS_ID,
                PARENT_PROCESS_ID,
                PROCESS_GROUP_ID,
                0,
                1,
                new GuestSession(PROCESS_ID, new byte[0]));
    }

    /// Returns the guest process id.
    int id() {
        return id;
    }

    /// Returns the guest parent process id.
    int parentId() {
        return parentId;
    }

    /// Returns the guest process group id.
    synchronized int processGroupId() {
        return processGroupId;
    }

    /// Updates the guest process group id represented by this process.
    synchronized void setProcessGroupId(int processGroupId) {
        this.processGroupId = processGroupId;
    }

    /// Returns the POSIX session shared by this process.
    synchronized GuestSession session() {
        return session;
    }

    /// Returns the guest session id.
    synchronized int sessionId() {
        return session.id();
    }

    /// Returns true when this process leads its current process group.
    synchronized boolean isProcessGroupLeader() {
        return processGroupId == id;
    }

    /// Returns true when this process leads its current session.
    synchronized boolean isSessionLeader() {
        return session.id() == id;
    }

    /// Creates a new session and process group while inheriting the previous session login name.
    synchronized void startNewSession() {
        session = session.copyForLeader(id);
        processGroupId = id;
    }

    /// Returns the process nice value.
    synchronized int niceValue() {
        return niceValue;
    }

    /// Updates the process nice value after ABI permission and range checks.
    synchronized void setNiceValue(int niceValue) {
        this.niceValue = niceValue;
    }

    /// Returns the numbered FreeBSD CPU set assigned to this process.
    synchronized int freeBsdCpuSetId() {
        return freeBsdCpuSetId;
    }

    /// Assigns this process and all of its threads to a numbered FreeBSD CPU set.
    synchronized void setFreeBsdCpuSetId(int freeBsdCpuSetId) {
        this.freeBsdCpuSetId = freeBsdCpuSetId;
    }

    /// Returns the effective FreeBSD memory-domain policy reported for this process.
    synchronized int freeBsdDomainPolicy(int basePolicy) {
        int policy = basePolicy;
        for (GuestThread thread : threads) {
            policy = thread.freeBsdDomainPolicy(basePolicy);
        }
        return policy;
    }

    /// Replaces the anonymous FreeBSD memory-domain policy of every live thread in this process.
    synchronized void setFreeBsdDomainPolicy(int policy) {
        for (GuestThread thread : threads) {
            thread.setFreeBsdDomainPolicy(policy);
        }
    }

    /// Returns the process leader thread state used by the initial architectural state.
    GuestThread initialThread() {
        return initialThread;
    }

    /// Creates an unregistered child thread state with a fresh guest thread id.
    GuestThread createChildThread(int threadId) {
        return new GuestThread(threadId);
    }

    /// Registers a live guest thread in this process.
    synchronized void registerThread(GuestThread thread) {
        threads.add(thread);
    }

    /// Removes a guest thread from the live process registry.
    synchronized void unregisterThread(GuestThread thread) {
        threads.remove(thread);
    }

    /// Returns the number of currently live guest threads in this process.
    synchronized int threadCount() {
        return threads.size();
    }

    /// Returns the live guest thread with the supplied id, or null when none is known.
    synchronized @Nullable GuestThread thread(long threadId) {
        if (threadId != (int) threadId) {
            return null;
        }

        int id = (int) threadId;
        for (GuestThread thread : threads) {
            if (thread.id() == id) {
                return thread;
            }
        }
        return null;
    }
}
