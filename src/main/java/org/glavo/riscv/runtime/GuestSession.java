// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.riscv.runtime;

import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Unmodifiable;

/// Stores state shared by every guest process in one POSIX session.
@NotNullByDefault
final class GuestSession {
    /// The guest process id of the session leader.
    private final int id;

    /// The raw non-NUL bytes of the session login name.
    private byte @Unmodifiable [] loginName;

    /// Creates a session with a defensively copied login name.
    GuestSession(int id, byte[] loginName) {
        this.id = id;
        this.loginName = loginName.clone();
    }

    /// Returns the guest session id.
    int id() {
        return id;
    }

    /// Returns a snapshot of the session login name bytes.
    synchronized byte @Unmodifiable [] loginName() {
        return loginName.clone();
    }

    /// Replaces the session login name with a defensive copy.
    synchronized void setLoginName(byte[] loginName) {
        this.loginName = loginName.clone();
    }

    /// Creates a new session that inherits this session's current login name.
    synchronized GuestSession copyForLeader(int leaderId) {
        return new GuestSession(leaderId, loginName);
    }
}
