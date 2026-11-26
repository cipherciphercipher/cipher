/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { Contact } from "./contacts";
import { inspectKey, type KeyProblem } from "./keys";
import type { Candidate } from "./recipients";

/**
 * Re-checks contact keys (PGP keys can expire or be revoked at any time) and
 * turns them into planner candidates. A key that can't be checked (for
 * example because GnuPG is missing) is reported as unusable instead of being
 * skipped, so the send is blocked rather than silently losing a reader.
 */
export async function candidatesFor(contacts: Contact[], nameOf: (c: Contact) => string, now = Date.now()): Promise<Map<string, Candidate>> {
    const out = new Map<string, Candidate>();
    await Promise.all(contacts.map(async c => {
        let problems: KeyProblem[];
        try {
            problems = (await inspectKey(c.key.type, c.key.material, now)).problems;
        } catch {
            problems = ["check-failed"];
        }
        out.set(c.userId, {
            userId: c.userId,
            name: nameOf(c),
            type: c.key.type,
            material: c.key.material,
            problems,
            verified: c.verified,
            pendingKeyChange: !!c.pendingKey
        });
    }));
    return out;
}
