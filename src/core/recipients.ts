/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Turns "who should be able to read this" into concrete ciphertexts.
 *
 * Invariants:
 *  - Nobody is ever dropped. If a selected person can't be encrypted to, the
 *    plan fails and says who and why.
 *  - At most MAX_RECIPIENTS people, counting yourself.
 *  - A ciphertext uses one format. A mixed selection fails unless the user
 *    explicitly allowed one ciphertext per format (allowSplit).
 */

import type { KeyProblem, KeyType } from "./keys";

export const MAX_RECIPIENTS = 10;

export interface Candidate {
    userId: string;
    name: string;
    type: KeyType;
    material: string;
    problems: KeyProblem[];
    verified: boolean;
    /** They posted a different key that hasn't been accepted; we still encrypt to the old one. */
    pendingKeyChange: boolean;
}

export interface SelfKeys {
    userId: string;
    age?: string;
    pgp?: string;
}

export interface PlanInput {
    self: SelfKeys;
    /** Other people. Your own ID is ignored if present. */
    selectedIds: string[];
    lookup: (userId: string) => Candidate | undefined;
    allowSplit: boolean;
    max?: number;
}

export interface CiphertextPlan {
    type: KeyType;
    /** Public keys to encrypt to, yours included when you have a key of this type. */
    keys: string[];
    /** Discord user IDs of everyone who can read this ciphertext. */
    readerIds: string[];
    includesSelf: boolean;
}

export type PlanWarning =
    | { code: "self-cannot-read"; type: KeyType; }
    | { code: "self-not-post-quantum"; }
    | { code: "unverified"; userIds: string[]; }
    | { code: "pending-key-change"; userIds: string[]; };

export type PlanError =
    | { code: "no-recipients"; }
    | { code: "over-cap"; count: number; max: number; }
    | { code: "missing-key"; userIds: string[]; }
    | { code: "unusable-key"; items: { userId: string; name: string; problems: KeyProblem[]; }[]; }
    | { code: "mixed-types"; age: Candidate[]; pgp: Candidate[]; }
    | { code: "mixed-age"; classic: Candidate[]; postQuantum: Candidate[]; };

/** Post-quantum age keys (age1pq1…) must never share a ciphertext with other age keys. */
export const isPostQuantum = (material: string | undefined) => !!material?.startsWith("age1pq1");

export type Plan =
    | { ok: true; ciphertexts: CiphertextPlan[]; readers: Candidate[]; warnings: PlanWarning[]; }
    | { ok: false; error: PlanError; };

export function normaliseSelection(selfId: string, ids: string[]): string[] {
    return [...new Set(ids)].filter(id => id !== selfId);
}

export function planEncryption(input: PlanInput): Plan {
    const max = input.max ?? MAX_RECIPIENTS;
    const ids = normaliseSelection(input.self.userId, input.selectedIds);

    if (ids.length === 0) return { ok: false, error: { code: "no-recipients" } };
    if (ids.length + 1 > max) return { ok: false, error: { code: "over-cap", count: ids.length + 1, max } };

    const missing: string[] = [];
    const readers: Candidate[] = [];
    for (const id of ids) {
        const c = input.lookup(id);
        if (c) readers.push(c);
        else missing.push(id);
    }
    if (missing.length) return { ok: false, error: { code: "missing-key", userIds: missing } };

    const unusable = readers.filter(c => c.problems.length > 0);
    if (unusable.length)
        return { ok: false, error: { code: "unusable-key", items: unusable.map(c => ({ userId: c.userId, name: c.name, problems: c.problems })) } };

    const byType: Record<KeyType, Candidate[]> = { age: [], pgp: [] };
    for (const c of readers) byType[c.type].push(c);
    const types = (["age", "pgp"] as const).filter(t => byType[t].length > 0);

    if (types.length > 1 && !input.allowSplit)
        return { ok: false, error: { code: "mixed-types", age: byType.age, pgp: byType.pgp } };

    // One normal (X25519) age key in a message lets a future quantum computer
    // read it, so post-quantum readers get a ciphertext of their own.
    const ageClassic = byType.age.filter(c => !isPostQuantum(c.material));
    const agePq = byType.age.filter(c => isPostQuantum(c.material));
    if (ageClassic.length && agePq.length && !input.allowSplit)
        return { ok: false, error: { code: "mixed-age", classic: ageClassic, postQuantum: agePq } };

    const groups: { type: KeyType; members: Candidate[]; pq: boolean; }[] = [
        ...ageClassic.length ? [{ type: "age" as const, members: ageClassic, pq: false }] : [],
        ...agePq.length ? [{ type: "age" as const, members: agePq, pq: true }] : [],
        ...byType.pgp.length ? [{ type: "pgp" as const, members: byType.pgp, pq: false }] : []
    ];

    const warnings: PlanWarning[] = [];
    const ciphertexts: CiphertextPlan[] = groups.map(({ type, members, pq }) => {
        let selfKey = input.self[type];
        if (!selfKey) warnings.push({ code: "self-cannot-read", type });
        // A normal own key would undo the post-quantum protection: leave it out.
        // (A post-quantum own key in a normal message is harmless.)
        else if (pq && !isPostQuantum(selfKey)) {
            warnings.push({ code: "self-not-post-quantum" });
            selfKey = undefined;
        }
        return {
            type,
            keys: [...members.map(m => m.material), ...selfKey ? [selfKey] : []],
            readerIds: [...members.map(m => m.userId), ...selfKey ? [input.self.userId] : []],
            includesSelf: !!selfKey
        };
    });

    const unverified = readers.filter(c => !c.verified).map(c => c.userId);
    if (unverified.length) warnings.push({ code: "unverified", userIds: unverified });
    const pending = readers.filter(c => c.pendingKeyChange).map(c => c.userId);
    if (pending.length) warnings.push({ code: "pending-key-change", userIds: pending });

    return { ok: true, ciphertexts, readers, warnings };
}

/**
 * For the "restrict to one type" choice: which selected people keep their
 * place and which would be removed. The UI shows `removed` before applying.
 */
export function restrictToType(selectedIds: string[], lookup: PlanInput["lookup"], type: KeyType) {
    const kept: string[] = [];
    const removed: string[] = [];
    for (const id of selectedIds) (lookup(id)?.type === type ? kept : removed).push(id);
    return { kept, removed };
}

export function describePlanError(error: PlanError, nameOf: (id: string) => string): string {
    switch (error.code) {
        case "no-recipients":
            return "Nobody else is selected, so nobody could read this message. Pick at least one recipient, or turn encryption off for this chat.";
        case "over-cap":
            return `Too many readers: ${error.count} selected, the limit is ${error.max} including you. Remove ${error.count - error.max} and try again.`;
        case "missing-key":
            return `No key saved for ${error.userIds.map(nameOf).join(", ")}. Add their key or remove them from the recipients.`;
        case "unusable-key":
            return "These keys can't be used: " + error.items.map(i => `${i.name} (${i.problems.map(p => p.replace(/-/g, " ")).join(", ")})`).join("; ") + ". Ask them for a new key or remove them."
                + (error.items.some(i => i.problems.includes("check-failed")) ? " If it says \"check failed\", Cipher couldn't check the key: make sure GnuPG is installed and working." : "");
        case "mixed-age":
            return `Some readers have post-quantum age keys (${error.postQuantum.map(c => c.name).join(", ")}) and some normal ones (${error.classic.map(c => c.name).join(", ")}). Mixing them in one message would undo the post-quantum protection, so send one copy per kind or remove some readers.`;
        case "mixed-types":
            return `Your recipients use different key types (age: ${error.age.map(c => c.name).join(", ")}; PGP: ${error.pgp.map(c => c.name).join(", ")}). Choose one type, or allow sending one ciphertext per type.`;
    }
}
