/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { KeyInfo, KeyType } from "./keys";

/** Minimal async key-value store. In the plugin this is Vencord's DataStore. */
export interface KV {
    get<T>(key: string): Promise<T | undefined>;
    set(key: string, value: unknown): Promise<void>;
}

export class MemoryKV implements KV {
    readonly data = new Map<string, unknown>();
    async get<T>(key: string) {
        const v = this.data.get(key);
        return v === undefined ? undefined : structuredClone(v) as T;
    }
    async set(key: string, value: unknown) {
        this.data.set(key, structuredClone(value));
    }
}

export interface ContactKey {
    type: KeyType;
    material: string;
    fingerprint: string;
    addedAt: number;
}

export interface Contact {
    userId: string;
    /** Name at the time the key was saved, for when Discord can't resolve the user. */
    displayName: string;
    key: ContactKey;
    verified: boolean;
    verifiedAt?: number;
    /** A different key this contact shared that hasn't been accepted. Never used for encryption. */
    pendingKey?: ContactKey & { seenAt: number; messageId?: string; };
    /** Fingerprints this contact used before, newest last. */
    history: { type: KeyType; fingerprint: string; replacedAt: number; }[];
    /** Shared keys the user looked at and chose not to accept. */
    dismissed?: string[];
}

export type ObserveResult =
    | { kind: "unknown"; }
    | { kind: "same"; }
    | { kind: "dismissed"; }
    | { kind: "changed"; contact: Contact; };

const STORE_KEY = "Cipher_contacts_v1";
const HISTORY_LIMIT = 10;

function toContactKey(info: KeyInfo, now: number): ContactKey {
    return { type: info.type, material: info.material, fingerprint: info.fingerprint, addedAt: now };
}

export class KeyChangeError extends Error {
    constructor(readonly contact: Contact) {
        super("This contact already has a different key. Replacing it must be confirmed.");
        this.name = "KeyChangeError";
    }
}

/**
 * Contact book keyed by Discord user ID. A key is only ever replaced through
 * replaceKey() or acceptPendingKey(), both of which the UI calls after a
 * loud, explicit confirmation.
 */
export class ContactBook {
    private contacts = new Map<string, Contact>();
    private listeners = new Set<() => void>();

    constructor(private kv: KV, private now: () => number = Date.now) { }

    async load() {
        const stored = await this.kv.get<Record<string, Contact>>(STORE_KEY);
        this.contacts = new Map(Object.entries(stored ?? {}));
        this.emit();
    }

    subscribe(fn: () => void) {
        this.listeners.add(fn);
        return () => void this.listeners.delete(fn);
    }

    private emit() {
        for (const fn of this.listeners) fn();
    }

    private async save() {
        await this.kv.set(STORE_KEY, Object.fromEntries(this.contacts));
        this.emit();
    }

    get(userId: string): Contact | undefined {
        return this.contacts.get(userId);
    }

    list(): Contact[] {
        return [...this.contacts.values()].sort((a, b) => a.displayName.localeCompare(b.displayName));
    }

    /** Adds a contact. Throws KeyChangeError if they already have a different key. */
    async add(userId: string, displayName: string, info: KeyInfo): Promise<"added" | "unchanged"> {
        const existing = this.contacts.get(userId);
        if (existing) {
            if (existing.key.fingerprint === info.fingerprint && existing.key.type === info.type) return "unchanged";
            throw new KeyChangeError(existing);
        }
        this.contacts.set(userId, {
            userId,
            displayName,
            key: toContactKey(info, this.now()),
            verified: false,
            history: []
        });
        await this.save();
        return "added";
    }

    /** Explicitly replaces a contact's key. Resets verification. */
    async replaceKey(userId: string, info: KeyInfo, opts: { verified?: boolean; } = {}): Promise<void> {
        const c = this.contacts.get(userId);
        if (!c) throw new Error("Unknown contact");
        if (c.key.fingerprint !== info.fingerprint || c.key.type !== info.type) {
            c.history = [...c.history, { type: c.key.type, fingerprint: c.key.fingerprint, replacedAt: this.now() }].slice(-HISTORY_LIMIT);
            c.key = toContactKey(info, this.now());
        }
        c.verified = !!opts.verified;
        c.verifiedAt = opts.verified ? this.now() : undefined;
        delete c.pendingKey;
        await this.save();
    }

    /**
     * Called when a contact posts a key in chat. Never changes the active key:
     * a different key is parked as pendingKey and reported as "changed".
     */
    async observeSharedKey(userId: string, info: KeyInfo, messageId?: string): Promise<ObserveResult> {
        const c = this.contacts.get(userId);
        if (!c) return { kind: "unknown" };
        if (c.key.fingerprint === info.fingerprint && c.key.type === info.type) return { kind: "same" };
        if (c.dismissed?.includes(info.fingerprint)) return { kind: "dismissed" };
        if (c.pendingKey?.fingerprint !== info.fingerprint) {
            c.pendingKey = { ...toContactKey(info, this.now()), seenAt: this.now(), messageId };
            await this.save();
        }
        return { kind: "changed", contact: c };
    }

    /** Compares a fingerprint with the stored one without changing anything. */
    checkKey(userId: string, type: KeyType, fingerprint: string): "unknown" | "same" | "changed" {
        const c = this.contacts.get(userId);
        if (!c) return "unknown";
        return c.key.fingerprint === fingerprint && c.key.type === type ? "same" : "changed";
    }

    /** Keeps the current key. The rejected key won't be flagged again. */
    async dismissPendingKey(userId: string) {
        const c = this.contacts.get(userId);
        if (!c?.pendingKey) return;
        c.dismissed = [...c.dismissed ?? [], c.pendingKey.fingerprint].slice(-HISTORY_LIMIT);
        delete c.pendingKey;
        await this.save();
    }

    isDismissed(userId: string, fingerprint: string) {
        return !!this.contacts.get(userId)?.dismissed?.includes(fingerprint);
    }

    async setVerified(userId: string, verified: boolean) {
        const c = this.contacts.get(userId);
        if (!c) return;
        c.verified = verified;
        c.verifiedAt = verified ? this.now() : undefined;
        await this.save();
    }

    async rename(userId: string, displayName: string) {
        const c = this.contacts.get(userId);
        if (!c || c.displayName === displayName) return;
        c.displayName = displayName;
        await this.save();
    }

    async remove(userId: string) {
        if (this.contacts.delete(userId)) await this.save();
    }
}
