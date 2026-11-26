/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import * as DataStore from "@api/DataStore";
import { UserStore, useEffect, useReducer } from "@webpack/common";

import { candidatesFor } from "./core/candidates";
import { ChannelPrefs } from "./core/channelPrefs";
import { type Contact, ContactBook, type KV } from "./core/contacts";
import { GroupStore } from "./core/groups";
import { IdentityManager } from "./core/identity";
import type { Candidate } from "./core/recipients";

/**
 * Everything is stored per Discord account, so switching accounts never
 * mixes up keys or contacts.
 */
function scopedKV(accountId: string): KV {
    const k = (key: string) => `${key}:${accountId}`;
    return {
        get: key => DataStore.get(k(key)),
        set: (key, value) => DataStore.set(k(key), value)
    };
}

class CipherState {
    accountId?: string;
    contacts!: ContactBook;
    groups!: GroupStore;
    channels!: ChannelPrefs;
    identity!: IdentityManager;
    private loading?: Promise<void>;
    private loaded = false;
    private listeners = new Set<() => void>();
    private unsubs: (() => void)[] = [];

    /** Loads stores for the logged-in account. Safe to call often. */
    ensure(): Promise<void> {
        const id = UserStore.getCurrentUser()?.id;
        if (!id) return Promise.reject(new Error("Not logged in"));
        if (id === this.accountId && this.loading) return this.loading;

        this.reset();
        this.accountId = id;
        const kv = scopedKV(id);
        this.contacts = new ContactBook(kv);
        this.groups = new GroupStore(kv);
        this.channels = new ChannelPrefs(kv);
        this.identity = new IdentityManager(kv);
        this.unsubs = [this.contacts, this.groups, this.channels, this.identity].map(s => s.subscribe(() => this.emit()));
        const loading = Promise.all([this.contacts.load(), this.groups.load(), this.channels.load(), this.identity.load()]).then(() => {
            if (this.loading !== loading) return;
            this.loaded = true;
            this.emit();
        });
        // If storage fails, let the next call retry instead of failing forever.
        loading.catch(() => { if (this.loading === loading) this.loading = undefined; });
        this.loading = loading;
        return loading;
    }

    get ready() {
        return this.loaded && this.accountId === UserStore.getCurrentUser()?.id;
    }

    /** Drops secrets and in-memory state (lock, logout, plugin stop). */
    reset() {
        this.identity?.lock();
        this.channels?.clearSession();
        for (const u of this.unsubs) u();
        this.unsubs = [];
        this.loading = undefined;
        this.loaded = false;
        this.accountId = undefined;
        this.emit();
    }

    subscribe(fn: () => void) {
        this.listeners.add(fn);
        return () => void this.listeners.delete(fn);
    }

    private emit() {
        for (const fn of this.listeners) fn();
    }
}

export const state = new CipherState();

/** Re-renders the component whenever any Cipher store changes. Returns whether stores are loaded. */
export function useCipher(): boolean {
    const [, force] = useReducer((x: number) => x + 1, 0);
    useEffect(() => {
        const unsub = state.subscribe(force);
        if (!state.ready) state.ensure().then(force, () => { });
        return unsub;
    }, []);
    return state.ready;
}

export function selfId(): string {
    return UserStore.getCurrentUser().id;
}

export function userName(userId: string): string {
    const u = UserStore.getUser(userId);
    if (u) return (u as any).globalName || u.username;
    return state.contacts?.get(userId)?.displayName ?? `User ${userId}`;
}

export function contactName(c: Contact) {
    return UserStore.getUser(c.userId) ? userName(c.userId) : c.displayName;
}

/** Planner candidates for the given users (all contacts when omitted), with fresh key checks. */
export function loadCandidates(userIds?: string[]): Promise<Map<string, Candidate>> {
    const contacts = userIds
        ? userIds.map(id => state.contacts.get(id)).filter((c): c is Contact => !!c)
        : state.contacts.list();
    return candidatesFor(contacts, contactName);
}
