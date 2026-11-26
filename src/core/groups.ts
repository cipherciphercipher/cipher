/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { randomId } from "./bytes";
import type { KV } from "./contacts";
import { CipherError } from "./errors";
import { MAX_RECIPIENTS } from "./recipients";

export interface RecipientGroup {
    id: string;
    name: string;
    memberIds: string[];
}

/** You are always a reader, so a group can hold everyone else up to the cap. */
export const MAX_GROUP_MEMBERS = MAX_RECIPIENTS - 1;

const STORE_KEY = "Cipher_groups_v1";

function clean(name: string, memberIds: string[]) {
    const n = name.trim();
    if (!n) throw new CipherError("invalid-input", "A group needs a name.");
    const ids = [...new Set(memberIds)];
    if (ids.length > MAX_GROUP_MEMBERS) throw new CipherError("invalid-input", `A group can have at most ${MAX_GROUP_MEMBERS} people (plus you).`);
    return { name: n.slice(0, 64), memberIds: ids };
}

export class GroupStore {
    private groups: RecipientGroup[] = [];
    private listeners = new Set<() => void>();

    constructor(private kv: KV) { }

    async load() {
        this.groups = await this.kv.get<RecipientGroup[]>(STORE_KEY) ?? [];
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
        await this.kv.set(STORE_KEY, this.groups);
        this.emit();
    }

    list(): RecipientGroup[] {
        return this.groups;
    }

    get(id: string) {
        return this.groups.find(g => g.id === id);
    }

    async create(name: string, memberIds: string[]): Promise<RecipientGroup> {
        const g = { id: randomId(10), ...clean(name, memberIds) };
        this.groups = [...this.groups, g];
        await this.save();
        return g;
    }

    async update(id: string, name: string, memberIds: string[]) {
        const c = clean(name, memberIds);
        this.groups = this.groups.map(g => g.id === id ? { ...g, ...c } : g);
        await this.save();
    }

    async remove(id: string) {
        this.groups = this.groups.filter(g => g.id !== id);
        await this.save();
    }
}
