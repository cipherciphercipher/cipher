/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * People and group DMs read from Discord's own client stores, so contacts and
 * groups can be picked instead of typed in as user IDs. This only reads what
 * the client already has loaded; it makes no requests.
 */

import { ChannelStore, RelationshipStore, UserStore } from "@webpack/common";

import { selfId, userName } from "../state";

export interface DiscordPerson {
    userId: string;
    name: string;
    username?: string;
    friend: boolean;
    /** Names of the group DMs you share with them. */
    groups: string[];
}

export interface DiscordGroup {
    channelId: string;
    name: string;
    /** Everyone in the group DM except you. */
    memberIds: string[];
}

export function discordGroups(): DiscordGroup[] {
    const me = selfId();
    return (ChannelStore.getSortedPrivateChannels?.() ?? [])
        .filter(c => c.isGroupDM())
        .map(c => {
            const memberIds = (c.recipients ?? []).filter(id => id !== me);
            return { channelId: c.id, name: c.name?.trim() || memberIds.map(userName).join(", ") || "Unnamed group", memberIds };
        })
        .filter(g => g.memberIds.length > 0);
}

/** Your friends plus everyone in your group DMs, without you, sorted by name. */
export function discordPeople(): DiscordPerson[] {
    const me = selfId();
    const people = new Map<string, DiscordPerson>();
    const get = (userId: string) => {
        let p = people.get(userId);
        if (!p) {
            p = { userId, name: userName(userId), username: UserStore.getUser(userId)?.username, friend: false, groups: [] };
            people.set(userId, p);
        }
        return p;
    };
    for (const id of RelationshipStore.getFriendIDs?.() ?? []) if (id !== me) get(id).friend = true;
    for (const g of discordGroups()) for (const id of g.memberIds) get(id).groups.push(g.name);
    return [...people.values()].sort((a, b) => Number(b.friend) - Number(a.friend) || a.name.localeCompare(b.name));
}

export function matchesPerson(p: DiscordPerson, query: string): boolean {
    const q = query.trim().toLowerCase();
    if (!q) return true;
    return p.name.toLowerCase().includes(q) || !!p.username?.toLowerCase().includes(q) || p.userId === q;
}
