/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { Channel } from "@vencord/discord-types";
import { GuildMemberCountStore } from "@webpack/common";

import { selfId, userName } from "../state";

export type Exposure =
    | { kind: "private"; outsiders: string[]; absentReaders: string[]; }
    | { kind: "server"; channelName: string; memberCount?: number; absentReaders: string[]; };

/**
 * Who can see the ciphertext (and its metadata) without being able to read it.
 * In DMs and group DMs that's every member who isn't a reader. In servers
 * it's everyone with access to the channel, which Cipher can't list.
 */
export function exposureFor(channel: Channel, readerIds: string[]): Exposure {
    const readers = new Set(readerIds);
    if (channel.isPrivate()) {
        const members = new Set(channel.recipients ?? []);
        return {
            kind: "private",
            outsiders: [...members].filter(id => !readers.has(id)),
            absentReaders: readerIds.filter(id => id !== selfId() && !members.has(id))
        };
    }
    return {
        kind: "server",
        channelName: channel.name,
        memberCount: channel.guild_id ? GuildMemberCountStore.getMemberCount(channel.guild_id) : undefined,
        absentReaders: []
    };
}

export function describeExposure(e: Exposure): string[] {
    const out: string[] = [];
    if (e.kind === "private") {
        if (e.outsiders.length) out.push(`${e.outsiders.map(userName).join(", ")} can see this encrypted message but can't read it.`);
        if (e.absentReaders.length) out.push(`${e.absentReaders.map(userName).join(", ")} ${e.absentReaders.length > 1 ? "are" : "is"} a reader but not in this chat, so they won't see it here.`);
    } else {
        out.push(`Everyone who can view #${e.channelName}${e.memberCount ? ` (server has about ${e.memberCount} members)` : ""} sees the encrypted message, who sent it and when. Only the readers above can read it.`);
    }
    return out;
}
