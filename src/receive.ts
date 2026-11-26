/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { Message } from "@vencord/discord-types";
import { MessageStore } from "@webpack/common";

import { decryptArmored, type DecryptedMessage } from "./core/compose";
import { ATTACHMENT_MAX_BYTES, parseAttachmentName, parseContent, reassemble } from "./core/envelope";
import { CipherError, type ErrorCode, errorCode, safeMessage } from "./core/errors";
import type { KeyType } from "./core/keys";
import { pgpAddressedTo } from "./core/pgpCipher";
import { state } from "./state";

export type DecryptOutcome =
    | ({ ok: true; } & DecryptedMessage)
    | { ok: false; code: ErrorCode; message: string; };

/**
 * Decrypted results, in memory only and keyed by the ciphertext itself.
 * Wiped whenever Cipher locks, the account changes or the plugin stops.
 * Plaintext is never written to Discord's message store or to disk.
 */
const results = new Map<string, Promise<DecryptOutcome>>();
/** Plenty for scrolling through history; the oldest results are dropped first. */
const MAX_RESULTS = 2000;

export function clearDecryptCache() {
    results.clear();
}

/**
 * After you close GnuPG's passphrase prompt, Cipher stops decrypting PGP
 * messages on its own until you click "Decrypt". Anyone with your public key
 * can post PGP messages to you, so without this every one of them would open
 * the prompt again.
 */
let pgpPaused = false;
const pauseListeners = new Set<() => void>();

export function isPgpPaused() {
    return pgpPaused;
}

export function setPgpPaused(paused: boolean) {
    if (pgpPaused === paused) return;
    pgpPaused = paused;
    for (const f of pauseListeners) f();
}

export function onPgpPauseChange(f: () => void): () => void {
    pauseListeners.add(f);
    return () => void pauseListeners.delete(f);
}

function verificationKeys(): string[] {
    const keys = state.contacts.list().filter(c => c.key.type === "pgp").map(c => c.key.material);
    for (const c of state.contacts.list()) if (c.pendingKey?.type === "pgp") keys.push(c.pendingKey.material);
    const own = state.identity.publicIdentity.pgp?.publicKey;
    if (own) keys.push(own);
    return keys;
}

/** Checks that need no private key, so they work while locked. */
export async function precheck(type: KeyType, armored: string, opts: { tryHidden?: boolean; } = {}): Promise<DecryptOutcome | null> {
    const fail = (code: ErrorCode): DecryptOutcome => ({ ok: false, code, message: new CipherError(code).message });
    if (!state.identity.has(type)) return fail("missing-key");
    if (type === "pgp") {
        try {
            // Read in JavaScript: only messages for the user's key go on to GnuPG.
            const to = pgpAddressedTo(armored, state.identity.publicIdentity.pgp!.keyIds);
            if (to === "no") return fail("not-recipient");
            if (to === "hidden" && !opts.tryHidden) return fail("hidden-recipients");
        } catch (e) {
            return { ok: false, code: errorCode(e), message: safeMessage(e) };
        }
    }
    return null;
}

export function decryptCached(type: KeyType, armored: string, opts: { tryHidden?: boolean; } = {}): Promise<DecryptOutcome> {
    const key = `${type}\n${opts.tryHidden ? "h" : ""}\n${armored}`;
    let p = results.get(key);
    if (!p) {
        p = (async (): Promise<DecryptOutcome> => {
            const pre = await precheck(type, armored, opts);
            if (pre) return pre;
            try {
                if (!state.identity.isUnlocked) return { ok: false, code: "locked", message: new CipherError("locked").message };
                const r = await decryptArmored(type, armored, { ageIdentity: state.identity.ageIdentity }, verificationKeys());
                return { ok: true, ...r };
            } catch (e) {
                return { ok: false, code: errorCode(e), message: safeMessage(e) };
            }
        })();
        // Don't cache "locked" or "cancelled": both change once the user acts.
        p.then(r => {
            if (r.ok || (r.code !== "locked" && r.code !== "cancelled")) return;
            results.delete(key);
            if (r.code === "cancelled" && type === "pgp") setPgpPaused(true);
        });
        if (results.size >= MAX_RESULTS) results.delete(results.keys().next().value!);
        results.set(key, p);
    }
    return p;
}

export interface PartGroup {
    type: KeyType;
    ref: string;
    set?: string;
    total: number;
    /** message ID per present part number */
    present: Map<number, string>;
    /** The message that shows the decrypted text: the highest part present. */
    displayMessageId: string;
    result: ReturnType<typeof reassemble>;
}

function channelMessages(channelId: string): Message[] {
    return (MessageStore.getMessages(channelId) as any)?._array ?? [];
}

/** All parts of one encrypted message from one author that are currently loaded. */
export function collectParts(channelId: string, authorId: string, ref: string): PartGroup | null {
    let group: Omit<PartGroup, "result" | "displayMessageId"> | null = null;
    const bodies: { part: number; total: number; body: string; }[] = [];
    let best = -1;
    let displayMessageId = "";
    for (const m of channelMessages(channelId)) {
        if (m.author?.id !== authorId) continue;
        const p = parseContent(m.content);
        if (p?.kind !== "part" || p.ref !== ref) continue;
        group ??= { type: p.type, ref, set: p.set, total: p.total, present: new Map() };
        group.present.set(p.part, m.id);
        bodies.push(p);
        if (p.part > best) {
            best = p.part;
            displayMessageId = m.id;
        }
    }
    if (!group) return null;
    return { ...group, displayMessageId, result: reassemble(bodies) };
}

/** A cheap string that changes whenever the loaded parts change, for useStateFromStores. */
export function partsSignature(channelId: string, authorId: string, ref: string): string {
    let sig = "";
    for (const m of channelMessages(channelId)) {
        if (m.author?.id !== authorId || !m.content.includes(`ref ${ref}`)) continue;
        sig += `${m.id}:${m.content.length};`;
    }
    return sig;
}

/** Other ciphertexts sent together with this one (the age/PGP copies of one message). */
export function siblingTypes(channelId: string, authorId: string, set: string, ref: string): KeyType[] {
    const types = new Set<KeyType>();
    for (const m of channelMessages(channelId)) {
        if (m.author?.id !== authorId) continue;
        const p = parseContent(m.content);
        if (p?.kind === "part" && p.set === set && p.ref !== ref) types.add(p.type);
        if (p?.kind === "attachment" && p.set === set) {
            for (const a of m.attachments ?? []) {
                const n = parseAttachmentName(a.filename);
                if (n) types.add(n.type);
            }
        }
    }
    return [...types];
}

/** Cipher attachments on a message, best match for the user's keys first. */
export function cipherAttachments(message: Message) {
    const out: { type: KeyType; url: string; size: number; name: string; }[] = [];
    for (const a of message.attachments ?? []) {
        const n = parseAttachmentName(a.filename);
        if (n) out.push({ type: n.type, url: a.url, size: a.size, name: a.filename });
    }
    return out.sort((a, b) => Number(state.identity.has(b.type)) - Number(state.identity.has(a.type)));
}

const downloads = new Map<string, Promise<string>>();

/** Only Discord's own CDN; never fetch an arbitrary URL from message data. */
const ATTACHMENT_HOSTS = new Set(["cdn.discordapp.com", "media.discordapp.net"]);

function isDiscordCdn(url: string) {
    try {
        const u = new URL(url);
        return u.protocol === "https:" && ATTACHMENT_HOSTS.has(u.hostname);
    } catch {
        return false;
    }
}

export function fetchAttachmentText(url: string, size: number): Promise<string> {
    if (size > ATTACHMENT_MAX_BYTES) return Promise.reject(new CipherError("too-large"));
    if (!isDiscordCdn(url)) return Promise.reject(new CipherError("internal", "This attachment isn't hosted on Discord, so Cipher won't download it."));
    let p = downloads.get(url);
    if (!p) {
        p = fetch(url, { credentials: "omit", referrerPolicy: "no-referrer" }).then(async r => {
            if (!r.ok) throw new CipherError("internal", "Couldn't download the encrypted attachment.");
            const text = await r.text();
            if (text.length > ATTACHMENT_MAX_BYTES) throw new CipherError("too-large");
            return text;
        }).catch(e => {
            downloads.delete(url);
            throw e instanceof CipherError ? e : new CipherError("internal", "Couldn't download the encrypted attachment.");
        });
        downloads.set(url, p);
    }
    return p;
}
