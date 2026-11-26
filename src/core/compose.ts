/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { ageDecrypt, ageEncrypt } from "./ageCipher";
import { randomId, utf8Encode } from "./bytes";
import { attachmentHeader, attachmentName, DISCORD_CHAR_LIMIT, fileNotice, splitArmored } from "./envelope";
import { CipherError } from "./errors";
import type { KeyType } from "./keys";
import { decodePayload, encodePayload } from "./payload";
import { pgpDecrypt, pgpEncrypt, pgpEngine, type SignatureStatus } from "./pgpCipher";
import type { PgpEngine } from "./pgpEngine";
import type { CiphertextPlan } from "./recipients";

export interface BuildOptions {
    ciphertexts: CiphertextPlan[];
    text: string;
    /** Fingerprint of the user's GnuPG key to sign PGP ciphertexts with. */
    signFingerprint?: string;
    /** Defaults to the installed GnuPG bridge. */
    pgp?: PgpEngine;
    charLimit?: number;
    /** More messages than this and the ciphertext goes in an attachment instead. */
    maxMessages?: number;
    newId?: () => string;
}

export interface EncryptedFile {
    name: string;
    type: KeyType;
    content: string;
}

export type Outgoing =
    | { kind: "messages"; messages: string[]; compressed: boolean; }
    | { kind: "file"; notice: string; attachmentContent: string; files: EncryptedFile[]; compressed: boolean; };

export const DEFAULT_MAX_MESSAGES = 4;

async function encryptOne(ct: CiphertextPlan, payload: Uint8Array, opts: BuildOptions) {
    return ct.type === "age" ? ageEncrypt(ct.keys, payload) : pgpEncrypt(opts.pgp ?? pgpEngine(), ct.keys, payload, opts.signFingerprint);
}

/**
 * Builds the Discord messages for an encrypted send.
 *
 * Order of fallbacks for long messages: first try uncompressed (no
 * compression side channel for short messages), then compress, then split
 * into up to maxMessages messages, and finally move the ciphertext into an
 * attachment.
 */
export async function buildOutgoing(opts: BuildOptions): Promise<Outgoing> {
    if (opts.ciphertexts.length === 0) throw new CipherError("internal");
    const limit = opts.charLimit ?? DISCORD_CHAR_LIMIT;
    const maxMessages = opts.maxMessages ?? DEFAULT_MAX_MESSAGES;
    const newId = opts.newId ?? randomId;
    const set = opts.ciphertexts.length > 1 ? newId() : undefined;
    const refs = opts.ciphertexts.map(() => newId());

    const encryptAll = async (compress: boolean) => {
        const payload = await encodePayload(opts.text, compress);
        const armored = await Promise.all(opts.ciphertexts.map(ct => encryptOne(ct, payload, opts)));
        const split = armored.map((a, i) => splitArmored(a, { type: opts.ciphertexts[i].type, ref: refs[i], set, limit }));
        return { armored, split, count: split.reduce((n, s) => n + s.length, 0) };
    };

    let compressed = false;
    let result = await encryptAll(false);
    if (result.count > opts.ciphertexts.length && utf8Encode(opts.text).length > 64) {
        const smaller = await encryptAll(true);
        if (smaller.count < result.count || smaller.armored.join("").length < result.armored.join("").length) {
            result = smaller;
            compressed = true;
        }
    }

    if (result.count <= maxMessages) return { kind: "messages", messages: result.split.flat(), compressed };

    const fileRef = newId();
    return {
        kind: "file",
        notice: fileNotice(fileRef, set),
        attachmentContent: attachmentHeader(fileRef, set),
        files: result.armored.map((content, i) => ({ name: attachmentName(fileRef, opts.ciphertexts[i].type), type: opts.ciphertexts[i].type, content })),
        compressed
    };
}

/** The server stores at most this much per message. */
export const MAX_LINK_CIPHERTEXT = 32 * 1024;

/** The exact text the server stores (and hashes), for a given armored ciphertext. */
export function normalizeForServer(armored: string): string {
    return armored.replace(/\r\n/g, "\n").trim() + "\n";
}

/**
 * Ciphertexts for a disappearing message: one per plan entry, compressed
 * when that's smaller, never split. Fails if one is over the server's limit.
 */
export async function buildLinkCiphertexts(opts: Pick<BuildOptions, "ciphertexts" | "text" | "signFingerprint" | "pgp">): Promise<{ type: KeyType; armored: string; }[]> {
    if (opts.ciphertexts.length === 0) throw new CipherError("internal");
    const encryptAll = async (compress: boolean) => {
        const payload = await encodePayload(opts.text, compress);
        return Promise.all(opts.ciphertexts.map(async ct => normalizeForServer(await encryptOne(ct, payload, opts as BuildOptions))));
    };
    let armored = await encryptAll(false);
    if (utf8Encode(opts.text).length > 64) {
        const smaller = await encryptAll(true);
        if (smaller.join("").length < armored.join("").length) armored = smaller;
    }
    if (armored.some(a => a.length > MAX_LINK_CIPHERTEXT))
        throw new CipherError("too-large", "This message is too long for a disappearing message. Send it as a normal message, or shorten it.");
    return armored.map((a, i) => ({ type: opts.ciphertexts[i].type, armored: a }));
}

export interface DecryptedMessage {
    text: string;
    /** Only PGP messages can carry signatures. */
    signature: SignatureStatus | { status: "not-supported"; };
}

export interface DecryptKeys {
    /** The user's age secret key, if they have one and Cipher is unlocked. */
    ageIdentity?: string;
    /** GnuPG, which holds the user's PGP secret key. Defaults to the installed bridge. */
    pgp?: PgpEngine;
}

/**
 * Decrypts armored ciphertext. `verificationKeys` are armored PGP public keys
 * to check signatures against (contacts and your own key).
 */
export async function decryptArmored(type: KeyType, armored: string, keys: DecryptKeys, verificationKeys: string[] = []): Promise<DecryptedMessage> {
    if (type === "age") {
        const data = await ageDecrypt(armored, keys.ageIdentity ? [keys.ageIdentity] : []);
        return { text: await decodePayload(data), signature: { status: "not-supported" } };
    }
    const { data, signature } = await pgpDecrypt(keys.pgp ?? pgpEngine(), armored, verificationKeys);
    return { text: await decodePayload(data), signature };
}
