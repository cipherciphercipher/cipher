/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { CipherError } from "./errors";

const encoder = new TextEncoder();

export function utf8Encode(s: string): Uint8Array {
    return encoder.encode(s);
}

export function utf8Decode(b: Uint8Array): string {
    try {
        return new TextDecoder("utf-8", { fatal: true }).decode(b);
    } catch {
        throw new CipherError("not-text");
    }
}

export function toHex(b: Uint8Array): string {
    let s = "";
    for (const x of b) s += x.toString(16).padStart(2, "0");
    return s;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) {
        out.set(p, o);
        o += p.length;
    }
    return out;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}

const ID_ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789";

/** Random identifier for linking message parts. Not secret, just unique. */
export function randomId(length = 8): string {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    let s = "";
    for (const b of bytes) s += ID_ALPHABET[b & 31];
    return s;
}
