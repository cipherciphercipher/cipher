/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * What the server accepts. It can't read messages, so it checks their shape:
 * only a real age or OpenPGP encrypted message gets stored, never a file or
 * plain text, and only a real public key goes into the directory.
 */

import { checkMessageShape, checkPublicKeyShape, dearmorPgp, PacketError, readSessionKeys } from "../../src/core/pgpPackets";

export const MAX_MESSAGE_CHARS = 32 * 1024;
export const MAX_READERS = 10;
export const MAX_PGP_KEY_CHARS = 32 * 1024;

const AGE_BEGIN = "-----BEGIN AGE ENCRYPTED FILE-----";
const AGE_END = "-----END AGE ENCRYPTED FILE-----";
const PGP_MSG_BEGIN = "-----BEGIN PGP MESSAGE-----";
const PGP_MSG_END = "-----END PGP MESSAGE-----";
const PGP_KEY_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const PGP_KEY_END = "-----END PGP PUBLIC KEY BLOCK-----";

export const AGE_RECIPIENT_RE = /^age1[02-9ac-hj-np-z]{58}$/;
export const AGE_PQ_RECIPIENT_RE = /^age1pq1[02-9ac-hj-np-z]{1952}$/;

export class Invalid extends Error { }

function strictBase64(s: string): Uint8Array {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) throw new Invalid("bad base64");
    const bin = atob(s);
    return Uint8Array.from(bin, c => c.charCodeAt(0));
}

/** The whole text must be exactly one armor block, nothing before or after. */
function onlyArmor(text: string, begin: string, end: string): string {
    const t = text.replace(/\r\n/g, "\n").trim();
    if (!t.startsWith(begin + "\n") || !t.endsWith("\n" + end)) throw new Invalid("not a single armor block");
    if (t.indexOf(begin, 1) !== -1 || t.indexOf(end) !== t.length - end.length) throw new Invalid("more than one block");
    return t;
}

/* ---------- age ---------- */

/** age file header (age-encryption.org/v1): only X25519 and post-quantum hybrid recipients, no passphrase. */
export function checkAgeMessage(text: string): void {
    const t = onlyArmor(text, AGE_BEGIN, AGE_END);
    const lines = t.split("\n").slice(1, -1);
    // age armor: 64-character lines, the last one shorter (RFC 7468 strict).
    for (let i = 0; i < lines.length; i++) {
        const last = i === lines.length - 1;
        if (lines[i].length === 0 || lines[i].length > 64 || (!last && lines[i].length !== 64)) throw new Invalid("bad armor lines");
    }
    const bin = strictBase64(lines.join(""));
    const head = new TextDecoder("latin1").decode(bin.subarray(0, Math.min(bin.length, 64 * 1024)));
    if (!head.startsWith("age-encryption.org/v1\n")) throw new Invalid("not an age file");
    const macAt = head.indexOf("\n--- ");
    if (macAt === -1) throw new Invalid("no header MAC");
    const stanzas = head.slice(0, macAt).split("\n").slice(1).filter(l => l.startsWith("-> "));
    if (stanzas.length === 0 || stanzas.length > MAX_READERS) throw new Invalid("bad reader count");
    for (const s of stanzas) {
        const kind = s.split(" ")[1];
        if (kind !== "X25519" && kind !== "mlkem768x25519") throw new Invalid("unsupported age recipient");
    }
    // After the MAC line: a 16-byte nonce and at least one encrypted chunk (16-byte tag).
    const macLineEnd = head.indexOf("\n", macAt + 1);
    if (macLineEnd === -1 || bin.length - (macLineEnd + 1) < 16 + 16) throw new Invalid("no payload");
}

/* ---------- OpenPGP ---------- */

/** End offset of the packet starting at `i`, following partial body lengths. */
function packetEnd(data: Uint8Array, i: number): { tag: number; end: number; } {
    const b = data[i];
    if (b === undefined || !(b & 0x80)) throw new Invalid("bad packet header");
    if (!(b & 0x40)) {
        const tag = (b >> 2) & 0x0f, t = b & 3;
        if (t === 3) throw new Invalid("indeterminate length");
        const hdr = t === 0 ? 2 : t === 1 ? 3 : 5;
        const len = t === 0 ? data[i + 1] : t === 1 ? (data[i + 1] << 8) + data[i + 2] : ((data[i + 1] << 24) >>> 0) + (data[i + 2] << 16) + (data[i + 3] << 8) + data[i + 4];
        if (!Number.isFinite(len) || i + hdr + len > data.length) throw new Invalid("truncated packet");
        return { tag, end: i + hdr + len };
    }
    const tag = b & 0x3f;
    let p = i + 1;
    for (let chunks = 0; chunks < 4096; chunks++) {
        const o = data[p];
        if (o === undefined) throw new Invalid("truncated packet");
        let len: number, hdr: number, partial = false;
        if (o < 192) { len = o; hdr = 1; }
        else if (o < 224) { len = ((o - 192) << 8) + (data[p + 1] ?? NaN) + 192; hdr = 2; }
        else if (o === 255) { len = ((data[p + 1] << 24) >>> 0) + (data[p + 2] << 16) + (data[p + 3] << 8) + data[p + 4]; hdr = 5; }
        else { len = 1 << (o & 0x1f); hdr = 1; partial = true; }
        if (!Number.isFinite(len) || p + hdr + len > data.length) throw new Invalid("truncated packet");
        p += hdr + len;
        if (!partial) return { tag, end: p };
    }
    throw new Invalid("too many chunks");
}

/** Session-key packets for 1..10 public keys, no passphrase, then one encrypted data packet and nothing else. */
export function checkPgpMessage(text: string): void {
    const t = onlyArmor(text, PGP_MSG_BEGIN, PGP_MSG_END);
    let data: Uint8Array;
    let s;
    try {
        data = dearmorPgp(t);
        s = readSessionKeys(data, MAX_READERS);
    } catch (e) {
        throw new Invalid(e instanceof PacketError ? e.message : "bad message");
    }
    if (s.passphrase > 0 || s.publicKey === 0) throw new Invalid("not encrypted to public keys");
    let i = 0;
    let packet = packetEnd(data, i);
    while (packet.tag === 1 || packet.tag === 10) {
        i = packet.end;
        packet = packetEnd(data, i);
    }
    // 18 = SEIPD (RFC 9580), 20 = OCB-encrypted data (LibrePGP, GnuPG 2.4+).
    if (packet.tag !== 18 && packet.tag !== 20) throw new Invalid("no encrypted data packet");
    if (packet.end !== data.length) throw new Invalid("data after the message");
    // The same shape check Cipher runs before handing a message to GnuPG.
    try {
        checkMessageShape(data, MAX_READERS);
    } catch (e) {
        throw new Invalid(e instanceof PacketError ? e.message : "bad message");
    }
}

export function checkMessage(text: string): "age" | "pgp" {
    if (text.length > MAX_MESSAGE_CHARS) throw new Invalid("too large");
    const t = text.trimStart();
    if (t.startsWith(AGE_BEGIN)) {
        checkAgeMessage(text);
        return "age";
    }
    if (t.startsWith(PGP_MSG_BEGIN)) {
        checkPgpMessage(text);
        return "pgp";
    }
    throw new Invalid("not an encrypted message");
}

/* ---------- public keys ---------- */

async function digestHex(alg: "SHA-1" | "SHA-256", parts: Uint8Array[]): Promise<string> {
    const total = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { total.set(p, o); o += p.length; }
    const d = new Uint8Array(await crypto.subtle.digest(alg, total));
    return [...d].map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

/**
 * Checks an OpenPGP public key and returns its fingerprint (v4: SHA-1, v6:
 * SHA-256, RFC 9580 §5.5.4). Only public-key, subkey, user ID and signature
 * packets are allowed, so nothing else can be smuggled into the directory.
 */
export async function checkPgpPublicKey(text: string): Promise<string> {
    if (text.length > MAX_PGP_KEY_CHARS) throw new Invalid("key too large");
    const t = onlyArmor(text, PGP_KEY_BEGIN, PGP_KEY_END);
    let data: Uint8Array;
    try {
        data = dearmorPgp(t);
    } catch {
        throw new Invalid("bad armor");
    }
    let i = 0, first = true, fingerprint = "";
    while (i < data.length) {
        const start = i;
        const { tag, end } = packetEnd(data, i);
        const hdrLen = (() => {
            const b = data[start];
            if (!(b & 0x40)) { const lt = b & 3; return lt === 0 ? 2 : lt === 1 ? 3 : 5; }
            const o = data[start + 1];
            return o < 192 ? 2 : o < 224 ? 3 : o === 255 ? 6 : -1;
        })();
        if (hdrLen < 0) throw new Invalid("partial length in a key");
        if (![2, 6, 13, 14].includes(tag)) throw new Invalid(`packet type ${tag} isn't allowed in a public key`);
        if (first) {
            if (tag !== 6) throw new Invalid("doesn't start with a public key");
            const body = data.subarray(start + hdrLen, end);
            if (body[0] === 4) {
                fingerprint = await digestHex("SHA-1", [Uint8Array.from([0x99, body.length >> 8, body.length & 0xff]), body]);
            } else if (body[0] === 6) {
                const n = body.length;
                fingerprint = await digestHex("SHA-256", [Uint8Array.from([0x9b, n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]), body]);
            } else {
                throw new Invalid("unsupported key version");
            }
            first = false;
        } else if (tag === 6) {
            throw new Invalid("more than one key");
        }
        i = end;
    }
    if (!fingerprint) throw new Invalid("no key");
    // The same shape check Cipher runs before handing a key to GnuPG (no photo IDs etc.).
    try {
        checkPublicKeyShape(data);
    } catch (e) {
        throw new Invalid(e instanceof PacketError ? e.message : "bad key");
    }
    return fingerprint;
}

/** age keys: the same fingerprint Cipher shows (SHA-256 of the key text). */
export async function checkAgePublicKey(text: string): Promise<string> {
    const t = text.trim();
    if (!AGE_RECIPIENT_RE.test(t) && !AGE_PQ_RECIPIENT_RE.test(t)) throw new Invalid("not an age public key");
    return digestHex("SHA-256", [new TextEncoder().encode(t)]);
}
