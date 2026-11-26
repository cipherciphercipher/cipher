/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Just enough OpenPGP packet parsing (RFC 9580) to tell who a message is
 * for, in plain JavaScript. Messages in chat are read here first, so GnuPG
 * only ever sees messages that are addressed to one of the user's keys:
 * strangers' messages never reach GnuPG's C parser.
 */

/** More session-key packets than this is refused. Cipher sends at most 10 readers. */
export const MAX_SESSION_KEY_PACKETS = 32;

export class PacketError extends Error {
    constructor(message = "malformed OpenPGP data") {
        super(message);
        this.name = "PacketError";
    }
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_INDEX = new Map([...B64].map((c, i) => [c, i]));

function base64Decode(s: string): Uint8Array {
    const clean = s.replace(/=+$/, "");
    if (clean.length % 4 === 1) throw new PacketError();
    const out = new Uint8Array(Math.floor(clean.length * 3 / 4));
    let bits = 0, acc = 0, o = 0;
    for (const c of clean) {
        const v = B64_INDEX.get(c);
        if (v === undefined) throw new PacketError();
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (acc >> bits) & 0xff;
        }
    }
    return out.subarray(0, o);
}

/** ASCII armor to binary (RFC 9580 §6.2). */
export function dearmorPgp(armored: string): Uint8Array {
    const lines = armored.replace(/\r\n/g, "\n").split("\n");
    const begin = lines.findIndex(l => /^-----BEGIN PGP [A-Z ]+-----$/.test(l.trim()));
    if (begin === -1) throw new PacketError();
    let i = begin + 1;
    // Skip armor headers up to the blank line.
    while (i < lines.length && lines[i].trim() !== "" && lines[i].includes(":")) i++;
    let b64 = "";
    let ended = false;
    for (; i < lines.length; i++) {
        const l = lines[i].trim();
        if (l.startsWith("-----END PGP")) {
            ended = true;
            break;
        }
        if (/^=[A-Za-z0-9+/]{4}$/.test(l)) continue; // CRC24 checksum
        if (l && !/^[A-Za-z0-9+/=]+$/.test(l)) throw new PacketError();
        b64 += l;
    }
    if (!b64 || !ended) throw new PacketError();
    return base64Decode(b64);
}

export interface SessionKeys {
    /** Public-key session-key packets (tag 1). */
    publicKey: number;
    /** Passphrase session-key packets (tag 3). */
    passphrase: number;
    /** Key IDs the public-key packets name, uppercase hex. */
    keyIds: string[];
    /** Public-key packets that don't say which key they're for (hidden recipients). */
    anonymous: number;
}

const hex = (b: Uint8Array) => [...b].map(x => x.toString(16).padStart(2, "0")).join("").toUpperCase();

/** Which key a PKESK packet body (RFC 9580 §5.1) is for, or null when it's hidden. */
function pkeskKeyId(body: Uint8Array): string | null {
    if (body[0] === 3) {
        if (body.length < 10) throw new PacketError();
        const id = body.subarray(1, 9);
        return id.every(b => b === 0) ? null : hex(id);
    }
    if (body[0] === 6) {
        if (body.length < 2) throw new PacketError();
        const n = body[1];
        if (n === 0) return null;
        if (body.length < 2 + n) throw new PacketError();
        const version = body[2];
        const fpr = body.subarray(3, 2 + n);
        if (version === 4 && fpr.length === 20) return hex(fpr.subarray(12));
        if (version === 6 && fpr.length === 32) return hex(fpr.subarray(0, 8));
        throw new PacketError();
    }
    throw new PacketError("unsupported session-key packet version");
}

/**
 * Reads the session-key packets at the start of a message, up to the first
 * other packet. Throws PacketError on anything it can't read.
 */
export function readSessionKeys(data: Uint8Array, max = MAX_SESSION_KEY_PACKETS): SessionKeys {
    const out: SessionKeys = { publicKey: 0, passphrase: 0, keyIds: [], anonymous: 0 };
    let i = 0;
    while (i < data.length) {
        const b = data[i];
        if (!(b & 0x80)) throw new PacketError();
        let tag: number, len: number, hdr: number;
        if (b & 0x40) {
            tag = b & 0x3f;
            const o = data[i + 1];
            if (o === undefined) throw new PacketError();
            if (o < 192) { len = o; hdr = 2; }
            else if (o < 224) { len = ((o - 192) << 8) + (data[i + 2] ?? NaN) + 192; hdr = 3; }
            else if (o === 255) { len = ((data[i + 2] << 24) >>> 0) + (data[i + 3] << 16) + (data[i + 4] << 8) + data[i + 5]; hdr = 6; }
            // Partial lengths are only allowed on data packets, which end the scan.
            else { len = -1; hdr = 2; }
        } else {
            tag = (b >> 2) & 0x0f;
            const t = b & 3;
            hdr = t === 0 ? 2 : t === 1 ? 3 : t === 2 ? 5 : 1;
            len = t === 0 ? data[i + 1] : t === 1 ? (data[i + 1] << 8) + data[i + 2] : t === 2 ? ((data[i + 1] << 24) >>> 0) + (data[i + 2] << 16) + (data[i + 3] << 8) + data[i + 4] : -1;
        }
        // Marker packets (tag 10) are ignored by readers; anything else ends the list.
        if (tag !== 1 && tag !== 3 && tag !== 10) return out;
        if (!Number.isFinite(len) || len < 0 || i + hdr + len > data.length) throw new PacketError();
        if (tag === 1) {
            out.publicKey++;
            const id = pkeskKeyId(data.subarray(i + hdr, i + hdr + len));
            if (id) out.keyIds.push(id);
            else out.anonymous++;
        }
        if (tag === 3) out.passphrase++;
        if (out.publicKey + out.passphrase > max) throw new PacketError("too many session-key packets");
        i += hdr + len;
    }
    return out;
}

export type Addressing = "yes" | "no" | "hidden";

/** Whether a PGP message can be for one of `ownKeyIds`, judged from its packets alone. */
export function pgpAddressing(armored: string, ownKeyIds: string[]): Addressing {
    const s = readSessionKeys(dearmorPgp(armored));
    // A passphrase packet is refused by the decrypt step anyway.
    if (s.passphrase > 0 || s.publicKey === 0) return "no";
    const mine = new Set(ownKeyIds.map(k => k.toUpperCase()));
    if (s.keyIds.some(k => mine.has(k))) return "yes";
    return s.anonymous > 0 ? "hidden" : "no";
}

/* ---------- packet shapes checked before GnuPG ---------- */

/*
 * GnuPG is C code, and anything handed to it is parsed by it. These checks
 * run first, in JavaScript, and only let through the exact shapes Cipher
 * makes and needs: a public key of key, subkey, user ID and signature
 * packets (no photo IDs, which GnuPG can hand to an external viewer), and
 * a message of session-key packets followed by one encrypted packet. After
 * decryption, the inside must be literal data with at most one signature,
 * never compressed (Cipher never compresses PGP data; it compresses the
 * plaintext itself, in JavaScript).
 */

export interface PacketSpan { tag: number; start: number; bodyStart: number; end: number; partial: boolean; }

/** The packet at `i`, following partial body lengths. Throws PacketError on anything malformed. */
export function packetAt(data: Uint8Array, i: number): PacketSpan {
    const b = data[i];
    if (b === undefined || !(b & 0x80)) throw new PacketError();
    if (!(b & 0x40)) {
        const tag = (b >> 2) & 0x0f, t = b & 3;
        if (t === 3) throw new PacketError("indeterminate length");
        const hdr = t === 0 ? 2 : t === 1 ? 3 : 5;
        if (i + hdr > data.length) throw new PacketError();
        const len = t === 0 ? data[i + 1] : t === 1 ? (data[i + 1] << 8) + data[i + 2] : ((data[i + 1] << 24) >>> 0) + (data[i + 2] << 16) + (data[i + 3] << 8) + data[i + 4];
        if (i + hdr + len > data.length) throw new PacketError();
        return { tag, start: i, bodyStart: i + hdr, end: i + hdr + len, partial: false };
    }
    const tag = b & 0x3f;
    let p = i + 1, partial = false, bodyStart = -1;
    for (let chunks = 0; chunks < 65536; chunks++) {
        const o = data[p];
        if (o === undefined) throw new PacketError();
        let len: number, hdr: number, more = false;
        if (o < 192) { len = o; hdr = 1; }
        else if (o < 224) { if (p + 1 >= data.length) throw new PacketError(); len = ((o - 192) << 8) + data[p + 1] + 192; hdr = 2; }
        else if (o === 255) { if (p + 4 >= data.length) throw new PacketError(); len = ((data[p + 1] << 24) >>> 0) + (data[p + 2] << 16) + (data[p + 3] << 8) + data[p + 4]; hdr = 5; }
        else { len = 1 << (o & 0x1f); hdr = 1; more = true; partial = true; }
        if (bodyStart < 0) bodyStart = p + hdr;
        if (p + hdr + len > data.length) throw new PacketError();
        p += hdr + len;
        if (!more) return { tag, start: i, bodyStart, end: p, partial };
    }
    throw new PacketError("too many chunks");
}

function packets(data: Uint8Array, max: number): PacketSpan[] {
    const out: PacketSpan[] = [];
    for (let i = 0; i < data.length;) {
        if (out.length >= max) throw new PacketError("too many packets");
        const p = packetAt(data, i);
        out.push(p);
        i = p.end;
    }
    return out;
}

export const MAX_PUBLIC_KEY_BYTES = 64 * 1024;

/**
 * A transferable public key as Cipher accepts it: one primary key (v4 or
 * v6), then only subkeys, user IDs and signatures, no partial lengths, no
 * photo IDs (user attributes), no secret keys, no trust packets.
 */
export function checkPublicKeyShape(data: Uint8Array): void {
    if (data.length === 0 || data.length > MAX_PUBLIC_KEY_BYTES) throw new PacketError("key size");
    const ps = packets(data, 1024);
    if (ps[0].tag !== 6) throw new PacketError("doesn't start with a public key");
    let subkeys = 0, uids = 0;
    for (const [n, p] of ps.entries()) {
        if (p.partial) throw new PacketError("partial length in a key");
        if (p.tag === 17) throw new PacketError("photo ID");
        if (p.tag === 6 && n > 0) throw new PacketError("more than one key");
        if (![2, 6, 13, 14].includes(p.tag)) throw new PacketError(`packet type ${p.tag} in a key`);
        if ((p.tag === 6 || p.tag === 14) && ![4, 6].includes(data[p.bodyStart])) throw new PacketError("key version");
        if (p.tag === 13 && p.end - p.bodyStart > 2048) throw new PacketError("user ID too long");
        if (p.tag === 14 && ++subkeys > 32) throw new PacketError("too many subkeys");
        if (p.tag === 13 && ++uids > 64) throw new PacketError("too many user IDs");
    }
}

/**
 * A secret key file as Cipher imports it: secret keys (5) each followed by
 * secret subkeys (7), user IDs (13) and signatures (2). No photo IDs, no
 * partial lengths, at most 16 keys.
 */
export function checkSecretKeyShape(data: Uint8Array): void {
    if (data.length === 0 || data.length > 256 * 1024) throw new PacketError("key size");
    const ps = packets(data, 4096);
    if (ps[0].tag !== 5) throw new PacketError("doesn't start with a secret key");
    let keys = 0;
    for (const p of ps) {
        if (p.partial) throw new PacketError("partial length in a key");
        if (p.tag === 17) throw new PacketError("photo ID");
        if (![2, 5, 7, 13].includes(p.tag)) throw new PacketError(`packet type ${p.tag} in a key`);
        if (p.tag === 5 && ++keys > 16) throw new PacketError("too many keys");
        if (p.tag === 13 && p.end - p.bodyStart > 2048) throw new PacketError("user ID too long");
    }
}

/**
 * An encrypted message as Cipher accepts it: public-key session-key packets
 * (and markers), then exactly one SEIPD (18) or OCB-encrypted (20) packet
 * reaching the end. No passphrase packets, nothing after the data.
 */
export function checkMessageShape(data: Uint8Array, maxSessionKeys = MAX_SESSION_KEY_PACKETS): void {
    const ps = packets(data, maxSessionKeys + 16);
    let esk = 0;
    for (const [n, p] of ps.entries()) {
        const last = n === ps.length - 1;
        if (p.tag === 10) continue;
        if (p.tag === 1) {
            if (p.partial) throw new PacketError();
            if (++esk > maxSessionKeys) throw new PacketError("too many session-key packets");
            continue;
        }
        if ((p.tag === 18 || p.tag === 20) && last && esk > 0) return;
        throw new PacketError(p.tag === 3 ? "passphrase packet" : "unexpected packet");
    }
    throw new PacketError("no encrypted data");
}

/**
 * What's inside after decryption: one literal-data packet (11), optionally
 * with one signature, either old style (signature, literal) or one-pass
 * (one-pass signature, literal, signature). Never compressed.
 */
export function checkInnerShape(data: Uint8Array): void {
    // GnuPG writes compressed packets with an indeterminate length, so look at the tag first.
    const b = data[0];
    if (b !== undefined && (b & 0x80) && ((b & 0x40) ? b & 0x3f : (b >> 2) & 0x0f) === 8) throw new PacketError("compressed");
    const tags = packets(data, 8).map(p => p.tag).filter(t => t !== 10);
    const ok = (t: number[]) => t.length === tags.length && t.every((x, i) => x === tags[i]);
    if (ok([11]) || ok([2, 11]) || ok([4, 11, 2])) return;
    throw new PacketError(tags.includes(8) ? "compressed" : "unexpected packets inside");
}
