/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Just enough OpenPGP to check a key-proof signature in a Worker: a v4
 * detached signature over binary data (type 0x00) made by the *primary* key
 * of a v4 public key. Crypto is WebCrypto's; this file only parses packets
 * and builds what gets hashed (RFC 9580 §5.2.4).
 *
 * Accepted: RSA (2048 to 8192 bits), ECDSA on P-256/P-384/P-521, Ed25519
 * (legacy EdDSA and the RFC 9580 form). Hashes: SHA-256/384/512.
 * Anything else, and any critical subpacket other than creation and expiry
 * time, makes the signature invalid.
 */

import { dearmorPgp } from "../../src/core/pgpPackets";

const PGP_SIG_BEGIN = "-----BEGIN PGP SIGNATURE-----";
const PGP_SIG_END = "-----END PGP SIGNATURE-----";

const HASHES: Record<number, "SHA-256" | "SHA-384" | "SHA-512"> = { 8: "SHA-256", 9: "SHA-384", 10: "SHA-512" };

const hex = (b: Uint8Array) => [...b].map(x => x.toString(16).padStart(2, "0")).join("");

class Bad extends Error { }

/** Reads one packet with a definite length. Signatures and keys never use partial lengths. */
export function readPacket(data: Uint8Array, i: number): { tag: number; body: Uint8Array; end: number; } {
    const b = data[i];
    if (b === undefined || !(b & 0x80)) throw new Bad();
    let tag: number, len: number, hdr: number;
    if (!(b & 0x40)) {
        tag = (b >> 2) & 0x0f;
        const t = b & 3;
        if (t === 3) throw new Bad();
        hdr = t === 0 ? 2 : t === 1 ? 3 : 5;
        if (i + hdr > data.length) throw new Bad();
        len = t === 0 ? data[i + 1] : t === 1 ? (data[i + 1] << 8) | data[i + 2] : ((data[i + 1] << 24) >>> 0) + (data[i + 2] << 16) + (data[i + 3] << 8) + data[i + 4];
    } else {
        tag = b & 0x3f;
        const o = data[i + 1];
        if (o === undefined) throw new Bad();
        if (o < 192) { len = o; hdr = 2; }
        else if (o < 224) { if (i + 3 > data.length) throw new Bad(); len = ((o - 192) << 8) + data[i + 2] + 192; hdr = 3; }
        else if (o === 255) { if (i + 6 > data.length) throw new Bad(); len = ((data[i + 2] << 24) >>> 0) + (data[i + 3] << 16) + (data[i + 4] << 8) + data[i + 5]; hdr = 6; }
        else throw new Bad();
    }
    const end = i + hdr + len;
    if (end > data.length) throw new Bad();
    return { tag, body: data.subarray(i + hdr, end), end };
}

/** A multiprecision integer: 2-byte bit count, then the bytes. */
function mpi(b: Uint8Array, p: number): { value: Uint8Array; next: number; } {
    if (p + 2 > b.length) throw new Bad();
    const bits = (b[p] << 8) | b[p + 1];
    const len = (bits + 7) >> 3;
    if (p + 2 + len > b.length) throw new Bad();
    return { value: b.subarray(p + 2, p + 2 + len), next: p + 2 + len };
}

function stripZeros(b: Uint8Array): Uint8Array {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    return b.subarray(i);
}

function leftPad(b: Uint8Array, size: number): Uint8Array {
    const v = stripZeros(b);
    if (v.length > size) throw new Bad();
    const out = new Uint8Array(size);
    out.set(v, size - v.length);
    return out;
}

const b64url = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const CURVES: Record<string, { name: "P-256" | "P-384" | "P-521"; size: number; }> = {
    "2a8648ce3d030107": { name: "P-256", size: 32 },
    "2b81040022": { name: "P-384", size: 48 },
    "2b81040023": { name: "P-521", size: 66 }
};
const ED25519_LEGACY_OID = "2b06010401da470f01";

type PrimaryKey =
    | { kind: "rsa"; n: Uint8Array; e: Uint8Array; }
    | { kind: "ecdsa"; curve: { name: "P-256" | "P-384" | "P-521"; size: number; }; point: Uint8Array; }
    | { kind: "ed25519"; point: Uint8Array; legacy: boolean; };

/** The signing material of a v4 primary key packet body, or null if it can't make a proof. */
export function primaryKeyFromBody(body: Uint8Array): PrimaryKey | null {
    try {
        if (body[0] !== 4 || body.length < 7) return null;
        const alg = body[5];
        if (alg === 1 || alg === 3) {
            const n = mpi(body, 6);
            const e = mpi(body, n.next);
            const bits = stripZeros(n.value).length * 8;
            const ev = stripZeros(e.value);
            // e must be odd and at least 3 (e = 1 would make any "signature" valid).
            const eNum = ev.length <= 4 ? ev.reduce((x, b) => x * 256 + b, 0) : NaN;
            if (bits < 2048 || bits > 8192 || !(eNum >= 3) || eNum % 2 === 0) return null;
            return { kind: "rsa", n: stripZeros(n.value), e: ev };
        }
        if (alg === 19 || alg === 22) {
            const oidLen = body[6];
            if (!oidLen || oidLen === 0xff || 7 + oidLen > body.length) return null;
            const oid = hex(body.subarray(7, 7 + oidLen));
            const point = mpi(body, 7 + oidLen).value;
            if (alg === 19) {
                const curve = CURVES[oid];
                if (!curve || point.length !== 1 + 2 * curve.size || point[0] !== 4) return null;
                return { kind: "ecdsa", curve, point };
            }
            if (oid !== ED25519_LEGACY_OID || point.length !== 33 || point[0] !== 0x40) return null;
            return { kind: "ed25519", point: point.subarray(1), legacy: true };
        }
        if (alg === 27) {
            if (body.length !== 6 + 32) return null;
            return { kind: "ed25519", point: body.subarray(6, 38), legacy: false };
        }
        return null;
    } catch {
        return null;
    }
}

/** The primary key packet body of an armored public key (already checked by checkPgpPublicKey). */
export function primaryKeyBody(armoredKey: string): Uint8Array | null {
    try {
        const p = readPacket(dearmorPgp(armoredKey), 0);
        return p.tag === 6 ? p.body : null;
    } catch {
        return null;
    }
}

function concat(...parts: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
}

/** Hashed subpackets: needs a creation time; refuses unknown critical ones and expired signatures. */
function checkSubpackets(area: Uint8Array, nowSec: number): boolean {
    let p = 0, created: number | undefined, expiresIn = 0;
    while (p < area.length) {
        const o = area[p];
        let len: number, hdr: number;
        if (o < 192) { len = o; hdr = 1; }
        else if (o < 255) { if (p + 1 >= area.length) return false; len = ((o - 192) << 8) + area[p + 1] + 192; hdr = 2; }
        else { if (p + 5 > area.length) return false; len = ((area[p + 1] << 24) >>> 0) + (area[p + 2] << 16) + (area[p + 3] << 8) + area[p + 4]; hdr = 5; }
        if (len < 1 || p + hdr + len > area.length) return false;
        const type = area[p + hdr] & 0x7f;
        const critical = !!(area[p + hdr] & 0x80);
        const data = area.subarray(p + hdr + 1, p + hdr + len);
        const u32 = () => data.length === 4 ? ((data[0] << 24) >>> 0) + (data[1] << 16) + (data[2] << 8) + data[3] : NaN;
        if (type === 2) {
            if (created !== undefined) return false;
            created = u32();
        } else if (type === 3) {
            expiresIn = u32();
        } else if (critical) {
            return false;
        }
        if (Number.isNaN(created) || Number.isNaN(expiresIn)) return false;
        p += hdr + len;
    }
    if (created === undefined) return false;
    // Freshness comes from the ticket (signed into the statement), not from the
    // signer's clock, so a computer with a wrong clock still works.
    if (expiresIn && created + expiresIn <= nowSec) return false;
    return true;
}

/**
 * Verifies an armored detached signature over `data` by the primary key in
 * `primaryBody`. Returns false for anything that isn't exactly that.
 */
export async function verifyPrimarySignature(primaryBody: Uint8Array, armoredSig: string, data: Uint8Array, now: number): Promise<boolean> {
    try {
        const key = primaryKeyFromBody(primaryBody);
        if (!key) return false;
        const t = armoredSig.replace(/\r\n/g, "\n").trim();
        if (!t.startsWith(PGP_SIG_BEGIN + "\n") || !t.endsWith("\n" + PGP_SIG_END) || t.indexOf(PGP_SIG_BEGIN, 1) !== -1) return false;
        const bin = dearmorPgp(t);
        const pkt = readPacket(bin, 0);
        if (pkt.tag !== 2 || pkt.end !== bin.length) return false;
        const s = pkt.body;

        // v4 signature: version, type, public-key algorithm, hash, hashed area, unhashed area, left 16 bits, values.
        if (s.length < 10 || s[0] !== 4 || s[1] !== 0x00) return false;
        const sigAlg = s[2], hash = HASHES[s[3]];
        if (!hash) return false;
        const hashedLen = (s[4] << 8) | s[5];
        if (6 + hashedLen + 2 > s.length) return false;
        if (!checkSubpackets(s.subarray(6, 6 + hashedLen), Math.floor(now / 1000))) return false;
        const unhashedLen = (s[6 + hashedLen] << 8) | s[7 + hashedLen];
        let p = 8 + hashedLen + unhashedLen;
        if (p + 2 > s.length) return false;
        const left16 = s.subarray(p, p + 2);
        p += 2;

        const trailerLen = 6 + hashedLen;
        const toHash = concat(data, s.subarray(0, trailerLen), Uint8Array.from([0x04, 0xff, trailerLen >>> 24, (trailerLen >> 16) & 0xff, (trailerLen >> 8) & 0xff, trailerLen & 0xff]));
        const digest = new Uint8Array(await crypto.subtle.digest(hash, toHash as BufferSource));
        if (digest[0] !== left16[0] || digest[1] !== left16[1]) return false;

        if (key.kind === "rsa") {
            if (sigAlg !== 1 && sigAlg !== 3) return false;
            const sv = mpi(s, p);
            if (sv.next !== s.length) return false;
            const k = await crypto.subtle.importKey("jwk", { kty: "RSA", n: b64url(key.n), e: b64url(key.e), ext: true }, { name: "RSASSA-PKCS1-v1_5", hash }, false, ["verify"]);
            return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", k, leftPad(sv.value, key.n.length) as BufferSource, toHash as BufferSource);
        }
        if (key.kind === "ecdsa") {
            if (sigAlg !== 19) return false;
            const r = mpi(s, p), sv = mpi(s, r.next);
            if (sv.next !== s.length) return false;
            const k = await crypto.subtle.importKey("raw", key.point as BufferSource, { name: "ECDSA", namedCurve: key.curve.name }, false, ["verify"]);
            const raw = concat(leftPad(r.value, key.curve.size), leftPad(sv.value, key.curve.size));
            return await crypto.subtle.verify({ name: "ECDSA", hash }, k, raw as BufferSource, toHash as BufferSource);
        }
        // Ed25519 signs the digest itself (RFC 9580 §5.2.3.3 and §5.2.3.4).
        let raw: Uint8Array;
        if (sigAlg === 22 && key.legacy) {
            const r = mpi(s, p), sv = mpi(s, r.next);
            if (sv.next !== s.length) return false;
            raw = concat(leftPad(r.value, 32), leftPad(sv.value, 32));
        } else if (sigAlg === 27 && !key.legacy) {
            if (s.length - p !== 64) return false;
            raw = s.subarray(p);
        } else {
            return false;
        }
        const k = await crypto.subtle.importKey("raw", key.point as BufferSource, { name: "Ed25519" }, false, ["verify"]);
        return await crypto.subtle.verify({ name: "Ed25519" }, k, raw as BufferSource, digest as BufferSource);
    } catch {
        return false;
    }
}
