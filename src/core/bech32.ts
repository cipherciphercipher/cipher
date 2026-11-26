/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Bech32 (BIP 173, without its 90-character limit, as age uses it). Only for
 * re-encoding post-quantum age public keys, which Cipher shares in a shorter
 * base64 form so they fit in one Discord message.
 */

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values: number[]): number {
    let chk = 1;
    for (const v of values) {
        const top = chk >>> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
    }
    return chk >>> 0;
}

function hrpExpand(hrp: string): number[] {
    const out: number[] = [];
    for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
    out.push(0);
    for (const c of hrp) out.push(c.charCodeAt(0) & 31);
    return out;
}

function convertBits(data: ArrayLike<number>, from: number, to: number, pad: boolean): number[] {
    let acc = 0, bits = 0;
    const out: number[] = [];
    const max = (1 << to) - 1;
    for (let i = 0; i < data.length; i++) {
        acc = (acc << from) | data[i];
        bits += from;
        while (bits >= to) {
            bits -= to;
            out.push((acc >> bits) & max);
        }
        acc &= (1 << bits) - 1;
    }
    if (pad) {
        if (bits > 0) out.push((acc << (to - bits)) & max);
    } else if (bits >= from || ((acc << (to - bits)) & max)) {
        throw new Error("bech32: bad padding");
    }
    return out;
}

export function bech32Encode(hrp: string, bytes: Uint8Array): string {
    const data = convertBits(bytes, 8, 5, true);
    const values = [...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
    const mod = polymod(values) ^ 1;
    const checksum = Array.from({ length: 6 }, (_, i) => (mod >>> (5 * (5 - i))) & 31);
    return hrp + "1" + [...data, ...checksum].map(d => CHARSET[d]).join("");
}

export function bech32Decode(s: string): { hrp: string; bytes: Uint8Array; } {
    if (s !== s.toLowerCase() && s !== s.toUpperCase()) throw new Error("bech32: mixed case");
    const lower = s.toLowerCase();
    const sep = lower.lastIndexOf("1");
    if (sep < 1 || sep + 7 > lower.length) throw new Error("bech32: bad separator");
    const hrp = lower.slice(0, sep);
    const data: number[] = [];
    for (const c of lower.slice(sep + 1)) {
        const v = CHARSET.indexOf(c);
        if (v === -1) throw new Error("bech32: bad character");
        data.push(v);
    }
    if (polymod([...hrpExpand(hrp), ...data]) !== 1) throw new Error("bech32: bad checksum");
    return { hrp, bytes: Uint8Array.from(convertBits(data.slice(0, -6), 5, 8, false)) };
}
