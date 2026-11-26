/**
 * Known-answer and cross-implementation tests for the cryptography Cipher
 * bundles (age-encryption and the @noble / @scure code it runs on).
 *
 * Reading the code can't prove an algorithm wasn't subtly weakened, so:
 *  1. official test vectors from the standards;
 *  2. random inputs compared against Node's OpenSSL, an independent implementation;
 *  3. an independent age implementation built here from the age spec on
 *     OpenSSL only, checked against age-encryption in both directions.
 */

import { createCipheriv, createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman, hkdfSync, randomBytes, scryptSync } from "node:crypto";

import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { scrypt } from "@noble/hashes/scrypt.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { armor, Decrypter, Encrypter, generateX25519Identity, identityToRecipient } from "age-encryption";
import { describe, expect, it } from "vitest";

const hex = (s: string) => Uint8Array.from(Buffer.from(s.replace(/\s+/g, ""), "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const utf8 = (s: string) => new TextEncoder().encode(s);

describe("official test vectors", () => {
    it("SHA-256 (FIPS 180-2)", () => {
        expect(toHex(sha256(utf8("abc")))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        expect(toHex(sha256(new Uint8Array()))).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    });

    it("HMAC-SHA-256 (RFC 4231 case 2)", () => {
        expect(toHex(hmac(sha256, utf8("Jefe"), utf8("what do ya want for nothing?"))))
            .toBe("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    });

    it("HKDF-SHA-256 (RFC 5869 case 1)", () => {
        const okm = hkdf(sha256, hex("0b".repeat(22)), hex("000102030405060708090a0b0c"), hex("f0f1f2f3f4f5f6f7f8f9"), 42);
        expect(toHex(okm)).toBe("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    });

    it("X25519 (RFC 7748 §5.2 and §6.1)", () => {
        expect(toHex(x25519.scalarMult(
            hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        ))).toBe("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        const alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        const bob = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        expect(toHex(x25519.getPublicKey(alice))).toBe("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        expect(toHex(x25519.getPublicKey(bob))).toBe("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        expect(toHex(x25519.getSharedSecret(alice, x25519.getPublicKey(bob)))).toBe("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    });

    it("ChaCha20-Poly1305 (RFC 8439 §2.8.2)", () => {
        const key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        const nonce = hex("070000004041424344454647");
        const aad = hex("50515253c0c1c2c3c4c5c6c7");
        const pt = utf8("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
        const sealed = chacha20poly1305(key, nonce, aad).encrypt(pt);
        expect(toHex(sealed.slice(-16))).toBe("1ae10b594f09e26a7e902ecbd0600691");
        expect(toHex(sealed.slice(0, 16))).toBe("d31a8d34648e60db7b86afbc53ef7ec2");
        expect(chacha20poly1305(key, nonce, aad).decrypt(sealed)).toEqual(pt);
    });

    it("scrypt (RFC 7914 §12)", () => {
        expect(toHex(scrypt(utf8("password"), utf8("NaCl"), { N: 1024, r: 8, p: 16, dkLen: 64 })))
            .toBe("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");
    });
});

/* ---------- independent primitives on Node's OpenSSL ---------- */

const X25519_PKCS8 = hex("302e020100300506032b656e04220420");
const X25519_SPKI = hex("302a300506032b656e032100");

function osslX25519(scalar: Uint8Array, point: Uint8Array): Uint8Array {
    const privateKey = createPrivateKey({ key: Buffer.concat([X25519_PKCS8, scalar]), format: "der", type: "pkcs8" });
    const publicKey = createPublicKey({ key: Buffer.concat([X25519_SPKI, point]), format: "der", type: "spki" });
    return new Uint8Array(diffieHellman({ privateKey, publicKey }));
}

function osslPublic(scalar: Uint8Array): Uint8Array {
    const der = createPublicKey(createPrivateKey({ key: Buffer.concat([X25519_PKCS8, scalar]), format: "der", type: "pkcs8" })).export({ format: "der", type: "spki" });
    return new Uint8Array(der.subarray(der.length - 32));
}

function osslSeal(key: Uint8Array, nonce: Uint8Array, data: Uint8Array) {
    const c = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    return new Uint8Array(Buffer.concat([c.update(data), c.final(), c.getAuthTag()]));
}

function osslOpen(key: Uint8Array, nonce: Uint8Array, sealed: Uint8Array) {
    const d = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    d.setAuthTag(sealed.subarray(sealed.length - 16));
    return new Uint8Array(Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]));
}

const osslHkdf = (ikm: Uint8Array, salt: Uint8Array, info: string, len = 32) => new Uint8Array(hkdfSync("sha256", ikm, salt, utf8(info), len));
const osslHmac = (key: Uint8Array, data: Uint8Array) => new Uint8Array(createHmac("sha256", key).update(data).digest());

describe("cross-checked against OpenSSL on random inputs", () => {
    it("SHA-256, HMAC, HKDF, scrypt", () => {
        for (let i = 0; i < 200; i++) {
            const data = randomBytes(i * 7);
            const key = randomBytes(1 + (i % 70));
            expect(toHex(sha256(data))).toBe(createHash("sha256").update(data).digest("hex"));
            expect(toHex(hmac(sha256, key, data))).toBe(toHex(osslHmac(key, data)));
            const salt = randomBytes(i % 40);
            expect(toHex(hkdf(sha256, data, salt, utf8("info" + i), 32 + (i % 50)))).toBe(toHex(osslHkdf(data, salt, "info" + i, 32 + (i % 50))));
        }
        for (const logN of [4, 8, 10]) {
            const pw = randomBytes(20);
            const salt = randomBytes(16);
            expect(toHex(scrypt(pw, salt, { N: 2 ** logN, r: 8, p: 1, dkLen: 32 }))).toBe(scryptSync(pw, salt, 32, { N: 2 ** logN, r: 8, p: 1 }).toString("hex"));
        }
    });

    it("X25519", () => {
        for (let i = 0; i < 100; i++) {
            const a = randomBytes(32);
            const b = randomBytes(32);
            expect(toHex(x25519.getPublicKey(a))).toBe(toHex(osslPublic(a)));
            expect(toHex(x25519.getSharedSecret(a, x25519.getPublicKey(b)))).toBe(toHex(osslX25519(a, osslPublic(b))));
        }
    });

    it("ChaCha20-Poly1305", () => {
        for (let i = 0; i < 200; i++) {
            const key = randomBytes(32);
            const nonce = randomBytes(12);
            const data = randomBytes(i * 13);
            const sealed = chacha20poly1305(key, nonce).encrypt(data);
            expect(toHex(sealed)).toBe(toHex(osslSeal(key, nonce, data)));
            expect(toHex(osslOpen(key, nonce, sealed))).toBe(toHex(data));
        }
    });

    it("random bytes come from the OS (crypto.getRandomValues), not Math.random", async () => {
        const original = Math.random;
        Math.random = () => { throw new Error("Math.random must not be used for keys"); };
        try {
            const id = await generateX25519Identity();
            expect(id).toMatch(/^AGE-SECRET-KEY-1/);
        } finally {
            Math.random = original;
        }
    });
});

/* ---------- independent age v1 (X25519 recipients) on OpenSSL ---------- */

const BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

function bech32Polymod(values: number[]) {
    const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
        const top = chk >>> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= G[i];
    }
    return chk;
}

function bech32Decode(s: string): { hrp: string; data: Uint8Array; } {
    const lower = s.toLowerCase();
    const pos = lower.lastIndexOf("1");
    const hrp = lower.slice(0, pos);
    const values = [...lower.slice(pos + 1)].map(c => BECH32.indexOf(c));
    if (values.includes(-1)) throw new Error("bad char");
    const hrpExp = [...[...hrp].map(c => c.charCodeAt(0) >> 5), 0, ...[...hrp].map(c => c.charCodeAt(0) & 31)];
    if (bech32Polymod([...hrpExp, ...values]) !== 1) throw new Error("bad checksum");
    let acc = 0, bits = 0;
    const out: number[] = [];
    for (const v of values.slice(0, -6)) {
        acc = (acc << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push((acc >> bits) & 0xff);
        }
    }
    return { hrp, data: Uint8Array.from(out) };
}

const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64").replace(/=+$/, "");
const unb64 = (s: string) => Uint8Array.from(Buffer.from(s, "base64"));
const cat = (...p: Uint8Array[]) => Uint8Array.from(Buffer.concat(p));

/** age payload: 64 KiB chunks, nonce = 11-byte big-endian counter || last-chunk flag. */
function streamNonce(i: number, last: boolean) {
    const n = new Uint8Array(12);
    new DataView(n.buffer).setUint32(7, i);
    n[11] = last ? 1 : 0;
    return n;
}

function independentAgeEncrypt(recipient: string, plaintext: Uint8Array): Uint8Array {
    const { hrp, data: pub } = bech32Decode(recipient);
    expect(hrp).toBe("age");
    const fileKey = randomBytes(16);
    const eph = randomBytes(32);
    const ephShare = osslPublic(eph);
    const shared = osslX25519(eph, pub);
    const wrapKey = osslHkdf(shared, cat(ephShare, pub), "age-encryption.org/v1/X25519");
    const body = osslSeal(wrapKey, new Uint8Array(12), fileKey);
    let header = `age-encryption.org/v1\n-> X25519 ${b64(ephShare)}\n${b64(body)}\n---`;
    const mac = osslHmac(osslHkdf(fileKey, new Uint8Array(), "header"), utf8(header));
    header += ` ${b64(mac)}\n`;
    const nonce = randomBytes(16);
    const payloadKey = osslHkdf(fileKey, nonce, "payload");
    const chunks: Uint8Array[] = [];
    const CH = 65536;
    const count = Math.max(1, Math.ceil(plaintext.length / CH));
    for (let i = 0; i < count; i++) chunks.push(osslSeal(payloadKey, streamNonce(i, i === count - 1), plaintext.subarray(i * CH, (i + 1) * CH)));
    return cat(utf8(header), nonce, ...chunks);
}

function independentAgeDecrypt(identity: string, file: Uint8Array): Uint8Array {
    const { hrp, data: scalar } = bech32Decode(identity);
    expect(hrp).toBe("age-secret-key-");
    const text = Buffer.from(file).toString("latin1");
    const end = text.indexOf("\n---");
    const macLineEnd = text.indexOf("\n", end + 1);
    const headerNoMac = text.slice(0, end + 4);
    const lines = headerNoMac.split("\n");
    expect(lines[0]).toBe("age-encryption.org/v1");
    const pub = osslPublic(scalar);
    let fileKey: Uint8Array | undefined;
    for (let i = 1; i < lines.length - 1; i++) {
        const args = lines[i].split(" ");
        if (args[0] !== "->" || args[1] !== "X25519") continue;
        const ephShare = unb64(args[2]);
        const body = unb64(lines[i + 1]);
        const wrapKey = osslHkdf(osslX25519(scalar, ephShare), cat(ephShare, pub), "age-encryption.org/v1/X25519");
        try {
            fileKey = osslOpen(wrapKey, new Uint8Array(12), body);
            break;
        } catch { /* not ours */ }
    }
    if (!fileKey) throw new Error("not a recipient");
    const mac = unb64(text.slice(end + 5, macLineEnd));
    expect(toHex(mac)).toBe(toHex(osslHmac(osslHkdf(fileKey, new Uint8Array(), "header"), utf8(headerNoMac))));
    const rest = file.subarray(macLineEnd + 1);
    const nonce = rest.subarray(0, 16);
    const payloadKey = osslHkdf(fileKey, nonce, "payload");
    const sealed = rest.subarray(16);
    const out: Uint8Array[] = [];
    const CH = 65536 + 16;
    const count = Math.max(1, Math.ceil(sealed.length / CH));
    for (let i = 0; i < count; i++) out.push(osslOpen(payloadKey, streamNonce(i, i === count - 1), sealed.subarray(i * CH, (i + 1) * CH)));
    return cat(...out);
}

describe("age-encryption matches an independent age implementation", () => {
    it("bech32 decoder accepts the BIP-173 vectors", () => {
        expect(bech32Decode("A12UEL5L").hrp).toBe("a");
        expect(bech32Decode("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw").hrp).toBe("abcdef");
        expect(() => bech32Decode("a12uel5m")).toThrow();
    });

    it("identity → recipient is X25519 base-point multiplication", async () => {
        for (let i = 0; i < 20; i++) {
            const id = await generateX25519Identity();
            const rec = await identityToRecipient(id);
            expect(toHex(bech32Decode(rec).data)).toBe(toHex(osslPublic(bech32Decode(id).data)));
        }
    });

    it("files from age-encryption decrypt with the independent implementation", async () => {
        for (const size of [0, 1, 100, 65535, 65536, 65537, 200_000]) {
            const id = await generateX25519Identity();
            const other = await generateX25519Identity();
            const e = new Encrypter();
            e.addRecipient(await identityToRecipient(other));
            e.addRecipient(await identityToRecipient(id));
            const pt = randomBytes(size);
            const file = armor.decode(armor.encode(await e.encrypt(pt)));
            expect(toHex(independentAgeDecrypt(id, file))).toBe(toHex(pt));
        }
    });

    it("files from the independent implementation decrypt with age-encryption", async () => {
        for (const size of [0, 1, 65536, 65537, 150_000]) {
            const id = await generateX25519Identity();
            const pt = randomBytes(size);
            const file = independentAgeEncrypt(await identityToRecipient(id), pt);
            const d = new Decrypter();
            d.addIdentity(id);
            expect(toHex(await d.decrypt(file))).toBe(toHex(pt));
        }
    });
});
