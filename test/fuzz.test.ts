import { beforeAll, describe, expect, it } from "vitest";

import { handle, makeToken } from "../server/src/index";
import { primaryKeyBody, primaryKeyFromBody, readPacket, verifyPrimarySignature } from "../server/src/pgpVerify";
import { checkAgePublicKey, checkMessage, checkPgpPublicKey, Invalid } from "../server/src/validate";
import { ageEncrypt, generateAgeIdentity } from "../src/core/ageCipher";
import { bech32Decode } from "../src/core/bech32";
import { utf8Encode } from "../src/core/bytes";
import { formatKeyShare, formatLinkMessage, isPureCipherContent, parseAttachmentName, parseContent, reassemble, splitArmored } from "../src/core/envelope";
import { CipherError } from "../src/core/errors";
import { isProofStatementFor, parseTicket, proofStatement, readAgeChallenge } from "../src/core/keyProof";
import { decodePayload, encodePayload } from "../src/core/payload";
import { pgpEncrypt } from "../src/core/pgpCipher";
import { checkInnerShape, checkMessageShape, checkPublicKeyShape, checkSecretKeyShape, dearmorPgp, PacketError, packetAt, pgpAddressing, readSessionKeys } from "../src/core/pgpPackets";
import { isPublicHostname, linkLoadPolicy, normalizeServerUrl, parseLinkUrl, serverRequestUrl } from "../src/core/serverApi";
import { newGpgHome, pgpUser, rawGpg, type TestUser } from "./helpers";

/*
 * Fuzzing: thousands of random and mutated inputs against every parser that
 * sees data from chat or from a server. Each must either accept or refuse
 * with its own error type: no crash, no other exception, no hang.
 * Deterministic (seeded), so any failure reproduces.
 */

let seed = 0x5eed1234;
const rand = () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32);
const int = (n: number) => Math.floor(rand() * n);
const pick = <T>(a: readonly T[]) => a[int(a.length)];
const bytes = (n: number) => Uint8Array.from({ length: n }, () => int(256));
const CHARS = "\u0000\n\r\t -#`<>:/.=+_@!\"'\\{}[]()|·🔒🔑ageAGEpgpPGP0123456789abcdefABCDEF\u202e\u200b\ud800";
const str = (n: number) => Array.from({ length: n }, () => pick([...CHARS])).join("");

function mutateBytes(src: Uint8Array): Uint8Array {
    const b = Uint8Array.from(src);
    switch (int(5)) {
        case 0: for (let i = 0; i < 1 + int(4); i++) b[int(b.length)] = int(256); return b;
        case 1: return b.subarray(0, int(b.length));
        case 2: { const i = int(b.length); return Uint8Array.from([...b.subarray(0, i), ...bytes(1 + int(8)), ...b.subarray(i)]); }
        case 3: { const i = int(b.length); return Uint8Array.from([...b.subarray(0, i), ...b.subarray(i + 1 + int(6))]); }
        default: { const i = int(b.length); b[i] = [0x00, 0xff, 0x80, 0x7f, 0xc0, 0xe0][int(6)]; return b; }
    }
}

function mutateString(src: string): string {
    const s = [...src];
    switch (int(5)) {
        case 0: for (let i = 0; i < 1 + int(4); i++) s[int(s.length)] = pick([...CHARS]); return s.join("");
        case 1: return s.slice(0, int(s.length)).join("");
        case 2: { const i = int(s.length); return [...s.slice(0, i), str(1 + int(10)), ...s.slice(i)].join(""); }
        case 3: { const i = int(s.length); return [...s.slice(0, i), ...s.slice(i + 1 + int(20))].join(""); }
        default: return s.join("").replace(/\n/g, pick(["\r\n", "\n\n", " \n", "\n"]));
    }
}

/** Runs fn; fails only on an exception that isn't one of the allowed types. */
function allowOnly(fn: () => unknown, ...allowed: (new (...a: never[]) => Error)[]) {
    try {
        fn();
    } catch (e) {
        if (!allowed.some(t => e instanceof t)) throw new Error(`unexpected ${(e as Error)?.constructor?.name}: ${(e as Error)?.message}`, { cause: e });
    }
}
async function allowOnlyAsync(fn: () => Promise<unknown>, ...allowed: (new (...a: never[]) => Error)[]) {
    try {
        await fn();
    } catch (e) {
        if (!allowed.some(t => e instanceof t)) throw new Error(`unexpected ${(e as Error)?.constructor?.name}: ${(e as Error)?.message}`, { cause: e });
    }
}

let alice: TestUser;
let pgpMsgBin: Uint8Array, pgpKeyBin: Uint8Array, secretBin: Uint8Array, sigArmored: string, statement: string;
let samples: string[];
beforeAll(async () => {
    alice = await pgpUser("fuzz");
    const msg = await pgpEncrypt(alice.engine!, [alice.publicKey], await encodePayload("fuzz", false));
    pgpMsgBin = dearmorPgp(msg);
    pgpKeyBin = dearmorPgp(alice.publicKey);
    secretBin = dearmorPgp(rawGpg(alice.home!, ["--armor", "--export-secret-keys", alice.fingerprint!]).stdout.toString());
    const fpr = alice.fingerprint!;
    const ticket = `p1.80351110224678912.pgp.${fpr}.${Date.now() + 60_000}.${"B".repeat(22)}.${"C".repeat(43)}`;
    statement = proofStatement("https://cipher.example", "80351110224678912", fpr, ticket);
    sigArmored = await alice.engine!.signProof(fpr, statement);
    const age = await generateAgeIdentity();
    const ageMsg = await ageEncrypt([age.recipient], await encodePayload("fuzz", false));
    samples = [
        ...splitArmored(msg, { type: "pgp", ref: "abcd1234" }),
        ...splitArmored(ageMsg, { type: "age", ref: "wxyz9876", set: "set12345" }),
        formatLinkMessage(Date.now() + 86_400_000, [{ url: "https://cipher.example.com/m/7AbCdEfGhIjKlMnOpQrStUv", type: "age", hash: "Q".repeat(43) }]),
        formatKeyShare("age", age.recipient, "123 456"),
        formatKeyShare("pgp", alice.publicKey, "123 456"),
        msg, ageMsg
    ];
}, 60_000);

describe("fuzz: chat message parsing", () => {
    it("never throws on random or mutated message text", () => {
        const t = performance.now();
        for (let i = 0; i < 6000; i++) {
            const input = i % 3 === 0 ? str(int(400)) : mutateString(pick(samples));
            const p = parseContent(input);
            isPureCipherContent(input, p);
            if (p && p.kind === "link") for (const l of p.links) expect(parseLinkUrl(l.url)).not.toBeNull();
        }
        expect(performance.now() - t).toBeLessThan(20_000);
    });

    it("never throws on random attachment names or reassembly input", () => {
        for (let i = 0; i < 3000; i++) parseAttachmentName(i % 2 ? str(int(40)) : mutateString("cipher-abcd1234.age"));
        for (let i = 0; i < 500; i++) {
            const parts = Array.from({ length: int(6) }, () => ({ part: int(12), total: int(12), body: str(int(50)) }));
            allowOnly(() => reassemble(parts as never), CipherError);
        }
    });

    it("decodes only real payloads; anything else is a CipherError", async () => {
        const good = await encodePayload("hello", true);
        for (let i = 0; i < 1500; i++)
            await allowOnlyAsync(() => decodePayload(i % 2 ? bytes(int(64)) : mutateBytes(good)), CipherError);
    });
});

describe("fuzz: OpenPGP packet checks (run before GnuPG)", () => {
    it("only ever throw PacketError, on random and mutated packets", () => {
        const t = performance.now();
        const srcs = () => [pgpMsgBin, pgpKeyBin, secretBin, dearmorPgp(sigArmored)];
        for (let i = 0; i < 5000; i++) {
            const data = i % 4 === 0 ? bytes(int(300)) : mutateBytes(pick(srcs()));
            allowOnly(() => readSessionKeys(data), PacketError);
            allowOnly(() => checkMessageShape(data), PacketError);
            allowOnly(() => checkPublicKeyShape(data), PacketError);
            allowOnly(() => checkSecretKeyShape(data), PacketError);
            allowOnly(() => checkInnerShape(data), PacketError);
            allowOnly(() => packetAt(data, 0), PacketError);
        }
        expect(performance.now() - t).toBeLessThan(20_000);
    });

    it("dearmor and addressing refuse junk without other errors", () => {
        for (let i = 0; i < 3000; i++) {
            const s = i % 2 ? str(int(300)) : mutateString(pick(samples.filter(x => x.includes("BEGIN PGP"))));
            allowOnly(() => dearmorPgp(s), PacketError);
            allowOnly(() => pgpAddressing(s, alice.info.keyIds), PacketError);
        }
    });

    it("rejects pathological lengths quickly (no huge allocations or hangs)", () => {
        const t = performance.now();
        // A partial-length chain claiming gigabytes, and a 4-byte length near 2^32.
        allowOnly(() => checkMessageShape(Uint8Array.from([0xD2, 0xEF, ...bytes(10)])), PacketError);
        allowOnly(() => checkMessageShape(Uint8Array.from([0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 1, 2])), PacketError);
        allowOnly(() => checkPublicKeyShape(Uint8Array.from([0x99, 0xFF, 0xFF, 1])), PacketError);
        allowOnly(() => checkInnerShape(new Uint8Array(1 << 20).fill(0xE0)), PacketError);
        expect(performance.now() - t).toBeLessThan(2000);
    });
});

describe("fuzz: server-side checks", () => {
    it("message and key validation only throw Invalid", async () => {
        const armorMsg = (b: Uint8Array) => `-----BEGIN PGP MESSAGE-----\n\n${btoa(String.fromCharCode(...b))}\n-----END PGP MESSAGE-----`;
        const armorKey = (b: Uint8Array) => `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n${btoa(String.fromCharCode(...b))}\n-----END PGP PUBLIC KEY BLOCK-----`;
        for (let i = 0; i < 1500; i++) {
            allowOnly(() => checkMessage(i % 3 ? armorMsg(mutateBytes(pgpMsgBin)) : mutateString(pick(samples))), Invalid);
            await allowOnlyAsync(() => checkPgpPublicKey(armorKey(mutateBytes(pgpKeyBin))), Invalid);
            await allowOnlyAsync(() => checkAgePublicKey(mutateString("age1" + "q".repeat(58))), Invalid);
        }
    });

    it("signature verification returns a boolean for any input, and true only for the real one", async () => {
        const body = primaryKeyBody(alice.publicKey)!;
        const data = utf8Encode(statement);
        expect(await verifyPrimarySignature(body, sigArmored, data, Date.now())).toBe(true);
        const sigBin = dearmorPgp(sigArmored);
        const armorSig = (b: Uint8Array) => `-----BEGIN PGP SIGNATURE-----\n\n${btoa(String.fromCharCode(...b))}\n-----END PGP SIGNATURE-----`;
        // The unhashed subpacket area isn't covered by the signature (OpenPGP by design);
        // a change anywhere else must make it fail.
        const pkt = readPacket(sigBin, 0);
        const hdr = pkt.end - pkt.body.length;
        const hashedLen = (pkt.body[4] << 8) | pkt.body[5];
        const unhashedLen = (pkt.body[6 + hashedLen] << 8) | pkt.body[7 + hashedLen];
        const freeFrom = hdr + 8 + hashedLen, freeTo = freeFrom + unhashedLen;
        for (let i = 0; i < 1500; i++) {
            const m = mutateBytes(sigBin);
            const sameKey = i % 5 !== 0;
            const r = await verifyPrimarySignature(sameKey ? body : mutateBytes(body), armorSig(m), data, Date.now());
            expect(typeof r).toBe("boolean");
            if (!r || !sameKey) continue;
            if (m.length !== sigBin.length) throw new Error("accepted a signature of a different length");
            const changed = [...m.keys()].filter(j => m[j] !== sigBin[j]);
            for (const j of changed) if (j < freeFrom || j >= freeTo) throw new Error(`accepted a change at byte ${j}, outside the unhashed area ${freeFrom}-${freeTo}`);
        }
        for (let i = 0; i < 1000; i++) allowOnly(() => readPacket(mutateBytes(pgpKeyBin), 0), Error);
        for (let i = 0; i < 1000; i++) expect(() => primaryKeyFromBody(mutateBytes(body))).not.toThrow();
    });

    it("tickets, statements and challenges parse only what they should", () => {
        const fpr = "A".repeat(40);
        const ticket = `p1.80351110224678912.pgp.${fpr}.${Date.now()}.${"B".repeat(22)}.${"C".repeat(43)}`;
        for (let i = 0; i < 5000; i++) {
            const t = mutateString(ticket);
            const p = parseTicket(t);
            if (p) expect(t).toMatch(/^p1\.\d+\.(age|pgp)\.[0-9A-F]+\.\d+\.[\w-]{22}\.[\w-]{43}$/);
            isProofStatementFor(mutateString(proofStatement("https://cipher.example", "80351110224678912", fpr, ticket)), fpr);
            expect(readAgeChallenge(mutateString(`Cipher key proof v1\nticket: ${ticket}\nnonce: ${"n".repeat(43)}\n`), ticket + "x")).toBeNull();
        }
    });

    it("URL and host checks never throw", () => {
        const bases = ["https://cipher.example.com", "http://localhost:8787", "https://192.168.1.1", "https://a.b.c/m/7" + "A".repeat(22)];
        for (let i = 0; i < 5000; i++) {
            const u = i % 2 ? str(int(60)) : mutateString(pick(bases));
            normalizeServerUrl(u);
            serverRequestUrl(u, pick(["GET", "PUT", "POST", "DELETE", str(4)]), mutateString("/v1/keys/80351110224678912"));
            parseLinkUrl(u);
            isPublicHostname(u);
            linkLoadPolicy(pick([null, "https://cipher.example.com"]), u, rand() < 0.5);
            allowOnly(() => bech32Decode(mutateString("age1" + "q".repeat(58))), Error);
        }
    });
});

describe("fuzz: the server's request handler", () => {
    it("never answers 500 to random JSON bodies on any route, signed in or not", async () => {
        const { DatabaseSync } = await import("node:sqlite");
        const { readFileSync } = await import("node:fs");
        const db = new DatabaseSync(":memory:");
        db.exec(readFileSync("server/schema.sql", "utf8"));
        const objects = new Map<string, { value: string; customMetadata?: Record<string, string>; }>();
        const env = {
            SECRET: "k".repeat(40), DISCORD_CLIENT_ID: "1", DISCORD_CLIENT_SECRET: "x", PUBLIC_URL: "https://cipher.example.com",
            USER_DAILY_UPLOADS: "100000",
            DB: { prepare: (sql: string) => { const mk = (v: unknown[]): any => ({ bind: (...x: unknown[]) => mk(x), first: async () => db.prepare(sql).get(...v as never[]) ?? null, run: async () => db.prepare(sql).run(...v as never[]), all: async () => ({ results: db.prepare(sql).all(...v as never[]) }) }); return mk([]); } }
        };
        void objects;
        const deps = { now: Date.now, fetch: async () => new Response("{}", { status: 400 }) };
        const tokens = await Promise.all(["80351110224678912", "80351110224678913"].map(async u => (await makeToken(env as never, u, Date.now())).token));
        const value = (depth: number): unknown => {
            const k = int(depth > 3 ? 5 : 9);
            if (k === 0) return null;
            if (k === 1) return rand() < 0.5;
            if (k === 2) return pick([0, -1, 1e308, 1.5, 7, 3, NaN]);
            if (k === 3) return pick(["age", "pgp", "", str(int(30)), "age1" + "q".repeat(58), "x".repeat(int(5000))]);
            if (k === 4) return pick(samples);
            if (k <= 6) return Array.from({ length: int(4) }, () => value(depth + 1));
            const o: Record<string, unknown> = {};
            for (const key of ["type", "key", "proof", "oldProof", "reset", "ciphertext", "ttlDays", "ticket", "response", "__proto__", str(5)]) if (rand() < 0.5) o[key] = value(depth + 1);
            return o;
        };
        const routes: [string, string][] = [["PUT", "/v1/keys"], ["POST", "/v1/keys/challenge"], ["POST", "/v1/keys/remove"], ["POST", "/v1/messages"], ["GET", "/v1/keys/80351110224678912"], ["DELETE", "/m/7" + "A".repeat(22)], ["GET", "/v1/auth/callback?code=AAAAAAAAAAAA"]];
        const statuses = new Map<number, number>();
        for (let i = 0; i < 1200; i++) {
            const [method, path] = pick(routes);
            const headers: Record<string, string> = { "Content-Type": pick(["application/json", "application/json; charset=utf-8", "text/plain"]) };
            if (rand() < 0.8) headers.Authorization = `Bearer ${pick(tokens)}`;
            if (method === "DELETE") headers["X-Delete-Token"] = rand() < 0.5 ? "A".repeat(43) : str(10).replace(/[^ -~]/g, "x");
            const body = method === "GET" || method === "DELETE" ? undefined : rand() < 0.1 ? str(int(200)) : JSON.stringify(value(0));
            const r = await handle(new Request("https://cipher.example.com" + path, { method, headers, body }), env as never, deps);
            statuses.set(r.status, (statuses.get(r.status) ?? 0) + 1);
            if (r.status >= 500) throw new Error(`${method} ${path} -> ${r.status} ${await r.text()} body=${body?.slice(0, 300)}`);
        }
        // Most random bodies are refused (4xx); none may crash the handler.
        expect([...statuses.keys()].every(s => s < 500)).toBe(true);
    }, 120_000);
});

void newGpgHome;
