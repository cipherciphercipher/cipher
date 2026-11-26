import { readFileSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import { accountCreatedAt, cleanup, type D1Database, type D1Statement, type Deps, type Env, handle, makeToken, type R2Bucket } from "../server/src/index";
import { primaryKeyFromBody } from "../server/src/pgpVerify";
import { checkAgePublicKey, checkMessage, checkPgpPublicKey } from "../server/src/validate";
import { ageDecrypt, ageEncrypt, agePassphraseEncrypt, generateAgeIdentity } from "../src/core/ageCipher";
import { utf8Decode } from "../src/core/bytes";
import type { GpgEngine } from "../src/core/gpg";
import { proofStatement, readAgeChallenge } from "../src/core/keyProof";
import { encodePayload } from "../src/core/payload";
import { pgpEncrypt } from "../src/core/pgpCipher";
import { newGpgHome, pgpUser, rawGpg, type TestUser } from "./helpers";

/* ---------- fakes for the Workers runtime ---------- */

/** D1 on top of Node's real SQLite, so the SQL itself is tested. */
class SqliteD1 implements D1Database {
    readonly db = new DatabaseSync(":memory:");
    constructor() {
        this.db.exec(readFileSync(join(__dirname, "..", "server", "schema.sql"), "utf8"));
    }
    prepare(sql: string): D1Statement {
        const db = this.db;
        // D1 uses ?1, ?2; node:sqlite takes them too.
        const make = (values: unknown[]): D1Statement => ({
            bind: (...v: unknown[]) => make(v),
            first: async <T>() => (db.prepare(sql).get(...values as never[]) ?? null) as T | null,
            run: async () => db.prepare(sql).run(...values as never[]),
            all: async <T>() => ({ results: db.prepare(sql).all(...values as never[]) as T[] })
        });
        return make([]);
    }
}

class MemoryR2 implements R2Bucket {
    readonly objects = new Map<string, { value: string; customMetadata?: Record<string, string>; }>();
    async get(key: string) {
        const o = this.objects.get(key);
        return o ? { customMetadata: o.customMetadata, text: async () => o.value } : null;
    }
    async head(key: string) {
        const o = this.objects.get(key);
        return o ? { customMetadata: o.customMetadata } : null;
    }
    async put(key: string, value: string, options?: { customMetadata?: Record<string, string>; }) {
        this.objects.set(key, { value, customMetadata: options?.customMetadata });
    }
    async delete(key: string) {
        this.objects.delete(key);
    }
}

const OLD_USER = "80351110224678912";   // created 2015
const BOT_USER = "80351110224678913";
let clock = Date.UTC(2026, 10, 25, 12);
const NEW_USER = String((BigInt(clock - 1420070400000 - 3600_000) << 22n) + 1n); // created an hour ago

/** Discord tokens the server asked Discord to revoke. */
const revoked: string[] = [];

function discordFake(): Deps["fetch"] {
    return async (url, init) => {
        // Like the Workers runtime, which only knows "follow" and "manual".
        if (init?.redirect !== "manual") throw new TypeError("Invalid redirect value");
        if (url.endsWith("/oauth2/token/revoke")) {
            revoked.push(new URLSearchParams(String(init?.body)).get("token") ?? "");
            return new Response(null, { status: 200 });
        }
        if (url.endsWith("/oauth2/token")) {
            const code = new URLSearchParams(String(init?.body)).get("code");
            if (code === "badcode0000") return new Response("{}", { status: 400 });
            if (code === "redirect000") return new Response(null, { status: 302, headers: { Location: "https://evil.example/" } });
            if (code === "htmlpage000") return new Response("<html>", { status: 200 });
            return Response.json({ access_token: `at-${code}`, refresh_token: `rt-${code}`, token_type: "Bearer" });
        }
        if (url.endsWith("/users/@me")) {
            const at = new Headers(init?.headers).get("Authorization") ?? "";
            if (at.includes("newacct")) return Response.json({ id: NEW_USER });
            if (at.includes("botacct")) return Response.json({ id: BOT_USER, bot: true });
            return Response.json({ id: OLD_USER });
        }
        throw new Error("unexpected fetch " + url);
    };
}

let env: Env & { DB: SqliteD1; MESSAGES: MemoryR2; };
const deps: Deps = { now: () => clock, fetch: discordFake() };
const BASE = "https://cipher.example";

function req(method: string, path: string, opts: { body?: unknown; token?: string; headers?: Record<string, string>; raw?: string; } = {}) {
    const headers: Record<string, string> = { ...opts.headers };
    if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
    let body: string | undefined;
    if (opts.raw !== undefined) body = opts.raw;
    else if (opts.body !== undefined) {
        body = JSON.stringify(opts.body);
        headers["Content-Type"] ??= "application/json";
    }
    return handle(new Request(BASE + path, { method, headers, body }), env, deps);
}

async function signIn(code = "goodcode1234"): Promise<string> {
    const r = await req("GET", `/v1/auth/callback?code=${code}`);
    expect(r.status).toBe(200);
    return (await r.json() as { token: string; }).token;
}

async function challenge(token: string, type: "age" | "pgp", key?: string) {
    const r = await req("POST", "/v1/keys/challenge", { token, body: key ? { type, key } : { type } });
    expect(r.status).toBe(200);
    return await r.json() as { ticket: string; challenge: string; statement: string; };
}

/** Answers an age challenge the way Cipher does. `stored`: for the key the server has now. */
async function proveAge(token: string, id: { identity: string; recipient: string; }, opts: { stored?: boolean; } = {}) {
    const c = await challenge(token, "age", opts.stored ? undefined : id.recipient);
    return { ticket: c.ticket, response: readAgeChallenge(utf8Decode(await ageDecrypt(c.challenge, [id.identity])), c.ticket)! };
}

async function provePgpWith(token: string, engine: GpgEngine, fingerprint: string, key?: string) {
    const c = await challenge(token, "pgp", key);
    return { ticket: c.ticket, response: await engine.signProof(fingerprint, c.statement) };
}
const provePgp = (token: string, u: TestUser) => provePgpWith(token, u.engine!, u.fingerprint!, u.publicKey);
const pgpHome = (u: TestUser) => u.home!;

beforeEach(() => {
    clock = Date.UTC(2026, 10, 25, 12);
    env = {
        DB: new SqliteD1(), MESSAGES: new MemoryR2(), SECRET: "s".repeat(48),
        DISCORD_CLIENT_ID: "123", DISCORD_CLIENT_SECRET: "shh", PUBLIC_URL: BASE,
        MONTHLY_UPLOAD_LIMIT: "1000", USER_DAILY_UPLOADS: "5"
    };
});

let pgp: TestUser;
let ageMsg: string, pgpMsg: string;
beforeAll(async () => {
    pgp = await pgpUser("srv");
    const a = await generateAgeIdentity();
    ageMsg = await ageEncrypt([a.recipient], await encodePayload("hi", false));
    pgpMsg = await pgpEncrypt(pgp.engine!, [pgp.publicKey], await encodePayload("hi", false));
}, 60_000);

/* ---------- tests ---------- */

describe("server: sign-in", () => {
    it("issues a token after Discord confirms the account", async () => {
        const token = await signIn();
        expect(token).toMatch(/^c1\.80351110224678912\.\d+\.[A-Za-z0-9_-]{43}$/);
    });

    it("refuses accounts younger than 2 days, bots, bad codes and refused codes", async () => {
        expect(accountCreatedAt(NEW_USER)).toBeGreaterThan(clock - 2 * 3600_000);
        expect((await req("GET", "/v1/auth/callback?code=newacct12345")).status).toBe(403);
        expect((await req("GET", "/v1/auth/callback?code=botacct12345")).status).toBe(401);
        expect((await req("GET", "/v1/auth/callback?code=badcode0000")).status).toBe(401);
        expect((await req("GET", "/v1/auth/callback?code=redirect000")).status).toBe(401);
        expect((await req("GET", "/v1/auth/callback?code=htmlpage000")).status).toBe(401);
        expect((await req("GET", "/v1/auth/callback?code=x")).status).toBe(400);
        expect((await req("GET", "/v1/auth/callback?code=" + encodeURIComponent("a&redirect_uri=evil"))).status).toBe(400);
    });

    it("rejects forged, edited, expired and foreign tokens", async () => {
        const token = await signIn();
        const put = (t: string) => req("PUT", "/v1/keys", { token: t, body: { type: "age", key: "x" } });
        expect((await put("")).status).toBe(401);
        expect((await put("c1.80351110224678912.9999999999.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).status).toBe(401);
        // Someone else's user ID with this token's signature.
        expect((await put(token.replace("80351110224678912", "80351110224678999"))).status).toBe(401);
        // Pushed-out expiry.
        const [, , , sig] = token.split(".");
        expect((await put(`c1.80351110224678912.9999999999.${sig}`)).status).toBe(401);
        // Signed with another server's secret.
        const other = await makeToken({ ...env, SECRET: "t".repeat(48) }, OLD_USER, clock);
        expect((await put(other.token)).status).toBe(401);
        // Expired.
        clock += 31 * 86_400_000;
        expect((await put(token)).status).toBe(401);
    });

    it("revokes the Discord tokens right after reading the user ID, also when refusing", async () => {
        revoked.length = 0;
        await signIn("goodcode1234");
        expect(revoked).toEqual(["rt-goodcode1234", "at-goodcode1234"]);
        revoked.length = 0;
        expect((await req("GET", "/v1/auth/callback?code=botacct12345")).status).toBe(401);
        expect(revoked).toEqual(["rt-botacct12345", "at-botacct12345"]);
    });

    it("caps sign-in attempts per IP, since each one calls Discord", async () => {
        const from = (ip: string) => req("GET", "/v1/auth/callback?code=badcode0000", { headers: { "CF-Connecting-IP": ip } });
        for (let i = 0; i < 50; i++) expect((await from("203.0.113.9")).status).toBe(401);
        expect((await from("203.0.113.9")).status).toBe(429);
        expect((await from("198.51.100.4")).status).toBe(401);
        // Counted under a keyed hash, never the IP itself.
        const rows = env.DB.db.prepare("SELECT who FROM usage").all() as { who: string; }[];
        expect(rows.every(r => !r.who.includes("203.0.113.9"))).toBe(true);
    });

    it("refuses to run with a short secret", async () => {
        env.SECRET = "short";
        expect((await req("GET", "/v1/auth/callback?code=goodcode1234")).status).toBe(500);
    });
});

describe("server: key directory", () => {
    it("stores and serves an age key and a PGP key, with the right fingerprints", async () => {
        const token = await signIn();
        const a = await generateAgeIdentity({ postQuantum: true });
        let r = await req("PUT", "/v1/keys", { token, body: { type: "age", key: a.recipient, proof: await proveAge(token, a) } });
        expect(r.status).toBe(200);
        r = await req("PUT", "/v1/keys", { token, body: { type: "pgp", key: pgp.publicKey, proof: await provePgp(token, pgp) } });
        expect(r.status).toBe(200);
        // Same fingerprint GnuPG computes.
        expect((await r.json() as { fingerprint: string; }).fingerprint).toBe(pgp.fingerprint);

        r = await req("GET", `/v1/keys/${OLD_USER}`);
        const got = await r.json() as { keys: { type: string; key: string; how: string; changedAt: number; pending?: unknown; }[]; };
        expect(got.keys.map(k => k.type)).toEqual(["age", "pgp"]);
        expect(got.keys[0]).toMatchObject({ key: a.recipient, how: "new", changedAt: clock });
        expect(got.keys[0].pending).toBeUndefined();

        expect((await req("POST", "/v1/keys/remove", { token, body: { type: "age", proof: await proveAge(token, a) } })).status).toBe(200);
        expect(((await (await req("GET", `/v1/keys/${OLD_USER}`)).json()) as { keys: unknown[]; }).keys).toHaveLength(1);
        expect((await req("GET", "/v1/keys/80351110224678000")).status).toBe(404);
    });

    it("refuses secret keys, junk, extra packets and anything smuggled in a key", async () => {
        const token = await signIn();
        const put = (type: string, key: string) => req("PUT", "/v1/keys", { token, body: { type, key } });
        const { home } = newGpgHome();
        rawGpg(home, ["--quick-gen-key", "x (t)", "future-default", "default", "never"]);
        const secret = rawGpg(home, ["--armor", "--export-secret-keys"]).stdout.toString();
        expect((await put("pgp", secret)).status).toBe(400);
        expect((await put("pgp", "hello")).status).toBe(400);
        expect((await put("age", "age1" + "q".repeat(58) + "x")).status).toBe(400);
        expect((await put("rsa", "x")).status).toBe(400);
        // A literal-data packet (a file) appended inside the key block.
        const data = rawGpg(home, ["--dearmor"], pgp.publicKey).stdout;
        // Control: the same re-armoring without anything added is accepted.
        const clean = rawGpg(home, ["--enarmor"], data).stdout.toString()
            .replace(/ARMORED FILE/g, "PUBLIC KEY BLOCK").replace(/^Comment:.*\n/m, "");
        expect(await checkPgpPublicKey(clean)).toBe(pgp.fingerprint);
        const withFile = Buffer.concat([data, Buffer.from([0xCB, 6, 0x62, 0, 0, 0, 0, 0])]);
        const armored = rawGpg(home, ["--enarmor"], withFile).stdout.toString()
            .replace(/ARMORED FILE/g, "PUBLIC KEY BLOCK").replace(/^Comment:.*\n/m, "");
        expect((await put("pgp", armored)).status).toBe(400);
        // Two keys in one block.
        const two = rawGpg(home, ["--enarmor"], Buffer.concat([data, data])).stdout.toString()
            .replace(/ARMORED FILE/g, "PUBLIC KEY BLOCK").replace(/^Comment:.*\n/m, "");
        expect((await put("pgp", two)).status).toBe(400);
        // Text around the block.
        expect((await put("pgp", "hi\n" + pgp.publicKey))).toMatchObject({ status: 400 });
        // Too big.
        expect((await put("pgp", pgp.publicKey + "\n".repeat(40000))).status).toBe(413);
    });

    it("limits key operations per day, challenges included", async () => {
        const token = await signIn();
        const a = await generateAgeIdentity();
        for (let i = 0; i < 20; i++) expect((await req("POST", "/v1/keys/challenge", { token, body: { type: "age", key: a.recipient } })).status).toBe(200);
        for (let i = 0; i < 20; i++) expect((await req("PUT", "/v1/keys", { token, body: { type: "age", key: a.recipient } })).status).toBe(403);
        expect((await req("POST", "/v1/keys/challenge", { token, body: { type: "age", key: a.recipient } })).status).toBe(429);
    });
});

describe("server: proof that a key is yours", () => {
    it("refuses a key without proof, or with proof that doesn't fit", async () => {
        const token = await signIn();
        const a = await generateAgeIdentity();
        const b = await generateAgeIdentity();
        const put = (proof: unknown) => req("PUT", "/v1/keys", { token, body: { type: "age", key: a.recipient, proof } });
        expect((await put(undefined)).status).toBe(403);
        expect((await put("x")).status).toBe(403);
        expect((await put({ ticket: "p1.x", response: "y" })).status).toBe(403);
        // Proof for a different key.
        expect((await put(await proveAge(token, b))).status).toBe(403);
        // The right ticket with a guessed answer.
        const good = await proveAge(token, a);
        expect((await put({ ...good, response: "A".repeat(43) })).status).toBe(403);
        // An edited ticket (another fingerprint, same HMAC).
        const bFpr = await checkAgePublicKey(b.recipient);
        const aFpr = await checkAgePublicKey(a.recipient);
        expect((await req("PUT", "/v1/keys", { token, body: { type: "age", key: b.recipient, proof: { ...good, ticket: good.ticket.replace(aFpr, bFpr) } } })).status).toBe(403);
        // Another account can't use it.
        const other = (await makeToken(env, "80351110224678999", clock)).token;
        expect((await req("PUT", "/v1/keys", { token: other, body: { type: "age", key: a.recipient, proof: good } })).status).toBe(403);
        // Another server's ticket.
        const foreign = { ...env, SECRET: "t".repeat(48) };
        const ft = await handle(new Request(BASE + "/v1/keys/challenge", { method: "POST", headers: { Authorization: `Bearer ${(await makeToken(foreign, OLD_USER, clock)).token}`, "Content-Type": "application/json" }, body: JSON.stringify({ type: "age", key: a.recipient }) }), foreign, deps);
        const fj = await ft.json() as { ticket: string; challenge: string; };
        expect((await put({ ticket: fj.ticket, response: readAgeChallenge(utf8Decode(await ageDecrypt(fj.challenge, [a.identity])), fj.ticket) })).status).toBe(403);
        // Expired.
        clock += 10 * 60_000;
        expect((await put(good)).status).toBe(403);
        clock -= 10 * 60_000;
        // Control: the real proof works.
        expect((await put(good)).status).toBe(200);
    });

    it("checks PGP proofs: the exact statement, signed by this key's primary key", async () => {
        const token = await signIn();
        const put = (proof: unknown, key = pgp.publicKey) => req("PUT", "/v1/keys", { token, body: { type: "pgp", key, proof } });
        const { ticket, statement } = await challenge(token, "pgp", pgp.publicKey);
        expect(statement).toBe(proofStatement(BASE, OLD_USER, pgp.fingerprint!, ticket));
        const home = pgpHome(pgp);
        const signed = (text: string, extra: string[] = []) => rawGpg(home, ["--armor", "--local-user", pgp.fingerprint! + "!", ...extra, "--detach-sign"], text).stdout.toString();

        // A different statement, text mode, SHA-1, a broken signature, someone else's key.
        expect((await put({ ticket, response: signed(statement.replace("user: ", "user: 1")) })).status).toBe(403);
        expect((await put({ ticket, response: signed(statement, ["--textmode"]) })).status).toBe(403);
        expect((await put({ ticket, response: signed(statement, ["--digest-algo", "SHA1"]) })).status).toBe(403);
        const good = signed(statement, ["--digest-algo", "SHA512"]);
        const broken = good.replace(/\n([A-Za-z0-9+/]{20})([A-Za-z0-9+/])/, (_, a: string, c: string) => `\n${a}${c === "A" ? "B" : "A"}`);
        expect(broken).not.toBe(good);
        expect((await put({ ticket, response: broken })).status).toBe(403);
        const stranger = await pgpUser("stranger");
        const theirs = rawGpg(pgpHome(stranger), ["--armor", "--local-user", stranger.fingerprint! + "!", "--detach-sign"], statement).stdout.toString();
        expect((await put({ ticket, response: theirs })).status).toBe(403);
        // A signature with extra data after it.
        expect((await put({ ticket, response: good + "\n" + good })).status).toBe(403);
        // Control: the real signature, and Cipher's own engine.
        expect((await put({ ticket, response: good })).status).toBe(200);
        expect((await put(await provePgp(token, pgp))).status).toBe(200);
    });

    it("answers a malformed age key with 400, not a crash", async () => {
        const token = await signIn();
        const a = await generateAgeIdentity();
        // Same shape, broken bech32 checksum.
        const last = a.recipient.at(-1)!;
        const broken = a.recipient.slice(0, -1) + (last === "q" ? "p" : "q");
        const r = await req("POST", "/v1/keys/challenge", { token, body: { type: "age", key: broken } });
        expect(r.status).toBe(400);
    });

    it("refuses RSA keys with a weak public exponent", () => {
        const n = new Uint8Array(256).fill(0xab);
        n[0] = 0xc1;
        const body = (e: number[]) => Uint8Array.from([4, 0, 0, 0, 0, 1, 0x08, 0x00, ...n, 0x00, Math.max(1, Math.ceil(Math.log2(e[0] + 1))), ...e]);
        expect(primaryKeyFromBody(body([1]))).toBeNull();
        expect(primaryKeyFromBody(body([4]))).toBeNull();
        expect(primaryKeyFromBody(body([3]))).not.toBeNull();
        const e65537 = Uint8Array.from([4, 0, 0, 0, 0, 1, 0x08, 0x00, ...n, 0x00, 17, 1, 0, 1]);
        expect(primaryKeyFromBody(e65537)).not.toBeNull();
    });

    it("accepts RSA and ECDSA primary keys too", async () => {
        const token = await signIn();
        for (const algo of ["rsa3072", "nistp256"]) {
            const { home, engine } = newGpgHome();
            rawGpg(home, ["--quick-gen-key", `${algo} (t)`, algo, "sign,cert", "never"]);
            const fpr = (await engine.listSecretKeys())[0].fingerprint;
            const key = await engine.exportPublicKey(fpr);
            const { ticket, statement } = await challenge(token, "pgp", key);
            const r = await req("PUT", "/v1/keys", { token, body: { type: "pgp", key, proof: { ticket, response: await engine.signProof(fpr, statement) } } });
            expect(r.status, algo).toBe(200);
            await req("POST", "/v1/keys/remove", { token, body: { type: "pgp", proof: await provePgpWith(token, engine, fpr) } });
        }
    }, 120_000);

    it("stops a stolen Discord account from swapping a key: only a visible, cancellable change after 7 days", async () => {
        const token = await signIn();
        const owner = await generateAgeIdentity();
        const attacker = await generateAgeIdentity();
        expect((await req("PUT", "/v1/keys", { token, body: { type: "age", key: owner.recipient, proof: await proveAge(token, owner) } })).status).toBe(200);

        // The attacker has the Discord account (the token) and their own key, not the owner's.
        const swap = (extra: Record<string, unknown> = {}) => proveAge(token, attacker).then(proof =>
            req("PUT", "/v1/keys", { token, body: { type: "age", key: attacker.recipient, proof, ...extra } }));
        let r = await swap();
        expect(r.status).toBe(409);
        expect(await r.json()).toMatchObject({ error: "old-key-proof-required" });
        // Proof from the attacker's own key doesn't count as proof from the old one.
        expect((await swap({ oldProof: await proveAge(token, attacker) })).status).toBe(403);
        r = await swap({ reset: true });
        expect(r.status).toBe(202);
        const lookup = async () => (await (await req("GET", `/v1/keys/${OLD_USER}`)).json() as { keys: { key: string; how: string; pending?: { fingerprint: string; effectiveAt: number; removal: boolean; }; }[]; }).keys[0];
        let k = await lookup();
        // Everyone still gets the owner's key, and sees the waiting change.
        expect(k.key).toBe(owner.recipient);
        expect(k.pending).toEqual({ removal: false, fingerprint: await checkAgePublicKey(attacker.recipient), effectiveAt: clock + 7 * 86_400_000 });

        // The owner cancels it with their key.
        expect((await req("PUT", "/v1/keys", { token, body: { type: "age", key: owner.recipient, proof: await proveAge(token, owner) } })).status).toBe(200);
        expect((await lookup()).pending).toBeUndefined();

        // Not cancelled: it takes effect after 7 days, marked as a reset.
        expect((await swap({ reset: true })).status).toBe(202);
        clock += 7 * 86_400_000 - 1;
        expect((await lookup()).key).toBe(owner.recipient);
        clock += 1;
        k = await lookup();
        expect(k).toMatchObject({ key: attacker.recipient, how: "reset" });
        expect(k.pending).toBeUndefined();
    });

    it("replaces a key at once with proof from the old one, and removes with proof or after the delay", async () => {
        const token = await signIn();
        const one = await generateAgeIdentity();
        const two = await generateAgeIdentity({ postQuantum: true });
        await req("PUT", "/v1/keys", { token, body: { type: "age", key: one.recipient, proof: await proveAge(token, one) } });
        const r = await req("PUT", "/v1/keys", { token, body: { type: "age", key: two.recipient, proof: await proveAge(token, two), oldProof: await proveAge(token, one, { stored: true }) } });
        expect(r.status).toBe(200);
        const keys = async () => (await (await req("GET", `/v1/keys/${OLD_USER}`)).json() as { keys: { key: string; how: string; pending?: unknown; }[]; }).keys;
        expect((await keys())[0]).toMatchObject({ key: two.recipient, how: "proven" });

        expect((await req("POST", "/v1/keys/remove", { token, body: { type: "age" } })).status).toBe(409);
        expect((await req("POST", "/v1/keys/remove", { token, body: { type: "age", proof: await proveAge(token, one) } })).status).toBe(403);
        expect((await req("POST", "/v1/keys/remove", { token, body: { type: "age", reset: true } })).status).toBe(202);
        expect((await keys())[0].pending).toMatchObject({ removal: true });
        clock += 7 * 86_400_000;
        // The daily job applies due resets even if nobody looks the key up.
        await cleanup(env, clock);
        expect(env.DB.db.prepare("SELECT count(*) AS n FROM keys").get()).toEqual(expect.objectContaining({ n: 0 }));
    });
});

describe("server: disappearing messages kept in D1 (no R2, free plan)", () => {
    beforeEach(() => { (env as { MESSAGES?: unknown; }).MESSAGES = undefined; });
    const count = () => (env.DB.db.prepare("SELECT count(*) AS n FROM messages").get() as { n: number; }).n;
    const used = () => (env.DB.db.prepare("SELECT bytes FROM stored_bytes WHERE k = 1").get() as { bytes: number; } | undefined)?.bytes ?? 0;

    it("stores, serves and deletes with the code, keeping nothing about the sender", async () => {
        const token = await signIn();
        const r = await req("POST", "/v1/messages", { token, body: { ciphertext: ageMsg, ttlDays: 3 } });
        expect(r.status).toBe(201);
        const { id, deleteToken } = await r.json() as { id: string; deleteToken: string; };
        const got = await req("GET", `/m/${id}`);
        expect(got.status).toBe(200);
        expect(await got.text()).toBe(ageMsg.trim() + "\n");
        const rows = env.DB.db.prepare("SELECT * FROM messages").all() as Record<string, unknown>[];
        expect(rows).toHaveLength(1);
        expect(Object.keys(rows[0]).sort()).toEqual(["body", "delete_hash", "expires_at", "id"]);
        expect(JSON.stringify(rows[0])).not.toContain(OLD_USER);
        expect(JSON.stringify(rows[0])).not.toContain(deleteToken);
        expect(used()).toBe(ageMsg.trim().length + 1);

        expect((await req("DELETE", `/m/${id}`, { headers: { "X-Delete-Token": "A".repeat(43) } })).status).toBe(403);
        expect((await req("DELETE", `/m/${id}`, { headers: { "X-Delete-Token": deleteToken } })).status).toBe(200);
        expect((await req("GET", `/m/${id}`)).status).toBe(404);
        expect(count()).toBe(0);
        expect(used()).toBe(0);
    });

    it("never serves an expired message, and the hourly job deletes them", async () => {
        const token = await signIn();
        const { id } = await (await req("POST", "/v1/messages", { token, body: { ciphertext: pgpMsg, ttlDays: 1 } })).json() as { id: string; };
        await req("POST", "/v1/messages", { token, body: { ciphertext: ageMsg, ttlDays: 1 } });
        await req("POST", "/v1/messages", { token, body: { ciphertext: ageMsg, ttlDays: 7 } });
        clock += 86_400_000;
        expect((await req("GET", `/m/${id}`)).status).toBe(404);
        expect(count()).toBe(2);
        await cleanup(env, clock);
        expect(count()).toBe(1);
        expect(used()).toBe(ageMsg.trim().length + 1);
    });

    it("stops accepting messages at the storage cap", async () => {
        const token = await signIn();
        env.MAX_STORED_MB = "0";
        expect((await req("POST", "/v1/messages", { token, body: { ciphertext: ageMsg, ttlDays: 1 } })).status).toBe(503);
        expect(count()).toBe(0);
    });
});

describe("server: disappearing messages", () => {
    it("stores an encrypted message, serves it, and deletes it with the delete code", async () => {
        const token = await signIn();
        const r = await req("POST", "/v1/messages", { token, body: { ciphertext: ageMsg, ttlDays: 7 } });
        expect(r.status).toBe(201);
        const { id, deleteToken, expiresAt } = await r.json() as { id: string; deleteToken: string; expiresAt: number; };
        expect(id).toMatch(/^7[A-Za-z0-9_-]{22}$/);
        expect(expiresAt).toBe(clock + 7 * 86_400_000);

        const got = await req("GET", `/m/${id}`);
        expect(got.status).toBe(200);
        expect(await got.text()).toBe(ageMsg.trim() + "\n");
        expect(got.headers.get("Content-Type")).toBe("text/plain; charset=utf-8");
        expect(got.headers.get("X-Content-Type-Options")).toBe("nosniff");
        expect(got.headers.get("Content-Security-Policy")).toContain("sandbox");
        expect(got.headers.get("Cross-Origin-Resource-Policy")).toBe("same-origin");
        expect(got.headers.get("X-Frame-Options")).toBe("DENY");
        expect(got.headers.get("Access-Control-Allow-Origin")).toBeNull();

        // Stored next to it: only the expiry and a hash of the delete code.
        const stored = [...env.MESSAGES.objects.entries()];
        expect(stored).toHaveLength(1);
        expect(stored[0][0]).toBe(`m/7d/${id.slice(1)}`);
        expect(Object.keys(stored[0][1].customMetadata!).sort()).toEqual(["d", "e"]);
        expect(JSON.stringify(stored[0][1].customMetadata)).not.toContain(OLD_USER);

        expect((await req("DELETE", `/m/${id}`, { headers: { "X-Delete-Token": "A".repeat(43) } })).status).toBe(403);
        expect((await req("DELETE", `/m/${id}`, { headers: { "X-Delete-Token": deleteToken } })).status).toBe(200);
        expect((await req("GET", `/m/${id}`)).status).toBe(404);
    });

    it("never serves a message after it expires", async () => {
        const token = await signIn();
        const { id } = await (await req("POST", "/v1/messages", { token, body: { ciphertext: pgpMsg, ttlDays: 1 } })).json() as { id: string; };
        clock += 86_400_000 - 1;
        expect((await req("GET", `/v1/messages/${id}`)).status).toBe(200);
        clock += 1;
        expect((await req("GET", `/v1/messages/${id}`)).status).toBe(404);
        expect(env.MESSAGES.objects.size).toBe(0);
    });

    it("accepts only real encrypted messages", async () => {
        const token = await signIn();
        const post = (ciphertext: string, ttlDays: number = 3) => req("POST", "/v1/messages", { token, body: { ciphertext, ttlDays } });
        env.USER_DAILY_UPLOADS = "1000";
        const { home } = newGpgHome();
        rawGpg(home, ["--import"], pgp.publicKey);
        const cases: [string, string][] = [
            ["plain text", "hello there"],
            ["signed but not encrypted", rawGpg(home, ["--quick-gen-key", "s (t)", "future-default", "default", "never"]) && rawGpg(home, ["--armor", "--sign"], "x").stdout.toString()],
            ["stored literal data (a file)", rawGpg(home, ["--armor", "--store"], "file contents").stdout.toString()],
            ["passphrase only", rawGpg(home, ["--armor", "--symmetric", "--passphrase", "p"], "x").stdout.toString()],
            ["key plus passphrase", rawGpg(home, ["--armor", "--trust-model", "always", "--passphrase", "p", "--recipient", pgp.fingerprint!, "--symmetric", "--encrypt"], "x").stdout.toString()],
            ["text around the block", "look:\n" + pgpMsg],
            ["two blocks", pgpMsg + "\n" + pgpMsg],
            ["age passphrase file", await agePassphraseEncrypt(new Uint8Array([1, 2, 3]), "pass phrase", 10)],
            ["random bytes in age armor", "-----BEGIN AGE ENCRYPTED FILE-----\n" + btoa("x".repeat(48)) + "\n-----END AGE ENCRYPTED FILE-----"],
            ["public key", pgp.publicKey]
        ];
        for (const [label, text] of cases) {
            const r = await post(text);
            expect(r.status, label).toBe(400);
        }
        expect((await post(ageMsg, 2)).status).toBe(400);
        expect((await post(ageMsg, 30)).status).toBe(400);
        expect(env.MESSAGES.objects.size).toBe(0);
    });

    it("refuses data hidden after the encrypted packet, and too many readers", async () => {
        const { home } = newGpgHome();
        const bin = rawGpg(home, ["--dearmor"], pgpMsg).stdout;
        // Control: re-armored unchanged, it passes.
        expect(checkMessage(rawGpg(home, ["--enarmor"], bin).stdout.toString()
            .replace(/ARMORED FILE/g, "MESSAGE").replace(/^Comment:.*\n/m, ""))).toBe("pgp");
        const tail = rawGpg(home, ["--enarmor"], Buffer.concat([bin, Buffer.from([0xCB, 3, 0x62, 0, 0])])).stdout.toString()
            .replace(/ARMORED FILE/g, "MESSAGE").replace(/^Comment:.*\n/m, "");
        expect(() => checkMessage(tail)).toThrow();
        const many = await Promise.all(Array.from({ length: 11 }, () => generateAgeIdentity()));
        const elevenReaders = await ageEncrypt(many.map(m => m.recipient), await encodePayload("x", false));
        expect(() => checkMessage(elevenReaders)).toThrow();
        const ten = await ageEncrypt(many.slice(0, 10).map(m => m.recipient), await encodePayload("x", false));
        expect(checkMessage(ten)).toBe("age");
        expect(checkMessage(pgpMsg)).toBe("pgp");
    });

    it("rejects oversized bodies, other content types and bad IDs", async () => {
        const token = await signIn();
        const big = await req("POST", "/v1/messages", { token, raw: JSON.stringify({ ciphertext: "A".repeat(50_000), ttlDays: 1 }), headers: { "Content-Type": "application/json" } });
        expect(big.status).toBe(413);
        expect((await req("POST", "/v1/messages", { token, raw: "ciphertext=x", headers: { "Content-Type": "text/plain" } })).status).toBe(415);
        expect((await req("POST", "/v1/messages", { token, raw: "{bad", headers: { "Content-Type": "application/json" } })).status).toBe(400);
        for (const bad of ["../keys", "7" + "A".repeat(21), "2" + "A".repeat(22), "7" + "A".repeat(21) + "/", "7%2e%2e%2fA"])
            expect((await req("GET", `/m/${bad}`)).status).toBe(404);
        expect((await req("PATCH", "/v1/keys")).status).toBe(405);
        expect((await req("GET", "/admin")).status).toBe(404);
    });

    it("enforces the per-user daily cap and the monthly bill cap", async () => {
        const token = await signIn();
        for (let i = 0; i < 5; i++) expect((await req("POST", "/v1/messages", { token, body: { ciphertext: ageMsg, ttlDays: 1 } })).status).toBe(201);
        expect((await req("POST", "/v1/messages", { token, body: { ciphertext: ageMsg, ttlDays: 1 } })).status).toBe(429);
        // Usage counters hold a keyed hash, never the user ID.
        const rows = env.DB.db.prepare("SELECT who FROM usage").all() as { who: string; }[];
        expect(rows.every(r => !r.who.includes(OLD_USER))).toBe(true);

        clock += 86_400_000;
        env.MONTHLY_UPLOAD_LIMIT = "6";
        expect((await req("POST", "/v1/messages", { token, body: { ciphertext: ageMsg, ttlDays: 1 } })).status).toBe(201);
        expect((await req("POST", "/v1/messages", { token, body: { ciphertext: ageMsg, ttlDays: 1 } })).status).toBe(503);

        await cleanup(env, clock);
        expect(env.DB.db.prepare("SELECT count(*) AS n FROM usage WHERE day < ?").get(new Date(clock).toISOString().slice(0, 10))).toEqual(expect.objectContaining({ n: 0 }));
    });

    it("needs a sign-in to upload, but not to read or to delete with the code", async () => {
        expect((await req("POST", "/v1/messages", { body: { ciphertext: ageMsg, ttlDays: 1 } })).status).toBe(401);
        expect((await req("GET", "/v1/health")).status).toBe(200);
    });

    it("refuses plain http instead of redirecting (except localhost, for development)", async () => {
        const plain = await handle(new Request("http://cipher.example/v1/health"), env, deps);
        expect(plain.status).toBe(403);
        expect(await plain.json()).toEqual({ error: "https-only" });
        expect((await handle(new Request("http://localhost:8787/v1/health"), env, deps)).status).toBe(200);
        expect((await req("GET", "/v1/health")).status).toBe(200);
    });

    it("applies the per-IP limiter to every request", async () => {
        let n = 0;
        env.LIMITER = { limit: async () => ({ success: ++n <= 2 }) };
        expect((await req("GET", "/v1/health")).status).toBe(200);
        expect((await req("GET", "/v1/health")).status).toBe(200);
        expect((await req("GET", "/v1/health")).status).toBe(429);
    });
});
