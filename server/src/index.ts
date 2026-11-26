/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Cipher's optional server, as one Cloudflare Worker:
 *
 *  - a public-key directory: Discord user ID -> age and/or PGP public key;
 *  - disappearing messages: encrypted text kept for 1, 3 or 7 days, then
 *    deleted. Discord only carries a short link to it. Stored in D1, or in
 *    R2 if a bucket is bound (see store.ts).
 *
 * It stores as little as possible: no logs, no sender or recipient next to
 * a message, no sessions (sign-in tokens are signed, not stored), and usage
 * counters keyed by a keyed hash of the user ID that are dropped daily.
 * It never sees plaintext: Cipher encrypts and decrypts on the user's PC.
 */

import { ageEncrypt } from "../../src/core/ageCipher";
import { ageChallengeText, KEY_RESET_DELAY_MS, MAX_PROOF_SIGNATURE, parseTicket, PROOF_NONCE_RE, PROOF_TTL_MS, proofStatement } from "../../src/core/keyProof";
import { primaryKeyBody, primaryKeyFromBody, verifyPrimarySignature } from "./pgpVerify";
import { d1Store, type MessageStore, r2Store } from "./store";
import { checkAgePublicKey, checkMessage, checkPgpPublicKey, Invalid } from "./validate";

/* ---------- the parts of the Workers runtime this uses ---------- */

export interface D1Result<T> { results?: T[]; }
export interface D1Statement {
    bind(...values: unknown[]): D1Statement;
    first<T = Record<string, unknown>>(): Promise<T | null>;
    run(): Promise<unknown>;
    all<T = Record<string, unknown>>(): Promise<D1Result<T>>;
}
export interface D1Database { prepare(sql: string): D1Statement; }

export interface R2Object { customMetadata?: Record<string, string>; text(): Promise<string>; }
export interface R2Bucket {
    get(key: string): Promise<R2Object | null>;
    head(key: string): Promise<{ customMetadata?: Record<string, string>; } | null>;
    put(key: string, value: string, options?: { customMetadata?: Record<string, string>; httpMetadata?: { contentType?: string; }; }): Promise<unknown>;
    delete(key: string): Promise<void>;
}

export interface RateLimiter { limit(o: { key: string; }): Promise<{ success: boolean; }>; }

export interface Env {
    DB: D1Database;
    /** Optional R2 bucket for messages. Without it, messages are kept in D1 (free plan, no card). */
    MESSAGES?: R2Bucket;
    /** D1 message storage: stop accepting messages past this many MB (free D1 databases hold 500 MB). */
    MAX_STORED_MB?: string;
    /** Long random string: signs sign-in tokens and keys the usage counters. */
    SECRET: string;
    DISCORD_CLIENT_ID: string;
    DISCORD_CLIENT_SECRET: string;
    /** Public URL of this Worker, e.g. https://cipher.example.com (no trailing slash). */
    PUBLIC_URL: string;
    /** Stop accepting uploads after this many in a calendar month (the bill cap). */
    MONTHLY_UPLOAD_LIMIT?: string;
    USER_DAILY_UPLOADS?: string;
    MIN_ACCOUNT_AGE_DAYS?: string;
    /** Optional Workers rate-limiting binding, applied per IP to every request. */
    LIMITER?: RateLimiter;
}

export interface Deps {
    now(): number;
    /** fetch, for talking to Discord's OAuth API only. */
    fetch(input: string, init?: RequestInit): Promise<Response>;
}

/* ---------- constants ---------- */

export const TTL_DAYS = [1, 3, 7] as const;
const DAY = 86_400_000;
const TOKEN_DAYS = 30;
const DISCORD_EPOCH = 1420070400000;
const SNOWFLAKE_RE = /^\d{17,20}$/;
/** Message IDs: TTL digit + 22 base64url characters (128 random bits). */
const MESSAGE_ID_RE = /^[137][A-Za-z0-9_-]{22}$/;
const MAX_BODY = 40 * 1024;
/** Sign-in attempts per IP address per day (shared VPN exits included, so not too low). */
const SIGNINS_PER_IP_PER_DAY = 50;
/** Challenges, publishes and removals together, per account per day. */
const KEY_OPS_PER_DAY = 40;

/**
 * Every response is data for Cipher, never a page: nothing may run, be framed,
 * be embedded by other sites, be sniffed as another type, or be cached.
 */
const SECURITY_HEADERS: Record<string, string> = {
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; sandbox",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Permissions-Policy": "interest-cohort=(), camera=(), microphone=(), geolocation=()",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store"
};

/* ---------- small helpers ---------- */

class HttpError extends Error {
    constructor(readonly status: number, readonly code: string) {
        super(code);
    }
}

function json(status: number, body: unknown): Response {
    return new Response(JSON.stringify(body), { status, headers: { ...SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8" } });
}

const enc = new TextEncoder();

function b64url(bytes: Uint8Array): string {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(s: string): Uint8Array {
    const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
    return Uint8Array.from(b, c => c.charCodeAt(0));
}

function randomB64url(bytes: number): string {
    return b64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function sha256Hex(s: string): Promise<string> {
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
    return [...d].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hmacKey(secret: string): Promise<CryptoKey> {
    if (!secret || secret.length < 32) throw new HttpError(500, "server-misconfigured");
    return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function hmacB64(secret: string, msg: string): Promise<string> {
    return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(msg))));
}

/** Keyed hash for usage counters: the stored value can't be turned back into a user ID or IP. */
async function pseudonym(env: Env, kind: string, value: string): Promise<string> {
    return (await hmacB64(env.SECRET, `${kind}|${value}`)).slice(0, 24);
}

async function readBody(req: Request, max = MAX_BODY): Promise<string> {
    const declared = Number(req.headers.get("Content-Length") ?? "0");
    if (declared > max) throw new HttpError(413, "too-large");
    if (!req.body) return "";
    const reader = req.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.length;
        if (total > max) {
            await reader.cancel();
            throw new HttpError(413, "too-large");
        }
        chunks.push(value);
    }
    const all = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) { all.set(c, o); o += c.length; }
    try {
        return new TextDecoder("utf-8", { fatal: true }).decode(all);
    } catch {
        throw new HttpError(400, "not-text");
    }
}

async function readJson(req: Request): Promise<Record<string, unknown>> {
    if (!(req.headers.get("Content-Type") ?? "").startsWith("application/json")) throw new HttpError(415, "json-only");
    try {
        const v = JSON.parse(await readBody(req));
        if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error();
        return v as Record<string, unknown>;
    } catch (e) {
        if (e instanceof HttpError) throw e;
        throw new HttpError(400, "bad-json");
    }
}

const intEnv = (v: string | undefined, d: number) => {
    const n = Number(v);
    return Number.isFinite(n) && n >= 0 ? n : d;
};

const today = (now: number) => new Date(now).toISOString().slice(0, 10);
const thisMonth = (now: number) => new Date(now).toISOString().slice(0, 7);

/* ---------- sign-in tokens (stateless) ---------- */

export async function makeToken(env: Env, userId: string, now: number): Promise<{ token: string; expiresAt: number; }> {
    const exp = Math.floor(now / 1000) + TOKEN_DAYS * 86400;
    const body = `c1.${userId}.${exp}`;
    return { token: `${body}.${await hmacB64(env.SECRET, "token|" + body)}`, expiresAt: exp * 1000 };
}

export async function verifyToken(env: Env, header: string | null, now: number): Promise<string> {
    const m = /^Bearer (c1\.(\d{17,20})\.(\d{1,12}))\.([A-Za-z0-9_-]{43})$/.exec(header ?? "");
    if (!m) throw new HttpError(401, "sign-in-required");
    const [, body, userId, exp, sig] = m;
    let sigBytes: Uint8Array;
    try {
        sigBytes = fromB64url(sig);
    } catch {
        throw new HttpError(401, "sign-in-required");
    }
    // crypto.subtle.verify compares in constant time.
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(env.SECRET), sigBytes as BufferSource, enc.encode("token|" + body));
    if (!ok || Number(exp) * 1000 <= now) throw new HttpError(401, "sign-in-required");
    return userId;
}

/* ---------- limits ---------- */

/** Adds one to today's counter for `who` and fails once it passes `max`. */
async function countToday(env: Env, now: number, scope: string, who: string, max: number) {
    const row = await env.DB.prepare(
        "INSERT INTO usage (day, who, count) VALUES (?1, ?2, 1) ON CONFLICT(day, who) DO UPDATE SET count = count + 1 RETURNING count"
    ).bind(today(now), `${scope}:${who}`).first<{ count: number; }>();
    if ((row?.count ?? 0) > max) throw new HttpError(429, "daily-limit");
}

function messageStore(env: Env): MessageStore {
    return env.MESSAGES ? r2Store(env.MESSAGES) : d1Store(env.DB, intEnv(env.MAX_STORED_MB, 400) * 1024 * 1024);
}

/** The monthly upload cap that keeps the bill bounded. */
async function countMonth(env: Env, now: number) {
    const limit = intEnv(env.MONTHLY_UPLOAD_LIMIT, 2_000_000);
    const row = await env.DB.prepare(
        "INSERT INTO budget (month, uploads) VALUES (?1, 1) ON CONFLICT(month) DO UPDATE SET uploads = uploads + 1 RETURNING uploads"
    ).bind(thisMonth(now)).first<{ uploads: number; }>();
    if ((row?.uploads ?? 0) > limit) throw new HttpError(503, "server-full");
}

/* ---------- Discord sign-in ---------- */

/** Discord's JSON, or a refusal if it sent anything else. */
async function discordJson<T>(res: Response): Promise<T> {
    if (!res.ok) throw new HttpError(401, "discord-refused");
    try {
        return await res.json() as T;
    } catch {
        throw new HttpError(401, "discord-refused");
    }
}

async function discordSignIn(env: Env, deps: Deps, code: string): Promise<string> {
    const tokenRes = await deps.fetch("https://discord.com/api/v10/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            client_id: env.DISCORD_CLIENT_ID,
            client_secret: env.DISCORD_CLIENT_SECRET,
            grant_type: "authorization_code",
            code,
            redirect_uri: `${env.PUBLIC_URL}/v1/auth/callback`
        }).toString(),
        // Workers only support "follow" and "manual". With "manual", a redirect comes back as a
        // 3xx response, which discordJson refuses: Discord's answers are never followed elsewhere.
        redirect: "manual"
    });
    const tok = await discordJson<{ access_token?: unknown; refresh_token?: unknown; token_type?: unknown; }>(tokenRes);
    if (typeof tok.access_token !== "string" || tok.token_type !== "Bearer") throw new HttpError(401, "discord-refused");

    try {
        const meRes = await deps.fetch("https://discord.com/api/v10/users/@me", {
            headers: { Authorization: `Bearer ${tok.access_token}` },
            redirect: "manual"
        });
        const me = await discordJson<{ id?: unknown; bot?: unknown; }>(meRes);
        if (typeof me.id !== "string" || !SNOWFLAKE_RE.test(me.id) || me.bot) throw new HttpError(401, "discord-refused");
        return me.id;
    } finally {
        // Only the user ID was needed. Revoke the grant at once, so no usable Discord token
        // is left anywhere and the app drops off the user's "Authorized Apps" list.
        await revokeDiscordTokens(env, deps, [tok.refresh_token, tok.access_token]);
    }
}

async function revokeDiscordTokens(env: Env, deps: Deps, tokens: unknown[]) {
    for (const token of tokens) {
        if (typeof token !== "string" || !token) continue;
        try {
            await deps.fetch("https://discord.com/api/v10/oauth2/token/revoke", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({ client_id: env.DISCORD_CLIENT_ID, client_secret: env.DISCORD_CLIENT_SECRET, token }).toString(),
                redirect: "manual"
            });
        } catch {
            // Best effort: the token expires on its own.
        }
    }
}

export function accountCreatedAt(userId: string): number {
    return Number(BigInt(userId) >> 22n) + DISCORD_EPOCH;
}

/* ---------- proof of key possession ---------- */

type KeyType = "age" | "pgp";

interface KeyRecord {
    type: KeyType; material: string; fingerprint: string; updated_at: number;
    first_at: number; changed_at: number; how: "new" | "proven" | "reset";
    pending_material: string | null; pending_fingerprint: string | null; pending_at: number | null;
}

const publicOrigin = (env: Env) => new URL(env.PUBLIC_URL).origin;
const normalizeKey = (v: unknown) => typeof v === "string" ? v.replace(/\r\n/g, "\n").trim() : "";

function keyType(v: unknown): KeyType {
    if (v !== "age" && v !== "pgp") throw new HttpError(400, "bad-type");
    return v;
}

async function keyFingerprint(type: KeyType, key: string): Promise<string> {
    try {
        return type === "age" ? await checkAgePublicKey(key) : await checkPgpPublicKey(key);
    } catch (e) {
        if (e instanceof Invalid) throw new HttpError(400, "invalid-key");
        throw e;
    }
}

function currentKey(env: Env, userId: string, type: KeyType) {
    return env.DB.prepare("SELECT material, fingerprint, pending_at FROM keys WHERE user_id = ?1 AND type = ?2")
        .bind(userId, type).first<Pick<KeyRecord, "material" | "fingerprint" | "pending_at">>();
}

/** Stateless: the ticket carries its own HMAC, and the age code is derived from it. */
async function issueTicket(env: Env, userId: string, type: KeyType, fingerprint: string, now: number) {
    const body = `p1.${userId}.${type}.${fingerprint}.${now + PROOF_TTL_MS}.${randomB64url(16)}`;
    return {
        ticket: `${body}.${await hmacB64(env.SECRET, "proof|" + body)}`,
        nonce: await hmacB64(env.SECRET, "nonce|" + body)
    };
}

function equalStrings(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return d === 0;
}

/** Checks a proof that `userId` holds the private key of `material` (fingerprint `fingerprint`). */
async function checkProof(env: Env, userId: string, type: KeyType, fingerprint: string, material: string, proof: unknown, now: number): Promise<boolean> {
    if (!proof || typeof proof !== "object" || Array.isArray(proof)) return false;
    const { ticket, response } = proof as Record<string, unknown>;
    if (typeof ticket !== "string" || typeof response !== "string") return false;
    const t = parseTicket(ticket);
    if (!t || t.userId !== userId || t.type !== type || t.fingerprint !== fingerprint) return false;
    if (t.expiresAt <= now || t.expiresAt > now + PROOF_TTL_MS) return false;
    const dot = ticket.lastIndexOf(".");
    const body = ticket.slice(0, dot);
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(env.SECRET), fromB64url(ticket.slice(dot + 1)) as BufferSource, enc.encode("proof|" + body));
    if (!ok) return false;
    if (type === "age") return PROOF_NONCE_RE.test(response) && equalStrings(response, await hmacB64(env.SECRET, "nonce|" + body));
    if (response.length > MAX_PROOF_SIGNATURE) return false;
    const primary = primaryKeyBody(material);
    if (!primary) return false;
    return verifyPrimarySignature(primary, response, enc.encode(proofStatement(publicOrigin(env), userId, fingerprint, ticket)), now);
}

/** Resets whose waiting time is over take effect (for one user, or everyone from the cron job). */
async function applyDueResets(env: Env, now: number, userId?: string) {
    const only = userId ? " AND user_id = ?2" : "";
    const args = userId ? [now, userId] : [now];
    await env.DB.prepare(`DELETE FROM keys WHERE pending_at IS NOT NULL AND pending_at <= ?1 AND pending_material = ''${only}`).bind(...args).run();
    await env.DB.prepare(
        "UPDATE keys SET material = pending_material, fingerprint = pending_fingerprint, updated_at = pending_at, changed_at = pending_at, how = 'reset', " +
        `pending_material = NULL, pending_fingerprint = NULL, pending_at = NULL WHERE pending_at IS NOT NULL AND pending_at <= ?1${only}`
    ).bind(...args).run();
}

/* ---------- routes ---------- */

type Handler = (req: Request, env: Env, deps: Deps, params: string[]) => Promise<Response>;

const routes: [string, RegExp, Handler][] = [
    ["GET", /^\/v1\/health$/, async () => json(200, { ok: true })],

    ["GET", /^\/v1\/oauth$/, async (_r, env) => json(200, { clientId: env.DISCORD_CLIENT_ID, redirectUri: `${env.PUBLIC_URL}/v1/auth/callback` })],

    ["GET", /^\/v1\/auth\/callback$/, async (req, env, deps) => {
        const code = new URL(req.url).searchParams.get("code") ?? "";
        if (!/^[A-Za-z0-9]{10,64}$/.test(code)) throw new HttpError(400, "bad-code");
        const now = deps.now();
        // Each attempt costs a call to Discord with this server's credentials, and floods of
        // bad codes could get the app limited by Discord. Real sign-ins are rare (30-day tokens).
        await countToday(env, now, "signin", await pseudonym(env, "ip", req.headers.get("CF-Connecting-IP") ?? "unknown"), SIGNINS_PER_IP_PER_DAY);
        const userId = await discordSignIn(env, deps, code);
        const minDays = intEnv(env.MIN_ACCOUNT_AGE_DAYS, 2);
        if (now - accountCreatedAt(userId) < minDays * DAY) throw new HttpError(403, "account-too-new");
        return json(200, { userId, ...await makeToken(env, userId, now) });
    }],

    ["GET", /^\/v1\/keys\/(\d{17,20})$/, async (_r, env, deps, [userId]) => {
        const now = deps.now();
        const select = () => env.DB.prepare(
            "SELECT type, material, fingerprint, updated_at, first_at, changed_at, how, pending_material, pending_fingerprint, pending_at FROM keys WHERE user_id = ?1 ORDER BY type"
        ).bind(userId).all<KeyRecord>();
        let r = await select();
        if ((r.results ?? []).some(k => k.pending_at !== null && k.pending_at <= now)) {
            await applyDueResets(env, now, userId);
            r = await select();
        }
        const keys = (r.results ?? []).map(k => ({
            type: k.type, key: k.material, fingerprint: k.fingerprint, updatedAt: k.updated_at,
            firstAt: k.first_at, changedAt: k.changed_at, how: k.how,
            ...k.pending_at !== null ? { pending: { removal: k.pending_material === "", fingerprint: k.pending_material === "" ? null : k.pending_fingerprint, effectiveAt: k.pending_at } } : {}
        }));
        return json(keys.length ? 200 : 404, { userId, keys });
    }],

    /** A one-time ticket for proving you hold a key: a challenge to decrypt (age) or a statement to sign (PGP). */
    ["POST", /^\/v1\/keys\/challenge$/, async (req, env, deps) => {
        const now = deps.now();
        const userId = await verifyToken(env, req.headers.get("Authorization"), now);
        await countToday(env, now, "keys", await pseudonym(env, "u", userId), KEY_OPS_PER_DAY);
        const body = await readJson(req);
        const type = keyType(body.type);
        // Without a key: the one currently published (to prove it before replacing or removing it).
        let key = normalizeKey(body.key);
        if (!key) {
            const row = await env.DB.prepare("SELECT material FROM keys WHERE user_id = ?1 AND type = ?2").bind(userId, type).first<{ material: string; }>();
            if (!row) throw new HttpError(404, "no-key");
            key = row.material;
        }
        const fingerprint = await keyFingerprint(type, key);
        if (type === "pgp") {
            const primary = primaryKeyBody(key);
            if (!primary || fingerprint.length !== 40 || !primaryKeyFromBody(primary)) throw new HttpError(400, "proof-unsupported-key");
        }
        const { ticket, nonce } = await issueTicket(env, userId, type, fingerprint, now);
        if (type === "age") {
            let challenge: string;
            try {
                challenge = await ageEncrypt([key], enc.encode(ageChallengeText(ticket, nonce)));
            } catch {
                // Looks like an age key but isn't one (bad checksum or point).
                throw new HttpError(400, "invalid-key");
            }
            return json(200, { ticket, challenge });
        }
        return json(200, { ticket, statement: proofStatement(publicOrigin(env), userId, fingerprint, ticket) });
    }],

    /**
     * Publishes a key. Always needs proof from the new key. Replacing a
     * different key also needs proof from the old one; without it (`reset`)
     * the new key only takes effect after KEY_RESET_DELAY_MS, and lookups
     * show the waiting change so people can notice a takeover.
     */
    ["PUT", /^\/v1\/keys$/, async (req, env, deps) => {
        const now = deps.now();
        const userId = await verifyToken(env, req.headers.get("Authorization"), now);
        await countToday(env, now, "keys", await pseudonym(env, "u", userId), KEY_OPS_PER_DAY);
        const body = await readJson(req);
        const type = keyType(body.type);
        const key = normalizeKey(body.key);
        const fingerprint = await keyFingerprint(type, key);
        if (!await checkProof(env, userId, type, fingerprint, key, body.proof, now)) throw new HttpError(403, "bad-proof");

        await applyDueResets(env, now, userId);
        const existing = await currentKey(env, userId, type);
        if (!existing) {
            const row = await env.DB.prepare(
                "INSERT INTO keys (user_id, type, material, fingerprint, updated_at, first_at, changed_at, how) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?5, 'new') " +
                "ON CONFLICT(user_id, type) DO NOTHING RETURNING user_id"
            ).bind(userId, type, key, fingerprint, now).first();
            if (!row) throw new HttpError(409, "try-again");
            return json(200, { ok: true, type, fingerprint });
        }
        if (existing.fingerprint === fingerprint) {
            // The same key (maybe with new subkeys or expiry). Proving it also cancels a waiting reset.
            const row = await env.DB.prepare(
                "UPDATE keys SET material = ?3, updated_at = ?4, pending_material = NULL, pending_fingerprint = NULL, pending_at = NULL " +
                "WHERE user_id = ?1 AND type = ?2 AND fingerprint = ?5 RETURNING user_id"
            ).bind(userId, type, key, now, fingerprint).first();
            if (!row) throw new HttpError(409, "try-again");
            return json(200, { ok: true, type, fingerprint, ...existing.pending_at !== null ? { cancelledReset: true } : {} });
        }
        if (body.oldProof !== undefined) {
            if (!await checkProof(env, userId, type, existing.fingerprint, existing.material, body.oldProof, now)) throw new HttpError(403, "bad-proof");
            const row = await env.DB.prepare(
                "UPDATE keys SET material = ?3, fingerprint = ?4, updated_at = ?5, changed_at = ?5, how = 'proven', pending_material = NULL, pending_fingerprint = NULL, pending_at = NULL " +
                "WHERE user_id = ?1 AND type = ?2 AND fingerprint = ?6 RETURNING user_id"
            ).bind(userId, type, key, fingerprint, now, existing.fingerprint).first();
            if (!row) throw new HttpError(409, "try-again");
            return json(200, { ok: true, type, fingerprint });
        }
        if (body.reset === true) {
            const effectiveAt = now + KEY_RESET_DELAY_MS;
            const row = await env.DB.prepare(
                "UPDATE keys SET pending_material = ?3, pending_fingerprint = ?4, pending_at = ?5 WHERE user_id = ?1 AND type = ?2 AND fingerprint = ?6 RETURNING user_id"
            ).bind(userId, type, key, fingerprint, effectiveAt, existing.fingerprint).first();
            if (!row) throw new HttpError(409, "try-again");
            return json(202, { ok: true, pending: true, type, fingerprint, effectiveAt });
        }
        return json(409, { error: "old-key-proof-required", fingerprint: existing.fingerprint });
    }],

    /** Removes a published key: with proof from it at once, otherwise (`reset`) after the delay. */
    ["POST", /^\/v1\/keys\/remove$/, async (req, env, deps) => {
        const now = deps.now();
        const userId = await verifyToken(env, req.headers.get("Authorization"), now);
        await countToday(env, now, "keys", await pseudonym(env, "u", userId), KEY_OPS_PER_DAY);
        const body = await readJson(req);
        const type = keyType(body.type);
        await applyDueResets(env, now, userId);
        const existing = await currentKey(env, userId, type);
        if (!existing) return json(200, { ok: true });
        if (body.proof !== undefined) {
            if (!await checkProof(env, userId, type, existing.fingerprint, existing.material, body.proof, now)) throw new HttpError(403, "bad-proof");
            await env.DB.prepare("DELETE FROM keys WHERE user_id = ?1 AND type = ?2 AND fingerprint = ?3").bind(userId, type, existing.fingerprint).run();
            return json(200, { ok: true });
        }
        if (body.reset === true) {
            const effectiveAt = now + KEY_RESET_DELAY_MS;
            await env.DB.prepare(
                "UPDATE keys SET pending_material = '', pending_fingerprint = '', pending_at = ?3 WHERE user_id = ?1 AND type = ?2"
            ).bind(userId, type, effectiveAt).run();
            return json(202, { ok: true, pending: true, removal: true, effectiveAt });
        }
        return json(409, { error: "old-key-proof-required", fingerprint: existing.fingerprint });
    }],

    ["POST", /^\/v1\/messages$/, async (req, env, deps) => {
        const now = deps.now();
        const userId = await verifyToken(env, req.headers.get("Authorization"), now);
        // Every attempt counts against the user's daily quota, rejected ones too.
        await countToday(env, now, "up", await pseudonym(env, "u", userId), intEnv(env.USER_DAILY_UPLOADS, 300));
        const body = await readJson(req);
        const ttl = body.ttlDays;
        if (!TTL_DAYS.includes(ttl as 1)) return json(400, { error: "bad-ttl" });
        const text = typeof body.ciphertext === "string" ? body.ciphertext.replace(/\r\n/g, "\n").trim() + "\n" : "";
        try {
            checkMessage(text);
        } catch (e) {
            if (e instanceof Invalid) return json(400, { error: "not-an-encrypted-message", detail: e.message });
            throw e;
        }
        // Only stored messages count towards the monthly bill cap.
        await countMonth(env, now);

        const id = `${ttl}${randomB64url(16)}`;
        const deleteToken = randomB64url(32);
        const expiresAt = now + (ttl as number) * DAY;
        // Only what's needed to expire and delete it. Nothing about the sender.
        if (!await messageStore(env).put(id, text, expiresAt, await sha256Hex(deleteToken))) throw new HttpError(503, "server-full");
        return json(201, { id, deleteToken, expiresAt });
    }],

    ["GET", /^\/(?:v1\/messages|m)\/([137][A-Za-z0-9_-]{22})$/, async (_r, env, deps, [id]) => {
        if (!MESSAGE_ID_RE.test(id)) throw new HttpError(404, "not-found");
        const store = messageStore(env);
        const msg = await store.get(id);
        if (!msg) throw new HttpError(404, "not-found");
        // The sweep runs hourly (D1) or daily (R2 lifecycle); never serve a message late.
        const exp = msg.expiresAt;
        if (!Number.isFinite(exp) || exp <= deps.now()) {
            await store.delete(id);
            throw new HttpError(404, "not-found");
        }
        return new Response(msg.text, {
            status: 200,
            headers: { ...SECURITY_HEADERS, "Content-Type": "text/plain; charset=utf-8", "X-Expires-At": String(exp) }
        });
    }],

    ["DELETE", /^\/(?:v1\/messages|m)\/([137][A-Za-z0-9_-]{22})$/, async (req, env, _d, [id]) => {
        const token = req.headers.get("X-Delete-Token") ?? "";
        if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new HttpError(403, "bad-delete-token");
        const store = messageStore(env);
        const msg = await store.get(id);
        if (!msg) return json(200, { ok: true });
        // Hashes of random tokens: comparing them leaks nothing useful about the token.
        if (msg.deleteHash !== await sha256Hex(token)) throw new HttpError(403, "bad-delete-token");
        await store.delete(id);
        return json(200, { ok: true });
    }]
];

export async function handle(req: Request, env: Env, deps: Deps): Promise<Response> {
    try {
        const url = new URL(req.url);
        // workers.dev also answers plain http. Refuse it rather than redirect, so a
        // client that got it wrong fails loudly instead of sending a token in the clear.
        const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
        if (url.protocol !== "https:" && !local) throw new HttpError(403, "https-only");
        if (env.LIMITER) {
            const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
            const { success } = await env.LIMITER.limit({ key: await pseudonym(env, "ip", ip) });
            if (!success) throw new HttpError(429, "slow-down");
        }
        const candidates = routes.filter(([, re]) => re.test(url.pathname));
        if (!candidates.length) throw new HttpError(404, "not-found");
        const route = candidates.find(([m]) => m === req.method);
        if (!route) throw new HttpError(405, "method-not-allowed");
        const params = route[1].exec(url.pathname)!.slice(1);
        return await route[2](req, env, deps, params);
    } catch (e) {
        if (e instanceof HttpError) return json(e.status, { error: e.code });
        // No logging: nothing about requests is kept anywhere.
        return json(500, { error: "internal" });
    }
}

/** Hourly jobs: expired messages, due key resets, usage counters from earlier days, old monthly totals. */
export async function cleanup(env: Env, now: number) {
    await messageStore(env).sweep(now);
    await applyDueResets(env, now);
    await env.DB.prepare("DELETE FROM usage WHERE day < ?1").bind(today(now)).run();
    const twoMonthsAgo = thisMonth(now - 62 * DAY);
    await env.DB.prepare("DELETE FROM budget WHERE month < ?1").bind(twoMonthsAgo).run();
}

export default {
    fetch(req: Request, env: Env): Promise<Response> {
        return handle(req, env, { now: Date.now, fetch: (i, init) => fetch(i, init) });
    },
    async scheduled(_event: unknown, env: Env): Promise<void> {
        await cleanup(env, Date.now());
    }
};
