/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Cipher's side of the optional server: sign-in with Discord, the public-key
 * directory and disappearing messages. Every request goes through native.ts
 * (Discord's main process), which only allows the requests listed in
 * core/serverApi.ts. Nothing here ever sends plaintext: only public keys and
 * ciphertext leave the computer.
 */

import * as DataStore from "@api/DataStore";
import type { PluginNative } from "@utils/types";
import { OAuth2AuthorizeModal, openModal, UserStore } from "@webpack/common";

import { ageDecrypt } from "./core/ageCipher";
import { sha256 } from "./core/bytes";
import { normalizeForServer } from "./core/compose";
import { CipherError } from "./core/errors";
import { parseTicket, proofStatement, readAgeChallenge } from "./core/keyProof";
import { inspectKey, type KeyType } from "./core/keys";
import { pgpEngine, toCipherError } from "./core/pgpCipher";
import { DELETE_TOKEN_RE, LINK_ID_RE, linkLoadPolicy, type LinkTtl, normalizeServerUrl, SERVER_TOKEN_RE } from "./core/serverApi";
import { settings } from "./settings";
import { state } from "./state";

type Native = PluginNative<typeof import("./native")>;

function native(): Native {
    const n = (globalThis as any).VencordNative?.pluginHelpers?.Cipher as Native | undefined;
    if (!n) throw new CipherError("internal", "The Cipher server needs the Discord desktop app.");
    return n;
}

/** The configured server's origin, or null when the server features are off. */
export function serverOrigin(): string | null {
    const raw = settings.store.serverUrl?.trim();
    return raw ? normalizeServerUrl(raw) : null;
}

async function call(method: string, path: string, opts: { body?: unknown; token?: string; deleteToken?: string; } = {}) {
    const origin = serverOrigin();
    if (!origin) throw new CipherError("internal", "No Cipher server is set up. Add one in Cipher's settings.");
    const r = await native().serverFetch(origin, method, path, opts.body === undefined ? undefined : JSON.stringify(opts.body), opts.token, opts.deleteToken);
    if (!r.ok) throw new CipherError("internal", r.code === "invalid-input" ? "Cipher refused that server request." : "Couldn't reach the Cipher server.");
    return r;
}

function parseJson<T>(text: string): T {
    try {
        return JSON.parse(text) as T;
    } catch {
        throw new CipherError("internal", "The Cipher server sent something unexpected.");
    }
}

function errorCode(body: string): string | undefined {
    try {
        const e = (JSON.parse(body) as { error?: unknown; }).error;
        return typeof e === "string" ? e : undefined;
    } catch {
        return undefined;
    }
}

function serverError(status: number, body: string): CipherError {
    const code = errorCode(body);
    const text: Record<string, string> = {
        "sign-in-required": "Sign in to the Cipher server again (Cipher settings).",
        "account-too-new": "The Cipher server only accepts Discord accounts older than 2 days.",
        "daily-limit": "You've reached today's limit on the Cipher server. Try again tomorrow, or send a normal message.",
        "server-full": "The Cipher server has reached its monthly limit and isn't accepting new messages right now.",
        "slow-down": "Too many requests to the Cipher server. Wait a minute.",
        "not-an-encrypted-message": "The Cipher server refused the message.",
        "invalid-key": "The Cipher server refused that key.",
        "bad-proof": "The Cipher server didn't accept the proof that this is your key. Try again.",
        "proof-unsupported-key": "This PGP key can't prove it's yours to the Cipher server: its main key must be able to sign, and be Ed25519, ECDSA (P-256/384/521) or RSA (2048 bits or more).",
        "no-key": "You haven't published a key of that type.",
        "try-again": "Your published key changed at the same time. Try again."
    };
    return new CipherError("internal", (code && text[code]) ?? `The Cipher server answered with an error (${status}).`);
}

/* ---------- sign-in ---------- */

interface Session { origin: string; userId: string; token: string; expiresAt: number; }

const sessionKey = () => `Cipher_server_session_v1:${UserStore.getCurrentUser()?.id}`;

export async function getSession(): Promise<Session | undefined> {
    const s = await DataStore.get<Session>(sessionKey());
    if (!s || s.origin !== serverOrigin() || s.expiresAt <= Date.now() || s.userId !== UserStore.getCurrentUser()?.id) return undefined;
    return s;
}

export async function signOut() {
    await DataStore.del(sessionKey());
}

/** Opens Discord's own "Authorize" window and exchanges the result for a Cipher server token. */
export async function signIn(): Promise<void> {
    const origin = serverOrigin();
    if (!origin) throw new CipherError("internal", "Set the server address first.");
    const r = await call("GET", "/v1/oauth");
    if (r.status !== 200) throw serverError(r.status, r.body);
    const { clientId, redirectUri } = parseJson<{ clientId?: unknown; redirectUri?: unknown; }>(r.body);
    if (typeof clientId !== "string" || !/^\d{17,20}$/.test(clientId) || redirectUri !== `${origin}/v1/auth/callback`)
        throw new CipherError("internal", "The Cipher server's sign-in settings look wrong.");

    const location = await new Promise<string | undefined>(resolve => {
        openModal((props: any) => <OAuth2AuthorizeModal
            {...props}
            scopes={["identify"]}
            responseType="code"
            redirectUri={redirectUri}
            permissions={0n}
            clientId={clientId}
            cancelCompletesFlow={false}
            callback={({ location }: { location?: string; }) => resolve(location)}
        />, { onCloseCallback: () => resolve(undefined) });
    });
    if (!location) throw new CipherError("cancelled", "Sign-in cancelled.");
    // Only ever follow the callback on our own server.
    const u = new URL(location);
    const code = u.searchParams.get("code") ?? "";
    if (u.origin !== origin || u.pathname !== "/v1/auth/callback" || !/^[A-Za-z0-9]{10,64}$/.test(code))
        throw new CipherError("internal", "Unexpected sign-in result.");

    const res = await call("GET", `/v1/auth/callback?code=${code}`);
    if (res.status !== 200) throw serverError(res.status, res.body);
    const s = parseJson<{ userId?: unknown; token?: unknown; expiresAt?: unknown; }>(res.body);
    const me = UserStore.getCurrentUser()?.id;
    if (typeof s.token !== "string" || !SERVER_TOKEN_RE.test(s.token) || s.userId !== me || typeof s.expiresAt !== "number")
        throw new CipherError("internal", "The Cipher server signed you in as someone else.");
    await DataStore.set(sessionKey(), { origin, userId: me, token: s.token, expiresAt: s.expiresAt } satisfies Session);
}

async function requireSession(): Promise<Session> {
    const s = await getSession();
    if (!s) throw new CipherError("internal", "Sign in to the Cipher server first (Cipher settings).");
    return s;
}

/* ---------- key directory ---------- */

export interface PendingChange { removal: boolean; fingerprint: string | null; effectiveAt: number; }

export interface DirectoryKey {
    type: KeyType; key: string; fingerprint: string; updatedAt: number;
    /** When the key's fingerprint last changed, and how: first key, approved by the old key, or a reset without it. */
    changedAt?: number;
    how?: "new" | "proven" | "reset";
    /** A replacement or removal requested without proof from this key, waiting out its delay. */
    pending?: PendingChange;
}

const num = (v: unknown) => typeof v === "number" && Number.isFinite(v) ? v : undefined;

function readDirectoryKey(k: any): DirectoryKey | null {
    if (!k || (k.type !== "age" && k.type !== "pgp") || typeof k.key !== "string" || k.key.length >= 64 * 1024) return null;
    // The server's fingerprint is only a hint (Cipher computes its own when a key is used), but keep it sane.
    if (typeof k.fingerprint !== "string" || !/^(?:[0-9A-F]{40}|[0-9A-F]{64})$/.test(k.fingerprint)) return null;
    const p = k.pending;
    const pending = p && typeof p === "object" && num(p.effectiveAt) !== undefined
        ? { removal: p.removal === true, fingerprint: typeof p.fingerprint === "string" && /^(?:[0-9A-F]{40}|[0-9A-F]{64})$/.test(p.fingerprint) ? p.fingerprint : null, effectiveAt: num(p.effectiveAt)! }
        : undefined;
    return {
        type: k.type, key: k.key, fingerprint: k.fingerprint, updatedAt: num(k.updatedAt) ?? 0,
        changedAt: num(k.changedAt), how: ["new", "proven", "reset"].includes(k.how) ? k.how : undefined,
        ...pending ? { pending } : {}
    };
}

const lookups = new Map<string, { at: number; keys: DirectoryKey[]; }>();

export async function lookupKeys(userId: string, opts: { fresh?: boolean; } = {}): Promise<DirectoryKey[]> {
    if (!/^\d{17,20}$/.test(userId)) return [];
    const cached = lookups.get(userId);
    if (!opts.fresh && cached && Date.now() - cached.at < 10 * 60_000) return cached.keys;
    const r = await call("GET", `/v1/keys/${userId}`);
    if (r.status === 404) return [];
    if (r.status !== 200) throw serverError(r.status, r.body);
    const body = parseJson<{ userId?: unknown; keys?: unknown; }>(r.body);
    if (body.userId !== userId || !Array.isArray(body.keys)) throw new CipherError("internal", "The Cipher server sent something unexpected.");
    const keys = body.keys.map(readDirectoryKey).filter((k): k is DirectoryKey => !!k);
    lookups.set(userId, { at: Date.now(), keys });
    return keys;
}

/** The published key can't be changed without proof from it, and this computer can't give that proof. */
export class OldKeyNeeded extends Error {
    constructor(readonly type: KeyType) {
        super("old key needed");
    }
}

async function fingerprintOf(type: KeyType, key: string): Promise<string> {
    return (await inspectKey(type, key)).fingerprint;
}

/**
 * Proves to the server that you hold the private key of `key` (or, without
 * `key`, of the key it has published for you). age: decrypts the server's
 * challenge, answering only if it is exactly a challenge. PGP: GnuPG signs
 * the fixed proof statement with the key's primary key.
 */
async function prove(s: Session, type: KeyType, fingerprint: string, key?: string): Promise<{ ticket: string; response: string; }> {
    const r = await call("POST", "/v1/keys/challenge", { token: s.token, body: key ? { type, key } : { type } });
    if (r.status !== 200) throw serverError(r.status, r.body);
    const body = parseJson<{ ticket?: unknown; challenge?: unknown; }>(r.body);
    const ticket = typeof body.ticket === "string" ? body.ticket : "";
    const t = parseTicket(ticket);
    if (!t || t.userId !== s.userId || t.type !== type || t.fingerprint !== fingerprint)
        throw new CipherError("internal", "The Cipher server sent something unexpected.");

    if (type === "age") {
        const identity = state.identity.ageIdentity;
        if (!identity) throw new CipherError("locked");
        if (typeof body.challenge !== "string" || body.challenge.length > 8192) throw new CipherError("internal", "The Cipher server sent something unexpected.");
        let plain: string;
        try {
            plain = new TextDecoder("utf-8", { fatal: true }).decode(await ageDecrypt(body.challenge, [identity]));
        } catch {
            throw new CipherError("internal", "Your age key couldn't open the Cipher server's challenge.");
        }
        const nonce = readAgeChallenge(plain, ticket);
        if (!nonce) throw new CipherError("internal", "The Cipher server sent a strange challenge, so Cipher didn't answer it.");
        return { ticket, response: nonce };
    }
    try {
        return { ticket, response: await pgpEngine().signProof(fingerprint, proofStatement(s.origin, s.userId, fingerprint, ticket)) };
    } catch (e) {
        throw toCipherError(e);
    }
}

/** Proof for the key currently published, if this computer still has its private key. */
async function proveOld(s: Session, type: KeyType, fingerprint: string): Promise<{ ticket: string; response: string; } | null> {
    if (type === "age") {
        const own = state.identity.publicIdentity.age?.recipient;
        if (!own || await fingerprintOf("age", own) !== fingerprint) return null;
        return prove(s, "age", fingerprint, own);
    }
    if (!/^[0-9A-F]{40}$/.test(fingerprint)) return null;
    const inGnupg = (await state.identity.gnupgKeys().catch(() => [])).some(k => k.fingerprint === fingerprint && k.hasSecret);
    return inGnupg ? prove(s, "pgp", fingerprint) : null;
}

/* Resets this computer asked for, so they don't set off the takeover warning. */
const resetsKey = () => `Cipher_server_resets_v1:${UserStore.getCurrentUser()?.id}`;
async function rememberReset(type: KeyType, effectiveAt: number) {
    await DataStore.update<Record<string, number>>(resetsKey(), (all = {}) => ({ ...all, [type]: effectiveAt }));
}

export type KeyChange = { done: true; } | { pending: true; effectiveAt: number; };

async function finish(s: Session, type: KeyType, r: { status: number; body: string; }): Promise<KeyChange> {
    lookups.delete(s.userId);
    if (r.status === 202) {
        const effectiveAt = num(parseJson<{ effectiveAt?: unknown; }>(r.body).effectiveAt) ?? 0;
        await rememberReset(type, effectiveAt);
        return { pending: true, effectiveAt };
    }
    if (r.status !== 200) throw serverError(r.status, r.body);
    return { done: true };
}

/**
 * Publishes your key, proving you hold it. Replacing a different published
 * key also needs proof from that one; if this computer can't give it, this
 * throws OldKeyNeeded, and `reset` publishes it after the server's delay.
 */
export async function publishKey(type: KeyType, key: string, opts: { reset?: boolean; } = {}): Promise<KeyChange> {
    const s = await requireSession();
    const proof = await prove(s, type, await fingerprintOf(type, key), key);
    let r = await call("PUT", "/v1/keys", { token: s.token, body: { type, key, proof, ...opts.reset ? { reset: true } : {} } });
    if (r.status === 409 && errorCode(r.body) === "old-key-proof-required" && !opts.reset) {
        const old = parseJson<{ fingerprint?: unknown; }>(r.body).fingerprint;
        const oldProof = typeof old === "string" ? await proveOld(s, type, old) : null;
        if (!oldProof) throw new OldKeyNeeded(type);
        r = await call("PUT", "/v1/keys", { token: s.token, body: { type, key, proof, oldProof } });
    }
    return finish(s, type, r);
}

/** Removes your published key, with proof from it; without that proof, `reset` removes it after the delay. */
export async function unpublishKey(type: KeyType, opts: { reset?: boolean; } = {}): Promise<KeyChange> {
    const s = await requireSession();
    const current = (await lookupKeys(s.userId, { fresh: true })).find(k => k.type === type);
    if (!current) return { done: true };
    let body: Record<string, unknown> = { type, reset: true };
    if (!opts.reset) {
        const proof = await proveOld(s, type, current.fingerprint);
        if (!proof) throw new OldKeyNeeded(type);
        body = { type, proof };
    }
    return finish(s, type, await call("POST", "/v1/keys/remove", { token: s.token, body }));
}

/**
 * Changes to your published keys that this computer didn't ask for: someone
 * with access to your Discord account may be trying to replace your key.
 */
export async function unexpectedKeyChanges(): Promise<DirectoryKey[]> {
    const s = await getSession();
    if (!s) return [];
    const mine = await DataStore.get<Record<string, number>>(resetsKey()) ?? {};
    const keys = await lookupKeys(s.userId, { fresh: true });
    return keys.filter(k => k.pending && mine[k.type] !== k.pending.effectiveAt);
}

/* ---------- disappearing messages ---------- */

function b64url(bytes: Uint8Array): string {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function ciphertextHash(armored: string): Promise<string> {
    return b64url(await sha256(new TextEncoder().encode(normalizeForServer(armored))));
}

interface StoredLink { origin: string; deleteToken: string; expiresAt: number; }
const linksKey = () => `Cipher_links_v1:${UserStore.getCurrentUser()?.id}`;

/** Uploads a ciphertext; the delete code stays on this computer so the sender can delete it early. */
export async function uploadMessage(armored: string, ttlDays: LinkTtl): Promise<{ url: string; id: string; expiresAt: number; hash: string; }> {
    const s = await requireSession();
    const r = await call("POST", "/v1/messages", { token: s.token, body: { ciphertext: normalizeForServer(armored), ttlDays } });
    if (r.status !== 201) throw serverError(r.status, r.body);
    const body = parseJson<{ id?: unknown; deleteToken?: unknown; expiresAt?: unknown; }>(r.body);
    if (typeof body.id !== "string" || !LINK_ID_RE.test(body.id) || typeof body.deleteToken !== "string" || !DELETE_TOKEN_RE.test(body.deleteToken) ||
        typeof body.expiresAt !== "number" || !Number.isFinite(body.expiresAt))
        throw new CipherError("internal", "The Cipher server sent something unexpected.");
    const now = Date.now();
    await DataStore.update<Record<string, StoredLink>>(linksKey(), (all = {}) => {
        for (const [id, l] of Object.entries(all)) if (l.expiresAt <= now) delete all[id];
        all[body.id as string] = { origin: s.origin, deleteToken: body.deleteToken as string, expiresAt: body.expiresAt as number };
        return all;
    });
    return { url: `${s.origin}/m/${body.id}`, id: body.id, expiresAt: body.expiresAt, hash: await ciphertextHash(armored) };
}

/** Downloads a message and checks it's exactly the ciphertext the sender linked to. */
export async function fetchMessage(origin: string, id: string, hash: string): Promise<{ armored: string; } | { gone: true; }> {
    if (!LINK_ID_RE.test(id)) throw new CipherError("malformed");
    // Checked again here, whatever the caller decided (see linkLoadPolicy).
    const own = serverOrigin();
    if (linkLoadPolicy(own, origin, true) === "never")
        throw new CipherError("internal", own ? "This message is on a different Cipher server. Cipher only contacts your own server." : "Cipher doesn't load messages from local network or IP addresses.");
    const r = await native().serverFetch(origin, "GET", `/m/${id}`, undefined, undefined, undefined);
    if (!r.ok) throw new CipherError("internal", "Couldn't reach the server holding this message.");
    if (r.status === 404) return { gone: true };
    if (r.status !== 200) throw serverError(r.status, r.body);
    if (await ciphertextHash(r.body) !== hash)
        throw new CipherError("decrypt-failed", "The server returned something other than the message that was sent. It may have been tampered with.");
    return { armored: r.body };
}

export async function canDeleteLink(id: string): Promise<boolean> {
    const all = await DataStore.get<Record<string, StoredLink>>(linksKey()) ?? {};
    return !!all[id];
}

/** Deletes the server copy now, with the delete code saved at upload. */
export async function deleteLink(id: string): Promise<void> {
    const all = await DataStore.get<Record<string, StoredLink>>(linksKey()) ?? {};
    const l = all[id];
    if (!l) throw new CipherError("internal", "This computer doesn't have the delete code for that message.");
    const r = await native().serverFetch(l.origin, "DELETE", `/m/${id}`, undefined, undefined, l.deleteToken);
    if (!r.ok || r.status !== 200) throw new CipherError("internal", "The server copy couldn't be deleted.");
    await DataStore.update<Record<string, StoredLink>>(linksKey(), (x = {}) => { delete x[id]; return x; });
}
