/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Runs in Discord's main process. Vencord exposes each export to the Discord
 * window over IPC, so everything here treats its arguments as untrusted:
 *  - calls are accepted only from Discord's own top-level page, not from
 *    iframes (embedded activities, other sites);
 *  - every argument is type- and size-checked;
 *  - there's no general "run gpg" entry point, only these operations;
 *  - exporting a secret key needs a click in a window shown by this process,
 *    which scripts in the Discord page can't answer for you.
 * Results are returned as { ok, value } / { ok, code } because thrown errors
 * don't survive IPC intact.
 */

import { BrowserWindow, dialog, type IpcMainInvokeEvent, powerMonitor } from "electron";

import { findGpg, GpgEngine } from "./core/gpg";
import { isProofStatementFor } from "./core/keyProof";
import { DELETE_TOKEN_RE, SERVER_TOKEN_RE, serverRequestUrl } from "./core/serverApi";
import { type PgpAvailability, type PgpErrorCode, PgpEngineError } from "./core/pgpEngine";

export type NativeResult<T> = { ok: true; value: T; } | { ok: false; code: PgpErrorCode; };

const FPR_RE = /^(?:[0-9A-F]{40}|[0-9A-F]{64})$/;
const MAX_KEY = 64 * 1024;
const MAX_KEYS = 256;
const MAX_MESSAGE = 4 * 1024 * 1024;
const MAX_PLAINTEXT = 1024 * 1024;

let engine: GpgEngine | null | undefined;

function gpg(): GpgEngine {
    if (engine === undefined) {
        const paths = findGpg();
        engine = paths ? new GpgEngine(paths) : null;
    }
    if (!engine) throw new PgpEngineError("not-found");
    return engine;
}

function fromDiscord(event: IpcMainInvokeEvent): boolean {
    const frame = event.senderFrame;
    if (!frame || frame.parent) return false;
    try {
        const u = new URL(frame.url);
        return u.protocol === "https:" && /^(?:canary\.|ptb\.)?discord\.com$/.test(u.hostname);
    } catch {
        return false;
    }
}

class Invalid extends Error { }

function check(ok: boolean) {
    if (!ok) throw new Invalid();
}

const isStr = (v: unknown, max: number): v is string => typeof v === "string" && v.length > 0 && v.length <= max;
const isFpr = (v: unknown): v is string => typeof v === "string" && FPR_RE.test(v);
const isPublicKey = (v: unknown) => isStr(v, MAX_KEY) && v.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----") && !v.includes("PRIVATE KEY");
const isBytes = (v: unknown, max: number): v is Uint8Array => v instanceof Uint8Array && v.length <= max;

async function run<T>(event: IpcMainInvokeEvent, validate: () => void, fn: (g: GpgEngine) => Promise<T>): Promise<NativeResult<T>> {
    try {
        check(fromDiscord(event));
        validate();
        const g = gpg();
        await g.requireSupported();
        return { ok: true, value: await fn(g) };
    } catch (e) {
        if (e instanceof Invalid) return { ok: false, code: "invalid-input" };
        return { ok: false, code: e instanceof PgpEngineError ? e.code : "failed" };
    }
}

/** Reports why GnuPG can't be used (missing, too old), so this one skips the version gate in run(). */
export async function available(event: IpcMainInvokeEvent): Promise<NativeResult<PgpAvailability>> {
    if (!fromDiscord(event)) return { ok: false, code: "invalid-input" };
    try {
        if (!findGpg()) return { ok: true, value: { ok: false, reason: "GnuPG isn't installed." } };
        return { ok: true, value: await gpg().available() };
    } catch {
        return { ok: false, code: "failed" };
    }
}

export function inspect(event: IpcMainInvokeEvent, armored: unknown) {
    return run(event, () => check(isStr(armored, MAX_KEY) && !(armored as string).includes("PRIVATE KEY")), g => g.inspect(armored as string));
}

export function listSecretKeys(event: IpcMainInvokeEvent) {
    return run(event, () => { }, g => g.listSecretKeys());
}

export function exportPublicKey(event: IpcMainInvokeEvent, fingerprint: unknown) {
    return run(event, () => check(isFpr(fingerprint)), g => g.exportPublicKey(fingerprint as string));
}

export function generateKey(event: IpcMainInvokeEvent, userId: unknown) {
    // A leading "-" would make gpg read the user ID as an option.
    // eslint-disable-next-line no-control-regex -- deliberately matching control characters to reject them
    return run(event, () => check(isStr(userId, 100) && !/[\u0000-\u001f\u007f]/.test(userId as string) && !(userId as string).trimStart().startsWith("-")), g => g.generateKey(userId as string));
}

export function importSecretKey(event: IpcMainInvokeEvent, armored: unknown) {
    return run(event, () => check(isStr(armored, 256 * 1024) && (armored as string).includes("-----BEGIN PGP PRIVATE KEY BLOCK-----")), g => g.importSecretKey(armored as string));
}

/** Asks in a native window. Any code in the Discord page could call these IPC handlers, so the page can't be the one to confirm. */
async function confirmNative(event: IpcMainInvokeEvent, message: string, detail: string, button: string): Promise<boolean> {
    const options = { type: "warning" as const, title: "Cipher", message, detail, buttons: ["Cancel", button], defaultId: 0, cancelId: 0, noLink: true };
    const win = BrowserWindow.fromWebContents(event.sender);
    const r = win ? await dialog.showMessageBox(win, options) : await dialog.showMessageBox(options);
    return r.response === 1;
}

export function exportSecretKey(event: IpcMainInvokeEvent, fingerprint: unknown) {
    return run(event, () => check(isFpr(fingerprint)), async g => {
        const fpr = (fingerprint as string).replace(/(.{4})/g, "$1 ").trim();
        const ok = await confirmNative(event,
            "Export your PGP secret key?",
            `Something in Discord asked GnuPG for the secret key\n${fpr}\n\nOnly allow this if you just clicked Export in Cipher's settings. The exported key stays protected by its passphrase.`,
            "Export");
        if (!ok) throw new PgpEngineError("cancelled");
        return g.exportSecretKey(fingerprint as string);
    });
}

export function encrypt(event: IpcMainInvokeEvent, recipientKeys: unknown, signFingerprint: unknown, data: unknown) {
    return run(event, () => {
        check(Array.isArray(recipientKeys) && recipientKeys.length > 0 && recipientKeys.length <= 10 && recipientKeys.every(isPublicKey));
        check(signFingerprint === undefined || signFingerprint === null || isFpr(signFingerprint));
        check(isBytes(data, MAX_PLAINTEXT));
    }, g => g.encrypt({ recipientKeys: recipientKeys as string[], signFingerprint: (signFingerprint as string) || undefined, data: data as Uint8Array }));
}

export function decrypt(event: IpcMainInvokeEvent, armored: unknown, verificationKeys: unknown, maxBytes: unknown) {
    return run(event, () => {
        check(isStr(armored, MAX_MESSAGE) && (armored as string).includes("-----BEGIN PGP MESSAGE-----"));
        check(Array.isArray(verificationKeys) && verificationKeys.length <= MAX_KEYS && verificationKeys.every(isPublicKey));
        check(typeof maxBytes === "number" && Number.isInteger(maxBytes) && maxBytes > 0 && maxBytes <= MAX_PLAINTEXT);
    }, g => g.decrypt({ armoredMessage: armored as string, verificationKeys: verificationKeys as string[], maxBytes: maxBytes as number }));
}

/** A real publish or removal needs at most two proofs; more than this a minute is something else. */
const MAX_PROOFS_PER_MINUTE = 6;
const recentProofs: number[] = [];

/**
 * Signs only a key-proof statement naming this key (checked again in gpg.ts).
 * Throttled, so a script in the page can't make GnuPG ask for the passphrase
 * over and over.
 */
export function signProof(event: IpcMainInvokeEvent, fingerprint: unknown, statement: unknown) {
    return run(event, () => {
        check(isFpr(fingerprint) && isStr(statement, 1024) && isProofStatementFor(statement as string, fingerprint as string));
        const now = Date.now();
        while (recentProofs.length && recentProofs[0] <= now - 60_000) recentProofs.shift();
        check(recentProofs.length < MAX_PROOFS_PER_MINUTE);
        recentProofs.push(now);
    }, g => g.signProof(fingerprint as string, statement as string));
}

export function keyProtection(event: IpcMainInvokeEvent, fingerprint: unknown) {
    return run(event, () => check(isFpr(fingerprint)), g => g.keyProtection(fingerprint as string));
}

export function forgetPassphrase(event: IpcMainInvokeEvent, fingerprint: unknown) {
    return run(event, () => check(isFpr(fingerprint)), g => g.forgetPassphrase(fingerprint as string));
}

/** For auto-lock: seconds since the last keyboard or mouse input anywhere on this computer, and whether the screen is locked. */
export function systemIdle(event: IpcMainInvokeEvent): { ok: true; idleSeconds: number; locked: boolean; } | { ok: false; } {
    if (!fromDiscord(event)) return { ok: false };
    try {
        return { ok: true, idleSeconds: powerMonitor.getSystemIdleTime(), locked: powerMonitor.getSystemIdleState(1) === "locked" };
    } catch {
        return { ok: false };
    }
}

/* ---------- Cipher server (optional) ---------- */

const MAX_SERVER_BODY = 40 * 1024;
const MAX_SERVER_RESPONSE = 64 * 1024;

/**
 * Talks to the user's chosen Cipher server, from the main process so
 * Discord's page rules (CSP) don't apply and no Discord cookies are sent.
 * Only the fixed requests in core/serverApi.ts are possible.
 */
export async function serverFetch(event: IpcMainInvokeEvent, base: unknown, method: unknown, path: unknown, body: unknown, token: unknown, deleteToken: unknown):
    Promise<{ ok: true; status: number; body: string; expiresAt?: number; } | { ok: false; code: "invalid-input" | "failed"; }> {
    if (!fromDiscord(event)) return { ok: false, code: "invalid-input" };
    if (typeof base !== "string" || typeof method !== "string" || typeof path !== "string") return { ok: false, code: "invalid-input" };
    const url = serverRequestUrl(base, method, path);
    if (!url) return { ok: false, code: "invalid-input" };
    if (body !== undefined && body !== null && !(typeof body === "string" && body.length <= MAX_SERVER_BODY)) return { ok: false, code: "invalid-input" };
    if (token !== undefined && token !== null && !(typeof token === "string" && SERVER_TOKEN_RE.test(token))) return { ok: false, code: "invalid-input" };
    if (deleteToken !== undefined && deleteToken !== null && !(typeof deleteToken === "string" && DELETE_TOKEN_RE.test(deleteToken))) return { ok: false, code: "invalid-input" };

    const headers: Record<string, string> = { Accept: "application/json, text/plain" };
    if (body) headers["Content-Type"] = "application/json";
    if (token) headers.Authorization = `Bearer ${token}`;
    if (deleteToken) headers["X-Delete-Token"] = deleteToken;
    try {
        const res = await fetch(url, {
            method, headers, body: (body as string) || undefined,
            redirect: "error", credentials: "omit", referrerPolicy: "no-referrer",
            signal: AbortSignal.timeout(15_000)
        });
        // Read at most MAX_SERVER_RESPONSE bytes.
        const reader = res.body?.getReader();
        const chunks: Uint8Array[] = [];
        let total = 0;
        if (reader) {
            for (;;) {
                const { done, value } = await reader.read();
                if (done) break;
                total += value.length;
                if (total > MAX_SERVER_RESPONSE) {
                    await reader.cancel();
                    return { ok: false, code: "failed" };
                }
                chunks.push(value);
            }
        }
        const text = new TextDecoder("utf-8", { fatal: false }).decode(Buffer.concat(chunks));
        const exp = Number(res.headers.get("X-Expires-At"));
        return { ok: true, status: res.status, body: text, ...Number.isFinite(exp) && exp > 0 ? { expiresAt: exp } : {} };
    } catch {
        return { ok: false, code: "failed" };
    }
}
