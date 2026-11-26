/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * The only requests Cipher ever makes to a Cipher server. native.ts refuses
 * anything else, so the Discord page can't use Cipher's bridge to reach other
 * URLs or other parts of a server.
 */

export const SERVER_TOKEN_RE = /^c1\.\d{17,20}\.\d{1,12}\.[A-Za-z0-9_-]{43}$/;
export const DELETE_TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
export const LINK_ID_RE = /^[137][A-Za-z0-9_-]{22}$/;
export const LINK_TTL_DAYS = [1, 3, 7] as const;
export type LinkTtl = typeof LINK_TTL_DAYS[number];

const ROUTES: [string, RegExp][] = [
    ["GET", /^\/v1\/oauth$/],
    ["GET", /^\/v1\/auth\/callback\?code=[A-Za-z0-9]{10,64}$/],
    ["GET", /^\/v1\/keys\/\d{17,20}$/],
    ["POST", /^\/v1\/keys\/challenge$/],
    ["PUT", /^\/v1\/keys$/],
    ["POST", /^\/v1\/keys\/remove$/],
    ["POST", /^\/v1\/messages$/],
    ["GET", /^\/m\/[137][A-Za-z0-9_-]{22}$/],
    ["DELETE", /^\/m\/[137][A-Za-z0-9_-]{22}$/]
];

/**
 * A server address as Cipher stores it: https origin only (no path, query,
 * user name or password). http is allowed only for localhost, for testing.
 * Returns the normalized origin, or null if it isn't acceptable.
 */
export function normalizeServerUrl(input: string): string | null {
    let u: URL;
    try {
        u = new URL(input.trim());
    } catch {
        return null;
    }
    if (u.username || u.password || u.search || u.hash) return null;
    if (u.pathname !== "/" && u.pathname !== "") return null;
    const local = u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
    if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) return null;
    return u.origin;
}

/** The full URL for an allowed request, or null. */
export function serverRequestUrl(base: string, method: string, path: string): string | null {
    const origin = normalizeServerUrl(base);
    if (!origin || origin !== base) return null;
    if (!ROUTES.some(([m, re]) => m === method && re.test(path))) return null;
    return origin + path;
}

/** Where a link in a Discord message points, if it's a Cipher message link. */
export function parseLinkUrl(url: string): { origin: string; id: string; } | null {
    let u: URL;
    try {
        u = new URL(url);
    } catch {
        return null;
    }
    const origin = normalizeServerUrl(u.origin);
    const m = /^\/m\/([137][A-Za-z0-9_-]{22})$/.exec(u.pathname);
    if (!origin || !m || u.search || u.username || u.password) return null;
    return { origin, id: m[1] };
}
