/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * How Cipher data looks inside Discord messages.
 *
 * Encrypted message (one part of possibly several):
 *
 *   -# 🔒 Cipher v1 · age · 1/2 · ref k3x9q2ab · set m4n5p6q7
 *   ```
 *   -----BEGIN AGE ENCRYPTED FILE-----
 *   ...
 *   ```
 *
 * The armor inside is standard, so the joined parts can also be decrypted
 * with the age or gpg command line tools. `ref` links the parts of one
 * ciphertext; `set` links the age and PGP copies of one message when a mixed
 * selection was sent as two ciphertexts. A message that fits in one part and
 * has no copy has nothing to link, so it carries neither:
 *
 *   -# 🔒 Cipher v1 · pgp · 1/1
 *
 * Too long for chat: a notice message (`file`) plus an attachment message
 * (`attachment`) carrying cipher-<ref>.age and/or cipher-<ref>.asc. The attachment is
 * sent first, so the notice is the message that clears the chat box.
 *
 * Public key share:
 *
 *   -# 🔑 Cipher v1 · public key · pgp · code 12345 67890 ...
 *   ```
 *   -----BEGIN PGP PUBLIC KEY BLOCK-----
 *   ...
 *   ```
 */

import { AGE_ARMOR_BEGIN, AGE_ARMOR_END } from "./ageCipher";
import { bech32Decode, bech32Encode } from "./bech32";
import { parseLinkUrl } from "./serverApi";
import type { KeyType } from "./keys";
import { PGP_MESSAGE_BEGIN, PGP_MESSAGE_END, PGP_PUBLIC_BEGIN, PGP_PUBLIC_END } from "./pgpCipher";

/** Discord allows 2000; keep a small margin in case the client normalises anything. */
export const DISCORD_CHAR_LIMIT = 1990;
export const ATTACHMENT_MAX_BYTES = 2 * 1024 * 1024;

const MSG_PREFIX = "-# 🔒 Cipher v1";
const KEY_PREFIX = "-# 🔑 Cipher v1";
const SEP = " · ";
const FENCE = "```";

const ID_RE = /^[a-z0-9]{4,16}$/;

export type ParsedContent =
    /** `ref` is absent only on a lone 1/1 message without `set`. */
    | { kind: "part"; type: KeyType; ref?: string; set?: string; part: number; total: number; body: string; }
    | { kind: "file-notice"; ref: string; set?: string; }
    | { kind: "attachment"; ref: string; set?: string; }
    | { kind: "raw"; type: KeyType; armored: string; }
    | { kind: "link"; expiresAt: number; links: MessageLink[]; }
    | { kind: "key"; type: KeyType; material: string; marked: boolean; };

/** A disappearing message on a Cipher server: where it is and the SHA-256 of its text. */
export interface MessageLink {
    url: string;
    origin: string;
    id: string;
    type: KeyType;
    /** base64url SHA-256 of the stored ciphertext, checked after download. */
    hash: string;
}

const MAX_LINKS = 4;
const LINK_LINE_RE = /^(https?:\/\/[^\s<>#]+)#(age|pgp)\.([A-Za-z0-9_-]{43})$/;
export const LINK_BEGIN = "-----BEGIN CIPHER DISAPPEARING MESSAGE-----";
export const LINK_END = "-----END CIPHER DISAPPEARING MESSAGE-----";
/** Four links fit in well under 1 KB of base64. */
const MAX_LINK_BASE64 = 2048;

/**
 * Disappearing message: a header with a Discord timestamp (so everyone sees
 * when it goes), then an armored block. Its body is the base64 of one line
 * per ciphertext, "<server>/m/<id>#<type>.<sha256>", so Discord shows no
 * clickable link and fetches no preview; Cipher decodes it, loads the text
 * and checks the hash.
 *
 *   -# 🔒 Cipher v1 · disappearing · expires <t:1767225600:R>
 *   ```
 *   -----BEGIN CIPHER DISAPPEARING MESSAGE-----
 *   aHR0cHM6Ly9jaXBoZXIuZXhhbXBsZS9tLzdBYkNkRWYuLi4jYWdlLlEyeHIuLi4=
 *   -----END CIPHER DISAPPEARING MESSAGE-----
 *   ```
 */
export function formatLinkMessage(expiresAt: number, links: { url: string; type: KeyType; hash: string; }[]): string {
    const head = headerLine(MSG_PREFIX, ["disappearing", `expires <t:${Math.floor(expiresAt / 1000)}:R>`]);
    const body = btoa(links.map(l => `${l.url}#${l.type}.${l.hash}`).join("\n"));
    const wrapped = body.match(/.{1,64}/g) ?? [];
    return `${head}\n${fenced([LINK_BEGIN, ...wrapped, LINK_END].join("\n"))}`;
}

function parseLinkMessage(content: string, tokens: string[]): ParsedContent | null {
    const exp = tokens.map(t => /^expires <t:(\d{9,11}):R>$/.exec(t)).find(Boolean);
    if (!exp) return null;
    // Exactly: header, fence, BEGIN, base64 lines, END, fence. Nothing else.
    const lines = content.replace(/\r\n/g, "\n").trim().split("\n").slice(1).map(l => l.trim());
    if (lines.length < 5 || lines[0] !== FENCE || lines[1] !== LINK_BEGIN || lines.at(-2) !== LINK_END || lines.at(-1) !== FENCE) return null;
    const b64 = lines.slice(2, -2).join("");
    if (!b64 || b64.length > MAX_LINK_BASE64 || b64.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) return null;
    let decoded: string;
    try {
        decoded = atob(b64);
    } catch {
        return null;
    }
    const entries = decoded.split("\n");
    if (entries.length === 0 || entries.length > MAX_LINKS) return null;
    const links: MessageLink[] = [];
    for (const entry of entries) {
        const m = LINK_LINE_RE.exec(entry);
        if (!m) return null;
        const where = parseLinkUrl(m[1]);
        if (!where) return null;
        links.push({ url: m[1], origin: where.origin, id: where.id, type: m[2] as KeyType, hash: m[3] });
    }
    return { kind: "link", expiresAt: Number(exp[1]) * 1000, links };
}

function fenced(body: string) {
    return `${FENCE}\n${body}\n${FENCE}`;
}

function headerLine(prefix: string, tokens: (string | undefined | false)[]) {
    return [prefix, ...tokens.filter(Boolean)].join(SEP);
}

export function partHeader(type: KeyType, part: number, total: number, ref: string, set?: string) {
    const lone = total === 1 && !set;
    return headerLine(MSG_PREFIX, [type, `${part}/${total}`, !lone && `ref ${ref}`, set && `set ${set}`]);
}

export function fileNotice(ref: string, set?: string) {
    return headerLine(MSG_PREFIX, ["file", `ref ${ref}`, set && `set ${set}`, "encrypted message attached above"]);
}

export function attachmentHeader(ref: string, set?: string) {
    return headerLine(MSG_PREFIX, ["attachment", `ref ${ref}`, set && `set ${set}`]);
}

export function attachmentName(ref: string, type: KeyType) {
    return `cipher-${ref}.${type === "age" ? "age" : "asc"}`;
}

export function parseAttachmentName(name: string): { ref: string; type: KeyType; } | null {
    const m = /^cipher-([a-z0-9]{4,16})\.(age|asc)$/.exec(name);
    return m ? { ref: m[1], type: m[2] === "age" ? "age" : "pgp" } : null;
}

const PQ_HRP = "age1pq";
const PQ_KEY_BYTES = 1216;

/**
 * A post-quantum age key is ~1960 characters in its usual bech32 form, too
 * long for one Discord message with a header. Key shares carry it as base64
 * (1624 characters) instead, and Cipher turns it back into age1pq1… on read.
 */
function pqToBase64(recipient: string): string {
    const { hrp, bytes } = bech32Decode(recipient);
    if (hrp !== PQ_HRP || bytes.length !== PQ_KEY_BYTES) throw new Error("not a post-quantum age key");
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/(.{64})/g, "$1\n").trim();
}

function pqFromBase64(body: string): string | null {
    try {
        const bin = atob(body.replace(/\s+/g, ""));
        if (bin.length !== PQ_KEY_BYTES) return null;
        return bech32Encode(PQ_HRP, Uint8Array.from(bin, c => c.charCodeAt(0)));
    } catch {
        return null;
    }
}

export function formatKeyShare(type: KeyType, material: string, code: string) {
    const m = material.trim();
    if (type === "age" && m.startsWith("age1pq1"))
        return headerLine(KEY_PREFIX, ["public key", "age-pq", `code ${code}`]) + "\n" + fenced(pqToBase64(m));
    return headerLine(KEY_PREFIX, ["public key", type, `code ${code}`]) + "\n" + fenced(m);
}

/**
 * Splits armored ciphertext into Discord messages of at most `limit`
 * characters, breaking only between armor lines.
 */
export function splitArmored(armored: string, opts: { type: KeyType; ref: string; set?: string; limit?: number; }): string[] {
    const limit = opts.limit ?? DISCORD_CHAR_LIMIT;
    const lines = armored.replace(/\r\n/g, "\n").trim().split("\n");

    // Header length depends on the part count, so guess, pack, and repeat
    // with a larger guess until the packed count fits the guess.
    let total = 1;
    for (let attempt = 0; attempt < 6; attempt++) {
        // header + "\n" + "```\n" + body + "\n```"
        const overhead = partHeader(opts.type, total, total, opts.ref, opts.set).length + 1 + FENCE.length * 2 + 2;
        const budget = limit - overhead;
        const chunks: string[] = [];
        let cur = "";
        for (const line of lines) {
            if (line.length > budget) throw new Error("Armor line longer than message budget");
            const next = cur ? cur + "\n" + line : line;
            if (next.length > budget) {
                chunks.push(cur);
                cur = line;
            } else {
                cur = next;
            }
        }
        if (cur) chunks.push(cur);
        const n = chunks.length;
        // A smaller count never makes the header longer, so n <= total fits.
        if (n <= total) return chunks.map((c, i) => partHeader(opts.type, i + 1, n, opts.ref, opts.set) + "\n" + fenced(c));
        total = n;
    }
    throw new Error("Could not split message");
}

function parseTokens(line: string) {
    return line.split(SEP).slice(1).map(t => t.trim());
}

function extractFenced(content: string, afterIndex: number): string | null {
    const start = content.indexOf(FENCE, afterIndex);
    if (start === -1) return null;
    let bodyStart = start + FENCE.length;
    const nl = content.indexOf("\n", bodyStart);
    if (nl === -1) return null;
    // Allow an optional language tag after the opening fence.
    if (/^[a-z]*$/i.test(content.slice(bodyStart, nl).trim())) bodyStart = nl + 1;
    const end = content.indexOf(FENCE, bodyStart);
    if (end === -1) return null;
    // Remove only the newline before the closing fence. Trimming more would
    // eat the blank line PGP armor has after its BEGIN line when a part
    // boundary falls right there.
    const body = content.slice(bodyStart, end).replace(/\r\n/g, "\n");
    return body.endsWith("\n") ? body.slice(0, -1) : body;
}

function findArmor(content: string, begin: string, end: string): string | null {
    const s = content.indexOf(begin);
    if (s === -1) return null;
    const e = content.indexOf(end, s);
    if (e === -1) return null;
    return content.slice(s, e + end.length).replace(/\r\n/g, "\n");
}

export function parseContent(content: string | undefined | null): ParsedContent | null {
    if (!content) return null;

    const lineEnd = content.indexOf("\n");
    const first = (lineEnd === -1 ? content : content.slice(0, lineEnd)).trim();

    if (first.startsWith(MSG_PREFIX + SEP)) {
        const tokens = parseTokens(first);
        if (tokens[0] === "disappearing") return parseLinkMessage(content, tokens);
        const ref = tokens.find(t => t.startsWith("ref "))?.slice(4);
        const setTok = tokens.find(t => t.startsWith("set "))?.slice(4);
        const set = setTok && ID_RE.test(setTok) ? setTok : undefined;
        if (setTok !== undefined && !set) return null;
        if (ref !== undefined && !ID_RE.test(ref)) return null;
        if (tokens.includes("file")) return ref ? { kind: "file-notice", ref, set } : null;
        if (tokens.includes("attachment")) return ref ? { kind: "attachment", ref, set } : null;

        const type = tokens.includes("age") ? "age" : tokens.includes("pgp") ? "pgp" : null;
        const pm = tokens.map(t => /^(\d{1,3})\/(\d{1,3})$/.exec(t)).find(Boolean);
        if (!type || !pm) return null;
        const part = Number(pm[1]);
        const total = Number(pm[2]);
        if (part < 1 || part > total) return null;
        // Only a lone message may leave out the ref: parts and copies need it to be linked.
        if (!ref && (total !== 1 || set)) return null;
        const body = extractFenced(content, lineEnd === -1 ? content.length : lineEnd);
        if (body == null) return null;
        return { kind: "part", type, ref, set, part, total, body };
    }

    if (first.startsWith(KEY_PREFIX + SEP)) {
        const tokens = parseTokens(first);
        const body = extractFenced(content, lineEnd === -1 ? content.length : lineEnd);
        if (!body?.trim()) return null;
        if (tokens.includes("age-pq")) {
            const material = pqFromBase64(body);
            return material ? { kind: "key", type: "age", material, marked: true } : null;
        }
        const type = tokens.includes("age") ? "age" : tokens.includes("pgp") ? "pgp" : null;
        if (!type) return null;
        return { kind: "key", type, material: body.trim(), marked: true };
    }

    const pgpMsg = findArmor(content, PGP_MESSAGE_BEGIN, PGP_MESSAGE_END);
    if (pgpMsg) return { kind: "raw", type: "pgp", armored: pgpMsg };
    const ageMsg = findArmor(content, AGE_ARMOR_BEGIN, AGE_ARMOR_END);
    if (ageMsg) return { kind: "raw", type: "age", armored: ageMsg };
    const pgpKey = findArmor(content, PGP_PUBLIC_BEGIN, PGP_PUBLIC_END);
    if (pgpKey) return { kind: "key", type: "pgp", material: pgpKey, marked: false };

    return null;
}

/**
 * Whether a message is nothing but Cipher data, so its own text can be hidden
 * and replaced by the decrypted text. Hand-pasted armor counts only when the
 * message is the armor alone, so no surrounding text is ever hidden. Key
 * shares stay visible.
 */
export function isPureCipherContent(content: string | undefined | null, parsed = parseContent(content)): boolean {
    if (!parsed || !content) return false;
    if (parsed.kind === "part" || parsed.kind === "file-notice" || parsed.kind === "attachment" || parsed.kind === "link") return true;
    return parsed.kind === "raw" && content.replace(/\r\n/g, "\n").trim() === parsed.armored.trim();
}

export interface PartRef {
    part: number;
    total: number;
    body: string;
}

/** Joins parts back into armor, or reports which part numbers are missing. */
export function reassemble(parts: PartRef[]): { armored: string; } | { missing: number[]; } | { error: "inconsistent"; } {
    if (parts.length === 0) return { error: "inconsistent" };
    const total = parts[0].total;
    if (parts.some(p => p.total !== total)) return { error: "inconsistent" };
    const byNum = new Map<number, string>();
    for (const p of parts) {
        const prev = byNum.get(p.part);
        if (prev !== undefined && prev !== p.body) return { error: "inconsistent" };
        byNum.set(p.part, p.body);
    }
    const missing: number[] = [];
    for (let i = 1; i <= total; i++) if (!byNum.has(i)) missing.push(i);
    if (missing.length) return { missing };
    return { armored: Array.from({ length: total }, (_, i) => byNum.get(i + 1)).join("\n") + "\n" };
}
