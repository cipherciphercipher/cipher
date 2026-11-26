/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { AGE_IDENTITY_RE, AGE_PQ_IDENTITY_RE, AGE_RECIPIENT_RE, isPqAgeRecipient, validateAgeRecipient } from "./ageCipher";
import { sha256, toHex, utf8Encode } from "./bytes";
import { CipherError } from "./errors";
import { PGP_PRIVATE_BEGIN, PGP_PUBLIC_BEGIN, PGP_PUBLIC_END, pgpEngine, toCipherError } from "./pgpCipher";
import type { PgpEngine } from "./pgpEngine";
import { checkPublicKeyShape, dearmorPgp } from "./pgpPackets";

export type KeyType = "age" | "pgp";

export const KEY_TYPE_LABEL: Record<KeyType, string> = { age: "age", pgp: "PGP" };

export type DetectedKey =
    | { kind: "public"; type: KeyType; material: string; }
    | { kind: "private"; type: KeyType; }
    | { kind: "unsupported"; reason: string; };

const PGP_PUBLIC_BLOCK_RE = new RegExp(`${PGP_PUBLIC_BEGIN}[\\s\\S]+?${PGP_PUBLIC_END}`);
const AGE_RECIPIENT_FIND_RE = /\bage1[02-9ac-hj-np-z]{58}\b/;
const AGE_PQ_RECIPIENT_FIND_RE = /\bage1pq1[02-9ac-hj-np-z]{1952}\b/;

/**
 * Works out what kind of key some pasted text contains. Private keys are
 * recognised so they can be refused loudly instead of saved as a contact.
 */
export function detectKey(text: string): DetectedKey | null {
    const t = text.replace(/\r\n/g, "\n").trim();
    if (!t) return null;
    if (t.includes(PGP_PRIVATE_BEGIN)) return { kind: "private", type: "pgp" };
    if (/AGE-SECRET-KEY-(PQ-)?1/.test(t)) return { kind: "private", type: "age" };

    const pgp = PGP_PUBLIC_BLOCK_RE.exec(t);
    if (pgp) return { kind: "public", type: "pgp", material: pgp[0] };

    const pq = AGE_PQ_RECIPIENT_FIND_RE.exec(t);
    if (pq) return { kind: "public", type: "age", material: pq[0] };
    if (/\bage1tag/.test(t)) return { kind: "unsupported", reason: "Hardware-token age keys aren't supported." };
    const age = AGE_RECIPIENT_FIND_RE.exec(t);
    if (age) return { kind: "public", type: "age", material: age[0] };
    return null;
}

export function isAgeIdentity(text: string): boolean {
    return AGE_IDENTITY_RE.test(text.trim()) || AGE_PQ_IDENTITY_RE.test(text.trim());
}

/** "age", "age PQ" (post-quantum) or "PGP", for badges. */
export function keyLabel(type: KeyType, material?: string): string {
    return type === "age" && material && isPqAgeRecipient(material) ? "age PQ" : KEY_TYPE_LABEL[type];
}

export type KeyProblem = "expired" | "revoked" | "no-encryption-subkey" | "check-failed";

export const KEY_PROBLEM_TEXT: Record<KeyProblem, string> = {
    "expired": "This PGP key has expired.",
    "revoked": "This PGP key has been revoked by its owner.",
    "no-encryption-subkey": "This PGP key has no usable encryption subkey.",
    "check-failed": "Cipher couldn't check this key. For PGP keys, make sure GnuPG is installed and working."
};

export interface KeyInfo {
    type: KeyType;
    /** Normalised public key: the age recipient or the armored PGP public key. */
    material: string;
    /** Uppercase hex. For PGP this is the key fingerprint, for age the SHA-256 of the recipient. */
    fingerprint: string;
    /** Short decimal code to compare out of band. */
    code: string;
    userIds: string[];
    /** PGP only: key IDs of the primary key and subkeys, to tell whether a message is addressed to this key. */
    keyIds: string[];
    expiresAt?: number;
    problems: KeyProblem[];
}

export function isUsable(info: Pick<KeyInfo, "problems">): boolean {
    return info.problems.length === 0;
}

/**
 * The comparison code: 6 groups of 5 digits (96 bits) derived from the
 * fingerprint. Both people see the same code for the same key, so reading it
 * to each other over a call or in person verifies the key.
 */
export async function comparisonCode(type: KeyType, fingerprint: string): Promise<string> {
    const digest = await sha256(utf8Encode(`cipher-code-v1:${type}:${fingerprint.toUpperCase()}`));
    const groups: string[] = [];
    for (let i = 0; i < 6; i++) {
        const n = (digest[i * 2] << 8) | digest[i * 2 + 1];
        groups.push(n.toString().padStart(5, "0"));
    }
    return groups.join(" ");
}

export function formatFingerprint(fp: string): string {
    return fp.toUpperCase().replace(/(.{4})(?=.)/g, "$1 ");
}

async function inspectAge(recipient: string): Promise<KeyInfo> {
    const material = recipient.trim();
    await validateAgeRecipient(material);
    const fingerprint = toHex(await sha256(utf8Encode(material))).toUpperCase();
    return { type: "age", material, fingerprint, code: await comparisonCode("age", fingerprint), userIds: [], keyIds: [], problems: [] };
}

async function inspectPgp(armored: string, now: number, engine: PgpEngine): Promise<KeyInfo> {
    const material = armored.replace(/\r\n/g, "\n").trim();
    if (material.includes(PGP_PRIVATE_BEGIN)) throw new CipherError("private-key-pasted");
    // Checked in JavaScript before GnuPG ever parses it (see pgpPackets.ts).
    try {
        checkPublicKeyShape(dearmorPgp(material));
    } catch {
        throw new CipherError("invalid-key", "Cipher only accepts plain PGP public keys: one key with its subkeys and user IDs, no photo ID. Ask for it exported with: gpg --armor --export-options export-minimal,no-export-attributes --export <their key>");
    }
    let keys;
    try {
        keys = await engine.inspect(material);
    } catch (e) {
        throw toCipherError(e);
    }
    if (keys.length !== 1) throw new CipherError("invalid-key", "Paste exactly one PGP public key.");
    const [key] = keys;

    const problems: KeyProblem[] = [];
    if (key.revoked) problems.push("revoked");
    if (key.expired || (key.expiresAt !== undefined && key.expiresAt <= now)) problems.push("expired");
    if (!problems.length && !key.canEncrypt) problems.push("no-encryption-subkey");

    return {
        type: "pgp",
        material,
        fingerprint: key.fingerprint,
        code: await comparisonCode("pgp", key.fingerprint),
        userIds: key.userIds,
        keyIds: key.keyIds,
        expiresAt: key.expiresAt,
        problems
    };
}

/** Parses and checks a public key. Throws CipherError if it can't be used at all. */
export async function inspectKey(type: KeyType, material: string, now = Date.now(), engine?: PgpEngine): Promise<KeyInfo> {
    return type === "age" ? inspectAge(material) : inspectPgp(material, now, engine ?? pgpEngine());
}

/** detectKey + inspectKey for text pasted by the user. */
export async function inspectPasted(text: string, now = Date.now(), engine?: PgpEngine): Promise<KeyInfo> {
    const found = detectKey(text);
    if (!found) throw new CipherError("invalid-key");
    if (found.kind === "private") throw new CipherError("private-key-pasted");
    if (found.kind === "unsupported") throw new CipherError("unsupported-key", found.reason);
    return inspectKey(found.type, found.material, now, engine);
}

export { AGE_RECIPIENT_RE };
