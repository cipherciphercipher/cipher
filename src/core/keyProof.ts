/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Proof of key possession for the Cipher server's key directory.
 *
 * Signing in with Discord isn't enough to change a published key: someone who
 * takes over a Discord account could otherwise swap in their own key for
 * everyone who looks it up. So publishing, replacing and removing a key needs
 * proof that you hold the private key:
 *
 *  - PGP: a detached signature, made by the key's primary key, over a fixed
 *    statement naming the server, the Discord account, the key and a
 *    one-time ticket from the server;
 *  - age (which can't sign): decrypting a challenge the server encrypted to
 *    the key, and sending back the random code inside.
 *
 * Shared by the client, the main-process bridge and the server, so all three
 * agree byte for byte on what is signed and what a challenge looks like.
 */

/** p1.<user>.<type>.<fingerprint>.<expiry ms>.<random>.<HMAC> */
export const PROOF_TICKET_RE = /^p1\.(\d{17,20})\.(age|pgp)\.([0-9A-F]{40}|[0-9A-F]{64})\.(\d{1,15})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/;
export const PROOF_NONCE_RE = /^[A-Za-z0-9_-]{43}$/;
/** A detached, armored OpenPGP signature as GnuPG writes it (RSA-8192 is about 1.5 KB). */
export const MAX_PROOF_SIGNATURE = 8 * 1024;
/** How long a ticket stays valid: long enough to type a GnuPG passphrase. */
export const PROOF_TTL_MS = 10 * 60_000;
/** A key replaced or removed without proof from the old key only takes effect after this long. */
export const KEY_RESET_DELAY_MS = 7 * 86_400_000;

export interface ProofTicket {
    userId: string;
    type: "age" | "pgp";
    fingerprint: string;
    expiresAt: number;
}

export function parseTicket(ticket: string): ProofTicket | null {
    const m = PROOF_TICKET_RE.exec(ticket);
    if (!m) return null;
    return { userId: m[1], type: m[2] as "age" | "pgp", fingerprint: m[3], expiresAt: Number(m[4]) };
}

/** What a PGP key signs. Only v4 fingerprints: GnuPG 2.4 can't use v6 keys. */
export function proofStatement(origin: string, userId: string, fingerprint: string, ticket: string): string {
    return `Cipher key proof v1\nserver: ${origin}\nuser: ${userId}\nkey: ${fingerprint}\nticket: ${ticket}\n`;
}

const ORIGIN = String.raw`(?:https:\/\/[a-z0-9.-]{1,253}(?::\d{1,5})?|http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::\d{1,5})?)`;
const STATEMENT_RE = new RegExp(String.raw`^Cipher key proof v1\nserver: ${ORIGIN}\nuser: (\d{17,20})\nkey: ([0-9A-F]{40})\nticket: (\S{1,200})\n$`);

/**
 * Checks that `statement` is a key-proof statement for `fingerprint` and
 * nothing else. The bridge to GnuPG only signs text that passes this, so the
 * Discord page can't use it to sign anything else with your key.
 */
export function isProofStatementFor(statement: string, fingerprint: string): boolean {
    const m = STATEMENT_RE.exec(statement);
    if (!m) return false;
    const t = parseTicket(m[3]);
    return m[2] === fingerprint && !!t && t.type === "pgp" && t.fingerprint === fingerprint && t.userId === m[1];
}

/** The plaintext of an age challenge. */
export function ageChallengeText(ticket: string, nonce: string): string {
    return `Cipher key proof v1\nticket: ${ticket}\nnonce: ${nonce}\n`;
}

/**
 * Reads a decrypted age challenge. Returns the code to send back only if the
 * plaintext is exactly a challenge for this ticket, so a server can't use
 * this to get any other message decrypted for it.
 */
export function readAgeChallenge(plain: string, ticket: string): string | null {
    const m = /^Cipher key proof v1\nticket: (\S{1,200})\nnonce: ([A-Za-z0-9_-]{43})\n$/.exec(plain);
    return m && m[1] === ticket ? m[2] : null;
}
