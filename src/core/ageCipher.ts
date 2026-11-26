/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { CipherError } from "./errors";

type AgeModule = typeof import("age-encryption");
let agePromise: Promise<AgeModule> | undefined;
/** Loaded lazily so the library costs nothing while the plugin is disabled. */
function age(): Promise<AgeModule> {
    return agePromise ??= import("age-encryption");
}

export const AGE_ARMOR_BEGIN = "-----BEGIN AGE ENCRYPTED FILE-----";
export const AGE_ARMOR_END = "-----END AGE ENCRYPTED FILE-----";

/** Native X25519 recipients only: age1 + 58 bech32 characters. */
export const AGE_RECIPIENT_RE = /^age1[02-9ac-hj-np-z]{58}$/;
export const AGE_IDENTITY_RE = /^AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]{58}$/;
/** Post-quantum hybrid (ML-KEM-768 + X25519): a 1216-byte public key. */
export const AGE_PQ_RECIPIENT_RE = /^age1pq1[02-9ac-hj-np-z]{1952}$/;
export const AGE_PQ_IDENTITY_RE = /^AGE-SECRET-KEY-PQ-1[02-9AC-HJ-NP-Z]{58}$/;

export function isPqAgeRecipient(recipient: string): boolean {
    return recipient.startsWith("age1pq1");
}

/** Default scrypt work factor for passphrase-protected data (age's default). */
export const DEFAULT_SCRYPT_LOG_N = 18;

export async function generateAgeIdentity(opts: { postQuantum?: boolean; } = {}): Promise<{ identity: string; recipient: string; }> {
    const { generateX25519Identity, generateHybridIdentity, identityToRecipient } = await age();
    const identity = opts.postQuantum ? await generateHybridIdentity() : await generateX25519Identity();
    return { identity, recipient: await identityToRecipient(identity) };
}

/** Validates an age secret key and returns its recipient. */
export async function ageIdentityToRecipient(identity: string): Promise<string> {
    const trimmed = identity.trim();
    if (!AGE_IDENTITY_RE.test(trimmed) && !AGE_PQ_IDENTITY_RE.test(trimmed)) throw new CipherError("invalid-key", "That isn't a valid age secret key.");
    const { identityToRecipient } = await age();
    try {
        return await identityToRecipient(trimmed);
    } catch {
        throw new CipherError("invalid-key", "That isn't a valid age secret key.");
    }
}

/** Throws unless `recipient` is a valid native X25519 age recipient. */
export async function validateAgeRecipient(recipient: string): Promise<void> {
    if (!AGE_RECIPIENT_RE.test(recipient) && !AGE_PQ_RECIPIENT_RE.test(recipient)) throw new CipherError("invalid-key");
    const { Encrypter } = await age();
    try {
        new Encrypter().addRecipient(recipient);
    } catch {
        throw new CipherError("invalid-key");
    }
}

export function normalizeAgeArmor(armored: string): string {
    return armored.replace(/\r\n/g, "\n").trim() + "\n";
}

export async function ageEncrypt(recipients: string[], data: Uint8Array): Promise<string> {
    if (recipients.length === 0) throw new CipherError("internal");
    const { Encrypter, armor } = await age();
    const e = new Encrypter();
    for (const r of recipients) e.addRecipient(r);
    return armor.encode(await e.encrypt(data));
}

function decodeArmor(mod: AgeModule, armored: string): Uint8Array {
    try {
        return mod.armor.decode(normalizeAgeArmor(armored));
    } catch {
        throw new CipherError("malformed");
    }
}

/** More recipient stanzas than this is refused. Cipher sends at most 10 readers. */
export const MAX_AGE_STANZAS = 32;

/**
 * Counts the recipient stanzas ("-> ...") in an age header, so a message
 * with thousands of them can't keep Discord busy trying each one.
 */
export function ageStanzaCount(binary: Uint8Array): number {
    const head = new TextDecoder("latin1").decode(binary.subarray(0, 256 * 1024));
    const end = head.indexOf("\n---");
    if (!head.startsWith("age-encryption.org/v1\n") || end === -1) throw new CipherError("malformed");
    return head.slice(0, end).split("\n").filter(l => l.startsWith("-> ")).length;
}

export async function ageDecrypt(armored: string, identities: string[]): Promise<Uint8Array> {
    const mod = await age();
    const binary = decodeArmor(mod, armored);
    if (ageStanzaCount(binary) > MAX_AGE_STANZAS) throw new CipherError("malformed");
    if (identities.length === 0) throw new CipherError("missing-key");
    const d = new mod.Decrypter();
    for (const i of identities) d.addIdentity(i);
    try {
        return await d.decrypt(binary);
    } catch (e) {
        if (e instanceof Error && e.message.includes("no identity matched")) throw new CipherError("not-recipient");
        throw new CipherError("decrypt-failed");
    }
}

export async function agePassphraseEncrypt(data: Uint8Array, passphrase: string, logN = DEFAULT_SCRYPT_LOG_N): Promise<string> {
    const { Encrypter, armor } = await age();
    const e = new Encrypter();
    e.setPassphrase(passphrase);
    e.setScryptWorkFactor(logN);
    return armor.encode(await e.encrypt(data));
}

export async function agePassphraseDecrypt(armored: string, passphrase: string): Promise<Uint8Array> {
    const mod = await age();
    const binary = decodeArmor(mod, armored);
    const d = new mod.Decrypter();
    d.addPassphrase(passphrase);
    try {
        return await d.decrypt(binary);
    } catch (e) {
        if (e instanceof Error && e.message.includes("no identity matched")) throw new CipherError("wrong-passphrase");
        throw new CipherError("decrypt-failed");
    }
}
