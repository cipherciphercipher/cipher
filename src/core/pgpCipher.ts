/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * PGP operations, done by the user's GnuPG through a PgpEngine.
 * Engine errors become CipherErrors with fixed, safe messages.
 */

import { CipherError } from "./errors";
import { MAX_PLAINTEXT_BYTES } from "./payload";
import { type PgpDecryptResult, type PgpEngine, PgpEngineError } from "./pgpEngine";
import { type Addressing, pgpAddressing } from "./pgpPackets";

export const PGP_MESSAGE_BEGIN = "-----BEGIN PGP MESSAGE-----";
export const PGP_MESSAGE_END = "-----END PGP MESSAGE-----";
export const PGP_PUBLIC_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
export const PGP_PUBLIC_END = "-----END PGP PUBLIC KEY BLOCK-----";
export const PGP_PRIVATE_BEGIN = "-----BEGIN PGP PRIVATE KEY BLOCK-----";

let current: PgpEngine | undefined;

/** Installs the engine used when none is passed explicitly (the plugin sets the GnuPG bridge). */
export function setPgpEngine(engine: PgpEngine | undefined) {
    current = engine;
}

export function pgpEngine(): PgpEngine {
    if (!current) throw new CipherError("pgp-unavailable");
    return current;
}

export function toCipherError(e: unknown): CipherError {
    if (e instanceof CipherError) return e;
    if (e instanceof PgpEngineError) {
        switch (e.code) {
            case "not-found": return new CipherError("pgp-unavailable");
            case "not-recipient": return new CipherError("not-recipient");
            case "decrypt-failed": return new CipherError("decrypt-failed");
            case "compressed": return new CipherError("compressed-pgp");
            case "cancelled": return new CipherError("cancelled");
            case "too-large": return new CipherError("too-large");
            case "invalid-key": return new CipherError("invalid-key");
            case "invalid-input": return new CipherError("invalid-input");
            case "failed": return new CipherError("internal", "GnuPG reported an error.");
        }
    }
    return new CipherError("internal");
}

async function wrap<T>(p: Promise<T>): Promise<T> {
    try {
        return await p;
    } catch (e) {
        throw toCipherError(e);
    }
}

export function pgpEncrypt(engine: PgpEngine, recipientKeys: string[], data: Uint8Array, signFingerprint?: string): Promise<string> {
    if (recipientKeys.length === 0) throw new CipherError("internal");
    return wrap(engine.encrypt({ recipientKeys, signFingerprint, data }));
}

export function pgpDecrypt(engine: PgpEngine, armored: string, verificationKeys: string[]): Promise<PgpDecryptResult> {
    return wrap(engine.decrypt({ armoredMessage: armored, verificationKeys, maxBytes: MAX_PLAINTEXT_BYTES + 64 }));
}

/**
 * Whether a message is decrypted without a click. age is memory-safe
 * JavaScript, so always. PGP goes to GnuPG's C code, so only for messages
 * from you and your contacts: anyone can address a PGP message to your key
 * (its ID is public), and a stranger's message must never reach GnuPG
 * unless you click. This also stops strangers from opening passphrase prompts.
 */
export function decryptsAutomatically(type: "age" | "pgp", trustedAuthor: boolean): boolean {
    return type === "age" || trustedAuthor;
}

/**
 * Whether a message is addressed to one of `ownKeyIds`, read from its packets
 * in JavaScript without running GnuPG: "hidden" when it hides its recipients,
 * "no" for passphrase messages. Strangers' messages never reach GnuPG.
 */
export function pgpAddressedTo(armoredMessage: string, ownKeyIds: string[]): Addressing {
    try {
        return pgpAddressing(armoredMessage, ownKeyIds);
    } catch {
        throw new CipherError("malformed");
    }
}

export type { SignatureStatus } from "./pgpEngine";
