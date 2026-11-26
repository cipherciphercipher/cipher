/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Every error Cipher shows to the user goes through this module.
 *
 * Rule: a user-facing message is chosen from the fixed table below and never
 * includes text from a library error, a key, a ciphertext or a plaintext.
 * Library errors are mapped to a code and the original error is dropped.
 */

export type ErrorCode =
    | "not-recipient"
    | "missing-key"
    | "locked"
    | "malformed"
    | "decrypt-failed"
    | "wrong-passphrase"
    | "weak-passphrase"
    | "invalid-key"
    | "private-key-pasted"
    | "unsupported-key"
    | "no-encryption-key"
    | "too-large"
    | "not-text"
    | "key-mismatch"
    | "invalid-input"
    | "pgp-unavailable"
    | "cancelled"
    | "hidden-recipients"
    | "compressed-pgp"
    | "internal";

const MESSAGES: Record<ErrorCode, string> = {
    "not-recipient": "You are not a recipient of this message.",
    "missing-key": "You don't have a private key of this type, so you can't read this message.",
    "locked": "Your keys are locked. Unlock Cipher with your passphrase first.",
    "malformed": "This message is damaged or not a valid encrypted message.",
    "decrypt-failed": "Decryption failed. The message may be damaged or tampered with.",
    "wrong-passphrase": "Wrong passphrase.",
    "weak-passphrase": "Passphrase must be at least 8 characters.",
    "invalid-key": "That doesn't look like a valid age or PGP public key.",
    "private-key-pasted": "That is a PRIVATE key. Never share it. Paste the public key instead.",
    "unsupported-key": "This kind of key isn't supported.",
    "no-encryption-key": "This PGP key has no usable encryption subkey.",
    "too-large": "The message is too large.",
    "not-text": "The decrypted message isn't valid text.",
    "invalid-input": "That input isn't valid.",
    "pgp-unavailable": "PGP needs GnuPG, which wasn't found or is too old. Install a current Gpg4win (Windows) or GnuPG 2.4+ and restart Discord.",
    "cancelled": "Cancelled: the GnuPG passphrase prompt was closed.",
    "hidden-recipients": "This PGP message hides who it's for, so Cipher doesn't try to decrypt it by itself.",
    "compressed-pgp": "This PGP message is compressed. Cipher refuses compressed PGP data, because unpacking it is a known way to attack GnuPG. Cipher itself never sends it; from the gpg command line, use --compress-algo none.",
    "key-mismatch": "Stored key data is inconsistent. Your key store may have been modified.",
    "internal": "Something went wrong inside Cipher."
};

export class CipherError extends Error {
    readonly code: ErrorCode;

    constructor(code: ErrorCode, message?: string) {
        super(message ?? MESSAGES[code]);
        this.name = "CipherError";
        this.code = code;
    }
}

/** A message that is always safe to show or log. */
export function safeMessage(err: unknown): string {
    if (err instanceof CipherError) return err.message;
    return MESSAGES.internal;
}

export function errorCode(err: unknown): ErrorCode {
    return err instanceof CipherError ? err.code : "internal";
}
