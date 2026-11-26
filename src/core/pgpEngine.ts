/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * PGP is done by the user's own GnuPG installation, never by bundled code.
 * This is the interface between Cipher and GnuPG. It's implemented by
 * core/gpg.ts (Node, runs gpg/gpgv) and, in Discord, by a thin proxy that
 * calls that implementation in Discord's main process over Vencord's
 * plugin IPC. Nothing in this file touches Node or Discord.
 */

export interface GpgKey {
    /** Primary key fingerprint, uppercase hex. */
    fingerprint: string;
    /** Key IDs of the primary key and all subkeys (uppercase hex, 16 chars). */
    keyIds: string[];
    userIds: string[];
    createdAt?: number;
    expiresAt?: number;
    revoked: boolean;
    expired: boolean;
    /** The key as a whole can encrypt (has a usable encryption subkey or primary). */
    canEncrypt: boolean;
    canSign: boolean;
    /** For secret key listings: the secret part is present (not a stub or card-only). */
    hasSecret?: boolean;
}

export type SignatureStatus =
    | { status: "unsigned"; }
    | { status: "valid"; signerFingerprint: string; keyWarning?: "expired" | "revoked"; }
    | { status: "invalid"; }
    | { status: "unknown-signer"; signerKeyId: string; };

export interface PgpDecryptResult {
    data: Uint8Array;
    signature: SignatureStatus;
}

export type PgpAvailability = { ok: true; version: string; } | { ok: false; reason: string; };

/** Errors the engine reports; mapped to CipherError codes by the caller. */
export type PgpErrorCode = "not-found" | "not-recipient" | "decrypt-failed" | "compressed" | "cancelled" | "too-large" | "invalid-key" | "invalid-input" | "failed";

export interface PgpEngine {
    available(): Promise<PgpAvailability>;
    /** Parses armored public key(s) without importing them anywhere. */
    inspect(armoredKeys: string): Promise<GpgKey[]>;
    /** Secret keys in the user's GnuPG keyring that Cipher could use. */
    listSecretKeys(): Promise<GpgKey[]>;
    exportPublicKey(fingerprint: string): Promise<string>;
    /** Creates a Curve25519 key in the user's keyring; GnuPG asks for its passphrase. */
    generateKey(userId: string): Promise<string>;
    /** Imports an armored secret key into the user's keyring. Returns the fingerprints imported. */
    importSecretKey(armored: string): Promise<string[]>;
    /** Exports a secret key, still protected by its GnuPG passphrase. */
    exportSecretKey(fingerprint: string): Promise<string>;
    /**
     * Encrypts to exactly these public keys (passed as files, not looked up
     * in the keyring) and optionally signs with a key from the user's keyring.
     */
    encrypt(opts: { recipientKeys: string[]; signFingerprint?: string; data: Uint8Array; }): Promise<string>;
    /** Decrypts with the user's keyring; checks signatures only against `verificationKeys`. */
    decrypt(opts: { armoredMessage: string; verificationKeys: string[]; maxBytes: number; }): Promise<PgpDecryptResult>;
    /**
     * Signs a key-proof statement (core/keyProof.ts) with the key's primary
     * key, for the Cipher server. Refuses any other text.
     */
    signProof(fingerprint: string, statement: string): Promise<string>;
    /** Whether the secret key has a passphrase (and if gpg-agent remembers it right now). */
    keyProtection(fingerprint: string): Promise<KeyProtection>;
    /** Makes gpg-agent forget the key's passphrase, so the next use asks again. */
    forgetPassphrase(fingerprint: string): Promise<void>;
}

/**
 * Whether GnuPG holds the secret key under a passphrase, from gpg-agent's
 * KEYINFO (never the key itself). "card": on a smartcard, which has a PIN.
 * `cached`: gpg-agent currently remembers the passphrase.
 */
export interface KeyProtection {
    state: "protected" | "unprotected" | "card" | "unknown";
    cached: boolean;
}

export class PgpEngineError extends Error {
    constructor(readonly code: PgpErrorCode, message?: string) {
        super(message ?? code);
        this.name = "PgpEngineError";
    }
}
