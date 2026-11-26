/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { AGE_ARMOR_BEGIN, ageIdentityToRecipient, agePassphraseDecrypt, agePassphraseEncrypt, DEFAULT_SCRYPT_LOG_N, generateAgeIdentity } from "./ageCipher";
import { utf8Decode, utf8Encode } from "./bytes";
import type { KV } from "./contacts";
import { CipherError } from "./errors";
import { inspectKey } from "./keys";
import { pgpEngine, toCipherError } from "./pgpCipher";
import type { GpgKey, PgpEngine } from "./pgpEngine";
import type { SelfKeys } from "./recipients";
import { checkPassphrase, type PublicIdentity, type SecretBundle, sealIdentity, type StoredIdentity, unsealIdentity } from "./vault";

const AGE_STORE_KEY = "Cipher_identity_v2";
const PGP_STORE_KEY = "Cipher_pgp_v1";

/** Which GnuPG key Cipher uses. Only public data: GnuPG keeps the secret key. */
export interface PgpSelection {
    fingerprint: string;
    publicKey: string;
    keyIds: string[];
    selectedAt: number;
}

export interface OwnKeys {
    age?: { recipient: string; createdAt: number; };
    pgp?: PgpSelection;
}

/** A secret key in GnuPG is usable by Cipher if it can sign and encrypt and isn't expired or revoked. */
export function usableGpgKey(k: GpgKey): boolean {
    return !!k.hasSecret && k.canEncrypt && k.canSign && !k.revoked && !k.expired;
}

/**
 * Your own keys.
 *
 * age: generated or imported by Cipher, sealed with your Cipher passphrase.
 * PGP: a key from your GnuPG keyring (e.g. made in Kleopatra). Cipher only
 * remembers which one; GnuPG asks for its passphrase when it's needed.
 *
 * "Unlocked" means you opened this session: the age key is unsealed (if you
 * have one) and Cipher may ask GnuPG to decrypt.
 */
export class IdentityManager {
    private stored?: StoredIdentity;
    private pgp?: PgpSelection;
    private secrets?: SecretBundle;
    private session = false;
    private listeners = new Set<() => void>();

    constructor(private kv: KV, private logN = DEFAULT_SCRYPT_LOG_N, private now: () => number = Date.now, private engine?: PgpEngine) { }

    private gpg(): PgpEngine {
        return this.engine ?? pgpEngine();
    }

    async load() {
        this.stored = await this.kv.get<StoredIdentity>(AGE_STORE_KEY);
        this.pgp = await this.kv.get<PgpSelection>(PGP_STORE_KEY);
        this.secrets = undefined;
        this.session = false;
        this.emit();
    }

    subscribe(fn: () => void) {
        this.listeners.add(fn);
        return () => void this.listeners.delete(fn);
    }

    private emit() {
        for (const fn of this.listeners) fn();
    }

    get publicIdentity(): OwnKeys {
        return { age: this.stored?.public.age, pgp: this.pgp };
    }

    has(type: "age" | "pgp") {
        return type === "age" ? !!this.stored?.public.age : !!this.pgp;
    }

    /** Unlocking needs the Cipher passphrase only if you have an age key. */
    get needsPassphrase() {
        return this.has("age");
    }

    get hasAnyKey() {
        return this.has("age") || this.has("pgp");
    }

    get isUnlocked() {
        return this.session && (!this.has("age") || !!this.secrets?.age);
    }

    get ageIdentity(): string | undefined {
        return this.isUnlocked ? this.secrets?.age?.identity : undefined;
    }

    selfKeys(userId: string): SelfKeys {
        return { userId, age: this.stored?.public.age?.recipient, pgp: this.pgp?.publicKey };
    }

    async unlock(passphrase?: string) {
        if (!this.hasAnyKey) throw new CipherError("missing-key", "You don't have any keys yet. Set one up in Cipher's settings.");
        if (this.has("age")) {
            if (passphrase === undefined) throw new CipherError("wrong-passphrase");
            this.secrets = await unsealIdentity(this.stored!, passphrase);
        }
        this.session = true;
        this.emit();
    }

    lock() {
        if (!this.session && !this.secrets) return;
        this.secrets = undefined;
        this.session = false;
        this.emit();
    }

    /* ---------- age ---------- */

    /** Opens the age vault with `passphrase` (or starts a new one) and re-seals it after `change`. */
    private async modifyAge(passphrase: string, change: (pub: PublicIdentity, sec: SecretBundle) => void) {
        let pub: PublicIdentity;
        let sec: SecretBundle;
        if (this.stored) {
            sec = await unsealIdentity(this.stored, passphrase);
            pub = structuredClone(this.stored.public);
        } else {
            checkPassphrase(passphrase);
            pub = {};
            sec = {};
        }
        change(pub, sec);
        if (!pub.age) {
            // No age key left: drop the vault entirely.
            await this.kv.set(AGE_STORE_KEY, undefined);
            this.stored = undefined;
            this.secrets = undefined;
        } else {
            const sealed = await sealIdentity(pub, sec, passphrase, this.logN);
            await this.kv.set(AGE_STORE_KEY, sealed);
            this.stored = sealed;
            this.secrets = sec;
            this.session = true;
        }
        this.emit();
    }

    async generateAge(passphrase: string, opts: { postQuantum?: boolean; } = {}) {
        if (this.has("age")) throw new CipherError("invalid-input", "You already have an age key. Delete it first to replace it.");
        const { identity, recipient } = await generateAgeIdentity(opts);
        await this.modifyAge(passphrase, (pub, sec) => {
            pub.age = { recipient, createdAt: this.now() };
            sec.age = { identity };
        });
    }

    /**
     * Imports an age secret key: a bare AGE-SECRET-KEY-1... line, an identity
     * file containing one, or a passphrase-encrypted export.
     */
    async importAge(text: string, passphrase: string, filePassphrase?: string) {
        if (this.has("age")) throw new CipherError("invalid-input", "You already have an age key. Delete it first to replace it.");
        let source = text.trim();
        if (source.includes(AGE_ARMOR_BEGIN)) {
            if (!filePassphrase) throw new CipherError("wrong-passphrase", "This key file is passphrase protected. Enter its passphrase.");
            source = utf8Decode(await agePassphraseDecrypt(source, filePassphrase));
        }
        const line = source.split(/\r?\n/).map(l => l.trim()).find(l => l.startsWith("AGE-SECRET-KEY-"));
        if (!line) throw new CipherError("invalid-key", "That isn't a valid age secret key.");
        const recipient = await ageIdentityToRecipient(line);
        await this.modifyAge(passphrase, (pub, sec) => {
            pub.age = { recipient, createdAt: this.now() };
            sec.age = { identity: line };
        });
    }

    async removeAge(passphrase: string) {
        await this.modifyAge(passphrase, (pub, sec) => {
            delete pub.age;
            delete sec.age;
        });
    }

    /** age secret key export, always passphrase protected. Requires Cipher to be unlocked. */
    async exportAge(exportPassphrase: string): Promise<string> {
        checkPassphrase(exportPassphrase);
        const identity = this.ageIdentity;
        if (!identity) throw new CipherError(this.has("age") ? "locked" : "missing-key");
        const file = `# age identity exported from Cipher\n# public key: ${this.stored!.public.age!.recipient}\n${identity}\n`;
        return agePassphraseEncrypt(utf8Encode(file), exportPassphrase, this.logN);
    }

    /* ---------- PGP via GnuPG ---------- */

    /** Secret keys in GnuPG, with whether Cipher can use each. */
    async gnupgKeys(): Promise<(GpgKey & { usable: boolean; })[]> {
        try {
            return (await this.gpg().listSecretKeys()).map(k => ({ ...k, usable: usableGpgKey(k) }));
        } catch (e) {
            throw toCipherError(e);
        }
    }

    /** Uses a key from the GnuPG keyring as your PGP key. */
    async usePgpKey(fingerprint: string) {
        const key = (await this.gnupgKeys()).find(k => k.fingerprint === fingerprint.toUpperCase());
        if (!key) throw new CipherError("missing-key", "That key isn't in your GnuPG keyring.");
        if (!key.usable) throw new CipherError("invalid-key", "That GnuPG key can't be used: it needs a secret key that can sign and encrypt, and mustn't be expired or revoked.");
        let publicKey;
        try {
            publicKey = await this.gpg().exportPublicKey(key.fingerprint);
        } catch (e) {
            throw toCipherError(e);
        }
        const info = await inspectKey("pgp", publicKey, this.now(), this.gpg());
        if (info.fingerprint !== key.fingerprint || info.problems.length) throw new CipherError("invalid-key");
        this.pgp = { fingerprint: key.fingerprint, publicKey: info.material, keyIds: info.keyIds, selectedAt: this.now() };
        await this.kv.set(PGP_STORE_KEY, this.pgp);
        this.emit();
    }

    /** Creates a new Curve25519 key in GnuPG (GnuPG asks for its passphrase) and uses it. */
    async createPgpKey(name: string) {
        // Leading dashes are stripped: gpg would read the user ID as an option.
        // eslint-disable-next-line no-control-regex -- deliberately matching control characters to reject them
        const clean = name.replace(/[\u0000-\u001f\u007f<>()]/g, "").trim().replace(/^-+\s*/, "").slice(0, 64) || "Cipher user";
        let fpr;
        try {
            fpr = await this.gpg().generateKey(`${clean} (Cipher)`);
        } catch (e) {
            throw toCipherError(e);
        }
        await this.usePgpKey(fpr);
    }

    /** Imports a secret key file into GnuPG and uses it. */
    async importPgpKey(armored: string) {
        let fprs;
        try {
            fprs = await this.gpg().importSecretKey(armored.trim());
        } catch (e) {
            throw toCipherError(e);
        }
        const keys = await this.gnupgKeys();
        const pick = keys.find(k => fprs.includes(k.fingerprint) && k.usable);
        if (!pick) throw new CipherError("invalid-key", "The key was imported into GnuPG, but it can't sign and encrypt, so Cipher can't use it.");
        await this.usePgpKey(pick.fingerprint);
    }

    /** Exports your PGP secret key from GnuPG, still protected by its GnuPG passphrase. */
    async exportPgp(): Promise<string> {
        if (!this.pgp) throw new CipherError("missing-key");
        try {
            return await this.gpg().exportSecretKey(this.pgp.fingerprint);
        } catch (e) {
            throw toCipherError(e);
        }
    }

    /** Stops using the PGP key. It stays in GnuPG. */
    async forgetPgp() {
        this.pgp = undefined;
        await this.kv.set(PGP_STORE_KEY, undefined);
        this.emit();
    }
}
